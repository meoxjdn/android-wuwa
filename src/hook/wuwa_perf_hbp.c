// SPDX-License-Identifier: GPL-2.0
/*
 * wuwa_perf_hbp.c — V18 事务级静态影子内存引擎 (原生设备版，绕过 Android 15 限制)
 */
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/xarray.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include "wuwa_perf_hbp.h"
#include "../core/wuwa_common.h"

extern pmd_t *wuwa_walk_to_pmd(struct mm_struct *mm, unsigned long va);
extern unsigned long kallsyms_lookup_name_ex(const char *name);

/* ==========================================================
 * 0. GKI 符号动态解析 (绕过 Android 15 EXPORT_SYMBOL 限制)
 * ========================================================== */
typedef int (*register_mn_fn)(struct mmu_notifier *, struct mm_struct *);
typedef void (*unregister_mn_fn)(struct mmu_notifier *, struct mm_struct *);
typedef void (*flush_tlb_fn)(struct mm_struct *, unsigned long, unsigned long, unsigned long, bool);

static register_mn_fn   fn_mmu_notifier_register = NULL;
static unregister_mn_fn fn_mmu_notifier_unregister = NULL;
static flush_tlb_fn     fn_flush_tlb_mm_range = NULL;

static int resolve_gki_symbols(void) {
    if (fn_mmu_notifier_register) return 0; 

    fn_mmu_notifier_register = (register_mn_fn)kallsyms_lookup_name_ex("mmu_notifier_register");
    fn_mmu_notifier_unregister = (unregister_mn_fn)kallsyms_lookup_name_ex("mmu_notifier_unregister");
    fn_flush_tlb_mm_range = (flush_tlb_fn)kallsyms_lookup_name_ex("flush_tlb_mm_range");

    if (!fn_mmu_notifier_register || !fn_mmu_notifier_unregister || !fn_flush_tlb_mm_range) {
        wuwa_err("Critical: Failed to lookup MMU Notifier / TLB symbols.\n");
        return -ENOSYS;
    }
    return 0;
}

/* ==========================================================
 * 基础结构定义
 * ========================================================== */
struct shadow_slot {
    unsigned long va;
    struct page *orig_page;
    struct page *shadow_page;
    struct mm_struct *mm;
    struct mmu_notifier notifier;
    pte_t old_pte;
    refcount_t refs;
    atomic_t state; 
    struct rcu_head rcu;
};

static DEFINE_XARRAY(g_shadow_xa);

/* ==========================================================
 * 1. 资源管理与生命周期闭环
 * ========================================================== */
static void shadow_slot_free_rcu(struct rcu_head *head) {
    struct shadow_slot *slot = container_of(head, struct shadow_slot, rcu);
    if (slot->orig_page) put_page(slot->orig_page);
    if (slot->shadow_page) put_page(slot->shadow_page);
    kfree(slot);
}

static void slot_put(struct shadow_slot *slot) {
    if (refcount_dec_and_test(&slot->refs))
        call_rcu(&slot->rcu, shadow_slot_free_rcu);
}

static void shadow_mn_release(struct mmu_notifier *mn, struct mm_struct *mm) {
    struct shadow_slot *slot = container_of(mn, struct shadow_slot, notifier);
    if (atomic_xchg(&slot->state, 0) == 1) {
        xa_erase(&g_shadow_xa, (unsigned long)mm ^ slot->va);
        slot_put(slot);
    }
}

static const struct mmu_notifier_ops shadow_ops = { .release = shadow_mn_release };

/* ==========================================================
 * 2. 连续页表 (ContPTE) 安全拆分
 * ========================================================== */
static int unfold_cont_group(struct mm_struct *mm, unsigned long addr, pmd_t *pmdp) {
    unsigned long start = addr & ~(PAGE_SIZE * 16 - 1);
    pte_t *ptep;
    spinlock_t *ptl;
    int i;

    ptep = pte_offset_map_lock(mm, pmdp, start, &ptl);
    if (!ptep) return -EFAULT;
    
    for (i = 0; i < 16; i++) {
        if (pte_val(ptep[i]) & (1ULL << 52)) {
            pte_t pte = ptep_get_and_clear(mm, start + (i * PAGE_SIZE), &ptep[i]);
            /* ⚠️ 绕过 set_pte_at 导致的 mte_sync_tags 和 __contpte_try_fold 报错 */
            WRITE_ONCE(*(u64 *)&ptep[i], pte_val(pte) & ~(1ULL << 52));
        }
    }
    pte_unmap_unlock(ptep, ptl);
    
    if (fn_flush_tlb_mm_range) {
        fn_flush_tlb_mm_range(mm, start, start + (PAGE_SIZE * 16), PAGE_SHIFT, false);
    }
    return 0;
}

/* ==========================================================
 * 3. 核心安装引擎：全路径失败回滚 + PTE 语义克隆
 * ========================================================== */
int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct pid *pid_s;
    struct task_struct *tsk;
    struct mm_struct *mm;
    int i, ret = 0;

    if (resolve_gki_symbols() != 0) return -ENOSYS;

    pid_s = find_get_pid(req->tid);
    if (!pid_s) return -ESRCH;
    tsk = get_pid_task(pid_s, PIDTYPE_PID);
    if (!tsk) { put_pid(pid_s); return -ESRCH; }
    mm = get_task_mm(tsk);
    if (!mm) { put_task_struct(tsk); put_pid(pid_s); return -ESRCH; }

    for (i = 0; i < req->hook_count; i++) {
        struct shadow_patch_req *preq = &req->hooks[i];
        unsigned long va = req->base_addr + preq->offset;
        struct shadow_slot *slot = NULL;
        struct page *old_p = NULL, *new_p = NULL;
        pte_t *ptep, old_pte;
        spinlock_t *ptl;
        bool pte_applied = false;
        size_t off = va & ~PAGE_MASK;

        if ((va & 3) || (off + 4 > PAGE_SIZE)) continue;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
        if (get_user_pages_remote(mm, va, 1, FOLL_WRITE | FOLL_FORCE, &old_p, NULL) <= 0) continue;
#else
        if (get_user_pages_remote(mm, va, 1, FOLL_WRITE | FOLL_FORCE, &old_p, NULL, NULL) <= 0) continue;
#endif
        new_p = alloc_page(GFP_HIGHUSER);
        if (!new_p) { put_page(old_p); continue; }

        u8 *src_k = kmap_local_page(old_p);
        if (*(uint32_t *)(src_k + off) != preq->expected) {
            wuwa_err("Verify mismatch at 0x%lx: exp %08x, got %08x\n", va, preq->expected, *(uint32_t *)(src_k + off));
            kunmap_local(src_k); put_page(old_p); __free_page(new_p);
            continue;
        }

        u8 *dst_k = kmap_local_page(new_p);
        memcpy(dst_k, src_k, PAGE_SIZE);

        switch (preq->action) {
            case SHADOW_DATA_PATCH: *(uint32_t *)(dst_k + off) = preq->patch_val; break;
            case SHADOW_RET_ONLY:   *(uint32_t *)(dst_k + off) = 0xD65F03C0; break;
            case SHADOW_HP_SET:
                ((uint32_t *)(dst_k + off))[0] = 0x52800020; 
                ((uint32_t *)(dst_k + off))[1] = 0xD65F03C0; break;
            case SHADOW_JUMP_B: {
                long j_off = (long)preq->target_va - (long)va;
                *(uint32_t *)(dst_k + off) = 0x14000000 | ((j_off >> 2) & 0x03FFFFFF);
                break;
            }
            case SHADOW_STUB_IF: {
                uint32_t *stub = (uint32_t *)(dst_k + 0xF00);
                unsigned long stub_va = (va & PAGE_MASK) + 0xF00;
                stub[0] = 0xB9401C22; stub[1] = 0x7100045F; stub[2] = 0x54000040;
                stub[3] = preq->expected; 
                stub[4] = 0x14000000 | (((long)va + 4 - (long)stub_va - 16) >> 2 & 0x03FFFFFF);
                stub[5] = 0xD65F03C0;
                *(uint32_t *)(dst_k + off) = 0x14000000 | (((long)stub_va - (long)va) >> 2 & 0x03FFFFFF);
                break;
            }
        }
        flush_icache_range((unsigned long)dst_k, (unsigned long)dst_k + PAGE_SIZE);
        kunmap_local(dst_k); kunmap_local(src_k);

        slot = kzalloc(sizeof(*slot), GFP_KERNEL);
        if (!slot) { __free_page(new_p); put_page(old_p); continue; }
        slot->va = va; slot->mm = mm; slot->orig_page = old_p; slot->shadow_page = new_p;
        refcount_set(&slot->refs, 1); atomic_set(&slot->state, 1);
        slot->notifier.ops = &shadow_ops;

        if (fn_mmu_notifier_register(&slot->notifier, mm)) { kfree(slot); __free_page(new_p); put_page(old_p); continue; }

        mmap_read_lock(mm);
        pmd_t *pmd = wuwa_walk_to_pmd(mm, va);
        if (!pmd || pmd_leaf(*pmd) || pmd_trans_huge(*pmd)) { ret = -EFAULT; goto err_rollback; }

        ptep = pte_offset_map_lock(mm, pmd, va, &ptl);
        bool is_cont = (ptep && (pte_val(*ptep) & (1ULL << 52)));
        if (ptep) pte_unmap_unlock(ptep, ptl);
        if (is_cont && unfold_cont_group(mm, va, pmd) != 0) { ret = -EAGAIN; goto err_rollback; }

        ptep = pte_offset_map_lock(mm, pmd, va, &ptl);
        if (!ptep || !pte_present(*ptep) || pte_special(*ptep)) {
            if (ptep) pte_unmap_unlock(ptep, ptl);
            ret = -ENOENT; goto err_rollback;
        }

        old_pte = *ptep;
        slot->old_pte = old_pte;
        u64 val = (pte_val(old_pte) & ~(PHYS_MASK & PAGE_MASK)) | (page_to_pfn(new_p) << PAGE_SHIFT);
        /* ⚠️ 裸写 PTE 绕过屏蔽符号 */
        WRITE_ONCE(*(u64 *)ptep, val & ~(1ULL << 52));
        pte_unmap_unlock(ptep, ptl);
        
        fn_flush_tlb_mm_range(mm, va, va + PAGE_SIZE, PAGE_SHIFT, false);
        pte_applied = true;

        if (xa_err(xa_store(&g_shadow_xa, (unsigned long)mm ^ va, slot, GFP_KERNEL))) {
            ret = -ENOSPC; goto err_rollback;
        }

        mmap_read_unlock(mm);
        continue; 

err_rollback:
        if (pte_applied) {
            ptep = pte_offset_map_lock(mm, pmd, va, &ptl);
            if (ptep) {
                WRITE_ONCE(*(u64 *)ptep, pte_val(slot->old_pte));
                pte_unmap_unlock(ptep, ptl);
                fn_flush_tlb_mm_range(mm, va, va + PAGE_SIZE, PAGE_SHIFT, false);
            }
        }
        mmap_read_unlock(mm);
        fn_mmu_notifier_unregister(&slot->notifier, mm);
        kfree(slot); __free_page(new_p); put_page(old_p);
    }
    mmput(mm); put_task_struct(tsk); put_pid(pid_s);
    return ret;
}

/* ==========================================================
 * 4. V18 独立字符设备接口 (彻底绕过 Android 15 Socket 限制)
 * ========================================================== */
#define DEV_NAME "logd_service"
#define V18_IOCTL_CMD 0x5A5A9999

static long wuwa_v18_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct wuwa_hbp_req req;
    
    if (cmd == V18_IOCTL_CMD) {
        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
        return wuwa_install_perf_hbp(&req);
    }
    return -ENOTTY;
}

static const struct file_operations core_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = wuwa_v18_ioctl,
    .compat_ioctl   = wuwa_v18_ioctl,
};

static struct miscdevice core_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEV_NAME,
    .fops  = &core_fops,
};

int wuwa_hbp_init_device(void) { return 0; }
void wuwa_hbp_cleanup_device(void) { }
void wuwa_cleanup_perf_hbp(void) { }

/* ==========================================================
 * 5. 在主入口真正注册设备 (修复 /dev 节点不生成的问题)
 * ========================================================== */
int wuwa_stealth_init(void) { 
    /* wuwa.c 必定会调用 stealth_init，所以必须在这里注册设备 */
    return misc_register(&core_misc);
}

void wuwa_stealth_cleanup(void) { 
    misc_deregister(&core_misc);
}
