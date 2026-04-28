// SPDX-License-Identifier: GPL-2.0
/*
 * wuwa_perf_hbp.c — V18.3 "Snapshot" 事务级影子内存引擎
 * 核心修复：解决了 mmap_lock 与 GUP 之间的递归死锁问题。
 * 流程： gather_pages -> map_and_patch -> write_lock -> swap_pte -> unlock.
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
#include <linux/proc_fs.h>
#include <linux/refcount.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>

#include "wuwa_perf_hbp.h"
#include "../core/wuwa_common.h"

/* 外部内核符号 */
extern pmd_t *wuwa_walk_to_pmd(struct mm_struct *mm, unsigned long va);
extern unsigned long kallsyms_lookup_name_ex(const char *name);

/* ==========================================================
 * 0. 架构级底层同步 (针对 ARM64 BTI/PAC 优化)
 * ========================================================== */

static inline void safe_flush_tlb_page(unsigned long va) {
    /* tlbi vae1is: 只针对当前虚拟地址的精准刷新，不全核广播，极致稳定 */
    dsb(ishst);
    __asm__ __volatile__ ("tlbi vae1is, %0" : : "r" (va >> 12) : "memory");
    dsb(ish);
    isb();
}

static inline void safe_sync_icache(void *addr, size_t len) {
    flush_icache_range((unsigned long)addr, (unsigned long)addr + len);
}

/* ==========================================================
 * 1. MMU Notifier 管理
 * ========================================================== */

typedef int (*register_mn_fn)(struct mmu_notifier *, struct mm_struct *);
typedef void (*unregister_mn_fn)(struct mmu_notifier *, struct mm_struct *);
static register_mn_fn   fn_mmu_notifier_register = NULL;
static unregister_mn_fn fn_mmu_notifier_unregister = NULL;

static void resolve_notifier_symbols(void) {
    if (fn_mmu_notifier_register) return;
    fn_mmu_notifier_register = (register_mn_fn)kallsyms_lookup_name_ex("mmu_notifier_register");
    fn_mmu_notifier_unregister = (unregister_mn_fn)kallsyms_lookup_name_ex("mmu_notifier_unregister");
}

struct shadow_slot {
    unsigned long va;
    struct page *orig_page;
    struct page *shadow_page;
    struct mm_struct *mm;
    struct mmu_notifier notifier;
    bool registered;
    pte_t old_pte;
    refcount_t refs;
    atomic_t state;
    struct rcu_head rcu;
};

static DEFINE_XARRAY(g_shadow_xa);

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
 * 2. 指令补丁构造引擎 (ARM64 4-Byte Aligned)
 * ========================================================== */

static int construct_patch(u8 *dst_k, size_t off, struct shadow_patch_req *preq, unsigned long va) {
    if (off + 4 > PAGE_SIZE) return -EFAULT;

    switch (preq->action) {
        case SHADOW_DATA_PATCH:
            *(uint32_t *)(dst_k + off) = preq->patch_val;
            break;
        case SHADOW_RET_ONLY:
            *(uint32_t *)(dst_k + off) = 0xD65F03C0; 
            break;
        case SHADOW_HP_SET:
            if (off + 8 > PAGE_SIZE) return -EFAULT;
            ((uint32_t *)(dst_k + off))[0] = 0x52800020; // MOV W0, #1
            ((uint32_t *)(dst_k + off))[1] = 0xD65F03C0; // RET
            break;
        case SHADOW_JUMP_B: {
            long j_off = (long)preq->target_va - (long)va;
            *(uint32_t *)(dst_k + off) = 0x14000000 | ((j_off >> 2) & 0x03FFFFFF);
            break;
        }
        case SHADOW_STUB_IF: {
            const size_t STUB_OFF = 0xF00;
            if (STUB_OFF + 24 > PAGE_SIZE) return -EFAULT;
            uint32_t *stub = (uint32_t *)(dst_k + STUB_OFF);
            unsigned long stub_va = (va & PAGE_MASK) + STUB_OFF;
            stub[0] = 0xB9401C22; stub[1] = 0x7100045F; stub[2] = 0x54000040;
            stub[3] = preq->expected;
            stub[4] = 0x14000000 | (((long)va + 4 - (long)stub_va - 16) >> 2 & 0x03FFFFFF);
            stub[5] = 0xD65F03C0;
            *(uint32_t *)(dst_k + off) = 0x14000000 | (((long)stub_va - (long)va) >> 2 & 0x03FFFFFF);
            break;
        }
        default: return -EINVAL;
    }
    return 0;
}

/* ==========================================================
 * 3. 核心安装引擎：Snapshot 事务流
 * ========================================================== */

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct pid *pid_s;
    struct task_struct *tsk;
    struct mm_struct *mm;
    int i, ret = 0;
    struct shadow_slot **slots;

    resolve_notifier_symbols();

    pid_s = find_get_pid(req->tid);
    if (!pid_s) return -ESRCH;
    tsk = get_pid_task(pid_s, PIDTYPE_PID);
    if (!tsk) { put_pid(pid_s); return -ESRCH; }
    mm = get_task_mm(tsk);
    if (!mm) { put_task_struct(tsk); put_pid(pid_s); return -ESRCH; }

    slots = kcalloc(req->hook_count, sizeof(void *), GFP_KERNEL);
    if (!slots) { ret = -ENOMEM; goto out_mm; }

    /* --- 阶段 1：预处理 (无锁状态) --- */
    for (i = 0; i < req->hook_count; i++) {
        struct shadow_patch_req *preq = &req->hooks[i];
        unsigned long va = req->base_addr + preq->offset;
        struct page *old_p = NULL, *new_p = NULL;
        size_t off = va & ~PAGE_MASK;

        /* A. 拿页 (此时不持有游戏的 mmap_lock) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
        if (get_user_pages_remote(mm, va, 1, FOLL_FORCE, &old_p, NULL) <= 0) continue;
#else
        if (get_user_pages_remote(mm, va, 1, FOLL_FORCE, &old_p, NULL, NULL) <= 0) continue;
#endif

        /* B. 分配影子页 */
        new_p = alloc_page(GFP_HIGHUSER);
        if (!new_p) { put_page(old_p); continue; }

        /* C. 验证并拷贝内容 */
        u8 *src_k = kmap_local_page(old_p);
        if (*(uint32_t *)(src_k + off) != preq->expected) {
            wuwa_err("Verify mismatch at 0x%lx: exp %08x, got %08x\n", va, preq->expected, *(uint32_t *)(src_k + off));
            kunmap_local(src_k); put_page(old_p); __free_page(new_p);
            continue;
        }

        u8 *dst_k = kmap_local_page(new_p);
        memcpy(dst_k, src_k, PAGE_SIZE);

        if (construct_patch(dst_k, off, preq, va) < 0) {
            kunmap_local(dst_k); kunmap_local(src_k);
            put_page(old_p); __free_page(new_p); continue;
        }

        safe_sync_icache(dst_k, PAGE_SIZE);
        kunmap_local(dst_k); kunmap_local(src_k);

        /* D. 封装 Slot */
        slots[i] = kzalloc(sizeof(struct shadow_slot), GFP_KERNEL);
        if (!slots[i]) { __free_page(new_p); put_page(old_p); continue; }
        slots[i]->va = va; slots[i]->mm = mm;
        slots[i]->orig_page = old_p; slots[i]->shadow_page = new_p;
        refcount_set(&slots[i]->refs, 1); atomic_set(&slots[i]->state, 1);
        slots[i]->notifier.ops = &shadow_ops;
    }

    /* --- 阶段 2：原子替换 (最短锁持有时间) --- */
    if (mmap_write_lock_killable(mm)) {
        ret = -EINTR; goto out_free_slots;
    }

    for (i = 0; i < req->hook_count; i++) {
        if (!slots[i]) continue;
        
        struct shadow_slot *slot = slots[i];
        pmd_t *pmd = wuwa_walk_to_pmd(mm, slot->va);
        if (!pmd || pmd_leaf(*pmd)) continue;

        spinlock_t *ptl;
        pte_t *ptep = pte_offset_map_lock(mm, pmd, slot->va, &ptl);
        if (!ptep || !pte_present(*ptep)) {
            if (ptep) pte_unmap_unlock(ptep, ptl);
            continue;
        }

        /* 拒绝 ContPTE，不强拆，防闪退 */
        if (pte_val(*ptep) & (1ULL << 52)) {
            wuwa_warn("ContPTE detected at 0x%lx, skipping.\n", slot->va);
            pte_unmap_unlock(ptep, ptl);
            continue;
        }

        /* 执行掉包 */
        slot->old_pte = *ptep;
        u64 val = (pte_val(*ptep) & ~(PHYS_MASK & PAGE_MASK)) | (page_to_pfn(slot->shadow_page) << PAGE_SHIFT);
        WRITE_ONCE(*(u64 *)ptep, val);
        
        pte_unmap_unlock(ptep, ptl);
        safe_flush_tlb_page(slot->va);

        /* 记录事务 */
        if (xa_err(xa_store(&g_shadow_xa, (unsigned long)mm ^ slot->va, slot, GFP_KERNEL))) {
            /* 回滚 */
            ptep = pte_offset_map_lock(mm, pmd, slot->va, &ptl);
            WRITE_ONCE(*(u64 *)ptep, pte_val(slot->old_pte));
            pte_unmap_unlock(ptep, ptl);
            safe_flush_tlb_page(slot->va);
        } else {
            if (fn_mmu_notifier_register && !fn_mmu_notifier_register(&slot->notifier, mm))
                slot->registered = true;
            wuwa_info("Success: 0x%lx -> Shadow\n", slot->va);
        }
    }
    mmap_write_unlock(mm);

out_free_slots:
    /* 注意：成功的 slots 已经被加入 xa/notifier，此处只释放失败的或用于清理的临时指针 */
    kfree(slots);
out_mm:
    mmput(mm); put_task_struct(tsk); put_pid(pid_s);
    return ret;
}

/* ==========================================================
 * 4. 直连 Proc 接口
 * ========================================================== */

#define V18_IOCTL_CMD 0x5A5A9999

static long wuwa_v18_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct wuwa_hbp_req req;
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;
    if (cmd == V18_IOCTL_CMD) {
        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
        return wuwa_install_perf_hbp(&req);
    }
    return -ENOTTY;
}

static const struct proc_ops v18_fops = {
    .proc_ioctl = wuwa_v18_ioctl,
    .proc_compat_ioctl = wuwa_v18_ioctl,
};

static struct proc_dir_entry *wuwa_proc_entry = NULL;

int wuwa_stealth_init(void) {
    wuwa_proc_entry = proc_create("wuwa_v18", 0666, NULL, &v18_fops);
    if (!wuwa_proc_entry) return -ENOMEM;
    wuwa_info("V18.3 Snapshot Engine ready at /proc/wuwa_v18\n");
    return 0;
}

void wuwa_stealth_cleanup(void) {
    if (wuwa_proc_entry) proc_remove(wuwa_proc_entry);
    xa_destroy(&g_shadow_xa);
}

int wuwa_hbp_init_device(void) { return 0; }
void wuwa_hbp_cleanup_device(void) { }
void wuwa_cleanup_perf_hbp(void) { }
