// SPDX-License-Identifier: GPL-2.0
/*
 * wuwa_perf_hbp.c — V18.12 "Absolute Power" 终极无删减版
 * * 修正说明：
 * 1. 补全 5 大 Action：0(DATA), 1(RET), 2(HP_SET), 3(JUMP_B), 4(STUB_IF).
 * 2. 增强校验日志：使用 pr_emerg 确保 Mismatch 日志在 dmesg 中最优先显示.
 * 3. 暴力缓存同步：保留核弹级 ic ialluis，对付 Android 15 指令预取.
 * 4. 事务级处理：确保 hook_count 每一个索引都被精准处理.
 */

#include <linux/version.h>
#include <linux/mm.h>
#include <linux/xarray.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/highmem.h>
#include <linux/refcount.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>

#include "wuwa_perf_hbp.h"
#include "../core/wuwa_common.h"

/* 外部符号声明 */
extern pmd_t *wuwa_walk_to_pmd(struct mm_struct *mm, unsigned long va);

/* 全局句柄 */
static struct proc_dir_entry *g_wuwa_proc = NULL;
static DEFINE_XARRAY(g_shadow_xa);

/* ==========================================================
 * 0. 架构级核弹刷新 (Force All Cores to Re-fetch)
 * ========================================================== */

static inline void nuclear_sync(struct mm_struct *mm, unsigned long va) {
    unsigned long asid = 0;
    unsigned long addr_val;

#ifdef CONFIG_ARM64_ASID_BITS
    asid = (unsigned long)(atomic64_read(&mm->context.id) & 0xffff);
#endif
    addr_val = (asid << 48) | (va >> 12);

    dsb(sy);
    /* 刷新所有核心的 TLB 缓存 */
    __asm__ __volatile__ ("tlbi vae1is, %0" : : "r" (addr_val) : "memory");
    dsb(sy);
    /* 刷新全局指令缓存，强制分支预测器重置 */
    __asm__ __volatile__ ("ic ialluis" : : : "memory");
    dsb(sy);
    isb();
}

/* ==========================================================
 * 1. 槽位对象
 * ========================================================== */

struct shadow_slot {
    unsigned long va;
    struct mm_struct *mm;
    struct page *orig_page;
    struct page *shadow_page;
    pte_t old_pte;
};

static void __free_slot_res(struct shadow_slot *slot) {
    if (!slot) return;
    if (slot->orig_page) put_page(slot->orig_page);
    if (slot->shadow_page) __free_page(slot->shadow_page);
    kfree(slot);
}

/* ==========================================================
 * 2. 补丁构造逻辑 (5大功能全家桶)
 * ========================================================== */

static int apply_patch_payload(u8 *dk, size_t off, struct shadow_patch_req *preq, unsigned long va) {
    if (off + 4 > PAGE_SIZE) return -EINVAL;

    switch (preq->action) {
        case 0: /* SHADOW_DATA_PATCH (全屏 4.5f) */
            *(uint32_t *)(dk + off) = preq->patch_val;
            break;

        case 1: /* SHADOW_RET_ONLY (去黑边) */
            *(uint32_t *)(dk + off) = 0xD65F03C0; 
            break;

        case 2: /* SHADOW_HP_SET (秒杀/血量) */
            if (off + 8 > PAGE_SIZE) return -EOVERFLOW;
            *(uint32_t *)(dk + off) = 0x52800020;     /* MOV W0, #1 */
            *(uint32_t *)(dk + off + 4) = 0xD65F03C0; /* RET */
            break;

        case 3: /* SHADOW_JUMP_B (秒过) */
        {
            long j_off = (long)preq->target_va - (long)va;
            if ((preq->target_va & 3) || (j_off < -134217728LL) || (j_off > 134217724LL)) {
                return -ERANGE;
            }
            *(uint32_t *)(dk + off) = 0x14000000 | ((j_off >> 2) & 0x03FFFFFF);
            break;
        }

        case 4: /* SHADOW_STUB_IF (无敌判断) */
        {
            const size_t ST_OFF = 0xF00;
            uint32_t *stub = (uint32_t *)(dk + ST_OFF);
            unsigned long s_va = (va & PAGE_MASK) + ST_OFF;
            if (ST_OFF + 24 > PAGE_SIZE) return -EFAULT;
            
            stub[0] = 0xB9401C22; /* LDR W2, [X1, #0x1C] */
            stub[1] = 0x7100045F; /* CMP W2, #1 */
            stub[2] = 0x54000040; /* B.EQ +8 */
            stub[3] = preq->expected; 
            stub[4] = 0x14000000 | (((long)va + 4 - (long)s_va - 16) >> 2 & 0x03FFFFFF);
            stub[5] = 0xD65F03C0;
            *(uint32_t *)(dk + off) = 0x14000000 | (((long)s_va - (long)va) >> 2 & 0x03FFFFFF);
            break;
        }
        default: return -EOPNOTSUPP;
    }
    return 0;
}

/* ==========================================================
 * 3. 核心安装引擎 (全功能扫描)
 * ========================================================== */

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct pid *pid_s; struct task_struct *tsk; struct mm_struct *mm;
    int i, ret = 0;
    struct shadow_slot **prep;

    if (!req || req->hook_count == 0 || req->hook_count > 16) return -EINVAL;

    pid_s = find_get_pid(req->tid);
    tsk = pid_s ? get_pid_task(pid_s, PIDTYPE_PID) : NULL;
    if (!tsk) { if (pid_s) put_pid(pid_s); return -ESRCH; }
    mm = get_task_mm(tsk);
    if (!mm) { put_task_struct(tsk); put_pid(pid_s); return -ESRCH; }

    prep = kcalloc(req->hook_count, sizeof(void *), GFP_KERNEL);
    if (!prep) { ret = -ENOMEM; goto out_mm; }

    /* --- 阶段 A：锁外深度克隆 --- */
    for (i = 0; i < req->hook_count; i++) {
        struct shadow_patch_req *preq = &req->hooks[i];
        unsigned long va = req->base_addr + preq->offset;
        struct page *op = NULL, *np = NULL;
        size_t off = va & ~PAGE_MASK;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
        if (get_user_pages_remote(mm, va, 1, FOLL_WRITE | FOLL_FORCE, &op, NULL) <= 0) continue;
#else
        if (get_user_pages_remote(mm, va, 1, FOLL_WRITE | FOLL_FORCE, &op, NULL, NULL) <= 0) continue;
#endif
        np = alloc_page(GFP_HIGHUSER);
        if (!np) { put_page(op); continue; }

        u8 *sk = kmap_local_page(op);
        if (*(uint32_t *)(sk + off) != preq->expected) {
            /* ★ 必改：一旦不匹配，直接紧急日志报错 */
            pr_emerg("[wuwa] CRITICAL Mismatch at 0x%lx: Exp %08x, Got %08x\n", va, preq->expected, *(uint32_t *)(sk + off));
            kunmap_local(sk); put_page(op); __free_page(np); continue;
        }

        u8 *dk = kmap_local_page(np);
        memcpy(dk, sk, PAGE_SIZE);
        
        if (apply_patch_payload(dk, off, preq, va) == 0) {
            flush_icache_range((unsigned long)dk, (unsigned long)dk + PAGE_SIZE);
            prep[i] = kzalloc(sizeof(struct shadow_slot), GFP_KERNEL);
            if (prep[i]) {
                prep[i]->va = va; prep[i]->mm = mm;
                prep_slots[i]->orig_page = op; prep[i]->shadow_page = np;
            }
        }
        kunmap_local(dk); kunmap_local(sk);
    }

    /* --- 阶段 B：锁内掉包 --- */
    if (mmap_write_lock_killable(mm)) { ret = -EINTR; goto out_clean; }

    for (i = 0; i < req->hook_count; i++) {
        if (!prep[i]) continue;
        
        pmd_t *pmd = wuwa_walk_to_pmd(mm, prep[i]->va);
        if (!pmd || pmd_leaf(*pmd)) continue;

        spinlock_t *ptl;
        pte_t *ptep = pte_offset_map_lock(mm, pmd, prep[i]->va, &ptl);
        if (ptep && pte_present(*ptep) && !(pte_val(*ptep) & (1ULL << 52))) {
            if (!xa_insert(&g_shadow_xa, (unsigned long)mm ^ prep[i]->va, prep[i], GFP_ATOMIC)) {
                u64 v = (pte_val(*ptep) & ~(PHYS_MASK & PAGE_MASK)) | (page_to_pfn(prep[i]->shadow_page) << PAGE_SHIFT);
                WRITE_ONCE(*(u64 *)ptep, v);
                nuclear_sync(mm, prep[i]->va);
                pr_info("[wuwa] V18.12 SUCCESS: Action %d applied at 0x%lx\n", req->hooks[i].action, prep[i]->va);
                prep[i] = NULL; /* 标记成功 */
            }
        }
        if (ptep) pte_unmap_unlock(ptep, ptl);
    }
    mmap_write_unlock(mm);

out_clean:
    for (i = 0; i < req->hook_count; i++) if (prep[i]) __free_slot_res(prep[i]);
    kfree(prep);
out_mm:
    mmput(mm); put_task_struct(tsk); put_pid(pid_s);
    return ret;
}

static long wuwa_v18_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct wuwa_hbp_req req;
    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
    return wuwa_install_perf_hbp(&req);
}

static const struct proc_ops v18_fops = { .proc_ioctl = wuwa_v18_ioctl, .proc_compat_ioctl = wuwa_v18_ioctl };

int wuwa_stealth_init(void) {
    g_wuwa_proc = proc_create("wuwa_v18", 0600, NULL, &v18_fops);
    return g_wuwa_proc ? 0 : -ENOMEM;
}

void wuwa_stealth_cleanup(void) { if (g_wuwa_proc) proc_remove(g_wuwa_proc); }

/* 占位符 */
void wuwa_cleanup_all_shadows(void) {}
int wuwa_hbp_init_device(void) { return 0; }
void wuwa_hbp_cleanup_device(void) { }
void wuwa_cleanup_perf_hbp(void) { }
