// SPDX-License-Identifier: GPL-2.0
/*
 * wuwa_perf_hbp.c — V18 事务级静态影子内存引擎 (终极点火版)
 */

#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/xarray.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/uaccess.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include "wuwa_perf_hbp.h"
#include "../core/wuwa_common.h"

extern pmd_t *wuwa_walk_to_pmd(struct mm_struct *mm, unsigned long va);

struct shadow_slot {
    unsigned long va;
    struct page *orig_page;
    struct page *shadow_page;
    struct mm_struct *mm;
    struct mmu_notifier notifier;
    pte_t old_pte;
    refcount_t refs;
    atomic_t state; /* 1: ACTIVE, 0: DYING */
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
            set_pte_at(mm, start + (i * PAGE_SIZE), &ptep[i], __pte(pte_val(pte) & ~(1ULL << 52)));
        }
    }
    pte_unmap_unlock(ptep, ptl);
    flush_tlb_mm_range(mm, start, start + (PAGE_SIZE * 16), PAGE_SHIFT, false);
    return 0;
}

/* ==========================================================
 * 3. 诊断查询 IOCTL：按需诊断，避免 VFS Hook 复杂度
 * ========================================================== */
int wuwa_diag_shadow_slot(struct wuwa_diag_req *req) {
    struct shadow_slot *slot;
    unsigned long key = (unsigned long)current->mm ^ req->va;
    int ret = -ENOENT;

    rcu_read_lock();
    slot = xa_load(&g_shadow_xa, key);
    if (slot && atomic_read(&slot->state) == 1) {
        if (refcount_inc_not_zero(&slot->refs)) {
            if (atomic_read(&slot->state) == 1) {
                size_t off = req->va & ~PAGE_MASK;
                u8 *k_shadow = kmap_local_page(slot->shadow_page);
                req->current_inst = *(uint32_t *)(k_shadow + off);
                req->ref_count = refcount_read(&slot->refs);
                req->state = 1;
                kunmap_local(k_shadow);
                ret = 0;
            }
            slot_put(slot);
        }
    }
    rcu_read_unlock();
    return ret;
}

/* ==========================================================
 * 4. 核心安装引擎：全路径失败回滚 + PTE 语义克隆
 * ========================================================== */
int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct pid *pid_s = find_get_pid(req->tid);
    struct task_struct *tsk;
    struct mm_struct *mm;
    int i, ret = 0;

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

        /* 1. 安检：边界与 4 字节指令对齐 */
        if ((va & 3) || (off + 4 > PAGE_SIZE)) {
            wuwa_err("Alignment or boundary check failed for 0x%lx\n", va);
            continue;
        }

        /* 2. 物理准备：强制 COW 获取原始页 */
        if (get_user_pages_remote(mm, va, 1, FOLL_WRITE | FOLL_FORCE, &old_p, NULL, NULL) <= 0) continue;
        new_p = alloc_page(GFP_HIGHUSER);
        if (!new_p) { put_page(old_p); continue; }

        /* 3. 保险丝：预期原始指令比对 */
        u8 *src_k = kmap_local_page(old_p);
        if (*(uint32_t *)(src_k + off) != preq->expected) {
            wuwa_err("Verify mismatch at 0x%lx: exp %08x, got %08x\n", va, preq->expected, *(uint32_t *)(src_k + off));
            kunmap_local(src_k); put_page(old_p); __free_page(new_p);
            continue;
        }

        /* 4. 打入补丁与缓存刷新 */
        u8 *dst_k = kmap_local_page(new_p);
        memcpy(dst_k, src_k, PAGE_SIZE);

        switch (preq->action) {
            case SHADOW_DATA_PATCH:
                *(uint32_t *)(dst_k + off) = preq->patch_val; break;
            case SHADOW_RET_ONLY:
                *(uint32_t *)(dst_k + off) = 0xD65F03C0; break;
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
                stub[0] = 0xB9401C22; // ldr w2, [x1, #0x1c]
                stub[1] = 0x7100045F; // cmp w2, #1
                stub[2] = 0x54000040; // b.eq (.is_invincible)
                stub[3] = preq->expected; 
                stub[4] = 0x14000000 | (((long)va + 4 - (long)stub_va - 16) >> 2 & 0x03FFFFFF); // ret origin
                stub[5] = 0xD65F03C0; // ret (.is_invincible)
                *(uint32_t *)(dst_k + off) = 0x14000000 | (((long)stub_va - (long)va) >> 2 & 0x03FFFFFF);
                break;
            }
        }
        flush_icache_range((unsigned long)dst_k, (unsigned long)dst_k + PAGE_SIZE);
        kunmap_local(dst_k); kunmap_local(src_k);

        /* 5. 锁外初始化与 Notifier 注册 */
        slot = kzalloc(sizeof(*slot), GFP_KERNEL);
        if (!slot) { __free_page(new_p); put_page(old_p); continue; }
        slot->va = va; slot->mm = mm; slot->orig_page = old_p; slot->shadow_page = new_p;
        refcount_set(&slot->refs, 1); atomic_set(&slot->state, 1);
        slot->notifier.ops = &shadow_ops;

        if (mmu_notifier_register(&slot->notifier, mm)) { kfree(slot); __free_page(new_p); put_page(old_p); continue; }

        /* 6. 页表手术 (事务起点) */
        mmap_read_lock(mm);
        pmd_t *pmd = wuwa_walk_to_pmd(mm, va);
        if (!pmd || pmd_leaf(*pmd) || pmd_trans_huge(*pmd)) { ret = -EFAULT; goto err_rollback; }

        /* ContPTE 安全检查与处理 */
        ptep = pte_offset_map_lock(mm, pmd, va, &ptl);
        bool is_cont = (ptep && (pte_val(*ptep) & (1ULL << 52)));
        if (ptep) pte_unmap_unlock(ptep, ptl);
        
        if (is_cont) {
            if (unfold_cont_group(mm, va, pmd) != 0) { ret = -EAGAIN; goto err_rollback; }
        }

        /* 拒绝非用户/非正常页 */
        ptep = pte_offset_map_lock(mm, pmd, va, &ptl);
        if (!ptep || !pte_present(*ptep) || pte_special(*ptep)) {
            if (ptep) pte_unmap_unlock(ptep, ptl);
            ret = -ENOENT; goto err_rollback;
        }

        /* 基因替换 */
        old_pte = *ptep;
        slot->old_pte = old_pte;
        u64 val = (pte_val(old_pte) & ~(PHYS_MASK & PAGE_MASK)) | (page_to_pfn(new_p) << PAGE_SHIFT);
        set_pte_at(mm, va, ptep, __pte(val & ~(1ULL << 52)));
        pte_unmap_unlock(ptep, ptl);
        flush_tlb_mm_range(mm, va, va + PAGE_SIZE, PAGE_SHIFT, false);
        pte_applied = true;

        /* 7. 索引落盘 (事务终点) */
        if (xa_err(xa_store(&g_shadow_xa, (unsigned long)mm ^ va, slot, GFP_KERNEL))) {
            ret = -ENOSPC; goto err_rollback;
        }

        mmap_read_unlock(mm);
        continue; // 成功，继续处理下一个 Hook

err_rollback:
        /* 事务倒车：还原 PTE 避免 UAF */
        if (pte_applied) {
            ptep = pte_offset_map_lock(mm, pmd, va, &ptl);
            if (ptep) {
                set_pte_at(mm, va, ptep, slot->old_pte);
                pte_unmap_unlock(ptep, ptl);
                flush_tlb_mm_range(mm, va, va + PAGE_SIZE, PAGE_SHIFT, false);
            }
        }
        mmap_read_unlock(mm);
        mmu_notifier_unregister(&slot->notifier, mm);
        kfree(slot);
        __free_page(new_p);
        put_page(old_p);
    }

    mmput(mm); put_task_struct(tsk); put_pid(pid_s);
    return ret;
}

/* 兼容原始的导出与注销 */
int wuwa_hbp_init_device(void) { return 0; }
void wuwa_hbp_cleanup_device(void) { /* 生命周期已交由 mmu_notifier 自动管理 */ }
void wuwa_cleanup_perf_hbp(void) { }
