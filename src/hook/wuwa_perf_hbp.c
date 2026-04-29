// SPDX-License-Identifier: GPL-2.0
/*
 * wuwa_perf_hbp.c — V18.18 "Pure God" 纯净展开版
 * * 修正说明：
 * 1. 彻底清空所有历史遗留的判断垃圾。
 * 2. 将用户提供的 7 条 God Mode 精准汇编直接写入核心路由 (Action 3)。
 * 3. 100% 全量源码，0 删减，不省略任何逻辑和日志！
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

extern pmd_t *wuwa_walk_to_pmd(struct mm_struct *mm, unsigned long va);

static struct proc_dir_entry *g_wuwa_proc = NULL;
static DEFINE_XARRAY(g_shadow_xa);

static inline void nuclear_sync_all_cores(struct mm_struct *mm, unsigned long va) 
{
    unsigned long asid = 0;
    unsigned long addr_val;

#ifdef CONFIG_ARM64_ASID_BITS
    asid = (unsigned long)(atomic64_read(&mm->context.id) & 0xffff);
#endif
    addr_val = (asid << 48) | (va >> 12);
    
    dsb(sy);
    __asm__ __volatile__ ("tlbi vae1is, %0" : : "r" (addr_val) : "memory");
    __asm__ __volatile__ ("ic ialluis" : : : "memory");
    dsb(sy);
    isb();
}

struct shadow_slot {
    unsigned long va;
    struct mm_struct *mm;
    struct page *orig_page;
    struct page *shadow_page;
    pte_t old_pte;
};

static void __release_slot(struct shadow_slot *slot) {
    if (!slot) {
        return;
    }
    if (slot->orig_page) {
        put_page(slot->orig_page);
    }
    if (slot->shadow_page) {
        __free_page(slot->shadow_page);
    }
    kfree(slot);
}

static int build_patch_instruction(u8 *dst_k, size_t off, struct shadow_patch_req *preq, unsigned long va) 
{
    if (off + 4 > PAGE_SIZE) {
        return -EINVAL;
    }

    switch (preq->action) {
        case 0: /* SHADOW_DATA_PATCH */
            *(uint32_t *)(dst_k + off) = preq->patch_val;
            pr_info("[wuwa] Action 0 (Data Patch) applied at 0x%lx\n", va);
            break;

        case 1: /* SHADOW_RET_ONLY */
            *(uint32_t *)(dst_k + off) = 0xD65F03C0; 
            pr_info("[wuwa] Action 1 (RET Only) applied at 0x%lx\n", va);
            break;

        case 2: /* SHADOW_JUMP_B (秒过) */
        {
            long j_off = (long)preq->target_va - (long)va;
            if ((preq->target_va & 3) || (j_off < -134217728LL) || (j_off > 134217724LL)) {
                pr_err("[wuwa] Action 2 B Jump target out of range! Target: 0x%llx\n", (unsigned long long)preq->target_va);
                return -ERANGE;
            }
            *(uint32_t *)(dst_k + off) = 0x14000000 | ((j_off >> 2) & 0x03FFFFFF);
            pr_info("[wuwa] Action 2 (JUMP_B) applied at 0x%lx\n", va);
            break;
        }

        case 3: /* ★ SHADOW_GOD_MODE (用户的终极精准汇编) ★ */
        {
            const size_t STUB_OFF = 0xF00; 
            uint32_t *stub = (uint32_t *)(dst_k + STUB_OFF);
            unsigned long s_va = (va & PAGE_MASK) + STUB_OFF;
            
            if (STUB_OFF + 28 > PAGE_SIZE) {
                pr_err("[wuwa] Action 3 God Mode stub out of bounds!\n");
                return -EFAULT;
            }

            /* 严丝合缝对齐你的 god_sc[7] 数组逻辑 */
            stub[0] = 0xB40000A1;     /* 0: CBZ X1, +20 (若X1为空，跳到[5]原指令) */
            stub[1] = 0xB9401C30;     /* 4: LDR W16, [X1, #0x1C] (读取TeamID) */
            stub[2] = 0x35000070;     /* 8: CBNZ W16, +12 (若不是0敌人，跳到[5]原指令) */
            stub[3] = 0x52800020;     /* C: MOV W0, #1 (若是0玩家，锁定伤害为1) */
            stub[4] = 0xD65F03C0;     /* 10: RET (玩家受击直接返回) */
            stub[5] = preq->expected; /* 14: [ORIG_INS] 原指令 */

            /* 18: B GOD+4 (跳回主逻辑流) */
            long j_back = ((long)va + 4) - ((long)s_va + 24);
            stub[6] = 0x14000000 | ((j_back >> 2) & 0x03FFFFFF);

            /* 在原地址写入飞往蹦床的 B 指令 */
            *(uint32_t *)(dst_k + off) = 0x14000000 | (((long)s_va - (long)va) >> 2 & 0x03FFFFFF);
            
            pr_info("[wuwa] Action 3 (Ultimate God Mode) deployed perfectly at 0x%lx\n", va);
            break;
        }

        case 4: /* SHADOW_DOUBLE_PATCH (去黑边双指令) */
            if (off + 8 > PAGE_SIZE) {
                return -EOVERFLOW;
            }
            *(uint32_t *)(dst_k + off) = preq->patch_val;
            *(uint32_t *)(dst_k + off + 4) = preq->patch_val_2;
            pr_info("[wuwa] Action 4 (Double Patch) applied at 0x%lx\n", va);
            break;

        case 5: /* SHADOW_SAFE_HP_STUB (秒杀蹦床) */
        {
            const size_t STUB_OFF = 0xF00; 
            uint32_t *stub = (uint32_t *)(dst_k + STUB_OFF);
            unsigned long s_va = (va & PAGE_MASK) + STUB_OFF;
            if (STUB_OFF + 8 > PAGE_SIZE) {
                return -EFAULT;
            }
            
            stub[0] = 0x52800020; /* MOV W0, #1 */
            stub[1] = 0xD65F03C0; /* RET */
            *(uint32_t *)(dst_k + off) = 0x14000000 | (((long)s_va - (long)va) >> 2 & 0x03FFFFFF);
            pr_info("[wuwa] Action 5 (Safe HP Trampoline) applied at 0x%lx\n", va);
            break;
        }

        case 6: /* SHADOW_FLOAT_RET (全屏浮点) */
        {
            if (off + 12 > PAGE_SIZE) {
                return -EOVERFLOW;
            }
            *(uint32_t *)(dst_k + off) = 0x1C000040;     /* LDR S0, [PC, #8] */
            *(uint32_t *)(dst_k + off + 4) = 0xD65F03C0; /* RET */
            *(uint32_t *)(dst_k + off + 8) = preq->patch_val; 
            pr_info("[wuwa] Action 6 (Float Ret) applied at 0x%lx, val: 0x%08x\n", va, preq->patch_val);
            break;
        }

        default:
            pr_err("[wuwa] UNKNOWN ACTION TYPE: %d\n", preq->action);
            return -EOPNOTSUPP;
    }
    return 0;
}

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) 
{
    struct pid *pid_s; 
    struct task_struct *tsk; 
    struct mm_struct *mm;
    int i, ret = 0;
    struct shadow_slot **prep_slots;

    if (!req || req->hook_count == 0 || req->hook_count > 16) {
        pr_err("[wuwa] Invalid hook request parameters.\n");
        return -EINVAL;
    }

    pid_s = find_get_pid(req->tid);
    if (!pid_s) {
        pr_err("[wuwa] Cannot find PID %d\n", req->tid);
        return -ESRCH;
    }

    tsk = get_pid_task(pid_s, PIDTYPE_PID);
    if (!tsk) { 
        put_pid(pid_s); 
        pr_err("[wuwa] Cannot get task struct for PID %d\n", req->tid);
        return -ESRCH; 
    }

    mm = get_task_mm(tsk);
    if (!mm) { 
        put_task_struct(tsk); 
        put_pid(pid_s); 
        pr_err("[wuwa] Cannot get mm_struct for PID %d\n", req->tid);
        return -ESRCH; 
    }

    prep_slots = kcalloc(req->hook_count, sizeof(void *), GFP_KERNEL);
    if (!prep_slots) { 
        pr_err("[wuwa] Failed to allocate prep_slots array.\n");
        ret = -ENOMEM; 
        goto out_mm; 
    }

    /* --- 阶段 A：锁外深度克隆 --- */
    for (i = 0; i < req->hook_count; i++) {
        struct shadow_patch_req *preq = &req->hooks[i];
        unsigned long va = req->base_addr + preq->offset;
        struct page *old_p = NULL;
        struct page *new_p = NULL;
        size_t off = va & ~PAGE_MASK;
        u8 *src_k = NULL;
        u8 *dst_k = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
        if (get_user_pages_remote(mm, va, 1, FOLL_WRITE | FOLL_FORCE, &old_p, NULL) <= 0) {
            pr_err("[wuwa] get_user_pages_remote failed at 0x%lx\n", va);
            continue;
        }
#else
        if (get_user_pages_remote(mm, va, 1, FOLL_WRITE | FOLL_FORCE, &old_p, NULL, NULL) <= 0) {
            pr_err("[wuwa] get_user_pages_remote failed at 0x%lx\n", va);
            continue;
        }
#endif

        new_p = alloc_page(GFP_HIGHUSER);
        if (!new_p) { 
            pr_err("[wuwa] alloc_page failed for shadow page.\n");
            put_page(old_p); 
            continue; 
        }

        src_k = kmap_local_page(old_p);
        if (*(uint32_t *)(src_k + off) != preq->expected) {
            pr_emerg("[wuwa] CRITICAL Mismatch at 0x%lx: Exp %08x, Got %08x\n", 
                     va, preq->expected, *(uint32_t *)(src_k + off));
            kunmap_local(src_k); 
            put_page(old_p); 
            __free_page(new_p); 
            continue;
        }

        dst_k = kmap_local_page(new_p);
        memcpy(dst_k, src_k, PAGE_SIZE);
        
        if (build_patch_instruction(dst_k, off, preq, va) == 0) {
            flush_icache_range((unsigned long)dst_k, (unsigned long)dst_k + PAGE_SIZE);
            prep_slots[i] = kzalloc(sizeof(struct shadow_slot), GFP_KERNEL);
            if (prep_slots[i]) {
                prep_slots[i]->va = va; 
                prep_slots[i]->mm = mm;
                prep_slots[i]->orig_page = old_p; 
                prep_slots[i]->shadow_page = new_p;
            } else {
                pr_err("[wuwa] kzalloc failed for shadow_slot.\n");
                put_page(old_p); 
                __free_page(new_p);
            }
        } else {
            pr_err("[wuwa] build_patch_instruction failed at 0x%lx\n", va);
            put_page(old_p); 
            __free_page(new_p);
        }

        kunmap_local(dst_k); 
        kunmap_local(src_k);
    }

    /* --- 阶段 B：锁内极速掉包 --- */
    if (mmap_write_lock_killable(mm)) { 
        pr_err("[wuwa] mmap_write_lock_killable interrupted.\n");
        ret = -EINTR; 
        goto out_clean; 
    }

    for (i = 0; i < req->hook_count; i++) {
        struct shadow_slot *slot = prep_slots[i];
        pmd_t *pmd; 
        spinlock_t *ptl; 
        pte_t *ptep; 
        u64 val;

        if (!slot) {
            continue;
        }
        
        if (xa_insert(&g_shadow_xa, (unsigned long)mm ^ slot->va, slot, GFP_ATOMIC)) {
            pr_err("[wuwa] xa_insert failed for va 0x%lx\n", slot->va);
            continue;
        }

        pmd = wuwa_walk_to_pmd(mm, slot->va);
        if (!pmd || pmd_leaf(*pmd)) { 
            pr_err("[wuwa] wuwa_walk_to_pmd failed for va 0x%lx\n", slot->va);
            xa_erase(&g_shadow_xa, (unsigned long)mm ^ slot->va); 
            continue; 
        }

        ptep = pte_offset_map_lock(mm, pmd, slot->va, &ptl);
        if (!ptep || !pte_present(*ptep) || (pte_val(*ptep) & (1ULL << 52))) {
            pr_err("[wuwa] Target PTE not present or protected by ContPTE at 0x%lx\n", slot->va);
            if (ptep) {
                pte_unmap_unlock(ptep, ptl);
            }
            xa_erase(&g_shadow_xa, (unsigned long)mm ^ slot->va);
            continue;
        }

        slot->old_pte = *ptep;
        val = (pte_val(*ptep) & ~(PHYS_MASK & PAGE_MASK)) | (page_to_pfn(slot->shadow_page) << PAGE_SHIFT);
        WRITE_ONCE(*(u64 *)ptep, val);
        pte_unmap_unlock(ptep, ptl);

        nuclear_sync_all_cores(mm, slot->va);

        pr_info("[wuwa] V18.18 SUCCESS: Hook slot %d fully deployed at 0x%lx\n", i, slot->va);
        prep_slots[i] = NULL; 
    }
    mmap_write_unlock(mm);

out_clean:
    for (i = 0; i < req->hook_count; i++) {
        if (prep_slots[i]) {
            __release_slot(prep_slots[i]);
        }
    }
    kfree(prep_slots);

out_mm:
    mmput(mm); 
    put_task_struct(tsk); 
    put_pid(pid_s);
    return ret;
}

#define V18_IOCTL_CMD 0x5A5A9999

static long wuwa_v18_ioctl(struct file *file, unsigned int cmd, unsigned long arg) 
{
    struct wuwa_hbp_req req;
    
    if (cmd == V18_IOCTL_CMD) {
        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
            pr_err("[wuwa] copy_from_user failed in ioctl.\n");
            return -EFAULT;
        }
        return wuwa_install_perf_hbp(&req);
    }
    return -ENOTTY;
}

static const struct proc_ops v18_fops = { 
    .proc_ioctl = wuwa_v18_ioctl, 
    .proc_compat_ioctl = wuwa_v18_ioctl 
};

int wuwa_stealth_init(void) 
{
    g_wuwa_proc = proc_create("wuwa_v18", 0600, NULL, &v18_fops);
    if (!g_wuwa_proc) {
        pr_err("[wuwa] Init Failed!\n");
        return -ENOMEM;
    }
    pr_info("[wuwa] V18.18 God Mode Engine Initialized.\n");
    return 0;
}

void wuwa_stealth_cleanup(void) 
{ 
    if (g_wuwa_proc) {
        proc_remove(g_wuwa_proc); 
        g_wuwa_proc = NULL;
    }
}

void wuwa_cleanup_all_shadows(void) 
{
    pr_info("[wuwa] Shadows retained for process stability upon exit.\n");
}

int wuwa_hbp_init_device(void) 
{ 
    pr_info("[wuwa] Dummy device init called.\n");
    return 0; 
}

void wuwa_hbp_cleanup_device(void) 
{ 
    pr_info("[wuwa] Dummy device cleanup called.\n");
}

void wuwa_cleanup_perf_hbp(void) 
{ 
    pr_info("[wuwa] Perf HBP dummy cleanup called.\n");
}
