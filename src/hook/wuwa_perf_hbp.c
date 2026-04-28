// SPDX-License-Identifier: GPL-2.0
/*
 * wuwa_perf_hbp.c — V18.10 "Full Arsenal" 全武备补齐版
 * 修复：补齐了 Action 4 (SHADOW_STUB_IF) 的无敌存根逻辑。
 * 保持了 V18.9 的核弹级同步和编译兼容。
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

/* ==========================================================
 * 0. 强制全局同步 (ARM64 Nuclear Sync)
 * ========================================================== */

static inline void nuclear_sync_all_cores(struct mm_struct *mm, unsigned long va) {
    unsigned long asid = 0;
    unsigned long addr_val;

#ifdef CONFIG_ARM64_ASID_BITS
    asid = (unsigned long)(atomic64_read(&mm->context.id) & 0xffff);
#endif
    addr_val = (asid << 48) | (va >> 12);

    dsb(sy);
    __asm__ __volatile__ ("tlbi vae1is, %0" : : "r" (addr_val) : "memory");
    dsb(sy);
    /* 强刷 I-Cache，让所有 CPU 读新指令 */
    __asm__ __volatile__ ("ic ialluis" : : : "memory");
    dsb(sy);
    isb();
}

/* ==========================================================
 * 1. 影子生命周期管理
 * ========================================================== */

struct shadow_slot {
    unsigned long va;
    struct mm_struct *mm;
    struct page *orig_page;
    struct page *shadow_page;
    pte_t old_pte;
};

static void __release_slot(struct shadow_slot *slot) {
    if (!slot) return;
    if (slot->orig_page) put_page(slot->orig_page);
    if (slot->shadow_page) __free_page(slot->shadow_page);
    kfree(slot);
}

/* ==========================================================
 * 2. 补丁构造逻辑 (补齐 Action 4)
 * ========================================================== */

static int build_patch_instruction(u8 *dst_k, size_t off, struct shadow_patch_req *preq, unsigned long va) {
    if (off + 4 > PAGE_SIZE) return -EINVAL;

    switch (preq->action) {
        case 0: /* SHADOW_DATA_PATCH */
            *(uint32_t *)(dst_k + off) = preq->patch_val;
            pr_info("[wuwa] Action 0 (Data) applied at 0x%lx\n", va);
            break;

        case 1: /* SHADOW_RET_ONLY */
            *(uint32_t *)(dst_k + off) = 0xD65F03C0; 
            pr_info("[wuwa] Action 1 (RET) applied at 0x%lx\n", va);
            break;

        case 2: /* SHADOW_HP_SET - 血量改 1 */
            if (off + 8 > PAGE_SIZE) return -EOVERFLOW;
            *(uint32_t *)(dst_k + off) = 0x52800020;     
            *(uint32_t *)(dst_k + off + 4) = 0xD65F03C0; 
            pr_info("[wuwa] Action 2 (HP_1) applied at 0x%lx\n", va);
            break;

        case 3: /* SHADOW_JUMP_B - 秒过 */
        {
            long j_off = (long)preq->target_va - (long)va;
            if ((preq->target_va & 3) || (j_off < -134217728LL) || (j_off > 134217724LL)) {
                pr_err("[wuwa] B Jump target out of range! Target: 0x%llx, PC: 0x%lx\n", 
                       (unsigned long long)preq->target_va, va);
                return -ERANGE;
            }
            *(uint32_t *)(dst_k + off) = 0x14000000 | ((j_off >> 2) & 0x03FFFFFF);
            pr_info("[wuwa] Action 3 (JUMP_B) applied at 0x%lx\n", va);
            break;
        }

        case 4: /* SHADOW_STUB_IF - 无敌判断存根 (大牛最需要的) */
        {
            const size_t STUB_OFF = 0xF00;
            if (STUB_OFF + 24 > PAGE_SIZE) return -EFAULT;
            
            uint32_t *stub = (uint32_t *)(dst_k + STUB_OFF);
            unsigned long stub_va = (va & PAGE_MASK) + STUB_OFF;
            
            /* 无敌判断存根汇编: 过滤自己的伤害 */
            stub[0] = 0xB9401C22; // LDR W2, [X1, #0x1C]
            stub[1] = 0x7100045F; // CMP W2, #1
            stub[2] = 0x54000040; // B.EQ +8 (跳过原始指令)
            stub[3] = preq->expected; // 还原游戏真实指令
            /* 跳回原函数的下一行 */
            stub[4] = 0x14000000 | (((long)va + 4 - (long)stub_va - 16) >> 2 & 0x03FFFFFF);
            stub[5] = 0xD65F03C0; // RET
            
            /* 修改入口点跳转到存根 */
            *(uint32_t *)(dst_k + off) = 0x14000000 | (((long)stub_va - (long)va) >> 2 & 0x03FFFFFF);
            pr_info("[wuwa] Action 4 (STUB_IF) applied at 0x%lx\n", va);
            break;
        }

        default:
            pr_err("[wuwa] UNKNOWN ACTION TYPE: %d\n", preq->action);
            return -EOPNOTSUPP;
    }
    return 0;
}

/* ==========================================================
 * 3. 终极安装引擎 (Snapshot 事务)
 * ========================================================== */

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct pid *pid_s;
    struct task_struct *tsk;
    struct mm_struct *mm;
    int i, ret = 0;
    struct shadow_slot **prep_slots;

    if (!req || req->hook_count == 0 || req->hook_count > 16) return -EINVAL;

    pid_s = find_get_pid(req->tid);
    if (!pid_s) return -ESRCH;
    tsk = get_pid_task(pid_s, PIDTYPE_PID);
    if (!tsk) { put_pid(pid_s); return -ESRCH; }
    mm = get_task_mm(tsk);
    if (!mm) { put_task_struct(tsk); put_pid(pid_s); return -ESRCH; }

    prep_slots = kcalloc(req->hook_count, sizeof(void *), GFP_KERNEL);
    if (!prep_slots) { ret = -ENOMEM; goto out_mm; }

    /* 阶段 A：静默预处理 */
    for (i = 0; i < req->hook_count; i++) {
        struct shadow_patch_req *preq = &req->hooks[i];
        unsigned long va = req->base_addr + preq->offset;
        struct page *old_p = NULL, *new_p = NULL;
        size_t off = va & ~PAGE_MASK;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
        if (get_user_pages_remote(mm, va, 1, FOLL_WRITE | FOLL_FORCE, &old_p, NULL) <= 0) continue;
#else
        if (get_user_pages_remote(mm, va, 1, FOLL_WRITE | FOLL_FORCE, &old_p, NULL, NULL) <= 0) continue;
#endif
        new_p = alloc_page(GFP_HIGHUSER);
        if (!new_p) { put_page(old_p); continue; }

        u8 *src_k = kmap_local_page(old_p);
        if (*(uint32_t *)(src_k + off) != preq->expected) {
            pr_err("[wuwa] Mismatch at 0x%lx: Exp %08x, Got %08x\n", va, preq->expected, *(uint32_t *)(src_k + off));
            kunmap_local(src_k); put_page(old_p); __free_page(new_p);
            continue;
        }

        u8 *dst_k = kmap_local_page(new_p);
        memcpy(dst_k, src_k, PAGE_SIZE);
        
        if (build_patch_instruction(dst_k, off, preq, va) < 0) {
            kunmap_local(dst_k); kunmap_local(src_k);
            put_page(old_p); __free_page(new_p);
            continue;
        }

        kunmap_local(dst_k); kunmap_local(src_k);

        prep_slots[i] = kzalloc(sizeof(struct shadow_slot), GFP_KERNEL);
        if (!prep_slots[i]) { put_page(old_p); __free_page(new_p); continue; }
        prep_slots[i]->va = va; prep_slots[i]->mm = mm;
        prep_slots[i]->orig_page = old_p; prep_slots[i]->shadow_page = new_p;
    }

    /* 阶段 B：秒级掉包与核弹刷新 */
    if (mmap_write_lock_killable(mm)) { ret = -EINTR; goto out_cleanup; }

    for (i = 0; i < req->hook_count; i++) {
        struct shadow_slot *slot = prep_slots[i];
        if (!slot) continue;

        if (xa_insert(&g_shadow_xa, (unsigned long)mm ^ slot->va, slot, GFP_ATOMIC)) continue;

        pmd_t *pmd = wuwa_walk_to_pmd(mm, slot->va);
        if (!pmd || pmd_leaf(*pmd)) { xa_erase(&g_shadow_xa, (unsigned long)mm ^ slot->va); continue; }

        spinlock_t *ptl;
        pte_t *ptep = pte_offset_map_lock(mm, pmd, slot->va, &ptl);
        if (!ptep || !pte_present(*ptep) || (pte_val(*ptep) & (1ULL << 52))) {
            if (ptep) pte_unmap_unlock(ptep, ptl);
            xa_erase(&g_shadow_xa, (unsigned long)mm ^ slot->va);
            continue;
        }

        slot->old_pte = *ptep;
        u64 val = (pte_val(*ptep) & ~(PHYS_MASK & PAGE_MASK)) | (page_to_pfn(slot->shadow_page) << PAGE_SHIFT);
        WRITE_ONCE(*(u64 *)ptep, val);
        pte_unmap_unlock(ptep, ptl);

        /* 核弹同步：所有 CPU 放弃抵抗，装载新代码 */
        nuclear_sync_all_cores(mm, slot->va);

        prep_slots[i] = NULL; 
        pr_info("[wuwa] V18.10 FINAL: Swapped VA 0x%lx with PFN %lx\n", slot->va, page_to_pfn(slot->shadow_page));
    }
    mmap_write_unlock(mm);

out_cleanup:
    for (i = 0; i < req->hook_count; i++) {
        if (prep_slots[i]) __release_slot(prep_slots[i]);
    }
    kfree(prep_slots);
out_mm:
    mmput(mm); put_task_struct(tsk); put_pid(pid_s);
    return ret;
}

/* ==========================================================
 * 4. 通信接口与初始化
 * ========================================================== */

#define V18_IOCTL_CMD 0x5A5A9999

static long wuwa_v18_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct wuwa_hbp_req req;
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

int wuwa_stealth_init(void) {
    g_wuwa_proc = proc_create("wuwa_v18", 0600, NULL, &v18_fops);
    if (!g_wuwa_proc) return -ENOMEM;
    return 0;
}

void wuwa_stealth_cleanup(void) {
    if (g_wuwa_proc) proc_remove(g_wuwa_proc);
}

int wuwa_hbp_init_device(void) { return 0; }
void wuwa_hbp_cleanup_device(void) { }
void wuwa_cleanup_perf_hbp(void) { }
