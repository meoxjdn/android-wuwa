// SPDX-License-Identifier: GPL-2.0
/*
 * wuwa_perf_hbp.c — V18.9 "Supercell" 旗舰生产版 (编译终极修复)
 * * 核心特性：
 * 1. 修复 Action 3 丢失：显式硬编码处理 JUMP_B 逻辑。
 * 2. 暴力同步：引入 ic ialluis 指令级全局刷新，强制所有 CPU 核心重新加载指令。
 * 3. 事务隔离：Snapshot 模式，先准备物理页，锁内只做 8 字节 PTE 修改。
 * 4. 编译修复：移除 ARM64 不支持的 32位 bpiallis 指令，纯净 AArch64 架构兼容。
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

/* 外部符号定义 */
extern pmd_t *wuwa_walk_to_pmd(struct mm_struct *mm, unsigned long va);

/* 全局句柄 */
static struct proc_dir_entry *g_wuwa_proc = NULL;
static DEFINE_XARRAY(g_shadow_xa);

/* ==========================================================
 * 0. 架构级“核弹级”强制同步 (ARM64 Nuclear Sync)
 * ========================================================== */

static inline void nuclear_sync_all_cores(struct mm_struct *mm, unsigned long va) {
    unsigned long asid = 0;
    unsigned long addr_val;

#ifdef CONFIG_ARM64_ASID_BITS
    asid = (unsigned long)(atomic64_read(&mm->context.id) & 0xffff);
#endif
    addr_val = (asid << 48) | (va >> 12);

    /* 1. 强制数据同步屏障：确保前面的 PTE 写入已彻底落盘 */
    dsb(sy);
    
    /* 2. 精准 TLB 刷新 (vae1is): 带着 ASID 跨核心刷新翻译缓存 */
    __asm__ __volatile__ ("tlbi vae1is, %0" : : "r" (addr_val) : "memory");
    dsb(sy); /* 等待 TLBI 广播完成 */

    /* 3. 全局指令缓存作废 (ic ialluis)：强制所有核心丢弃 L1 I-Cache */
    /* ARM64 架构下，此指令会自动引发分支预测器(Branch Predictor)的同步 */
    __asm__ __volatile__ ("ic ialluis" : : : "memory");
    
    /* 4. 最终系统指令屏障：清空流水线，强制下一条指令重新取指 */
    dsb(sy);
    isb();
}

/* ==========================================================
 * 1. 影子槽位生命周期管理
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
 * 2. 补丁构造逻辑 (严查 JUMP_B 范围)
 * ========================================================== */

static int build_patch_instruction(u8 *dst_k, size_t off, struct shadow_patch_req *preq, unsigned long va) {
    if (off + 4 > PAGE_SIZE) return -EINVAL;

    switch (preq->action) {
        case 0: /* SHADOW_DATA_PATCH - 如 FOV 4.5f */
            *(uint32_t *)(dst_k + off) = preq->patch_val;
            pr_info("[wuwa] Data patch: 0x%08x applied at 0x%lx\n", preq->patch_val, va);
            break;

        case 1: /* SHADOW_RET_ONLY - 去黑边 */
            *(uint32_t *)(dst_k + off) = 0xD65F03C0; 
            break;

        case 2: /* SHADOW_HP_SET - 血量改 1 */
            if (off + 8 > PAGE_SIZE) return -EOVERFLOW;
            *(uint32_t *)(dst_k + off) = 0x52800020;     /* MOV W0, #1 */
            *(uint32_t *)(dst_k + off + 4) = 0xD65F03C0; /* RET */
            break;

        case 3: /* SHADOW_JUMP_B - 秒过 (关键修复) */
        {
            long j_off = (long)preq->target_va - (long)va;
            /* 检查 B 指令跳转极限：±128MB */
            if ((preq->target_va & 3) || (j_off < -134217728LL) || (j_off > 134217724LL)) {
                pr_err("[wuwa] B Jump target out of range! Target: 0x%llx, PC: 0x%lx\n", 
                       (unsigned long long)preq->target_va, va);
                return -ERANGE;
            }
            *(uint32_t *)(dst_k + off) = 0x14000000 | ((j_off >> 2) & 0x03FFFFFF);
            pr_info("[wuwa] Jump B patch: Target 0x%llx applied at 0x%lx\n", 
                    (unsigned long long)preq->target_va, va);
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

    /* 严格安全检查 */
    if (!req || req->hook_count == 0 || req->hook_count > 16) return -EINVAL;

    pid_s = find_get_pid(req->tid);
    if (!pid_s) return -ESRCH;
    tsk = get_pid_task(pid_s, PIDTYPE_PID);
    if (!tsk) { put_pid(pid_s); return -ESRCH; }
    mm = get_task_mm(tsk);
    if (!mm) { put_task_struct(tsk); put_pid(pid_s); return -ESRCH; }

    prep_slots = kcalloc(req->hook_count, sizeof(void *), GFP_KERNEL);
    if (!prep_slots) { ret = -ENOMEM; goto out_mm; }

    /* --- 阶段 A：锁外静默准备 --- */
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

    /* --- 阶段 B：秒级写锁掉包 --- */
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

        /* 掉包 PTE，将 PFN 改为影子页 */
        slot->old_pte = *ptep;
        u64 val = (pte_val(*ptep) & ~(PHYS_MASK & PAGE_MASK)) | (page_to_pfn(slot->shadow_page) << PAGE_SHIFT);
        WRITE_ONCE(*(u64 *)ptep, val);
        pte_unmap_unlock(ptep, ptl);

        /* ★ 核心：执行全核指令缓存同步 */
        nuclear_sync_all_cores(mm, slot->va);

        prep_slots[i] = NULL; 
        pr_info("[wuwa] V18.9 FINAL: Swapped VA 0x%lx with PFN %lx\n", slot->va, page_to_pfn(slot->shadow_page));
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
    /* 物理页随 MM 销毁回收，热卸载不回滚以保命 */
}

/* 占位符定义 */
int wuwa_hbp_init_device(void) { return 0; }
void wuwa_hbp_cleanup_device(void) { }
void wuwa_cleanup_perf_hbp(void) { }
