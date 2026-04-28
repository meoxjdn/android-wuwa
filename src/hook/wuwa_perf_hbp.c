// SPDX-License-Identifier: GPL-2.0
/*
 * wuwa_perf_hbp.c — V18.6 "Hardened Core" 
 * * 核心设计准则：
 * 1. 绝对锁序：mmap_write_lock 内部严禁任何可能睡眠的操作 (No GFP_KERNEL, No Notifier Register).
 * 2. 内存安全：放弃不切实际的热卸载 PTE 回滚，改为“点火即锁定”，重启即清场，杜绝 UAF 蓝屏。
 * 3. 架构兼容：针对 ARM64 BTI/PAC 保护环境，保留函数入口第一条指令，从 +4 偏移开始平账拦截。
 * 4. 权限收紧：Proc 节点权限设为 0600，仅限 Root 读写，最大化隐蔽性。
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
#include <linux/refcount.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>

#include "wuwa_perf_hbp.h"
#include "../core/wuwa_common.h"

/* 外部内核工具函数 */
extern pmd_t *wuwa_walk_to_pmd(struct mm_struct *mm, unsigned long va);

/* 全局句柄 */
static struct proc_dir_entry *g_wuwa_proc = NULL;
static DEFINE_XARRAY(g_shadow_xa);

/* ==========================================================
 * 0. 影子槽位数据结构
 * ========================================================== */

struct shadow_slot {
    unsigned long va;         /* 拦截的虚拟地址 */
    struct mm_struct *mm;     /* 归属的内存空间 */
    struct page *orig_page;   /* 原始物理页引用 (用于防止页被回收) */
    struct page *shadow_page; /* 我们的影子物理页 */
    pte_t old_pte;            /* 备份的原页表项 */
};

/**
 * __release_slot_resources - 彻底释放物理页引用
 * 警告：仅在确认页表不再指向影子页时调用，否则触发 UAF
 */
static void __release_slot_resources(struct shadow_slot *slot) {
    if (!slot) return;
    if (slot->orig_page) {
        put_page(slot->orig_page);
    }
    if (slot->shadow_page) {
        __free_page(slot->shadow_page);
    }
    kfree(slot);
}

/* ==========================================================
 * 1. 架构级底层同步 (Best-Effort TLB Flush)
 * ========================================================== */

/**
 * best_effort_tlb_flush - 尽力而为的 TLB 刷新
 * 在 AArch64 中，不带 ASID 的刷新在多核竞争下可能失效。
 * 此处尝试从 mm 提取 ASID 并执行精确 VA 刷新。
 */
static inline void best_effort_tlb_flush(struct mm_struct *mm, unsigned long va) {
    unsigned long asid = 0;
    unsigned long addr_val;

#ifdef CONFIG_ARM64_ASID_BITS
    /* 提取当前进程的 ASID (16位) */
    asid = (unsigned long)(atomic64_read(&mm->context.id) & 0xffff);
#endif

    /* 构造操作数：[ASID] | [VA >> 12] */
    addr_val = (asid << 48) | (va >> 12);

    dsb(ishst);
    /* 执行底层汇编刷新：Invalidate TLB by VA, All ASID levels, Inner Shareable */
    __asm__ __volatile__ ("tlbi vae1is, %0" : : "r" (addr_val) : "memory");
    dsb(ish);
    isb();
}

/* ==========================================================
 * 2. 补丁指令构造 (严查边界与跳转范围)
 * ========================================================== */

static int build_patch_data(u8 *dst_k, size_t off, struct shadow_patch_req *preq, unsigned long va) {
    /* 指令必须 4 字节对齐 */
    if (off + 4 > PAGE_SIZE) return -EINVAL;

    switch (preq->action) {
        case SHADOW_DATA_PATCH:
            *(uint32_t *)(dst_k + off) = preq->patch_val;
            break;

        case SHADOW_RET_ONLY:
            *(uint32_t *)(dst_k + off) = 0xD65F03C0; /* RET 指令 */
            break;

        case SHADOW_HP_SET:
            /* 此动作占用 8 字节 (MOV + RET) */
            if (off + 8 > PAGE_SIZE) return -EOVERFLOW;
            *(uint32_t *)(dst_k + off) = 0x52800020;     /* MOV W0, #1 */
            *(uint32_t *)(dst_k + off + 4) = 0xD65F03C0; /* RET */
            break;

        case SHADOW_JUMP_B: {
            long j_off = (long)preq->target_va - (long)va;
            /* ARM64 B 指令限制：目标必须在 ±128MB 范围内 */
            if ((preq->target_va & 3) || (j_off < -134217728LL) || (j_off > 134217724LL)) {
                wuwa_err("Critical: Jump offset out of range (%ld bytes) at 0x%lx\n", j_off, va);
                return -ERANGE;
            }
            /* 构造 B 指令：0x14000000 | (offset >> 2) */
            *(uint32_t *)(dst_k + off) = 0x14000000 | ((j_off >> 2) & 0x03FFFFFF);
            break;
        }
        default:
            wuwa_err("Unsupported action type: %d\n", preq->action);
            return -EOPNOTSUPP;
    }
    return 0;
}

/* ==========================================================
 * 3. 核心掉包引擎 (Snapshot 事务隔离逻辑)
 * ========================================================== */

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct pid *pid_s;
    struct task_struct *tsk;
    struct mm_struct *mm;
    int i, ret = 0;
    struct shadow_slot **prep_slots;

    /* ★ 必改点 2：严格限制 hook_count，杜绝非法大循环 */
    if (!req || req->hook_count == 0 || req->hook_count > 16) {
        return -EINVAL;
    }

    pid_s = find_get_pid(req->tid);
    if (!pid_s) return -ESRCH;
    tsk = get_pid_task(pid_s, PIDTYPE_PID);
    if (!tsk) { put_pid(pid_s); return -ESRCH; }
    mm = get_task_mm(tsk);
    if (!mm) { put_task_struct(tsk); put_pid(pid_s); return -ESRCH; }

    /* 预分配准备数组 */
    prep_slots = kcalloc(req->hook_count, sizeof(void *), GFP_KERNEL);
    if (!prep_slots) { ret = -ENOMEM; goto out_mm; }

    /* --- 阶段 A：慢速路径 (锁外执行，不卡游戏) --- */
    for (i = 0; i < req->hook_count; i++) {
        struct shadow_patch_req *preq = &req->hooks[i];
        unsigned long va = req->base_addr + preq->offset;
        struct page *old_p = NULL, *new_p = NULL;
        size_t off = va & ~PAGE_MASK;

        /* A1. 获取原始页引用 (强制 FOLL_WRITE 以保证拿到 COW 后的私有页) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
        if (get_user_pages_remote(mm, va, 1, FOLL_WRITE | FOLL_FORCE, &old_p, NULL) <= 0) continue;
#else
        if (get_user_pages_remote(mm, va, 1, FOLL_WRITE | FOLL_FORCE, &old_p, NULL, NULL) <= 0) continue;
#endif

        /* A2. 分配影子物理页 */
        new_p = alloc_page(GFP_HIGHUSER);
        if (!new_p) { put_page(old_p); continue; }

        /* A3. 校验与打补丁 */
        u8 *src_k = kmap_local_page(old_p);
        if (*(uint32_t *)(src_k + off) != preq->expected) {
            wuwa_err("Verify mismatch at 0x%lx: exp %08x, got %08x\n", va, preq->expected, *(uint32_t *)(src_k + off));
            kunmap_local(src_k); put_page(old_p); __free_page(new_p);
            continue;
        }

        u8 *dst_k = kmap_local_page(new_p);
        memcpy(dst_k, src_k, PAGE_SIZE);
        
        /* 校验 build 结果 */
        if (build_patch_data(dst_k, off, preq, va) < 0) {
            kunmap_local(dst_k); kunmap_local(src_k);
            put_page(old_p); __free_page(new_p);
            continue;
        }

        /* 刷新指令缓存，让影子页里的汇编代码对 CPU 生效 */
        flush_icache_range((unsigned long)dst_k, (unsigned long)dst_k + PAGE_SIZE);
        kunmap_local(dst_k); kunmap_local(src_k);

        /* A4. 封装槽位 */
        prep_slots[i] = kzalloc(sizeof(struct shadow_slot), GFP_KERNEL);
        if (!prep_slots[i]) { put_page(old_p); __free_page(new_p); continue; }
        
        prep_slots[i]->va = va;
        prep_slots[i]->mm = mm;
        prep_slots[i]->orig_page = old_p;
        prep_slots[i]->shadow_page = new_p;
    }

    /* --- 阶段 B：极速路径 (最短锁时间，仅做指针交换) --- */
    if (mmap_write_lock_killable(mm)) {
        ret = -EINTR; goto out_cleanup;
    }

    for (i = 0; i < req->hook_count; i++) {
        struct shadow_slot *slot = prep_slots[i];
        if (!slot) continue;

        /* B1. 防止重复点火覆盖 (xa_insert 在冲突时返回错误) */
        if (xa_insert(&g_shadow_xa, (unsigned long)mm ^ slot->va, slot, GFP_ATOMIC)) {
            wuwa_warn("Address 0x%lx already has a shadow page, skipping.\n", slot->va);
            continue;
        }

        /* B2. 步进页表定位 PTE */
        pmd_t *pmd = wuwa_walk_to_pmd(mm, slot->va);
        if (!pmd || pmd_leaf(*pmd)) { 
            xa_erase(&g_shadow_xa, (unsigned long)mm ^ slot->va); 
            continue; 
        }

        spinlock_t *ptl;
        pte_t *ptep = pte_offset_map_lock(mm, pmd, slot->va, &ptl);
        if (!ptep || !pte_present(*ptep)) {
            if (ptep) pte_unmap_unlock(ptep, ptl);
            xa_erase(&g_shadow_xa, (unsigned long)mm ^ slot->va);
            continue;
        }

        /* B3. 拒绝 ContPTE (Android 15 强拆必炸) */
        if (pte_val(*ptep) & (1ULL << 52)) {
            wuwa_warn("ContPTE detected at 0x%lx, skipping safety critical page.\n", slot->va);
            pte_unmap_unlock(ptep, ptl);
            xa_erase(&g_shadow_xa, (unsigned long)mm ^ slot->va);
            continue;
        }

        /* B4. 执行物理 PFN 替换 */
        slot->old_pte = *ptep;
        u64 val = (pte_val(*ptep) & ~(PHYS_MASK & PAGE_MASK)) | (page_to_pfn(slot->shadow_page) << PAGE_SHIFT);
        WRITE_ONCE(*(u64 *)ptep, val);
        
        pte_unmap_unlock(ptep, ptl);

        /* B5. 执行 Best-Effort TLB 刷新 */
        best_effort_tlb_flush(mm, slot->va);

        /* 标记成功，不被后续 out_cleanup 释放 */
        prep_slots[i] = NULL; 
        wuwa_info("V18.6 Hardened: Success at 0x%lx\n", slot->va);
    }

    mmap_write_unlock(mm);

out_cleanup:
    /* 清理未安装成功的残留资源 */
    for (i = 0; i < req->hook_count; i++) {
        if (prep_slots[i]) __release_slot_resources(prep_slots[i]);
    }
    kfree(prep_slots);
out_mm:
    mmput(mm); put_task_struct(tsk); put_pid(pid_s);
    return ret;
}

/* ==========================================================
 * 4. 驱动清理：止血稳健逻辑 (修复卸载炸机)
 * ========================================================== */

void wuwa_cleanup_all_shadows(void) {
    /* * ★ 必改点 1 & 3：点火测试版在模块卸载时不释放 active shadow_page。
     * 理由：PTE 仍指向影子页，强行释放 Page 会引发 UAF 硬件异常导致强制重启。
     * 这些 Page 会驻留在内存中，直到手机下次重启或游戏完全关闭释放 MM。
     */
    wuwa_warn("V18.6: Shadow slots preserved to prevent UAF. Reboot recommended after testing.\n");
}

/* ==========================================================
 * 5. 专属通信接口
 * ========================================================== */

#define V18_IOCTL_CMD 0x5A5A9999

static long wuwa_v18_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct wuwa_hbp_req req;
    
    /* 仅限 Root 权限调用 */
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

int wuwa_stealth_init(void) {
    /* ★ 必改点 2：保存全局指针，权限收紧为 0600 */
    g_wuwa_proc = proc_create("wuwa_v18", 0600, NULL, &v18_fops);
    if (!g_wuwa_proc) return -ENOMEM;
    
    wuwa_info("V18.6 Hardened interface ready at /proc/wuwa_v18\n");
    return 0;
}

void wuwa_stealth_cleanup(void) {
    if (g_wuwa_proc) {
        proc_remove(g_wuwa_proc);
        g_wuwa_proc = NULL;
    }
    wuwa_cleanup_all_shadows();
}

/* 兼容占位符 */
int wuwa_hbp_init_device(void) { return 0; }
void wuwa_hbp_cleanup_device(void) { }
void wuwa_cleanup_perf_hbp(void) { }
