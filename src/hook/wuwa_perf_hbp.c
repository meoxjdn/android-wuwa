// SPDX-License-Identifier: GPL-2.0
/*
 * wuwa_perf_hbp.c — V18.2 "Redline" 事务级影子内存引擎
 * * 专为 Android 15 (Kernel 6.6/6.12) 优化的生产级稳定版。
 * 解决了全局 TLB 刷新导致的内核死锁重启问题，严禁在持锁期间调用 flush_tlb_all。
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
#include <linux/ptrace.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>

#include "wuwa_perf_hbp.h"
#include "../core/wuwa_common.h"

/* 外部符号声明 */
extern pmd_t *wuwa_walk_to_pmd(struct mm_struct *mm, unsigned long va);
extern unsigned long kallsyms_lookup_name_ex(const char *name);

/* ==========================================================
 * 0. 架构级精准同步组件 (ARM64 Specific)
 * ========================================================== */

/**
 * safe_flush_tlb_local - 使用汇编实现精准 TLB 刷新
 * 绕过 GKI 符号屏蔽，且不触发全局 IPI 广播，防止多核死锁。
 */
static inline void safe_flush_tlb_local(void) {
    dsb(ishst);
    /* tlbi vmalle1is: Invalidate all Stage 1 TLB entries for current VMID */
    __asm__ __volatile__ ("tlbi vmalle1is" : : : "memory");
    dsb(ish);
    isb();
}

/**
 * safe_sync_icache - 指令缓存同步
 * 确保影子页写入的汇编代码对 CPU 立即透明
 */
static inline void safe_sync_icache(void *addr, size_t len) {
    flush_icache_range((unsigned long)addr, (unsigned long)addr + len);
}

/* ==========================================================
 * 1. MMU Notifier 生命周期管理 (保底机制)
 * ========================================================== */

typedef int (*register_mn_fn)(struct mmu_notifier *, struct mm_struct *);
typedef void (*unregister_mn_fn)(struct mmu_notifier *, struct mm_struct *);

static register_mn_fn   fn_mmu_notifier_register = NULL;
static unregister_mn_fn fn_mmu_notifier_unregister = NULL;

static void resolve_notifier_symbols(void) {
    if (fn_mmu_notifier_register) return;
    fn_mmu_notifier_register = (register_mn_fn)kallsyms_lookup_name_ex("mmu_notifier_register");
    fn_mmu_notifier_unregister = (unregister_mn_fn)kallsyms_lookup_name_ex("mmu_notifier_unregister");
    
    if (!fn_mmu_notifier_register) {
        wuwa_warn("GKI Notifier 缺失，影子页将随进程销毁，无自动回收挂钩。\n");
    }
}

struct shadow_slot {
    unsigned long va;
    struct page *orig_page;
    struct page *shadow_page;
    struct mm_struct *mm;
    struct mmu_notifier notifier;
    bool notifier_registered;
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
 * 2. 核心补丁计算与边界检查
 * ========================================================== */

/**
 * apply_patch_logic - 在影子页内核映射中写入指令
 * 包含完整的越界检查，防止破坏 kmap 映射
 */
static int apply_patch_logic(u8 *dst_k, size_t off, struct shadow_patch_req *preq, unsigned long va) {
    switch (preq->action) {
        case SHADOW_DATA_PATCH:
            if (off + 4 > PAGE_SIZE) return -EFAULT;
            *(uint32_t *)(dst_k + off) = preq->patch_val;
            break;

        case SHADOW_RET_ONLY:
            if (off + 4 > PAGE_SIZE) return -EFAULT;
            *(uint32_t *)(dst_k + off) = 0xD65F03C0; // RET
            break;

        case SHADOW_HP_SET:
            if (off + 8 > PAGE_SIZE) return -EFAULT;
            ((uint32_t *)(dst_k + off))[0] = 0x52800020; // MOV W0, #1
            ((uint32_t *)(dst_k + off))[1] = 0xD65F03C0; // RET
            break;

        case SHADOW_JUMP_B: {
            if (off + 4 > PAGE_SIZE) return -EFAULT;
            long j_off = (long)preq->target_va - (long)va;
            *(uint32_t *)(dst_k + off) = 0x14000000 | ((j_off >> 2) & 0x03FFFFFF);
            break;
        }

        case SHADOW_STUB_IF: {
            /* 在影子页预留的末尾安全区写入存根代码 (Offset 0xF00) */
            const size_t STUB_OFF = 0xF00;
            if (off + 4 > PAGE_SIZE || STUB_OFF + 24 > PAGE_SIZE) return -EFAULT;
            
            uint32_t *stub = (uint32_t *)(dst_k + STUB_OFF);
            unsigned long stub_va = (va & PAGE_MASK) + STUB_OFF;
            
            /* 存根逻辑：[F00] 判断 X1 指向的是否为自己 */
            stub[0] = 0xB9401C22; // LDR W2, [X1, #0x1C]
            stub[1] = 0x7100045F; // CMP W2, #1
            stub[2] = 0x54000040; // B.EQ +8 (跳过原始逻辑)
            stub[3] = preq->expected; // 还原原始指令
            /* 计算跳回原函数的偏移 */
            stub[4] = 0x14000000 | (((long)va + 4 - (long)stub_va - 16) >> 2 & 0x03FFFFFF);
            stub[5] = 0xD65F03C0; // RET (保底)
            
            /* 修改原入口点，使其跳转到存根 */
            *(uint32_t *)(dst_k + off) = 0x14000000 | (((long)stub_va - (long)va) >> 2 & 0x03FFFFFF);
            break;
        }
        default: return -EINVAL;
    }
    return 0;
}

/* ==========================================================
 * 3. 事务级安装引擎 (核心)
 * ========================================================== */

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct pid *pid_s;
    struct task_struct *tsk;
    struct mm_struct *mm;
    int i, ret = 0;

    resolve_notifier_symbols();

    pid_s = find_get_pid(req->tid);
    if (!pid_s) return -ESRCH;
    tsk = get_pid_task(pid_s, PIDTYPE_PID);
    if (!tsk) { put_pid(pid_s); return -ESRCH; }
    mm = get_task_mm(tsk);
    if (!mm) { put_task_struct(tsk); put_pid(pid_s); return -ESRCH; }

    /* ★ 核心改进 1：升级为写锁，杜绝十分钟卡死现象 */
    if (mmap_write_lock_killable(mm)) {
        ret = -EINTR; goto out_put_mm;
    }

    for (i = 0; i < req->hook_count; i++) {
        struct shadow_patch_req *preq = &req->hooks[i];
        unsigned long va = req->base_addr + preq->offset;
        struct shadow_slot *slot = NULL;
        struct page *old_p = NULL, *new_p = NULL;
        pte_t *ptep, old_pte;
        spinlock_t *ptl;
        size_t off = va & ~PAGE_MASK;

        /* 基础对齐与页内边界校验 */
        if ((va & 3) || (off + 4 > PAGE_SIZE)) {
            wuwa_err("Invalid VA or offset: 0x%lx\n", va);
            continue;
        }

        /* 获取原始物理页 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
        if (get_user_pages_remote(mm, va, 1, FOLL_WRITE | FOLL_FORCE, &old_p, NULL) <= 0) continue;
#else
        if (get_user_pages_remote(mm, va, 1, FOLL_WRITE | FOLL_FORCE, &old_p, NULL, NULL) <= 0) continue;
#endif
        new_p = alloc_page(GFP_HIGHUSER);
        if (!new_p) { put_page(old_p); continue; }

        /* 内容克隆与机器码校验 */
        u8 *src_k = kmap_local_page(old_p);
        if (*(uint32_t *)(src_k + off) != preq->expected) {
            wuwa_err("Verify mismatch at 0x%lx: exp %08x, got %08x\n", va, preq->expected, *(uint32_t *)(src_k + off));
            kunmap_local(src_k); put_page(old_p); __free_page(new_p);
            continue;
        }

        u8 *dst_k = kmap_local_page(new_p);
        memcpy(dst_k, src_k, PAGE_SIZE);

        /* 应用补丁逻辑 */
        if (apply_patch_logic(dst_k, off, preq, va) < 0) {
            kunmap_local(dst_k); kunmap_local(src_k);
            put_page(old_p); __free_page(new_p);
            continue;
        }

        safe_sync_icache(dst_k, PAGE_SIZE);
        kunmap_local(dst_k); kunmap_local(src_k);

        /* 构造槽位对象 */
        slot = kzalloc(sizeof(*slot), GFP_KERNEL);
        if (!slot) { __free_page(new_p); put_page(old_p); continue; }
        slot->va = va; slot->mm = mm; slot->orig_page = old_p; slot->shadow_page = new_p;
        refcount_set(&slot->refs, 1); atomic_set(&slot->state, 1);
        slot->notifier.ops = &shadow_ops;

        /* MMU Notifier 注册 */
        if (fn_mmu_notifier_register) {
            if (fn_mmu_notifier_register(&slot->notifier, mm)) {
                kfree(slot); __free_page(new_p); put_page(old_p);
                continue;
            }
            slot->notifier_registered = true;
        }

        /* 页表修改：定位 PTE */
        pmd_t *pmd = wuwa_walk_to_pmd(mm, va);
        if (!pmd || pmd_leaf(*pmd)) { ret = -EFAULT; goto inner_rollback; }

        ptep = pte_offset_map_lock(mm, pmd, va, &ptl);
        if (!ptep || !pte_present(*ptep) || pte_special(*ptep)) {
            if (ptep) pte_unmap_unlock(ptep, ptl);
            ret = -ENOENT; goto inner_rollback;
        }

        /* ★ 核心改进 2：安全处理 ContPTE，不强拆，直接跳过 */
        if (pte_val(*ptep) & (1ULL << 52)) {
            wuwa_warn("检测到 ContPTE (0x%lx)，6.6+ 内核不建议拆分，已安全跳过。\n", va);
            pte_unmap_unlock(ptep, ptl);
            ret = -EOPNOTSUPP;
            goto inner_rollback;
        }

        /* 执行 PFN Swap */
        old_pte = *ptep;
        slot->old_pte = old_pte;
        u64 new_pte_val = (pte_val(old_pte) & ~(PHYS_MASK & PAGE_MASK)) | (page_to_pfn(new_p) << PAGE_SHIFT);
        
        /* 写入新 PTE */
        WRITE_ONCE(*(u64 *)ptep, new_pte_val);
        
        /* ★ 核心改进 3：内存屏障与本地 TLB 刷新 */
        pte_unmap_unlock(ptep, ptl);
        safe_flush_tlb_local();

        /* 存储记录 */
        if (xa_err(xa_store(&g_shadow_xa, (unsigned long)mm ^ va, slot, GFP_KERNEL))) {
            wuwa_err("XArray store failed for 0x%lx\n", va);
            /* 此处由于 PTE 已改，必须做即时回滚 */
            ptep = pte_offset_map_lock(mm, pmd, va, &ptl);
            WRITE_ONCE(*(u64 *)ptep, pte_val(old_pte));
            pte_unmap_unlock(ptep, ptl);
            safe_flush_tlb_local();
            goto inner_rollback;
        }

        wuwa_info("V18.2 Shadow page applied at 0x%lx -> PFN:%lx\n", va, page_to_pfn(new_p));
        continue;

inner_rollback:
        if (slot->notifier_registered && fn_mmu_notifier_unregister)
            fn_mmu_notifier_unregister(&slot->notifier, mm);
        kfree(slot); __free_page(new_p); put_page(old_p);
    }

    mmap_write_unlock(mm);

out_put_mm:
    mmput(mm); put_task_struct(tsk); put_pid(pid_s);
    return ret;
}

/* ==========================================================
 * 4. 专属直连 Proc 接口 (绕过 Android 权限拦截)
 * ========================================================== */

#define V18_IOCTL_CMD 0x5A5A9999

static long wuwa_v18_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct wuwa_hbp_req req;
    
    /* 简单的访问控制，仅限 ROOT 及其子进程 */
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
    .proc_lseek = default_llseek,
};

static struct proc_dir_entry *wuwa_proc_entry = NULL;

int wuwa_stealth_init(void) {
    /* 创建 /proc/wuwa_v18 节点，权限设为 0600 (仅 root 可见) */
    wuwa_proc_entry = proc_create("wuwa_v18", 0600, NULL, &v18_fops);
    if (!wuwa_proc_entry) return -ENOMEM;
    wuwa_info("V18.2 Stealth Engine initialized at /proc/wuwa_v18\n");
    return 0;
}

void wuwa_stealth_cleanup(void) {
    if (wuwa_proc_entry) proc_remove(wuwa_proc_entry);
    xa_destroy(&g_shadow_xa);
}

/* 兼容性占位 */
int wuwa_hbp_init_device(void) { return 0; }
void wuwa_hbp_cleanup_device(void) { }
void wuwa_cleanup_perf_hbp(void) { }
