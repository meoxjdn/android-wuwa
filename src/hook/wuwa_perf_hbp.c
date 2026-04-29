// SPDX-License-Identifier: GPL-2.0
/*
 * wuwa_perf_hbp.c — V18.16 "Zero Compromise" 零妥协满血展开版
 * * 修正说明：
 * 1. 新增 Action 7 完美的浮点直读引擎（彻底解决 FMOV 非法指令导致的闪退）。
 * 2. 绝对完整，0 删减！恢复所有被折叠的 pr_info、pr_emerg 日志和完整的 if-else 展开！
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

static inline void nuclear_sync_all_cores(struct mm_struct *mm, unsigned long va) 
{
    unsigned long asid = 0;
    unsigned long addr_val;

#ifdef CONFIG_ARM64_ASID_BITS
    asid = (unsigned long)(atomic64_read(&mm->context.id) & 0xffff);
#endif
    addr_val = (asid << 48) | (va >> 12);

    /* 1. 强制数据同步屏障：确保内存写入已完成 */
    dsb(sy);
    
    /* 2. 精准 TLB 刷新 (vae1is) */
    __asm__ __volatile__ ("tlbi vae1is, %0" : : "r" (addr_val) : "memory");
    
    /* 3. 全局指令缓存作废 (ic ialluis)：对付 RET/B 跳转的关键 */
    __asm__ __volatile__ ("ic ialluis" : : : "memory");
    
    /* 4. 最终系统同步 */
    dsb(sy);
    isb();
}

/* ==========================================================
 * 1. 槽位对象管理
 * ========================================================== */

struct shadow_slot {
    unsigned long va;
    struct mm_struct *mm;
    struct page *orig_page;
    struct page *shadow_page;
    pte_t old_pte;
};

static void __release_slot(struct shadow_slot *slot) 
{
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

/* ==========================================================
 * 2. 补丁构造逻辑 (包含 0xFFC 蹦床 和 终极浮点引擎)
 * ========================================================== */

static int build_patch_instruction(u8 *dst_k, size_t off, struct shadow_patch_req *preq, unsigned long va) 
{
    if (off + 4 > PAGE_SIZE) {
        return -EINVAL;
    }

    switch (preq->action) {
        case 0: /* SHADOW_DATA_PATCH */
            *(uint32_t *)(dst_k + off) = preq->patch_val;
            pr_info("[wuwa] Action 0 (Data) applied at 0x%lx\n", va);
            break;

        case 1: /* SHADOW_RET_ONLY */
            *(uint32_t *)(dst_k + off) = 0xD65F03C0; 
            pr_info("[wuwa] Action 1 (RET) applied at 0x%lx\n", va);
            break;

        case 2: /* SHADOW_HP_SET (常规血量) */
            if (off + 8 > PAGE_SIZE) {
                return -EOVERFLOW;
            }
            *(uint32_t *)(dst_k + off) = 0x52800020;     /* MOV W0, #1 */
            *(uint32_t *)(dst_k + off + 4) = 0xD65F03C0; /* RET */
            pr_info("[wuwa] Action 2 (HP_1) applied at 0x%lx\n", va);
            break;

        case 3: /* SHADOW_JUMP_B */
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

        case 4: /* SHADOW_STUB_IF */
        {
            const size_t STUB_OFF = 0xF00;
            uint32_t *stub = (uint32_t *)(dst_k + STUB_OFF);
            unsigned long s_va = (va & PAGE_MASK) + STUB_OFF;
            
            if (STUB_OFF + 24 > PAGE_SIZE) {
                return -EFAULT;
            }
            
            stub[0] = 0xB9401C22; /* LDR W2, [X1, #0x1C] */
            stub[1] = 0x7100045F; /* CMP W2, #1 */
            stub[2] = 0x54000040; /* B.EQ +8 */
            stub[3] = preq->expected; 
            stub[4] = 0x14000000 | (((long)va + 4 - (long)s_va - 16) >> 2 & 0x03FFFFFF);
            stub[5] = 0xD65F03C0;
            
            *(uint32_t *)(dst_k + off) = 0x14000000 | (((long)s_va - (long)va) >> 2 & 0x03FFFFFF);
            pr_info("[wuwa] Action 4 (STUB_IF) applied at 0x%lx\n", va);
            break;
        }

        case 5: /* SHADOW_DOUBLE_PATCH */
            if (off + 8 > PAGE_SIZE) {
                return -EOVERFLOW;
            }
            *(uint32_t *)(dst_k + off) = preq->patch_val;
            *(uint32_t *)(dst_k + off + 4) = preq->patch_val_2;
            pr_info("[wuwa] Action 5 (Double Patch) applied at 0x%lx\n", va);
            break;

        case 6: /* ★ SHADOW_SAFE_HP_STUB：针对 0xFFC 的页内安全蹦床 ★ */
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
            pr_info("[wuwa] Action 6 (Safe HP Trampoline) successfully avoided boundary at 0x%lx\n", va);
            break;
        }

        case 7: /* ★ SHADOW_FLOAT_RET：V18.16 终极浮点直读引擎 ★ */
        {
            if (off + 12 > PAGE_SIZE) {
                pr_err("[wuwa] Float Ret Action 7 failed: cross page boundary at 0x%lx\n", va);
                return -EOVERFLOW;
            }
            /* LDR S0, [PC, #8] -> 读取偏移 8 字节后的数据到浮点寄存器 */
            *(uint32_t *)(dst_k + off) = 0x1C000040;     
            /* RET -> 立即返回，保持栈平衡 */
            *(uint32_t *)(dst_k + off + 4) = 0xD65F03C0; 
            /* 存放控制端传来的真实浮点数据 (如 4.5f 的 IEEE 754 原码) */
            *(uint32_t *)(dst_k + off + 8) = preq->patch_val; 
            
            pr_info("[wuwa] Action 7 (Float Return Engine) applied at 0x%lx, value: 0x%08x\n", va, preq->patch_val);
            break;
        }

        default:
            pr_err("[wuwa] UNKNOWN ACTION TYPE: %d\n", preq->action);
            return -EOPNOTSUPP;
    }
    return 0;
}

/* ==========================================================
 * 3. 核心安装引擎 
 * ========================================================== */

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
        /* 核心保险丝：校验期望的原机器码 */
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

        /* 物理替换 */
        slot->old_pte = *ptep;
        val = (pte_val(*ptep) & ~(PHYS_MASK & PAGE_MASK)) | (page_to_pfn(slot->shadow_page) << PAGE_SHIFT);
        WRITE_ONCE(*(u64 *)ptep, val);
        pte_unmap_unlock(ptep, ptl);

        /* 核弹刷新 */
        nuclear_sync_all_cores(mm, slot->va);

        pr_info("[wuwa] V18.16 SUCCESS: Action %d fully deployed at 0x%lx\n", req->hooks[i].action, slot->va);
        prep_slots[i] = NULL; /* 标记成功，防止在 out_clean 中被释放 */
    }
    mmap_write_unlock(mm);

out_clean:
    /* 清理所有未安装成功的预备页 */
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

/* ==========================================================
 * 4. 通信接口与初始化
 * ========================================================== */

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
        pr_err("[wuwa] Failed to create /proc/wuwa_v18\n");
        return -ENOMEM;
    }
    pr_info("[wuwa] V18.16 Stealth Proc Engine initialized successfully.\n");
    return 0;
}

void wuwa_stealth_cleanup(void) 
{ 
    if (g_wuwa_proc) {
        proc_remove(g_wuwa_proc); 
        g_wuwa_proc = NULL;
        pr_info("[wuwa] V18.16 Stealth Proc Engine removed.\n");
    }
}

/* ★ 底层占位符清理函数 (完整保留，防止链接时报 undef 错误) ★ */
void wuwa_cleanup_all_shadows(void) 
{
    /* 卸载时由于采用了“点火即锁定”策略，暂不主动销毁物理页以防 UAF */
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
