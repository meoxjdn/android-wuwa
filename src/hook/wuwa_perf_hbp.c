// SPDX-License-Identifier: GPL-2.0
/*
 * wuwa_perf_hbp.c — PTE UXN + OOL 多线程状态机引擎 (融入主模块版)
 * 架构特点：零 Inline Hook 内存修改，原生指令 OOL 推进，Epoch 防 ABA，无痕 Lazy GC。
 * 通信架构：由 wuwa_ioctl 驱动，无 /dev 节点。
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mmu_context.h>
#include <linux/hashtable.h>
#include <linux/rcupdate.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/ptrace.h>
#include <asm/esr.h>
#include <asm/cacheflush.h>

/* 此头文件应包含你在 ioctl 中定义的 struct stealth_req */
// #include "wuwa_perf_hbp.h" 

#define MAX_HOOKS 16
#define OOL_SLOT_SIZE 64
#define MAX_OOL_SLOTS 256
#define GC_WATERMARK  (MAX_OOL_SLOTS - 16)
#define PTE_UXN_BIT   (1ULL << 54)

#define BRK_MAGIC_IMM 0x1337
#define BRK_MAGIC_INST (0xD4200000 | (BRK_MAGIC_IMM << 5))

#pragma pack(push, 8)
struct hook_request {
    uint64_t vaddr;
    uint32_t original_inst; 
    
    uint32_t modify_x_idx;
    uint64_t modify_x_val;
    uint32_t modify_s_idx;
    uint32_t modify_s_val;
    uint32_t add_sp_val;
    
    uint32_t pc_behavior;
    uint64_t pc_jump_addr;
    
    uint32_t use_cond;
    uint32_t cond_base_reg;
    uint32_t cond_offset;
    uint32_t cond_cmp_val;
    
    uint32_t false_x0_modify;
    uint64_t false_x0_val;
    uint32_t false_add_sp;
    uint32_t false_pc_behavior;
};

struct stealth_req {
    int      pid;
    uint64_t trampoline_base; 
    uint32_t hook_count;
    struct   hook_request hooks[MAX_HOOKS];
};
#pragma pack(pop)

enum ool_state {
    OOL_IDLE = 0,
    OOL_EXECUTING = 1
};

struct thread_ool_state {
    pid_t tid;
    u64   epoch;          
    unsigned long original_pc;
    uint64_t slot_uaddr;  
    enum ool_state state;
    struct hlist_node node;
};

static struct stealth_req g_current_req;
static DEFINE_RWLOCK(g_engine_lock);

static DECLARE_BITMAP(g_ool_bitmap, MAX_OOL_SLOTS);
static DEFINE_SPINLOCK(g_ool_lock);

#define OOL_HASH_BITS 8
static DEFINE_HASHTABLE(g_ool_hash, OOL_HASH_BITS);
static DEFINE_SPINLOCK(g_hash_lock);

static struct kprobe kp_mem_abort;
static struct kprobe kp_brk_handler;

/* ==========================================
 * 内存与权限控制模块
 * ========================================== */
static int modify_page_uxn_safe(struct task_struct *tsk, unsigned long vaddr, bool set_uxn)
{
    struct mm_struct *mm;
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *pte;
    spinlock_t *ptl;
    pte_t old_pte, new_pte;
    int ret = 0;

    mm = get_task_mm(tsk);
    if (!mm) return -ESRCH;

    mmap_read_lock(mm);
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) { ret = -EFAULT; goto out; }
    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) { ret = -EFAULT; goto out; }
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud)) { ret = -EFAULT; goto out; }
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) { ret = -EFAULT; goto out; }
    pte = pte_offset_map_lock(mm, pmd, vaddr, &ptl);
    if (!pte) { ret = -EFAULT; goto out; }

    old_pte = *pte;
    new_pte = set_uxn ? __pte(pte_val(old_pte) | PTE_UXN_BIT) : __pte(pte_val(old_pte) & ~PTE_UXN_BIT);
    set_pte_at(mm, vaddr, pte, new_pte);
    pte_unmap_unlock(pte, ptl);

    flush_tlb_page(vma_lookup(mm, vaddr), vaddr);

out:
    mmap_read_unlock(mm);
    mmput(mm);
    return ret;
}

/* ==========================================
 * OOL 状态机与垃圾回收 (Lazy GC)
 * ========================================== */
static void stealth_lazy_gc_locked(void)
{
    struct thread_ool_state *ts;
    struct hlist_node *tmp;
    struct task_struct *tsk;
    int bkt, reclaimed = 0;

    hash_for_each_safe(g_ool_hash, bkt, tmp, ts, node) {
        if (ts->state == OOL_IDLE) continue;

        rcu_read_lock();
        tsk = find_task_by_vpid(ts->tid);
        
        if (!tsk || tsk->start_time != ts->epoch) {
            int slot_idx = (ts->slot_uaddr - g_current_req.trampoline_base) / OOL_SLOT_SIZE;
            spin_lock(&g_ool_lock);
            clear_bit(slot_idx, g_ool_bitmap);
            spin_unlock(&g_ool_lock);

            hash_del(&ts->node);
            kfree(ts);
            reclaimed++;
        }
        rcu_read_unlock();
    }
}

static struct thread_ool_state *get_or_create_thread_state(struct task_struct *current_tsk)
{
    struct thread_ool_state *ts;
    pid_t tid = current_tsk->pid;
    u64 current_epoch = current_tsk->start_time;
    int slot_idx, used_slots;

    spin_lock(&g_hash_lock);

    hash_for_each_possible(g_ool_hash, ts, node, tid) {
        if (ts->tid == tid) {
            if (unlikely(ts->epoch != current_epoch)) {
                ts->epoch = current_epoch;
                ts->state = OOL_IDLE; 
            }
            spin_unlock(&g_hash_lock);
            return ts;
        }
    }

    spin_lock(&g_ool_lock);
    used_slots = bitmap_weight(g_ool_bitmap, MAX_OOL_SLOTS);
    spin_unlock(&g_ool_lock);

    if (used_slots >= GC_WATERMARK) stealth_lazy_gc_locked();

    ts = kzalloc(sizeof(*ts), GFP_ATOMIC);
    if (!ts) goto out_unlock;

    spin_lock(&g_ool_lock);
    slot_idx = find_first_zero_bit(g_ool_bitmap, MAX_OOL_SLOTS);
    if (slot_idx >= MAX_OOL_SLOTS) {
        spin_unlock(&g_ool_lock);
        kfree(ts);
        ts = NULL;
        goto out_unlock;
    }
    set_bit(slot_idx, g_ool_bitmap);
    spin_unlock(&g_ool_lock);

    ts->tid = tid;
    ts->epoch = current_epoch;
    ts->slot_uaddr = g_current_req.trampoline_base + (slot_idx * OOL_SLOT_SIZE);
    ts->state = OOL_IDLE;
    hash_add(g_ool_hash, &ts->node, tid);

out_unlock:
    spin_unlock(&g_hash_lock);
    return ts;
}

/* ==========================================
 * 核心拦截路由 (异常流调度)
 * ========================================== */
static int pre_do_mem_abort(struct kprobe *p, struct pt_regs *kprobe_regs)
{
    unsigned int esr = kprobe_regs->regs[1]; 
    struct pt_regs *user_regs = (struct pt_regs *)kprobe_regs->regs[2];
    int ec = ESR_ELx_EC(esr);
    int i;
    struct thread_ool_state *ts;

    if (ec != 0x20 && ec != 0x21) return 0;
    if (!user_regs || current->tgid != g_current_req.pid) return 0;

    read_lock(&g_engine_lock);
    for (i = 0; i < g_current_req.hook_count; i++) {
        struct hook_request *req = &g_current_req.hooks[i];
        
        if (user_regs->pc == req->vaddr) {
            ts = get_or_create_thread_state(current);
            if (!ts || ts->state == OOL_EXECUTING) break; 

            if (req->modify_x_idx < 32) {
                user_regs->regs[req->modify_x_idx] = req->modify_x_val;
            }

            uint32_t insts[2] = {req->original_inst, BRK_MAGIC_INST};
            if (copy_to_user((void __user *)ts->slot_uaddr, insts, sizeof(insts)) == 0) {
                ts->original_pc = user_regs->pc;
                ts->state = OOL_EXECUTING;
                user_regs->pc = ts->slot_uaddr;
                
                read_unlock(&g_engine_lock);
                instruction_pointer_set(kprobe_regs, (unsigned long)user_regs->pc);
                return 1; 
            }
        }
    }
    read_unlock(&g_engine_lock);
    return 0;
}

static int pre_do_debug_exception(struct kprobe *p, struct pt_regs *kprobe_regs)
{
    unsigned int esr = kprobe_regs->regs[1];
    struct pt_regs *user_regs = (struct pt_regs *)kprobe_regs->regs[2];
    int ec = ESR_ELx_EC(esr);
    struct thread_ool_state *ts;

    if (ec != 0x3C || !user_regs || current->tgid != g_current_req.pid) return 0;

    if ((esr & 0xFFFF) == BRK_MAGIC_IMM) {
        ts = get_or_create_thread_state(current);
        if (ts && ts->state == OOL_EXECUTING) {
            if (user_regs->pc == ts->slot_uaddr + 4) {
                user_regs->pc = ts->original_pc + 4;
                ts->state = OOL_IDLE;
                instruction_pointer_set(kprobe_regs, (unsigned long)user_regs->pc);
                return 1; 
            }
        }
    }
    return 0;
}

/* ==========================================
 * 提供给 wuwa_ioctl.c 调用的控制接口
 * ========================================== */

/* 安装 PTE UXN 载荷 */
int wuwa_install_perf_hbp(void *raw_req) 
{
    struct stealth_req *req = (struct stealth_req *)raw_req;
    struct task_struct *task;
    int i;

    if (!req) return -EINVAL;
    
    task = pid_task(find_vpid(req->pid), PIDTYPE_PID);
    if (!task || !task->mm) return -ESRCH;

    write_lock(&g_engine_lock);
    g_current_req = *req;
    write_unlock(&g_engine_lock);

    for (i = 0; i < req->hook_count; i++) {
        modify_page_uxn_safe(task, req->hooks[i].vaddr, true);
        pr_info("[Stealth] UXN set on 0x%llx\n", req->hooks[i].vaddr);
    }
    return 0;
}
EXPORT_SYMBOL(wuwa_install_perf_hbp);

/* 初始化引擎（供 src/core/wuwa.c 调用） */
int wuwa_stealth_init(void)
{
    int ret;
    kp_mem_abort.symbol_name = "do_mem_abort";
    kp_mem_abort.pre_handler = pre_do_mem_abort;
    ret = register_kprobe(&kp_mem_abort);
    
    kp_brk_handler.symbol_name = "do_debug_exception";
    kp_brk_handler.pre_handler = pre_do_debug_exception;
    ret |= register_kprobe(&kp_brk_handler);

    if (ret < 0) {
        pr_err("[Stealth] Kprobe init failed.\n");
        return ret;
    }
    pr_info("[Stealth] OOL UXN Engine Core initialized.\n");
    return 0;
}
EXPORT_SYMBOL(wuwa_stealth_init);

/* 清理引擎（供 src/core/wuwa.c 调用） */
void wuwa_stealth_cleanup(void)
{
    unregister_kprobe(&kp_mem_abort);
    unregister_kprobe(&kp_brk_handler);
    pr_info("[Stealth] Engine Unloaded.\n");
}
EXPORT_SYMBOL(wuwa_stealth_cleanup);
