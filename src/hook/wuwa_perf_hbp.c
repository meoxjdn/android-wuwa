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

#include "../core/wuwa_common.h"
#include "wuwa_perf_hbp.h"
#include "../utils/wuwa_utils.h" /* 引入 kallsyms_lookup_name_ex */

#define OOL_SLOT_SIZE 64
#define PTE_UXN_BIT   (1ULL << 54)
#define GC_WATERMARK  (MAX_OOL_SLOTS - 16)
#define BRK_MAGIC_IMM 0x1337
#define BRK_MAGIC_INST (0xD4200000 | (BRK_MAGIC_IMM << 5))

enum ool_state { OOL_IDLE = 0, OOL_EXECUTING = 1 };

struct thread_ool_state {
    pid_t tid;
    u64   epoch;          
    unsigned long original_pc;
    uint64_t slot_uaddr;  
    enum ool_state state;
    struct hlist_node node;
};

static struct wuwa_stealth_req g_current_req;
static DEFINE_RWLOCK(g_engine_lock);

static DECLARE_BITMAP(g_ool_bitmap, MAX_OOL_SLOTS);
static DEFINE_SPINLOCK(g_ool_lock);

#define OOL_HASH_BITS 8
static DEFINE_HASHTABLE(g_ool_hash, OOL_HASH_BITS);
static DEFINE_SPINLOCK(g_hash_lock);

static struct kprobe kp_mem_abort;
static struct kprobe kp_brk_handler;

/* 动态解析函数指针，彻底避开 Android 15 的 export 限制 */
static long (*fn_copy_from_user_nofault)(void *dst, const void __user *src, size_t size) = NULL;

/* ==========================================
 * PTE 强暴修改模块 (绕过 MTE 与 ContPTE)
 * ========================================== */
static int modify_page_uxn_safe(struct task_struct *tsk, unsigned long vaddr, bool set_uxn)
{
    struct mm_struct *mm;
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *pte;
    spinlock_t *ptl;
    pte_t old_pte, new_pte;
    unsigned long tlbi_addr;
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
    
    /* * ★ 核心突破 1：不准用 set_pte_at！ 
     * 直接对 PTE 的物理内存强制覆盖 8 字节，绕过 __contpte_try_fold 和 mte_sync_tags 
     */
    WRITE_ONCE(*((u64 *)pte), pte_val(new_pte));
    
    pte_unmap_unlock(pte, ptl);

    /* * ★ 核心突破 2：不准用 flush_tlb_page！
     * 直接手写 ARM64 TLB 刷新汇编指令，绕过 mmu_notifier 限制
     */
    tlbi_addr = vaddr >> 12;
    asm volatile("dsb ishst");
    asm volatile("tlbi vae1is, %0" : : "r"(tlbi_addr));
    asm volatile("dsb ish");
    asm volatile("isb");

out:
    mmap_read_unlock(mm);
    mmput(mm);
    return ret;
}

/* ==========================================
 * OOL 状态机与 Lazy GC
 * ========================================== */
static void stealth_lazy_gc_locked(void)
{
    struct thread_ool_state *ts;
    struct hlist_node *tmp;
    struct task_struct *tsk;
    int bkt;

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
 * Kprobe 异常分流中枢
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

            // 条件判定逻辑 (使用动态解析的安全内存读取)
            if (req->use_cond && fn_copy_from_user_nofault) {
                uint32_t mem_val = 0;
                uint64_t tgt_addr = user_regs->regs[req->cond_base_reg] + req->cond_offset;
                if (fn_copy_from_user_nofault(&mem_val, (void __user *)tgt_addr, 4) == 0) {
                    if (mem_val != req->cond_cmp_val) {
                        user_regs->sp += req->false_add_sp;
                        if (req->false_x0_modify) user_regs->regs[0] = req->false_x0_val;
                        if (req->false_pc_behavior == PC_BEHAVIOR_RET) {
                            instruction_pointer_set(kprobe_regs, user_regs->regs[30]);
                        }
                        read_unlock(&g_engine_lock);
                        return 1;
                    }
                }
            }

            if (req->modify_x_idx < 32) user_regs->regs[req->modify_x_idx] = req->modify_x_val;
            
            // 劫持调度
            if (req->pc_behavior == PC_BEHAVIOR_RET) {
                instruction_pointer_set(kprobe_regs, user_regs->regs[30]);
                read_unlock(&g_engine_lock);
                return 1;
            } else if (req->pc_behavior == PC_BEHAVIOR_JUMP) {
                instruction_pointer_set(kprobe_regs, req->pc_jump_addr);
                read_unlock(&g_engine_lock);
                return 1;
            } else if (req->pc_behavior == PC_BEHAVIOR_SKIP) {
                instruction_pointer_set(kprobe_regs, user_regs->pc + 4);
                read_unlock(&g_engine_lock);
                return 1;
            }

            // 原始指令推进：挂载 OOL
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
 * 控制接口
 * ========================================== */
int wuwa_install_stealth(struct wuwa_stealth_req *req) 
{
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
        wuwa_info("[Stealth] UXN set on 0x%llx\n", req->hooks[i].vaddr);
    }
    return 0;
}

void wuwa_cleanup_stealth(void)
{
    struct task_struct *task;
    int i;
    
    write_lock(&g_engine_lock);
    if (g_current_req.pid != 0) {
        task = pid_task(find_vpid(g_current_req.pid), PIDTYPE_PID);
        if (task && task->mm) {
            for (i = 0; i < g_current_req.hook_count; i++) {
                modify_page_uxn_safe(task, g_current_req.hooks[i].vaddr, false);
            }
        }
        g_current_req.pid = 0;
    }
    write_unlock(&g_engine_lock);
    wuwa_info("[Stealth] Cleaned up PTE UXN hooks.\n");
}

int wuwa_stealth_init(void)
{
    int ret;
    
    /* ★ 核心突破 3：动态解析 copy_from_user_nofault ★ */
    fn_copy_from_user_nofault = (void *)kallsyms_lookup_name_ex("copy_from_user_nofault");
    if (!fn_copy_from_user_nofault) {
        /* 内核可能将此函数重命名了（如 probe_kernel_read），我们优雅降级 */
        wuwa_warn("[Stealth] copy_from_user_nofault NOT FOUND. Condition eval may be skipped.\n");
    }
    
    kp_mem_abort.symbol_name = "do_mem_abort";
    kp_mem_abort.pre_handler = pre_do_mem_abort;
    ret = register_kprobe(&kp_mem_abort);
    
    kp_brk_handler.symbol_name = "do_debug_exception";
    kp_brk_handler.pre_handler = pre_do_debug_exception;
    ret |= register_kprobe(&kp_brk_handler);

    if (ret < 0) {
        wuwa_err("[Stealth] Kprobe init failed.\n");
        return ret;
    }
    wuwa_info("[Stealth] OOL UXN Engine Core initialized.\n");
    return 0;
}

void wuwa_stealth_cleanup(void)
{
    wuwa_cleanup_stealth();
    unregister_kprobe(&kp_mem_abort);
    unregister_kprobe(&kp_brk_handler);
}
