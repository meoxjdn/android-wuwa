// SPDX-License-Identifier: GPL-2.0
/*
 * wuwa_perf_hbp.c — PTE UXN 引擎 (浴火重生版)
 * 架构：Kprobe 哑弹劫持 + AOT 预编译跳板 + 裸写 PTE
 */

#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mmu_context.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/ptrace.h>
#include <asm/esr.h>

#include "../core/wuwa_common.h"
#include "wuwa_perf_hbp.h"
#include "../utils/wuwa_utils.h"

#define PTE_UXN_BIT   (1ULL << 54)
#define BRK_MAGIC_IMM 0x1337
#define OOL_SLOT_SIZE 64

/* 全局配置 (由于只有一个目标游戏，精简为读写锁保护即可) */
static struct wuwa_stealth_req g_current_req;
static DEFINE_RWLOCK(g_engine_lock);

static struct kprobe kp_mem_abort;
static struct kprobe kp_brk_handler;

/* 动态解析的安全读内存函数 */
static long (*fn_copy_from_user_nofault)(void *dst, const void __user *src, size_t size) = NULL;

/* ==========================================
 * Kprobe 哑弹函数 (Dummy Function)
 * 核心黑科技：用于欺骗内核异常分发状态机
 * ========================================== */
static void dummy_mem_abort(void) 
{
    /* 什么都不做，瞬间返回。
     * 此时内核会以为 do_mem_abort 已执行完毕，直接触发原生的 ERET 返回用户态。
     */
}

/* ==========================================
 * PTE 强暴修改模块 (绕过 GKI 限制)
 * ========================================== */
static int modify_page_uxn_baremetal(struct task_struct *tsk, unsigned long vaddr, bool set_uxn)
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
    
    /* 裸写物理内存，无视 MTE/ContPTE */
    WRITE_ONCE(*((u64 *)pte), pte_val(new_pte));
    pte_unmap_unlock(pte, ptl);

    /* 纯汇编硬刷 TLB */
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
 * 极简热路径路由 (O(N) 查表，因为 N 极小，速度极快)
 * ========================================== */
static int pre_do_mem_abort(struct kprobe *p, struct pt_regs *kprobe_regs)
{
    unsigned int esr = kprobe_regs->regs[1]; 
    struct pt_regs *user_regs = (struct pt_regs *)kprobe_regs->regs[2];
    int ec = ESR_ELx_EC(esr);
    int i;
    unsigned long fault_pc;

    if (unlikely(ec != 0x20 && ec != 0x21)) return 0;
    if (unlikely(!user_regs || current->tgid != g_current_req.pid)) return 0;

    fault_pc = user_regs->pc;

    read_lock(&g_engine_lock);
    for (i = 0; i < g_current_req.hook_count; i++) {
        struct hook_request *req = &g_current_req.hooks[i];
        
        if (fault_pc == req->vaddr) {
            /* 1. 条件判定逻辑 */
            if (req->use_cond && fn_copy_from_user_nofault) {
                uint32_t mem_val = 0;
                uint64_t tgt_addr = user_regs->regs[req->cond_base_reg] + req->cond_offset;
                if (fn_copy_from_user_nofault(&mem_val, (void __user *)tgt_addr, 4) == 0) {
                    if (mem_val != req->cond_cmp_val) {
                        user_regs->sp += req->false_add_sp;
                        if (req->false_x0_modify) user_regs->regs[0] = req->false_x0_val;
                        if (req->false_pc_behavior == PC_BEHAVIOR_RET) {
                            user_regs->pc = user_regs->regs[30]; // 返回上一层
                            goto swallow_exception;
                        }
                    }
                }
            }

            /* 2. 通用寄存器修改 */
            if (req->modify_x_idx < 32) user_regs->regs[req->modify_x_idx] = req->modify_x_val;
            
            /* 3. 控制流调度 */
            if (req->pc_behavior == PC_BEHAVIOR_RET) {
                user_regs->pc = user_regs->regs[30];
            } else if (req->pc_behavior == PC_BEHAVIOR_JUMP) {
                user_regs->pc = req->pc_jump_addr;
            } else if (req->pc_behavior == PC_BEHAVIOR_SKIP) {
                user_regs->pc = fault_pc + 4;
            } else {
                /* 原生执行流：引流至对应的预编译跳板 */
                user_regs->pc = g_current_req.trampoline_base + (i * OOL_SLOT_SIZE);
            }

swallow_exception:
            /* ★ 核心突破：Kprobe 哑弹劫持！
             * 将内核执行流指向一个空函数，完美跳过真实的 do_mem_abort，
             * 内核会自然 ERET 回到我们刚刚修改的 user_regs->pc 处！
             */
            instruction_pointer_set(kprobe_regs, (unsigned long)dummy_mem_abort);
            read_unlock(&g_engine_lock);
            return 1; 
        }
    }
    read_unlock(&g_engine_lock);
    return 0; // 不是目标地址，放行原生异常
}

static int pre_do_debug_exception(struct kprobe *p, struct pt_regs *kprobe_regs)
{
    unsigned int esr = kprobe_regs->regs[1];
    struct pt_regs *user_regs = (struct pt_regs *)kprobe_regs->regs[2];
    int ec = ESR_ELx_EC(esr);
    unsigned long return_pc;
    int i;

    if (unlikely(ec != 0x3C || !user_regs || current->tgid != g_current_req.pid)) return 0;
    if (unlikely((esr & 0xFFFF) != BRK_MAGIC_IMM)) return 0;

    return_pc = user_regs->pc - 4; // 计算是哪个跳板触发的 BRK

    read_lock(&g_engine_lock);
    for (i = 0; i < g_current_req.hook_count; i++) {
        unsigned long tramp_addr = g_current_req.trampoline_base + (i * OOL_SLOT_SIZE);
        if (return_pc == tramp_addr) {
            /* 闭环：跳板指令执行完毕，推进回原始 PC 的下一条指令 */
            user_regs->pc = g_current_req.hooks[i].vaddr + 4;
            
            /* 同样使用哑弹劫持法吞掉 BRK 异常 */
            instruction_pointer_set(kprobe_regs, (unsigned long)dummy_mem_abort);
            read_unlock(&g_engine_lock);
            return 1;
        }
    }
    read_unlock(&g_engine_lock);
    return 0;
}

/* ==========================================
 * 控制面：路由表构建 (AOT 预编译)
 * ========================================== */
int wuwa_install_stealth(struct wuwa_stealth_req *req) 
{
    struct task_struct *task;
    int i;
    
    if (!req) return -EINVAL;
    
    task = pid_task(find_vpid(req->pid), PIDTYPE_PID);
    if (!task || !task->mm) return -ESRCH;

    /* ★ 核心优化：在安全上下文预先写入用户态跳板 (AOT) ★ */
    for (i = 0; i < req->hook_count; i++) {
        if (req->hooks[i].pc_behavior == PC_BEHAVIOR_NONE) {
            uint32_t insts[2] = {req->hooks[i].original_inst, BRK_MAGIC_INST};
            unsigned long tramp_addr = req->trampoline_base + (i * OOL_SLOT_SIZE);
            if (copy_to_user((void __user *)tramp_addr, insts, sizeof(insts))) {
                wuwa_err("[Stealth] Failed to write AOT trampoline at 0x%lx\n", tramp_addr);
                return -EFAULT;
            }
        }
    }

    write_lock(&g_engine_lock);
    g_current_req = *req;
    write_unlock(&g_engine_lock);

    /* 置位 UXN */
    for (i = 0; i < req->hook_count; i++) {
        modify_page_uxn_baremetal(task, req->hooks[i].vaddr, true);
        wuwa_info("[Stealth] UXN Trap set for 0x%llx\n", req->hooks[i].vaddr);
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
                modify_page_uxn_baremetal(task, g_current_req.hooks[i].vaddr, false);
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
    
    fn_copy_from_user_nofault = (void *)kallsyms_lookup_name_ex("copy_from_user_nofault");
    
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
    
    wuwa_info("[Stealth] PTE UXN Engine Core initialized.\n");
    return 0;
}

void wuwa_stealth_cleanup(void)
{
    wuwa_cleanup_stealth();
    unregister_kprobe(&kp_mem_abort);
    unregister_kprobe(&kp_brk_handler);
}
