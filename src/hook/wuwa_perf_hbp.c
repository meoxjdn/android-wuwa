// SPDX-License-Identifier: GPL-2.0
/*
 * wuwa_universal_hbp.c — 终极通用硬件断点执行引擎 (免重编版)
 */

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/rcupdate.h>
#include <asm/processor.h>
#include <asm/fpsimd.h>
#include <asm/ptrace.h>

#define DEV_NAME  "logd_service"
#define MAX_HOOKS 16
#define MAX_BPS   2048   

#define PC_BEHAVIOR_NONE  0
#define PC_BEHAVIOR_SKIP  1  /* PC += 4 */
#define PC_BEHAVIOR_RET   2  /* PC = LR */
#define PC_BEHAVIOR_JUMP  3  /* PC = target_addr */

#pragma pack(push, 8)
/* ★ 通用载荷指令集 (由控制端下发) ★ */
struct hook_request {
    uint64_t vaddr;             // 拦截的指令地址

    /* 1. 常规修改指令 */
    uint32_t modify_x_idx;      // 要修改的通用寄存器 (0-31, 0xFF表示不改)
    uint64_t modify_x_val;      // 写入的值
    uint32_t modify_s_idx;      // 要修改的浮点寄存器 (0-31, 0xFF表示不改)
    uint32_t modify_s_val;      // 写入的浮点值 (HEX)
    uint32_t add_sp_val;        // 堆栈补偿 (SP += X)
    
    /* 2. 控制流调度指令 */
    uint32_t pc_behavior;       // 正常情况下的 PC 去向
    uint64_t pc_jump_addr;      // 如果是 JUMP，目标地址

    /* 3. 动态内存条件判定分支 (可选) */
    uint32_t use_cond;          // 是否启用条件判断 (1=开启)
    uint32_t cond_base_reg;     // 基址寄存器
    uint32_t cond_offset;       // 偏移量
    uint32_t cond_cmp_val;      // 对比值
    
    // 如果条件不匹配，执行以下备用逻辑 (如怪物强行重置)
    uint32_t false_x0_modify;   // 是否强制修改返回值 X0 (1=是)
    uint64_t false_x0_val;
    uint32_t false_add_sp;      
    uint32_t false_pc_behavior; 
};

struct wuwa_hbp_req {
    int      tid;
    uint32_t hook_count;
    struct   hook_request hooks[MAX_HOOKS];
};

struct core_cmd_packet {
    uint32_t cmd_id;
    uint64_t payload_ptr;
};
#pragma pack(pop)

#define CMD_HBP_INSTALL 0x5A5A1001
#define CMD_HBP_CLEANUP 0x5A5A1002

struct hook_config {
    uint32_t count;
    struct hook_request hooks[MAX_HOOKS];
};

static struct hook_config __rcu *g_hook_config = NULL;
static struct perf_event  *g_bps[MAX_BPS];
static int                 g_bp_count  = 0;
static DEFINE_MUTEX(g_bp_mutex);

typedef struct perf_event *(*reg_fn_t)(struct perf_event_attr *, perf_overflow_handler_t, void *, struct task_struct *);
typedef void  (*unreg_fn_t)(struct perf_event *);
typedef long  (*read_nofault_fn_t)(void *, const void __user *, size_t);
typedef void  (*fpsimd_save_fn_t)(struct user_fpsimd_state *);
typedef void  (*fpsimd_load_fn_t)(const struct user_fpsimd_state *);

static reg_fn_t          fn_register     = NULL;
static unreg_fn_t        fn_unregister   = NULL;
static read_nofault_fn_t fn_nofault_read = NULL;
static fpsimd_save_fn_t  fn_fpsimd_save  = NULL;
static fpsimd_load_fn_t  fn_fpsimd_load  = NULL;

extern unsigned long kallsyms_lookup_name_ex(const char *name);

static int resolve_symbols_natively(void) {
    if (fn_register) return 0;
    fn_register   = (reg_fn_t)kallsyms_lookup_name_ex("register_user_hw_breakpoint");
    fn_unregister = (unreg_fn_t)kallsyms_lookup_name_ex("unregister_hw_breakpoint");
    fn_nofault_read = (read_nofault_fn_t)kallsyms_lookup_name_ex("copy_from_user_nofault");
    if (!fn_nofault_read) fn_nofault_read = (read_nofault_fn_t)kallsyms_lookup_name_ex("probe_kernel_read");
    fn_fpsimd_save = (fpsimd_save_fn_t)kallsyms_lookup_name_ex("fpsimd_save_state");
    if (!fn_fpsimd_save) fn_fpsimd_save = (fpsimd_save_fn_t)kallsyms_lookup_name_ex("fpsimd_save_and_flush_cpu_state");
    fn_fpsimd_load = (fpsimd_load_fn_t)kallsyms_lookup_name_ex("fpsimd_load_state");
    if (!fn_fpsimd_load) fn_fpsimd_load = (fpsimd_load_fn_t)kallsyms_lookup_name_ex("fpsimd_flush_cpu_state");
    if (!fn_register || !fn_unregister) return -ENOSYS;
    return 0;
}

static void apply_pc_behavior(struct pt_regs *regs, uint64_t current_pc, uint32_t behavior, uint64_t jump_addr) {
    if (behavior == PC_BEHAVIOR_SKIP) {
        instruction_pointer_set(regs, current_pc + 4);
    } else if (behavior == PC_BEHAVIOR_RET) {
        instruction_pointer_set(regs, regs->regs[30]);
    } else if (behavior == PC_BEHAVIOR_JUMP) {
        instruction_pointer_set(regs, jump_addr);
    }
}

static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    struct hook_config *cfg;
    uint64_t pc;
    int i;

    if (unlikely(!regs)) return;
    pc = instruction_pointer(regs);

    cfg = rcu_dereference_sched(g_hook_config);
    if (!cfg) return;

    for (i = 0; i < cfg->count; i++) {
        struct hook_request *req = &cfg->hooks[i];

        if (pc != req->vaddr) continue;

        /* 分支 1: 处理条件判定逻辑 (如怪物阵营判定) */
        if (req->use_cond) {
            uint32_t mem_val = 0;
            uint64_t tgt_addr = regs->regs[req->cond_base_reg] + req->cond_offset;
            int read_ok = fn_nofault_read ? (fn_nofault_read(&mem_val, (void __user *)tgt_addr, 4) == 0) : 0;
            
            if (read_ok && mem_val != req->cond_cmp_val) {
                /* 判定失败：执行备用惩罚/重置逻辑 */
                regs->sp += req->false_add_sp;
                if (req->false_x0_modify) regs->regs[0] = req->false_x0_val;
                apply_pc_behavior(regs, pc, req->false_pc_behavior, 0);
                break; // 结束处理
            }
        }

        /* 分支 2: 执行通用修改载荷 */
        if (req->modify_x_idx < 32) {
            regs->regs[req->modify_x_idx] = req->modify_x_val;
        }

        if (req->modify_s_idx < 32 && fn_fpsimd_save && fn_fpsimd_load && bp->ctx && bp->ctx->task) {
            struct task_struct *tsk = bp->ctx->task;
            struct user_fpsimd_state *fp = &tsk->thread.uw.fpsimd_state;
            fn_fpsimd_save(fp);
            fp->vregs[req->modify_s_idx] = (fp->vregs[req->modify_s_idx] & ~((__uint128_t)0xFFFFFFFFULL)) | ((__uint128_t)req->modify_s_val);
            fn_fpsimd_load(fp);
        }

        if (req->add_sp_val > 0) {
            regs->sp += req->add_sp_val;
        }

        /* 分支 3: 控制流结算 */
        apply_pc_behavior(regs, pc, req->pc_behavior, req->pc_jump_addr);
        break; 
    }
}

static struct perf_event *install_bp(struct task_struct *tsk, uint64_t addr, int *out_err) {
    struct perf_event_attr attr;
    struct perf_event     *bp;

    if (!fn_register) { if (out_err) *out_err = -ENOSYS; return NULL; }

    hw_breakpoint_init(&attr);
    attr.bp_addr  = addr;
    attr.bp_len   = HW_BREAKPOINT_LEN_4;
    attr.bp_type  = HW_BREAKPOINT_X;
    attr.disabled = 0;

    bp = fn_register(&attr, wuwa_hbp_handler, NULL, tsk);
    if (IS_ERR(bp)) { if (out_err) *out_err = PTR_ERR(bp); return NULL; }
    return bp;
}

void wuwa_cleanup_perf_hbp(void) {
    struct hook_config *old_cfg;
    int i;
    mutex_lock(&g_bp_mutex);
    old_cfg = rcu_dereference_protected(g_hook_config, lockdep_is_held(&g_bp_mutex));
    RCU_INIT_POINTER(g_hook_config, NULL);
    for (i = 0; i < g_bp_count; i++) {
        if (g_bps[i] && fn_unregister) { fn_unregister(g_bps[i]); g_bps[i] = NULL; }
    }
    g_bp_count = 0;
    mutex_unlock(&g_bp_mutex);
    if (old_cfg) { synchronize_rcu(); kfree(old_cfg); }
}

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct hook_config *new_cfg, *old_cfg;
    struct task_struct *tsk;
    struct pid         *pid_struct;
    uint32_t            hook_count;
    int                 i, ret = 0;

    if (!req) return -EINVAL;
    hook_count = req->hook_count > MAX_HOOKS ? MAX_HOOKS : req->hook_count;
    if (resolve_symbols_natively() != 0) return -ENOSYS;

    pid_struct = find_get_pid(req->tid);
    if (!pid_struct) return -ESRCH;
    rcu_read_lock();
    tsk = pid_task(pid_struct, PIDTYPE_PID);
    if (!tsk) { rcu_read_unlock(); put_pid(pid_struct); return -ESRCH; }
    get_task_struct(tsk);
    rcu_read_unlock();

    new_cfg = kzalloc(sizeof(*new_cfg), GFP_KERNEL);
    if (!new_cfg) { ret = -ENOMEM; goto out_task; }

    mutex_lock(&g_bp_mutex);
    if (g_bp_count + hook_count > MAX_BPS) { mutex_unlock(&g_bp_mutex); kfree(new_cfg); ret = -ENOSPC; goto out_task; }
    old_cfg = rcu_dereference_protected(g_hook_config, lockdep_is_held(&g_bp_mutex));

    new_cfg->count = hook_count;
    for (i = 0; i < hook_count; i++) new_cfg->hooks[i] = req->hooks[i];
    rcu_assign_pointer(g_hook_config, new_cfg);

    for (i = 0; i < hook_count; i++) {
        int bp_err = 0;
        struct perf_event *bp = install_bp(tsk, req->hooks[i].vaddr, &bp_err);
        if (bp) g_bps[g_bp_count++] = bp; else ret = bp_err;
    }
    mutex_unlock(&g_bp_mutex);
    if (old_cfg) { synchronize_rcu(); kfree(old_cfg); }

out_task:
    put_task_struct(tsk); put_pid(pid_struct);
    return ret;
}

static ssize_t core_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    struct core_cmd_packet pkt;
    struct wuwa_hbp_req    req;
    if (count != sizeof(pkt)) return -EINVAL;
    if (copy_from_user(&pkt, buf, sizeof(pkt))) return -EFAULT;
    if (pkt.cmd_id == CMD_HBP_INSTALL) {
        if (copy_from_user(&req, (void __user *)pkt.payload_ptr, sizeof(req))) return -EFAULT;
        return wuwa_install_perf_hbp(&req) < 0 ? -EFAULT : count;
    } else if (pkt.cmd_id == CMD_HBP_CLEANUP) {
        wuwa_cleanup_perf_hbp(); return count;
    } 
    return -EINVAL;
}

static const struct file_operations core_fops = { .owner = THIS_MODULE, .write = core_write };
static struct miscdevice core_misc = { .minor = MISC_DYNAMIC_MINOR, .name = DEV_NAME, .fops = &core_fops };
int wuwa_hbp_init_device(void) { return misc_register(&core_misc); }
void wuwa_hbp_cleanup_device(void) { wuwa_cleanup_perf_hbp(); misc_deregister(&core_misc); }
