// SPDX-License-Identifier: GPL-2.0
/*
 * wuwa_perf_hbp.c — 泛用硬件断点拦截模块 (终极 RCU 安全版)
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
#define MAX_BPS   2048   /* 支持海量线程的断点总数 */

enum generic_action_type {
    ACT_PC_SKIP            = 0,
    ACT_PC_RET             = 1,
    ACT_SET_REG_SKIP       = 2,
    ACT_SET_REG_RET        = 3,
    ACT_SET_FPREG_RET      = 4,
    ACT_COND_MEM_READ_SKIP = 5
};

struct hook_request {
    uint64_t vaddr;
    uint32_t action;
    uint32_t reg_idx_1;
    uint32_t reg_idx_2;
    uint64_t val_1;
    uint64_t val_2;
    uint32_t offset;
    uint32_t cmp_val;
    uint32_t sp_add;
};

struct wuwa_hbp_req {
    int      tid;
    uint32_t hook_count;
    struct   hook_request hooks[MAX_HOOKS];
};

#define CMD_HBP_INSTALL 0x5A5A1001
#define CMD_HBP_CLEANUP 0x5A5A1002

struct core_cmd_packet {
    uint32_t cmd_id;
    uint64_t payload_ptr;
};

/* RCU 保护的配置结构 */
struct hook_config {
    uint32_t count;
    struct hook_request hooks[MAX_HOOKS];
};

/* NMI 侧仅读取此 RCU 指针 */
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

/* --- 核心 NMI 硬件断点回调 --- */
static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    struct hook_config *cfg;
    uint64_t pc;
    int i;

    if (unlikely(!regs)) return;
    pc = instruction_pointer(regs);

    /* 无锁获取 RCU 快照 */
    cfg = rcu_dereference_sched(g_hook_config);
    if (!cfg) return;

    for (i = 0; i < cfg->count; i++) {
        struct hook_request *req = &cfg->hooks[i];

        if (pc != req->vaddr) continue;
        if (req->reg_idx_1 >= 32 || req->reg_idx_2 >= 32) break;

        switch (req->action) {
        case ACT_PC_SKIP:
            instruction_pointer_set(regs, pc + 4);
            break;

        case ACT_PC_RET:
            instruction_pointer_set(regs, regs->regs[30]);
            break;

        case ACT_SET_REG_SKIP:
            regs->regs[req->reg_idx_1] = req->val_1;
            instruction_pointer_set(regs, pc + 4);
            break;

        case ACT_SET_REG_RET:
            regs->regs[req->reg_idx_1] = req->val_1;
            instruction_pointer_set(regs, regs->regs[30]);
            break;

        case ACT_SET_FPREG_RET:
            if (fn_fpsimd_save && fn_fpsimd_load && bp->ctx && bp->ctx->task) {
                struct task_struct *tsk = bp->ctx->task;
                struct user_fpsimd_state *fp = &tsk->thread.uw.fpsimd_state;

                fn_fpsimd_save(fp);
                fp->vregs[req->reg_idx_1] = (fp->vregs[req->reg_idx_1] & ~((__uint128_t)0xFFFFFFFFULL)) | ((__uint128_t)(uint32_t)req->val_1);
                fn_fpsimd_load(fp);
            }
            instruction_pointer_set(regs, regs->regs[30]);
            break;

        case ACT_COND_MEM_READ_SKIP: {
            uint32_t flag = 0;
            uint64_t tgt_addr = regs->regs[req->reg_idx_1] + req->offset;

            /* ★ 致命 Bug 修复：正确传递读出的内存值，防止指针错位导致游戏闪退 */
            if (fn_nofault_read && fn_nofault_read(&flag, (void __user *)tgt_addr, 4) == 0) {
                if (flag == req->cmp_val) {
                    /* 是玩家 (判断为 1) -> 触发无敌，修复堆栈强制返回 */
                    regs->sp += req->sp_add;
                    regs->regs[0] = req->val_1;
                    instruction_pointer_set(regs, regs->regs[30]);
                } else {
                    /* 是怪物 (判断不为 1) -> 执行被拦截的原指令 (ldr w19, [x1, #0x1c]) */
                    /* 此处必须将读到的真实值(flag)赋给目标寄存器，绝对不能赋地址！ */
                    regs->regs[req->reg_idx_2] = flag;
                    instruction_pointer_set(regs, pc + 4);
                }
            } else {
                /* 内存读取失败时的安全容错处理 */
                regs->regs[req->reg_idx_2] = 0;
                instruction_pointer_set(regs, pc + 4);
            }
            break;
        }
        }
        break; 
    }
}

/* --- 透传底层硬件真实错误码 --- */
static struct perf_event *install_bp(struct task_struct *tsk, uint64_t addr, int *out_err) {
    struct perf_event_attr attr;
    struct perf_event     *bp;

    if (!fn_register) {
        if (out_err) *out_err = -ENOSYS;
        return NULL;
    }

    hw_breakpoint_init(&attr);
    attr.bp_addr  = addr;
    attr.bp_len   = HW_BREAKPOINT_LEN_4;
    attr.bp_type  = HW_BREAKPOINT_X;
    attr.disabled = 0;

    bp = fn_register(&attr, wuwa_hbp_handler, NULL, tsk);
    if (IS_ERR(bp)) {
        if (out_err) *out_err = PTR_ERR(bp); 
        return NULL;
    }
    return bp;
}

void wuwa_cleanup_perf_hbp(void) {
    struct hook_config *old_cfg;
    int i;

    mutex_lock(&g_bp_mutex);
    old_cfg = rcu_dereference_protected(g_hook_config, lockdep_is_held(&g_bp_mutex));
    RCU_INIT_POINTER(g_hook_config, NULL);

    for (i = 0; i < g_bp_count; i++) {
        if (g_bps[i] && fn_unregister) {
            fn_unregister(g_bps[i]);
            g_bps[i] = NULL;
        }
    }
    g_bp_count = 0;
    mutex_unlock(&g_bp_mutex);

    if (old_cfg) {
        synchronize_rcu();
        kfree(old_cfg);
    }
}

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct hook_config *new_cfg;
    struct hook_config *old_cfg;
    struct task_struct *tsk;
    struct pid         *pid_struct;
    uint32_t            hook_count;
    int                 i, ret = 0;

    if (!req) return -EINVAL;

    hook_count = req->hook_count > MAX_HOOKS ? MAX_HOOKS : req->hook_count;
    for (i = 0; i < hook_count; i++) {
        if (req->hooks[i].reg_idx_1 >= 32 || req->hooks[i].reg_idx_2 >= 32)
            return -EINVAL;
    }

    if (resolve_symbols_natively() != 0) return -ENOSYS;

    pid_struct = find_get_pid(req->tid);
    if (!pid_struct) return -ESRCH;

    rcu_read_lock();
    tsk = pid_task(pid_struct, PIDTYPE_PID);
    if (!tsk) {
        rcu_read_unlock();
        put_pid(pid_struct);
        return -ESRCH;
    }
    get_task_struct(tsk);
    rcu_read_unlock();

    new_cfg = kzalloc(sizeof(*new_cfg), GFP_KERNEL);
    if (!new_cfg) { ret = -ENOMEM; goto out_task; }

    mutex_lock(&g_bp_mutex);

    if (g_bp_count + hook_count > MAX_BPS) {
        mutex_unlock(&g_bp_mutex);
        kfree(new_cfg);
        ret = -ENOSPC;
        goto out_task;
    }

    old_cfg = rcu_dereference_protected(g_hook_config, lockdep_is_held(&g_bp_mutex));

    new_cfg->count = hook_count;
    for (i = 0; i < hook_count; i++) {
        new_cfg->hooks[i] = req->hooks[i];
    }

    rcu_assign_pointer(g_hook_config, new_cfg);

    for (i = 0; i < hook_count; i++) {
        int bp_err = 0;
        struct perf_event *bp = install_bp(tsk, req->hooks[i].vaddr, &bp_err);
        if (bp) {
            g_bps[g_bp_count++] = bp;
        } else {
            ret = bp_err;
        }
    }

    mutex_unlock(&g_bp_mutex);

    if (old_cfg) {
        synchronize_rcu();
        kfree(old_cfg);
    }

out_task:
    put_task_struct(tsk);
    put_pid(pid_struct);
    return ret;
}

static ssize_t core_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    struct core_cmd_packet pkt;
    struct wuwa_hbp_req    req;
    int err;

    if (count != sizeof(pkt)) return -EINVAL;
    if (copy_from_user(&pkt, buf, sizeof(pkt))) return -EFAULT;

    if (pkt.cmd_id == CMD_HBP_INSTALL) {
        if (copy_from_user(&req, (void __user *)pkt.payload_ptr, sizeof(req)))
            return -EFAULT;
        
        err = wuwa_install_perf_hbp(&req);
        
        if (err < 0) return err;
        return count; 
        
    } else if (pkt.cmd_id == CMD_HBP_CLEANUP) {
        wuwa_cleanup_perf_hbp();
        return count;
    } 

    return -EINVAL;
}

static const struct file_operations core_fops = {
    .owner = THIS_MODULE,
    .write = core_write,
};

static struct miscdevice core_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEV_NAME,
    .fops  = &core_fops,
};

int wuwa_hbp_init_device(void) {
    return misc_register(&core_misc);
}

void wuwa_hbp_cleanup_device(void) {
    wuwa_cleanup_perf_hbp();
    misc_deregister(&core_misc);
}
