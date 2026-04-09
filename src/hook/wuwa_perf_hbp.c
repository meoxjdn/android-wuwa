#include "../ioctl/wuwa_ioctl.h"
#include "wuwa_perf_hbp.h"
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/task_work.h>
#include <linux/version.h>

/* ================================================================
 * 核心偏移：100% 恢复为你最初实测有效的偏移！
 * ================================================================ */
#define OFF_BORDER      0x8951160ULL
#define OFF_PAUSE_WIN   0x2639fd8ULL
#define OFF_PAUSE_JMP   0x53709a0ULL
#define OFF_KILL        0x33b2ffcULL
#define OFF_DAMAGE      0x844f4d0ULL  // 恢复最原始有效的 MOV X19, X1 位置

/* 致命错误1修复：恢复大容量槽位，防止 UnityMain 断点被静默丢弃 */
#define MAX_BPS         512

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    #define WUWA_TWA TWA_SIGNAL
#else
    #define WUWA_TWA TWA_RESUME
#endif

/* 全局状态与卸载同步锁 */
static uint64_t          g_game_base  = 0;
static struct perf_event *g_bps[MAX_BPS];
static int               g_bp_count   = 0;
static int               g_border_on  = 0;
static int               g_skip_on    = 0;
static int               g_damage_on  = 0;
static int               g_maxhp_on   = 0;

static DEFINE_MUTEX(g_bp_mutex);
static atomic_t          g_handler_active = ATOMIC_INIT(0);
static atomic_t          g_shutting_down  = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(g_handler_wq);

typedef struct perf_event *(*reg_fn_t)(struct perf_event_attr *, perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unreg_fn_t)(struct perf_event *);
typedef long (*read_nofault_fn_t)(void *, const void __user *, size_t);
typedef int (*task_work_add_fn_t)(struct task_struct *, struct callback_head *, enum task_work_notify_mode);

static reg_fn_t           fn_register      = NULL;
static unreg_fn_t         fn_unregister    = NULL;
static read_nofault_fn_t  fn_nofault_read  = NULL;
static task_work_add_fn_t fn_task_work_add = NULL;

static unsigned long resolve_symbol(const char *name) {
    struct kprobe kp;
    unsigned long addr = 0;
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = name;
    if (register_kprobe(&kp) == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    }
    return addr;
}

static int resolve_all_symbols(void) {
    if (fn_register && fn_unregister && fn_nofault_read) return 0;
    fn_register      = (reg_fn_t)resolve_symbol("register_user_hw_breakpoint");
    fn_unregister    = (unreg_fn_t)resolve_symbol("unregister_hw_breakpoint");
    fn_nofault_read  = (read_nofault_fn_t)resolve_symbol("copy_from_user_nofault");
    if (!fn_nofault_read) fn_nofault_read = (read_nofault_fn_t)resolve_symbol("probe_kernel_read");
    fn_task_work_add = (task_work_add_fn_t)resolve_symbol("task_work_add");

    if (!fn_register || !fn_unregister) return -ENOSYS;
    return 0;
}

/* ================================================================
 * 核心断点回调 (去除所有内鬼拦截，还原 100 行版本的粗暴直接)
 * ================================================================ */
static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    uint64_t pc;
    uint64_t base;

    if (atomic_read(&g_shutting_down)) return;
    atomic_inc(&g_handler_active);
    if (atomic_read(&g_shutting_down)) goto out;

    /* 致命错误2修复：仅保留判空，彻底删除 validate_regs 和 SPSR_SS 误杀拦截！ */
    if (unlikely(!regs)) goto out;

    pc   = regs->pc;
    base = READ_ONCE(g_game_base);

    /* 1. 决斗场去黑边 */
    if (g_border_on && pc == base + OFF_BORDER) {
        regs->regs[0] = 1; // 致命错误3修复：补回这行丢失的代码！
        regs->pc = regs->regs[30];
        goto out;
    }

    /* 2. 副本秒过 */
    if (g_skip_on && pc == base + OFF_PAUSE_WIN) {
        regs->pc = base + OFF_PAUSE_JMP;
        goto out;
    }

    /* 3. 1血秒杀 */
    if (g_maxhp_on && pc == base + OFF_KILL) {
        regs->regs[0] = 1;
        regs->pc      = regs->regs[30];
        goto out;
    }

    /* 4. 智能无敌 (100% 恢复有效版本的业务逻辑) */
    if (g_damage_on && pc == base + OFF_DAMAGE) {
        uint32_t flag = 0;
        uint64_t target_addr = regs->regs[1] + 0x1C;
        if (fn_nofault_read && fn_nofault_read(&flag, (void __user *)target_addr, 4) == 0) {
            if (flag == 1) { 
                /* 敌人放行 (复刻原始逻辑) */
                regs->regs[19] = regs->regs[1];
                regs->pc += 4;
                goto out;
            }
        }
        /* 玩家受击：保护堆栈，无敌返回 */
        regs->sp += 0x30;
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        goto out;
    }

out:
    if (atomic_dec_and_test(&g_handler_active)) wake_up_all(&g_handler_wq);
}

/* ================================================================
 * 安装与清理
 * ================================================================ */
static struct perf_event *install_bp(struct task_struct *tsk, uint64_t addr) {
    struct perf_event_attr attr;
    struct perf_event     *bp;
    hw_breakpoint_init(&attr);
    attr.bp_addr  = addr;
    attr.bp_len   = HW_BREAKPOINT_LEN_4;
    attr.bp_type  = HW_BREAKPOINT_X;
    attr.disabled = 0;
    if (!fn_register) return NULL;
    bp = fn_register(&attr, wuwa_hbp_handler, NULL, tsk);
    if (IS_ERR(bp)) return NULL;
    return bp;
}

struct wuwa_cleanup_work { struct callback_head work; };
static void wuwa_on_game_exit(struct callback_head *work) {
    struct wuwa_cleanup_work *cw = container_of(work, struct wuwa_cleanup_work, work);
    wuwa_cleanup_perf_hbp();
    kfree(cw);
}

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct task_struct       *tsk;
    struct pid               *pid_struct;
    struct wuwa_cleanup_work *cw;
    struct perf_event        *bp;
    bool                      first_call;

    if (!req) return -EINVAL;
    if (resolve_all_symbols()) return -ENOSYS;

    pid_struct = find_get_pid(req->tid);
    if (!pid_struct) return -ESRCH;

    tsk = pid_task(pid_struct, PIDTYPE_PID);
    if (!tsk) { put_pid(pid_struct); return -ESRCH; }

    mutex_lock(&g_bp_mutex);

    first_call = (g_bp_count == 0);
    if (first_call) {
        WRITE_ONCE(g_game_base, req->base_addr);
        WRITE_ONCE(g_border_on, req->border_on);
        WRITE_ONCE(g_skip_on,   req->skip_on);
        WRITE_ONCE(g_damage_on, req->damage_on);
        WRITE_ONCE(g_maxhp_on,  req->maxhp_on);
        atomic_set(&g_shutting_down, 0);
        smp_mb();
    }

    if (g_bp_count + 5 >= MAX_BPS) {
        pr_err("[wuwa] 坑位已满！当前: %d\n", g_bp_count);
        goto unlock_out;
    }

    if (req->border_on) { bp = install_bp(tsk, req->base_addr + OFF_BORDER); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->skip_on)   { bp = install_bp(tsk, req->base_addr + OFF_PAUSE_WIN); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->maxhp_on)  { bp = install_bp(tsk, req->base_addr + OFF_KILL); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->damage_on) { bp = install_bp(tsk, req->base_addr + OFF_DAMAGE); if (bp) g_bps[g_bp_count++] = bp; }

    if (first_call) {
        cw = kmalloc(sizeof(*cw), GFP_KERNEL);
        if (cw) {
            init_task_work(&cw->work, wuwa_on_game_exit);
            if (fn_task_work_add) {
                if (fn_task_work_add(tsk, &cw->work, WUWA_TWA) != 0) kfree(cw);
            } else { kfree(cw); }
        }
    }

unlock_out:
    mutex_unlock(&g_bp_mutex);
    put_pid(pid_struct);
    return 0;
}

void wuwa_cleanup_perf_hbp(void) {
    struct perf_event *local_bps[MAX_BPS];
    int                local_count, i;

    atomic_set(&g_shutting_down, 1);
    smp_mb();
    wait_event_timeout(g_handler_wq, atomic_read(&g_handler_active) == 0, msecs_to_jiffies(1000));

    mutex_lock(&g_bp_mutex);
    local_count = g_bp_count;
    memcpy(local_bps, g_bps, sizeof(struct perf_event *) * local_count);
    memset(g_bps, 0, sizeof(g_bps));
    g_bp_count = 0;
    mutex_unlock(&g_bp_mutex);

    for (i = 0; i < local_count; i++) {
        if (local_bps[i] && fn_unregister) {
            fn_unregister(local_bps[i]);
            local_bps[i] = NULL;
        }
    }
}
