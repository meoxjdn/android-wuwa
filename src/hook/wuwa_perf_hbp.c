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
#include <asm/debug-monitors.h>
#include <asm/processor.h>
#include <asm/fpsimd.h>

/* ================================================================
 * 核心偏移定义 (已填入你的真实数据)
 * ================================================================ */
#define OFF_BORDER       0x8951160ULL
#define OFF_PAUSE_WIN    0x2639fd8ULL
#define OFF_PAUSE_JMP    0x53709a0ULL
#define OFF_KILL         0x33b2ffcULL
#define OFF_DAMAGE_STR   0x844f4c8ULL
#define OFF_FOV          0x9326F78ULL  // 你的 FOV 真实入口地址

/* * 坑位扩容：支持最多 32 个核心线程，每个线程 5 个断点 
 * 32 * 5 = 160，彻底解决日志里 11 个线程导致坑位溢出的问题
 */
#define MAX_BPS          160

/* 120.0f 的 IEEE 754 浮点十六进制 */
#define FOV_TARGET_BITS  0x4089999AU

/* ================================================================
 * TWA 兼容宏
 * ================================================================ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
  #define WUWA_TWA  TWA_SIGNAL
#else
  #define WUWA_TWA  TWA_RESUME
#endif

/* ================================================================
 * 全局状态与同步锁
 * ================================================================ */
static uint64_t          g_game_base  = 0;
static struct perf_event *g_bps[MAX_BPS];
static int               g_bp_count   = 0;
static int               g_fov_on     = 0;
static int               g_border_on  = 0;
static int               g_skip_on    = 0;
static int               g_damage_on  = 0;
static int               g_maxhp_on   = 0;

static DEFINE_MUTEX(g_bp_mutex);
static atomic_t          g_handler_active = ATOMIC_INIT(0);
static atomic_t          g_shutting_down  = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(g_handler_wq);

/* ================================================================
 * 函数指针类型定义
 * ================================================================ */
typedef struct perf_event *(*reg_fn_t)(struct perf_event_attr *, perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unreg_fn_t)(struct perf_event *);
typedef long (*read_nofault_fn_t)(void *, const void __user *, size_t);
typedef void (*fpsimd_save_fn_t)(struct user_fpsimd_state *);
typedef void (*fpsimd_load_fn_t)(const struct user_fpsimd_state *);
typedef int (*task_work_add_fn_t)(struct task_struct *, struct callback_head *, enum task_work_notify_mode);

static reg_fn_t            fn_register      = NULL;
static unreg_fn_t          fn_unregister    = NULL;
static read_nofault_fn_t   fn_nofault_read  = NULL;
static fpsimd_save_fn_t    fn_fpsimd_save   = NULL;
static fpsimd_load_fn_t    fn_fpsimd_load   = NULL;
static task_work_add_fn_t  fn_task_work_add = NULL;

/* ================================================================
 * Kprobe 符号解析
 * ================================================================ */
static unsigned long resolve_symbol(const char *name) {
    struct kprobe kp;
    unsigned long addr = 0;
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = name;
    if (register_kprobe(&kp) == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    }
    pr_info("[wuwa] resolve '%s' => 0x%lx\n", name, addr);
    return addr;
}

static int resolve_all_symbols(void) {
    if (fn_register && fn_unregister && fn_nofault_read) return 0;

    fn_register      = (reg_fn_t)resolve_symbol("register_user_hw_breakpoint");
    fn_unregister    = (unreg_fn_t)resolve_symbol("unregister_hw_breakpoint");
    fn_nofault_read  = (read_nofault_fn_t)resolve_symbol("copy_from_user_nofault");
    if (!fn_nofault_read) fn_nofault_read = (read_nofault_fn_t)resolve_symbol("probe_kernel_read");

    fn_fpsimd_save   = (fpsimd_save_fn_t)resolve_symbol("fpsimd_save_state");
    if (!fn_fpsimd_save) fn_fpsimd_save = (fpsimd_save_fn_t)resolve_symbol("fpsimd_save_and_flush_cpu_state");

    fn_fpsimd_load   = (fpsimd_load_fn_t)resolve_symbol("fpsimd_load_state");
    if (!fn_fpsimd_load) fn_fpsimd_load = (fpsimd_load_fn_t)resolve_symbol("fpsimd_flush_cpu_state");

    fn_task_work_add = (task_work_add_fn_t)resolve_symbol("task_work_add");

    if (!fn_register || !fn_unregister) {
        pr_err("[wuwa] 核心符号解析失败\n");
        return -ENOSYS;
    }
    return 0;
}

/* ================================================================
 * 安全内存读取
 * ================================================================ */
static inline int safe_read_u32(uint64_t addr, uint32_t *out) {
    if (!fn_nofault_read) return -ENOSYS;
    if (!access_ok((void __user *)addr, 4)) return -EFAULT;
    return (int)fn_nofault_read(out, (const void __user *)addr, 4);
}

static inline int validate_regs(struct pt_regs *regs) {
    if (unlikely(!regs)) return 0;
    if (!user_mode(regs)) return 0;
    if (regs->pc & 0x3) return 0;
    return 1;
}

/* ================================================================
 * 核心断点回调
 * ================================================================ */
static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    uint64_t pc;
    uint64_t base;

    if (atomic_read(&g_shutting_down)) return;
    atomic_inc(&g_handler_active);

    if (atomic_read(&g_shutting_down)) goto out;
    if (!validate_regs(regs)) goto out;
    if (regs->pstate & DBG_SPSR_SS) goto out;

    pc   = regs->pc;
    base = READ_ONCE(g_game_base);

    /* 1. 决斗场去黑边 */
    if (g_border_on && pc == base + OFF_BORDER) {
        regs->regs[0] = 1;
        regs->pc      = regs->regs[30];
        goto out;
    }

    /* 2. 全屏视野 (FOV)：内核级浮点完美修改 + 立即返回 */
    if (g_fov_on && pc == base + OFF_FOV) {
        if (fn_fpsimd_save && fn_fpsimd_load) {
            struct user_fpsimd_state *fp = &current->thread.uw.fpsimd_state;
            fn_fpsimd_save(fp);
            // 写入 120.0f (4.3f 等) 到 S0
            fp->vregs[0] = (fp->vregs[0] & ~((__uint128_t)0xFFFFFFFFULL)) | (__uint128_t)FOV_TARGET_BITS;
            fn_fpsimd_load(fp);
        }
        regs->pc = regs->regs[30]; // 强行返回，调用方直接读取 S0 里的新视野
        goto out;
    }

    /* 3. 副本秒过 */
    if (g_skip_on && pc == base + OFF_PAUSE_WIN) {
        regs->pc = base + OFF_PAUSE_JMP;
        goto out;
    }

    /* 4. 1血秒杀 */
    if (g_maxhp_on && pc == base + OFF_KILL) {
        regs->regs[0] = 1;
        regs->pc      = regs->regs[30];
        goto out;
    }

    /* 5. 智能无敌 (断在 STR 写入点，完美防卡死) */
    if (g_damage_on && pc == base + OFF_DAMAGE_STR) {
        uint32_t team_id = 1;
        if (regs->regs[1] != 0) {
            safe_read_u32(regs->regs[1] + 0x1C, &team_id);
        }
        if (team_id == 0) {
            regs->pc += 4; // 玩家：跳过扣血的 STR 写入
        }
        // 敌人：什么都不改，内核自动单步执行 STR，正常扣血
        goto out;
    }

out:
    if (atomic_dec_and_test(&g_handler_active)) wake_up_all(&g_handler_wq);
}

/* ================================================================
 * 辅助功能：安装与退出清理
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
    pr_info("[wuwa] 游戏进程退出，执行自动清理\n");
    wuwa_cleanup_perf_hbp();
    kfree(cw);
}

/* ================================================================
 * 外部接口：安装
 * ================================================================ */
int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct task_struct       *tsk;
    struct pid               *pid_struct;
    struct wuwa_cleanup_work *cw;
    struct perf_event        *bp;
    int                       ret;
    bool                      first_call;

    if (!req) return -EINVAL;

    ret = resolve_all_symbols();
    if (ret) return ret;

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
        WRITE_ONCE(g_fov_on,    req->fov_on);
        atomic_set(&g_shutting_down, 0);
        smp_mb();
    }

    // 坑位保护，每个线程最多需要 5 个断点
    if (g_bp_count + 5 >= MAX_BPS) {
        pr_err("[wuwa] 硬件断点坑位已满 (当前=%d, 最大=%d)，忽略后续线程\n", g_bp_count, MAX_BPS);
        ret = -ENOSPC;
        goto unlock_out;
    }

    /* 安装断点 */
    if (req->border_on) {
        bp = install_bp(tsk, req->base_addr + OFF_BORDER);
        if (bp) g_bps[g_bp_count++] = bp;
    }
    if (req->skip_on) {
        bp = install_bp(tsk, req->base_addr + OFF_PAUSE_WIN);
        if (bp) g_bps[g_bp_count++] = bp;
    }
    if (req->maxhp_on) {
        bp = install_bp(tsk, req->base_addr + OFF_KILL);
        if (bp) g_bps[g_bp_count++] = bp;
    }
    if (req->damage_on) {
        bp = install_bp(tsk, req->base_addr + OFF_DAMAGE_STR);
        if (bp) g_bps[g_bp_count++] = bp;
    }
    if (req->fov_on) {
        bp = install_bp(tsk, req->base_addr + OFF_FOV);
        if (bp) g_bps[g_bp_count++] = bp;
    }

    /* 挂载退出钩子 (只挂一次) */
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

    if (ret == 0) pr_info("[wuwa] TID %d 注入成功，当前已用断点数: %d\n", req->tid, g_bp_count);
    return ret;
}

/* ================================================================
 * 外部接口：清理
 * ================================================================ */
void wuwa_cleanup_perf_hbp(void) {
    struct perf_event *local_bps[MAX_BPS];
    int                local_count;
    int                i;

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
    pr_info("[wuwa] 清理完成\n");
}
