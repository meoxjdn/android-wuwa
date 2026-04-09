/* wuwa_perf_hbp.c */
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
#include <asm/debug-monitors.h>
#include <asm/processor.h>
#include <asm/fpsimd.h>

/* ================================================================
 * 偏移定义
 * ================================================================ */
#define OFF_BORDER       0x8951160ULL
#define OFF_PAUSE_WIN    0x2639fd8ULL
#define OFF_PAUSE_JMP    0x53709a0ULL
#define OFF_KILL         0x33b2ffcULL
#define OFF_DAMAGE_STR   0x844f4c8ULL
#define OFF_FOV_LDR      0x0ULL        /* TODO: IDA 确认后填入实际偏移 */
#define OFF_FOV_POOL     (OFF_FOV_LDR + 8ULL)

#define MAX_BPS          8
#define FOV_TARGET       120.0f

/* ================================================================
 * TWA 兼容
 * ================================================================ */
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
  #define WUWA_TWA  TWA_SIGNAL
#else
  #define WUWA_TWA  TWA_RESUME
#endif

/* ================================================================
 * 全局状态
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
typedef struct perf_event *(*reg_fn_t)(
    struct perf_event_attr *,
    perf_overflow_handler_t,
    void *,
    struct task_struct *);

typedef void (*unreg_fn_t)(struct perf_event *);

typedef long (*read_nofault_fn_t)(
    void *,
    const void __user *,
    size_t);

typedef long (*write_nofault_fn_t)(
    void __user *,
    const void *,
    size_t);

typedef void (*fpsimd_save_fn_t)(struct user_fpsimd_state *);
typedef void (*fpsimd_load_fn_t)(const struct user_fpsimd_state *);

typedef int (*task_work_add_fn_t)(
    struct task_struct *,
    struct callback_head *,
    enum task_work_notify_mode);

static reg_fn_t            fn_register       = NULL;
static unreg_fn_t          fn_unregister     = NULL;
static read_nofault_fn_t   fn_nofault_read   = NULL;
static write_nofault_fn_t  fn_nofault_write  = NULL;
static fpsimd_save_fn_t    fn_fpsimd_save    = NULL;
static fpsimd_load_fn_t    fn_fpsimd_load    = NULL;
static task_work_add_fn_t  fn_task_work_add  = NULL;

/* ================================================================
 * Kprobe 符号解析
 * ================================================================ */
static unsigned long resolve_symbol(const char *name)
{
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

static int resolve_all_symbols(void)
{
    if (fn_register && fn_unregister && fn_nofault_read)
        return 0;

    fn_register = (reg_fn_t)
        resolve_symbol("register_user_hw_breakpoint");

    fn_unregister = (unreg_fn_t)
        resolve_symbol("unregister_hw_breakpoint");

    fn_nofault_read = (read_nofault_fn_t)
        resolve_symbol("copy_from_user_nofault");
    if (!fn_nofault_read)
        fn_nofault_read = (read_nofault_fn_t)
            resolve_symbol("probe_kernel_read");

    fn_nofault_write = (write_nofault_fn_t)
        resolve_symbol("copy_to_user_nofault");

    fn_fpsimd_save = (fpsimd_save_fn_t)
        resolve_symbol("fpsimd_save_state");
    if (!fn_fpsimd_save)
        fn_fpsimd_save = (fpsimd_save_fn_t)
            resolve_symbol("fpsimd_save_and_flush_cpu_state");

    fn_fpsimd_load = (fpsimd_load_fn_t)
        resolve_symbol("fpsimd_load_state");
    if (!fn_fpsimd_load)
        fn_fpsimd_load = (fpsimd_load_fn_t)
            resolve_symbol("fpsimd_flush_cpu_state");

    /* task_work_add 不在 GKI 白名单，通过 kprobe 解析 */
    fn_task_work_add = (task_work_add_fn_t)
        resolve_symbol("task_work_add");

    if (!fn_register || !fn_unregister) {
        pr_err("[wuwa] 核心符号解析失败\n");
        return -ENOSYS;
    }

    if (!fn_task_work_add)
        pr_warn("[wuwa] task_work_add 不可用，退出钩子禁用\n");
    if (!fn_nofault_read)
        pr_warn("[wuwa] 内存安全读取不可用\n");
    if (!fn_fpsimd_save || !fn_fpsimd_load)
        pr_warn("[wuwa] fpsimd 不可用，FOV 走字面量池方案\n");

    return 0;
}

/* ================================================================
 * 安全内存读取
 * ================================================================ */
static inline int safe_read_u32(uint64_t addr, uint32_t *out)
{
    if (!fn_nofault_read)
        return -ENOSYS;
    if (!access_ok((void __user *)addr, 4))
        return -EFAULT;
    return (int)fn_nofault_read(out, (const void __user *)addr, 4);
}

/* ================================================================
 * pt_regs 合法性校验
 * ================================================================ */
static inline int validate_regs(struct pt_regs *regs)
{
    if (unlikely(!regs))
        return 0;
    if (!user_mode(regs))
        return 0;
    if (regs->pc & 0x3)
        return 0;
    return 1;
}

/* ================================================================
 * FOV 路线一：改字面量池
 * ================================================================ */
static int fov_patch_literal_pool(uint64_t game_base, float fov)
{
    uint64_t pool_addr;
    uint32_t bits;
    long     ret;

    if (OFF_FOV_LDR == 0ULL)
        return -ENOENT;

    if (!fn_nofault_write)
        return -ENOSYS;

    pool_addr = game_base + OFF_FOV_POOL;
    memcpy(&bits, &fov, 4);

    ret = fn_nofault_write((void __user *)pool_addr, &bits, 4);
    if (ret != 0) {
        pr_warn("[wuwa] FOV 字面量池写入失败 ret=%ld\n", ret);
        return (int)ret;
    }

    pr_info("[wuwa] FOV 字面量池已更新 addr=0x%llx val=0x%08X\n",
            pool_addr, bits);
    return 0;
}

/* ================================================================
 * FOV 路线三：fpsimd 直接操作
 * ================================================================ */
static void fov_handle_via_fpsimd(struct pt_regs *regs, float fov)
{
    struct user_fpsimd_state *fp;
    uint32_t                  bits;

    if (!fn_fpsimd_save || !fn_fpsimd_load) {
        pr_warn_ratelimited("[wuwa] fpsimd 不可用，FOV 跳过\n");
        return;
    }

    fp = &current->thread.uw.fpsimd_state;

    fn_fpsimd_save(fp);

    memcpy(&bits, &fov, 4);
    fp->vregs[0] = (fp->vregs[0] & ~((__uint128_t)0xFFFFFFFFULL)) |
                   (__uint128_t)bits;

    fn_fpsimd_load(fp);

    regs->pc += 4;
}

/* ================================================================
 * 核心断点回调
 * ================================================================ */
static void wuwa_hbp_handler(struct perf_event       *bp,
                              struct perf_sample_data *data,
                              struct pt_regs          *regs)
{
    uint64_t pc;
    uint64_t base;

    if (atomic_read(&g_shutting_down))
        return;

    atomic_inc(&g_handler_active);

    if (atomic_read(&g_shutting_down))
        goto out;

    if (!validate_regs(regs))
        goto out;

    if (regs->pstate & DBG_SPSR_SS)
        goto out;

    pc   = regs->pc;
    base = READ_ONCE(g_game_base);

    /* 去黑边 */
    if (g_border_on && pc == base + OFF_BORDER) {
        regs->regs[0] = 1;
        regs->pc      = regs->regs[30];
        goto out;
    }

    /* 秒过副本 */
    if (g_skip_on && pc == base + OFF_PAUSE_WIN) {
        regs->pc = base + OFF_PAUSE_JMP;
        goto out;
    }

    /* 1血秒杀 */
    if (g_maxhp_on && pc == base + OFF_KILL) {
        regs->regs[0] = 1;
        regs->pc      = regs->regs[30];
        goto out;
    }

    /* 智能无敌 */
    if (g_damage_on && pc == base + OFF_DAMAGE_STR) {
        uint32_t team_id = 1;

        if (regs->regs[1] != 0)
            safe_read_u32(regs->regs[1] + 0x1C, &team_id);

        if (team_id == 0)
            regs->pc += 4;

        goto out;
    }

    /* 全屏 FOV（路线三） */
    if (g_fov_on && OFF_FOV_LDR != 0ULL &&
        pc == base + OFF_FOV_LDR) {
        fov_handle_via_fpsimd(regs, FOV_TARGET);
        goto out;
    }

out:
    if (atomic_dec_and_test(&g_handler_active))
        wake_up_all(&g_handler_wq);
}

/* ================================================================
 * 断点安装辅助
 * ================================================================ */
static struct perf_event *install_bp(struct task_struct *tsk,
                                      uint64_t            addr)
{
    struct perf_event_attr attr;
    struct perf_event     *bp;

    hw_breakpoint_init(&attr);
    attr.bp_addr  = addr;
    attr.bp_len   = HW_BREAKPOINT_LEN_4;
    attr.bp_type  = HW_BREAKPOINT_X;
    attr.disabled = 0;

    if (!fn_register)
        return NULL;

    bp = fn_register(&attr, wuwa_hbp_handler, NULL, tsk);
    if (IS_ERR(bp)) {
        pr_err("[wuwa] 断点安装失败 addr=0x%llx err=%ld\n",
               addr, PTR_ERR(bp));
        return NULL;
    }

    pr_info("[wuwa] 断点已安装 addr=0x%llx\n", addr);
    return bp;
}

/* ================================================================
 * 进程退出自清理
 * ================================================================ */
struct wuwa_cleanup_work {
    struct callback_head work;
};

static void wuwa_on_game_exit(struct callback_head *work)
{
    struct wuwa_cleanup_work *cw =
        container_of(work, struct wuwa_cleanup_work, work);

    pr_info("[wuwa] 游戏进程退出，执行自动清理\n");
    wuwa_cleanup_perf_hbp();
    kfree(cw);
}

/* ================================================================
 * 外部接口：安装
 * ================================================================ */
int wuwa_install_perf_hbp(struct wuwa_hbp_req *req)
{
    struct task_struct       *tsk;
    struct pid               *pid_struct;
    struct wuwa_cleanup_work *cw;
    struct perf_event        *bp;
    int                       fov_needs_bp = 0;
    int                       ret;

    if (!req)
        return -EINVAL;

    ret = resolve_all_symbols();
    if (ret)
        return ret;

    wuwa_cleanup_perf_hbp();

    pid_struct = find_get_pid(req->tid);
    if (!pid_struct)
        return -ESRCH;

    tsk = pid_task(pid_struct, PIDTYPE_PID);
    if (!tsk) {
        put_pid(pid_struct);
        return -ESRCH;
    }

    WRITE_ONCE(g_game_base, req->base_addr);
    WRITE_ONCE(g_border_on, req->border_on);
    WRITE_ONCE(g_skip_on,   req->skip_on);
    WRITE_ONCE(g_damage_on, req->damage_on);
    WRITE_ONCE(g_maxhp_on,  req->maxhp_on);
    WRITE_ONCE(g_fov_on,    req->fov_on);

    atomic_set(&g_shutting_down, 0);
    smp_mb();

    mutex_lock(&g_bp_mutex);

    /* 去黑边 */
    if (req->border_on && g_bp_count < MAX_BPS) {
        bp = install_bp(tsk, req->base_addr + OFF_BORDER);
        if (bp) g_bps[g_bp_count++] = bp;
    }

    /* 秒过副本 */
    if (req->skip_on && g_bp_count < MAX_BPS) {
        bp = install_bp(tsk, req->base_addr + OFF_PAUSE_WIN);
        if (bp) g_bps[g_bp_count++] = bp;
    }

    /* 1血秒杀 */
    if (req->maxhp_on && g_bp_count < MAX_BPS) {
        bp = install_bp(tsk, req->base_addr + OFF_KILL);
        if (bp) g_bps[g_bp_count++] = bp;
    }

    /* 智能无敌 */
    if (req->damage_on && g_bp_count < MAX_BPS) {
        bp = install_bp(tsk, req->base_addr + OFF_DAMAGE_STR);
        if (bp) g_bps[g_bp_count++] = bp;
    }

    /* 全屏 FOV */
    if (req->fov_on) {
        ret = fov_patch_literal_pool(req->base_addr, FOV_TARGET);
        if (ret != 0 && OFF_FOV_LDR != 0ULL) {
            pr_info("[wuwa] FOV 切换到路线三\n");
            fov_needs_bp = 1;
        }
        if (fov_needs_bp && g_bp_count < MAX_BPS) {
            bp = install_bp(tsk, req->base_addr + OFF_FOV_LDR);
            if (bp) g_bps[g_bp_count++] = bp;
        }
    }

    /* 进程退出钩子 */
    cw = kmalloc(sizeof(*cw), GFP_KERNEL);
    if (cw) {
        init_task_work(&cw->work, wuwa_on_game_exit);
        if (fn_task_work_add) {
            if (fn_task_work_add(tsk, &cw->work, WUWA_TWA) != 0)
                kfree(cw);
        } else {
            kfree(cw);
            pr_warn("[wuwa] 退出钩子未挂载，游戏退出后请手动 rmmod\n");
        }
    }

    mutex_unlock(&g_bp_mutex);
    put_pid(pid_struct);

    pr_info("[wuwa] 安装完成，共 %d 个断点\n", g_bp_count);
    return 0;
}

/* ================================================================
 * 外部接口：清理
 * ================================================================ */
void wuwa_cleanup_perf_hbp(void)
{
    struct perf_event *local_bps[MAX_BPS];
    int                local_count;
    int                i;

    atomic_set(&g_shutting_down, 1);
    smp_mb();

    wait_event_timeout(g_handler_wq,
                       atomic_read(&g_handler_active) == 0,
                       msecs_to_jiffies(1000));

    mutex_lock(&g_bp_mutex);
    local_count = g_bp_count;
    memcpy(local_bps, g_bps,
           sizeof(struct perf_event *) * local_count);
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
