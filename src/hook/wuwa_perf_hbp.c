#include "wuwa_perf_hbp.h"
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/kprobes.h>
#include <linux/mutex.h> // 绝对安全的互斥锁

/* ===== 游戏核心偏移 ===== */
#define OFF_BORDER   0x8951160
#define OFF_SKIP     0x2639fd8
#define OFF_SKIP_JMP 0x53709a0

/* 【核心修改】将无敌断点下移到安全的 MOV X19, X1 指令处 (原偏移 0x844f4b4 + 0x1C) */
#define OFF_DAMAGE   0x844f4d0 

#define OFF_MAXHP    0x33b2ffc

#pragma pack(push, 8)
struct wuwa_hbp_req {
    int tid;
    uint64_t base_addr;
    int fov_on;
    int border_on;
    int skip_on;
    int damage_on;
    int maxhp_on;
};
#pragma pack(pop)

static uint64_t g_game_base = 0;
static int g_border_on = 0;
static int g_skip_on = 0;
static int g_damage_on = 0;
static int g_maxhp_on = 0;

#define MAX_BPS 512
static struct perf_event *g_bps[MAX_BPS];
static int g_bp_count = 0;

/* 安全互斥锁，防止安装断点时内核崩溃 */
static DEFINE_MUTEX(g_bp_mutex);

typedef struct perf_event *(*reg_user_hwbkpt_t)(struct perf_event_attr *attr,
                                                perf_overflow_handler_t triggered,
                                                void *context,
                                                struct task_struct *tsk);
typedef void (*unreg_hwbkpt_t)(struct perf_event *bp);
typedef long (*cfun_t)(void *dst, const void __user *src, size_t size);

static reg_user_hwbkpt_t fn_register = NULL;
static unreg_hwbkpt_t fn_unregister = NULL;
static cfun_t fn_nofault_read = NULL;

/* Kprobe 内存探针寻址引擎 */
static unsigned long resolve_hidden_symbol(const char *name) {
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr = 0;
    if (register_kprobe(&kp) == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    }
    return addr;
}

/* ===== 硬件断点内核回调 (硬中断上下文) ===== */
static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    uint64_t pc = regs->pc;

    if (g_skip_on && pc == g_game_base + OFF_SKIP) {
        regs->pc = g_game_base + OFF_SKIP_JMP;
        return;
    }

    if (g_border_on && pc == g_game_base + OFF_BORDER) {
        regs->pc = regs->regs[30]; 
        return;
    }

    /* 【核心修复】无敌/伤害的稳定版拦截逻辑 */
    if (g_damage_on && pc == g_game_base + OFF_DAMAGE) {
        uint32_t flag = 0;
        // 此时 X1 依然是你的对象指针
        uint64_t target_addr = regs->regs[1] + 0x1c;
        
        if (fn_nofault_read) {
            if (fn_nofault_read(&flag, (void __user *)target_addr, 4) == 0) {
                if (flag == 1) {
                    /* 需要放行：因为我们拦截的是 MOV X19, X1，必须帮它完成这步操作！ */
                    regs->regs[19] = regs->regs[1]; 
                    /* 强行把 PC 往下移，跳过这条指令，打破死循环！ */
                    regs->pc += 4; 
                    return;
                }
            }
        }
        
        /* 正常秒杀/无敌修改，提前返回，直接绕过整个函数的运算 */
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    if (g_maxhp_on && pc == g_game_base + OFF_MAXHP) {
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }
}

static struct perf_event *install_bp(struct task_struct *tsk, uint64_t addr) {
    struct perf_event_attr attr;
    struct perf_event *bp;

    hw_breakpoint_init(&attr);
    attr.bp_addr = addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_X; 
    attr.disabled = 0;

    if (!fn_register) return NULL;
    
    bp = fn_register(&attr, wuwa_hbp_handler, NULL, tsk);
    if (IS_ERR(bp)) return NULL;
    
    return bp;
}

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct task_struct *tsk;
    struct perf_event *bp;
    struct pid *pid_struct;

    if (!req) return -EINVAL;

    if (!fn_register || !fn_unregister) {
        fn_register = (reg_user_hwbkpt_t)resolve_hidden_symbol("register_user_hw_breakpoint");
        fn_unregister = (unreg_hwbkpt_t)resolve_hidden_symbol("unregister_hw_breakpoint");
        fn_nofault_read = (cfun_t)resolve_hidden_symbol("copy_from_user_nofault");
        
        if (!fn_nofault_read) fn_nofault_read = (cfun_t)resolve_hidden_symbol("probe_kernel_read");

        if (!fn_register || !fn_unregister) {
            return -ENOSYS;
        }
    }

    g_game_base = req->base_addr;
    g_border_on = req->border_on;
    g_skip_on = req->skip_on;
    g_damage_on = req->damage_on;
    g_maxhp_on = req->maxhp_on;

    pid_struct = find_get_pid(req->tid);
    if (!pid_struct) return -ESRCH;

    tsk = pid_task(pid_struct, PIDTYPE_PID);
    if (!tsk) {
        put_pid(pid_struct);
        return -ESRCH;
    }

    mutex_lock(&g_bp_mutex);
    if (req->border_on && g_bp_count < MAX_BPS) {
        bp = install_bp(tsk, g_game_base + OFF_BORDER);
        if (bp) g_bps[g_bp_count++] = bp;
    }
    if (req->skip_on && g_bp_count < MAX_BPS) {
        bp = install_bp(tsk, g_game_base + OFF_SKIP);
        if (bp) g_bps[g_bp_count++] = bp;
    }
    if (req->damage_on && g_bp_count < MAX_BPS) {
        bp = install_bp(tsk, g_game_base + OFF_DAMAGE);
        if (bp) g_bps[g_bp_count++] = bp;
    }
    if (req->maxhp_on && g_bp_count < MAX_BPS) {
        bp = install_bp(tsk, g_game_base + OFF_MAXHP);
        if (bp) g_bps[g_bp_count++] = bp;
    }
    mutex_unlock(&g_bp_mutex);

    put_pid(pid_struct);
    return 0; 
}

void wuwa_cleanup_perf_hbp(void) {
    int i;
    mutex_lock(&g_bp_mutex);
    for (i = 0; i < g_bp_count; i++) {
        if (g_bps[i] && fn_unregister) {
            fn_unregister(g_bps[i]);
            g_bps[i] = NULL;
        }
    }
    g_bp_count = 0;
    mutex_unlock(&g_bp_mutex);
}
