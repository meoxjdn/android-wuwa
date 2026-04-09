#include "wuwa_perf_hbp.h"
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/kprobes.h> 

/* ===== 游戏核心偏移 ===== */
#define OFF_BORDER   0x8951160
#define OFF_SKIP     0x2639fd8
#define OFF_SKIP_JMP 0x53709a0
#define OFF_DAMAGE   0x844f4b4
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
static DEFINE_SPINLOCK(g_bp_lock);

/* ===== 探针寻址函数指针定义 ===== */
typedef struct perf_event *(*reg_user_hwbkpt_t)(struct perf_event_attr *attr,
                                                perf_overflow_handler_t triggered,
                                                void *context,
                                                struct task_struct *tsk);
typedef void (*unreg_hwbkpt_t)(struct perf_event *bp);
typedef long (*cfun_t)(void *dst, const void __user *src, size_t size); // 定义无缺页拷贝

static reg_user_hwbkpt_t fn_register = NULL;
static unreg_hwbkpt_t fn_unregister = NULL;
static cfun_t fn_nofault_read = NULL; // 存放安全的读取函数

static unsigned long resolve_hidden_symbol(const char *name) {
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr = 0;
    if (register_kprobe(&kp) == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    }
    return addr;
}

/* ===== 硬件断点内核回调 (这里绝对不能有任何会休眠的代码) ===== */
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

    if (g_damage_on && pc == g_game_base + OFF_DAMAGE) {
        uint32_t flag = 0;
        uint64_t target_addr = regs->regs[1] + 0x1c;
        
        // 使用探针挖出来的安全读取函数，绝对不会引发 Kernel Panic 死机！
        if (fn_nofault_read) {
            if (fn_nofault_read(&flag, (void __user *)target_addr, 4) == 0) {
                if (flag == 1) return; // 放行原指令
            }
        }
        
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

    // 初始化时一并挖出 copy_from_user_nofault
    if (!fn_register || !fn_unregister || !fn_nofault_read) {
        fn_register = (reg_user_hwbkpt_t)resolve_hidden_symbol("register_user_hw_breakpoint");
        fn_unregister = (unreg_hwbkpt_t)resolve_hidden_symbol("unregister_hw_breakpoint");
        fn_nofault_read = (cfun_t)resolve_hidden_symbol("copy_from_user_nofault");
        
        // 兼容更旧或更新的内核命名
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

    spin_lock(&g_bp_lock);
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
    spin_unlock(&g_bp_lock);

    put_pid(pid_struct);
    return 0; 
}

void wuwa_cleanup_perf_hbp(void) {
    int i;
    spin_lock(&g_bp_lock);
    for (i = 0; i < g_bp_count; i++) {
        if (g_bps[i] && fn_unregister) {
            fn_unregister(g_bps[i]);
            g_bps[i] = NULL;
        }
    }
    g_bp_count = 0;
    spin_unlock(&g_bp_lock);
}
