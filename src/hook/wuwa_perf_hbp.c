#include "wuwa_perf_hbp.h"
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>

/* ===== 核心偏移 (参考你的 KPM) ===== */
#define OFF_BORDER     0x8951160   
#define OFF_PAUSE_WIN  0x2639fd8   
#define OFF_PAUSE_JMP  0x53709a0
/* 恢复到最原始的函数入口！ */
#define OFF_GODMODE    0x844f4b4   
#define OFF_KILL       0x33b2ffc   

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
static DEFINE_MUTEX(g_bp_mutex);

typedef struct perf_event *(*reg_user_hwbkpt_t)(struct perf_event_attr *attr, perf_overflow_handler_t triggered, void *context, struct task_struct *tsk);
typedef void (*unreg_hwbkpt_t)(struct perf_event *bp);
typedef long (*cfun_t)(void *dst, const void __user *src, size_t size);

static reg_user_hwbkpt_t fn_register = NULL;
static unreg_hwbkpt_t fn_unregister = NULL;
static cfun_t fn_nofault_read = NULL;

static unsigned long resolve_hidden_symbol(const char *name) {
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr = 0;
    if (register_kprobe(&kp) == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    }
    return addr;
}

/* ===== wuwa 核心拦截逻辑 ===== */
static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    uint64_t pc = regs->pc;

    // 1. 秒过副本 (对应 KPM 的 B 指令)
    if (g_skip_on && pc == g_game_base + OFF_PAUSE_WIN) {
        regs->pc = g_game_base + OFF_PAUSE_JMP;
        return;
    }

    // 2. 去黑边 (对应 KPM 的 RET)
    if (g_border_on && pc == g_game_base + OFF_BORDER) {
        regs->pc = regs->regs[30]; 
        return;
    }

    // 3. 智能敌我无敌 (1:1 完美复刻 KPM 汇编逻辑)
    if (g_damage_on && pc == g_game_base + OFF_GODMODE) {
        // [对应 KPM: CBZ X1] 如果 X1 是空，坚决不碰，放行原指令！
        if (regs->regs[1] != 0) {
            uint32_t team_id = 1; 
            uint64_t target_addr = regs->regs[1] + 0x1c;
            
            // [对应 KPM: LDR W16] 安全读取 team_id
            if (fn_nofault_read && fn_nofault_read(&team_id, (void __user *)target_addr, 4) == 0) {
                // [对应 KPM: CBNZ W16] 如果 team_id == 0 (玩家)，才执行无敌
                if (team_id == 0) {
                    regs->regs[0] = 1;          // [对应 KPM: MOV W0, #1]
                    regs->pc = regs->regs[30];  // [对应 KPM: RET]
                    return;
                }
            }
        }
        // 如果走到这里(X1为空，或是敌人，或读取失败)：
        // 绝对不要修改 PC！内核底层会自动 Single-Step (单步) 原本的 STP 指令，无缝放行！
        return;
    }

    // 4. 1血秒杀 (对应 KPM 写入的 MOV W0, #1; RET)
    if (g_maxhp_on && pc == g_game_base + OFF_KILL) {
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
        if (!fn_register || !fn_unregister) return -ENOSYS;
    }

    g_game_base = req->base_addr;
    g_border_on = req->border_on;
    g_skip_on = req->skip_on;
    g_damage_on = req->damage_on;
    g_maxhp_on = req->maxhp_on;

    pid_struct = find_get_pid(req->tid);
    if (!pid_struct) return -ESRCH;
    tsk = pid_task(pid_struct, PIDTYPE_PID);
    if (!tsk) { put_pid(pid_struct); return -ESRCH; }

    mutex_lock(&g_bp_mutex);
    if (req->border_on && g_bp_count < MAX_BPS) {
        bp = install_bp(tsk, g_game_base + OFF_BORDER);
        if (bp) g_bps[g_bp_count++] = bp;
    }
    if (req->skip_on && g_bp_count < MAX_BPS) {
        bp = install_bp(tsk, g_game_base + OFF_PAUSE_WIN);
        if (bp) g_bps[g_bp_count++] = bp;
    }
    if (req->damage_on && g_bp_count < MAX_BPS) {
        // 恢复在最安全的头部断点 0x844f4b4
        bp = install_bp(tsk, g_game_base + OFF_GODMODE);
        if (bp) g_bps[g_bp_count++] = bp;
    }
    if (req->maxhp_on && g_bp_count < MAX_BPS) {
        // 新增 1血秒杀的断点支持
        bp = install_bp(tsk, g_game_base + OFF_KILL);
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
