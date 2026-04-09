#include "wuwa_perf_hbp.h"
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>

/* ================================================================
 * 核心偏移 (与你的 KPM 影子页完美对应)
 * ================================================================ */
#define OFF_BORDER     0x8951160ULL
#define OFF_PAUSE_WIN  0x2639fd8ULL
#define OFF_PAUSE_JMP  0x53709a0ULL
#define OFF_GODMODE    0x844f4b4ULL   /* 伤害函数入口：精准截杀点 */
#define OFF_KILL       0x33b2ffcULL   /* 1血秒杀入口 */

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

/* Kprobe 动态寻址：无视 Android 15 白名单 */
static unsigned long resolve_hidden_symbol(const char *name) {
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr = 0;
    if (register_kprobe(&kp) == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    }
    return addr;
}

/* ================================================================
 * 核心硬件断点回调：零崩溃、零闪退
 * ================================================================ */
static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    uint64_t pc;
    if (unlikely(!regs)) return;
    pc = regs->pc;

    // 1. 秒过副本 (修改 PC 跳转至通关结算块)
    if (g_skip_on && pc == g_game_base + OFF_PAUSE_WIN) {
        regs->pc = g_game_base + OFF_PAUSE_JMP;
        return;
    }

    // 2. 去黑边 (入口处直接阻截返回，极度安全)
    if (g_border_on && pc == g_game_base + OFF_BORDER) {
        regs->pc = regs->regs[30]; 
        return;
    }

    // 3. 智能无敌 (入口阻截法，完美重现 KPM 逻辑)
    if (g_damage_on && pc == g_game_base + OFF_GODMODE) {
        // [防御性编程] 确保 X1 对象指针非空
        if (regs->regs[1] != 0) {
            uint32_t team_id = 1; // 默认视为敌人
            uint64_t target_addr = regs->regs[1] + 0x1C;
            
            // 安全读取内存中的 Team ID (绝对不会缺页死机)
            if (fn_nofault_read && fn_nofault_read(&team_id, (void __user *)target_addr, 4) == 0) {
                if (team_id == 0) {
                    // === 玩家实体 ===
                    // 此时在函数刚进门 (0x844f4b4)，堆栈还没动，强行 RET 完美无副作用
                    regs->regs[0] = 1;          // 锁定伤害为1
                    regs->pc = regs->regs[30];  // 踹回上一层函数
                    return;
                }
            }
        }
        // === 敌人实体 / 读取失败 / 环境伤害 ===
        // 什么都不做！直接 return！
        // 内核硬件断点系统会自动 Single-Step (单步执行) 这条指令，无缝放行！
        return;
    }

    // 4. 1血秒杀 (入口阻截，同理极度安全)
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
        bp = install_bp(tsk, g_game_base + OFF_GODMODE);
        if (bp) g_bps[g_bp_count++] = bp;
    }
    if (req->maxhp_on && g_bp_count < MAX_BPS) {
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
