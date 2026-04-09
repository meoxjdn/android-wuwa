#include "wuwa_perf_hbp.h"
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>

/* ===== 游戏核心偏移 (从你的 Ptrace 工具中移植) ===== */
#define OFF_BORDER   0x8951160
#define OFF_SKIP     0x2639fd8
#define OFF_SKIP_JMP 0x53709a0
#define OFF_DAMAGE   0x844f4b4
#define OFF_MAXHP    0x33b2ffc

/* 与 C++ 端严格对应的结构体 (8字节对齐) */
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

/* ===== 全局状态配置 ===== */
static uint64_t g_game_base = 0;
static int g_border_on = 0;
static int g_skip_on = 0;
static int g_damage_on = 0;
static int g_maxhp_on = 0;

#define MAX_BPS 512
static struct perf_event *g_bps[MAX_BPS];
static int g_bp_count = 0;
static DEFINE_SPINLOCK(g_bp_lock);

/* 安全内存读取，防止 copy_from_user 导致中断休眠死机 */
static int safe_read_u32(uint64_t addr, uint32_t *val) {
    int ret;
    pagefault_disable();
    ret = __get_user(*val, (uint32_t __user *)addr);
    pagefault_enable();
    return ret;
}

/* ===== 硬件断点内核回调 (核心劫持逻辑) ===== */
static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    uint64_t pc = regs->pc;

    // 1. 副本秒过 (Skip)
    if (g_skip_on && pc == g_game_base + OFF_SKIP) {
        regs->pc = g_game_base + OFF_SKIP_JMP;
        return;
    }

    // 2. 去黑边 (Border)
    if (g_border_on && pc == g_game_base + OFF_BORDER) {
        regs->pc = regs->regs[30]; 
        return;
    }

    // 3. 副本全秒/伤害 (Damage)
    if (g_damage_on && pc == g_game_base + OFF_DAMAGE) {
        uint32_t flag = 0;
        uint64_t target_addr = regs->regs[1] + 0x1c;
        
        if (safe_read_u32(target_addr, &flag) == 0) {
            if (flag == 1) {
                /* 内核自动单步跳过并放行 */
                return; 
            }
        }
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    // 4. 副本最大血量 (MaxHP)
    if (g_maxhp_on && pc == g_game_base + OFF_MAXHP) {
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }
}

/* ===== 安装单个断点 ===== */
static struct perf_event *install_bp(struct task_struct *tsk, uint64_t addr) {
    struct perf_event_attr attr;
    struct perf_event *bp;

    hw_breakpoint_init(&attr);
    attr.bp_addr = addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_X; 
    attr.disabled = 0;

    bp = register_user_hw_breakpoint(&attr, wuwa_hbp_handler, NULL, tsk);
    if (IS_ERR(bp)) return NULL;
    
    return bp;
}

/* ===== 与 C++ 工具通信的入口 (已修复类型冲突) ===== */
int wuwa_install_perf_hbp(struct wuwa_hbp_req *user_req) {
    struct wuwa_hbp_req req;
    struct task_struct *tsk;
    struct perf_event *bp;
    struct pid *pid_struct;

    // 将用户态指针强制转换读取，匹配头文件声明
    if (copy_from_user(&req, (void __user *)user_req, sizeof(req))) {
        return -EFAULT;
    }

    g_game_base = req.base_addr;
    g_border_on = req.border_on;
    g_skip_on = req.skip_on;
    g_damage_on = req.damage_on;
    g_maxhp_on = req.maxhp_on;

    pid_struct = find_get_pid(req.tid);
    if (!pid_struct) return -ESRCH;

    tsk = pid_task(pid_struct, PIDTYPE_PID);
    if (!tsk) {
        put_pid(pid_struct);
        return -ESRCH;
    }

    spin_lock(&g_bp_lock);
    if (req.border_on && g_bp_count < MAX_BPS) {
        bp = install_bp(tsk, g_game_base + OFF_BORDER);
        if (bp) g_bps[g_bp_count++] = bp;
    }
    if (req.skip_on && g_bp_count < MAX_BPS) {
        bp = install_bp(tsk, g_game_base + OFF_SKIP);
        if (bp) g_bps[g_bp_count++] = bp;
    }
    if (req.damage_on && g_bp_count < MAX_BPS) {
        bp = install_bp(tsk, g_game_base + OFF_DAMAGE);
        if (bp) g_bps[g_bp_count++] = bp;
    }
    if (req.maxhp_on && g_bp_count < MAX_BPS) {
        bp = install_bp(tsk, g_game_base + OFF_MAXHP);
        if (bp) g_bps[g_bp_count++] = bp;
    }
    spin_unlock(&g_bp_lock);

    put_pid(pid_struct);
    return 0; 
}

/* ===== 清理函数 ===== */
void wuwa_cleanup_perf_hbp(void) {
    int i;
    spin_lock(&g_bp_lock);
    for (i = 0; i < g_bp_count; i++) {
        if (g_bps[i]) {
            unregister_hw_breakpoint(g_bps[i]);
            g_bps[i] = NULL;
        }
    }
    g_bp_count = 0;
    spin_unlock(&g_bp_lock);
}
