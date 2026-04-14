#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <asm/processor.h>
#include <asm/fpsimd.h>

/* ================================================================
 * 日志伪装与静默控制
 * ================================================================ */
#define DEBUG_MODE 0

#if DEBUG_MODE
#define CORE_INFO(fmt, ...) pr_info("[kworker] " fmt, ##__VA_ARGS__)
#define CORE_ERR(fmt, ...) pr_err("[kworker_err] " fmt, ##__VA_ARGS__)
#else
#define CORE_INFO(fmt, ...) do {} while(0)
#define CORE_ERR(fmt, ...) do {} while(0)
#endif

/* ================================================================
 * 核心偏移
 * ================================================================ */
#define OFF_BORDER      0x8951160ULL
#define OFF_PAUSE_WIN   0x2639fd8ULL
#define OFF_PAUSE_JMP   0x53709a0ULL
#define OFF_KILL        0x33b2ffcULL
#define OFF_DAMAGE      0x844f4d0ULL
#define OFF_FOV         0x9326F78ULL  

#define MAX_BPS         160
#define FOV_TARGET_BITS 0x4089999AU

/* ================================================================
 * 全局状态与类型定义
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

typedef struct perf_event *(*reg_fn_t)(struct perf_event_attr *, perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unreg_fn_t)(struct perf_event *);
typedef long (*read_nofault_fn_t)(void *, const void __user *, size_t);
typedef void (*fpsimd_save_fn_t)(struct user_fpsimd_state *);
typedef void (*fpsimd_load_fn_t)(const struct user_fpsimd_state *);

static reg_fn_t           fn_register      = NULL;
static unreg_fn_t         fn_unregister    = NULL;
/* 恢复基础底层函数指针 */
static read_nofault_fn_t  fn_nofault_read  = NULL;
static fpsimd_save_fn_t   fn_fpsimd_save   = NULL;
static fpsimd_load_fn_t   fn_fpsimd_load   = NULL;

#pragma pack(push, 8)
struct wuwa_hbp_req {
    int      tid;
    uint64_t base_addr;
    int      fov_on;
    int      border_on;
    int      skip_on;
    int      damage_on;
    int      maxhp_on;
    uint64_t reg_addr;
    uint64_t unreg_addr;
    /* 接收用户态解析的底层函数地址 */
    uint64_t nofault_read_addr;
    uint64_t fpsimd_save_addr;
    uint64_t fpsimd_load_addr;
};
#pragma pack(pop)

struct core_cmd_packet {
    uint32_t cmd_id;
    uint64_t payload_ptr;
};
#define CMD_HBP_INSTALL 0x5A5A1001

/* ================================================================
 * 核心断点回调 (已全量还原业务逻辑)
 * ================================================================ */
static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    uint64_t pc;
    uint64_t base;

    if (unlikely(!regs)) return;

    pc   = regs->pc;
    base = g_game_base;

    /* 1. 去黑边 */
    if (g_border_on && pc == base + OFF_BORDER) {
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    /* 2. 副本秒过 */
    if (g_skip_on && pc == base + OFF_PAUSE_WIN) {
        regs->pc = base + OFF_PAUSE_JMP;
        return;
    }

    /* 3. 1血秒杀 */
    if (g_maxhp_on && pc == base + OFF_KILL) {
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    /* 4. 智能无敌 (还原完整内存安全读取与敌我判定逻辑) */
    if (g_damage_on && pc == base + OFF_DAMAGE) {
        uint32_t flag = 0;
        uint64_t target_addr = regs->regs[1] + 0x1C;
        if (fn_nofault_read) {
            if (fn_nofault_read(&flag, (void __user *)target_addr, 4) == 0) {
                if (flag == 1) { // 敌人受击
                    regs->regs[19] = regs->regs[1]; 
                    regs->pc += 4; 
                    return;
                }
            }
        }
        /* 玩家受击，执行免疫与堆栈修复 */
        regs->sp += 0x30;
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    /* 5. 全屏 FOV (还原浮点寄存器暴力修改逻辑) */
    if (g_fov_on && pc == base + OFF_FOV) {
        if (fn_fpsimd_save && fn_fpsimd_load) {
            struct user_fpsimd_state *fp = &current->thread.uw.fpsimd_state;
            fn_fpsimd_save(fp);
            fp->vregs[0] = (fp->vregs[0] & ~((__uint128_t)0xFFFFFFFFULL)) | (__uint128_t)FOV_TARGET_BITS;
            fn_fpsimd_load(fp);
        }
        regs->pc = regs->regs[30];
        return;
    }
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

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct task_struct *tsk;
    struct pid         *pid_struct;

    if (!req) return -EINVAL;

    /* 接收并初始化所有函数指针 */
    if (!fn_register && req->reg_addr) fn_register = (reg_fn_t)req->reg_addr;
    if (!fn_unregister && req->unreg_addr) fn_unregister = (unreg_fn_t)req->unreg_addr;
    if (!fn_nofault_read && req->nofault_read_addr) fn_nofault_read = (read_nofault_fn_t)req->nofault_read_addr;
    if (!fn_fpsimd_save && req->fpsimd_save_addr) fn_fpsimd_save = (fpsimd_save_fn_t)req->fpsimd_save_addr;
    if (!fn_fpsimd_load && req->fpsimd_load_addr) fn_fpsimd_load = (fpsimd_load_fn_t)req->fpsimd_load_addr;
    
    if (!fn_register) return -ENOSYS;

    pid_struct = find_get_pid(req->tid);
    if (!pid_struct) return -ESRCH;

    tsk = pid_task(pid_struct, PIDTYPE_PID);
    if (!tsk) { put_pid(pid_struct); return -ESRCH; }

    mutex_lock(&g_bp_mutex);

    if (g_bp_count == 0) {
        g_game_base = req->base_addr;
        g_border_on = req->border_on;
        g_skip_on   = req->skip_on;
        g_damage_on = req->damage_on;
        g_maxhp_on  = req->maxhp_on;
        g_fov_on    = req->fov_on;
    }

    if (g_bp_count + 5 >= MAX_BPS) goto unlock_out;

    if (req->border_on) { struct perf_event *bp = install_bp(tsk, req->base_addr + OFF_BORDER); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->skip_on)   { struct perf_event *bp = install_bp(tsk, req->base_addr + OFF_PAUSE_WIN); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->maxhp_on)  { struct perf_event *bp = install_bp(tsk, req->base_addr + OFF_KILL); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->damage_on) { struct perf_event *bp = install_bp(tsk, req->base_addr + OFF_DAMAGE); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->fov_on)    { struct perf_event *bp = install_bp(tsk, req->base_addr + OFF_FOV); if (bp) g_bps[g_bp_count++] = bp; }

unlock_out:
    mutex_unlock(&g_bp_mutex);
    put_pid(pid_struct);
    CORE_INFO("Injected TID: %d\n", req->tid);
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

/* ================================================================
 * 字符设备通信层
 * ================================================================ */
static ssize_t core_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    struct core_cmd_packet pkt;
    struct wuwa_hbp_req req;
    
    if (count != sizeof(pkt)) return -EINVAL;
    if (copy_from_user(&pkt, buf, sizeof(pkt))) return -EFAULT;
    
    if (pkt.cmd_id == CMD_HBP_INSTALL) {
        if (copy_from_user(&req, (void __user *)pkt.payload_ptr, sizeof(req))) {
            return -EFAULT;
        }
        wuwa_install_perf_hbp(&req);
    }
    return count;
}

static const struct file_operations core_fops = {
    .owner = THIS_MODULE,
    .write = core_write,
};

static struct miscdevice core_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "logd_service",
    .fops  = &core_fops,
};

int wuwa_hbp_init_device(void) {
    int ret = misc_register(&core_misc);
    if (ret) CORE_ERR("Failed to register misc device\n");
    return ret;
}

void wuwa_hbp_cleanup_device(void) {
    wuwa_cleanup_perf_hbp();
    misc_deregister(&core_misc);
}
