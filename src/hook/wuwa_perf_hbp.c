#include "wuwa_perf_hbp.h"
#include "../ioctl/wuwa_ioctl.h" /* 必须引入此头文件以获取 wuwa_hbp_req 定义 */
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>

#define OFF_FOV      0x9326F78
#define OFF_BORDER   0x8951160
#define OFF_SKIP     0x2639fd8
#define OFF_SKIP_JMP 0x53709a0
#define OFF_DAMAGE   0x844f4b4
#define OFF_MAXHP    0x33b2ffc

#define MAX_BP_EVENTS 128
static struct perf_event *g_bp_events[MAX_BP_EVENTS];
static int g_bp_count = 0;

static uint64_t g_base = 0;
static int g_fov_on = 0, g_border_on = 0, g_skip_on = 0, g_damage_on = 0, g_maxhp_on = 0;

/* 当 CPU 硬件触发断点时，内核直接调用的溢出回调函数 */
static void wuwa_hbp_handler(struct perf_event *bp,
                             struct perf_sample_data *data,
                             struct pt_regs *regs) {
    uint64_t pc = regs->pc;

    // pr_info("wuwa: Breakpoint Hit at PC: %llx\n", pc); // 取消注释可用于调试触发状态

    if (g_skip_on && pc == g_base + OFF_SKIP) {
        regs->pc = g_base + OFF_SKIP_JMP;
        return;
    }

    if (g_damage_on && pc == g_base + OFF_DAMAGE) {
        uint64_t target_addr = regs->regs[1] + 0x1c;
        uint32_t flag = 0;
        
        // 内核态无缺页安全读取，防止引发 Kernel Panic
        if (copy_from_user(&flag, (void __user *)target_addr, 4) == 0) {
            if (flag == 1) return; 
        }
        regs->regs[0] = 1;
        regs->pc = regs->regs[30]; // 返回
        return;
    }

    if (g_maxhp_on && pc == g_base + OFF_MAXHP) {
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    if (g_border_on && pc == g_base + OFF_BORDER) {
        regs->pc = regs->regs[30];
        return;
    }

    if (g_fov_on && pc == g_base + OFF_FOV) {
        // 内核态避免随意修改浮点寄存器，仅作跳过处理防止黑屏
        regs->pc = regs->regs[30];
        return;
    }
}

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct perf_event_attr attr;
    struct perf_event *bp;
    uint64_t addrs[5];
    int addr_cnt = 0;
    int i;

    g_base = req->base_addr;
    g_fov_on = req->fov_on;
    g_border_on = req->border_on;
    g_skip_on = req->skip_on;
    g_damage_on = req->damage_on;
    g_maxhp_on = req->maxhp_on;

    if (g_fov_on) addrs[addr_cnt++] = g_base + OFF_FOV;
    if (g_border_on) addrs[addr_cnt++] = g_base + OFF_BORDER;
    if (g_skip_on) addrs[addr_cnt++] = g_base + OFF_SKIP;
    if (g_damage_on) addrs[addr_cnt++] = g_base + OFF_DAMAGE;
    if (g_maxhp_on) addrs[addr_cnt++] = g_base + OFF_MAXHP;

    if (addr_cnt == 0 || g_bp_count + addr_cnt > MAX_BP_EVENTS) {
        return -ENOSPC;
    }

    // 遍历申请硬件槽位
    for (i = 0; i < addr_cnt; i++) {
        memset(&attr, 0, sizeof(attr));
        attr.type = PERF_TYPE_BREAKPOINT;
        attr.size = sizeof(attr);
        attr.bp_addr = addrs[i];           // 地址必须对齐
        attr.bp_len = HW_BREAKPOINT_LEN_4; // 长度4字节
        attr.bp_type = HW_BREAKPOINT_X;    // 执行类型断点
        attr.disabled = 0;                 // 立刻激活

        // 使用 perf_event 直接绕过部分 ptrace 和内核限制
        bp = perf_event_create_kernel_counter(&attr, req->tid, -1, wuwa_hbp_handler, NULL);
        
        if (IS_ERR(bp)) {
            pr_err("wuwa: Failed to install HBP on TID %d at %llx (err: %ld)\n", req->tid, addrs[i], PTR_ERR(bp));
            continue;
        }

        g_bp_events[g_bp_count++] = bp;
    }

    if (addr_cnt > 0) {
        pr_info("wuwa: Perf HW Breakpoints installed for TID %d\n", req->tid);
    }
    return 0;
}

void wuwa_cleanup_perf_hbp(void) {
    int i;
    for (i = 0; i < g_bp_count; i++) {
        if (g_bp_events[i]) {
            perf_event_release_kernel(g_bp_events[i]);
            g_bp_events[i] = NULL;
        }
    }
    g_bp_count = 0;
    pr_info("wuwa: Perf HW Breakpoints cleaned up\n");
}
