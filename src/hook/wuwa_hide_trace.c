#include "wuwa_hide_trace.h"
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/version.h>
#include "../core/wuwa_kallsyms.h" // [新增] 使用驱动自带的查找工具

// [新增] 定义函数指针
typedef long (*copy_from_user_nofault_t)(void *dst, const void __user *src, size_t size);
static copy_from_user_nofault_t my_copy_from_user_nofault = NULL;

struct proc_status_data {
    struct task_struct *task;
    unsigned int orig_ptrace;
};

static int entry_proc_pid_status(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct proc_status_data *data = (struct proc_status_data *)ri->data;
    struct task_struct *task = NULL;

#ifdef CONFIG_ARM64
    // ARM64 中，task_struct 是 proc_pid_status 的第4个参数，存放在 x3 寄存器
    task = (struct task_struct *)regs->regs[3];
#endif

    if (task) {
        data->task = task;
        data->orig_ptrace = task->ptrace;
        task->ptrace = 0; // 强行置 0，抹除 TracerPid
    } else {
        data->task = NULL;
    }
    return 0;
}

static int ret_proc_pid_status(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct proc_status_data *data = (struct proc_status_data *)ri->data;

    // 恢复原来的值，保证内核状态正常
    if (data->task) {
        data->task->ptrace = data->orig_ptrace;
    }
    return 0;
}

static struct kretprobe trace_kretprobe = {
    .handler = ret_proc_pid_status,
    .entry_handler = entry_proc_pid_status,
    .data_size = sizeof(struct proc_status_data),
    .maxactive = 30, // 支持并发读取的数量
};

int wuwa_hide_trace_init(void) {
    int err;
    trace_kretprobe.kp.symbol_name = "proc_pid_status";

    err = register_kretprobe(&trace_kretprobe);
    if (err < 0) {
        pr_err("wuwa: Failed to register kretprobe for hiding TracerPid: %d\n", err);
        return err;
    }

    pr_info("wuwa: TracerPid auto-hiding activated via Kretprobes!\n");
    return 0;
}

void wuwa_hide_trace_exit(void) {
    unregister_kretprobe(&trace_kretprobe);
    pr_info("wuwa: TracerPid hider removed.\n");
}
