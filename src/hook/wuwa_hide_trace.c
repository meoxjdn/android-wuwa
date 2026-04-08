#include "wuwa_hide_trace.h"
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/version.h>

struct proc_status_data {
    struct task_struct *task;
    unsigned int orig_ptrace;
};

/* 入口 Hook：抹除 TracerPid */
static int entry_proc_pid_status(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct proc_status_data *data = (struct proc_status_data *)ri->data;
    struct task_struct *task = NULL;

#ifdef CONFIG_ARM64
    task = (struct task_struct *)regs->regs[3];
#endif

    if (task) {
        data->task = task;
        data->orig_ptrace = task->ptrace;
        task->ptrace = 0; // 强行置 0
    } else {
        data->task = NULL;
    }
    return 0;
}

/* 返回 Hook：恢复真实状态 */
static int ret_proc_pid_status(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct proc_status_data *data = (struct proc_status_data *)ri->data;
    if (data->task) {
        data->task->ptrace = data->orig_ptrace;
    }
    return 0;
}

static struct kretprobe trace_kretprobe = {
    .handler = ret_proc_pid_status,
    .entry_handler = entry_proc_pid_status,
    .data_size = sizeof(struct proc_status_data),
    .maxactive = 64, 
};

int wuwa_hide_trace_init(void) {
    int err;
    trace_kretprobe.kp.symbol_name = "proc_pid_status";
    
    err = register_kretprobe(&trace_kretprobe);
    if (err < 0) {
        pr_err("wuwa: Failed to register kretprobe for hiding TracerPid: %d\n", err);
        return err;
    }

    pr_info("wuwa: TracerPid auto-hiding activated!\n");
    return 0;
}

void wuwa_hide_trace_exit(void) {
    unregister_kretprobe(&trace_kretprobe);
    pr_info("wuwa: TracerPid hider removed.\n");
}
