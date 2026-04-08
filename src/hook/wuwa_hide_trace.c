#include "wuwa_hide_trace.h"
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/version.h>
/* 直接声明外部函数，无视头文件路径迷宫 */
extern unsigned long wuwa_kallsyms_lookup_name(const char *name);

/* [新增] 定义函数指针，绕过内核符号导出限制 */
typedef long (*copy_from_user_nofault_t)(void *dst, const void __user *src, size_t size);
static copy_from_user_nofault_t my_copy_from_user_nofault = NULL;

struct proc_status_data {
    struct task_struct *task;
    unsigned int orig_ptrace;
};

/* 入口 Hook：在 proc_pid_status 执行前把 ptrace 抹掉 */
static int entry_proc_pid_status(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct proc_status_data *data = (struct proc_status_data *)ri->data;
    struct task_struct *task = NULL;

#ifdef CONFIG_ARM64
    /* * 在 Kernel 6.6 / ARM64 中：
     * task_struct 通常是 proc_pid_status 的第4个参数 (x3 寄存器)
     * 注意：不同内核版本参数位置可能微调，如果失效需检查寄存器序号
     */
    task = (struct task_struct *)regs->regs[3];
#endif

    if (task) {
        data->task = task;
        data->orig_ptrace = task->ptrace;
        task->ptrace = 0; // 强行置 0，让游戏看到的 TracerPid 永远为 0
    } else {
        data->task = NULL;
    }
    return 0;
}

/* 返回 Hook：在执行完后恢复 ptrace，避免影响系统正常功能 */
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

/* 驱动初始化调用此函数 */
int wuwa_hide_trace_init(void) {
    int err;

    /* 1. 动态查找被隐藏的 copy_from_user_nofault */
    my_copy_from_user_nofault = (copy_from_user_nofault_t)wuwa_kallsyms_lookup_name("copy_from_user_nofault");
    
    if (!my_copy_from_user_nofault) {
        pr_warn("wuwa: copy_from_user_nofault not found, trying kernel variant...\n");
        my_copy_from_user_nofault = (copy_from_user_nofault_t)wuwa_kallsyms_lookup_name("copy_from_kernel_nofault");
    }

    if (my_copy_from_user_nofault) {
        pr_info("wuwa: Successfully linked memory copy symbols.\n");
    }

    /* 2. 注册 Kretprobe 隐藏 TracerPid */
    trace_kretprobe.kp.symbol_name = "proc_pid_status";
    err = register_kretprobe(&trace_kretprobe);
    if (err < 0) {
        pr_err("wuwa: Failed to register kretprobe: %d\n", err);
        return err;
    }

    pr_info("wuwa: TracerPid auto-hiding activated! (GKI 6.6 mode)\n");
    return 0;
}

void wuwa_hide_trace_exit(void) {
    unregister_kretprobe(&trace_kretprobe);
    pr_info("wuwa: TracerPid hider removed.\n");
}
