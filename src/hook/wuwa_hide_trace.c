#include "wuwa_hide_trace.h"
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long lookup_name(const char *name) {
    struct kprobe kp = { .symbol_name = name };
    unsigned long retval;
    if (register_kprobe(&kp) < 0) return 0;
    retval = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return retval;
}
#else
static unsigned long lookup_name(const char *name) {
    return kallsyms_lookup_name(name);
}
#endif

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    struct ftrace_ops ops;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct pt_regs *regs) {
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if (!within_module(parent_ip, THIS_MODULE)) {
#ifdef CONFIG_ARM64
        regs->pc = (unsigned long)hook->function;
#else
        regs->ip = (unsigned long)hook->function;
#endif
    }
}

static asmlinkage int (*orig_proc_pid_status)(struct seq_file *m, struct pid_namespace *ns,
                                              struct pid *pid, struct task_struct *task);

static asmlinkage int hooked_proc_pid_status(struct seq_file *m, struct pid_namespace *ns,
                                             struct pid *pid, struct task_struct *task) {
    int ret;
    unsigned int backup_ptrace;
    if (!task) return orig_proc_pid_status(m, ns, pid, task);

    /* 核心操作：读取 status 时，强制把 ptrace 标志设为 0 */
    backup_ptrace = task->ptrace;
    task->ptrace = 0;
    ret = orig_proc_pid_status(m, ns, pid, task);
    task->ptrace = backup_ptrace;
    
    return ret;
}

static struct ftrace_hook trace_hook = {
    .name = "proc_pid_status",
    .function = hooked_proc_pid_status,
    .original = &orig_proc_pid_status,
};

int wuwa_hide_trace_init(void) {
    int err;
    trace_hook.address = lookup_name(trace_hook.name);
    if (!trace_hook.address) return -ENOENT;

    *((unsigned long *)trace_hook.original) = trace_hook.address;
    trace_hook.ops.func = (ftrace_func_t)fh_ftrace_thunk;

#ifdef CONFIG_ARM64
    trace_hook.ops.flags = FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED | FTRACE_OPS_FL_RECURSION_SAFE | FTRACE_OPS_FL_IPMODIFY;
#else
    trace_hook.ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;
#endif

    err = ftrace_set_filter(&trace_hook.ops, (unsigned char *)trace_hook.name, strlen(trace_hook.name), 0);
    if (err) return err;
    
    err = register_ftrace_function(&trace_hook.ops);
    if (!err) pr_info("wuwa: TracerPid auto-hiding activated!\n");
    return err;
}

void wuwa_hide_trace_exit(void) {
    unregister_ftrace_function(&trace_hook.ops);
    ftrace_set_filter(&trace_hook.ops, NULL, 0, 1);
    pr_info("wuwa: TracerPid hider removed.\n");
}
