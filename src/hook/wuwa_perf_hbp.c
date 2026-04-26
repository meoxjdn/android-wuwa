#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <asm/pgtable.h>
#include <asm/barrier.h>
#include <asm/fpsimd.h>

#define DEV_NAME "stealth_uxn_engine"
#define MAX_HOOKS 32
#define FOV_TARGET_BITS 0x4089999AU

enum hook_action {
    ACTION_RET       = 0,
    ACTION_FOV       = 1,
    ACTION_JMP       = 2,
    ACTION_DAMAGE    = 3,
    ACTION_MAXHP     = 4
};

struct hook_request {
    uint64_t vaddr;
    uint32_t action;
    uint64_t reg_val;
};

struct ioctl_init_req {
    pid_t pid;
    uint32_t hook_count;
    struct hook_request hooks[MAX_HOOKS];
};

#define IOCTL_MAGIC 'U'
#define CMD_INIT_HOOKS _IOW(IOCTL_MAGIC, 1, struct ioctl_init_req)
#define CMD_CLEANUP    _IO(IOCTL_MAGIC, 2)

struct hook_node {
    uint64_t vaddr;
    uint32_t action;
    uint64_t reg_val;
    pte_t *ptep;
    pte_t orig_pte;
    int active;
    int is_stepping; 
};

struct client_ctx {
    pid_t target_pid;
    struct task_struct *task;
    struct hook_node hooks[MAX_HOOKS];
    uint32_t hook_count;
    struct mutex lock;
};

static struct client_ctx *g_active_ctx = NULL;

typedef long (*read_nofault_fn_t)(void *, const void __user *, size_t);
typedef void (*fpsimd_save_fn_t)(struct user_fpsimd_state *);
typedef void (*fpsimd_load_fn_t)(const struct user_fpsimd_state *);

static read_nofault_fn_t  fn_nofault_read  = NULL;
static fpsimd_save_fn_t   fn_fpsimd_save   = NULL;
static fpsimd_load_fn_t   fn_fpsimd_load   = NULL;
extern unsigned long kallsyms_lookup_name_ex(const char *name);

static void resolve_symbols(void) {
    if (fn_nofault_read) return;
    fn_nofault_read = (read_nofault_fn_t)kallsyms_lookup_name_ex("copy_from_user_nofault");
    if (!fn_nofault_read) fn_nofault_read = (read_nofault_fn_t)kallsyms_lookup_name_ex("probe_kernel_read");
    fn_fpsimd_save = (fpsimd_save_fn_t)kallsyms_lookup_name_ex("fpsimd_save_state");
    if (!fn_fpsimd_save) fn_fpsimd_save = (fpsimd_save_fn_t)kallsyms_lookup_name_ex("fpsimd_save_and_flush_cpu_state");
    fn_fpsimd_load = (fpsimd_load_fn_t)kallsyms_lookup_name_ex("fpsimd_load_state");
    if (!fn_fpsimd_load) fn_fpsimd_load = (fpsimd_load_fn_t)kallsyms_lookup_name_ex("fpsimd_flush_cpu_state");
}

static pte_t *walk_and_get_pte(struct mm_struct *mm, unsigned long addr) {
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *pte;
    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) return NULL;
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return NULL;
    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud)) return NULL;
    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) return NULL;
    pte = pte_offset_kernel(pmd, addr);
    return pte;
}

static inline void stealth_set_pte_hard(pte_t *ptep, pte_t pte_val) {
    WRITE_ONCE(*ptep, pte_val);
    dsb(ishst);
    isb();
}

static inline void stealth_flush_tlb_page_hard(unsigned long vaddr) {
    unsigned long page_addr = vaddr >> 12;
    dsb(ishst);
    asm volatile("tlbi vaae1is, %0" : : "r" (page_addr));
    dsb(ish);
    isb();
}

static int apply_pte_uxn(struct client_ctx *ctx, struct hook_request *req, int index) {
    struct mm_struct *mm = ctx->task->mm;
    pte_t *ptep;
    pte_t pte_val;

    if (!mm) return -EINVAL;
    mmap_read_lock(mm);
    ptep = walk_and_get_pte(mm, req->vaddr);
    if (!ptep || !pte_present(*ptep)) { mmap_read_unlock(mm); return -EFAULT; }

    ctx->hooks[index].vaddr = req->vaddr;
    ctx->hooks[index].action = req->action;
    ctx->hooks[index].reg_val = req->reg_val;
    ctx->hooks[index].ptep = ptep;
    ctx->hooks[index].orig_pte = *ptep;
    ctx->hooks[index].is_stepping = 0;

    pte_val = *ptep;
    pte_val = set_pte_bit(pte_val, __pgprot(PTE_UXN));
    stealth_set_pte_hard(ptep, pte_val);
    stealth_flush_tlb_page_hard(req->vaddr);
    
    ctx->hooks[index].active = 1;
    mmap_read_unlock(mm);
    return 0;
}

static void restore_all_ptes(struct client_ctx *ctx) {
    struct mm_struct *mm;
    int i;
    if (!ctx || !ctx->task || !ctx->task->mm) return;
    mm = ctx->task->mm;

    mmap_read_lock(mm);
    for (i = 0; i < ctx->hook_count; i++) {
        if (ctx->hooks[i].active && ctx->hooks[i].ptep) {
            stealth_set_pte_hard(ctx->hooks[i].ptep, ctx->hooks[i].orig_pte);
            stealth_flush_tlb_page_hard(ctx->hooks[i].vaddr);
            ctx->hooks[i].active = 0;
        }
    }
    mmap_read_unlock(mm);
}

/* ==========================================================
 * 纯汇编劫持层 (Inline Hook Handlers)
 * 彻底抛弃 Kprobe，使用裸函数指针接管异常向量！
 * ========================================================== */

/* 定义原函数的函数指针类型 */
typedef int (*fault_handler_t)(unsigned long far, unsigned int esr, struct pt_regs *regs);
static fault_handler_t orig_do_page_fault = NULL;
static fault_handler_t orig_single_step_handler = NULL;

/* 劫持 do_page_fault 的处理函数 */
int stealth_do_page_fault(unsigned long far, unsigned int esr, struct pt_regs *regs) {
    uint64_t pc;
    int i;

    /* 检查是否是 EL0 的指令异常 (0x20) */
    if (!regs || !g_active_ctx || (esr >> 26) != 0x20) {
        return orig_do_page_fault(far, esr, regs); /* 不是我们的目标，放行给原内核处理 */
    }
    
    pc = regs->pc;

    for (i = 0; i < g_active_ctx->hook_count; i++) {
        /* 匹配 4KB UXN 页异常 */
        if (g_active_ctx->hooks[i].active && (pc & ~0xFFFULL) == (g_active_ctx->hooks[i].vaddr & ~0xFFFULL)) {
            
            /* 命中 Hook 行 */
            if (pc == g_active_ctx->hooks[i].vaddr) {
                uint32_t action = g_active_ctx->hooks[i].action;
                if (action == ACTION_RET) { regs->pc = regs->regs[30]; } 
                else if (action == ACTION_JMP) { regs->pc = g_active_ctx->hooks[i].reg_val; } 
                else if (action == ACTION_FOV) {
                    if (fn_fpsimd_save && fn_fpsimd_load) {
                        struct user_fpsimd_state *fp = &current->thread.uw.fpsimd_state;
                        fn_fpsimd_save(fp);
                        fp->vregs[0] = (fp->vregs[0] & ~((__uint128_t)0xFFFFFFFFULL)) | (__uint128_t)FOV_TARGET_BITS;
                        fn_fpsimd_load(fp);
                    }
                    regs->pc = regs->regs[30];
                }
                else if (action == ACTION_MAXHP) { regs->regs[0] = 1; regs->pc = regs->regs[30]; }
                else if (action == ACTION_DAMAGE) {
                    uint32_t flag = 0;
                    uint64_t target_addr = regs->regs[1] + 0x1C;
                    if (fn_nofault_read && fn_nofault_read(&flag, (void __user *)target_addr, 4) == 0 && flag == 1) {
                        regs->regs[19] = regs->regs[1]; 
                        regs->pc += 4; 
                    } else {
                        regs->sp += 0x30; regs->regs[0] = 1; regs->pc = regs->regs[30];
                    }
                }
            }
            
            /* 解除 UXN 并走一步 */
            stealth_set_pte_hard(g_active_ctx->hooks[i].ptep, g_active_ctx->hooks[i].orig_pte);
            stealth_flush_tlb_page_hard(pc);
            
            /* 开启硬件单步 (PSTATE.SS = bit 21) */
            regs->pstate |= (1ULL << 21);
            g_active_ctx->hooks[i].is_stepping = 1;
            
            return 0; /* 成功处理，强行截断原生 do_page_fault 的执行！ */
        }
    }
    
    return orig_do_page_fault(far, esr, regs);
}

/* 劫持 single_step_handler 的处理函数 */
int stealth_single_step_handler(unsigned long addr, unsigned int esr, struct pt_regs *regs) {
    int i;

    /* 检查是否是单步异常 (0x32) */
    if (!regs || !g_active_ctx || (esr >> 26) != 0x32) {
        return orig_single_step_handler(addr, esr, regs);
    }

    for (i = 0; i < g_active_ctx->hook_count; i++) {
        if (g_active_ctx->hooks[i].active && g_active_ctx->hooks[i].is_stepping) {
            
            pte_t uxn_pte = set_pte_bit(g_active_ctx->hooks[i].orig_pte, __pgprot(PTE_UXN));
            stealth_set_pte_hard(g_active_ctx->hooks[i].ptep, uxn_pte);
            stealth_flush_tlb_page_hard(g_active_ctx->hooks[i].vaddr);

            /* 关闭硬件单步 */
            regs->pstate &= ~(1ULL << 21);
            g_active_ctx->hooks[i].is_stepping = 0;

            return 0; /* 成功处理，拦截到底！ */
        }
    }
    return orig_single_step_handler(addr, esr, regs);
}

/* ==========================================================
 * 控制端 IOCTL 接口
 * ========================================================== */
static int dev_open(struct inode *inode, struct file *file) {
    struct client_ctx *ctx = kzalloc(sizeof(struct client_ctx), GFP_KERNEL);
    if (!ctx) return -ENOMEM;
    mutex_init(&ctx->lock);
    file->private_data = ctx;
    return 0;
}

static int dev_release(struct inode *inode, struct file *file) {
    struct client_ctx *ctx = file->private_data;
    if (ctx) {
        mutex_lock(&ctx->lock);
        restore_all_ptes(ctx);
        if (ctx->task) put_task_struct(ctx->task);
        if (g_active_ctx == ctx) g_active_ctx = NULL;
        mutex_unlock(&ctx->lock);
        kfree(ctx);
    }
    return 0;
}

static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct client_ctx *ctx = file->private_data;
    struct ioctl_init_req req;
    struct pid *pid_struct;
    int i, ret = 0;

    if (!ctx) return -EINVAL;
    resolve_symbols();

    switch (cmd) {
        case CMD_INIT_HOOKS:
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            mutex_lock(&ctx->lock);
            if (ctx->task) put_task_struct(ctx->task);
            
            pid_struct = find_get_pid(req.pid);
            if (!pid_struct) { mutex_unlock(&ctx->lock); return -ESRCH; }
            
            ctx->task = get_pid_task(pid_struct, PIDTYPE_PID);
            put_pid(pid_struct);
            if (!ctx->task) { mutex_unlock(&ctx->lock); return -ESRCH; }
            
            ctx->target_pid = req.pid;
            ctx->hook_count = req.hook_count > MAX_HOOKS ? MAX_HOOKS : req.hook_count;
            g_active_ctx = ctx;

            for (i = 0; i < ctx->hook_count; i++) apply_pte_uxn(ctx, &req.hooks[i], i);
            mutex_unlock(&ctx->lock);
            break;

        case CMD_CLEANUP:
            mutex_lock(&ctx->lock);
            restore_all_ptes(ctx);
            ctx->hook_count = 0;
            mutex_unlock(&ctx->lock);
            break;

        default:
            ret = -ENOTTY;
    }
    return ret;
}

static const struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = dev_open,
    .release        = dev_release,
    .unlocked_ioctl = dev_ioctl,
};

static struct miscdevice misc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEV_NAME,
    .fops  = &fops,
};

/* ==========================================================
 * 启动注册核心
 * 请利用你的 hijack_arm64 引擎绑定下面两个函数！
 * ========================================================== */

/* 声明你框架中 hijack_arm64.o 提供的方法 (按你项目实际定义的宏修改) */
extern int hijack_start(void *target, void *new_func, void **old_func);

int wuwa_hbp_init_device(void) {
    unsigned long pf_addr, ss_addr;

    pf_addr = kallsyms_lookup_name_ex("do_page_fault");
    ss_addr = kallsyms_lookup_name_ex("single_step_handler");

    if (!pf_addr || !ss_addr) {
        pr_err("[stealth_engine] Cannot find core fault handlers.\n");
        return -ENOSYS;
    }

    /* * 【核心改动：Inline Hook 注册】
     * 抛弃 Kprobe，调用你编译进来的 hijack_arm64 内联引擎。
     * 如果你框架里的函数名叫 inline_hook 或者别的，请在这里自行替换！
     */
    if (hijack_start((void *)pf_addr, (void *)stealth_do_page_fault, (void **)&orig_do_page_fault) < 0) {
        pr_err("[stealth_engine] Inline hook failed on do_page_fault\n");
        return -EINVAL;
    }
    
    if (hijack_start((void *)ss_addr, (void *)stealth_single_step_handler, (void **)&orig_single_step_handler) < 0) {
        pr_err("[stealth_engine] Inline hook failed on single_step_handler\n");
        return -EINVAL;
    }

    pr_info("[stealth_engine] Ultimate PTE UXN Engine Armed via Inline Hook!\n");
    return misc_register(&misc_dev);
}

void wuwa_hbp_cleanup_device(void) {
    /* * 如果你的框架有 unhook 函数 (如 hijack_stop)，请在这里解除挂钩
     * 例如: hijack_stop((void *)orig_do_page_fault);
     */
    misc_deregister(&misc_dev);
}

int wuwa_install_perf_hbp(void *req) { return 0; }
void wuwa_cleanup_perf_hbp(void) { }
