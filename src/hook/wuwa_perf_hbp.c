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
#include <linux/kprobes.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/fpsimd.h>

#define DEV_NAME "stealth_uxn_engine"
#define MAX_HOOKS 32
#define FOV_TARGET_BITS 0x4089999AU

/* ==========================================================
 * 通用通信协议 & 行为定义
 * ========================================================== */
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

/* ==========================================================
 * 内部状态与 PTE 管理 (绑定 fd)
 * ========================================================== */
struct hook_node {
    uint64_t vaddr;
    uint32_t action;
    uint64_t reg_val;
    pte_t *ptep;
    pte_t orig_pte;
    int active;
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

/* 核心页表漫游机制 */
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

static int apply_pte_uxn(struct client_ctx *ctx, struct hook_request *req, int index) {
    struct mm_struct *mm = ctx->task->mm;
    pte_t *ptep;
    pte_t pte_val;

    if (!mm) return -EINVAL;
    mmap_read_lock(mm);
    ptep = walk_and_get_pte(mm, req->vaddr);
    if (!ptep || !pte_present(*ptep)) {
        mmap_read_unlock(mm);
        return -EFAULT;
    }

    ctx->hooks[index].vaddr = req->vaddr;
    ctx->hooks[index].action = req->action;
    ctx->hooks[index].reg_val = req->reg_val;
    ctx->hooks[index].ptep = ptep;
    ctx->hooks[index].orig_pte = *ptep;

    /* 赋予不可执行权限 UXN */
    pte_val = *ptep;
    pte_val = set_pte_bit(pte_val, __pgprot(PTE_UXN));
    set_pte_at(mm, req->vaddr, ptep, pte_val);
    
    /* 解决 Android15-6.6 内核编译报错：彻底废弃 mm->mmap 链表，使用兼容的刷新宏 */
    flush_tlb_mm(mm);
    
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
            set_pte_at(mm, ctx->hooks[i].vaddr, ctx->hooks[i].ptep, ctx->hooks[i].orig_pte);
            flush_tlb_mm(mm);
            ctx->hooks[i].active = 0;
        }
    }
    mmap_read_unlock(mm);
}

/* ==========================================================
 * Kprobe 异常捕获 (核心拦截逻辑)
 * ========================================================== */
static struct kprobe kp_mem_abort;

static int pre_mem_abort_handler(struct kprobe *p, struct pt_regs *regs) {
    struct pt_regs *fault_regs = (struct pt_regs *)regs->regs[2];
    uint64_t pc;
    int i;

    if (!fault_regs || !g_active_ctx) return 0;
    pc = fault_regs->pc;

    for (i = 0; i < g_active_ctx->hook_count; i++) {
        if (g_active_ctx->hooks[i].active && pc == g_active_ctx->hooks[i].vaddr) {
            uint32_t action = g_active_ctx->hooks[i].action;

            if (action == ACTION_RET) {
                fault_regs->pc = fault_regs->regs[30];
            } 
            else if (action == ACTION_JMP) {
                fault_regs->pc = g_active_ctx->hooks[i].reg_val;
            } 
            else if (action == ACTION_FOV) {
                if (fn_fpsimd_save && fn_fpsimd_load) {
                    struct user_fpsimd_state *fp = &current->thread.uw.fpsimd_state;
                    fn_fpsimd_save(fp);
                    fp->vregs[0] = (fp->vregs[0] & ~((__uint128_t)0xFFFFFFFFULL)) | (__uint128_t)FOV_TARGET_BITS;
                    fn_fpsimd_load(fp);
                }
                fault_regs->pc = fault_regs->regs[30];
            }
            else if (action == ACTION_MAXHP) {
                fault_regs->regs[0] = 1;
                fault_regs->pc = fault_regs->regs[30];
            }
            else if (action == ACTION_DAMAGE) {
                uint32_t flag = 0;
                uint64_t target_addr = fault_regs->regs[1] + 0x1C;
                if (fn_nofault_read && fn_nofault_read(&flag, (void __user *)target_addr, 4) == 0) {
                    if (flag == 1) { 
                        fault_regs->regs[19] = fault_regs->regs[1]; 
                        fault_regs->pc += 4; 
                        instruction_pointer_set(regs, regs->pc + 4);
                        return 1; 
                    }
                }
                fault_regs->sp += 0x30;
                fault_regs->regs[0] = 1;
                fault_regs->pc = fault_regs->regs[30];
            }
            
            instruction_pointer_set(regs, regs->pc + 4); 
            return 1; 
        }
    }
    return 0;
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
 * 暴露给主模块 (wuwa.c) 调用的初始化接口，去除 module_init 避免符号冲突
 * ========================================================== */

int wuwa_hbp_init_device(void) {
    kp_mem_abort.symbol_name = "do_mem_abort";
    kp_mem_abort.pre_handler = pre_mem_abort_handler;
    register_kprobe(&kp_mem_abort);
    return misc_register(&misc_dev);
}

void wuwa_hbp_cleanup_device(void) {
    unregister_kprobe(&kp_mem_abort);
    misc_deregister(&misc_dev);
}

/* 兼容你 wuwa_ioctl.c 里遗留的调用，防止编译找不到符号 */
int wuwa_install_perf_hbp(void *req) { return 0; }
void wuwa_cleanup_perf_hbp(void) { }
