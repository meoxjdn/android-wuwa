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
typedef void *(*module_alloc_fn_t)(unsigned long);
typedef void (*module_memfree_fn_t)(void *);

static read_nofault_fn_t  fn_nofault_read  = NULL;
static fpsimd_save_fn_t   fn_fpsimd_save   = NULL;
static fpsimd_load_fn_t   fn_fpsimd_load   = NULL;
static module_alloc_fn_t  fn_module_alloc  = NULL;
static module_memfree_fn_t fn_module_memfree = NULL;

extern unsigned long kallsyms_lookup_name_ex(const char *name);

static void resolve_symbols(void) {
    if (fn_nofault_read) return;
    fn_nofault_read = (read_nofault_fn_t)kallsyms_lookup_name_ex("copy_from_user_nofault");
    if (!fn_nofault_read) fn_nofault_read = (read_nofault_fn_t)kallsyms_lookup_name_ex("probe_kernel_read");
    fn_fpsimd_save = (fpsimd_save_fn_t)kallsyms_lookup_name_ex("fpsimd_save_state");
    if (!fn_fpsimd_save) fn_fpsimd_save = (fpsimd_save_fn_t)kallsyms_lookup_name_ex("fpsimd_save_and_flush_cpu_state");
    fn_fpsimd_load = (fpsimd_load_fn_t)kallsyms_lookup_name_ex("fpsimd_load_state");
    if (!fn_fpsimd_load) fn_fpsimd_load = (fpsimd_load_fn_t)kallsyms_lookup_name_ex("fpsimd_flush_cpu_state");
    
    /* 动态挖出被 GKI 隐藏的内存分配 API */
    fn_module_alloc = (module_alloc_fn_t)kallsyms_lookup_name_ex("module_alloc");
    fn_module_memfree = (module_memfree_fn_t)kallsyms_lookup_name_ex("module_memfree");
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
 * 微型 ARM64 Inline Hook 蹦床引擎 (纯动态寻址)
 * ========================================================== */
extern int init_arch(void);
extern int hook_write_range(void *target, void *source, int size);
extern void (*flush_icache_range_ptr)(unsigned long, unsigned long);

static void build_absolute_jump(u8 *buf, uint64_t target_addr) {
    uint32_t *insn = (uint32_t *)buf;
    uint64_t *addr = (uint64_t *)(buf + 8);
    insn[0] = 0x58000050; 
    insn[1] = 0xd61f0200; 
    *addr = target_addr;
}

static int stealth_inline_hook(void *target, void *new_func, void **old_func) {
    u8 *trampoline;
    u8 jump_insn[16];
    int ret;
    
    if (init_arch() != 0) return -ENOSYS;
    if (!fn_module_alloc || !fn_module_memfree) return -ENOSYS;
    
    /* 使用挖出来的真实地址动态分配内存 */
    trampoline = fn_module_alloc(128);
    if (!trampoline) return -ENOMEM;
    
    memcpy(trampoline, target, 16);
    build_absolute_jump(trampoline + 16, (uint64_t)target + 16);
    
    if (flush_icache_range_ptr) {
        flush_icache_range_ptr((unsigned long)trampoline, (unsigned long)trampoline + 32);
    }
    
    *old_func = trampoline;
    
    build_absolute_jump(jump_insn, (uint64_t)new_func);
    ret = hook_write_range(target, jump_insn, 16);
    
    if (ret < 0) {
        fn_module_memfree(trampoline);
        *old_func = NULL;
    }
    return ret;
}

/* ==========================================================
 * 原生函数指针劫持区 (接管异常向量)
 * ========================================================== */
typedef int (*fault_handler_t)(unsigned long far, unsigned int esr, struct pt_regs *regs);
static fault_handler_t orig_do_page_fault = NULL;
static fault_handler_t orig_single_step_handler = NULL;

int stealth_do_page_fault(unsigned long far, unsigned int esr, struct pt_regs *regs) {
    uint64_t pc;
    int i;

    if (!regs || !g_active_ctx || (esr >> 26) != 0x20) {
        return orig_do_page_fault(far, esr, regs);
    }
    
    pc = regs->pc;

    for (i = 0; i < g_active_ctx->hook_count; i++) {
        if (g_active_ctx->hooks[i].active && (pc & ~0xFFFULL) == (g_active_ctx->hooks[i].vaddr & ~0xFFFULL)) {
            
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
            
            stealth_set_pte_hard(g_active_ctx->hooks[i].ptep, g_active_ctx->hooks[i].orig_pte);
            stealth_flush_tlb_page_hard(pc);
            
            regs->pstate |= (1ULL << 21);
            g_active_ctx->hooks[i].is_stepping = 1;
            
            return 0; 
        }
    }
    return orig_do_page_fault(far, esr, regs);
}

int stealth_single_step_handler(unsigned long addr, unsigned int esr, struct pt_regs *regs) {
    int i;
    if (!regs || !g_active_ctx || (esr >> 26) != 0x32) {
        return orig_single_step_handler(addr, esr, regs);
    }

    for (i = 0; i < g_active_ctx->hook_count; i++) {
        if (g_active_ctx->hooks[i].active && g_active_ctx->hooks[i].is_stepping) {
            pte_t uxn_pte = set_pte_bit(g_active_ctx->hooks[i].orig_pte, __pgprot(PTE_UXN));
            stealth_set_pte_hard(g_active_ctx->hooks[i].ptep, uxn_pte);
            stealth_flush_tlb_page_hard(g_active_ctx->hooks[i].vaddr);

            regs->pstate &= ~(1ULL << 21);
            g_active_ctx->hooks[i].is_stepping = 0;
            return 0;
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
    resolve_symbols(); /* 确保在此处初始化所有函数指针 */

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

int wuwa_hbp_init_device(void) {
    unsigned long pf_addr, ss_addr;

    /* 先执行符号解析，准备好蹦床需要的 module_alloc */
    resolve_symbols();

    pf_addr = kallsyms_lookup_name_ex("do_page_fault");
    ss_addr = kallsyms_lookup_name_ex("single_step_handler");

    if (!pf_addr || !ss_addr) return -ENOSYS;

    if (stealth_inline_hook((void *)pf_addr, (void *)stealth_do_page_fault, (void **)&orig_do_page_fault) < 0) {
        return -EINVAL;
    }
    
    if (stealth_inline_hook((void *)ss_addr, (void *)stealth_single_step_handler, (void **)&orig_single_step_handler) < 0) {
        return -EINVAL;
    }

    pr_info("[stealth_engine] Dynamic Inline Hook Engine Armed!\n");
    return misc_register(&misc_dev);
}

void wuwa_hbp_cleanup_device(void) {
    misc_deregister(&misc_dev);
}

/* 兼容遗留调用 */
int wuwa_install_perf_hbp(void *req) { return 0; }
void wuwa_cleanup_perf_hbp(void) { }
