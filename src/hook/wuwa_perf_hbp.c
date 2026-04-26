#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
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

#define MAX_HOOKS 32
#define DEV_NAME "stealth_uxn_engine"

/* ==========================================================
 * 通用通信协议 (用户态与内核态共享)
 * ========================================================== */
enum hook_action {
    ACTION_SKIP_INSTRUCTION = 0,
    ACTION_MODIFY_REG_X0    = 1,
    ACTION_MAX_HP_SIM       = 2
};

struct hook_request {
    uint64_t vaddr;          /* 要 Hook 的虚拟地址 */
    uint32_t action;         /* 触发时的行为 */
    uint64_t reg_val;        /* 附加参数 (如寄存器要修改的值) */
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
 * 内部状态管理 (绑定到 fd 级别防泄漏)
 * ========================================================== */
struct hook_node {
    uint64_t vaddr;
    uint32_t action;
    uint64_t reg_val;
    pte_t *ptep;             /* 页表项指针 */
    pte_t orig_pte;          /* 原始页表项值 */
    int active;
};

struct client_ctx {
    pid_t target_pid;
    struct task_struct *task;
    struct hook_node hooks[MAX_HOOKS];
    uint32_t hook_count;
    struct mutex lock;
};

/* ==========================================================
 * 核心引擎：PTE 漫游与 UXN 修改
 * ========================================================== */
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

    /* 设置 UXN (Unprivileged Execute Never) 位 */
    pte_val = *ptep;
    pte_val = set_pte_bit(pte_val, __pgprot(PTE_UXN));
    set_pte_at(mm, req->vaddr, ptep, pte_val);
    
    /* 刷新 TLB 确保生效 */
    flush_tlb_page(ctx->task->active_mm->mmap, req->vaddr);
    
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
            flush_tlb_page(mm->mmap, ctx->hooks[i].vaddr);
            ctx->hooks[i].active = 0;
        }
    }
    mmap_read_unlock(mm);
}

/* ==========================================================
 * 异常捕获 (Instruction Abort & Timer Spoofing)
 * ========================================================== */
/* * 注意：在真实产品中，需要用 kprobe hook do_el0_instruction_abort 或 do_mem_abort
 * 这里展示一个 kprobe 骨架用于捕获异常并分配逻辑。
 */
static struct kprobe kp_mem_abort;

static int pre_mem_abort_handler(struct kprobe *p, struct pt_regs *regs) {
    /* * 在这里检查触发异常的地址 (regs->pc) 是否在我们的 ctx->hooks 列表中。
     * 如果匹配：
     * 1. 模拟该指令或根据 action 跳过 (regs->pc += 4)
     * 2. 如果是修改寄存器，直接修改 regs->regs[0] 等。
     * 3. 返回非零值以阻止原始内核缺页异常继续处理。
     */
     // TODO: 遍历所有 active fd 的 ctx，匹配 regs->pc
    return 0;
}

/* * 时钟伪造拦截：反作弊会读取 CNTVCT_EL0
 * 我们需要在系统层面清空 CNTKCTL_EL1.EL0VCTEN，迫使 MRS 陷阱到内核，
 * 然后在此处扣除我们执行 Hook 所耗费的 Time Delta。
 */
static struct kprobe kp_undef_instr;
static int pre_undef_handler(struct kprobe *p, struct pt_regs *regs) {
    /* 检查是否是 MRS Xn, CNTVCT_EL0 指令 (opcode = 0xd53b0df0) */
    uint32_t opcode;
    if (copy_from_user(&opcode, (void __user *)regs->pc, 4) == 0) {
        if ((opcode & 0xFFFFFFE0) == 0xD53B0DE0) { // 掩码匹配 MRS 时钟寄存器
            int target_reg = opcode & 0x1F;
            /* 读取真实时间，减去固定的异常损耗 (例如 2500 cycle)，写回寄存器 */
            uint64_t fake_time;
            asm volatile("mrs %0, cntvct_el0" : "=r" (fake_time));
            fake_time -= 2500; 
            regs->regs[target_reg] = fake_time;
            regs->pc += 4; /* 跳过该指令 */
            return 1; /* 拦截成功，不再传递给原 undef handler */
        }
    }
    return 0;
}

/* ==========================================================
 * 文件操作接口 (防泄漏机制核心)
 * ========================================================== */
static int dev_open(struct inode *inode, struct file *file) {
    struct client_ctx *ctx = kzalloc(sizeof(struct client_ctx), GFP_KERNEL);
    if (!ctx) return -ENOMEM;
    
    mutex_init(&ctx->lock);
    file->private_data = ctx; /* 绑定生命周期 */
    return 0;
}

static int dev_release(struct inode *inode, struct file *file) {
    struct client_ctx *ctx = file->private_data;
    if (ctx) {
        mutex_lock(&ctx->lock);
        restore_all_ptes(ctx); /* 自动清理恢复所有修改过的页表 */
        if (ctx->task) {
            put_task_struct(ctx->task);
        }
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

    switch (cmd) {
        case CMD_INIT_HOOKS:
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            
            mutex_lock(&ctx->lock);
            if (ctx->task) put_task_struct(ctx->task); /* 清理旧任务 */
            
            pid_struct = find_get_pid(req.pid);
            if (!pid_struct) { mutex_unlock(&ctx->lock); return -ESRCH; }
            
            ctx->task = get_pid_task(pid_struct, PIDTYPE_PID);
            put_pid(pid_struct);
            if (!ctx->task) { mutex_unlock(&ctx->lock); return -ESRCH; }
            
            ctx->target_pid = req.pid;
            ctx->hook_count = req.hook_count > MAX_HOOKS ? MAX_HOOKS : req.hook_count;
            
            for (i = 0; i < ctx->hook_count; i++) {
                apply_pte_uxn(ctx, &req.hooks[i], i);
            }
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

static int __init uxn_engine_init(void) {
    int ret;
    /* 注册 Kprobes */
    kp_undef_instr.symbol_name = "do_undefinstr";
    kp_undef_instr.pre_handler = pre_undef_handler;
    register_kprobe(&kp_undef_instr);
    
    ret = misc_register(&misc_dev);
    return ret;
}

static void __exit uxn_engine_exit(void) {
    unregister_kprobe(&kp_undef_instr);
    misc_deregister(&misc_dev);
}

module_init(uxn_engine_init);
module_exit(uxn_engine_exit);
MODULE_LICENSE("GPL");
