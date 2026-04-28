#include "wuwa_ioctl.h"

#include <asm-generic/errno-base.h>

#include "wuwa_page_walk.h"
#include "wuwa_sock.h"
#include "wuwa_utils.h"
#include "wuwa_proc_dmabuf.h"

#include <asm/pgtable-prot.h>
#include <asm/pgtable-types.h>
#include <asm/pgtable.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "wuwa_proc.h"
#include "wuwa_safe_signal.h"
#include "../hook/wuwa_perf_hbp.h" /* 包含 PTE SOTA 引擎头文件 */

int do_vaddr_translate(struct socket* sock, void* arg) {
    struct wuwa_addr_translate_cmd cmd;
    int ret;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    ret = translate_process_vaddr(cmd.pid, cmd.va, &cmd.phy_addr);
    if (ret < 0) {
        return ret;
    }

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }
    return 0;
}

int do_debug_info(struct socket* sock, void* arg) {
    struct wuwa_debug_info_cmd debug_info_cmd;

    debug_info_cmd.ttbr0_el1 = read_sysreg_s(SYS_TTBR0_EL1);
    debug_info_cmd.task_struct = (u64)current;
    debug_info_cmd.mm_struct = (u64)current->mm;
    debug_info_cmd.pgd_addr = (u64)current->mm->pgd;
    debug_info_cmd.pgd_phys_addr = virt_to_phys(current->mm->pgd);
    debug_info_cmd.mm_asid = ASID(current->mm);
    debug_info_cmd.mm_right = ((uint64_t)(ASID(current->mm)) << 48 |
                                virt_to_phys(current->mm->pgd) | (uint64_t)1) ==
                               debug_info_cmd.ttbr0_el1;

    if (copy_to_user(arg, &debug_info_cmd, sizeof(debug_info_cmd))) {
        return -EFAULT;
    }

    return 0;
}

int do_at_s1e0r(struct socket* sock, void* arg) {
    struct wuwa_at_s1e0r_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    struct pid* pid_struct = find_get_pid(cmd.pid);
    if (!pid_struct) {
        wuwa_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct task_struct* task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        wuwa_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct mm_struct* mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        wuwa_warn("failed to get mm: %d\n", cmd.pid);
        return -ESRCH;
    }

    u64 original_ttbr0 = read_sysreg_s(SYS_TTBR0_EL1);
    u64 new_ttbr0 = (uint64_t)(ASID(mm)) << 48 |
                    virt_to_phys(mm->pgd) | (uint64_t)1;
    dsb(ish);
    asm volatile("msr ttbr0_el1, %0" ::"r"(new_ttbr0));
    dsb(ish);
    isb();

    asm volatile("at s1e0r, %0" ::"r"(cmd.va));
    isb();
    uintptr_t pa = read_sysreg_s(SYS_PAR_EL1);
    cmd.phy_addr = pa;
    mmput(mm);

    dsb(ish);
    asm volatile("msr ttbr0_el1, %0" ::"r"(original_ttbr0));
    dsb(ish);
    isb();

    if (cmd.phy_addr == 0) {
        return -EFAULT;
    }

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }
    return 0;
}

int do_get_page_info(struct socket* sock, void* arg) {
    struct wuwa_page_info_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    struct pid* pid_struct = find_get_pid(cmd.pid);
    if (!pid_struct) {
        wuwa_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct task_struct* task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        wuwa_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct mm_struct* mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        wuwa_warn("failed to get mm: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct page* page_struct = vaddr_to_page(mm, cmd.va);
    if (!page_struct) {
        wuwa_warn("failed to get page for va: %lx\n", cmd.va);
        mmput(mm);
        return -EFAULT;
    }

    uintptr_t phy_addr = page_to_phys(page_struct);
    cmd.page.phy_addr = phy_addr;
    cmd.page.flags = page_struct->flags;
    cmd.page._mapcount = page_struct->_mapcount;
    cmd.page._refcount = page_struct->_refcount;

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

int do_pte_mapping(struct socket* sock, void* arg) {
#if defined(BUILD_PTE_MAPPING)
    struct wuwa_sock* ws = (struct wuwa_sock*)sock->sk;
    struct wuwa_pte_mapping_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    if (cmd.start_addr < 0 || cmd.start_addr >= TASK_SIZE_64) {
        wuwa_warn("invalid start address: 0x%lx\n", cmd.start_addr);
        return -EINVAL;
    }

    if (cmd.num_pages <= 0 ||
        cmd.num_pages > (TASK_SIZE_64 - cmd.start_addr) / PAGE_SIZE) {
        wuwa_warn("invalid number of pages: %zu\n", cmd.num_pages);
        return -EINVAL;
    }

    pgd_t* pgd;
    p4d_t* p4d;
    pud_t* pud;
    pmd_t* pmd;
    pte_t* pte;
    struct page* page = NULL;
    int ret = 0;

    struct pid* pid_struct = find_get_pid(cmd.pid);
    if (!pid_struct) {
        wuwa_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct task_struct* task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        wuwa_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct mm_struct* mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        wuwa_warn("failed to get mm: %d\n", cmd.pid);
        return -ESRCH;
    }

    static int (*my__pmd_alloc)(struct mm_struct* mm, pud_t* pud,
                                 unsigned long address) = NULL;
    my__pmd_alloc = (int (*)(struct mm_struct*, pud_t*, unsigned long))
        kallsyms_lookup_name_ex("__pmd_alloc");
    static int (*my__pte_alloc)(struct mm_struct* mm, pmd_t* pmd) = NULL;
    my__pte_alloc = (int (*)(struct mm_struct*, pmd_t*))
        kallsyms_lookup_name_ex("__pte_alloc");

    if (my__pmd_alloc == NULL || my__pte_alloc == NULL) {
        wuwa_err("failed to find __pmd_alloc or __pte_alloc symbols\n");
        ret = -ENOENT;
        goto out_mm;
    }

#define my_pte_alloc(mm, pmd) \
    (unlikely(pmd_none(*(pmd))) && my__pte_alloc(mm, pmd))
#define my_pte_alloc_map(mm, pmd, address) \
    (my_pte_alloc(mm, pmd) ? NULL : pte_offset_map(pmd, address))

    unsigned long addr = cmd.start_addr;
    size_t i;
    struct page** page_arr = kmalloc_array(cmd.num_pages,
                                            sizeof(struct page*), GFP_KERNEL);
    if (!page_arr) {
        wuwa_err("failed to allocate page array\n");
        ret = -ENOMEM;
        goto out_mm;
    }

    for (i = 0; i < cmd.num_pages; i++) {
        pgd = pgd_offset(mm, addr);
        if (pgd_none(*pgd) || pgd_bad(*pgd)) {
            ret = -EINVAL;
            wuwa_err("bad pgd for 0x%lx\n", addr);
            goto rollback;
        }

        p4d = p4d_alloc(mm, pgd, addr);
        if (!p4d) {
            ret = -ENOMEM;
            goto rollback;
        }

        pud = pud_alloc(mm, p4d, addr);
        if (!pud) {
            ret = -ENOMEM;
            goto rollback;
        }

        if (unlikely(pud_none(*pud))) {
            if (my__pmd_alloc(mm, pud, addr)) {
                wuwa_err("failed to allocate pmd\n");
                ret = -ENOMEM;
                goto rollback;
            }
        }

        pmd = pmd_offset(pud, addr);
        if (!pmd) {
            wuwa_err("failed to get pmd\n");
            ret = -ENOMEM;
            goto rollback;
        }

        pte = my_pte_alloc_map(mm, pmd, addr);
        if (!pte) {
            ret = -ENOMEM;
            wuwa_err("failed to allocate pte for address 0x%lx\n", addr);
            goto rollback;
        }
        if (!pte_none(*pte)) {
            ret = -EEXIST;
            wuwa_err("pte already exists for address 0x%lx\n", addr);
            pte_unmap(pte);
            goto rollback;
        }

        page = alloc_page(GFP_USER | __GFP_ZERO);
        if (!page) {
            ret = -ENOMEM;
            wuwa_err("failed to allocate page %zu\n", i);
            pte_unmap(pte);
            goto rollback;
        }
        page_arr[i] = page;

        pte_t new_pte = mk_pte(page, PAGE_SHARED_EXEC);
        new_pte = pte_mkwrite(pte_mkdirty(pte_mkyoung(new_pte)));
        set_pte(pte, new_pte);
        pte_unmap(pte);

        wuwa_info("mapped page %zu at address 0x%lx\n", i, addr);
        addr += PAGE_SIZE;
    }

    flush_tlb_all();
    mmput(mm);

    for (int i = 0; i < cmd.num_pages; ++i) {
        struct page* p = page_arr[i];
        if (!p) {
            wuwa_err("page %d is NULL\n", i);
            continue;
        }
        if (!ws->used_pages) {
            wuwa_err("used_pages array not initialized\n");
            break;
        }
        arraylist_add(ws->used_pages, p);
    }
    kfree(page_arr);

    if (cmd.hide) {
        wuwa_add_unsafe_region(ws->session, task->cred->uid.val,
                                cmd.start_addr, cmd.num_pages);
    }

    wuwa_info("successfully mapped page at address 0x%lx for pid %d\n",
              cmd.start_addr, cmd.pid);
    return 0;

rollback:
    while (i--)
        __free_page(page_arr[i]);
out_mm:
    mmput(mm);
    return ret;
#else
    return -EINVAL;
#endif
}

int do_page_table_walk(struct socket* sock, void* arg) {
    struct wuwa_page_table_walk_cmd cmd;
    struct page_walk_stats stats;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    struct task_struct* task = get_target_task(cmd.pid);
    if (!task) {
        return -ESRCH;
    }

    struct mm_struct* mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -ESRCH;
    }

    traverse_page_tables(mm, &stats);

    cmd.total_pte_count   = stats.total_pte_count;
    cmd.present_pte_count = stats.present_pte_count;
    cmd.pmd_huge_count    = stats.pmd_huge_count;
    cmd.pud_huge_count    = stats.pud_huge_count;

    mmput(mm);
    put_task_struct(task);

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

int do_copy_process(struct socket* sock, void* arg) {
    int ret = 0;
    struct wuwa_copy_process_cmd cmd;
    struct pid* pid;
    struct task_struct* task;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    if (!cmd.fn || !cmd.child_stack) {
        wuwa_err("invalid function pointer or child stack\n");
        return -EINVAL;
    }

    pid = find_get_pid(cmd.pid);
    if (!pid) {
        wuwa_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    task = get_pid_task(pid, PIDTYPE_PID);
    put_pid(pid);
    if (!task) {
        wuwa_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    ret = -1;
    put_task_struct(task);
    if (ret) {
        wuwa_err("failed to create remote thread: %d\n", ret);
        goto prepare_fault;
    }

    return 0;

prepare_fault:
    return ret;
}

#if !defined(ARCH_HAS_VALID_PHYS_ADDR_RANGE) || defined(MODULE)
static inline int memk_valid_phys_addr_range(uintptr_t addr, size_t size) {
    return addr + size <= __pa(high_memory);
}
#define IS_VALID_PHYS_ADDR_RANGE(x, y) memk_valid_phys_addr_range(x, y)
#else
#define IS_VALID_PHYS_ADDR_RANGE(x, y) valid_phys_addr_range(x, y)
#endif

int do_read_physical_memory(struct socket* sock, void __user* arg) {
    struct wuwa_read_physical_memory_cmd cmd;
    uintptr_t pa;
    void* mapped;
    int ret;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    ret = translate_process_vaddr(cmd.pid, cmd.src_va,
                                   (uintptr_t*)&cmd.phy_addr);
    if (ret < 0) {
        return ret;
    }

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    pa = cmd.phy_addr;
    if (!pa || !pfn_valid(__phys_to_pfn(pa)) ||
        !IS_VALID_PHYS_ADDR_RANGE(pa, cmd.size)) {
        return -EFAULT;
    }

    mapped = phys_to_virt(pa);
    if (!mapped) {
        return -ENOMEM;
    }

    if (copy_to_user((void*)cmd.dst_va, mapped, cmd.size)) {
        return -EACCES;
    }

    return 0;
}

int do_get_module_base(struct socket* sock, void __user* arg) {
    struct wuwa_get_module_base_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    uintptr_t base = get_module_base(cmd.pid, cmd.name, cmd.vm_flag);
    if (base == 0) {
        return -ENAVAIL;
    }

    cmd.base = base;
    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

int do_find_process(struct socket* sock, void* arg) {
    struct wuwa_find_proc_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    cmd.pid = find_process_by_name(cmd.name);
    if (cmd.pid == 0) {
        return -ENAVAIL;
    }

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

int do_write_physical_memory(struct socket* sock, void __user* arg) {
    struct wuwa_write_physical_memory_cmd cmd;
    uintptr_t pa;
    void* mapped;
    int ret;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    ret = translate_process_vaddr(cmd.pid, cmd.dst_va,
                                   (uintptr_t*)&cmd.phy_addr);
    if (ret < 0) {
        return ret;
    }

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    pa = cmd.phy_addr;
    if (!pa || !pfn_valid(__phys_to_pfn(pa)) ||
        !IS_VALID_PHYS_ADDR_RANGE(pa, cmd.size)) {
        return -EFAULT;
    }

    mapped = phys_to_virt(pa);
    if (!mapped) {
        return -ENOMEM;
    }

    if (copy_from_user(mapped, (void*)cmd.src_va, cmd.size)) {
        return -EACCES;
    }

    return 0;
}

int do_is_process_alive(struct socket* sock, void* arg) {
    struct wuwa_is_proc_alive_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    cmd.alive = is_pid_alive(cmd.pid);

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

int do_hide_process(struct socket* sock, void* arg) {
    struct task_struct* task;
    struct wuwa_hide_proc_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    if ((task = find_task_by_vpid(cmd.pid)) == NULL)
        return -ESRCH;
    task->flags ^= PF_INVISIBLE;

    return -EINVAL;
}

int do_give_root(struct socket* sock, void* arg) {
    struct wuwa_give_root_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    cmd.result = give_root();

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

int do_read_physical_memory_ioremap(struct socket* sock, void* arg) {
    struct wuwa_read_physical_memory_ioremap_cmd cmd;
    pgprot_t prot;
    uintptr_t pa;
    void* mapped;
    int ret;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    if (cmd.size == 0 || cmd.size > PAGE_SIZE) {
        return -EFAULT;
    }

    if (cmd.prot < WMT_NORMAL || cmd.prot > WMT_NORMAL_iNC_oWB) {
        return -EINVAL;
    }

    ret = convert_wmt_to_pgprot(cmd.prot, &prot);
    if (ret < 0) {
        return ret;
    }

    ret = translate_process_vaddr(cmd.pid, cmd.src_va, &cmd.phy_addr);
    if (ret < 0) {
        return ret;
    }

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    pa = cmd.phy_addr;
    if (!pa || !pfn_valid(__phys_to_pfn(pa))) {
        return -EFAULT;
    }

    mapped = wuwa_ioremap_prot(pa, cmd.size, prot);
    if (!mapped) {
        wuwa_err("failed to ioremap physical address 0x%lx\n", pa);
        return -ENOMEM;
    }

    ret = copy_to_user((void*)cmd.dst_va, mapped, cmd.size);
    iounmap(mapped);

    return ret ? -EACCES : 0;
}

int do_write_physical_memory_ioremap(struct socket* sock, void* arg) {
    struct wuwa_write_physical_memory_ioremap_cmd cmd;
    pgprot_t prot;
    uintptr_t pa;
    void* mapped;
    int ret;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    if (cmd.size == 0 || cmd.size > PAGE_SIZE) {
        return -EFAULT;
    }

    if (cmd.prot < WMT_NORMAL || cmd.prot > WMT_NORMAL_iNC_oWB) {
        return -EINVAL;
    }

    ret = convert_wmt_to_pgprot(cmd.prot, &prot);
    if (ret < 0) {
        return ret;
    }

    ret = translate_process_vaddr(cmd.pid, cmd.src_va, &cmd.phy_addr);
    if (ret < 0) {
        return ret;
    }

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    pa = cmd.phy_addr;
    if (!pa || !pfn_valid(__phys_to_pfn(pa))) {
        return -EFAULT;
    }

    mapped = wuwa_ioremap_prot(pa, cmd.size, prot);
    if (!mapped) {
        wuwa_err("failed to ioremap physical address 0x%lx\n", pa);
        return -ENOMEM;
    }

    ret = copy_from_user(mapped, (void*)cmd.dst_va, cmd.size);
    iounmap(mapped);

    return ret ? -EACCES : 0;
}

int do_list_processes(struct socket* sock, void __user* arg) {
    struct wuwa_list_processes_cmd cmd;
    struct task_struct* task;
    u8* kernel_bitmap;
    size_t process_count = 0;
    int ret = 0;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    if (cmd.bitmap_size < 8192) {
        wuwa_warn("bitmap size too small: %zu (minimum 8192)\n",
                  cmd.bitmap_size);
        return -EINVAL;
    }

    kernel_bitmap = kzalloc(cmd.bitmap_size, GFP_KERNEL);
    if (!kernel_bitmap) {
        wuwa_err("failed to allocate kernel bitmap\n");
        return -ENOMEM;
    }

    rcu_read_lock();
    for_each_process(task) {
        pid_t pid = task->pid;
        if (pid >= 0 && pid < (cmd.bitmap_size * 8)) {
            size_t byte_index = pid / 8;
            size_t bit_index  = pid % 8;
            kernel_bitmap[byte_index] |= (1 << bit_index);
            process_count++;
        }
    }
    rcu_read_unlock();

    if (copy_to_user(cmd.bitmap, kernel_bitmap, cmd.bitmap_size)) {
        ret = -EFAULT;
        goto out_free;
    }

    cmd.process_count = process_count;
    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        ret = -EFAULT;
        goto out_free;
    }

out_free:
    kfree(kernel_bitmap);
    return ret;
}

int do_get_process_info(struct socket* sock, void __user* arg) {
    struct wuwa_get_proc_info_cmd cmd;
    struct pid* pid_struct;
    struct task_struct* task;
    char cmdline[256];
    int ret = 0;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    pid_struct = find_get_pid(cmd.pid);
    if (!pid_struct) {
        wuwa_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        wuwa_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    cmd.tgid = task->tgid;
    cmd.uid  = task->cred->uid.val;
    cmd.ppid = task->real_parent ? task->real_parent->pid : 0;
    cmd.prio = task->prio;

    cmdline[0] = '\0';

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    static int (*my_get_cmdline)(struct task_struct* task,
                                  char* buffer, int buflen) = NULL;
    if (my_get_cmdline == NULL) {
        my_get_cmdline = (void*)kallsyms_lookup_name_ex("get_cmdline");
    }

    if (my_get_cmdline != NULL && task->mm != NULL) {
        ret = my_get_cmdline(task, cmdline, sizeof(cmdline));
    } else {
        ret = -1;
    }
#else
    if (task->mm != NULL) {
        struct mm_struct* mm = get_task_mm(task);
        if (mm) {
            unsigned long arg_start, arg_end;
            unsigned int len;

            spin_lock(&mm->arg_lock);
            arg_start = mm->arg_start;
            arg_end   = mm->arg_end;
            spin_unlock(&mm->arg_lock);

            len = arg_end - arg_start;
            if (len > sizeof(cmdline) - 1)
                len = sizeof(cmdline) - 1;

            ret = access_process_vm(task, arg_start, cmdline, len,
                                     FOLL_FORCE);
            mmput(mm);
        } else {
            ret = -1;
        }
    } else {
        ret = -1;
    }
#endif

    if (ret < 0 || cmdline[0] == '\0') {
        strncpy(cmd.name, task->comm, sizeof(cmd.name) - 1);
    } else {
        char* space = strchr(cmdline, ' ');
        if (space) *space = '\0';

        char* slash    = strrchr(cmdline, '/');
        char* prog_name = slash ? (slash + 1) : cmdline;

        strncpy(cmd.name, prog_name, sizeof(cmd.name) - 1);
    }
    cmd.name[sizeof(cmd.name) - 1] = '\0';

    put_task_struct(task);

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

/* ================================================================
 * PTE UXN Stealth 引擎控制接口处理函数
 * ================================================================ */
int do_set_stealth(struct socket* sock, void __user* arg) {
    struct wuwa_stealth_req req;

    if (copy_from_user(&req, arg, sizeof(req))) {
        wuwa_err("[Stealth] copy_from_user failed\n");
        return -EFAULT;
    }
    
    wuwa_info("[Stealth] Installing PTE Trap for PID: %d, Hooks: %d\n", req.pid, req.hook_count);
    return wuwa_install_stealth(&req);
}

int do_clean_stealth(struct socket* sock, void __user* arg) {
    wuwa_cleanup_stealth();
    return 0;
}
