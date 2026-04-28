#ifndef WUWA_IOCTL_H
#define WUWA_IOCTL_H

#include "wuwa_common.h"
#include "wuwa_bindproc.h"
/* ⚠️ 彻底删除了对 wuwa_perf_hbp.h 的引用，切断依赖 */

struct wuwa_addr_translate_cmd {
    uintptr_t phy_addr; 
    pid_t pid; 
    uintptr_t va; 
};

struct wuwa_debug_info_cmd {
    u64 ttbr0_el1; 
    u64 task_struct;
    u64 mm_struct; 
    u64 pgd_addr; 
    u64 pgd_phys_addr;
    u64 mm_asid; 
    u32 mm_right;
};

struct wuwa_at_s1e0r_cmd {
    uintptr_t phy_addr;
    pid_t pid;
    uintptr_t va;
};

struct kernel_page {
    unsigned long flags; 
    union { 
        atomic_t _mapcount;
        unsigned int page_type;
    };
    atomic_t _refcount;
    uintptr_t phy_addr;
};

struct wuwa_page_info_cmd {
    pid_t pid;
    uintptr_t va;
    struct kernel_page page; 
};

#ifndef WUWA_DISABLE_DMABUF
struct wuwa_dma_buf_create_cmd {
    pid_t pid;
    uintptr_t va;
    size_t size;
    int fd;
};
#endif

struct wuwa_pte_mapping_cmd {
    pid_t pid;
    uintptr_t start_addr;
    size_t num_pages;
    int hide; 
};

struct wuwa_page_table_walk_cmd {
    pid_t pid; 
    u64 total_pte_count; 
    u64 present_pte_count; 
    u64 pmd_huge_count; 
    u64 pud_huge_count; 
};

struct wuwa_copy_process_cmd {
    pid_t pid;
    int (*__user fn)(void*);
    void* __user child_stack;
    size_t child_stack_size;
    u64 flags;
    void* __user arg;
    int __user* child_tid;
};

struct wuwa_read_physical_memory_cmd {
    pid_t pid; 
    uintptr_t src_va; 
    uintptr_t dst_va; 
    size_t size; 
    uintptr_t phy_addr; 
};

struct wuwa_write_physical_memory_cmd {
    pid_t pid; 
    uintptr_t src_va; 
    uintptr_t dst_va; 
    size_t size; 
    uintptr_t phy_addr; 
};

struct wuwa_get_module_base_cmd {
    pid_t pid; 
    char name[256]; 
    uintptr_t base; 
    int vm_flag; 
};

struct wuwa_find_proc_cmd {
    pid_t pid; 
    char name[256]; 
};

struct wuwa_is_proc_alive_cmd {
    pid_t pid; 
    int alive; 
};

struct wuwa_hide_proc_cmd {
    pid_t pid; 
    int hide; 
};

struct wuwa_give_root_cmd {
    int result; 
};

struct wuwa_read_physical_memory_ioremap_cmd {
    pid_t pid; 
    uintptr_t src_va; 
    uintptr_t dst_va; 
    size_t size; 
    uintptr_t phy_addr; 
    int prot; 
};

struct wuwa_write_physical_memory_ioremap_cmd {
    pid_t pid; 
    uintptr_t src_va; 
    uintptr_t dst_va; 
    size_t size; 
    uintptr_t phy_addr; 
    int prot; 
};

struct wuwa_bind_proc_cmd {
    pid_t pid; 
    int fd; 
};

struct wuwa_list_processes_cmd {
    u8* __user bitmap; 
    size_t bitmap_size; 
    size_t process_count; 
};

struct wuwa_get_proc_info_cmd {
    pid_t pid; 
    pid_t tgid; 
    char name[256]; 
    uid_t uid; 
    pid_t ppid; 
    int prio; 
};


/* IOCTL command for virtual to physical address translation */
#define WUWA_IOCTL_ADDR_TRANSLATE _IOWR('W', 1, struct wuwa_addr_translate_cmd)
#define WUWA_IOCTL_DEBUG_INFO _IOR('W', 2, struct wuwa_debug_info_cmd)
#define WUWA_IOCTL_AT_S1E0R _IOWR('W', 3, struct wuwa_at_s1e0r_cmd)
#define WUWA_IOCTL_PAGE_INFO _IOWR('W', 4, struct wuwa_page_info_cmd)
#ifndef WUWA_DISABLE_DMABUF
#define WUWA_IOCTL_DMA_BUF_CREATE _IOWR('W', 5, struct wuwa_dma_buf_create_cmd)
#endif
#define WUWA_IOCTL_PTE_MAPPING _IOWR('W', 6, struct wuwa_pte_mapping_cmd)
#define WUWA_IOCTL_PAGE_TABLE_WALK _IOWR('W', 7, struct wuwa_page_table_walk_cmd)
#define WUWA_IOCTL_COPY_PROCESS _IOWR('W', 8, struct wuwa_copy_process_cmd)
#define WUWA_IOCTL_READ_MEMORY _IOWR('W', 9, struct wuwa_read_physical_memory_cmd)
#define WUWA_IOCTL_GET_MODULE_BASE _IOWR('W', 10, struct wuwa_get_module_base_cmd)
#define WUWA_IOCTL_FIND_PROCESS _IOWR('W', 11, struct wuwa_find_proc_cmd)
#define WUWA_IOCTL_WRITE_MEMORY _IOWR('W', 12, struct wuwa_write_physical_memory_cmd)
#define WUWA_IOCTL_IS_PROCESS_ALIVE _IOWR('W', 13, struct wuwa_is_proc_alive_cmd)
#define WUWA_IOCTL_HIDE_PROCESS _IOWR('W', 14, struct wuwa_hide_proc_cmd)
#define WUWA_IOCTL_GIVE_ROOT _IOWR('W', 15, struct wuwa_give_root_cmd)
#define WUWA_IOCTL_READ_MEMORY_IOREMAP _IOWR('W', 16, struct wuwa_read_physical_memory_ioremap_cmd)
#define WUWA_IOCTL_WRITE_MEMORY_IOREMAP _IOWR('W', 17, struct wuwa_write_physical_memory_ioremap_cmd)
#define WUWA_IOCTL_BIND_PROC _IOWR('W', 18, struct wuwa_bind_proc_cmd)
#define WUWA_IOCTL_LIST_PROCESSES _IOWR('W', 19, struct wuwa_list_processes_cmd)
#define WUWA_IOCTL_GET_PROC_INFO _IOWR('W', 20, struct wuwa_get_proc_info_cmd)

int do_vaddr_translate(struct socket* sock, void __user* arg);
int do_debug_info(struct socket* sock, void __user* arg);
int do_at_s1e0r(struct socket* sock, void __user* arg);
int do_get_page_info(struct socket* sock, void __user* arg);
#ifndef WUWA_DISABLE_DMABUF
int do_create_proc_dma_buf(struct socket* sock, void __user* arg);
#endif
int do_pte_mapping(struct socket* sock, void __user* arg);
int do_page_table_walk(struct socket* sock, void __user* arg);
int do_copy_process(struct socket* sock, void __user* arg);
int do_read_physical_memory(struct socket* sock, void __user* arg);
int do_get_module_base(struct socket* sock, void __user* arg);
int do_find_process(struct socket* sock, void __user* arg);
int do_write_physical_memory(struct socket* sock, void __user* arg);
int do_is_process_alive(struct socket* sock, void __user* arg);
int do_hide_process(struct socket* sock, void __user* arg);
int do_give_root(struct socket* sock, void __user* arg);
int do_read_physical_memory_ioremap(struct socket* sock, void __user* arg);
int do_write_physical_memory_ioremap(struct socket* sock, void __user* arg);
int do_list_processes(struct socket* sock, void __user* arg);
int do_get_process_info(struct socket* sock, void __user* arg);

typedef int (*ioctl_handler_t)(struct socket* sock, void __user* arg);

static const struct ioctl_cmd_map {
    unsigned int cmd;
    ioctl_handler_t handler;
} ioctl_handlers[] = {
    {.cmd = WUWA_IOCTL_ADDR_TRANSLATE, .handler = do_vaddr_translate},
    {.cmd = WUWA_IOCTL_DEBUG_INFO, .handler = do_debug_info},
    {.cmd = WUWA_IOCTL_AT_S1E0R, .handler = do_at_s1e0r}, 
    {.cmd = WUWA_IOCTL_PAGE_INFO, .handler = do_get_page_info},
#ifndef WUWA_DISABLE_DMABUF
    {.cmd = WUWA_IOCTL_DMA_BUF_CREATE, .handler = do_create_proc_dma_buf},
#endif
    {.cmd = WUWA_IOCTL_PTE_MAPPING, .handler = do_pte_mapping},
    {.cmd = WUWA_IOCTL_PAGE_TABLE_WALK, .handler = do_page_table_walk},
    {.cmd = WUWA_IOCTL_COPY_PROCESS, .handler = do_copy_process},
    {.cmd = WUWA_IOCTL_READ_MEMORY, .handler = do_read_physical_memory},
    {.cmd = WUWA_IOCTL_GET_MODULE_BASE, .handler = do_get_module_base},
    {.cmd = WUWA_IOCTL_FIND_PROCESS, .handler = do_find_process},
    {.cmd = WUWA_IOCTL_WRITE_MEMORY, .handler = do_write_physical_memory},
    {.cmd = WUWA_IOCTL_IS_PROCESS_ALIVE, .handler = do_is_process_alive},
    {.cmd = WUWA_IOCTL_HIDE_PROCESS, .handler = do_hide_process},
    {.cmd = WUWA_IOCTL_GIVE_ROOT, .handler = do_give_root},
    {.cmd = WUWA_IOCTL_READ_MEMORY_IOREMAP, .handler = do_read_physical_memory_ioremap},
    {.cmd = WUWA_IOCTL_WRITE_MEMORY_IOREMAP, .handler = do_write_physical_memory_ioremap},
    {.cmd = WUWA_IOCTL_BIND_PROC, .handler = do_bind_proc},
    {.cmd = WUWA_IOCTL_LIST_PROCESSES, .handler = do_list_processes},
    {.cmd = WUWA_IOCTL_GET_PROC_INFO, .handler = do_get_process_info},
    /* ⚠️ 彻底切断了旧 Socket 框架与 V18 的关联 */
    {.cmd = 0, .handler = NULL} 
};

#endif // WUWA_IOCTL_H
