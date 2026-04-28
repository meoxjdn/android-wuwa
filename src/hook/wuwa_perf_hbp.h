#ifndef WUWA_PERF_HBP_H
#define WUWA_PERF_HBP_H

#include <linux/types.h>

#define MAX_HOOKS 16
#define MAX_OOL_SLOTS 256

/* PTE UXN 控制流去向枚举 */
#define PC_BEHAVIOR_NONE  0
#define PC_BEHAVIOR_SKIP  1
#define PC_BEHAVIOR_RET   2
#define PC_BEHAVIOR_JUMP  3

#pragma pack(push, 8)
struct hook_request {
    uint64_t vaddr;
    uint32_t original_inst; 
    
    uint32_t modify_x_idx;
    uint64_t modify_x_val;
    uint32_t modify_s_idx;
    uint32_t modify_s_val;
    uint32_t add_sp_val;
    
    uint32_t pc_behavior;
    uint64_t pc_jump_addr;
    
    uint32_t use_cond;
    uint32_t cond_base_reg;
    uint32_t cond_offset;
    uint32_t cond_cmp_val;
    
    uint32_t false_x0_modify;
    uint64_t false_x0_val;
    uint32_t false_add_sp;
    uint32_t false_pc_behavior;
};

/* 适配 IOCTL 的通用 Stealth 载荷结构体 */
struct wuwa_stealth_req {
    int      pid;
    uint64_t trampoline_base; // 用户态分配的 OOL RWX 跳板基址
    uint32_t hook_count;
    struct   hook_request hooks[MAX_HOOKS];
};
#pragma pack(pop)

/* 暴露给 wuwa.c 调用的生命周期函数 */
int wuwa_stealth_init(void);
void wuwa_stealth_cleanup(void);

/* 暴露给 wuwa_ioctl.c 调用的载荷下发函数 */
int wuwa_install_stealth(struct wuwa_stealth_req *req);
void wuwa_cleanup_stealth(void);

#endif // WUWA_PERF_HBP_H
