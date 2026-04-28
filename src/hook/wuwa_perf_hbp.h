/* wuwa_perf_hbp.h */
#ifndef WUWA_PERF_HBP_H
#define WUWA_PERF_HBP_H

#include <linux/types.h>

/* V18 影子内存补丁动作定义 */
enum shadow_action_v18 {
    SHADOW_DATA_PATCH = 0, /* 修改常量/数据 (全屏 4.3f) */
    SHADOW_RET_ONLY   = 1, /* 函数入口直接返回 (去黑边) */
    SHADOW_JUMP_B     = 2, /* 近距离 B 跳转 (秒过) */
    SHADOW_STUB_IF    = 3, /* 条件分支存根 (无敌判断) */
    SHADOW_HP_SET     = 4  /* 赋值并返回 (血量修改) */
};

/* 单个 Hook 请求结构 */
struct shadow_patch_req {
    uint64_t offset;       /* 相对基址偏移 */
    uint32_t action;       /* 动作类型 (shadow_action_v18) */
    uint32_t expected;     /* 预期原始指令 (核心保险丝) */
    uint32_t patch_val;    /* 补丁指令或数据 */
    uint64_t target_va;    /* 跳转目标绝对地址 */
};

/* 核心 IOCTL 请求结构 */
struct wuwa_hbp_req {
    int      tid;
    uint32_t hook_count;
    uint64_t base_addr;
    struct shadow_patch_req hooks[16];
};

/* 诊断查询结构 */
struct wuwa_diag_req {
    uint64_t va;
    uint32_t current_inst;
    int state;
    int ref_count;
};

int  wuwa_install_perf_hbp(struct wuwa_hbp_req *req);
int  wuwa_diag_shadow_slot(struct wuwa_diag_req *req);
void wuwa_cleanup_perf_hbp(void);

#endif /* WUWA_PERF_HBP_H */
