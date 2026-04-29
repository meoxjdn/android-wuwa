#ifndef WUWA_PERF_HBP_H
#define WUWA_PERF_HBP_H

#include <linux/types.h>

/* V18.18 影子内存补丁动作定义 (大牛清洗纯净版) */
enum shadow_action_v18 {
    SHADOW_DATA_PATCH   = 0,
    SHADOW_RET_ONLY     = 1,
    SHADOW_JUMP_B       = 2, /* 秒过 */
    SHADOW_GOD_MODE     = 3, /* ★ 你的终极精准无敌汇编 (替代了所有旧逻辑) */
    SHADOW_DOUBLE_PATCH = 4, /* 去黑边双指令 */
    SHADOW_SAFE_HP_STUB = 5, /* 秒杀防越界蹦床 */
    SHADOW_FLOAT_RET    = 6  /* 全屏浮点引擎 */
};

struct shadow_patch_req {
    uint64_t offset;       
    uint32_t action;       
    uint32_t expected;     
    uint32_t patch_val;    
    uint32_t patch_val_2;  
    uint64_t target_va;    
};

struct wuwa_hbp_req {
    int      tid;
    uint32_t hook_count;
    uint64_t base_addr;
    struct shadow_patch_req hooks[16];
};

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
