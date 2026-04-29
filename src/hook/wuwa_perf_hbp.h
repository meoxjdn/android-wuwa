#ifndef WUWA_PERF_HBP_H
#define WUWA_PERF_HBP_H

#include <linux/types.h>

/* V18.17 影子内存补丁动作定义 */
enum shadow_action_v18 {
    SHADOW_DATA_PATCH   = 0,
    SHADOW_RET_ONLY     = 1,
    SHADOW_JUMP_B       = 2,
    SHADOW_STUB_IF      = 3,
    SHADOW_HP_SET       = 4,
    SHADOW_DOUBLE_PATCH = 5,
    SHADOW_SAFE_HP_STUB = 6, 
    SHADOW_FLOAT_RET    = 7,
    SHADOW_GOD_MODE_STUB= 8  /* ★ V18.17 终极无敌跳板引擎 (大牛定制版) */
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
