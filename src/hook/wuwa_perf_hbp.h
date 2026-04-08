#ifndef WUWA_PERF_HBP_H
#define WUWA_PERF_HBP_H

#include <linux/types.h>

/* 定义与 C++ 通信的配置结构体 */
struct wuwa_hbp_req {
    int tid;
    uint64_t base_addr;
    int fov_on;
    int border_on;
    int skip_on;
    int damage_on;
    int maxhp_on;
};

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req);
void wuwa_cleanup_perf_hbp(void);

#endif
