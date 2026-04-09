/* wuwa_perf_hbp.h */
#ifndef WUWA_PERF_HBP_H
#define WUWA_PERF_HBP_H

#include <linux/types.h>

#pragma pack(push, 8)
struct wuwa_hbp_req {
    int      tid;
    uint64_t base_addr;
    int      fov_on;
    int      border_on;
    int      skip_on;
    int      damage_on;
    int      maxhp_on;
};
#pragma pack(pop)

int  wuwa_install_perf_hbp(struct wuwa_hbp_req *req);
void wuwa_cleanup_perf_hbp(void);

#endif /* WUWA_PERF_HBP_H */
