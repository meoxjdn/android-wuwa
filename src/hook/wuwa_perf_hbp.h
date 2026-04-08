#ifndef WUWA_PERF_HBP_H
#define WUWA_PERF_HBP_H

#include <linux/types.h>

/* 注意：wuwa_hbp_req 的定义已移至 wuwa_ioctl.h，此处仅作前向声明 */
struct wuwa_hbp_req;

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req);
void wuwa_cleanup_perf_hbp(void);

#endif
