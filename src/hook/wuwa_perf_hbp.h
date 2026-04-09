/* wuwa_perf_hbp.h */
#ifndef WUWA_PERF_HBP_H
#define WUWA_PERF_HBP_H

#include <linux/types.h>

/* 前向声明，避免循环 include */
struct wuwa_hbp_req;

int  wuwa_install_perf_hbp(struct wuwa_hbp_req *req);
void wuwa_cleanup_perf_hbp(void);

#endif /* WUWA_PERF_HBP_H */
