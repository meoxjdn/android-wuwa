#include <asm/tlbflush.h>
#include <asm/unistd.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include "wuwa_common.h"
#include "wuwa_kallsyms.h"
#include "wuwa_protocol.h"
#include "wuwa_safe_signal.h"
#include "wuwa_sock.h"
#include "wuwa_utils.h"
#include "hijack_arm64.h"

// 引入功能头文件
#include "wuwa_hide_trace.h" 
#include "../hook/wuwa_perf_hbp.h" 

static int __init wuwa_init(void) {
    int ret;
    wuwa_info("helo!\n");

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    ret = disable_kprobe_blacklist();
    if (ret) {
        wuwa_err("disable_kprobe_blacklist failed: %d\n", ret);
        return ret;
    }
#endif

    ret = init_arch();
    if (ret) {
        wuwa_err("init_arch failed: %d\n", ret);
        return ret;
    }

    /* 保留原有的协议初始化，维持其他 ioctl 基础功能不受影响 */
    ret = wuwa_proto_init();
    if (ret) {
        wuwa_err("wuwa_socket_init failed: %d\n", ret);
        goto out;
    }

    /* 启动 PTE UXN SOTA 引擎 (纯净启动，无设备节点暴露) */
    ret = wuwa_stealth_init();
    if (ret) {
        wuwa_err("wuwa_stealth_init failed: %d\n", ret);
        goto clean_proto;
    }

#if defined(BUILD_HIDE_SIGNAL)
    ret = wuwa_safe_signal_init();
    if (ret) {
        wuwa_err("wuwa_safe_signal_init failed: %d\n", ret);
        goto clean_hbp;
    }
#endif

#if defined(HIDE_SELF_MODULE)
    hide_module();
#endif

#if defined(BUILD_NO_CFI)
    wuwa_info("NO_CFI is enabled, patched: %d\n", cfi_bypass());
#endif

    // 启动 TracerPid 隐藏逻辑 (基于 Kretprobe)
    if (wuwa_hide_trace_init() != 0) {
        wuwa_warn("wuwa_hide_trace_init failed, device might lack Ftrace support.\n");
    }

    return 0;

/* 异常回滚清理链 */
#if defined(BUILD_HIDE_SIGNAL)
clean_hbp:
    wuwa_stealth_cleanup();
#endif

clean_proto:
    wuwa_proto_cleanup();

out:
    return ret;
}

static void __exit wuwa_exit(void) {
    wuwa_info("bye!\n");

    // 清理并恢复 PTE UXN 状态，注销异常钩子
    wuwa_stealth_cleanup();
    
    // 卸载 TracerPid 隐藏 Hook
    wuwa_hide_trace_exit();
    
    // 清理原有的 Socket 协议
    wuwa_proto_cleanup();

#if defined(BUILD_HIDE_SIGNAL)
    wuwa_safe_signal_cleanup();
#endif
}

module_init(wuwa_init);
module_exit(wuwa_exit);

MODULE_AUTHOR("fuqiuluo");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("https://github.com/fuqiuluo/android-wuwa");
MODULE_VERSION("1.0.5");

MODULE_IMPORT_NS(DMA_BUF);
