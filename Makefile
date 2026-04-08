obj-m := android-wuwa.o

android-wuwa-y := \
android-wuwa-y := \
    src/core/wuwa.o \
    src/net/wuwa_sock.o \
    src/net/wuwa_protocol.o \
    src/utils/wuwa_utils.o \
    src/ioctl/wuwa_ioctl.o \
    src/mm/wuwa_page_walk.o \
    src/mm/wuwa_proc_dmabuf.o \
    src/hook/wuwa_safe_signal.o \
    src/hook/wuwa_hide_trace.o \
    src/hook/wuwa_perf_hbp.o \
    src/proc/wuwa_proc.o \

src := $(if $(filter /%,$(src)),$(src),$(srctree)/$(src))

KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(MDIR))
$(info -- WUWA_SRC_DIR: $(src))
$(info -- WUWA_OBJ_DIR: $(obj))

ccflags-y += -I$(src)/src/core -I$(src)/src/net -I$(src)/src/ioctl -I$(src)/src/mm
ccflags-y += -I$(src)/src/inlinehook -I$(src)/src/hook -I$(src)/src/proc -I$(src)/src/utils

ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function -Wno-unused-variable

# 编译时启用 隐藏模块功能
#ccflags-y += -DHIDE_SELF_MODULE
# 编译时启用 PTE_MAPPING 功能
#ccflags-y += -DBUILD_PTE_MAPPING
# 编译时启用 HIDE_SIGNAL 功能
#ccflags-y += -DBUILD_HIDE_SIGNAL
#ccflags-y += -DPTE_WALK
ccflags-y += -DBUILD_NO_CFI
# 如果 Android 12 5.10 内核出现 page_pinner_inited 导出失败 需要先禁用DMA buffer 创建作为临时处理方案
# 默认禁用 DMA buffer 功能，如需启用请注释下面这行
ccflags-y += -DWUWA_DISABLE_DMABUF

all:
	make -C $(KDIR) M=$(MDIR) modules

clean:
	make -C $(KDIR) M=$(MDIR) clean
    
compdb:
	python3 $(MDIR)/.vscode/generate_compdb.py -O $(KDIR) $(MDIR)

.PHONY: all clean
