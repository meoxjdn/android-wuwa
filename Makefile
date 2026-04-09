obj-m := android-wuwa.o

android-wuwa-y := \
    src/core/wuwa.o \
    src/net/wuwa_sock.o \
    src/net/wuwa_protocol.o \
    src/utils/wuwa_utils.o \
    src/utils/arraylist.o \
    src/ioctl/wuwa_ioctl.o \
    src/mm/wuwa_page_walk.o \
    src/mm/wuwa_proc_dmabuf.o \
    src/hook/wuwa_safe_signal.o \
    src/hook/wuwa_hide_trace.o \
    src/hook/wuwa_perf_hbp.o \
    src/proc/wuwa_proc.o

# 注意：如果你的源码里有 src/inlinehook/ 文件夹，请务必把下面这行前面的 # 去掉
# android-wuwa-y += src/inlinehook/inlinehook.o

src := $(if $(filter /%,$(src)),$(src),$(srctree)/$(src))
KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

ccflags-y += -I$(src)/src/core -I$(src)/src/net -I$(src)/src/ioctl -I$(src)/src/mm
ccflags-y += -I$(src)/src/inlinehook -I$(src)/src/hook -I$(src)/src/proc -I$(src)/src/utils

ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function -Wno-unused-variable
ccflags-y += -DBUILD_NO_CFI -DWUWA_DISABLE_DMABUF

all:
	make -C $(KDIR) M=$(MDIR) modules

clean:
	make -C $(KDIR) M=$(MDIR) clean

.PHONY: all clean
