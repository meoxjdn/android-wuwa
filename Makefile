obj-m := android-wuwa.o

# 1. 自动获取当前项目绝对路径
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

# 2. 自动扫描所有目录，找齐所有需要的 .c 源码，不再手动乱猜！
WUWA_SRCS := $(wildcard $(MDIR)/src/core/*.c \
                        $(MDIR)/src/net/*.c \
                        $(MDIR)/src/utils/*.c \
                        $(MDIR)/src/ioctl/*.c \
                        $(MDIR)/src/mm/*.c \
                        $(MDIR)/src/hook/*.c \
                        $(MDIR)/src/proc/*.c \
                        $(MDIR)/src/inlinehook/*.c)

# 3. 自动转换成编译目标
android-wuwa-y := $(patsubst $(MDIR)/%.c,%.o,$(WUWA_SRCS))

KDIR ?= /lib/modules/$(shell uname -r)/build

# 4. 包含所有头文件路径
ccflags-y += -I$(MDIR)/src/core -I$(MDIR)/src/net -I$(MDIR)/src/ioctl -I$(MDIR)/src/mm
ccflags-y += -I$(MDIR)/src/inlinehook -I$(MDIR)/src/hook -I$(MDIR)/src/proc -I$(MDIR)/src/utils

# 5. 消除无用警告并适配 Android 15
ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function -Wno-unused-variable
ccflags-y += -DBUILD_NO_CFI -DWUWA_DISABLE_DMABUF

all:
	make -C $(KDIR) M=$(MDIR) modules

clean:
	make -C $(KDIR) M=$(MDIR) clean

.PHONY: all clean
