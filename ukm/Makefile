obj-m += ukm.o

# -fno-stack-protector is necessary because kernels without stack protectors do
# not have __stack_chk_fail.
# Use -DDISABLE_NETPOLL_SUPPORT to disable netpoll (e.g. for testing on Debian)
CFLAGS_ukm.o := -I$(PWD) -fno-stack-protector -DENABLE_DEBUGGING $(UKM_FLAGS)

CURRENT_MODULES := /lib/modules/$(shell uname -r)/build
NEW_MODULES := $(shell find '/lib/modules' -mindepth 2 -maxdepth 2 -name build -print -quit)
# You can override the kernel source tree with KERNEL.
# To cross-compile (e.g. MIPS), specify ARCH=mips CROSS_COMPILE=mips-linux-gnu-
# and ensure that your kernel source is configured correctly (in particular,
# specify these arguments while configuring your kernel!)
KERNEL ?= $(shell test -e "$(CURRENT_MODULES)" && echo "$(CURRENT_MODULES)" || echo "$(NEW_MODULES)")

.PHONY: all module

all: module

module:
	make -C $(KERNEL) M=$(PWD) modules

clean:
	make -C $(KERNEL) M=$(PWD) clean

