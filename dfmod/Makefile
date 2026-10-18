# DirtyFrag module build.
# Modules: df_self (self-contained second stage, device-agnostic scan)
# Usage: make KDIR=/path/to/kernel
# Toolchain: clang-11 must be in PATH.
obj-m += df_self.o df_stager.o

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=arm64 LLVM=1 modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=arm64 LLVM=1 clean

.PHONY: all clean
