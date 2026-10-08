# DirtyFrag stager module build (SM-G991B/HZC2, 5.4.242).
# Usage: make KDIR=/path/to/kernel-G991BXXSJHZC2
# Toolchain: clang-11 (S21/toolchains/clang-r383902) must be in PATH.
obj-m += df_stager.o

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=arm64 LLVM=1 modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=arm64 LLVM=1 clean

.PHONY: all clean
