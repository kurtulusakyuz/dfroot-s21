#!/usr/bin/env bash
# Run kbuild with the compiler reported by the connected stock S21.
# Usage: bash scripts/kernel-make.sh olddefconfig
#        bash scripts/kernel-make.sh modules_prepare
set -euo pipefail

S21_ROOT="${S21_ROOT_OVERRIDE:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
S21_KERNEL="$S21_ROOT/kernel-G991BXXSJHZC2"
S21_OUT="$S21_ROOT/out/stock-prepare"
S21_CLANG="$S21_ROOT/toolchains/clang-r383902/bin"
S21_GNU="$S21_ROOT/toolchains/aarch64-gcc-4.9/bin"
S21_GNU32="$S21_ROOT/toolchains/arm-gcc-4.9/bin"
S21_HOST="$S21_ROOT/toolchains/host-tools/usr"

export PATH="$S21_CLANG:$S21_GNU:$S21_GNU32:$S21_HOST/bin:$PATH"
export BISON_PKGDATADIR="$S21_HOST/share/bison"
export PLATFORM_VERSION=11
export ANDROID_MAJOR_VERSION=r
# Samsung GPU Kconfig evaluates this numeric environment variable.
export SEC_BUILD_CONF_VENDOR_BUILD_OS=15

mkdir -p "$S21_OUT"
exec make -C "$S21_KERNEL" O="$S21_OUT" \
    ARCH=arm64 LLVM=1 LLVM_IAS=1 \
    CC="$S21_CLANG/clang" LD="$S21_CLANG/ld.lld" \
    CROSS_COMPILE="$S21_GNU/aarch64-linux-android-" \
    CROSS_COMPILE_COMPAT="$S21_GNU32/arm-linux-androideabi-" \
    CLANG_TRIPLE=aarch64-linux-gnu- \
    LOCALVERSION=-30958140-abG991BXXSJHZC2 \
    "$@"
