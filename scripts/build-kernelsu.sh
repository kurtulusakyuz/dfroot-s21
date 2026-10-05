#!/usr/bin/env bash
# Compile the experimental S21 module; never install or load it.
set -euo pipefail
# Self-contained clone: S21_ROOT_OVERRIDE disinda toolchains arar
# (repo dista 2GB toolchain tasimaz; yanina S21/toolchains koy
# ya da override ver).
S21_ROOT="${S21_ROOT_OVERRIDE:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
S21_MODULE="$S21_ROOT/work/KernelSU-v3.2.5/kernel"
exec bash "$S21_ROOT/scripts/kernel-make.sh" \
    M="$S21_MODULE" src="$S21_MODULE" \
    CONFIG_KSU=m CONFIG_KSU_S21_54=y \
    CONFIG_KSU_SAMSUNG_KDP=y CONFIG_KSU_SAMSUNG_RKP=y \
    CONFIG_KSU_SAMSUNG_DEFEX=y CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y \
    "$@" modules
