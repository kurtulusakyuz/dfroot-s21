#ifndef __KSU_SAMSUNG_DEFEX_H
#define __KSU_SAMSUNG_DEFEX_H

#include <linux/compiler.h>
#include <linux/types.h>

int ksu_samsung_defex_init(void);
void ksu_samsung_defex_exit(void);
void ksu_samsung_defex_sync_current(void);
void ksu_dp_inject_app_dir(uid_t uid);
void ksu_dp_jit_execve(const char __user *upath);

#endif
