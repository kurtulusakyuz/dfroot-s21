/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_MOUNT_NS_54_H
#define __KSU_MOUNT_NS_54_H

#include <linux/path.h>
#include <linux/version.h>

#ifdef CONFIG_KSU_S21_54
/* S21 (5.4) has no path_mount/path_umount (5.15+); these reconstruct them. */
int ksu_path_mount(const char *dev_name, struct path *path, const char *type_page,
                   unsigned long flags, void *data_page);
int ksu_path_umount(struct path *path, int flags);
void ksu_mount_ns_54_init(void);
#else
/* Kernels with the native path-based helpers (or Android backports). */
extern int path_mount(const char *dev_name, struct path *path, const char *type_page,
                      unsigned long flags, void *data_page);
extern int path_umount(struct path *path, int flags);
#define ksu_path_mount path_mount
#define ksu_path_umount path_umount
static inline void ksu_mount_ns_54_init(void) {}
#endif

#endif
