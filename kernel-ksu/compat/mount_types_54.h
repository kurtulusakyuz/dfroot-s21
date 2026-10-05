/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Reproduction of the internal `struct mount` layout for S21 (5.4).
 * `struct mount` is defined in fs/mount.h (internal) and is NOT exported, but
 * with RANDSTRUCT disabled its layout is deterministic. This reproduction is
 * pinned to the S21 tree (fs/mount.h, sha256
 * 6e7cfd373123432aa8795e0996ae329ca5b38953102adcac43fcd750f820b8d5)
 * and is used only to reach mnt_list/mnt_mounts/mnt_child/mnt_parent so the
 * path_mount/path_umount backport can iterate/detach the real mount tree.
 *
 * S21 config used here: CONFIG_SMP=y, CONFIG_FSNOTIFY=y, CONFIG_KDP_NS=y.
 */
#ifndef __KSU_MOUNT_TYPES_54_H
#define __KSU_MOUNT_TYPES_54_H

#include <linux/mount.h> /* struct vfsmount, struct kdp_vfsmount, struct path */
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/types.h>

struct dentry;
struct mnt_namespace;
struct mountpoint;
struct fsnotify_mark_connector;

struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};

struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	union {
		struct rcu_head mnt_rcu;
		struct llist_node mnt_llist;
	};
	struct mnt_pcp *mnt_pcp; /* CONFIG_SMP=y (__percpu elided) */
	struct list_head mnt_mounts;
	struct list_head mnt_child;
	struct list_head mnt_instance;
	const char *mnt_devname;
	struct list_head mnt_list;
	struct list_head mnt_expire;
	struct list_head mnt_share;
	struct list_head mnt_slave_list;
	struct list_head mnt_slave;
	struct mount *mnt_master;
	struct mnt_namespace *mnt_ns;
	struct mountpoint *mnt_mp;
	union {
		struct hlist_node mnt_mp_list;
		struct hlist_node mnt_umount;
	};
	struct list_head mnt_umounting;
	struct fsnotify_mark_connector *mnt_fsnotify_marks; /* CONFIG_FSNOTIFY=y (__rcu elided) */
	u32 mnt_fsnotify_mask;
	int mnt_id;
	int mnt_group_id;
	int mnt_expiry_mark;
	struct hlist_head mnt_pins;
	struct hlist_head mnt_stuck_children;
};

#ifdef CONFIG_KDP_NS
struct kdp_mount {
	struct mount mount;
	struct vfsmount *mnt;
};
#endif

/* Internal enum from fs/namespace.c (not exported). */
enum ksu_umount_tree_flags {
	KSU_UMOUNT_SYNC = 1,
	KSU_UMOUNT_PROPAGATE = 2,
	KSU_UMOUNT_CONNECTED = 4,
};

#endif
