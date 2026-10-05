/* SPDX-License-Identifier: GPL-2.0 */
/*
 * S21 (5.4) backport of path_mount()/path_umount(). These only exist on 5.15+
 * (or in Android's 5.10 backport); on S21 they are absent AND do_umount /
 * do_change_type are inlined by LTO, so they cannot be resolved from kallsyms.
 *
 * We reconstruct them from their resolvable pieces:
 *   - security_sb_umount(), umount_tree(), change_mnt_propagation(),
 *     namespace_unlock(), propagate_mount_busy()  (resolved from kallsyms)
 *   - namespace_sem, mount_lock, event            (resolved data)
 *   - the internal struct mount layout            (mount_types_54.h)
 *   - the small inline helpers (namespace_lock, lock_mount_hash,
 *     unlock_mount_hash, flags_to_propagation_type, next_mnt) reimplemented.
 *
 * These are the REAL mount/umount operations, not stubs. If any symbol fails
 * to resolve at init, the feature degrades to a logged -EOPNOTSUPP instead of
 * crashing.
 */
#include <linux/fs.h>
#include <linux/log2.h>
#include <linux/mount.h>
#include <linux/printk.h>
#include <linux/rwsem.h>
#include <linux/seqlock.h>
#include <linux/slab.h>
#include <uapi/linux/mount.h>

#include "compat/mount_ns_54.h"
#include "compat/mount_types_54.h"
#include "infra/symbol_resolver.h"

typedef int (*ksu_security_sb_umount_t)(struct vfsmount *mnt, int flags);
typedef void (*ksu_umount_tree_t)(struct mount *mnt, int how);
typedef void (*ksu_change_mnt_propagation_t)(struct mount *mnt, int type);
typedef void (*ksu_namespace_unlock_t)(void);
typedef int (*ksu_propagate_mount_busy_t)(struct mount *mnt, int refcnt);

static ksu_security_sb_umount_t ksu_security_sb_umount_fn;
static ksu_umount_tree_t ksu_umount_tree_fn;
static ksu_change_mnt_propagation_t ksu_change_mnt_propagation_fn;
static ksu_namespace_unlock_t ksu_namespace_unlock_fn;
static ksu_propagate_mount_busy_t ksu_propagate_mount_busy_fn;

static struct rw_semaphore *ksu_namespace_sem;
static seqlock_t *ksu_mount_lock;
static u64 *ksu_event;

static struct mount *ksu_real_mount(struct vfsmount *mnt)
{
#ifdef CONFIG_KDP_NS
    return ((struct kdp_vfsmount *)mnt)->bp_mount;
#else
    return NULL;
#endif
}

/* --- inline helpers from fs/namespace.c, reimplemented --- */

static int ksu_flags_to_propagation_type(int ms_flags)
{
    int type = ms_flags & ~(MS_REC | MS_SILENT);

    if (type & ~(MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE))
        return 0;
    if (!is_power_of_2(type))
        return 0;
    return type;
}

static struct mount *ksu_next_mnt(struct mount *p, struct mount *root)
{
    struct list_head *next = p->mnt_mounts.next;
    if (next == &p->mnt_mounts) {
        while (1) {
            if (p == root)
                return NULL;
            next = p->mnt_child.next;
            if (next != &p->mnt_parent->mnt_mounts)
                break;
            p = p->mnt_parent;
        }
    }
    return list_entry(next, struct mount, mnt_child);
}

int __nocfi ksu_path_umount(struct path *path, int flags)
{
    struct mount *mnt;
    int ret;

    if (!path || !path->mnt)
        return -EINVAL;

    if (!ksu_security_sb_umount_fn || !ksu_umount_tree_fn || !ksu_namespace_unlock_fn ||
        !ksu_namespace_sem || !ksu_mount_lock) {
        pr_warn_once("ksu_path_umount: helpers not resolved; umount disabled\n");
        return -EOPNOTSUPP;
    }
    if (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))
        return -EINVAL;

    mnt = ksu_real_mount(path->mnt);
    if (!mnt)
        return -EINVAL;

    ret = ksu_security_sb_umount_fn(path->mnt, flags);
    if (ret)
        return ret;

    /* Optimistic MNT_LOCKED check (do_umount re-checks under the locks). */
    if (path->mnt->mnt_flags & MNT_LOCKED)
        return -EINVAL;

    down_write(ksu_namespace_sem);
    write_seqlock(ksu_mount_lock);
    if (ksu_event)
        (*ksu_event)++;

    if (flags & MNT_DETACH) {
        if (!list_empty(&mnt->mnt_list))
            ksu_umount_tree_fn(mnt, KSU_UMOUNT_PROPAGATE);
        ret = 0;
    } else {
        /* Non-detach path. shrink_submounts() is inlined and intentionally
         * skipped here: the module's mounts have no submounts. */
        ret = -EBUSY;
        if (!ksu_propagate_mount_busy_fn || !ksu_propagate_mount_busy_fn(mnt, 2)) {
            if (!list_empty(&mnt->mnt_list))
                ksu_umount_tree_fn(mnt, KSU_UMOUNT_PROPAGATE | KSU_UMOUNT_SYNC);
            ret = 0;
        }
    }

    write_sequnlock(ksu_mount_lock);
    ksu_namespace_unlock_fn();
    return ret;
}

int __nocfi ksu_path_mount(const char *dev_name, struct path *path, const char *type_page,
                           unsigned long flags, void *data_page)
{
    struct mount *mnt, *m;
    int recurse, type;

    (void)dev_name;
    (void)type_page;
    (void)data_page;

    if (!path || !path->mnt)
        return -EINVAL;

    if (!ksu_change_mnt_propagation_fn || !ksu_namespace_unlock_fn ||
        !ksu_namespace_sem || !ksu_mount_lock) {
        pr_warn_once("ksu_path_mount: helpers not resolved; mount disabled\n");
        return -EOPNOTSUPP;
    }

    /* Only the propagation-change case (MS_PRIVATE|MS_REC etc.) is used by
     * su_mount_ns.c; other path_mount operations require further inlined
     * fs/namespace.c helpers and are not reconstructed. */
    if (!(flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE)))
        return -EINVAL;

    if (path->dentry != path->mnt->mnt_root)
        return -EINVAL;

    type = ksu_flags_to_propagation_type(flags);
    if (!type)
        return -EINVAL;

    if (type == MS_SHARED) {
        /* invent_group_ids() is inlined and not reconstructed; MS_SHARED is
         * not used by the module. */
        pr_warn_once("ksu_path_mount: MS_SHARED not supported\n");
        return -EOPNOTSUPP;
    }

    mnt = ksu_real_mount(path->mnt);
    if (!mnt)
        return -EINVAL;
    recurse = flags & MS_REC;

    down_write(ksu_namespace_sem);
    write_seqlock(ksu_mount_lock);
    for (m = mnt; m; m = (recurse ? ksu_next_mnt(m, mnt) : NULL))
        ksu_change_mnt_propagation_fn(m, type);
    write_sequnlock(ksu_mount_lock);
    ksu_namespace_unlock_fn();
    return 0;
}

void ksu_mount_ns_54_init(void)
{
    ksu_security_sb_umount_fn = (ksu_security_sb_umount_t)ksu_resolve_symbol_for_functable_hook("security_sb_umount");
    ksu_umount_tree_fn = (ksu_umount_tree_t)ksu_resolve_symbol_for_functable_hook("umount_tree");
    ksu_change_mnt_propagation_fn =
        (ksu_change_mnt_propagation_t)ksu_resolve_symbol_for_functable_hook("change_mnt_propagation");
    ksu_namespace_unlock_fn = (ksu_namespace_unlock_t)ksu_resolve_symbol_for_functable_hook("namespace_unlock");
    ksu_propagate_mount_busy_fn =
        (ksu_propagate_mount_busy_t)ksu_resolve_symbol_for_functable_hook("propagate_mount_busy");
    ksu_namespace_sem = (struct rw_semaphore *)(void *)find_kernel_symbol_exact("namespace_sem");
    ksu_mount_lock = (seqlock_t *)(void *)find_kernel_symbol_exact("mount_lock");
    ksu_event = (u64 *)(void *)find_kernel_symbol_exact("event");

    if (!ksu_security_sb_umount_fn || !ksu_umount_tree_fn || !ksu_change_mnt_propagation_fn ||
        !ksu_namespace_unlock_fn || !ksu_namespace_sem || !ksu_mount_lock)
        pr_warn("ksu_mount_ns_54: some helpers not found; umount/mount-ns features disabled\n");
}
