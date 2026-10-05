// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "security.h"
#include "ss/services.h"
#include "selinux/policy_types.h"
#include "compat/selinux_policy_54.h"
#include "infra/symbol_resolver.h"

struct ksu_policy_stamp_54 {
    u32 sequence;
    bool netlink_route;
    bool netlink_getneigh;
};

static int policy_stamp(struct ksu_policy_stamp_54 *stamp)
{
    struct selinux_ss *ss = READ_ONCE(KSU_DATA(KSU_SELINUX_STATE, selinux_state)->ss);

    if (!ss)
        return -EAGAIN;
    /* Only scalar reads while holding the spin-based native read lock. */
    read_lock(&ss->policy_rwlock);
    stamp->sequence = ss->latest_granting;
    stamp->netlink_route = ss->policydb.android_netlink_route;
    stamp->netlink_getneigh = ss->policydb.android_netlink_getneigh;
    read_unlock(&ss->policy_rwlock);
    return stamp->sequence ? 0 : -EAGAIN;
}

ksu_policy_t *ksu_policy_54_snapshot(void)
{
    struct ksu_policy_stamp_54 before, after;
    struct file *file;
    struct policydb *db;
    ksu_policy_t *snapshot;
    void *data;
    loff_t size, pos = 0;
    size_t capacity, used = 0;
    ssize_t count;
    char extra;
    int ret;

    ret = policy_stamp(&before);
    if (ret)
        return ERR_PTR(ret);
    /* The native open serializes an immutable buffer under fsi->mutex.
     * Preserve normal VFS and SELinux access checks and propagate denials.
     */
    file = filp_open("/sys/fs/selinux/policy", O_RDONLY, 0);
    if (IS_ERR(file))
        return ERR_CAST(file);
    ret = -EINVAL;
    if (file_inode(file)->i_sb->s_magic != SELINUX_MAGIC ||
        !S_ISREG(file_inode(file)->i_mode))
        goto close_file;
    size = i_size_read(file_inode(file));
    if (size <= 0)
        goto close_file;
    ret = -EFBIG;
    if (size > 64U * 1024U * 1024U)
        goto close_file;
    capacity = (size_t)size;
    data = vmalloc(capacity);
    ret = -ENOMEM;
    if (!data)
        goto close_file;

    while (used < capacity) {
        count = kernel_read(file, (char *)data + used, capacity - used, &pos);
        if (count < 0) {
            ret = count;
            goto free_data;
        }
        if (!count)
            break;
        used += count;
    }
    /* Never silently accept a snapshot truncated by the advertised size. */
    count = kernel_read(file, &extra, 1, &pos);
    if (count) {
        ret = count < 0 ? count : -EFBIG;
        goto free_data;
    }
    ret = policy_stamp(&after);
    if (ret)
        goto free_data;
    if (before.sequence != after.sequence ||
        before.netlink_route != after.netlink_route ||
        before.netlink_getneigh != after.netlink_getneigh) {
        ret = -EAGAIN;
        goto free_data;
    }
    fput(file);
    db = ksu_policy_54_parse(data, used);
    vfree(data);
    if (IS_ERR(db))
        return ERR_CAST(db);
    /* The stock binary writer omits these Android-specific config bits. */
    db->android_netlink_route = before.netlink_route;
    db->android_netlink_getneigh = before.netlink_getneigh;
    snapshot = kzalloc(sizeof(*snapshot), GFP_KERNEL);
    if (!snapshot) {
        ksu_policy_54_destroy(db);
        return ERR_PTR(-ENOMEM);
    }
    snapshot->policydb = *db;
    snapshot->latest_granting = before.sequence;
    /* Do not borrow a live sidtab: it can be replaced after our read. */
    snapshot->sidtab = NULL;
    kfree(db);
    return snapshot;

free_data:
    vfree(data);
close_file:
    fput(file);
    return ERR_PTR(ret);
}
