// SPDX-License-Identifier: GPL-2.0
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/unaligned.h>
#include "ss/policydb.h"
#include "compat/selinux_policy_54.h"

/* Match the bound imposed by S21 sel_write_load(). */
#define KSU_POLICY_54_MAX_SIZE (64U * 1024U * 1024U)

int ksu_policy_54_serialize(struct policydb *db, void **data, size_t *len)
{
    struct policy_file fp;
    void *buffer;
    size_t capacity, used, config_offset;
    u32 config;
    int ret;

    if (!data || !len)
        return -EINVAL;
    *data = NULL;
    *len = 0;
    if (!db || db->policyvers < POLICYDB_VERSION_AVTAB ||
        db->policyvers > POLICYDB_VERSION_MAX)
        return -EINVAL;
    if (db->len > KSU_POLICY_54_MAX_SIZE)
        return -EFBIG;

    /* db->len describes the input policy. Added rules can outgrow it.
     * S21 put_entry() returns -EINVAL when its output buffer is too small.
     * Other -EINVAL failures are bounded by the same cap and stay errors.
     */
    capacity = max_t(size_t, db->len, 4096);
    for (;;) {
        buffer = vmalloc(capacity);
        if (!buffer)
            return -ENOMEM;
        fp.data = buffer;
        fp.len = capacity;
        ret = policydb_write(db, &fp);
        if (!ret)
            break;
        vfree(buffer);
        if (ret != -EINVAL || capacity == KSU_POLICY_54_MAX_SIZE)
            return ret;
        capacity = min_t(size_t, capacity * 2, KSU_POLICY_54_MAX_SIZE);
    }

    used = capacity - fp.len;
    /* Header: magic, identifier length, identifier, version, config.
     * Validate the writer's format before restoring Samsung Android flags.
     */
    config_offset = 3 * sizeof(u32) + strlen(POLICYDB_STRING);
    if (used < config_offset + sizeof(u32) ||
        get_unaligned_le32(buffer) != POLICYDB_MAGIC ||
        get_unaligned_le32((char *)buffer + sizeof(u32)) != strlen(POLICYDB_STRING) ||
        memcmp((char *)buffer + 2 * sizeof(u32), POLICYDB_STRING, strlen(POLICYDB_STRING)) ||
        get_unaligned_le32((char *)buffer + config_offset - sizeof(u32)) != db->policyvers) {
        vfree(buffer);
        return -EINVAL;
    }

    config = get_unaligned_le32((char *)buffer + config_offset);
    if (db->android_netlink_route)
        config |= POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE;
    if (db->android_netlink_getneigh)
        config |= POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH;
    put_unaligned_le32(config, (char *)buffer + config_offset);

    *data = buffer;
    *len = used;
    return 0;
}
