// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/slab.h>
#include "ss/policydb.h"
#include "compat/selinux_policy_54.h"

/* These definitions belong to our pinned private parser, not stock SELinux. */
int ksu_s21_policydb_read(struct policydb *db, void *fp);
void ksu_s21_policydb_destroy(struct policydb *db);

struct policydb *ksu_policy_54_parse(const void *data, size_t len)
{
    struct policydb *db;
    struct policy_file fp;
    int ret;

    if (!data || !len)
        return ERR_PTR(-EINVAL);
    if (len > 64U * 1024U * 1024U)
        return ERR_PTR(-EFBIG);
    db = kzalloc(sizeof(*db), GFP_KERNEL);
    if (!db)
        return ERR_PTR(-ENOMEM);
    fp.data = (char *)data;
    fp.len = len;
    ret = ksu_s21_policydb_read(db, &fp);
    if (ret) {
        /* The reader cleans its partial contents; only the wrapper remains. */
        kfree(db);
        return ERR_PTR(ret);
    }
    if (fp.len) {
        ksu_s21_policydb_destroy(db);
        kfree(db);
        return ERR_PTR(-EINVAL);
    }
    db->len = len;
    return db;
}

void ksu_policy_54_destroy(struct policydb *db)
{
    if (!db)
        return;
    ksu_s21_policydb_destroy(db);
    kfree(db);
}

void ksu_policy_54_destroy_contents(struct policydb *db)
{
    ksu_s21_policydb_destroy(db);
}
