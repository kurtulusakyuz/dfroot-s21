// SPDX-License-Identifier: GPL-2.0
#include <linux/slab.h>
#include "ss/policydb.h"
#include "selinux/sepolicy.h"

/* Only mutate a private policy copy in sleepable context. Samsung's
 * hashtab_insert() may reschedule and allocate with GFP_KERNEL.
 */
bool ksu_filename_trans_54(struct policydb *db, u32 source, u32 target,
                           u16 tclass, u32 output, const char *name)
{
    struct filename_trans lookup = {
        .stype = source, .ttype = target, .tclass = tclass, .name = name,
    };
    struct filename_trans *key;
    struct filename_trans_datum *datum;
    bool had_target;
    int ret;

    if (!db->filename_trans || db->policyvers < POLICYDB_VERSION_FILENAME_TRANS)
        return false;

    datum = hashtab_search(db->filename_trans, &lookup);
    if (datum) {
        datum->otype = output;
        return true;
    }

    key = kmemdup(&lookup, sizeof(lookup), GFP_KERNEL);
    if (!key)
        return false;
    key->name = kstrdup(name, GFP_KERNEL);
    if (!key->name)
        goto free_key;
    datum = kmalloc(sizeof(*datum), GFP_KERNEL);
    if (!datum)
        goto free_name;
    datum->otype = output;

    /* This bitmap uses the type value itself, not value - 1. See
     * filename_compute_type() and filename_trans_read() in the S21 tree.
     */
    had_target = ebitmap_get_bit(&db->filename_trans_ttypes, target);
    ret = ebitmap_set_bit(&db->filename_trans_ttypes, target, 1);
    if (ret)
        goto free_datum;
    ret = hashtab_insert(db->filename_trans, key, datum);
    if (ret) {
        if (!had_target)
            ebitmap_set_bit(&db->filename_trans_ttypes, target, 0);
        goto free_datum;
    }
    /* policydb_destroy() now owns key, name and datum. */
    return true;

free_datum:
    kfree(datum);
free_name:
    kfree(key->name);
free_key:
    kfree(key);
    return false;
}
