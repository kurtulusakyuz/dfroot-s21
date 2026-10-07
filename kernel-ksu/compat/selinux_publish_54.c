// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/audit.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <net/netlabel.h>
#include "ksu.h"
#include "security.h"
#include "selinux/selinux.h"
#include "avc.h"
#include "avc_ss.h"
#include "objsec.h"
#include "netlabel.h"
#include "xfrm.h"
#include "ss/services.h"
#include "ss/conditional.h"
#include "compat/selinux_policy_54.h"
#include "infra/symbol_resolver.h"

/* Exact G991BXXSJHZC2 selinuxfs.c layout, not a generic kernel interface.
 * A pinned file keeps the superblock and this object alive while locked.
 */
struct ksu_selinux_fs_info_54 {
    struct dentry *bool_dir;
    unsigned int bool_num;
    char **bool_pending_names;
    unsigned int *bool_pending_values;
    struct dentry *class_dir;
    unsigned long last_class_ino;
    bool policy_opened;
    struct dentry *policycap_dir;
    struct mutex mutex;
    unsigned long last_ino;
    struct selinux_state *state;
    struct super_block *sb;
};

static bool same_permissions(struct symtab *old, struct symtab *new)
{
    struct hashtab_node *node;
    struct perm_datum *a, *b;
    u32 i;

    if (old->nprim != new->nprim || !old->table || !new->table ||
        old->table->nel != new->table->nel)
        return false;
    for (i = 0; i < old->table->size; i++) {
        for (node = old->table->htable[i]; node; node = node->next) {
            a = node->datum;
            b = hashtab_search(new->table, node->key);
            if (!a || !b || a->value != b->value)
                return false;
        }
    }
    return true;
}

/* KSU edits append types/attributes and change rules. They must not renumber
 * existing contexts or alter the class/permission map, MLS mode or policy
 * capabilities. This is deliberately not a general policy-reload API.
 * Caller holds the live policy read lock. No allocation or sleeping here.
 */
static bool same_context_schema(struct policydb *old, struct policydb *new)
{
    u32 kind, i;

    if (old->policyvers != new->policyvers || old->mls_enabled != new->mls_enabled ||
        old->reject_unknown != new->reject_unknown || old->allow_unknown != new->allow_unknown ||
        old->android_netlink_route != new->android_netlink_route ||
        old->android_netlink_getneigh != new->android_netlink_getneigh ||
        old->process_class != new->process_class || old->process_trans_perms != new->process_trans_perms ||
        !ebitmap_cmp(&old->policycaps, &new->policycaps))
        return false;
    for (kind = 0; kind < SYM_NUM; kind++) {
        if (new->symtab[kind].nprim < old->symtab[kind].nprim ||
            (kind != SYM_TYPES && new->symtab[kind].nprim != old->symtab[kind].nprim))
            return false;
        for (i = 0; i < old->symtab[kind].nprim; i++) {
            const char *a = old->sym_val_to_name[kind][i];
            const char *b = new->sym_val_to_name[kind][i];
            if (!a || !b || strcmp(a, b))
                return false;
        }
    }
    for (i = 0; i < old->p_types.nprim; i++) {
        struct type_datum *a = old->type_val_to_struct[i];
        struct type_datum *b = new->type_val_to_struct[i];
        if (!a || !b || a->primary != b->primary || a->attribute != b->attribute || a->bounds != b->bounds)
            return false;
    }
    for (i = 0; i < old->p_bools.nprim; i++) {
        if (old->bool_val_to_struct[i]->state != new->bool_val_to_struct[i]->state)
            return false;
    }
    for (i = 0; i < old->p_classes.nprim; i++) {
        struct class_datum *a = old->class_val_to_struct[i];
        struct class_datum *b = new->class_val_to_struct[i];
        if (!a || !b || !same_permissions(&a->permissions, &b->permissions) ||
            !!a->comdatum != !!b->comdatum)
            return false;
        if (a->comdatum && (!a->comkey || !b->comkey || strcmp(a->comkey, b->comkey) ||
                           !same_permissions(&a->comdatum->permissions, &b->comdatum->permissions)))
            return false;
    }
    return true;
}

int ksu_policy_54_publish(ksu_policy_t *snapshot)
{
    struct policydb *prepared, *retired;
    struct ksu_selinux_fs_info_54 *fsi;
    struct selinux_ss *ss;
    struct file *file;
    void *data;
    size_t len;
    u32 sequence;
    int ret;

    if (!snapshot || !snapshot->latest_granting)
        return -EINVAL;
    /* Reparse our edited private copy before taking any live writer lock. */
    ret = ksu_policy_54_serialize(&snapshot->policydb, &data, &len);
    if (ret)
        return ret;
    prepared = ksu_policy_54_parse(data, len);
    vfree(data);
    if (IS_ERR(prepared))
        return PTR_ERR(prepared);
    retired = kmalloc(sizeof(*retired), GFP_KERNEL);
    if (!retired) {
        ret = -ENOMEM;
        goto destroy_prepared;
    }
    file = NULL;
    {
        /* Manager (untrusted_app) cannot open selinuxfs load node and
         * fails the load_policy check. Caller is already authorized by
         * the ioctl perm (manager_or_root); perform open + check as ksu.
         * Upstream ksud runs in KSU domain and passes trivially. */
        const struct cred *saved = override_creds(ksu_cred);
        file = filp_open("/sys/fs/selinux/load", O_WRONLY, 0);
        if (IS_ERR(file)) {
            ret = PTR_ERR(file);
            revert_creds(saved);
            goto free_retired;
        }
        ret = -EINVAL;
        if (file_inode(file)->i_sb->s_magic != SELINUX_MAGIC) {
            revert_creds(saved);
            goto close_file;
        }
        fsi = file_inode(file)->i_sb->s_fs_info;
        if (!fsi || fsi->sb != file_inode(file)->i_sb || fsi->state != KSU_DATA(KSU_SELINUX_STATE, selinux_state)) {
            revert_creds(saved);
            goto close_file;
        }
        mutex_lock(&fsi->mutex);
        /* Match sel_write_load's explicit policy-load authorization check. */
        ret = ksu_b_avc_has_perm(KSU_DATA(KSU_SELINUX_STATE, selinux_state), current_sid(), SECINITSID_SECURITY,
                          SECCLASS_SECURITY, SECURITY__LOAD_POLICY, NULL);
        revert_creds(saved);
        if (ret)
            goto unlock_fsi;
    }
    ss = KSU_DATA(KSU_SELINUX_STATE, selinux_state)->ss;
    ret = -EAGAIN;
    if (!ss)
        goto unlock_fsi;
    read_lock(&ss->policy_rwlock);
    if (ss->latest_granting != snapshot->latest_granting)
        ret = -EAGAIN;
    else
        ret = same_context_schema(&ss->policydb, prepared) ? 0 : -EOPNOTSUPP;
    read_unlock(&ss->policy_rwlock);
    if (ret)
        goto unlock_fsi;

    write_lock_irq(&ss->policy_rwlock);
    if (ss->latest_granting != snapshot->latest_granting) {
        write_unlock_irq(&ss->policy_rwlock);
        ret = -EAGAIN;
        goto unlock_fsi;
    }
    *retired = ss->policydb;
    ss->policydb = *prepared;
    sequence = ++ss->latest_granting;
    write_unlock_irq(&ss->policy_rwlock);

    /* Existing IDs/maps/capabilities remain valid by the schema guard.
     * No sidtab is borrowed from the snapshot or freed on this path.
     */
    kfree(prepared);
    prepared = NULL;
    ksu_policy_54_destroy(retired);
    retired = NULL;
    ksu_b_avc_ss_reset(KSU_DATA(KSU_SELINUX_STATE, selinux_state)->avc, sequence);
    ksu_b_selnl_notify_policyload(sequence);
    ksu_b_selinux_status_update_policyload(KSU_DATA(KSU_SELINUX_STATE, selinux_state), sequence);
    selinux_netlbl_cache_invalidate();
    selinux_xfrm_notify_policyload();
    ksu_b_audit_log(audit_context(), GFP_KERNEL, AUDIT_MAC_POLICY_LOAD,
              "auid=%u ses=%u lsm=selinux res=1",
              from_kuid(&init_user_ns, audit_get_loginuid(current)),
              audit_get_sessionid(current));
    ret = 0;
unlock_fsi:
    mutex_unlock(&fsi->mutex);
close_file:
    fput(file);
free_retired:
    kfree(retired);
destroy_prepared:
    ksu_policy_54_destroy(prepared);
    return ret;
}

