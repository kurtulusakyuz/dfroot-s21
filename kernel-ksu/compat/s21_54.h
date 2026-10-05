/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KSU_COMPAT_S21_54_H
#define KSU_COMPAT_S21_54_H

#include <linux/version.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0) || \
    LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
#error "The S21 compatibility profile requires the audited Samsung 5.4 tree"
#endif

/* S21 task_work_add() uses bool notify; true selects notify-on-resume. */
#define TWA_RESUME true

/*
 * SELinux "ss" layer namespace. Samsung removed all EXPORT_SYMBOL from
 * security/selinux/, so the module carries its own copies of these pure
 * data-structure helpers (see compat/ss/ and compat/selinux_services_54.c).
 * Renaming keeps every call site (and the copied definitions) pointing at the
 * module-local ksu_s21_* symbols instead of the unexported stock ones.
 * These operate only on the module's own policydb/sidtab snapshots.
 */
#define hashtab_create ksu_s21_hashtab_create
#define hashtab_insert ksu_s21_hashtab_insert
#define hashtab_search ksu_s21_hashtab_search
#define hashtab_destroy ksu_s21_hashtab_destroy
#define hashtab_map ksu_s21_hashtab_map
#define hashtab_stat ksu_s21_hashtab_stat
#define hashtab_cache_init ksu_s21_hashtab_cache_init

#define ebitmap_cmp ksu_s21_ebitmap_cmp
#define ebitmap_cpy ksu_s21_ebitmap_cpy
#define ebitmap_netlbl_export ksu_s21_ebitmap_netlbl_export
#define ebitmap_netlbl_import ksu_s21_ebitmap_netlbl_import
#define ebitmap_contains ksu_s21_ebitmap_contains
#define ebitmap_get_bit ksu_s21_ebitmap_get_bit
#define ebitmap_set_bit ksu_s21_ebitmap_set_bit
#define ebitmap_destroy ksu_s21_ebitmap_destroy
#define ebitmap_read ksu_s21_ebitmap_read
#define ebitmap_write ksu_s21_ebitmap_write
#define ebitmap_cache_init ksu_s21_ebitmap_cache_init

#define avtab_insert_nonunique ksu_s21_avtab_insert_nonunique
#define avtab_search ksu_s21_avtab_search
#define avtab_search_node ksu_s21_avtab_search_node
#define avtab_search_node_next ksu_s21_avtab_search_node_next
#define avtab_destroy ksu_s21_avtab_destroy
#define avtab_init ksu_s21_avtab_init
#define avtab_alloc ksu_s21_avtab_alloc
#define avtab_hash_eval ksu_s21_avtab_hash_eval
#define avtab_read_item ksu_s21_avtab_read_item
#define avtab_read ksu_s21_avtab_read
#define avtab_write_item ksu_s21_avtab_write_item
#define avtab_write ksu_s21_avtab_write
#define avtab_cache_init ksu_s21_avtab_cache_init

#define symtab_init ksu_s21_symtab_init

#define policydb_destroy ksu_s21_policydb_destroy
#define policydb_load_isids ksu_s21_policydb_load_isids
#define policydb_class_isvalid ksu_s21_policydb_class_isvalid
#define policydb_role_isvalid ksu_s21_policydb_role_isvalid
#define policydb_type_isvalid ksu_s21_policydb_type_isvalid
#define policydb_context_isvalid ksu_s21_policydb_context_isvalid
#define string_to_security_class ksu_s21_string_to_security_class
#define string_to_av_perm ksu_s21_string_to_av_perm
#define policydb_read ksu_s21_policydb_read
#define policydb_write ksu_s21_policydb_write

#define evaluate_cond_node ksu_s21_evaluate_cond_node
#define cond_policydb_init ksu_s21_cond_policydb_init
#define cond_policydb_destroy ksu_s21_cond_policydb_destroy
#define cond_init_bool_indexes ksu_s21_cond_init_bool_indexes
#define cond_destroy_bool ksu_s21_cond_destroy_bool
#define cond_index_bool ksu_s21_cond_index_bool
#define cond_read_bool ksu_s21_cond_read_bool
#define cond_read_list ksu_s21_cond_read_list
#define cond_write_bool ksu_s21_cond_write_bool
#define cond_write_list ksu_s21_cond_write_list
#define cond_compute_xperms ksu_s21_cond_compute_xperms
#define cond_compute_av ksu_s21_cond_compute_av

#define mls_compute_context_len ksu_s21_mls_compute_context_len
#define mls_sid_to_context ksu_s21_mls_sid_to_context
#define mls_level_isvalid ksu_s21_mls_level_isvalid
#define mls_range_isvalid ksu_s21_mls_range_isvalid
#define mls_context_isvalid ksu_s21_mls_context_isvalid
#define mls_context_to_sid ksu_s21_mls_context_to_sid
#define mls_from_string ksu_s21_mls_from_string
#define mls_range_set ksu_s21_mls_range_set
#define mls_setup_user_range ksu_s21_mls_setup_user_range
#define mls_convert_context ksu_s21_mls_convert_context
#define mls_compute_sid ksu_s21_mls_compute_sid
#define mls_export_netlbl_lvl ksu_s21_mls_export_netlbl_lvl
#define mls_import_netlbl_lvl ksu_s21_mls_import_netlbl_lvl
#define mls_export_netlbl_cat ksu_s21_mls_export_netlbl_cat
#define mls_import_netlbl_cat ksu_s21_mls_import_netlbl_cat

#define sidtab_init ksu_s21_sidtab_init
#define sidtab_set_initial ksu_s21_sidtab_set_initial
#define sidtab_hash_stats ksu_s21_sidtab_hash_stats
#define sidtab_search ksu_s21_sidtab_search
#define sidtab_search_force ksu_s21_sidtab_search_force
#define sidtab_context_to_sid ksu_s21_sidtab_context_to_sid
#define sidtab_convert ksu_s21_sidtab_convert
#define sidtab_destroy ksu_s21_sidtab_destroy

#define context_add_hash ksu_s21_context_add_hash
#define services_compute_xperms_drivers ksu_s21_services_compute_xperms_drivers

/* symtab_search/symtab_insert are not kernel symbols on 5.4 (added in 5.9). */
#define symtab_search(s, name) hashtab_search((s)->table, name)
#define symtab_insert(s, name, datum) hashtab_insert((s)->table, name, datum)

/*
 * The S21 probe helpers check user address ranges, disable page faults, and
 * return 0/-EFAULT, matching the nofault callers here. The string helper
 * retains the count limit and the original NUL-inclusive return convention.
 * This does not establish that the helpers are exported by the stock kernel.
 */
/* Trimmed on HZC2: provided by file_wrapper.c via runtime resolution. */
long probe_user_read(void *dst, const void __user *src, size_t size);
long probe_user_write(void __user *dst, const void *src, size_t size);
long probe_kernel_write(void *dst, const void *src, size_t size);
#define copy_from_user_nofault probe_user_read
#define copy_to_user_nofault probe_user_write
#define copy_to_kernel_nofault probe_kernel_write
#define strncpy_from_user_nofault strncpy_from_unsafe_user

#endif
