/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KSU_SELINUX_POLICY_54_H
#define KSU_SELINUX_POLICY_54_H

#include <linux/types.h>
#include "selinux/policy_types.h"

struct policydb;

/* The caller owns a detached, exclusively accessed policydb. This function
 * may sleep. On success, the caller owns *data and must use vfree().
 * It neither parses the result nor installs it in the live kernel.
 */
int ksu_policy_54_serialize(struct policydb *db, void **data, size_t *len);

/* Parse a complete private buffer. Returns an owned policydb or ERR_PTR.
 * No live policy or SID table is modified. May sleep; data remains borrowed.
 */
struct policydb *ksu_policy_54_parse(const void *data, size_t len);
/* Accepts NULL or a successful parse result, never an ERR_PTR. */
void ksu_policy_54_destroy(struct policydb *db);

/* Release a successfully parsed embedded policydb, retaining its container. */
void ksu_policy_54_destroy_contents(struct policydb *db);

/* Read-only, sleepable acquisition through native selinuxfs access checks.
 * Returns an owned snapshot or ERR_PTR; EAGAIN means the policy changed.
 * The captured sequence must be checked again by a future publisher.
 */
ksu_policy_t *ksu_policy_54_snapshot(void);

/* Restricted KSU rule update, preserving existing context IDs/maps.
 * Caller retains ownership on success and failure. May sleep; EAGAIN means
 * stale snapshot, EOPNOTSUPP means an unsupported schema change.
 */
int ksu_policy_54_publish(ksu_policy_t *snapshot);

#endif
