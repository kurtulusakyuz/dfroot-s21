/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KSU_POLICY_TYPES_H
#define KSU_POLICY_TYPES_H

#ifdef CONFIG_KSU_S21_54
#include "ss/policydb.h"

/* A module-owned snapshot, NOT the layout of any stock kernel object.
 * policydb contents are owned here. SID lifetime is managed separately by
 * the caller, as in the existing KernelSU backup-policy contract.
 */
typedef struct ksu_policy_snapshot_54 {
    struct policydb policydb;
    struct sidtab *sidtab;
    u32 latest_granting;
} ksu_policy_t;
#else
typedef struct selinux_policy ksu_policy_t;
#endif

#endif
