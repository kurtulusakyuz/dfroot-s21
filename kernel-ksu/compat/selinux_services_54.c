/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Self-contained copies of the two S21 SELinux "services" helpers the module
 * needs that are not part of the "ss" layer files. Function symbols are
 * renamed to ksu_s21_* via compat/s21_54.h. Source bodies are pinned to the
 * Samsung S21 tree (G991BXXSJHZC2 / 5.4.242).
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/string.h>
#include <linux/preempt.h>

#include "security.h"
#include "ss/policydb.h"
#include "ss/context.h"
#include "ss/mls.h"
#include "ss/services.h"
#include "ss/avtab.h"

/*
 * Write the security context string representation of the context structure
 * `context' into a dynamically allocated string of the correct size.
 * (Copied from security/selinux/ss/services.c, S21 tree.)
 */
static int context_struct_to_string(struct policydb *p,
				    struct context *context,
				    char **scontext, u32 *scontext_len)
{
	char *scontextp;
	gfp_t kmalloc_flag = GFP_ATOMIC;

	if (scontext)
		*scontext = NULL;
	*scontext_len = 0;

	if (context->len) {
		*scontext_len = context->len;
		if (scontext) {
			*scontext = kstrdup(context->str, GFP_ATOMIC);
			if (!(*scontext))
				return -ENOMEM;
		}
		return 0;
	}

	*scontext_len += strlen(sym_name(p, SYM_USERS, context->user - 1)) + 1;
	*scontext_len += strlen(sym_name(p, SYM_ROLES, context->role - 1)) + 1;
	*scontext_len += strlen(sym_name(p, SYM_TYPES, context->type - 1)) + 1;
	*scontext_len += mls_compute_context_len(p, context);

	if (!scontext)
		return 0;

	if (!in_interrupt() && !in_atomic())
		kmalloc_flag = GFP_KERNEL;
	scontextp = kmalloc(*scontext_len, kmalloc_flag);
	if (!scontextp)
		return -ENOMEM;
	*scontext = scontextp;

	scontextp += sprintf(scontextp, "%s:%s:%s",
		sym_name(p, SYM_USERS, context->user - 1),
		sym_name(p, SYM_ROLES, context->role - 1),
		sym_name(p, SYM_TYPES, context->type - 1));

	mls_sid_to_context(p, context, &scontextp);

	*scontextp = 0;

	return 0;
}

int context_add_hash(struct policydb *policydb,
		     struct context *context)
{
	int rc;
	char *str;
	int len;

	if (context->str) {
		context->hash = context_compute_hash(context->str);
	} else {
		rc = context_struct_to_string(policydb, context,
					      &str, &len);
		if (rc)
			return rc;
		context->hash = context_compute_hash(str);
		kfree(str);
	}
	return 0;
}

void services_compute_xperms_drivers(struct extended_perms *xperms,
				     struct avtab_node *node)
{
	unsigned int i;

	if (node->datum.u.xperms->specified == AVTAB_XPERMS_IOCTLDRIVER) {
		for (i = 0; i < ARRAY_SIZE(xperms->drivers.p); i++)
			xperms->drivers.p[i] |= node->datum.u.xperms->perms.p[i];
	} else if (node->datum.u.xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION) {
		security_xperm_set(xperms->drivers.p,
				   node->datum.u.xperms->driver);
	}

	if (node->key.specified & AVTAB_XPERMS_ALLOWED)
		xperms->len = 1;
}
