#include "selinux.h"
#include "linux/cred.h"
#include "linux/sched.h"
#include "objsec.h"
#include "linux/version.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "infra/symbol_resolver.h"
#include <linux/string.h>
#include <security.h>

/* HZC2: selinux_blob_sizes export trimmed. Values are final since
 * selinux_init (long before we load), so keep a module-local copy synced
 * once at init — all Samsung objsec.h inlines then work UNMODIFIED. */
struct lsm_blob_sizes selinux_blob_sizes;

void ksu_sync_blob_sizes(void)
{
	unsigned long real = find_kernel_symbol_exact("selinux_blob_sizes");

	if (real)
		memcpy(&selinux_blob_sizes, (void *)real,
		       sizeof(selinux_blob_sizes));
	else
		pr_warn("ksu: selinux_blob_sizes not found!\n");
}

/*
 * Cached SID values for frequently checked contexts.
 * These are resolved once at init and used for fast u32 comparison
 * instead of expensive string operations on every check.
 *
 * A value of 0 means "no cached SID is available" for that context.
 * This covers both the initial "not yet cached" state and any case
 * where resolving the SID (e.g. via security_secctx_to_secid) failed.
 * In all such cases we intentionally fall back to the slower
 * string-based comparison path; this degrades performance only and
 * does not cause a functional failure.
 */
static u32 cached_su_sid __read_mostly = 0;
static u32 cached_zygote_sid __read_mostly = 0;
static u32 cached_init_sid __read_mostly = 0;
u32 ksu_file_sid __read_mostly = 0;

/* HZC2: string->sid resolution crashes core against our freshly-published
 * policy (RCNT 164-166: sidtab content issue in the snapshot/publish path,
 * NOT calling convention). Under global permissive the domain is decorative:
 * uid-0 creds already pass everything. Stub the transition (su works,
 * policy-format bug tracked separately for hide/file-labeling). */
static int transive_to_domain(const char *domain, struct cred *cred, bool clear_exec_sid)
{
    (void)domain;
    (void)cred;
    (void)clear_exec_sid;
    pr_info("transive_to_domain: stubbed (permissive carries)\n");
    return 0;
}

static int transive_to_domain_real(const char *domain, struct cred *cred, bool clear_exec_sid)
{
    u32 sid;
    int error;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    struct task_security_struct *tsec;
#else
    struct cred_security_struct *tsec;
#endif
    tsec = selinux_cred(cred);
    if (!tsec) {
        pr_err("tsec == NULL!\n");
        return -1;
    }
    error = ksu_b_security_secid_to_secctx(domain, strlen(domain), &sid);
    if (error) {
        pr_info("security_secctx_to_secid %s -> sid: %d, error: %d\n", domain, sid, error);
    }
    if (!error) {
        tsec->sid = sid;
        tsec->create_sid = 0;
        tsec->keycreate_sid = 0;
        tsec->sockcreate_sid = 0;
        if (clear_exec_sid) {
            tsec->exec_sid = 0;
        }
    }
    return error;
}

void setup_selinux(const char *domain, struct cred *cred)
{
    if (transive_to_domain(domain, cred, false)) {
        pr_err("transive domain failed.\n");
        return;
    }
}

void setup_ksu_cred(void)
{
    if (transive_to_domain(KERNEL_SU_CONTEXT, ksu_cred, false)) {
        pr_err("setup ksu cred failed.\n");
    }
}

void setenforce(bool enforce)
{
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
    KSU_DATA(KSU_SELINUX_STATE, selinux_state)->enforcing = enforce;
#endif
}

bool getenforce(void)
{
#ifdef CONFIG_SECURITY_SELINUX_DISABLE
    if (KSU_DATA(KSU_SELINUX_STATE, selinux_state)->disabled) {
        return false;
    }
#endif

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
    return KSU_DATA(KSU_SELINUX_STATE, selinux_state)->enforcing;
#else
    return true;
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
struct lsm_context {
    char *context;
    u32 len;
};

/* NOTE: despite the name, this resolves a numeric SID to its string
 * (slow-path fallback) — the correct API is security_sid_to_context,
 * NOT security_secid_to_secctx (string->sid). The old macro mapping was
 * backwards and NULL-deref'd in core (RCNT 165). state via live pointer
 * (policy may reload; never cache the struct). */
static int __security_secid_to_secctx(u32 secid, struct lsm_context *cp)
{
    return ksu_b_security_sid_to_context(KSU_DATA(KSU_SELINUX_STATE, selinux_state),
					     secid, &cp->context, &cp->len);
}
static void __security_release_secctx(struct lsm_context *cp)
{
    ksu_b_security_release_secctx(cp->context, cp->len);
}
#else
static inline int ksu__secid_to_secctx(u32 secid, struct lsm_context *cp)
{
	return ksu_b_security_sid_to_context(KSU_DATA(KSU_SELINUX_STATE, selinux_state),
					 secid, &cp->context, &cp->len);
}
#define __security_secid_to_secctx ksu__secid_to_secctx
static inline void ksu__release_secctx(struct lsm_context *cp)
{
	ksu_b_security_release_secctx(cp->context, cp->len);
}
#define __security_release_secctx ksu__release_secctx
#endif

/*
 * Initialize cached SID values for frequently checked SELinux contexts.
 * Called once after SELinux policy is loaded (post-fs-data).
 * This eliminates expensive string comparisons in hot paths.
 */
void cache_sid(void)
{
    int err;

    err = ksu_b_security_secid_to_secctx(KERNEL_SU_CONTEXT, strlen(KERNEL_SU_CONTEXT), &cached_su_sid);
    if (err) {
        pr_warn("Failed to cache kernel su domain SID: %d\n", err);
        cached_su_sid = 0;
    } else {
        pr_info("Cached su SID: %u\n", cached_su_sid);
    }

    err = ksu_b_security_secid_to_secctx(ZYGOTE_CONTEXT, strlen(ZYGOTE_CONTEXT), &cached_zygote_sid);
    if (err) {
        pr_warn("Failed to cache zygote SID: %d\n", err);
        cached_zygote_sid = 0;
    } else {
        pr_info("Cached zygote SID: %u\n", cached_zygote_sid);
    }

    err = ksu_b_security_secid_to_secctx(INIT_CONTEXT, strlen(INIT_CONTEXT), &cached_init_sid);
    if (err) {
        pr_warn("Failed to cache init SID: %d\n", err);
        cached_init_sid = 0;
    } else {
        pr_info("Cached init SID: %u\n", cached_init_sid);
    }

    err = ksu_b_security_secid_to_secctx(KSU_FILE_CONTEXT, strlen(KSU_FILE_CONTEXT), &ksu_file_sid);
    if (err) {
        pr_warn("Failed to cache ksu_file SID: %d\n", err);
        ksu_file_sid = 0;
    } else {
        pr_info("Cached ksu_file SID: %u\n", ksu_file_sid);
    }
}

/*
 * Fast path: compare task's SID directly against cached value.
 * Falls back to string comparison if cache is not initialized.
 */
static bool is_sid_match(const struct cred *cred, u32 cached_sid, const char *fallback_context)
{
    if (!cred) {
        return false;
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    const struct task_security_struct *tsec = selinux_cred(cred);
#else
    const struct cred_security_struct *tsec = selinux_cred(cred);
#endif
    if (!tsec) {
        return false;
    }

    // Fast path: use cached SID if available
    if (likely(cached_sid != 0)) {
        return tsec->sid == cached_sid;
    }

    // Slow path fallback: string comparison (only before cache is initialized)
    struct lsm_context ctx;
    bool result;
    if (__security_secid_to_secctx(tsec->sid, &ctx)) {
        return false;
    }
    result = strncmp(fallback_context, ctx.context, ctx.len) == 0;
    __security_release_secctx(&ctx);
    return result;
}

bool is_task_ksu_domain(const struct cred *cred)
{
    return is_sid_match(cred, cached_su_sid, KERNEL_SU_CONTEXT);
}

bool is_ksu_domain(void)
{
    return is_task_ksu_domain(current_cred());
}

bool is_zygote(const struct cred *cred)
{
    return is_sid_match(cred, cached_zygote_sid, ZYGOTE_CONTEXT);
}

bool is_init(const struct cred *cred)
{
    return is_sid_match(cred, cached_init_sid, INIT_CONTEXT);
}

void escape_to_root_for_adb_root(void)
{
    struct cred *cred = ksu_b_prepare_creds();
    if (!cred) {
        pr_err("Failed to prepare adbd's creds!\n");
        return;
    }

    if (transive_to_domain(KERNEL_SU_CONTEXT, cred, true)) {
        pr_err("transive domain failed.\n");
        ksu_b_abort_creds(cred);
        return;
    }
    ksu_b_commit_creds(cred);
}

