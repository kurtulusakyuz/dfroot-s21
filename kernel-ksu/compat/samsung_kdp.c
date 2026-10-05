#include <linux/completion.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/user.h>
#include <linux/user_namespace.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/refcount.h>
#include <linux/pid.h>

#include "infra/symbol_resolver.h"
#include "ksu_samsung_kdp.h"
#include "klog.h"

#ifdef CONFIG_KSU_SAMSUNG_KDP
enum samsung_kdp_cred_command {
    SAMSUNG_KDP_COPY_CREDS = 0,
};

typedef struct cred *(*prepare_ro_creds_t)(struct cred *cred, int command, u64 task);
typedef void (*kdp_assign_pgd_t)(struct task_struct *task);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
typedef unsigned int (*kdp_usecount_sub_and_test_t)(int nr, struct cred *cred);
#else
typedef unsigned int (*kdp_usecount_dec_and_test_t)(struct cred *cred);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
typedef long (*inc_rlimit_ucounts_t)(struct ucounts *ucounts, enum rlimit_type type, long value);
typedef bool (*dec_rlimit_ucounts_t)(struct ucounts *ucounts, enum rlimit_type type, long value);
#endif

struct samsung_kdp_commit_work {
    struct work_struct work;
    struct completion completion;
    struct task_struct *target;
    const struct cred *old_cred;
    struct cred *rw_cred;
    int result;
    bool async;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#else
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#endif

#define KSU_GRANT_POOL 8
static struct samsung_kdp_commit_work ksu_grant_pool[KSU_GRANT_POOL];
static atomic_t ksu_grant_pool_idx = ATOMIC_INIT(0);
static unsigned long ksu_grant_pool_busy;

static void samsung_kdp_commit_worker(struct work_struct *work)
{
    struct samsung_kdp_commit_work *commit_work = container_of(work, struct samsung_kdp_commit_work, work);
    struct task_struct *target = commit_work->target;
    const struct cred *old_cred = commit_work->old_cred;
    const struct cred *target_cred;
    const struct cred *target_real_cred;
    struct cred *ro_cred;
    bool user_changed;

    /* Async grant path: prepare here (sleepable worker context). kworker
     * runs as root, so the fresh cred is already fully root. */
    pr_info("ksu wk: start pid=%d\n", task_pid_nr(target));
    ksu_mark("/dev/dfWK_START");
    if (!commit_work->rw_cred) {
        commit_work->rw_cred = ksu_b_prepare_creds();
        if (!commit_work->rw_cred) {
            commit_work->result = -ENOMEM;
            goto out;
        }
    }
    pr_info("ksu wk: prepared\n");
    ksu_mark("/dev/dfWK_PREP");

    if (!uid_eq(current_euid(), GLOBAL_ROOT_UID)) {
        commit_work->result = -EPERM;
        goto out;
    }

    /* Already root (e.g. repeated execs in a granted session): skip the
     * commit entirely (avoids redundant KDP traffic + log spam). */
    if (uid_eq(task_uid(target), GLOBAL_ROOT_UID)) {
        commit_work->result = 0;
        goto out;
    }

    target_cred = rcu_access_pointer(target->cred);
    target_real_cred = rcu_access_pointer(target->real_cred);
    /* Async grant (su via exec): exec COPIES creds (new object!) between
     * queue and work, so pointer-equality always fails here. Compare only
     * for the sync API; async forces the grant (target verified at queue
     * time by path+allowlist; worst case grants the task it became). */
    if (!commit_work->async &&
        (target_cred != old_cred || target_real_cred != old_cred)) {
        commit_work->result = -EBUSY;
        goto out;
    }
    pr_info("ksu wk: committing to pid=%d\n", task_pid_nr(target));

    pr_info("ksu wk: calling prepare_ro\n");
    ksu_mark("/dev/dfWK_RO");
    ro_cred = ksu_b_prepare_ro_creds(commit_work->rw_cred, SAMSUNG_KDP_COPY_CREDS, (u64)target);
    pr_info("ksu wk: prepare_ro done\n");
    ksu_mark("/dev/dfWK_RODONE");
    if (!ro_cred) {
        commit_work->result = -EIO;
        goto out;
    }

    user_changed = ro_cred->user != old_cred->user;
    if (user_changed) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
        inc_rlimit_ucounts_fn(ro_cred->ucounts, UCOUNT_RLIMIT_NPROC, 1);
#else
        atomic_inc(&ro_cred->user->processes);
#endif
    }

    rcu_assign_pointer(target->real_cred, ro_cred);
    rcu_assign_pointer(target->cred, ro_cred);
    ksu_b_kdp_assign_pgd(target);

    if (user_changed) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
        dec_rlimit_ucounts_fn(old_cred->ucounts, UCOUNT_RLIMIT_NPROC, 1);
#else
        atomic_dec(&old_cred->user->processes);
#endif
    }

    ksu_b_abort_creds(commit_work->rw_cred);
    commit_work->rw_cred = NULL;
    ksu_put_cred(old_cred);
    ksu_put_cred(old_cred);
    commit_work->result = 0;

    pr_info("Samsung KDP task-scoped credential install pid=%d uid=%u euid=%u\n", task_pid_nr(target),
            __kuid_val(ro_cred->uid), __kuid_val(ro_cred->euid));
out:
    if (!commit_work->async)
        complete(&commit_work->completion);
    else {
        /* async pool release: drop our refs, free the slot (no kfree:
         * pool is static). */
        int idx = (int)(commit_work - ksu_grant_pool);

        __put_task_struct(commit_work->target);
        ksu_samsung_kdp_put_cred(commit_work->old_cred);
        commit_work->async = false;
        smp_wmb();
        clear_bit(idx, &ksu_grant_pool_busy);
    }
}
#endif

void ksu_samsung_kdp_put_cred(const struct cred *cred)
{
#ifdef CONFIG_KSU_SAMSUNG_KDP
    struct cred *mutable_cred = (struct cred *)cred;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    if (mutable_cred && ksu_symtab[KSU_KDP_USECOUNT_DEC_AND_TEST] && ((kdp_usecount_sub_and_test_t)ksu_sym_addr(KSU_KDP_USECOUNT_DEC_AND_TEST))(1, mutable_cred))
#else
    if (mutable_cred && ksu_symtab[KSU_KDP_USECOUNT_DEC_AND_TEST] && ((kdp_usecount_dec_and_test_t)ksu_sym_addr(KSU_KDP_USECOUNT_DEC_AND_TEST))(mutable_cred))
#endif
        __put_cred(mutable_cred);
#else
    put_cred(cred);
#endif
}

/* Fire-and-forget root grant for tracepoint-atomic context: only
 * non-sleeping ops here (kmalloc ATOMIC, ref bumps, schedule). Worker
 * (sleepable) prepares + KDP-commits to the target. */
/* Pre-allocated grant pool (GFP_ATOMIC fails routinely under the
 * reclaim storms on this device; a failed kmalloc silently drops the
 * grant with no log. Pool filled once at init (sleepable). */

int ksu_kdp_grant_root_async(void)
{
    struct samsung_kdp_commit_work *w;
    int i;

    w = NULL;
    for (i = 0; i < KSU_GRANT_POOL; i++) {
        int j = atomic_inc_return(&ksu_grant_pool_idx) % KSU_GRANT_POOL;

        if (!test_and_set_bit(j, &ksu_grant_pool_busy)) {
            w = &ksu_grant_pool[j];
            break;
        }
    }
    if (!w) {
        pr_info("ksu grant: pool exhausted\n");
        return -EBUSY;
    }
    w->async = true;
    w->target = current;
    refcount_inc(&current->usage);
    w->old_cred = current_real_cred();
    atomic_inc((atomic_t *)&w->old_cred->usage);
    w->rw_cred = NULL;
    w->result = -EIO;
    w->async = true;
    INIT_WORK(&w->work, samsung_kdp_commit_worker);
    schedule_work(&w->work);
    return 0;
}

int ksu_samsung_kdp_init(void)
{
#ifdef CONFIG_KSU_SAMSUNG_KDP
    ksu_symtab[KSU_PREPARE_RO_CREDS] = (unsigned long)ksu_resolve_symbol_for_functable_hook("prepare_ro_creds");
    ksu_symtab[KSU_KDP_ASSIGN_PGD] = (unsigned long)ksu_resolve_symbol_for_functable_hook("kdp_assign_pgd");
    pr_info("ksu kdp: prepare_ro_creds=%px kdp_assign_pgd=%px\n",
	    (void *)ksu_symtab[KSU_PREPARE_RO_CREDS],
	    (void *)ksu_symtab[KSU_KDP_ASSIGN_PGD]);
    if (!ksu_symtab[KSU_PREPARE_RO_CREDS] || !ksu_symtab[KSU_KDP_ASSIGN_PGD]) {
        pr_err("Samsung KDP credential functions unavailable\n");
        return -ENOENT;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    kdp_usecount_sub_and_test_fn = (kdp_usecount_sub_and_test_t)ksu_resolve_symbol_for_functable_hook(
        "kdp_usecount_sub_and_test");
    if (!kdp_usecount_sub_and_test_fn) {
        pr_err("Samsung KDP credential functions unavailable\n");
        return -ENOENT;
    }
#else
    ksu_symtab[KSU_KDP_USECOUNT_DEC_AND_TEST] =
	    (unsigned long)ksu_resolve_symbol_for_functable_hook("kdp_usecount_dec_and_test");
    if (!ksu_symtab[KSU_KDP_USECOUNT_DEC_AND_TEST])
        pr_warn("ksu kdp: kdp_usecount_dec_and_test missing (o1s has no KDP ucounts)\n");
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    ksu_symtab[KSU_INC_RLIMIT_UCOUNTS] =
	    (unsigned long)ksu_resolve_symbol_for_functable_hook("inc_rlimit_ucounts");
    ksu_symtab[KSU_DEC_RLIMIT_UCOUNTS] =
	    (unsigned long)ksu_resolve_symbol_for_functable_hook("dec_rlimit_ucounts");
    if (!ksu_symtab[KSU_INC_RLIMIT_UCOUNTS] || !ksu_symtab[KSU_DEC_RLIMIT_UCOUNTS])
        pr_warn("ksu kdp: rlimit ucounts missing (unused below 5.11)\n");
#endif

    pr_info("Samsung KDP task-scoped credential and native PGD path enabled\n");
#endif
    return 0;
}

void ksu_samsung_kdp_exit(void)
{
}

int ksu_samsung_kdp_commit_creds(struct cred *cred)
{
#ifdef CONFIG_KSU_SAMSUNG_KDP
    struct samsung_kdp_commit_work commit_work;
    bool queued;

    if (!cred)
        return -EINVAL;

    INIT_WORK(&commit_work.work, samsung_kdp_commit_worker);
    init_completion(&commit_work.completion);
    commit_work.target = current;
    commit_work.old_cred = current_real_cred();
    commit_work.rw_cred = cred;
    commit_work.result = -EIO;

    get_task_struct(commit_work.target);
    queued = schedule_work(&commit_work.work);
    if (!queued) {
        put_task_struct(commit_work.target);
        return -EBUSY;
    }

    wait_for_completion(&commit_work.completion);
    put_task_struct(commit_work.target);
    return commit_work.result;
#else
    return commit_creds(cred);
#endif
}
