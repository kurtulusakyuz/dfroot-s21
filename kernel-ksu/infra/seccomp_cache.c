#include <linux/version.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/printk.h>
#include "klog.h" // IWYU pragma: keep
#include "infra/seccomp_cache.h"

#ifdef CONFIG_KSU_S21_54
/*
 * S21 (5.4.242) has no seccomp action cache: SECCOMP_ARCH_NATIVE_NR and
 * struct seccomp_filter.cache do not exist, and every filter is evaluated by
 * running its BPF program (seccomp_run_filters -> BPF_PROG_RUN).
 *
 * The only callers (hook/setuid_hook.c) use ksu_seccomp_allow_cache() to let
 * the manager / allow-listed process issue __NR_reboot despite its app seccomp
 * filter. Reproducing that behavior on 5.4 requires a hot-path .text hook on
 * seccomp_run_filters (every syscall) plus a per-task flag; on this RKP/CFI
 * protected Samsung kernel that is the same risk class as the S23 RKP crash
 * documented in the RootMyGalaxy postmortem.
 *
 * In the RootMyGalaxy flow a reboot drops root anyway (payload is not
 * persistent), so the manager-reboot feature is not used. We therefore keep
 * these as explicit, documented no-ops rather than silently stubbing them or
 * taking the hot-path patch risk. Revisit if a real need for manager reboot
 * appears. See DERLEME_DURUMU.md.
 */
void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
    (void)filter;
    (void)nr;
    pr_warn_once("ksu_seccomp_clear_cache: no seccomp action_cache on 5.4; no-op\n");
}

void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
    (void)filter;
    (void)nr;
    pr_warn_once("ksu_seccomp_allow_cache: no seccomp action_cache on 5.4; manager reboot is not permitted\n");
}
#else
struct action_cache {
    DECLARE_BITMAP(allow_native, SECCOMP_ARCH_NATIVE_NR);
#ifdef SECCOMP_ARCH_COMPAT
    DECLARE_BITMAP(allow_compat, SECCOMP_ARCH_COMPAT_NR);
#endif
};

struct seccomp_filter {
    refcount_t refs;
    refcount_t users;
    bool log;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    bool wait_killable_recv;
#endif
    struct action_cache cache;
    struct seccomp_filter *prev;
    struct bpf_prog *prog;
    struct notification *notif;
    struct mutex notify_lock;
    wait_queue_head_t wqh;
};

void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
    if (!filter) {
        return;
    }

    if (nr >= 0 && nr < SECCOMP_ARCH_NATIVE_NR) {
        clear_bit(nr, filter->cache.allow_native);
    }

#ifdef SECCOMP_ARCH_COMPAT
    if (nr >= 0 && nr < SECCOMP_ARCH_COMPAT_NR) {
        clear_bit(nr, filter->cache.allow_compat);
    }
#endif
}

void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
    if (!filter) {
        return;
    }

    if (nr >= 0 && nr < SECCOMP_ARCH_NATIVE_NR) {
        set_bit(nr, filter->cache.allow_native);
    }

#ifdef SECCOMP_ARCH_COMPAT
    if (nr >= 0 && nr < SECCOMP_ARCH_COMPAT_NR) {
        set_bit(nr, filter->cache.allow_compat);
    }
#endif
}
#endif
