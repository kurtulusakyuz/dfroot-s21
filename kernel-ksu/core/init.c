#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/moduleparam.h>

#include "policy/allowlist.h"
#include "feature/kernel_umount.h"
#include "ksu_samsung_kdp.h"
#include "policy/app_profile.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"
#include "hook/syscall_hook_manager.h"
#include "hook/lsm_hook.h"
#include "runtime/ksud.h"
#include "runtime/ksud_boot.h"
#include "feature/sulog.h"
#include "supercall/supercall.h"
#include "ksu.h"
#include "infra/file_wrapper.h"
#include "selinux/selinux.h"
#include "hook/syscall_hook.h"
#include "feature/adb_root.h"
#include "feature/selinux_hide.h"
#include "infra/symbol_resolver.h"
#include "compat/samsung_defex.h"
#include "compat/mount_ns_54.h"
#include "feature/sucompat.h"

#ifdef CONFIG_KSU_S21_54
/* Module-local SELinux "ss" caches (see compat/ss/, compat/s21_54.h). */
extern void ksu_s21_hashtab_cache_init(void);
extern void ksu_s21_ebitmap_cache_init(void);
extern void ksu_s21_avtab_cache_init(void);
#endif

#if defined(__x86_64__)
#include <asm/cpufeature.h>
#include <linux/version.h>
#ifndef X86_FEATURE_INDIRECT_SAFE
#error "FATAL: Your kernel is missing the indirect syscall bypass patches!"
#endif
#endif

// workaround for A12-5.10 kernel
// Some third-party kernel (e.g. linegaeOS) uses wrong toolchain, which supports
// CC_HAVE_STACKPROTECTOR_SYSREG while gki's toolchain doesn't.
// Therefore, ksu lkm, which uses gki toolchain, requires this __stack_chk_guard,
// while those third-party kernel can't provide.
// Thus, we manually provide it instead of using kernel's
#if defined(CONFIG_STACKPROTECTOR) &&                                                                                  \
    (defined(CONFIG_ARM64) && defined(MODULE) && !defined(CONFIG_STACKPROTECTOR_PER_TASK))
#include <linux/stackprotector.h>
#include <linux/random.h>
unsigned long __stack_chk_guard __ro_after_init __attribute__((visibility("hidden")));

__attribute__((no_stack_protector)) void __init ksu_setup_stack_chk_guard()
{
    unsigned long canary;

    /* Try to get a semi random initial value. */
    get_random_bytes(&canary, sizeof(canary));
    canary ^= LINUX_VERSION_CODE;
    canary &= CANARY_MASK;
    __stack_chk_guard = canary;
}

__attribute__((naked)) int __init kernelsu_init_early(void)
{
    asm("mov x19, x30;\n"
        "bl ksu_setup_stack_chk_guard;\n"
        "mov x30, x19;\n"
        "b kernelsu_init;\n");
}
#define NEED_OWN_STACKPROTECTOR 1
#else
#define NEED_OWN_STACKPROTECTOR 0
#endif

struct cred *ksu_cred;
bool ksu_late_loaded;

#ifdef CONFIG_KSU_DEBUG
bool allow_shell = true;
#else
bool allow_shell = false;
#endif
module_param(allow_shell, bool, 0);

bool ksu_no_custom_rc = false;
module_param_named(norc, ksu_no_custom_rc, bool, 0);

/* RKP bisect: skip ALL kprobe/kretprobe text-patching when set.
 * insmod kko.ko nokprobe=1 — tracepoint/dispatcher hooks stay. */
bool ksu_no_kprobe = false;
module_param_named(nokprobe, ksu_no_kprobe, bool, 0);

/* Policy-bisect: skip live policy publish (snapshot/rules compute only).
 * insmod kko.ko nopolicy=1 — tests whether our published policy wedges AVC. */
bool ksu_no_policy = false;
module_param_named(nopolicy, ksu_no_policy, bool, 0);

int __init kernelsu_init(void)
{
    int ret;

#if defined(__x86_64__)
    // If the kernel has the hardening patch, X86_FEATURE_INDIRECT_SAFE must be set
    if (!boot_cpu_has(X86_FEATURE_INDIRECT_SAFE)) {
        pr_alert("*************************************************************");
        pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
        pr_alert("**                                                         **");
        pr_alert("**        X86_FEATURE_INDIRECT_SAFE is not enabled!        **");
        pr_alert("**      KernelSU will abort initialization to prevent      **");
        pr_alert("**                     kernel panic.                       **");
        pr_alert("**                                                         **");
        pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
        pr_alert("*************************************************************");
        return -ENOSYS;
    }
#endif

#ifdef MODULE
    ksu_late_loaded = (current->pid != 1);
#else
    ksu_late_loaded = false;
#endif

#ifdef CONFIG_KSU_DEBUG
    pr_alert("*************************************************************");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("**                                                         **");
    pr_alert("**         You are running KernelSU in DEBUG mode          **");
    pr_alert("**                                                         **");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("*************************************************************");
#endif
    if (allow_shell) {
        pr_alert("shell is allowed at init!");
    }

#ifdef CONFIG_KSU_SAMSUNG_KDP
    pr_info("Samsung KDP credential reference handling enabled\n");
#endif

    if (ksu_init_symbol_resolver())
        return -ENODEV;
    ksu_sync_blob_sizes();
    pr_info("ksu phase: resolver+blob done\n");
    ret = ksu_samsung_kdp_init();
    if (ret)
        return ret;

#ifdef CONFIG_KSU_S21_54
    ksu_s21_hashtab_cache_init();
    ksu_s21_ebitmap_cache_init();
    ksu_s21_avtab_cache_init();
    ksu_mount_ns_54_init();
    pr_info("ksu phase: s21 caches+mountns done\n");
#endif

    pr_info("ksu phase: calling prepare_creds\n");
    ksu_cred = ksu_b_prepare_creds();
    pr_info("ksu phase: prepare_creds done\n");
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
        ksu_samsung_kdp_exit();
        return -ENOSYS;
    }

    ret = ksu_samsung_defex_init();
    if (ret) {
        ksu_put_cred(ksu_cred);
        ksu_samsung_kdp_exit();
        return ret;
    }

#ifdef CONFIG_KSU_S21_54
    /* Fail before registering callbacks if the stock policy cannot be read
     * or updated. No partially initialized module may survive this error.
     */
    if (ksu_late_loaded) {
        ret = apply_kernelsu_rules();
        if (ret) {
            ksu_samsung_defex_exit();
            ksu_put_cred(ksu_cred);
            ksu_cred = NULL;
            ksu_samsung_kdp_exit();
            return ret;
        }
    }
#endif

    pr_info("ksu phase: defex+rules done\n");
    ksu_syscall_hook_init();
    pr_info("ksu phase: syscall hooks done\n");

    ksu_feature_init();
    ksu_sulog_init();
    ksu_adb_root_init();
    ksu_lsm_hook_init();
    ksu_su_bprm_init();
    ksu_selinux_hide_init();

    ksu_supercalls_init();
    pr_info("ksu phase: init complete\n");
    ksu_mark("/dev/dfINIT");

    if (ksu_late_loaded) {
        pr_info("late load mode, skipping kprobe hooks\n");

#ifndef CONFIG_KSU_S21_54
        apply_kernelsu_rules();
#endif
        /* HZC2: cache_sid() NULL-derefs in core string resolution against
         * the freshly-published policy (RCNT 164) — sidtab content issue,
         * not calling convention (bridge verified). All is_sid_match users
         * have string fallbacks; file labeling degrades (sid 0) until the
         * policy parser is fixed. Skip for now: basic su first. */
        // cache_sid();
        setup_ksu_cred();

        // Grant current process (ksud late-load) root
        // with KSU SELinux domain before enforcing SELinux, so it
        // can continue to access /data/app etc. after enforcement.
        escape_to_root_for_init();

        ksu_allowlist_init();
        ksu_load_allow_list();
        ksu_umount_scan_modules();

        ksu_syscall_hook_manager_init();

        ksu_throne_tracker_init();
        ksu_observer_init();
        ksu_file_wrapper_init();

        ksu_boot_completed = true;
        track_throne(false);

        if (!getenforce()) {
            pr_info("Permissive SELinux, enforcing\n");
            setenforce(true);
        }

    } else {
        ksu_syscall_hook_manager_init();

        ksu_allowlist_init();

        ksu_throne_tracker_init();

        ksu_ksud_init();

        ksu_file_wrapper_init();
    }

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
    kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif
    return 0;
}

void __exit kernelsu_exit(void)
{
    // Phase 1: Stop all hooks first to prevent new callbacks
    ksu_syscall_hook_manager_exit();

    ksu_supercalls_exit();

    if (!ksu_late_loaded)
        ksu_ksud_exit();

    // Wait for any in-flight RCU readers (e.g. handler traversing allow_list)
    synchronize_rcu();

    // Phase 2: Now safe to release data structures
    ksu_observer_exit();

    ksu_throne_tracker_exit();

    ksu_allowlist_exit();

    ksu_selinux_hide_exit();
    ksu_lsm_hook_exit();
    ksu_adb_root_exit();
    ksu_sulog_exit();
    ksu_feature_exit();

    ksu_samsung_defex_exit();
    ksu_put_cred(ksu_cred);
    ksu_samsung_kdp_exit();
}

#if NEED_OWN_STACKPROTECTOR
module_init(kernelsu_init_early);
#else
module_init(kernelsu_init);
#endif
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
