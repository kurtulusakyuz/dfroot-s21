#include "linux/printk.h"
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/tracepoint.h>
#include <asm/syscall.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <trace/events/syscalls.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
#include <linux/compat.h>
#include <linux/sched/task_stack.h>
#endif

#include "arch.h"
#include "infra/symbol_resolver.h"
#include "klog.h" // IWYU pragma: keep
#include "hook/syscall_hook_manager.h"
#include "hook/tp_marker.h"
#include "feature/sucompat.h"
#include "hook/setuid_hook.h"
#include "hook/syscall_hook.h"
#include "hook/syscall_event_bridge.h"
#include "policy/allowlist.h"
#include "feature/kernel_umount.h"
#include "feature/adb_root.h"
#include "feature/sucompat.h"
#include "manager/manager_identity.h"
#include <linux/cred.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include "supercall/supercall.h"
#include "include/uapi/supercall.h"
extern bool ksu_no_kprobe;

static bool syscall_hook_manager_initialized;

#if defined(CONFIG_KSU_SAMSUNG_RKP) && defined(CONFIG_KRETPROBES) && defined(__aarch64__)
struct ksu_setresuid_task_work {
    struct callback_head callback;
    uid_t old_uid;
    uid_t new_uid;
};

static bool setresuid_kretprobe_registered;
static bool samsung_sucompat_kprobes_registered;

#define SAMSUNG_SUCOMPAT_BYPASS_NR (-2)

static bool samsung_sucompat_should_redirect(int syscall_nr)
{
    struct pt_regs *syscall_regs = task_pt_regs(current);

    if (unlikely(syscall_regs->syscallno == SAMSUNG_SUCOMPAT_BYPASS_NR)) {
        syscall_regs->syscallno = syscall_nr;
        return false;
    }

    return ksu_su_compat_enabled &&
           ksu_is_allow_uid_for_current(current_uid().val);
}

static long __nocfi samsung_sucompat_execve(const struct pt_regs *regs)
{
    struct pt_regs *syscall_regs = (struct pt_regs *)regs;
    int syscall_nr = syscall_regs->syscallno;
    long ret;

    syscall_regs->syscallno = SAMSUNG_SUCOMPAT_BYPASS_NR;
    ret = ksu_hook_execve(__NR_execve, regs);
    syscall_regs->syscallno = syscall_nr;
    return ret;
}

static long __nocfi samsung_sucompat_newfstatat(const struct pt_regs *regs)
{
    struct pt_regs *syscall_regs = (struct pt_regs *)regs;
    int syscall_nr = syscall_regs->syscallno;
    long ret;

    syscall_regs->syscallno = SAMSUNG_SUCOMPAT_BYPASS_NR;
    ret = ksu_hook_newfstatat(__NR_newfstatat, regs);
    syscall_regs->syscallno = syscall_nr;
    return ret;
}

static long __nocfi samsung_sucompat_faccessat(const struct pt_regs *regs)
{
    struct pt_regs *syscall_regs = (struct pt_regs *)regs;
    int syscall_nr = syscall_regs->syscallno;
    long ret;

    syscall_regs->syscallno = SAMSUNG_SUCOMPAT_BYPASS_NR;
    ret = ksu_hook_faccessat(__NR_faccessat, regs);
    syscall_regs->syscallno = syscall_nr;
    return ret;
}

static long __nocfi samsung_sucompat_statx(const struct pt_regs *regs)
{
    struct pt_regs *syscall_regs = (struct pt_regs *)regs;
    int syscall_nr = syscall_regs->syscallno;
    long ret;

    syscall_regs->syscallno = SAMSUNG_SUCOMPAT_BYPASS_NR;
    ret = ksu_hook_newfstatat(__NR_statx, regs);
    syscall_regs->syscallno = syscall_nr;
    return ret;
}

#ifdef __NR_faccessat2
static long __nocfi samsung_sucompat_faccessat2(const struct pt_regs *regs)
{
    struct pt_regs *syscall_regs = (struct pt_regs *)regs;
    int syscall_nr = syscall_regs->syscallno;
    long ret;

    syscall_regs->syscallno = SAMSUNG_SUCOMPAT_BYPASS_NR;
    ret = ksu_hook_faccessat(__NR_faccessat2, regs);
    syscall_regs->syscallno = syscall_nr;
    return ret;
}
#endif

static int samsung_sucompat_execve_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    if (!samsung_sucompat_should_redirect(__NR_execve))
        return 0;

    instruction_pointer_set(regs, (unsigned long)samsung_sucompat_execve);
    return 1;
}

static int samsung_sucompat_newfstatat_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    if (!samsung_sucompat_should_redirect(__NR_newfstatat))
        return 0;

    instruction_pointer_set(regs, (unsigned long)samsung_sucompat_newfstatat);
    return 1;
}

static int samsung_sucompat_faccessat_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    if (!samsung_sucompat_should_redirect(__NR_faccessat))
        return 0;

    instruction_pointer_set(regs, (unsigned long)samsung_sucompat_faccessat);
    return 1;
}

static int samsung_sucompat_statx_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    if (!samsung_sucompat_should_redirect(__NR_statx))
        return 0;

    instruction_pointer_set(regs, (unsigned long)samsung_sucompat_statx);
    return 1;
}

#ifdef __NR_faccessat2
static int samsung_sucompat_faccessat2_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    if (!samsung_sucompat_should_redirect(__NR_faccessat2))
        return 0;

    instruction_pointer_set(regs, (unsigned long)samsung_sucompat_faccessat2);
    return 1;
}
#endif

static struct kprobe samsung_sucompat_execve_kprobe = {
    .pre_handler = samsung_sucompat_execve_pre_handler,
};

static struct kprobe samsung_sucompat_newfstatat_kprobe = {
    .pre_handler = samsung_sucompat_newfstatat_pre_handler,
};

static struct kprobe samsung_sucompat_faccessat_kprobe = {
    .pre_handler = samsung_sucompat_faccessat_pre_handler,
};

static struct kprobe samsung_sucompat_statx_kprobe = {
    .pre_handler = samsung_sucompat_statx_pre_handler,
};

#ifdef __NR_faccessat2
static struct kprobe samsung_sucompat_faccessat2_kprobe = {
    .pre_handler = samsung_sucompat_faccessat2_pre_handler,
};
#endif

static int samsung_sucompat_hook_init(void)
{
    int ret;

    if (ksu_no_kprobe) {
        pr_info("hook_manager: sucompat kprobes skipped (nokprobe)\n");
        return 0;
    }
    if (!ksu_syscall_table)
        return -ENOENT;

    samsung_sucompat_execve_kprobe.addr =
        (kprobe_opcode_t *)READ_ONCE(ksu_syscall_table[__NR_execve]);
    samsung_sucompat_newfstatat_kprobe.addr =
        (kprobe_opcode_t *)READ_ONCE(ksu_syscall_table[__NR_newfstatat]);
    samsung_sucompat_faccessat_kprobe.addr =
        (kprobe_opcode_t *)READ_ONCE(ksu_syscall_table[__NR_faccessat]);
    samsung_sucompat_statx_kprobe.addr =
        (kprobe_opcode_t *)READ_ONCE(ksu_syscall_table[__NR_statx]);
#ifdef __NR_faccessat2
    samsung_sucompat_faccessat2_kprobe.addr =
        (kprobe_opcode_t *)READ_ONCE(ksu_syscall_table[__NR_faccessat2]);
#endif

    ksu_sucompat_init();

    ret = ksu_b_register_kprobe(&samsung_sucompat_execve_kprobe);
    if (ret)
        goto exit_sucompat;

    ret = ksu_b_register_kprobe(&samsung_sucompat_newfstatat_kprobe);
    if (ret)
        goto unregister_execve;

    ret = ksu_b_register_kprobe(&samsung_sucompat_faccessat_kprobe);
    if (ret)
        goto unregister_newfstatat;

    ret = ksu_b_register_kprobe(&samsung_sucompat_statx_kprobe);
    if (ret)
        goto unregister_faccessat;

#ifdef __NR_faccessat2
    ret = ksu_b_register_kprobe(&samsung_sucompat_faccessat2_kprobe);
    if (ret)
        goto unregister_statx;
#endif

    samsung_sucompat_kprobes_registered = true;
    pr_info("hook_manager: Samsung sucompat kprobes registered\n");
    return 0;

#ifdef __NR_faccessat2
unregister_statx:
    ksu_b_unregister_kprobe(&samsung_sucompat_statx_kprobe);
#endif
unregister_faccessat:
    ksu_b_unregister_kprobe(&samsung_sucompat_faccessat_kprobe);
unregister_newfstatat:
    ksu_b_unregister_kprobe(&samsung_sucompat_newfstatat_kprobe);
unregister_execve:
    ksu_b_unregister_kprobe(&samsung_sucompat_execve_kprobe);
exit_sucompat:
    ksu_sucompat_exit();
    return ret;
}

static void samsung_sucompat_hook_exit(void)
{
    if (!samsung_sucompat_kprobes_registered)
        return;

#ifdef __NR_faccessat2
    ksu_b_unregister_kprobe(&samsung_sucompat_faccessat2_kprobe);
#endif
    ksu_b_unregister_kprobe(&samsung_sucompat_statx_kprobe);
    ksu_b_unregister_kprobe(&samsung_sucompat_faccessat_kprobe);
    ksu_b_unregister_kprobe(&samsung_sucompat_newfstatat_kprobe);
    ksu_b_unregister_kprobe(&samsung_sucompat_execve_kprobe);
    samsung_sucompat_kprobes_registered = false;
    ksu_sucompat_exit();
}

static void setresuid_task_work_func(struct callback_head *callback)
{
    struct ksu_setresuid_task_work *work = container_of(callback, struct ksu_setresuid_task_work, callback);

    ksu_handle_setresuid(work->old_uid, work->new_uid);
    kfree(work);
}

static int setresuid_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    *(uid_t *)ri->data = current_uid().val;
    return 0;
}

static int setresuid_return_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ksu_setresuid_task_work *work;
    uid_t old_uid = *(uid_t *)ri->data;
    uid_t new_uid;

    if (regs_return_value(regs) < 0)
        return 0;

    new_uid = current_uid().val;
    if (old_uid == new_uid)
        return 0;

    work = kzalloc(sizeof(*work), GFP_ATOMIC);
    if (!work)
        return 0;

    work->old_uid = old_uid;
    work->new_uid = new_uid;
    work->callback.func = setresuid_task_work_func;

    if (ksu_b_task_work_add(current, &work->callback, true))
        kfree(work);

    return 0;
}

static struct kretprobe setresuid_kretprobe = {
    .kp.symbol_name = "__arm64_sys_setresuid",
    .entry_handler = setresuid_entry_handler,
    .handler = setresuid_return_handler,
    .data_size = sizeof(uid_t),
};

static int samsung_setresuid_hook_init(void)
{
    int ret;

    if (ksu_no_kprobe) {
        pr_info("hook_manager: setresuid kretprobe skipped (nokprobe)\n");
        return 0;
    }
    ret = ksu_b_register_kretprobe(&setresuid_kretprobe);

    if (ret) {
        pr_err("hook_manager: Samsung setresuid kretprobe failed: %d\n", ret);
        return ret;
    }

    setresuid_kretprobe_registered = true;
    ksu_setuid_hook_init();
    pr_info("hook_manager: Samsung setresuid kretprobe registered\n");
    return 0;
}

static void samsung_setresuid_hook_exit(void)
{
    if (!setresuid_kretprobe_registered)
        return;

    ksu_b_unregister_kretprobe(&setresuid_kretprobe);
    setresuid_kretprobe_registered = false;
    ksu_setuid_hook_exit();
}
#endif

#ifdef CONFIG_KRETPROBES

static struct kretprobe *init_kretprobe(const char *name, kretprobe_handler_t handler)
{
    struct kretprobe *rp = kzalloc(sizeof(struct kretprobe), GFP_KERNEL);
    if (!rp)
        return NULL;
    rp->kp.symbol_name = name;
    rp->handler = handler;
    rp->data_size = 0;
    rp->maxactive = 0;

    int ret = ksu_b_register_kretprobe(rp);
    pr_info("hook_manager: register_%s kretprobe: %d\n", name, ret);
    if (ret) {
        kfree(rp);
        return NULL;
    }

    return rp;
}

static void destroy_kretprobe(struct kretprobe **rp_ptr)
{
    struct kretprobe *rp = *rp_ptr;
    if (!rp)
        return;
    ksu_b_unregister_kretprobe(rp);
    synchronize_rcu();
    kfree(rp);
    *rp_ptr = NULL;
}

static int syscall_regfunc_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long flags;
    ksu_tp_marker_lock(&flags);
    if (ksu_tp_marker_reg_count() < 1) {
        // while install our tracepoint, mark our processes
        ksu_mark_running_process_locked();
    } else if (ksu_tp_marker_reg_count() == 1) {
        // while other tracepoint first added, mark all processes
        ksu_mark_all_process();
    }
    ksu_tp_marker_inc_reg_count();
    ksu_tp_marker_unlock(&flags);
    return 0;
}

static int syscall_unregfunc_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long flags;
    ksu_tp_marker_lock(&flags);
    ksu_tp_marker_dec_reg_count();
    if (ksu_tp_marker_reg_count() <= 0) {
        // while no tracepoint left, unmark all processes
        ksu_unmark_all_process();
    } else if (ksu_tp_marker_reg_count() == 1) {
        // while just our tracepoint left, unmark disallowed processes
        ksu_mark_running_process_locked();
    }
    ksu_tp_marker_unlock(&flags);
    return 0;
}

static struct kretprobe *syscall_regfunc_rp = NULL;
static struct kretprobe *syscall_unregfunc_rp = NULL;
#endif

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
// sys_enter handler: redirect hooked syscalls to the dispatcher
static void ksu_sys_enter_handler(void *data, struct pt_regs *regs, long id)
{
#if defined(__x86_64__)
    if (unlikely(in_compat_syscall()))
#elif defined(__aarch64__)
    if (unlikely(is_compat_task()))
#endif
        return;

    /* RKP-safe direct su grant (dispatcher needs table writes that die
     * on RKP; this path needs none). Persistent override carries into the
     * pending exec. */
    if (id == __NR_execve || id == __NR_execveat)
        ksu_su_grant_on_exec(regs, id);

    /* Manager driver-FD install (replaces reboot_kprobe, RKP-fatal):
     * reboot(DEADBEEF, CAFEBABE, cmd, &out_fd) -> task_work installs FD. */
    if (id == __NR_reboot &&
        (u32)PT_REGS_PARM1(regs) == KSU_INSTALL_MAGIC1 &&
        (u32)PT_REGS_PARM2(regs) == KSU_INSTALL_MAGIC2) {
        ksu_supercall_install_fd_async((int __user *)PT_REGS_SYSCALL_PARM4(regs));
    }

    /* Manager driver-FD into the MANAGER PROCESS ITSELF, on its own
     * syscalls. (The exec hook installs into fork+exec children whose
     * fd dies with them.) Atomic-safe: presence check uses only
     * file_lock; install is queued task_work. Runs at syscall entry,
     * before the body takes any lock. */
    if (is_uid_manager(current_uid().val) && !ksu_current_has_driver_fd())
        ksu_supercall_install_mgr_fd_async();

    /* Umount tetigi (kprobe olu: nokprobe): setuid ailesinde app UID'ine
     * gecislerde task_work kuyrukla. Sadece app/isolated hedeflerde
     * (zygote uzmanlasma); modul yoksa handler ilk satirda doner.
     * setresuid/setreuid'de UC parametre de taranir: zygote (-1, uid,
     * uid) cagirabilir, PARM1 tek basina yetmez. */
    if (id == __NR_setresuid || id == __NR_setuid || id == __NR_setreuid) {
        uid_t ids[3];
        int nids = 1;
        ids[0] = (uid_t)PT_REGS_PARM1(regs);
        if (id != __NR_setuid) {
            ids[1] = (uid_t)PT_REGS_PARM2(regs);
            ids[2] = (uid_t)PT_REGS_PARM3(regs);
            nids = 3;
        }
        for (int i = 0; i < nids; i++) {
            if (is_appuid(ids[i]) || is_isolated_process(ids[i]))
                ksu_umount_async(current_uid().val, ids[i]);
        }

        /* ADB Root re-grant: adbd (root) shell dogururken shell'e duser;
         * ebeveyn adbd ise geri yukselt (bayrak acikken). LD_PRELOAD
         * lib'i APEX linker izolasyonunda etkisiz, bu kancadir. */
        if (ksu_adb_root_enabled() && current_uid().val == 0 &&
            (ids[0] == 2000 || (nids == 3 && (ids[1] == 2000 || ids[2] == 2000)))) {
            struct task_struct *par;
            bool is_adbd = false;

            rcu_read_lock();
            par = rcu_dereference(current->real_parent);
            if (par && !strcmp(par->comm, "adbd"))
                is_adbd = true;
            rcu_read_unlock();
            if (is_adbd) {
                pr_info("ksu adb re-grant: pid %d\n", current->pid);
                ksu_su_grant_current_async();
            }
        }
    }

    /* ADB Root exec kancasi (dispatcher olu: nokprobe + RO tablo).
     * Atomik varyant: LD_PRELOAD kurulumu nofault, escape task_work'te.
     * Bayrak kapaliysa tek static-key kontrolu (sifir maliyet). */
    if ((id == __NR_execve || id == __NR_execveat) &&
        ksu_adb_root_enabled())
        ksu_adb_root_handle_execve_atomic(regs, id);

    if (ksu_dispatcher_nr < 0)
        return;

    if (ksu_has_syscall_hook(id)) {
        struct pt_regs *current_regs = task_pt_regs(current);

#if defined(__x86_64__)
        // Stash the original syscall number in ax.
        // We use ax because it currently just holds -ENOSYS and is safe to overwrite.
        current_regs->ax = id;
        current_regs->orig_ax = ksu_dispatcher_nr;
#elif defined(__aarch64__)
        PT_REGS_ORIG_SYSCALL(current_regs) = id;
        current_regs->syscallno = ksu_dispatcher_nr;
#endif
    }
}
#endif

void __init ksu_syscall_hook_manager_init(void)
{
    int ret;
    pr_info("hook_manager: ksu_hook_manager_init called\n");

    /* Tracepoint first: the RKP-safe direct su path lives here and must run
     * even when the dispatcher (table writes) is unavailable. */
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    ret = tracepoint_probe_register(KSU_DATA(KSU_TRACEPOINT_SYS_ENTER, __tracepoint_sys_enter), ksu_sys_enter_handler, NULL);
#ifndef CONFIG_KRETPROBES
    ksu_mark_running_process_locked();
#endif
    if (ret) {
        pr_err("hook_manager: failed to register sys_enter tracepoint: %d\n", ret);
    } else {
        pr_info("hook_manager: sys_enter tracepoint registered\n");
    }
    ksu_mark("/dev/dfTP");
    if (!ret)
        ksu_mark("/dev/dfTP_OK");
#endif

    if (ksu_dispatcher_nr < 0) {
        pr_warn("hook_manager: dispatcher unavailable; syscall event hooks disabled\n");
#if defined(CONFIG_KSU_SAMSUNG_RKP) && defined(CONFIG_KRETPROBES) && defined(__aarch64__)
        samsung_setresuid_hook_init();
        ret = samsung_sucompat_hook_init();
        if (ret)
            pr_err("hook_manager: Samsung sucompat hook init failed: %d\n", ret);
#endif
        return;
    }

    syscall_hook_manager_initialized = true;

#ifdef CONFIG_KRETPROBES
    if (ksu_no_kprobe) {
        pr_info("hook_manager: regfunc kretprobes skipped (nokprobe)\n");
    } else {
        syscall_regfunc_rp = init_kretprobe("syscall_regfunc", syscall_regfunc_handler);
        syscall_unregfunc_rp = init_kretprobe("syscall_unregfunc", syscall_unregfunc_handler);
    }
#endif

    // Register syscall hooks via dispatcher
    ksu_register_syscall_hook(__NR_setresuid, ksu_hook_setresuid);
    ksu_register_syscall_hook(__NR_execve, ksu_hook_execve);
    ksu_register_syscall_hook(__NR_newfstatat, ksu_hook_newfstatat);
    ksu_register_syscall_hook(__NR_faccessat, ksu_hook_faccessat);

    ksu_setuid_hook_init();
    ksu_sucompat_init();
}

void __exit ksu_syscall_hook_manager_exit(void)
{
    pr_info("hook_manager: ksu_hook_manager_exit called\n");

    if (!syscall_hook_manager_initialized) {
#if defined(CONFIG_KSU_SAMSUNG_RKP) && defined(CONFIG_KRETPROBES) && defined(__aarch64__)
        samsung_sucompat_hook_exit();
        samsung_setresuid_hook_exit();
#endif
        ksu_syscall_hook_exit();
        return;
    }
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    tracepoint_probe_unregister(KSU_DATA(KSU_TRACEPOINT_SYS_ENTER, __tracepoint_sys_enter), ksu_sys_enter_handler, NULL);
    synchronize_srcu(KSU_DATA(KSU_TRACEPOINT_SRCU, tracepoint_srcu));
    pr_info("hook_manager: sys_enter tracepoint unregistered\n");
#endif

#ifdef CONFIG_KRETPROBES
    destroy_kretprobe(&syscall_regfunc_rp);
    destroy_kretprobe(&syscall_unregfunc_rp);
#endif

    ksu_unregister_syscall_hook(__NR_setresuid);
    ksu_unregister_syscall_hook(__NR_execve);
    ksu_unregister_syscall_hook(__NR_newfstatat);
    ksu_unregister_syscall_hook(__NR_faccessat);

    ksu_syscall_hook_exit();

    ksu_sucompat_exit();
    ksu_setuid_hook_exit();
}
