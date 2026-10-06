#include "linux/file.h"
#include "compat/s21_54.h"
#include "linux/namei.h"
#include <linux/compiler_types.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/sched/task_stack.h>
#include <linux/ptrace.h>

#include "arch.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "infra/symbol_resolver.h"
#include "runtime/ksud.h"
#include "feature/sucompat.h"
#include "policy/app_profile.h"
#include "hook/syscall_hook.h"
#include "manager/manager_identity.h"
#include <linux/task_work.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include "ksu_samsung_kdp.h"
#include <linux/binfmts.h>
#include <linux/dcache.h>
#include <linux/fcntl.h>
#include <linux/fs_struct.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include "supercall/supercall.h"
#include "hook/lsm_hook.h"
#include "sulog/event.h"
#include "feature/adb_root.h"
#include "ksu.h"
#include "util.h"

/* HZC2: /system is read-only (verity dm) and overlay-mounting it wedges
 * the kernel (RCNT 168 hardlockup). Point SU_PATH at a dormant, exec-able
 * system binary instead: the grant fires on faccessat/stat (no new file,
 * no mount, no exec of anything new). uiautomator exists, never runs. */
/* HZC2: grant fires on exec (persistent override, no dispatcher needed).
 * Any allowlisted exec of the shell becomes root. init(allowed? no:
 * uid-0 requires ksu domain) and daemons are unaffected in practice:
 * only allowlisted UIDs (shell w/ allow_shell, manager, explicit allows)
 * trigger. */
#define SU_PATH "/system/bin/sh"
#define SH_PATH "/system/bin/sh"
/* App/shell'in cagirdigi su ikilisi (allowlist'teki UID exec ederse
 * grant atesler; SU_PATH kontrolune ek). */
#define SU_BIN_PATH "/data/adb/ksu/bin/su"
/* Klasik su yollari (cihazda yok): allowlist exec'i ksud'ye cevrilir
 * (upstream sucompat; arg0'dan root_shell'e girer). */
#define SU_ALIAS1 "/system/bin/su"
#define SU_ALIAS2 "/system/xbin/su"
/* /system_ext/bin aynasindaki su (PATH kesfi icin; gercek dosya,
 * yonlendirme gerekmez, grant yeterli). */
#define SU_ALIAS3 "/system_ext/bin/su"
/* NOT: busybox aynada shell kullanimina aciktir ama ASLA grant
 * listesine girmez (busybox sh = sessiz root deligi olur). */
/* sulog bosaltici: manager Sulog ekrani Runtime.exec ile calistirir
 * (non-root exec: DEFEX-safe). Driver fd + grant burada kurulur;
 * kendisi GET_SULOG_FD ile kuyrugu bosaltir. */
#define SULOG_DRAIN_PATH "/data/adb/ksu/bin/ksudrain"
/* olay raportoru: mrun mounts sonunda modul bayragini kaldirir.
 * drainer ile ayni desen (fd + grant), non-root exec guvenli. */
#define KSUEV_PATH "/data/adb/ksu/bin/ksuev"

bool ksu_su_compat_enabled __read_mostly = true;

static int su_compat_feature_get(u64 *value)
{
    *value = ksu_su_compat_enabled ? 1 : 0;
    return 0;
}

static int su_compat_feature_set(u64 value)
{
    bool enable = value != 0;
    ksu_su_compat_enabled = enable;
    pr_info("su_compat: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
    .feature_id = KSU_FEATURE_SU_COMPAT,
    .name = "su_compat",
    .get_handler = su_compat_feature_get,
    .set_handler = su_compat_feature_set,
};

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
    // To avoid having to mmap a page in userspace, just write below the stack
    // pointer.
    char __user *p = (void __user *)current_user_stack_pointer() - len;

    return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *ksud_user_path(void)
{
    static const char ksud_path[] = KSUD_PATH;

    return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

static char __user *empty_user_path(void)
{
    return userspace_stack_buffer("", sizeof(""));
}

static const char su_path[] = SU_PATH;

static bool is_ksud_exists()
{
    struct path path;

    if (kern_path(KSUD_PATH, 0, &path) < 0) {
        return false;
    }
    path_put(&path);
    return true;
}

long ksu_handle_faccessat_sucompat(int orig_nr, struct pt_regs *regs)
{
    const char __user **filename_user, *orig_filename;
    long ret;
    const struct cred *old_cred;

    if (!ksu_is_allow_uid_for_current(current_uid().val)) {
        goto do_orig_facessat;
    }

    filename_user = (const char __user **)&PT_REGS_PARM2(regs);

    char path[sizeof(su_path) + 1];
    memset(path, 0, sizeof(path));
    strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
        old_cred = override_creds(ksu_cred);
        if (is_ksud_exists()) {
            pr_info("faccessat su->ksud!\n");
            orig_filename = *filename_user;
            *filename_user = ksud_user_path();
            ret = ksu_syscall_table[orig_nr](regs);
            revert_creds(old_cred);
            *filename_user = orig_filename;
            return ret;
        } else {
            revert_creds(old_cred);
        }
    }

do_orig_facessat:
    return ksu_syscall_table[orig_nr](regs);
}

long ksu_handle_stat_sucompat(int orig_nr, struct pt_regs *regs)
{
    const char __user **filename_user, *orig_filename;
    long ret;
    const struct cred *old_cred;

    if (!ksu_is_allow_uid_for_current(current_uid().val)) {
        goto do_orig_stat;
    }

    filename_user = (const char __user **)&PT_REGS_PARM2(regs);

    char path[sizeof(su_path) + 1];
    memset(path, 0, sizeof(path));
    strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
        old_cred = override_creds(ksu_cred);
        if (is_ksud_exists()) {
            pr_info("newfstatat su->ksud!\n");
            orig_filename = *filename_user;
            *filename_user = ksud_user_path();
            ret = ksu_syscall_table[orig_nr](regs);
            revert_creds(old_cred);
            *filename_user = orig_filename;
            return ret;
        } else {
            revert_creds(old_cred);
        }
    }

do_orig_stat:
    return ksu_syscall_table[orig_nr](regs);
}

/* RKP-safe direct su grant (no dispatcher/table writes): called from the
 * sys_enter tracepoint for execve/execveat. Persistent: creds installed on
 * current propagate across the pending exec. */
static void ksu_su_grant_task_work(struct callback_head *cb)
{
	__u32 uid = current_uid().val;
	__u32 euid = current_euid().val;

	kfree(cb);
	escape_with_root_profile();
	/* sulog: tum grant'ler buradan gecer (dispatcher olu). Kuyruk
	 * bosalmazsa drainer gorur; toggle kapaliysa kimse okumaz. */
	ksu_sulog_emit_grant_root(0, uid, euid, GFP_KERNEL);
}

/* Disaridan kuyruklanabilir grant (orn. setresuid re-grant): 16B
 * GFP_ATOMIC, task_work sleepable escape yapar. */
int ksu_su_grant_current_async(void)
{
	struct callback_head *cb = kmalloc(sizeof(*cb), GFP_ATOMIC);

	if (!cb)
		return -ENOMEM;
	init_task_work(cb, ksu_su_grant_task_work);
	if (ksu_b_task_work_add(current, cb, true)) {
		kfree(cb);
		return -ESRCH;
	}
	return 0;
}

void ksu_su_grant_on_exec(struct pt_regs *regs, long id)
{
	const char __user *fn;
	char path[32];
	long ret;

	/* ATOMIC CONTEXT (sys_enter tracepoint): absolutely nothing here may
	 * sleep. In particular NO filp_open (markers!), NO escape/KDP-commit
	 * (waits), NO raw cred writes (KDP). Only: uid/path checks (nofault
	 * reads) + queue async worker. Violations wedge random CPUs in 15-20s
	 * (RCNT 152-175 hardlockup series). */
	if (id == __NR_execve || id == __NR_execveat)
		pr_debug("ksu grant chk: %s(%d) id=%ld\n", current->comm,
			current_uid().val, id);
	if (!ksu_is_allow_uid_for_current(current_uid().val))
		return;
	pr_debug("ksu grant chk: allow ok\n");
	if (id == __NR_execve)
		fn = (const char __user *)PT_REGS_PARM1(regs);
	else if (id == __NR_execveat)
		fn = (const char __user *)PT_REGS_PARM2(regs);
	else
		return;
	memset(path, 0, sizeof(path));
	ret = ksu_b_probe_user_read(path, fn, sizeof(path));
	pr_debug("ksu grant chk: read=%ld path=%.16s\n", ret, path);
	if (ret < 0 || path[0] != '/') {
		/* Mutlak yol yoksa grant yok: AT_EMPTY_PATH/fd-exec ve
		 * goreceli cagrilar standart akista kullanilmiyor
		 * (resolver kaldirildi). su daima mutlak yolla cagrilir. */
		return;
	}
	/* Standart akis (Magisk-vari): shell tek basina grant URETMEZ.
	 * Grant yalnizca acik su cagrilarinda: SU_BIN, klasik aliaslar
	 * (ksud'ye yonlenir). Boylece adb shell 2000 acar, su ile
	 * yukselinir. Manager bypass aynen duruyor. */
	if (!is_uid_manager(current_uid().val)) {
		/* ADB Root (upstream fix uyarlamasi): bayrak acikken adbd'nin
		 * dogurdugu /system/bin/sh'e grant ver. Yonlendirme RKP'de
		 * olu oldugu icin grant yolu kullanilir (LD_PRELOAD APEX'te
		 * etkisizdi). Ebeveyn adbd olmayan sh'ler etkilenmez. */
		bool adb_shell = false;
		if (ksu_adb_root_enabled() && strcmp(path, SH_PATH) == 0) {
			struct task_struct *par;

			rcu_read_lock();
			par = rcu_dereference(current->real_parent);
			adb_shell = par && strcmp(par->comm, "adbd") == 0;
			rcu_read_unlock();
			if (adb_shell)
				pr_info("ksu adb grant: %s(%d) exec %s (adbd child)\n",
					current->comm, current_uid().val, path);
		}
		if (!adb_shell &&
		    strcmp(path, SU_BIN_PATH) &&
		    strcmp(path, SU_ALIAS1) && strcmp(path, SU_ALIAS2) &&
		    strcmp(path, SU_ALIAS3) &&
		    strcmp(path, SULOG_DRAIN_PATH) && strcmp(path, KSUEV_PATH))
			return;
		/* sulog bosaltici: driver fd kur (kendi tarar) + asagida grant.
		 * non-root exec oldugu icin DEFEX'e takilmaz. */
		if (strcmp(path, SULOG_DRAIN_PATH) == 0) {
			pr_info("ksu drain fd install: %s(%d)\n",
				current->comm, current_uid().val);
			ksu_supercall_install_mgr_fd_async();
		}
		/* olay raportoru: ayni desen (fd + asagida grant). */
		if (strcmp(path, KSUEV_PATH) == 0) {
			pr_info("ksu ksuev fd install: %s(%d)\n",
				current->comm, current_uid().val);
			ksu_supercall_install_mgr_fd_async();
		}
		/* Klasik su yollari (/system/bin/su): dosya yok, exec ENOENT
		 * olurdu. Upstream sucompat tasarimi: filename'i ksud yoluna
		 * cevir (tracepoint atomik: nofault write + regs store, uyku
		 * yok; syscall govdesi regs'i canli okur). ksud arg0'dan su
		 * oldugunu anlar, iceride driver'dan yukselir (kanitli). */
		if (strcmp(path, SU_ALIAS1) == 0 || strcmp(path, SU_ALIAS2) == 0) {
			char __user *kpath = (char __user *)current_user_stack_pointer() -
					      sizeof(KSUD_PATH);
			if (probe_user_write(kpath, KSUD_PATH, sizeof(KSUD_PATH))) {
				pr_info("ksu su redirect: stack write failed\n");
				return;
			}
			if (id == __NR_execve)
				regs->__PT_PARM1_REG = (unsigned long)kpath;
			else
				regs->__PT_PARM2_REG = (unsigned long)kpath;
			pr_info("ksu su redirect: %s(%d) %s -> ksud\n",
				current->comm, current_uid().val, path);
		}
	} else {
		pr_info("ksu grant chk: manager bypass\n");
		/* Manager getVersion fd-taramasiyla calisir: process'ine
		 * [ksu_driver] fd'si kur (yoksa; kurulum task_work'te). */
		ksu_supercall_install_mgr_fd_async();
	}
/* Atomic-safe persistent grant: override only (no sleep: no KDP commit,
 * no profile, no seccomp here — those need sleepable context and crashed
 * in tracepoint (RCNT 170: wait_for_completion in atomic). New image
 * inherits root creds across exec. Old cred intentionally leaked (one ref
 * per su; revert would drop the grant). RKP tolerated: override_creds is
 * a standard API (NFS/overlay use it); KDP hardening comes later if the
 * watcher objects. */
/* Persistent grant WITHOUT split (override alone breaks exec's
 * commit_creds BUG_ON(cred != real_cred), RCNT 171): install ksu_cred to
 * BOTH pointers (mirror revert_creds' dance). All ops atomic-safe
 * (rcu_assign + put_cred defers via RCU; DEBUG_CREDENTIALS off).
 * Old cred held 2 refs (cred+real); ksu_cred gets 2 fresh refs. */
	/* put_cred/get_cred inlines pull trimmed symbols (get_new_cred,
	 * is_kdp_protect_addr); use raw atomics instead (arch, no imports).
	 * Old cred refs intentionally leaked (2/task, ~400B — su is rare);
	 * ksu_cred bumped to stay correct. */
	/* DISABLED 2026-10-04: raw cred writes trip KDP (RCNT 172 instant
	 * panic on adbd's own sh exec!). Grant logic moves to an LSM bprm
	 * hook (sleepable, sanctioned KDP API). This path now only logs. */
	/* Queue async grant via task_work (runs on return-to-user, sleepable
	 * process context — NOT a workqueue (whose KDP path is suspect).
	 * 16B GFP_ATOMIC; failure just skips (logged). */
	{
		struct callback_head *cb =
			kmalloc(sizeof(*cb), GFP_ATOMIC);

		if (likely(cb)) {
			init_task_work(cb, ksu_su_grant_task_work);
			if (ksu_b_task_work_add(current, cb, true))
				kfree(cb);
		} else {
			pr_info("ksu grant: cb alloc failed\n");
		}
	}
	pr_info("ksu su grant: %s(%d) exec %s (cred+real, persistent)\n",
		current->comm, current_uid().val, SU_PATH);
}

long ksu_handle_execve_sucompat(const char __user **filename_user, int orig_nr, struct pt_regs *regs)
{
    const char __user *fn;
    const char __user *const __user *argv_user = (const char __user *const __user *)PT_REGS_PARM2(regs);
    struct ksu_sulog_pending_event *pending_sucompat = NULL;
    char path[sizeof(su_path) + 1];
    long ret, orig_regs[5];
    unsigned long addr;
    int tmp_fd;
    struct file *ksud_file;
    const struct cred *old_cred;

    if (unlikely(!filename_user))
        goto do_orig_execve;

    if (!ksu_is_allow_uid_for_current(current_uid().val))
        goto do_orig_execve;

    addr = untagged_addr((unsigned long)*filename_user);
    fn = (const char __user *)addr;
    memset(path, 0, sizeof(path));

    ret = strncpy_from_user(path, fn, sizeof(path));

    if (ret < 0) {
        pr_warn("Access filename when execve failed: %ld", ret);
        goto do_orig_execve;
    }

    if (likely(memcmp(path, su_path, sizeof(su_path))))
        goto do_orig_execve;

    pr_info("sys_execve su found\n");

    tmp_fd = get_unused_fd_flags(O_CLOEXEC);
    if (tmp_fd < 0) {
        pr_err("alloc tmp fd err: %d\n", tmp_fd);
        goto do_orig_execve;
    }

    old_cred = override_creds(ksu_cred);
    ksud_file = filp_open(KSUD_PATH, O_PATH, 0);
    revert_creds(old_cred);
    if (IS_ERR(ksud_file)) {
        pr_err("open ksud err: %ld\n", PTR_ERR(ksud_file));
        put_unused_fd(tmp_fd);
        goto do_orig_execve;
    }

    fd_install(tmp_fd, ksud_file);

    pending_sucompat = ksu_sulog_capture_sucompat(*filename_user, argv_user, GFP_KERNEL);
    // execve(file, argv, environ)
    // execveat(fd, file, argv, environ, flags)
    orig_regs[0] = regs->__PT_PARM1_REG;
    orig_regs[1] = regs->__PT_PARM2_REG;
    orig_regs[2] = regs->__PT_PARM3_REG;
    orig_regs[3] = regs->__PT_SYSCALL_PARM4_REG;
    orig_regs[4] = regs->__PT_PARM5_REG;
    regs->__PT_PARM5_REG = AT_EMPTY_PATH;
    regs->__PT_SYSCALL_PARM4_REG = regs->__PT_PARM3_REG;
    regs->__PT_PARM3_REG = regs->__PT_PARM2_REG;
    regs->__PT_PARM2_REG = empty_user_path();
    regs->__PT_PARM1_REG = tmp_fd;

    ret = escape_with_root_profile();
    if (ret) {
        pr_err("escape_with_root_profile failed: %ld\n", ret);
    }
    ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);

    ret = ksu_syscall_table[__NR_execveat](regs);
    if (ret < 0) {
        ksu_close_fd(tmp_fd);
        regs->__PT_PARM1_REG = orig_regs[0];
        regs->__PT_PARM2_REG = orig_regs[1];
        regs->__PT_PARM3_REG = orig_regs[2];
        regs->__PT_SYSCALL_PARM4_REG = orig_regs[3];
        regs->__PT_PARM5_REG = orig_regs[4];
    }
    return ret;

do_orig_execve:
    return ksu_syscall_table[orig_nr](regs);
}

// sucompat: permitted process can execute 'su' to gain root access.
/* LSM bprm su hook (RKP-safe: data-list edit, no text patch; sleepable
 * context so the full sanctioned escape incl. KDP commit may run).
 * Replaces selinux_bprm_set_creds slot, chains original (labeling kept),
 * then applies su grant for allowlisted execs of SU_PATH. */
static int ksu_bprm_su_hook(struct linux_binprm *bprm);

static struct ksu_lsm_hook ksu_bprm_hook =
	KSU_LSM_HOOK_INIT(bprm_set_creds, "selinux_bprm_set_creds",
			  ksu_bprm_su_hook, 0);

static int ksu_bprm_su_hook(struct linux_binprm *bprm)
{
	int ret;

	ret = ksu_b_selinux_bprm_set_creds(bprm);
	if (ret)
		return ret;
	if (!ksu_is_allow_uid_for_current(current_uid().val))
		return 0;
	/* Standart akis: sadece acik su ikilisi grant uretir (SU_PATH
	 * tek basina yetmez; bkz. ksu_su_grant_on_exec). */
	if (strcmp(bprm->filename, SU_BIN_PATH))
		return 0;
	pr_info("ksu bprm su grant: %s(%d) exec %s\n", current->comm,
		current_uid().val, SU_BIN_PATH);
	return escape_with_root_profile();
}

void ksu_su_bprm_init(void)
{
	int ret = ksu_lsm_hook(&ksu_bprm_hook);

	if (ret)
		pr_warn("ksu bprm hook not installed: %d\n", ret);
	else
		pr_info("ksu bprm hook installed\n");
}

void __init ksu_sucompat_init()
{
    if (ksu_register_feature_handler(&su_compat_handler)) {
        pr_err("Failed to register su_compat feature handler\n");
    }
}

void ksu_sucompat_exit()
{
    ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
