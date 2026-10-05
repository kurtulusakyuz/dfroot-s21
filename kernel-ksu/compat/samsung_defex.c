#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kprobes.h>
#include <linux/sched.h>

#include "compat/samsung_defex.h"
#include "infra/symbol_resolver.h"
#include "klog.h"
#include "selinux/selinux.h"
extern bool ksu_no_kprobe;

#ifdef CONFIG_KSU_SAMSUNG_DEFEX
/* Exported on HZC2 (not trimmed): call directly (no CFI hazard).
 * Prototypes verbatim from defex_internal.h:111-112. */
extern void get_task_creds(struct task_struct *p, unsigned int *uid_ptr,
			   unsigned int *fsuid_ptr, unsigned int *egid_ptr,
			   unsigned short *cred_flags_ptr);
extern int set_task_creds(struct task_struct *p, unsigned int uid,
			  unsigned int fsuid, unsigned int egid,
			  unsigned short cred_flags);
static bool defex_enforce_hooked;

static int ksu_samsung_defex_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    struct task_struct *task = (struct task_struct *)regs->regs[0];

    (void)probe;
    if (task == current && current_uid().val == 0 && is_ksu_domain())
        regs->regs[0] = 0;

    return 0;
}

static struct kprobe defex_enforce_kprobe = {
    .symbol_name = "task_defex_enforce",
    .pre_handler = ksu_samsung_defex_pre_handler,
};
#endif

int ksu_samsung_defex_init(void)
{
#ifdef CONFIG_KSU_SAMSUNG_DEFEX
    int ret;

    if (ksu_no_kprobe) {
        pr_info("Samsung DEFEX hook skipped (nokprobe)\n");
        return 0;
    }

    ret = ksu_b_register_kprobe(&defex_enforce_kprobe);
    if (ret) {
        pr_err("Samsung DEFEX enforce hook unavailable: %d\n", ret);
        return ret;
    }
    defex_enforce_hooked = true;

    pr_info("Samsung DEFEX credential synchronization and KSU-task bypass enabled\n");
#endif
    return 0;
}

void ksu_samsung_defex_exit(void)
{
#ifdef CONFIG_KSU_SAMSUNG_DEFEX
    if (defex_enforce_hooked) {
        ksu_b_unregister_kprobe(&defex_enforce_kprobe);
        defex_enforce_hooked = false;
    }
#endif
}

void ksu_samsung_defex_sync_current(void)
{
#ifdef CONFIG_KSU_SAMSUNG_DEFEX
    const struct cred *cred = current_cred();
    unsigned int stored_uid;
    unsigned int stored_fsuid;
    unsigned int stored_egid;
    unsigned short cred_flags;
    int ret;

    ksu_b_get_task_creds(current, &stored_uid, &stored_fsuid, &stored_egid, &cred_flags);

    if (__kuid_val(cred->euid) == 0 && __kuid_val(cred->fsuid) == 0 && __kgid_val(cred->egid) == 0) {
        stored_uid = 1;
        stored_fsuid = 1;
        stored_egid = 1;
    } else {
        stored_uid = __kuid_val(cred->euid);
        stored_fsuid = __kuid_val(cred->fsuid);
        stored_egid = __kgid_val(cred->egid);
    }

    ret = ksu_b_set_task_creds(current, stored_uid, stored_fsuid, stored_egid, cred_flags);
    if (ret)
        pr_err("Samsung DEFEX credential synchronization failed: %d\n", ret);
#endif
}
