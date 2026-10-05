/* df_full: complete DirtyFrag second stage for SM-G991B/HZC2 (5.4.242).
 *
 * Replicates diabl0w dirtyfrag.ko observable behavior (RE'd from the 6.6
 * image) against the HZC2 tree, minus the Samsung-DEFEX pre-dance (added
 * only if UMH exec proves blocked):
 *   1. kprobe-resolve kallsyms_lookup_name (no text reads, no slidedep).
 *   2. selinux_state.enforcing = 0 (permissive).
 *   3. UMH: /system/bin/sh -c "<ksud> late-load --package-name
 *      me.weishu.kernelsu --ro-partitions[ --soft-reboot] &&
 *      touch /dev/dfm0 || touch /dev/dfm1".
 *   4. Progress markers to /data/local/tmp/dfS{1,2,3} (best effort;
 *      shell-readable, unlike dmesg).
 *   5. Stay resident (return 0): the -E2BIG unload path hangs on HZC2.
 *
 * Imports are all versioned symbols present in the HZC2 symvers.
 * vermagic must match the running kernel (see dfmod/Makefile).
 */
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/umh.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IonStack_S21");
MODULE_DESCRIPTION("DirtyFrag full second stage (HZC2)");

typedef unsigned long (*kln_t)(const char *name);

static int soft_reboot;
module_param(soft_reboot, int, 0400);

#define KSUD_PATH "/data/user_de/0/df.root/ksud"

static int umh_init(struct subprocess_info *info, struct cred *new)
{
	(void)info;
	(void)new;
	return 0;
}

/* best-effort shell-readable progress marker */
static void mark(const char *name)
{
	struct file *f;

	f = filp_open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(f))
		return;
	{
		char c = '1';
		loff_t pos = 0;
		kernel_write(f, &c, 1, &pos);
	}
	filp_close(f, NULL);
}

static int dummy_pre(struct kprobe *p, struct pt_regs *regs)
{
	(void)p;
	(void)regs;
	return 0;
}

static int __init dff_init(void)
{
	static struct kprobe kp;
	kln_t kln;
	unsigned long sstate;
	struct subprocess_info *sub;
	static char cmd[512];
	static char *argv[] = {
		(char *)"/system/bin/sh",
		(char *)"-c",
		cmd,
		NULL
	};
	static char *envp[] = {
		(char *)"HOME=/",
		(char *)"PATH=/sbin:/vendor/bin:/system/bin",
		NULL
	};
	int rc;

	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = "kallsyms_lookup_name";
	kp.pre_handler = dummy_pre;
	if (register_kprobe(&kp)) {
		pr_err("dff: register_kprobe failed\n");
		return -ENODEV;
	}
	kln = (kln_t)kp.addr;
	unregister_kprobe(&kp);
	if (!kln) {
		pr_err("dff: no kln addr\n");
		return -ENODEV;
	}
	sstate = kln("selinux_state");
	if (!sstate) {
		pr_err("dff: selinux_state unresolved\n");
		return -ENODEV;
	}
	*(volatile unsigned char *)sstate = 0;
	__asm__ volatile("dsb sy" ::: "memory");
	pr_info("dff: permissive set\n");
	mark("/data/local/tmp/dfS1");

	snprintf(cmd, sizeof(cmd),
		 "%s late-load --package-name me.weishu.kernelsu"
		 " --ro-partitions%s && touch /dev/dfm0 || touch /dev/dfm1",
		 KSUD_PATH, soft_reboot ? " --soft-reboot" : "");
	sub = call_usermodehelper_setup("/system/bin/sh", argv, envp,
					GFP_KERNEL, umh_init, NULL, NULL);
	if (!sub) {
		pr_err("dff: umh_setup NULL\n");
		return -ENODEV;
	}
	mark("/data/local/tmp/dfS2");
	rc = call_usermodehelper_exec(sub, UMH_WAIT_PROC);
	pr_info("dff: umh_exec rc=%d\n", rc);
	mark("/data/local/tmp/dfS3");
	return 0;
}

module_init(dff_init);
