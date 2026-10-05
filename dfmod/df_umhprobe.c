/* df_umhprobe: single-variable test for UMH imports on SM-G991B/HZC2.
 * Imports ONLY printk (proven) + call_usermodehelper_setup/exec.
 * Resident on success. lsmod-visible verdict:
 *   present => UMH importable (df_full-style works, CFI-safe direct calls)
 *   absent  => UMH trimmed (exec moves to userspace stage instead)
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/umh.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IonStack_S21");
MODULE_DESCRIPTION("UMH import probe (HZC2)");

static char *soft_reboot;
module_param(soft_reboot, charp, 0400);

static void *volatile sink;

static int __init dfu_init(void)
{
	pr_info("dfu: loaded\n");
	sink = (void *)call_usermodehelper_setup;
	sink = (void *)call_usermodehelper_exec;
	return 0;
}

module_init(dfu_init);
