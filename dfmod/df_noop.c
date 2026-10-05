/* df_noop: control experiment for SM-G991B/HZC2.
 * Identical load path to df_kprobe (vermagic, imports, init flow) but
 * writes NOTHING - returns -E2BIG immediately. If the device still resets,
 * the trigger is environmental (thermal/load), not our write. If it runs
 * clean, the selinux_state write is the reset trigger (RKP guard).
 */
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IonStack_S21");
MODULE_DESCRIPTION("DirtyFrag no-op control (HZC2)");

static char *soft_reboot;
module_param(soft_reboot, charp, 0400);

static int __init dfnoop_init(void)
{
	pr_info("dfnoop: control loaded, staying resident (no unload)\n");
	return 0;
}

module_init(dfnoop_init);
