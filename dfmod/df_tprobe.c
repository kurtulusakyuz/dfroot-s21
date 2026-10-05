/* df_tprobe: combined whitelist + text-read probe for SM-G991B/HZC2.
 * Imports ONLY printk (proven) + sprint_symbol (untested).
 * init: if *(u32*)&sprint_symbol == 0x17ced555 (the B-stub, slide-
 * independent content) return 0 resident (VISIBLE in lsmod);
 * else return -ENODEV.
 *   lsmod present  => sprint_symbol whitelisted AND text readable.
 *   lsmod absent   => split-probe needed (see df_tread.c plan).
 */
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IonStack_S21");
MODULE_DESCRIPTION("sprint_symbol + text-read probe (HZC2)");

static char *soft_reboot;
module_param(soft_reboot, charp, 0400);

extern int sprint_symbol(char *buffer, unsigned long address);

static int __init dft_init(void)
{
	unsigned int w = *(volatile unsigned int *)&sprint_symbol;

	pr_info("dft: stubval=%08x\n", w);
	if (w == 0x17ced555U)
		return 0;
	return -ENODEV;
}

module_init(dft_init);
