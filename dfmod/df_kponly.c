/* df_kponly: single-variable CRC probe for SM-G991B/HZC2.
 * Imports ONLY printk (proven via df_noop) + register_kprobe /
 * unregister_kprobe (suspect). Resident on success. lsmod-visible.
 */
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IonStack_S21");
MODULE_DESCRIPTION("kprobe CRC probe (HZC2)");

static char *soft_reboot;
module_param(soft_reboot, charp, 0400);

static int dummy_pre(struct kprobe *p, struct pt_regs *regs)
{
	(void)p;
	(void)regs;
	return 0;
}

static int __init dfkp_init(void)
{
	static struct kprobe kp;

	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = "kallsyms_lookup_name";
	kp.pre_handler = dummy_pre;
	if (register_kprobe(&kp)) {
		pr_err("dfkp: register failed\n");
		return -ENODEV;
	}
	pr_info("dfkp: kprobe ok addr=%px\n", kp.addr);
	unregister_kprobe(&kp);
	pr_info("dfkp: resident, kprobe CRCs match\n");
	return 0;
}

module_init(dfkp_init);
