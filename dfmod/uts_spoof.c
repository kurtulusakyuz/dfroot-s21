/* uts_spoof: GKI-gate bypass for KSU Manager (o1s reports non-GKI release).
 * Overwrites init_uts_ns.release with a GKI-looking string so the manager's
 * KMI check passes. DATA write (like selinux_state), no text, no exec. */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/utsname.h>

MODULE_LICENSE("GPL");

extern int sprint_symbol(char *buffer, unsigned long address);
typedef unsigned long (*kln_t)(const char *name);
#define KLN_FILE 0xffffffc0102f860cUL

static int name_is(const char *buf, const char *want)
{
	int i;
	for (i = 0; want[i]; i++)
		if (buf[i] != want[i])
			return 0;
	return buf[i] == '+' && buf[i + 1] == '0' && buf[i + 2] == 'x' &&
	       buf[i + 3] == '0' && buf[i + 4] == '/';
}

static int __init spoof_init(void)
{
	static char buf[256];
	unsigned long a, found = 0, un;
	unsigned long j;
	kln_t kln;
	struct uts_namespace *uts;

	for (a = KLN_FILE - (1UL << 20); a < KLN_FILE + (16UL << 20); a += 4) {
		for (j = 0; j < sizeof(buf); j++)
			buf[j] = 0;
		sprint_symbol(buf, a);
		if (name_is(buf, "kallsyms_lookup_name")) {
			found = a;
			break;
		}
	}
	if (!found)
		return -ENODEV;
	kln = (kln_t)found;
	un = kln("init_uts_ns");
	if (!un)
		return -ENODEV;
	uts = (struct uts_namespace *)un;
	strncpy(uts->name.release, "5.4.242-android11-abG991BXXSJHZC2",
		sizeof(uts->name.release));
	pr_info("uts: spoofed release\n");
	return 0;
}

module_init(spoof_init);
