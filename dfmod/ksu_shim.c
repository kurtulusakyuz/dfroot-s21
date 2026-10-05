/* ksu_shim: exact-type forwarders for the 7 symbols Samsung trimmed from
 * HZC2 (kko's unknowns): prepare_creds, abort_creds, register_kprobe,
 * unregister_kprobe, strncpy_from_unsafe_user, kallsyms_lookup_size_offset,
 * static_key_disable. kko links against THESE; they jump to kallsyms-
 * resolved addresses (kallsyms has all T/t regardless of export trimming).
 *
 * CFI discipline (RCNT 147/148 lessons):
 *  - prototypes VERBATIM from HZC2 headers (cred.h:174/177, kprobes.h:362/3,
 *    uaccess.h:357, kallsyms.h:83, jump_label.h:229), full includes only,
 *    no forward decls;
 *  - addresses kept as `unsigned long` GLOBALS (never fn pointers across
 *    boundaries); each wrapper casts to an exact-type LOCAL and calls
 *    (v82's proven inline-icall shape — no __cfi_slowpath);
 *  - missing address -> -ENODEV (clean insmod failure, never a panic).
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cred.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/jump_label.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IonStack_S21");
MODULE_DESCRIPTION("KSU trimmed-symbol shim (o1s HZC2)");

extern int sprint_symbol(char *buffer, unsigned long address);

typedef unsigned long (*kln_t)(const char *name);

#define KLN_FILE	0xffffffc0102f860cUL
#define SCAN_DOWN	(1UL << 20)
#define SCAN_UP		(16UL << 20)
#define SCAN_STRIDE	4UL

/* Typed globals (NOT ulong): init assigns via cast-of-kln-result (v82's
 * proven inline shape); wrappers call through them with zero casts. */
static struct cred *(*F_prepare)(void);
static void (*F_abort)(struct cred *);
static int (*F_regkp)(struct kprobe *);
static void (*F_unregkp)(struct kprobe *);
static long (*F_strncpy)(char *, const void __user *, long);
static int (*F_klso)(unsigned long, unsigned long *, unsigned long *);
static void (*F_skd)(struct static_key *);

struct cred *__nocfi prepare_creds(void)
{
	return F_prepare();
}
EXPORT_SYMBOL(prepare_creds);

void __nocfi abort_creds(struct cred *cred)
{
	F_abort(cred);
}
EXPORT_SYMBOL(abort_creds);

int __nocfi register_kprobe(struct kprobe *p)
{
	return F_regkp(p);
}
EXPORT_SYMBOL(register_kprobe);

void __nocfi unregister_kprobe(struct kprobe *p)
{
	F_unregkp(p);
}
EXPORT_SYMBOL(unregister_kprobe);

long __nocfi strncpy_from_unsafe_user(char *dst,
					const void __user *unsafe_addr,
					long count)
{
	return F_strncpy(dst, unsafe_addr, count);
}
EXPORT_SYMBOL(strncpy_from_unsafe_user);

int __nocfi kallsyms_lookup_size_offset(unsigned long addr,
					unsigned long *symbolsize,
					unsigned long *offset)
{
	return F_klso(addr, symbolsize, offset);
}
EXPORT_SYMBOL(kallsyms_lookup_size_offset);

void __nocfi static_key_disable(struct static_key *key)
{
	F_skd(key);
}
EXPORT_SYMBOL(static_key_disable);

static int name_is(const char *buf, const char *want)
{
	int i;

	for (i = 0; want[i]; i++) {
		if (buf[i] != want[i])
			return 0;
	}
	return buf[i] == '+' && buf[i + 1] == '0' && buf[i + 2] == 'x' &&
	       buf[i + 3] == '0' && buf[i + 4] == '/';
}

static int __init shim_init(void)
{
	static char buf[256];
	unsigned long base = KLN_FILE - SCAN_DOWN;
	unsigned long end = KLN_FILE + SCAN_UP;
	unsigned long a, found = 0;
	unsigned long j;
	kln_t kln;

	for (a = base; a < end; a += SCAN_STRIDE) {
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
	F_prepare = (void *)kln("prepare_creds");
	F_abort = (void *)kln("abort_creds");
	F_regkp = (void *)kln("register_kprobe");
	F_unregkp = (void *)kln("unregister_kprobe");
	F_strncpy = (void *)kln("strncpy_from_unsafe_user");
	F_klso = (void *)kln("kallsyms_lookup_size_offset");
	F_skd = (void *)kln("static_key_disable");
	if (!F_prepare || !F_abort || !F_regkp || !F_unregkp || !F_strncpy ||
	    !F_klso || !F_skd) {
		pr_info("shim: address missing, refusing to load\n");
		return -ENODEV;
	}
	pr_info("shim: 7 symbols resolved, ready\n");
	return 0;
}

module_init(shim_init);
