/* df_probe: whitelist discovery for SM-G991B/HZC2 (5.4.242).
 * References a batch of candidate kernel symbols (address-take only, never
 * called). insmod reports EVERY unresolvable symbol to stderr (captured by
 * the stage into /data/local/tmp/inserr). Resident on success (return 0).
 */
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");

extern int printk(const char *fmt, ...);
extern void *memset(void *s, int c, __kernel_size_t n);
extern void *memcpy(void *d, const void *s, __kernel_size_t n);
extern void *memmove(void *d, const void *s, __kernel_size_t n);
extern __kernel_size_t strlen(const char *s);
extern int strncmp(const char *a, const char *b, __kernel_size_t n);
extern int sprintf(char *buf, const char *fmt, ...);
extern int snprintf(char *buf, __kernel_size_t n, const char *fmt, ...);
extern int sprint_symbol(char *buffer, unsigned long address);
extern int sprint_symbol_no_offset(char *buffer, unsigned long address);
extern unsigned long kallsyms_lookup_name(const char *name); /* NOT exported on HZC2 (modpost-proven) - kept as documentation */
extern void dump_stack(void);
#include <linux/umh.h>
#include <linux/fs.h>

static void *volatile sink;

static int __init dfprobe_init(void)
{
	sink = (void *)printk;
	sink = memset;
	sink = memcpy;
	sink = memmove;
	sink = (void *)strlen;
	sink = (void *)strncmp;
	sink = (void *)sprintf;
	sink = (void *)snprintf;
	sink = (void *)sprint_symbol;
	sink = (void *)sprint_symbol_no_offset;
	/* kallsyms_lookup_name intentionally NOT referenced (unexported). */
	sink = (void *)dump_stack;
	sink = (void *)call_usermodehelper_setup;
	sink = (void *)call_usermodehelper_exec;
	sink = (void *)filp_open;
	sink = (void *)kernel_write;
	sink = (void *)filp_close;
	sink = (void *)register_kprobe;
	sink = (void *)unregister_kprobe;
	return 0;
}

module_init(dfprobe_init);
