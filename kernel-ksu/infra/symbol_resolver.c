#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/version.h>

#include "infra/symbol_resolver.h"

// https://github.com/torvalds/linux/commit/89245600941e4e0f87d77f60ee269b5e61ef4e49
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define USE_KCFI 1
#else
#define USE_KCFI 0
#endif

#if !USE_KCFI
static const char cfi_suffix[] = ".cfi_jt";
static const size_t cfi_suffix_len = sizeof(cfi_suffix) - 1;
#endif

// It's not guaranteed to have this symbol exist in 5.x kernel
// https://github.com/torvalds/linux/commit/d721def7392a7348ffb9f3583b264239cbd3702c
// https://github.com/gregkh/linux/commit/2aa861ec72908b4bdc20d74725dc1c8c71a8d214
// https://github.com/gregkh/linux/commit/318a206633c248d876ea72f7133d2a2e50ad7e35
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
#define ALWAYS_HAVE_ON_EACH_SYMBOL 1
#else
#define ALWAYS_HAVE_ON_EACH_SYMBOL 0
#endif

#if !ALWAYS_HAVE_ON_EACH_SYMBOL
static int (*kallsyms_on_each_symbol_fn)(int (*fn)(void *, const char *, struct module *, unsigned long),
                                         void *data) = NULL;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define HAVE_ON_EACH_MATCH_SYMBOL 1
#else
#define HAVE_ON_EACH_MATCH_SYMBOL 0
#endif

// https://github.com/torvalds/linux/commit/4dc533e0f2c04174e1ae4aa98e7cffc1c04b9998
#if HAVE_ON_EACH_MATCH_SYMBOL
static int (*kallsyms_on_each_match_symbol_fn)(int (*fn)(void *, unsigned long), const char *name, void *data) = NULL;
static int find_kernel_symbol_exact_cb(void *data, unsigned long addr)
{
    *(unsigned long *)data = addr;
    return 0;
}
#endif

struct ksu_lookup_symbol_ctx {
    const char *symbol_name;
    size_t symbol_len;
    void *match;
};

/* Bootstrap scanner (df_self-proven on HZC2): kallsyms_lookup_name is NOT
 * exported, so resolve it by scanning for "kallsyms_lookup_name+0x0/"
 * via sprint_symbol (GPL-exported). noinline: keeps the v82 call-result
 * cast shape at every user. */
extern int sprint_symbol(char *buffer, unsigned long address);

#define SCAN_KLN_FILE	0xffffffc0102f860cUL
static unsigned long ksu_scan_kln_addr;

static int ksu_name_is(const char *buf, const char *want)
{
	int i;

	for (i = 0; want[i]; i++) {
		if (buf[i] != want[i])
			return 0;
	}
	return buf[i] == '+' && buf[i + 1] == '0' && buf[i + 2] == 'x' &&
	       buf[i + 3] == '0' && buf[i + 4] == '/';
}


/* __nocfi bridges for callees with no CFI table entry (never address-taken
 * in core, no .cfi_jt): the central validator rejects their raw addresses
 * no matter how exact the type is (RCNT 154: register_kprobe). Unchecked
 * jump executes normally (df_self precedent). Addresses never taken by the
 * kernel (direct KSU-internal calls only). Prototypes verbatim from HZC2
 * headers (kprobes.h). */
__nocfi int ksu_b_avc_has_perm(struct selinux_state *state, u32 ssid,
				 u32 tsid, u16 tclass, u32 requested,
				 struct common_audit_data *auditdata)
{
	int (*f)(struct selinux_state *, u32, u32, u16, u32,
		 struct common_audit_data *) =
		(int (*)(struct selinux_state *, u32, u32, u16, u32,
			 struct common_audit_data *))ksu_sym_addr(KSU_AVC_HAS_PERM);

	return f(state, ssid, tsid, tclass, requested, auditdata);
}

__nocfi int ksu_b_register_kprobe(struct kprobe *p)
{
	int (*f)(struct kprobe *) =
		(int (*)(struct kprobe *))ksu_sym_addr(KSU_REGISTER_KPROBE);

	return f(p);
}

__nocfi void ksu_b_unregister_kprobe(struct kprobe *p)
{
	void (*f)(struct kprobe *) =
		(void (*)(struct kprobe *))ksu_sym_addr(KSU_UNREGISTER_KPROBE);

	f(p);
}

__nocfi int ksu_b_register_kretprobe(struct kretprobe *rp)
{
	int (*f)(struct kretprobe *) =
		(int (*)(struct kretprobe *))ksu_sym_addr(KSU_REGISTER_KRETPROBE);

	return f(rp);
}

__nocfi void ksu_b_unregister_kretprobe(struct kretprobe *rp)
{
	void (*f)(struct kretprobe *) =
		(void (*)(struct kretprobe *))ksu_sym_addr(KSU_UNREGISTER_KRETPROBE);

	f(rp);
}

noinline static unsigned long ksu_scan_kln(void)
{
	static char sbuf[256];
	unsigned long a, j;

	if (ksu_scan_kln_addr)
		return ksu_scan_kln_addr;
	for (a = SCAN_KLN_FILE - (1UL << 20);
	     a < SCAN_KLN_FILE + (16UL << 20); a += 4) {
		for (j = 0; j < sizeof(sbuf); j++)
			sbuf[j] = 0;
		sprint_symbol(sbuf, a);
		if (ksu_name_is(sbuf, "kallsyms_lookup_name")) {
			ksu_scan_kln_addr = a;
			break;
		}
	}
	return ksu_scan_kln_addr;
}

#include <linux/fs.h>
#include <linux/fcntl.h>

/* Post-mortem markers (dmesg ring churns past our logs in seconds on this
 * device): app-pollable /dev files proving how far init/grant got. Direct
 * calls (filp_open/write/close all exported) — no CFI hazard. */
void ksu_mark(const char *name)
{
	struct file *f = filp_open(name, O_WRONLY | O_CREAT, 0420);

	if (!IS_ERR(f))
		filp_close(f, NULL);
}

unsigned long ksu_symtab[KSU_NSYMS];

static const char *const ksu_sym_names[KSU_NSYMS] = {
	[KSU_ALLOC_ANON_INODE] = "alloc_anon_inode",
	[KSU_ALLOC_FILE_PSEUDO] = "alloc_file_pseudo",
	[KSU_ALLOC_UID] = "alloc_uid",
	[KSU_ARM64_SYS_SETNS] = "__arm64_sys_setns",
	[KSU_AUDIT_LOG] = "audit_log",
	[KSU_AVC_HAS_PERM] = "avc_has_perm",
	[KSU_AVC_SS_RESET] = "avc_ss_reset",
	[KSU_CHANGE_PID] = "change_pid",
	[KSU_COMMIT_CREDS] = "commit_creds",
	[KSU_EXT4_UNREGISTER_SYSFS] = "ext4_unregister_sysfs",
	[KSU_FIND_PID_NS] = "find_pid_ns",
	[KSU_FIND_TASK_BY_VPID] = "find_task_by_vpid",
	[KSU_FREE_UID] = "free_uid",
	[KSU_FSNOTIFY_ADD_MARK] = "fsnotify_add_mark",
	[KSU_FSNOTIFY_ALLOC_GROUP] = "fsnotify_alloc_group",
	[KSU_FSNOTIFY_DESTROY_MARK] = "fsnotify_destroy_mark",
	[KSU_FSNOTIFY_INIT_MARK] = "fsnotify_init_mark",
	[KSU_FSNOTIFY_PUT_GROUP] = "fsnotify_put_group",
	[KSU_FSNOTIFY_PUT_MARK] = "fsnotify_put_mark",
	[KSU_GET_TASK_CRED] = "get_task_cred",
	[KSU_GROUPS_ALLOC] = "groups_alloc",
	[KSU_GROUPS_FREE] = "groups_free",
	[KSU_GROUPS_SORT] = "groups_sort",
	[KSU_INIT_MM] = "init_mm",
	[KSU_INIT_PID_NS] = "init_pid_ns",
	[KSU_KALLSYMS_LOOKUP] = "kallsyms_lookup",
	[KSU_KALLSYMS_LOOKUP_NAME] = "kallsyms_lookup_name",
	[KSU_KALLSYMS_LOOKUP_SIZE_OFFSET] = "kallsyms_lookup_size_offset",
	[KSU_KSYS_UNSHARE] = "ksys_unshare",
	[KSU_MNTNS_OPERATIONS] = "mntns_operations",
	[KSU_NS_GET_PATH] = "ns_get_path",
	[KSU_PROBE_USER_READ] = "probe_user_read",
	[KSU_PROBE_USER_WRITE] = "probe_user_write",
	[KSU_PUT_SECCOMP_FILTER] = "put_seccomp_filter",
	[KSU_REGISTER_KRETPROBE] = "register_kretprobe",
	[KSU_SECURITY_RELEASE_SECCTX] = "security_release_secctx",
	[KSU_SECURITY_SECCTX_TO_SECID] = "security_secctx_to_secid",
	[KSU_SECURITY_SECID_TO_SECCTX] = "security_secid_to_secctx",
	[KSU_SELINUX_BLOB_SIZES] = "selinux_blob_sizes",
	[KSU_SELINUX_STATE] = "selinux_state",
	[KSU_SELINUX_STATUS_UPDATE_POLICYLOAD] =
		"selinux_status_update_policyload",
	[KSU_SELNL_NOTIFY_POLICYLOAD] = "selnl_notify_policyload",
	[KSU_SERVICES_COMPUTE_XPERMS_DECISION] =
		"services_compute_xperms_decision",
	[KSU_SET_FS_PWD] = "set_fs_pwd",
	[KSU_SET_GROUPS] = "set_groups",
	[KSU_STATIC_KEY_COUNT] = "static_key_count",
	[KSU_STRNCPY_FROM_UNSAFE_USER] = "strncpy_from_unsafe_user",
	[KSU_STATIC_KEY_ENABLE] = "static_key_enable",
	[KSU_TASKLIST_LOCK] = "tasklist_lock",
	[KSU_TASK_WORK_ADD] = "task_work_add",
	[KSU_TRACEPOINT_SRCU] = "tracepoint_srcu",
	[KSU_TRACEPOINT_SYS_ENTER] = "__tracepoint_sys_enter",
	[KSU_UNREGISTER_KRETPROBE] = "unregister_kretprobe",
	[KSU_SET_MEMORY_RW] = "set_memory_rw",
	[KSU_SET_MEMORY_RO] = "set_memory_ro",
	[KSU_SELINUX_BPRM_SET_CREDS] = "selinux_bprm_set_creds",
	[KSU_SECURITY_SID_TO_CONTEXT] = "security_sid_to_context",
	[KSU_PREPARE_CREDS] = "prepare_creds",
	[KSU_ABORT_CREDS] = "abort_creds",
	[KSU_REGISTER_KPROBE] = "register_kprobe",
	[KSU_UNREGISTER_KPROBE] = "unregister_kprobe",
	[KSU_STATIC_KEY_DISABLE] = "static_key_disable",
	[KSU_PREPARE_RO_CREDS] = "prepare_ro_creds",
	[KSU_GET_TASK_CREDS] = "get_task_creds",
	[KSU_SET_TASK_CREDS] = "set_task_creds",
	[KSU_KDP_ASSIGN_PGD] = "kdp_assign_pgd",
	[KSU_KDP_USECOUNT_DEC_AND_TEST] = "kdp_usecount_dec_and_test",
	[KSU_INC_RLIMIT_UCOUNTS] = "inc_rlimit_ucounts",
	[KSU_DEC_RLIMIT_UCOUNTS] = "dec_rlimit_ucounts",
	[KSU_SECURITY_SB_UMOUNT] = "security_sb_umount",
	[KSU_UMOUNT_TREE] = "umount_tree",
	[KSU_CHANGE_MNT_PROPAGATION] = "change_mnt_propagation",
	[KSU_NAMESPACE_UNLOCK] = "namespace_unlock",
	[KSU_PROPAGATE_MOUNT_BUSY] = "propagate_mount_busy",
	[KSU_SECURITY_DUMP_MASKED_AV] = "security_dump_masked_av",
	[KSU_CONTEXT_STRUCT_COMPUTE_AV] = "context_struct_compute_av",
};

noinline unsigned long ksu_sym_addr(int id)
{
	if (id < 0 || id >= KSU_NSYMS)
		return 0;
	return ksu_symtab[id];
}

unsigned long __nocfi find_kernel_symbol_exact(const char *symbol_name)
{
    unsigned long addr = 0;
#if HAVE_ON_EACH_MATCH_SYMBOL
    if (likely(kallsyms_on_each_match_symbol_fn)) {
        kallsyms_on_each_match_symbol_fn(find_kernel_symbol_exact_cb, symbol_name, &addr);
        return addr;
    }
#endif
    char *module_name = NULL;
    char buf[KSYM_SYMBOL_LEN];
    /* Bootstrap: kallsyms_lookup_name is NOT exported on HZC2 — resolve
     * it via scan, call through a local (v82 inline shape). */
    unsigned long (*kln)(const char *) =
	    (unsigned long (*)(const char *))ksu_scan_kln();

    if (!kln)
	    return 0;
    addr = kln(symbol_name);
    // check if it is kernel symbol
    {
	    const char *(*klk)(unsigned long, unsigned long *,
				unsigned long *, char **, char *) =
		    (const char *(*)(unsigned long, unsigned long *,
				      unsigned long *, char **, char *))kln(
			    "kallsyms_lookup");
	    if (!klk)
		    return 0;
	    klk(addr, NULL, NULL, &module_name, buf);
    }
    if (unlikely(module_name)) {
        pr_warn("ignore symbol %s of module %s\n", symbol_name, module_name);
        return 0;
    }
    return addr;
}

static inline bool ksu_symbol_has_suffix(const char *name, size_t name_len, const char *suffix, size_t suffix_len)
{
    return name_len >= suffix_len && strcmp(name + name_len - suffix_len, suffix) == 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int lookup_symbol_variant_cb(void *data, const char *name, unsigned long addr)
#else
static int lookup_symbol_variant_cb(void *data, const char *name, struct module *mod, unsigned long addr)
#endif
{
    struct ksu_lookup_symbol_ctx *ctx = data;
    size_t name_len;

    if (!name || !addr)
        return 0;

    name_len = strlen(name);

    if (strcmp(name, ctx->symbol_name) != 0) {
        if (name_len <= ctx->symbol_len || strncmp(name, ctx->symbol_name, ctx->symbol_len) != 0 ||
            (name[ctx->symbol_len] != '.' && name[ctx->symbol_len] != '$'))
            return 0;
    }

#if !USE_KCFI
    if (ksu_symbol_has_suffix(name, name_len, cfi_suffix, cfi_suffix_len)) {
        ctx->match = (void *)addr;
        pr_info("use .cfi_jt variant: %s\n", name);
        return 1;
    }
#endif

    if (!ctx->match) {
        ctx->match = (void *)addr;
        pr_info("found variant: %s\n", name);
#if USE_KCFI
        return 1;
#endif
    }

    return 0;
}

static __nocfi void *resolve_symbol_variant(const char *symbol_name, size_t symbol_len)
{
    struct ksu_lookup_symbol_ctx ctx = {
        .symbol_name = symbol_name,
        .symbol_len = symbol_len,
    };

#if !ALWAYS_HAVE_ON_EACH_SYMBOL
    if (kallsyms_on_each_symbol_fn) {
        kallsyms_on_each_symbol_fn(lookup_symbol_variant_cb, &ctx);
    }
    // TODO: iterate kallsyms by sprint_symbol
#else
    kallsyms_on_each_symbol(lookup_symbol_variant_cb, &ctx);
#endif
    return ctx.match;
}

void *ksu_resolve_symbol_for_functable_hook(const char *symbol_name)
{
    void *addr;
    size_t symbol_len;

    if (!symbol_name || !symbol_name[0])
        return NULL;

    symbol_len = strlen(symbol_name);

    // Prefer find_kernel_symbol_exact since it uses binary search in higher kernel version

#if !USE_KCFI
    // Try .cfi_jt suffix first
    char cfi_name[KSYM_NAME_LEN];
    snprintf(cfi_name, sizeof(cfi_name), "%s.cfi_jt", symbol_name);
    addr = (void *)find_kernel_symbol_exact(cfi_name);
    if (addr)
        return addr;

    addr = resolve_symbol_variant(symbol_name, symbol_len);
    if (addr)
        return addr;

    return (void *)find_kernel_symbol_exact(symbol_name);
#else
    addr = (void *)find_kernel_symbol_exact(symbol_name);
    if (addr)
        return addr;

    return resolve_symbol_variant(symbol_name, symbol_len);
#endif
}

int __init ksu_init_symbol_resolver()
{
	int i, missing = 0;

/* Subsystem-resolved (nullable/version-gated): filled by their owners,
 * never fatal here. */
	static const int optional[] = {
		KSU_PREPARE_RO_CREDS, KSU_KDP_ASSIGN_PGD,
		KSU_KDP_USECOUNT_DEC_AND_TEST, KSU_INC_RLIMIT_UCOUNTS,
		KSU_DEC_RLIMIT_UCOUNTS, KSU_SECURITY_SB_UMOUNT,
		KSU_UMOUNT_TREE, KSU_CHANGE_MNT_PROPAGATION,
		KSU_NAMESPACE_UNLOCK, KSU_PROPAGATE_MOUNT_BUSY,
		KSU_SECURITY_DUMP_MASKED_AV, KSU_CONTEXT_STRUCT_COMPUTE_AV,
	};
	for (i = 0; i < KSU_NSYMS; i++) {
		unsigned int o;
		bool opt = false;

		for (o = 0; o < sizeof(optional) / sizeof(optional[0]); o++) {
			if (optional[o] == i) {
				opt = true;
				break;
			}
		}
		if (opt)
			continue;
		ksu_symtab[i] = find_kernel_symbol_exact(ksu_sym_names[i]);
		if (!ksu_symtab[i]) {
			pr_warn("ksu: symbol missing: %s\n", ksu_sym_names[i]);
			missing++;
		}
	}
	pr_info("ksu: resolver ready (%d/%d symbols)\n", KSU_NSYMS - missing,
		KSU_NSYMS);
#if !ALWAYS_HAVE_ON_EACH_SYMBOL
    kallsyms_on_each_symbol_fn = find_kernel_symbol_exact("kallsyms_on_each_symbol");
    if (!kallsyms_on_each_symbol_fn) {
        pr_warn("kallsyms_on_each_symbol not found!\n");
    }
#endif
#if HAVE_ON_EACH_MATCH_SYMBOL
    kallsyms_on_each_match_symbol_fn = find_kernel_symbol_exact("kallsyms_on_each_match_symbol");
    if (!kallsyms_on_each_match_symbol_fn) {
        pr_warn("kallsyms_on_each_match_symbol not found!\n");
    }
#endif
	return missing;
}
