#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include "compat/samsung_defex.h"
#include "infra/symbol_resolver.h"
#include "klog.h"
#include "policy/allowlist.h"
#include "selinux/selinux.h"
extern bool ksu_no_kprobe;

#ifdef CONFIG_KSU_SAMSUNG_DEFEX
/* Exported on HZC2 (not trimmed): call directly (no CFI hazard).
 * Prototypes verbatim from defex_internal.h:111-112. */
extern void get_task_creds(struct task_struct *p, unsigned int *uid_ptr,
			   unsigned int *fsuid_ptr, unsigned int *egid_ptr,
			   unsigned short *cred_flags_ptr);
extern int set_task_creds(struct task_struct *p, unsigned int uid,
			  unsigned int fsuid, unsigned int egid,
			  unsigned short cred_flags);
static bool defex_enforce_hooked;
static bool defex_rules_hooked;
static u8 *defex_unlock_cell;
static bool defex_unlocked_by_ksu;
bool ksu_defex_bypass = false;
module_param_named(defex_bypass, ksu_defex_bypass, bool, 0);
MODULE_PARM_DESC(defex_bypass,
	"Register task_defex_enforce + rules_lookup bypass probes. Off by "
	"default: probe registration patches text (BRK) and HARDLOCKUPs on "
	"RKP kernels (S21 HZC2: patch_text stop-machine hang -> WDT reset). "
	"Only for unlocked-BL kernels without RKP text protection.");

static int ksu_samsung_defex_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    struct task_struct *task = (struct task_struct *)regs->regs[0];

    (void)probe;
    if (task == current && current_uid().val == 0 &&
        (is_ksu_domain() || is_shell_domain()))
        regs->regs[0] = 0;

    return 0;
}

static struct kprobe defex_enforce_kprobe = {
    .symbol_name = "task_defex_enforce",
    .pre_handler = ksu_samsung_defex_pre_handler,
};

/* task_defex_user_exec: first arg is the EXEC'D PATH (goes straight into
 * local_fopen->filp_open), so nulling regs[0] is not safe there. Instead
 * force its sub-check "rules_lookup(path, 0x800, ...)" to report a rule
 * hit (nonzero == allow): kretprobe rewrites the return value. Only for
 * root-ksu tasks (uid 0 + ksu/shell domain); everyone else unaffected.
 * Verified on HZC2 disasm: cbz w0 -> allow-return in user_exec; rules
 * lookup nonzero return == allow; boot_state_unlocked (+0x3ed) and rules_ready (+0x3f6)
 * gate the raw early returns. */
static int ksu_samsung_rules_ret_handler(struct kretprobe_instance *ri,
					 struct pt_regs *regs)
{
    (void)ri;
    if (current_uid().val == 0 && (is_ksu_domain() || is_shell_domain()))
        regs->regs[0] = 1;
    return 0;
}
static struct kretprobe defex_rules_retprobe = {
    .kp = { .symbol_name = "rules_lookup" },
    .handler = ksu_samsung_rules_ret_handler,
};

/* ===== dpolicy runtime injection (kprobe-free / text-patch-free) =====
 * Source: kernel security/samsung/defex_lsm/core/defex_rules_proc.c.
 * lookup_tree() routes every path with a /system/, /product/, /apex/,
 * /system_ext/ or /postinstall/system/ prefix into the SECONDARY tree
 * (packed_rules_secondary, a plain .bss POINTER) and only falls back to
 * the RKP-guarded __ro_after_init primary array when the secondary is
 * empty. Nothing re-verifies a loaded blob after boot, so we may build
 * a private copy of the active tree, APPEND leaves that whitelist our
 * own binaries (feature_safeplace_path + feature_ped_exception), and
 * atomically repoint packed_rules_secondary at it. Only .bss/vmalloc
 * writes - no BRK, no stop-machine, no RKP page: safe on locked-BL
 * HZC2. NON-system lookups (e.g. under /data) still hit the read-only
 * primary tree, so /data binaries stay blocked - this is an is_system
 * escape hatch, not a global one. */
enum {
    DP_FEAT_IS_FILE         = 1u,
    DP_FEAT_PED_EXCEPTION   = 8u,
    DP_FEAT_SAFEPLACE_PATH  = 32u,
    DP_LOAD_SYSTEM_FIRST    = 0x04, /* defex_rules_proc.c:33 */
};

/* Packed item: u16 next_level@0, u16 next_file@2, u16 feature_type@4,
 * u8 size@6, [integrity[32] if compiled in], name@item_size. Root item
 * reuses bytes 2..5 as u32 data_size and its next_level is
 * item_size + 16 ("DEFEX_RULES_FILE" name length), which is how we
 * detect whether the device kernel was built with DEFEX_INTEGRITY
 * (item_size 39) or without (item_size 7). */
#define DP_ROOT_NAME 16

static bool ksu_dpolicy_inject = false;
module_param_named(dpolicy_inject, ksu_dpolicy_inject, bool, 0);
MODULE_PARM_DESC(dpolicy_inject,
	"Append safeplace+ped_exception leaves for dpolicy_inject_paths "
	"into a private copy of the DEFEX secondary rules tree and swap "
	"packed_rules_secondary. Data-only, kprobe-free, locked-BL safe.");

static char *dpolicy_inject_paths =
	"/data/adb/ksu/bin/su:/data/adb/ksu/bin/busybox"
	":/data/adb/ksu/bin/ksud"
	":/system_ext/bin/su:/system_ext/bin/busybox"
	":/system/system_ext/bin/su:/system/system_ext/bin/busybox"
	":/system_ext/bin/ksud:/system/system_ext/bin/ksud"
	":/data/:/mnt/"
	":/system/:/system_ext/:/vendor/:/product/:/odm/:/apex/";
module_param_named(dpolicy_inject_paths, dpolicy_inject_paths, charp, 0644);
MODULE_PARM_DESC(dpolicy_inject_paths,
	"Colon-separated trusted exec paths to whitelist in the injected "
	"tree (TARGETS WILL BE READABLE/EXEC AS ROOT, keep tight).");

static u16 dp_get16(const u8 *p)
{
	u16 v;
	memcpy(&v, p, 2);
	return v;
}

static void dp_set16(u8 *p, u16 v)
{
	memcpy(p, &v, 2);
}

/* Root item: bytes 2..5 = u32 data_size (total payload size). */
static u32 dp_root_size(const u8 *root)
{
	u32 v;
	memcpy(&v, root + 2, 4);
	return v;
}

/* Children chain: parent->next_level is the first child offset,
 * sibling links live in child->next_file (pack_rules.c:215-233). */
static u32 dp_find_child(const u8 *blob, const u8 *parent,
			 const char *name, u16 l, u32 isz)
{
	u32 off = dp_get16(parent);
	u32 n;

	if (!off)
		return 0;
	for (n = 1; off; n++) {
		const u8 *it = blob + off;

		if (it[6] == l && !memcmp(it + isz, name, l))
			return off;
		off = dp_get16(it + 2);
		if (n > 8192) /* corrupt chain guard */
			return 0;
	}
	return 0;
}

/* Does a dir-wildcard already cover this directory? Walks `dir` through
 * the blob the same way rules_lookup does: any ancestor (or the dir
 * itself) carrying the exec bits = covered; reaching the dir end without
 * bits = not covered (a file under it would fall out of the walk
 * unfeatured). Blob ownership = current *packed_rules_secondary (old
 * buffers stay valid behind a swap, no lock needed for reads). */
static int dp_covered(const u8 *blob, const u8 *parent,
		      const char *dir, u32 isz)
{
	const char *p = dir;
	u32 off;

	if (!blob || !parent || *p != '/')
		return 0;
	p++;
	for (;;) {
		const char *sep = strchr(p, '/');
		size_t l = sep ? (size_t)(sep - p) : strlen(p);

		if (!l)
			return 0;
		off = dp_find_child(blob, parent, p, (u16)l, isz);
		if (!off)
			return 0;
		if (dp_get16(blob + off + 4) &
		    (DP_FEAT_PED_EXCEPTION | DP_FEAT_SAFEPLACE_PATH))
			return 1;
		if (!sep)
			return 0;
		p = sep + 1;
		if (!*p)
			return 0;
		parent = blob + off;
	}
}/* Append one item (dir or file leaf) at the end of the private blob and
 * hang it into parent's child chain. */
static u32 dp_append(u8 *blob, u32 cap, u32 *sz, u8 *parent,
		     const char *name, u16 l, u32 isz, u16 feature)
{
	u32 off = *sz;
	u8 *it;

	/* tree offsets (next_level/next_file) are u16 - never put an item
	 * past 64KB or the in-kernel lookup will wrap. */
	if (off > 0xfffe)
		return 0;
	if (*sz + isz + l > cap)
		return 0; /* headroom exhausted; caller aborts before swap */
	it = blob + off;
	u32 first = dp_get16(parent);
	u32 sib;

	memset(it, 0, isz);
	dp_set16(it + 4, feature);
	it[6] = (u8)l;
	memcpy(it + isz, name, l);
	*sz += isz + l;

	if (!first) {
		dp_set16(parent, (u16)off);
	} else {
		const u8 *c = blob + first;
		u32 n;

		for (n = 0; n < 8192; n++) {
			sib = dp_get16(c + 2);
			if (!sib)
				break;
			c = blob + sib;
		}
		dp_set16((u8 *)c + 2, (u16)off);
	}
	return off;
}

/* Whitelist one absolute path. Intermediate segments become feature-0
 * dir items if missing (kernel lookup_dir returns dir items before
 * touching feature bits); the last segment gets
 * feature_is_file|ped_exception|safeplace_path so BOTH the root-exec
 * safeplace check (task_defex_safeplace, real creds) and the
 * already-running-root PED exception check (task_defex_is_secured)
 * accept it. Feature lookup return value is the item offset, i.e. any
 * nonzero = allow. */
static int dp_whitelist(u8 *blob, u32 cap, u32 *sz, u32 isz, const char *path)
{
	const char *p = path;
	u8 *parent = blob; /* root item */
	u32 off;

	if (*p != '/') {
		pr_info("dpolicy inject: skip '%s' (not absolute)\n", path);
		return 0;
	}
	p++;
	for (;;) {
		const char *sep = strchr(p, '/');
		size_t l = sep ? (size_t)(sep - p) : strlen(p);
		bool leaf = !sep;
		/* trailing slash: wildcard dir item - exec bits on the DIR
		 * itself make rules_lookup early-return allow for EVERY
		 * path under it (walker checks the matched item's feature
		 * before descending), no per-file whitelist needed */
		bool wild = sep && !sep[1];
		const char *tmp;

		if (!l) {
			pr_info("dpolicy inject: skip '%s' (empty segment)\n", path);
			return 0;
		}
		if (l > 255)
			return 0;

		off = dp_find_child(blob, parent, p, (u16)l, isz);
		if (leaf && off) {
			u16 feat = dp_get16(blob + off + 4);

			feat |= (u16)(DP_FEAT_IS_FILE | DP_FEAT_PED_EXCEPTION |
				      DP_FEAT_SAFEPLACE_PATH);
			dp_set16(blob + off + 4, feat);
			return 1;
		}
		if (leaf) {
			off = dp_append(blob, cap, sz, parent, p, (u16)l, isz,
					(u16)(DP_FEAT_IS_FILE |
					      DP_FEAT_PED_EXCEPTION |
					      DP_FEAT_SAFEPLACE_PATH));
		} else if (wild && off) {
			/* existing dir item: add the exec bits in place */
			u16 feat = dp_get16(blob + off + 4);

			feat |= (u16)(DP_FEAT_PED_EXCEPTION |
				      DP_FEAT_SAFEPLACE_PATH);
			dp_set16(blob + off + 4, feat);
			return 1;
		} else if (!off) {
			off = dp_append(blob, cap, sz, parent, p, (u16)l, isz,
					wild ? (u16)(DP_FEAT_PED_EXCEPTION |
						     DP_FEAT_SAFEPLACE_PATH)
					     : 0);
		}
		if (!off)
			return 0;
		parent = blob + off;
		if (leaf)
			return 1;
		if (wild)
			return 1;

		tmp = p + l;
		p = *tmp ? tmp + 1 : tmp;
	}
}

static void ksu_dpolicy_inject_run(void)
{
	u8 *primary = (u8 *)find_kernel_symbol_exact("packed_rules_primary");
	u8 **secondary = (u8 **)find_kernel_symbol_exact("packed_rules_secondary");
	u32 *load_flags = (u32 *)find_kernel_symbol_exact("load_flags");
	u8 *src, *nbuf;
	u32 isz, srcsz, sz, headroom;
	const char *q, *s;

	if (!primary || !secondary) {
		pr_info("dpolicy inject: symbols not resolved "
			"(primary=%px secondary=%px), skipped\n",
			primary, secondary);
		return;
	}
	if (load_flags && (*load_flags & DP_LOAD_SYSTEM_FIRST)) {
		pr_info("dpolicy inject: LOAD_FLAG_SYSTEM_FIRST set, tree "
			"layout differs, skipped\n");
		return;
	}

	src = *secondary ? *secondary : primary;
	srcsz = dp_root_size(src);
	isz = dp_get16(src) - DP_ROOT_NAME;

	if (memcmp(src + isz, "DEFEX_RULES_FILE", 16) != 0 || src[6] != 16) {
		pr_info("dpolicy inject: root header mismatch, skipped "
			"(isz=%u data_size=%u)\n", isz, srcsz);
		return;
	}
	if (isz != 7 && isz != 39) {
		pr_info("dpolicy inject: unexpected item size %u, skipped\n", isz);
		return;
	}
	if (srcsz < isz * 4 || srcsz > (32u << 20)) {
		pr_info("dpolicy inject: bad blob size %u, skipped\n", srcsz);
		return;
	}
	pr_info("dpolicy inject: src=%s data_size=%u item_size=%u paths='%s'\n",
		*secondary ? "secondary" : "primary(fallback)", srcsz, isz,
		dpolicy_inject_paths ? dpolicy_inject_paths : "(null)");

	/* headroom: exact bound - for each path segment we may append one
	 * item costing item_size + segment name bytes (plus slack).
	 * Previously this was 4*256*(isz+260) (~300KB) per injection; the
	 * allocation is intentional (old buffer stays alive so in-flight
	 * rules_lookup walkers keep a valid tree), so keep the vmalloc
	 * leak bounded by making it small. */
	headroom = 64;
	q = dpolicy_inject_paths ?: "";
	while (*q) {
		const char *end;

		for (end = q; *end && *end != ':'; end++)
			;
		for (s = q; s < end && *s; ) {
			const char *sep = strchr(s, '/');

			if (sep && sep < end)
				s = sep + 1;
			else
				s = end;
			headroom += isz + 64;
		}
		q = *end ? end + 1 : end;
	}
	if (headroom < 4096)
		headroom = 4096;
	/* tree offsets are u16: never plan past 64KB even for huge blobs */
	if (srcsz + headroom > 0xfffe)
		headroom = 0xfffe - srcsz;
	nbuf = vmalloc(srcsz + headroom);
	if (!nbuf) {
		pr_info("dpolicy inject: vmalloc failed, skipped\n");
		return;
	}
	memcpy(nbuf, src, srcsz);
	sz = srcsz;
	/* Zero the append slack BEFORE walking/appending: stale sibling
	 * links (from earlier, smaller-sz trees) then read zeroed items
	 * and terminate, instead of chasing uninitialized vmalloc bytes
	 * (hardware hardlockup in rules_lookup). */
	memset(nbuf + sz, 0, headroom);
	for (q = dpolicy_inject_paths; *q; q++) {
		/* colon is our separator; slice one run */
		const char *e = q;

		while (*e && *e != ':')
			e++;
		if (e != q) {
			/* dp_whitelist needs NUL-terminated path */
			char tmp[256];
			size_t len = (size_t)(e - q);

			if (len >= sizeof(tmp))
				goto next;
			memcpy(tmp, q, len);
			tmp[len] = 0;
			if (dp_whitelist(nbuf, srcsz + headroom, &sz, isz, tmp))
				pr_info("dpolicy inject: whitelisted '%s'\n", tmp);
			else
				pr_info("dpolicy inject: FAILED '%s'\n", tmp);
		}
next:
		q = e;
		if (!*q)
			break;
	}

	/* Single atomic repoint; the old blob (if any) is left alive so
	 * in-flight lookups keep a valid tree behind the swapped
	 * pointer. Sources read = boot phase data, no lock held.
	 * Root data_size is kept == final tree size so later re-injectors
	 * never copy a truncated bound. */
	dp_set16(nbuf + 2, sz);
	smp_wmb();
	*secondary = nbuf;
	smp_wmb();
	pr_info("dpolicy inject: packed_rules_secondary -> %px "
		"(grow %u -> %u bytes)\n",
		nbuf, srcsz, sz);
}

/* Runtime re-injection: the app (uid 0) may extend the whitelist after
 * boot by writing dpolicy_inject_paths then echoing 1 into the trigger
 * param. The run copies the CURRENT secondary blob, so earlier
 * injections persist; unchanged runs keep the previous buffer. */
static bool dp_inject_active = false;
static DEFINE_MUTEX(dp_inject_lock);

static int dp_inject_trigger_set(const char *val, const struct kernel_param *kp)
{
	int v = 0;

	if (!dp_inject_active)
		return 0; /* bypass trigger before module init completes */
	if (val && kstrtoint(val, 0, &v) < 0)
		return -EINVAL;
	if (v == 0)
		return 0;
	mutex_lock(&dp_inject_lock);
	ksu_dpolicy_inject_run();
	mutex_unlock(&dp_inject_lock);
	return 0;
}

static const struct kernel_param_ops dp_inject_trigger_ops = {
	.set = dp_inject_trigger_set,
};
module_param_cb(dpolicy_inject_trigger, &dp_inject_trigger_ops, NULL, 0644);
MODULE_PARM_DESC(dpolicy_inject_trigger,
	"Write 1 to re-run the injection with the current "
	"dpolicy_inject_paths (runtime whitelist extension).");

/* procfs runtime trigger. The module kobject is deleted at init
 * (core/init.c kobject_del, anti-detection), so the sysfs parameter
 * files above never appear in /sys/module/kernelsu on device. The
 * procfs entry lives outside that kobject and therefore survives:
 * uid-0 writers echo "path1:path2" (replace) or "+path" (append) to
 * /proc/ksu_dpi; each write re-runs the tree rebuild against the
 * CURRENT secondary blob, so earlier injections persist. */
static bool dp_paths_heap;

static int dp_paths_update(const char *newlist, bool append)
{
	char *old = dpolicy_inject_paths;
	size_t cl = old ? strlen(old) : 0;
	size_t al = strlen(newlist) + 1;
	char *ns = kmalloc(cl + al + 2, GFP_KERNEL);

	if (!ns)
		return -ENOMEM;
	if (append && cl)
		snprintf(ns, cl + al + 2, "%s:%s", old, newlist);
	else
		snprintf(ns, cl + al + 2, "%s", newlist);
	if (dp_paths_heap && old)
		kfree(old);
	dpolicy_inject_paths = ns;
	dp_paths_heap = true;
	return 0;
}

static ssize_t dp_inject_proc_write(struct file *f, const char __user *ubuf,
				    size_t len, loff_t *off)
{
	char *tmp;
	size_t clen = len;

	if (!dp_inject_active)
		return -ENODEV; /* init not finished */
	if (len == 0 || len > 2000)
		return -EINVAL;
	tmp = kmalloc(len + 1, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;
	if (copy_from_user(tmp, ubuf, len)) {
		kfree(tmp);
		return -EFAULT;
	}
	tmp[len] = 0;
	while (clen && (tmp[clen - 1] == '\n' || tmp[clen - 1] == '\r'))
		tmp[--clen] = 0;
	if (!clen) {
		kfree(tmp);
		return -EINVAL;
	}
	if (tmp[0] == '+') {
		if (clen < 2) {
			kfree(tmp);
			return -EINVAL;
		}
		if (dp_paths_update(tmp + 1, true)) {
			kfree(tmp);
			return -ENOMEM;
		}
	} else if (dp_paths_update(tmp, false)) {
		kfree(tmp);
		return -ENOMEM;
	}
	kfree(tmp);
	mutex_lock(&dp_inject_lock);
	ksu_dpolicy_inject_run();
	mutex_unlock(&dp_inject_lock);
	return len;
}

static int dp_inject_proc_show(struct seq_file *m, void *v)
{
	mutex_lock(&dp_inject_lock);
	seq_printf(m, "%s\n", dpolicy_inject_paths ?: "(none)");
	mutex_unlock(&dp_inject_lock);
	return 0;
}

static int dp_inject_proc_open(struct inode *inode, struct file *f)
{
	return single_open(f, dp_inject_proc_show, NULL);
}

static const struct file_operations dp_inject_proc_fops = {
	.owner = THIS_MODULE,
	.open = dp_inject_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = dp_inject_proc_write,
};

/* App su-grant auto-whitelist: uid -> allowlist pkg key ->
 * /data/user/<n>/<pkg>/files/ gets a trailing-slash dir-wildcard item so
 * ANY binary the app drops under its own data dir runs as root on the
 * very first exec (no manual /proc/ksu_dpi write needed). Called with
 * the PRE-escape app uid from escape_with_root_profile(). */
static u32 dp_last_injected_uid = 0;

void ksu_dp_inject_app_dir(uid_t uid)
{
	struct app_profile *profile;
	const char *pkg;
	char pathbuf[190];
	size_t i, n;
	u32 usridx = (u32)uid / PER_USER_RANGE;

	if (!dp_inject_active)
		return;
	if (!is_appuid((uid_t)uid))
		return; /* root/shell/system uids irrelevant */
	if ((u32)uid == dp_last_injected_uid)
		return; /* avoid rebuild storm on repeated su calls */

	rcu_read_lock();
	profile = ksu_get_app_profile(uid);
	if (!profile) {
		rcu_read_unlock();
		return;
	}
	pkg = profile->key;
	n = 0;
	while (n < KSU_MAX_PACKAGE_NAME && pkg[n])
		n++;
	if (!n || n > 99)
		pkg = NULL;
	else
		for (i = 0; i < n; i++) {
			unsigned char c = pkg[i];

			if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'z') &&			    !(c >= 'A' && c <= 'Z') && c != '.' && c != '_')
				pkg = NULL;
		}
	if (pkg) {
		i = snprintf(pathbuf, sizeof(pathbuf),
			     "/data/user/%u/%s/files/", usridx, pkg);
	}
	rcu_read_unlock();
	ksu_put_app_profile(profile);
	if (!pkg || i >= sizeof(pathbuf))
		return;

	if (dpolicy_inject_paths &&
	    strstr(dpolicy_inject_paths, pathbuf)) {
		/* already injected (list-level dedup) */
		dp_last_injected_uid = (u32)uid;
		return;
	}
	if (dp_paths_update(pathbuf, true)) {
		pr_info("dpolicy inject: app-dir append OOM for %s\n", pathbuf);
		return;
	}
	mutex_lock(&dp_inject_lock);
	ksu_dpolicy_inject_run();
	mutex_unlock(&dp_inject_lock);
	dp_last_injected_uid = (u32)uid;
	pr_info("dpolicy inject: app-dir wildcard for uid %u '%s'\n",
		(u32)uid, pathbuf);
}

/* JIT exec whitelist (hook runs pre-syscall): a uid-0 process execs an
 * unknown path -> canonicalize to the d_path realpath (DEFEX compares
 * against exactly that), derive the parent dir and grant it a
 * dir-wildcard unless an existing wildcard ancestor already covers it.
 * Only NEW dirs cause a rebuild; covered/common ones are no-ops. */
void ksu_dp_jit_execve(const char __user *upath)
{
	static u8 **secondary_sym;
	static int resolved;
	u8 **secondary;
	u8 *blob;
	struct path spath;
	char *parent;
	char pathbuf[256];
	char *buf, *canon;
	size_t pl;
	ssize_t ret;

	if (!dp_inject_active || !resolved) {
		if (!resolved) {
			secondary_sym = (u8 **)find_kernel_symbol_exact(
				"packed_rules_secondary");
			resolved = 1;
		}
		if (!dp_inject_active)
			return;
	}
	if (!upath)
		return;
	ret = strncpy_from_user(pathbuf, upath, sizeof(pathbuf));
	if (ret <= 0)
		return;
	buf = kmalloc(PATH_MAX + 2, GFP_KERNEL);
	if (!buf)
		return;
	if (kern_path(pathbuf, LOOKUP_FOLLOW, &spath)) {
		kfree(buf);
		return;
	}
	canon = d_path(&spath, buf, PATH_MAX);
	path_put(&spath);
	if (IS_ERR(canon))
		goto out;
	parent = strrchr(canon, '/');
	if (!parent || parent == canon) /* "/" or malformed */
		goto out;
	pl = strlen(canon);
	buf[pl] = '/';
	buf[pl + 1] = 0; /* dir string with trailing slash for dp_whitelist */
	secondary = secondary_sym;
	blob = secondary ? (u8 *)*secondary : NULL;
	if (blob) {
		u32 isz2 = dp_get16(blob) - DP_ROOT_NAME;

		if ((isz2 == 7 || isz2 == 39) &&
		    dp_covered(blob, blob, buf, isz2)) {
			/* wildcard ancestor (e.g. /data/, /mnt/, /system/)
			 * already grants everything below - no rebuild */
			goto out;
		}
	}
	if (dp_paths_update(buf, false))
		goto out;
	mutex_lock(&dp_inject_lock);
	ksu_dpolicy_inject_run();
	mutex_unlock(&dp_inject_lock);
	pr_info("dpolicy inject: jit exec dir '%s'\n", buf);
out:
	kfree(buf);
	return;
}



#endif /* CONFIG_KSU_SAMSUNG_DEFEX */

int ksu_samsung_defex_init(void)
{
#ifdef CONFIG_KSU_SAMSUNG_DEFEX
    int ret;

    /* dpolicy injection first: pure data writes (.bss pointer + private
     * vmalloc copy), no probes, no text patching. Runs on any boot
     * state, locked-BL safe on HZC2. */
    if (ksu_dpolicy_inject) {
        ksu_dpolicy_inject_run();
        pr_info("dpolicy inject: complete (probes untouched)\n");
    }
    dp_inject_active = true; /* runtime re-inject trigger now live */
    if (!proc_create("ksu_dpi", 0600, NULL, &dp_inject_proc_fops))
        pr_info("dpolicy inject: proc trigger create failed\n");
    else
        pr_info("dpolicy inject: runtime trigger /proc/ksu_dpi ready\n");

    /* DEFEX kill-switch status (read-only probe): task_defex_user_exec /
     * enforce return early when boot_state_unlocked != 0. All kernel-side
     * write paths proven blocked on HZC2: direct store panics (9600004e),
     * linear alias also RO, set_memory_rw refuses (-22), fixmap helpers
     * unexported, own-PTE flip halts the CPU (RKP-g-guarded pagetables).
     * Write must come from the exploit side (see df_stager) or via a
     * DEFEX rule injection. This block only reports. */
    {
        unsigned long addr = find_kernel_symbol_exact("boot_state_unlocked");
        if (addr) {
            defex_unlock_cell = (u8 *)addr;
            pr_info("defex unlock: boot_state_unlocked=%u (read-only)\n",
                *defex_unlock_cell);
        } else {
            pr_info("defex unlock: boot_state_unlocked not resolved\n");
        }
    }

    /* Locate defex_get_features and dump its head for offline analysis
     * (DEFEX kill-switch hunt; reads only, no writes). */
    {
        unsigned long addr = find_kernel_symbol_exact("defex_get_features");
        if (addr) {
            unsigned char *p = (unsigned char *)addr;
            pr_info("defex_get_features @ %px: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                (void *)addr,
                p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
                p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
            /* The function reads two flag bytes via adrp+ldrb; decode the
             * page here and dump their live values. adrp is at +0. */
            {
                u32 insn;
                unsigned long page;
                unsigned char *f0;
                /* read adrp safely (text is readable) */
                insn = *(volatile u32 *)addr;
                /* adrp: page = (pc & ~0xfff) + (immhi:immlo << 12) */
                page = (addr & ~0xfffUL) +
                    ((((insn >> 5) & 0x7ffffUL) << 2) |
                     ((insn >> 29) & 0x3UL)) * 0x1000UL;
                /* imm12 of the two ldrb is read from the image layout
                 * (1136/1140 on HZC2); dump a window instead of trusting
                 * hardcoded offsets. */
                f0 = (unsigned char *)(page + 0x440UL);
                pr_info("defex flags page %px +0x440: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                    (void *)page,
                    f0[0], f0[1], f0[2], f0[3], f0[4], f0[5], f0[6], f0[7],
                    f0[8], f0[9], f0[10], f0[11], f0[12], f0[13], f0[14], f0[15],
                    f0[16], f0[17], f0[18], f0[19], f0[20], f0[21], f0[22], f0[23],
                    f0[24], f0[25], f0[26], f0[27], f0[28], f0[29], f0[30], f0[31],
                    f0[32], f0[33], f0[34], f0[35], f0[36], f0[37], f0[38], f0[39],
                    f0[40], f0[41], f0[42], f0[43], f0[44], f0[45], f0[46], f0[47],
                    f0[48], f0[49], f0[50], f0[51], f0[52], f0[53], f0[54], f0[55],
                    f0[56], f0[57], f0[58], f0[59], f0[60], f0[61], f0[62], f0[63]);
            }
        } else {
            pr_info("defex_get_features not resolved\n");
        }
        /* Cred-flag exemption probe: dump check/set cred helpers. */
        {
            unsigned long caddr = find_kernel_symbol_exact("task_defex_check_creds");
            unsigned long saddr = find_kernel_symbol_exact("set_task_creds");
            unsigned char *p;
            int i;
            pr_info("defex cred helpers: check=%px set=%px\n",
                (void *)caddr, (void *)saddr);
            if (caddr) {
                p = (unsigned char *)caddr;
                for (i = 0; i < 4; i++, p += 16)
                    pr_info("defex check+%d: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                        i * 16, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
                        p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
            }
        }
    }

    /* Register only where enforcement actually runs (boot_state_unlocked
     * == 0, i.e. locked bootloader). Unlocked stays probe-less, as before.
     * defex_bypass=0 is the escape hatch if a probe misbehaves. */
    {
        int want_hook;
        if (defex_unlock_cell) {
            want_hook = (*defex_unlock_cell == 0);
        } else {
            /* unresolved cell (different firmware): decide by param */
            want_hook = ksu_defex_bypass;
        }
        if (!want_hook || !ksu_defex_bypass) {
            pr_info("Samsung DEFEX bypass: skip (unlocked or disabled)\n");
            return 0;
        }
    }

    ret = ksu_b_register_kprobe(&defex_enforce_kprobe);
    if (ret) {
        pr_err("Samsung DEFEX enforce hook unavailable: %d\n", ret);
        return ret;
    }
    defex_enforce_hooked = true;

    ret = ksu_b_register_kretprobe(&defex_rules_retprobe);
    if (ret) {
        pr_err("Samsung DEFEX rules hook unavailable: %d\n", ret);
        ksu_b_unregister_kprobe(&defex_enforce_kprobe);
        defex_enforce_hooked = false;
        return ret;
    }
    defex_rules_hooked = true;

    pr_info("Samsung DEFEX credential synchronization and KSU-task bypass enabled\n");
#endif
    return 0;
}

void ksu_samsung_defex_exit(void)
{
#ifdef CONFIG_KSU_SAMSUNG_DEFEX
    if (defex_unlocked_by_ksu && defex_unlock_cell) {
        defex_unlocked_by_ksu = false;
        pr_info("defex unlock: exit (cell untouched)\n");
    }
    if (defex_rules_hooked) {
        ksu_b_unregister_kretprobe(&defex_rules_retprobe);
        defex_rules_hooked = false;
    }
    if (defex_enforce_hooked) {
        ksu_b_unregister_kprobe(&defex_enforce_kprobe);
        defex_enforce_hooked = false;
    }
#endif
}

void ksu_samsung_defex_sync_current(void)
{
#ifdef CONFIG_KSU_SAMSUNG_DEFEX
    const struct cred *cred = current_cred();
    unsigned int stored_uid;
    unsigned int stored_fsuid;
    unsigned int stored_egid;
    unsigned short cred_flags;
    int ret;

    ksu_b_get_task_creds(current, &stored_uid, &stored_fsuid, &stored_egid, &cred_flags);

    if (__kuid_val(cred->euid) == 0 && __kuid_val(cred->fsuid) == 0 && __kgid_val(cred->egid) == 0) {
        stored_uid = 1;
        stored_fsuid = 1;
        stored_egid = 1;
    } else {
        stored_uid = __kuid_val(cred->euid);
        stored_fsuid = __kuid_val(cred->fsuid);
        stored_egid = __kgid_val(cred->egid);
    }

    ret = ksu_b_set_task_creds(current, stored_uid, stored_fsuid, stored_egid, cred_flags);
    if (ret)
        pr_err("Samsung DEFEX credential synchronization failed: %d\n", ret);
#endif
}
