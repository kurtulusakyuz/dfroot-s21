#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/types.h>

#include "feature/kernel_umount.h"
#include "infra/symbol_resolver.h"
#include "klog.h" // IWYU pragma: keep
#include "policy/allowlist.h"
#include "selinux/selinux.h"
#include "policy/feature.h"
#include "runtime/ksud_boot.h"
#include "ksu.h"
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/dcache.h>

/* Boot'ta modul bayragi: /data/adb/modules altinda system/ iceren
 * etkin modul varsa ksu_module_mounted=true (ksud olmadan umount/hide
 * zinciri calissin). Sleepable init baglami, RKP-temasli degil. */
#define KSU_MODULE_SCAN_DIR "/data/adb/modules"

struct ksu_mod_scan_ctx {
	struct dir_context ctx;
	bool found;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static bool ksu_mod_scan_actor(struct dir_context *ctx, const char *name,
			       int namelen, loff_t off, u64 ino,
			       unsigned int d_type)
#else
static int ksu_mod_scan_actor(struct dir_context *ctx, const char *name,
			      int namelen, loff_t off, u64 ino,
			      unsigned int d_type)
#endif
{
	struct ksu_mod_scan_ctx *mc =
		container_of(ctx, struct ksu_mod_scan_ctx, ctx);
	char sub[256];
	struct path p;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define FILLDIR_OK true
#define FILLDIR_STOP false
#else
#define FILLDIR_OK 0
#define FILLDIR_STOP -EINVAL
#endif

	if (namelen <= 2 && (name[0] == '.' &&
	    (namelen == 1 || name[1] == '.')))
		return FILLDIR_OK;
	/* system/ alt-agaci + disable yoksa say */
	if (snprintf(sub, sizeof(sub), KSU_MODULE_SCAN_DIR "/%.*s/system",
		     namelen, name) >= (int)sizeof(sub))
		return FILLDIR_OK;
	if (kern_path(sub, 0, &p) != 0)
		return FILLDIR_OK;
	path_put(&p);
	if (snprintf(sub, sizeof(sub), KSU_MODULE_SCAN_DIR "/%.*s/disable",
		     namelen, name) >= (int)sizeof(sub))
		return FILLDIR_OK;
	if (kern_path(sub, 0, &p) == 0) {
		path_put(&p);
		return FILLDIR_OK;
	}
	mc->found = true;
	return FILLDIR_STOP;
}

static bool ksu_umount_scan_core(void)
{
	struct file *fp;
	struct ksu_mod_scan_ctx mc;
	bool found = false;

	fp = filp_open(KSU_MODULE_SCAN_DIR, O_RDONLY, 0);
	if (IS_ERR(fp))
		return false;
	memset(&mc, 0, sizeof(mc));
	mc.ctx.actor = ksu_mod_scan_actor;
	mc.ctx.pos = 0;
	iterate_dir(fp, &mc.ctx);
	filp_close(fp, 0);
	found = mc.found;
	return found;
}

void __init ksu_umount_scan_modules(void)
{
	if (ksu_umount_scan_core()) {
		ksu_module_mounted = true;
		pr_info("ksu umount: modules present, flag set\n");
	}
}

/* mrun bind listesi: umount hedefleri buradan okunur. Her satir
 * "hedef|modid" (modid yoksa sadece hedef). cacerts satirlari
 * ATLANIR: modulun sagladigi CA dosyalari rootsuz uygulamada da
 * gorunmeli (ornegin ag denetim uygulamasi sertifikasi).
 * Sleepable baglamda cagrilmalidir (task_work/init). */
#define KSU_MOUNTLIST_PATH "/data/adb/mirror/.mounted"

int ksu_umount_add_entry(const char *path, unsigned int flags)
{
	struct mount_entry *entry, *new_entry;

	if (!path || *path != '/')
		return -EINVAL;
	new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
	if (!new_entry)
		return -ENOMEM;
	new_entry->umountable = kstrdup(path, GFP_KERNEL);
	if (!new_entry->umountable) {
		kfree(new_entry);
		return -ENOMEM;
	}
	new_entry->flags = flags;
	down_write(&mount_list_lock);
	list_for_each_entry(entry, &mount_list, list) {
		if (!strcmp(entry->umountable, path)) {
			up_write(&mount_list_lock);
			kfree(new_entry->umountable);
			kfree(new_entry);
			return -EEXIST;
		}
	}
	list_add(&new_entry->list, &mount_list);
	up_write(&mount_list_lock);
	pr_info("ksu umount: list add %s\n", path);
	return 0;
}

void ksu_umount_wipe_list(void)
{
	struct mount_entry *entry, *tmp;

	down_write(&mount_list_lock);
	list_for_each_entry_safe(entry, tmp, &mount_list, list) {
		list_del(&entry->list);
		kfree(entry->umountable);
		kfree(entry);
	}
	up_write(&mount_list_lock);
}

static void ksu_umount_sync_from_mountlist(void)
{
	struct file *fp;
	char *buf;
	loff_t pos = 0;
	ssize_t n;
	char *line, *end;

	buf = kmalloc(4096, GFP_KERNEL);
	if (!buf)
		return;
	fp = filp_open(KSU_MOUNTLIST_PATH, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		kfree(buf);
		return;
	}
	n = kernel_read(fp, buf, 4095, &pos);
	filp_close(fp, 0);
	if (n <= 0) {
		kfree(buf);
		return;
	}
	buf[n] = '\0';
	line = buf;
	while (line && *line) {
		end = strchr(line, '\n');
		if (end)
			*end = '\0';
		/* modid ayraci: hedef '|' oncesi */
		{
			char *sep = strchr(line, '|');

			if (sep)
				*sep = '\0';
		}
		/* bos satir + cacerts (CA gorunurlugu) atla */
		if (*line && !strstr(line, "cacerts"))
			ksu_umount_add_entry(line, 0);
		line = end ? end + 1 : NULL;
	}
	kfree(buf);
}

/* Tembel senkron: setuid tetiginde (sleepable task_work) modul
 * durumunu tazele. ksuev cagrisi gerekmez; kur/kaldir kendiliginden
 * yansır. Modul yoksa bayrak duser + liste bosalir. */
void ksu_umount_sync_state(void)
{
	if (ksu_umount_scan_core()) {
		ksu_module_mounted = true;
		ksu_umount_sync_from_mountlist();
	} else if (ksu_module_mounted) {
		ksu_module_mounted = false;
		ksu_umount_wipe_list();
		pr_info("ksu umount: no modules, flag cleared\n");
	}
}
#include "compat/mount_ns_54.h"

static bool ksu_kernel_umount_enabled = true;

static int kernel_umount_feature_get(u64 *value)
{
    *value = ksu_kernel_umount_enabled ? 1 : 0;
    return 0;
}

static int kernel_umount_feature_set(u64 value)
{
    bool enable = value != 0;
    ksu_kernel_umount_enabled = enable;
    pr_info("kernel_umount: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler kernel_umount_handler = {
    .feature_id = KSU_FEATURE_KERNEL_UMOUNT,
    .name = "kernel_umount",
    .get_handler = kernel_umount_feature_get,
    .set_handler = kernel_umount_feature_set,
};

static void ksu_umount_mnt(const char *mnt, struct path *path, int flags)
{
    int err = ksu_path_umount(path, flags);
    if (err) {
        pr_info("umount %s failed: %d\n", mnt, err);
    }
}

static void try_umount(const char *mnt, int flags)
{
    struct path path;
    int err = kern_path(mnt, 0, &path);
    if (err) {
        return;
    }

    if (path.dentry == path.mnt->mnt_root) {
        ksu_umount_mnt(mnt, &path, flags);
    }

    // kern_path() took a reference on the dentry and vfsmount; always drop it.
    path_put(&path);
}

struct umount_tw {
    struct callback_head cb;
};

int ksu_handle_umount(uid_t old_uid, uid_t new_uid)
{
    // tembel senkron: modul kur/kaldir kendiliginden yansir
    // (ksuev cagrisi gerekmez). sleepable task_work baglami.
    // /data/adb root-only oldugu icin ksu yetkisiyle oku.
    {
        const struct cred *saved = override_creds(ksu_cred);
        ksu_umount_sync_state();
        revert_creds(saved);
    }
    // if there isn't any module mounted, just ignore it!
    if (!ksu_module_mounted) {
        return 0;
    }

    if (!ksu_kernel_umount_enabled) {
        return 0;
    }

    // There are 6 scenarios:
    // 1. Normal app: zygote -> appuid
    // 2. Isolated process forked from zygote: zygote -> isolated_process
    // 3. App zygote forked from zygote: zygote -> appuid
    // 4. Webview zygote forked from zygote: zygote -> WEBVIEW_ZYGOTE_UID (no need to handle, app cannot run custom code)
    // 5. Isolated process forked from app zygote: appuid -> isolated_process (already handled by 3)
    // 6. Isolated process forked from webview zygote (no need to handle, app cannot run custom code)
    if (!is_appuid(new_uid) && !is_isolated_process(new_uid)) {
        return 0;
    }

    if (!ksu_uid_should_umount(new_uid) && !is_isolated_process(new_uid)) {
        return 0;
    }

    // check old process's selinux context, if it is not zygote, ignore it!
    // because some su apps may setuid to untrusted_app but they are in global mount namespace
    // when we umount for such process, that is a disaster!
    // also handle case 4 and 5
    bool is_zygote_child = is_zygote(current_cred());
    if (!is_zygote_child) {
        pr_info("handle umount ignore non zygote child: %d\n", current->pid);
        return 0;
    }
    // umount the target mnt
    pr_info("handle umount for uid: %d, pid: %d\n", new_uid, current->pid);

    const struct cred *saved = override_creds(ksu_cred);

    struct mount_entry *entry;
    down_read(&mount_list_lock);
    list_for_each_entry (entry, &mount_list, list) {
        pr_info("%s: unmounting: %s flags: 0x%x\n", __func__, entry->umountable, entry->flags);
        try_umount(entry->umountable, entry->flags);
    }
    up_read(&mount_list_lock);

    revert_creds(saved);

    return 0;
}

void __init ksu_kernel_umount_init(void)
{
    if (ksu_register_feature_handler(&kernel_umount_handler)) {
        pr_err("Failed to register kernel_umount feature handler\n");
    }
}

/* setuid AILESI tracepoint tetigi (kprobe olu: nokprobe): uid degisimi
 * return-to-user'da task_work ile handle edilir (uyunabilir baglam).
 * Modul yoksa ksu_handle_umount ilk satirda doner (sifir maliyet). */
struct ksu_umu_tw {
	struct callback_head cb;
	uid_t old_uid;
	uid_t new_uid;
};

static void ksu_umount_tw_func(struct callback_head *cb)
{
	struct ksu_umu_tw *tw = container_of(cb, struct ksu_umu_tw, cb);
	uid_t o = tw->old_uid, n = tw->new_uid;

	kfree(tw);
	ksu_handle_umount(o, n);
}

int ksu_umount_async(uid_t old_uid, uid_t new_uid)
{
	struct ksu_umu_tw *tw = kmalloc(sizeof(*tw), GFP_ATOMIC);

	if (!tw)
		return -ENOMEM;
	tw->old_uid = old_uid;
	tw->new_uid = new_uid;
	tw->cb.func = ksu_umount_tw_func;
	if (ksu_b_task_work_add(current, &tw->cb, true)) {
		kfree(tw);
		return -ESRCH;
	}
	return 0;
}

void __exit ksu_kernel_umount_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_KERNEL_UMOUNT);
}
