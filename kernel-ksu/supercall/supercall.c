#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "uapi/supercall.h"
#include "supercall/internal.h"
#include "arch.h"
#include "util.h"
#include "klog.h" // IWYU pragma: keep
#include "infra/symbol_resolver.h"
extern bool ksu_no_kprobe;

struct ksu_install_fd_tw {
    struct callback_head cb;
    int __user *outp;
};

static int anon_ksu_release(struct inode *inode, struct file *filp)
{
    pr_info("ksu fd released\n");
    return 0;
}

static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return ksu_supercall_handle_ioctl(cmd, (void __user *)arg);
}

static const struct file_operations anon_ksu_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = anon_ksu_ioctl,
    .compat_ioctl = anon_ksu_ioctl,
    .release = anon_ksu_release,
};

int ksu_install_fd(void)
{
    struct file *filp;
    int fd;

    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0) {
        pr_err("ksu_install_fd: failed to get unused fd\n");
        return fd;
    }

    filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL, O_RDWR | O_CLOEXEC);
    if (IS_ERR(filp)) {
        pr_err("ksu_install_fd: failed to create anon inode file\n");
        put_unused_fd(fd);
        return PTR_ERR(filp);
    }

    fd_install(fd, filp);
    pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);
    return fd;
}

static void ksu_install_fd_tw_func(struct callback_head *cb)
{
    struct ksu_install_fd_tw *tw = container_of(cb, struct ksu_install_fd_tw, cb);
    int fd = ksu_install_fd();

    pr_info("[%d] install ksu fd: %d\n", current->pid, fd);
    if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
        pr_err("install ksu fd reply err\n");
        ksu_close_fd(fd);
    }

    kfree(tw);
}

/* Manager getVersion fd-taramasiyla ([ksu_driver] readlink) calisir:
 * bu process'te zaten driver fd varsa dokunma, yoksa kur.
 * Atomic-safe (sys_enter'dan cagrilabilir): sadece file_lock + f_op
 * karsilastirma, uyku yok. Syscall girisinde calisir (body henuz
 * kilit almamis olur). */
bool ksu_current_has_driver_fd(void)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	unsigned int i;
	bool found = false;

	if (!files)
		return true;
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	for (i = 0; i < fdt->max_fds; i++) {
		struct file *f = fdt->fd[i];
		if (f && f->f_op == &anon_ksu_fops) {
			found = true;
			break;
		}
	}
	spin_unlock(&files->file_lock);
	return found;
}

static void ksu_mgr_fd_tw_func(struct callback_head *cb)
{
	kfree(cb);
	if (ksu_current_has_driver_fd())
		return;
	pr_info("ksu mgr fd install for pid %d\n", current->pid);
	ksu_install_fd();
}

/* Manager exec'lerinde kuyruga girer (atomik baglamdan cagrilir, sadece
 * kuyruklar; kurulum return-to-user'da, process'in kendi baglaminda). */
int ksu_supercall_install_mgr_fd_async(void)
{
	struct callback_head *cb = kmalloc(sizeof(*cb), GFP_ATOMIC);

	if (!cb)
		return -ENOMEM;
	cb->func = ksu_mgr_fd_tw_func;
	if (ksu_b_task_work_add(current, cb, true)) {
		kfree(cb);
		return -ESRCH;
	}
	return 0;
}

/* RKP-safe fd-install trigger (no kprobe): called from the sys_enter
 * tracepoint on magic reboot(). Queues task_work (sleepable return path)
 * that installs the driver FD + copy_to_user. Replaces reboot_kp. */
int ksu_supercall_install_fd_async(int __user *outp)
{
	struct ksu_install_fd_tw *tw;

	tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw)
		return -ENOMEM;
	tw->outp = outp;
	tw->cb.func = ksu_install_fd_tw_func;
	if (ksu_b_task_work_add(current, &tw->cb, true)) {
		kfree(tw);
		return -ESRCH;
	}
	return 0;
}

static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    int magic1 = (int)PT_REGS_PARM1(real_regs);
    int magic2 = (int)PT_REGS_PARM2(real_regs);

    if (magic1 == KSU_INSTALL_MAGIC1 && magic2 == KSU_INSTALL_MAGIC2) {
        struct ksu_install_fd_tw *tw;
        unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);

        tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
        if (!tw)
            return 0;

        tw->outp = (int __user *)arg4;
        tw->cb.func = ksu_install_fd_tw_func;

        if (ksu_b_task_work_add(current, &tw->cb, true)) {
            kfree(tw);
            pr_warn("install fd add task_work failed\n");
        }
    }

    return 0;
}

static struct kprobe reboot_kp = {
    .symbol_name = REBOOT_SYMBOL,
    .pre_handler = reboot_handler_pre,
};

void __init ksu_supercalls_init(void)
{
    int rc;

    ksu_supercall_dump_commands();

    if (ksu_no_kprobe) {
        pr_info("reboot kprobe skipped (nokprobe)\n");
        return;
    }
    rc = ksu_b_register_kprobe(&reboot_kp);
    if (rc) {
        pr_err("reboot kprobe failed: %d\n", rc);
    } else {
        pr_info("reboot kprobe registered successfully\n");
    }
}

void __exit ksu_supercalls_exit(void)
{
    ksu_b_unregister_kprobe(&reboot_kp);
    ksu_supercall_cleanup_state();
}
