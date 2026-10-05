/* Auto-generated __nocfi bridges (bulk): unchecked jumps to trimmed
 * (slot-less) targets. See symbol_resolver.c header comment for rationale.
 * Prototypes verbatim from HZC2 headers/source defs. */
#include <linux/audit.h>
#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/user.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/task_work.h>
#include <linux/seccomp.h>
#include <linux/fsnotify_backend.h>
#include <linux/proc_ns.h>
#include <linux/fs_struct.h>
#include <linux/jump_label.h>
#include <linux/security.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include "infra/symbol_resolver.h"
#include "selinux/sepolicy.h"
#include <security.h>
#include <ss/context.h>
#include <ss/services.h>
#include "avc.h"
#include "objsec.h"

__nocfi void ksu_b_avc_ss_reset(struct selinux_avc *avc, u32 seqno)
{
	void (*f)(struct selinux_avc *avc, u32 seqno) =
		(void (*)(struct selinux_avc *avc, u32 seqno))ksu_sym_addr(KSU_AVC_SS_RESET);

	f(avc, seqno);
}

__nocfi void ksu_b_selnl_notify_policyload(u32 seqno)
{
	void (*f)(u32 seqno) =
		(void (*)(u32 seqno))ksu_sym_addr(KSU_SELNL_NOTIFY_POLICYLOAD);

	f(seqno);
}

__nocfi void ksu_b_selinux_status_update_policyload(struct selinux_state *state, int seqno)
{
	void (*f)(struct selinux_state *state, int seqno) =
		(void (*)(struct selinux_state *state, int seqno))ksu_sym_addr(KSU_SELINUX_STATUS_UPDATE_POLICYLOAD);

	f(state, seqno);
}

__nocfi void ksu_b_services_compute_xperms_decision(struct extended_perms_decision *xpermd, struct avtab_node *node)
{
	void (*f)(struct extended_perms_decision *xpermd, struct avtab_node *node) =
		(void (*)(struct extended_perms_decision *xpermd, struct avtab_node *node))ksu_sym_addr(KSU_SERVICES_COMPUTE_XPERMS_DECISION);

	f(xpermd, node);
}

__nocfi void ksu_b_get_task_creds(struct task_struct *p, unsigned int *uid_ptr, unsigned int *fsuid_ptr, unsigned int *egid_ptr, unsigned short *cred_flags_ptr)
{
	void (*f)(struct task_struct *p, unsigned int *uid_ptr, unsigned int *fsuid_ptr, unsigned int *egid_ptr, unsigned short *cred_flags_ptr) =
		(void (*)(struct task_struct *p, unsigned int *uid_ptr, unsigned int *fsuid_ptr, unsigned int *egid_ptr, unsigned short *cred_flags_ptr))ksu_sym_addr(KSU_GET_TASK_CREDS);

	f(p, uid_ptr, fsuid_ptr, egid_ptr, cred_flags_ptr);
}

__nocfi int ksu_b_set_task_creds(struct task_struct *p, unsigned int uid, unsigned int fsuid, unsigned int egid, unsigned short cred_flags)
{
	int (*f)(struct task_struct *p, unsigned int uid, unsigned int fsuid, unsigned int egid, unsigned short cred_flags) =
		(int (*)(struct task_struct *p, unsigned int uid, unsigned int fsuid, unsigned int egid, unsigned short cred_flags))ksu_sym_addr(KSU_SET_TASK_CREDS);

	return f(p, uid, fsuid, egid, cred_flags);
}

__nocfi int ksu_b_commit_creds(struct cred *new)
{
	int (*f)(struct cred *new) =
		(int (*)(struct cred *new))ksu_sym_addr(KSU_COMMIT_CREDS);

	return f(new);
}

__nocfi void ksu_b_abort_creds(struct cred *real)
{
	void (*f)(struct cred *real) =
		(void (*)(struct cred *real))ksu_sym_addr(KSU_ABORT_CREDS);

	f(real);
}

__nocfi struct group_info * ksu_b_groups_alloc(int gidsetsize)
{
	struct group_info * (*f)(int gidsetsize) =
		(struct group_info * (*)(int gidsetsize))ksu_sym_addr(KSU_GROUPS_ALLOC);

	return f(gidsetsize);
}

__nocfi void ksu_b_groups_free(struct group_info *group_info)
{
	void (*f)(struct group_info *group_info) =
		(void (*)(struct group_info *group_info))ksu_sym_addr(KSU_GROUPS_FREE);

	f(group_info);
}

__nocfi void ksu_b_groups_sort(struct group_info *group_info)
{
	void (*f)(struct group_info *group_info) =
		(void (*)(struct group_info *group_info))ksu_sym_addr(KSU_GROUPS_SORT);

	f(group_info);
}

__nocfi void ksu_b_set_groups(struct cred *cred, struct group_info *group_info)
{
	void (*f)(struct cred *cred, struct group_info *group_info) =
		(void (*)(struct cred *cred, struct group_info *group_info))ksu_sym_addr(KSU_SET_GROUPS);

	f(cred, group_info);
}

__nocfi struct user_struct * ksu_b_alloc_uid(kuid_t uid)
{
	struct user_struct * (*f)(kuid_t uid) =
		(struct user_struct * (*)(kuid_t uid))ksu_sym_addr(KSU_ALLOC_UID);

	return f(uid);
}

__nocfi void ksu_b_free_uid(struct user_struct *user)
{
	void (*f)(struct user_struct *user) =
		(void (*)(struct user_struct *user))ksu_sym_addr(KSU_FREE_UID);

	f(user);
}

__nocfi void ksu_b_put_seccomp_filter(struct task_struct *tsk)
{
	void (*f)(struct task_struct *tsk) =
		(void (*)(struct task_struct *tsk))ksu_sym_addr(KSU_PUT_SECCOMP_FILTER);

	f(tsk);
}

__nocfi int ksu_b_task_work_add(struct task_struct *task, struct callback_head *twork, bool notify)
{
	int (*f)(struct task_struct *task, struct callback_head *twork, bool notify) =
		(int (*)(struct task_struct *task, struct callback_head *twork, bool notify))ksu_sym_addr(KSU_TASK_WORK_ADD);

	return f(task, twork, notify);
}

__nocfi const struct cred * ksu_b_get_task_cred(struct task_struct *task)
{
	const struct cred * (*f)(struct task_struct *task) =
		(const struct cred * (*)(struct task_struct *task))ksu_sym_addr(KSU_GET_TASK_CRED);

	return f(task);
}

__nocfi struct task_struct * ksu_b_find_task_by_vpid(pid_t vnr)
{
	struct task_struct * (*f)(pid_t vnr) =
		(struct task_struct * (*)(pid_t vnr))ksu_sym_addr(KSU_FIND_TASK_BY_VPID);

	return f(vnr);
}

__nocfi void ksu_b_change_pid(struct task_struct *task, enum pid_type type, struct pid *pid)
{
	void (*f)(struct task_struct *task, enum pid_type type, struct pid *pid) =
		(void (*)(struct task_struct *task, enum pid_type type, struct pid *pid))ksu_sym_addr(KSU_CHANGE_PID);

	f(task, type, pid);
}

__nocfi struct pid * ksu_b_find_pid_ns(int nr, struct pid_namespace *ns)
{
	struct pid * (*f)(int nr, struct pid_namespace *ns) =
		(struct pid * (*)(int nr, struct pid_namespace *ns))ksu_sym_addr(KSU_FIND_PID_NS);

	return f(nr, ns);
}

__nocfi void * ksu_b_ns_get_path(struct path *path, struct task_struct *task, const struct proc_ns_operations *ns_ops)
{
	void * (*f)(struct path *path, struct task_struct *task, const struct proc_ns_operations *ns_ops) =
		(void * (*)(struct path *path, struct task_struct *task, const struct proc_ns_operations *ns_ops))ksu_sym_addr(KSU_NS_GET_PATH);

	return f(path, task, ns_ops);
}

__nocfi void ksu_b_set_fs_pwd(struct fs_struct *fs, const struct path *path)
{
	void (*f)(struct fs_struct *fs, const struct path *path) =
		(void (*)(struct fs_struct *fs, const struct path *path))ksu_sym_addr(KSU_SET_FS_PWD);

	f(fs, path);
}

__nocfi long ksu_b_ksys_unshare(unsigned long unshare_flags)
{
	long (*f)(unsigned long unshare_flags) =
		(long (*)(unsigned long unshare_flags))ksu_sym_addr(KSU_KSYS_UNSHARE);

	return f(unshare_flags);
}

__nocfi long ksu_b___arm64_sys_setns(const struct pt_regs *regs)
{
	long (*f)(const struct pt_regs *regs) =
		(long (*)(const struct pt_regs *regs))ksu_sym_addr(KSU_ARM64_SYS_SETNS);

	return f(regs);
}

__nocfi struct inode * ksu_b_alloc_anon_inode(struct super_block *sb)
{
	struct inode * (*f)(struct super_block *sb) =
		(struct inode * (*)(struct super_block *sb))ksu_sym_addr(KSU_ALLOC_ANON_INODE);

	return f(sb);
}

__nocfi struct file * ksu_b_alloc_file_pseudo(struct inode *inode, struct vfsmount *mnt, const char *name, int flags, const struct file_operations *fops)
{
	struct file * (*f)(struct inode *inode, struct vfsmount *mnt, const char *name, int flags, const struct file_operations *fops) =
		(struct file * (*)(struct inode *inode, struct vfsmount *mnt, const char *name, int flags, const struct file_operations *fops))ksu_sym_addr(KSU_ALLOC_FILE_PSEUDO);

	return f(inode, mnt, name, flags, fops);
}

__nocfi void ksu_b_ext4_unregister_sysfs(struct super_block *sb)
{
	void (*f)(struct super_block *sb) =
		(void (*)(struct super_block *sb))ksu_sym_addr(KSU_EXT4_UNREGISTER_SYSFS);

	f(sb);
}

__nocfi struct fsnotify_group * ksu_b_fsnotify_alloc_group(const struct fsnotify_ops *ops)
{
	struct fsnotify_group * (*f)(const struct fsnotify_ops *ops) =
		(struct fsnotify_group * (*)(const struct fsnotify_ops *ops))ksu_sym_addr(KSU_FSNOTIFY_ALLOC_GROUP);

	return f(ops);
}

__nocfi void ksu_b_fsnotify_put_group(struct fsnotify_group *group)
{
	void (*f)(struct fsnotify_group *group) =
		(void (*)(struct fsnotify_group *group))ksu_sym_addr(KSU_FSNOTIFY_PUT_GROUP);

	f(group);
}

__nocfi void ksu_b_fsnotify_init_mark(struct fsnotify_mark *mark, struct fsnotify_group *group)
{
	void (*f)(struct fsnotify_mark *mark, struct fsnotify_group *group) =
		(void (*)(struct fsnotify_mark *mark, struct fsnotify_group *group))ksu_sym_addr(KSU_FSNOTIFY_INIT_MARK);

	f(mark, group);
}

__nocfi int ksu_b_fsnotify_add_mark(struct fsnotify_mark *mark, fsnotify_connp_t *connp, unsigned int type, int allow_dups, __kernel_fsid_t *fsid)
{
	int (*f)(struct fsnotify_mark *mark, fsnotify_connp_t *connp, unsigned int type, int allow_dups, __kernel_fsid_t *fsid) =
		(int (*)(struct fsnotify_mark *mark, fsnotify_connp_t *connp, unsigned int type, int allow_dups, __kernel_fsid_t *fsid))ksu_sym_addr(KSU_FSNOTIFY_ADD_MARK);

	return f(mark, connp, type, allow_dups, fsid);
}

__nocfi void ksu_b_fsnotify_destroy_mark(struct fsnotify_mark *mark, struct fsnotify_group *group)
{
	void (*f)(struct fsnotify_mark *mark, struct fsnotify_group *group) =
		(void (*)(struct fsnotify_mark *mark, struct fsnotify_group *group))ksu_sym_addr(KSU_FSNOTIFY_DESTROY_MARK);

	f(mark, group);
}

__nocfi void ksu_b_fsnotify_put_mark(struct fsnotify_mark *mark)
{
	void (*f)(struct fsnotify_mark *mark) =
		(void (*)(struct fsnotify_mark *mark))ksu_sym_addr(KSU_FSNOTIFY_PUT_MARK);

	f(mark);
}

__nocfi long ksu_b_probe_user_read(void *dst, const void __user *src, size_t size)
{
	long (*f)(void *dst, const void __user *src, size_t size) =
		(long (*)(void *dst, const void __user *src, size_t size))ksu_sym_addr(KSU_PROBE_USER_READ);

	return f(dst, src, size);
}

__nocfi long ksu_b_probe_user_write(void __user *dst, const void *src, size_t size)
{
	long (*f)(void __user *dst, const void *src, size_t size) =
		(long (*)(void __user *dst, const void *src, size_t size))ksu_sym_addr(KSU_PROBE_USER_WRITE);

	return f(dst, src, size);
}

__nocfi long ksu_b_strncpy_from_unsafe_user(char *dst, const void __user *src, long count)
{
	long (*f)(char *dst, const void __user *src, long count) =
		(long (*)(char *dst, const void __user *src, long count))ksu_sym_addr(KSU_STRNCPY_FROM_UNSAFE_USER);

	return f(dst, src, count);
}

__nocfi void ksu_b_security_release_secctx(char *secdata, u32 seclen)
{
	void (*f)(char *secdata, u32 seclen) =
		(void (*)(char *secdata, u32 seclen))ksu_sym_addr(KSU_SECURITY_RELEASE_SECCTX);

	f(secdata, seclen);
}

__nocfi int ksu_b_security_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
	int (*f)(const char *secdata, u32 seclen, u32 *secid) =
		(int (*)(const char *secdata, u32 seclen, u32 *secid))ksu_sym_addr(KSU_SECURITY_SECCTX_TO_SECID);

	return f(secdata, seclen, secid);
}

__nocfi int ksu_b_static_key_count(struct static_key *key)
{
	int (*f)(struct static_key *key) =
		(int (*)(struct static_key *key))ksu_sym_addr(KSU_STATIC_KEY_COUNT);

	return f(key);
}

__nocfi void ksu_b_static_key_enable(struct static_key *key)
{
	void (*f)(struct static_key *key) =
		(void (*)(struct static_key *key))ksu_sym_addr(KSU_STATIC_KEY_ENABLE);

	f(key);
}

__nocfi struct cred *ksu_b_prepare_creds(void)
{
	struct cred *(*f)(void) =
		(struct cred *(*)(void))ksu_sym_addr(KSU_PREPARE_CREDS);

	return f();
}

__nocfi int ksu_b_kallsyms_lookup_size_offset(unsigned long addr,
					      unsigned long *symbolsize,
					      unsigned long *offset)
{
	int (*f)(unsigned long, unsigned long *, unsigned long *) =
		(int (*)(unsigned long, unsigned long *, unsigned long *))
		ksu_sym_addr(KSU_KALLSYMS_LOOKUP_SIZE_OFFSET);

	return f(addr, symbolsize, offset);
}

__nocfi int ksu_b_security_secid_to_secctx(const char *secdata, u32 seclen,
					   u32 *secid)
{
	int (*f)(const char *, u32, u32 *) =
		(int (*)(const char *, u32, u32 *))
		ksu_sym_addr(KSU_SECURITY_SECID_TO_SECCTX);

	return f(secdata, seclen, secid);
}

__nocfi void ksu_b_static_key_disable(struct static_key *key)
{
	void (*f)(struct static_key *) =
		(void (*)(struct static_key *))ksu_sym_addr(KSU_STATIC_KEY_DISABLE);

	f(key);
}

__nocfi void ksu_b_audit_log(struct audit_context *ctx, gfp_t gfp_mask,
			     int type, const char *fmt, unsigned int auid,
			     unsigned int ses)
{
	void (*f)(struct audit_context *, gfp_t, int, const char *, ...) =
		(void (*)(struct audit_context *, gfp_t, int, const char *,
			   ...))ksu_sym_addr(KSU_AUDIT_LOG);

	f(ctx, gfp_mask, type, fmt, auid, ses);
}

__nocfi int ksu_b_security_sid_to_context(struct selinux_state *state,
					  u32 sid, char **scontext,
					  u32 *scontext_len)
{
	int (*f)(struct selinux_state *, u32, char **, u32 *) =
		(int (*)(struct selinux_state *, u32, char **, u32 *))
		ksu_sym_addr(KSU_SECURITY_SID_TO_CONTEXT);

	return f(state, sid, scontext, scontext_len);
}

__nocfi struct cred *ksu_b_prepare_ro_creds(struct cred *old, int kdp_cmd,
					    u64 task)
{
	struct cred *(*f)(struct cred *, int, u64) =
		(struct cred *(*)(struct cred *, int, u64))
		ksu_sym_addr(KSU_PREPARE_RO_CREDS);

	return f(old, kdp_cmd, task);
}

__nocfi void ksu_b_kdp_assign_pgd(struct task_struct *task)
{
	void (*f)(struct task_struct *) =
		(void (*)(struct task_struct *))ksu_sym_addr(KSU_KDP_ASSIGN_PGD);

	f(task);
}

__nocfi int ksu_b_selinux_bprm_set_creds(struct linux_binprm *bprm)
{
	int (*f)(struct linux_binprm *) =
		(int (*)(struct linux_binprm *))ksu_sym_addr(KSU_SELINUX_BPRM_SET_CREDS);

	return f(bprm);
}

__nocfi int ksu_b_set_memory_rw(unsigned long addr, int numpages)
{
	int (*f)(unsigned long, int) =
		(int (*)(unsigned long, int))ksu_sym_addr(KSU_SET_MEMORY_RW);

	return f(addr, numpages);
}

__nocfi int ksu_b_set_memory_ro(unsigned long addr, int numpages)
{
	int (*f)(unsigned long, int) =
		(int (*)(unsigned long, int))ksu_sym_addr(KSU_SET_MEMORY_RO);

	return f(addr, numpages);
}
