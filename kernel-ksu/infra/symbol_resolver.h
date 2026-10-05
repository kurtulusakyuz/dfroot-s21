#ifndef __KSU_SYMBOL_RESOLVER_H
#define __KSU_SYMBOL_RESOLVER_H

#include <linux/cred.h>
#include <linux/fsnotify_backend.h>
#include <linux/jump_label.h>
#include <linux/kprobes.h>
#include <linux/pid.h>
#include <linux/proc_ns.h>
#include <linux/sched.h>
#include <linux/task_work.h>
#include "selinux/sepolicy.h"
#include <security.h>
#include <ss/context.h>
#include <ss/services.h>
#include <ss/conditional.h>
#include "avc.h"

void *ksu_resolve_symbol_for_functable_hook(const char *symbol_name);
unsigned long find_kernel_symbol_exact(const char *symbol_name);
int ksu_init_symbol_resolver();

/* HZC2 trimmed-symbol discipline (RCNT 147/148 lessons):
 * Device trims ~51 exports KSU needs. All are resolved at init into
 * ksu_symtab[] (addresses as data — no CFI on data). Calls go through
 * KSU_CALL, which casts the result of the noinline ksu_sym_addr() call
 * to typeof(sym) — the header's OWN declaration, so the prototype is
 * exact by construction (zero transcription risk), and the cast source
 * is a call result (v82's proven inline-icall shape, no slowpath).
 * DATA uses KSU_DATA (plain address use, CFI-free).
 * Rule: NEVER call a trimmed symbol directly; NEVER store function
 * pointers in globals/params (slowpath trap). */
enum ksu_sym_id {
	KSU_ALLOC_ANON_INODE,
	KSU_ALLOC_FILE_PSEUDO,
	KSU_ALLOC_UID,
	KSU_ARM64_SYS_SETNS,
	KSU_AUDIT_LOG,
	KSU_AVC_HAS_PERM,
	KSU_AVC_SS_RESET,
	KSU_CHANGE_PID,
	KSU_COMMIT_CREDS,
	KSU_EXT4_UNREGISTER_SYSFS,
	KSU_FIND_PID_NS,
	KSU_FIND_TASK_BY_VPID,
	KSU_FREE_UID,
	KSU_FSNOTIFY_ADD_MARK,
	KSU_FSNOTIFY_ALLOC_GROUP,
	KSU_FSNOTIFY_DESTROY_MARK,
	KSU_FSNOTIFY_INIT_MARK,
	KSU_FSNOTIFY_PUT_GROUP,
	KSU_FSNOTIFY_PUT_MARK,
	KSU_GET_TASK_CRED,
	KSU_GROUPS_ALLOC,
	KSU_GROUPS_FREE,
	KSU_GROUPS_SORT,
	KSU_INIT_MM,
	KSU_INIT_PID_NS,
	KSU_KALLSYMS_LOOKUP,
	KSU_KALLSYMS_LOOKUP_NAME,
	KSU_KALLSYMS_LOOKUP_SIZE_OFFSET,
	KSU_KSYS_UNSHARE,
	KSU_MNTNS_OPERATIONS,
	KSU_NS_GET_PATH,
	KSU_PROBE_USER_READ,
	KSU_PROBE_USER_WRITE,
	KSU_PUT_SECCOMP_FILTER,
	KSU_REGISTER_KRETPROBE,
	KSU_SECURITY_RELEASE_SECCTX,
	KSU_SECURITY_SECCTX_TO_SECID,
	KSU_SECURITY_SECID_TO_SECCTX,
	KSU_SELINUX_BLOB_SIZES,
	KSU_SELINUX_STATE,
	KSU_SELINUX_STATUS_UPDATE_POLICYLOAD,
	KSU_SELNL_NOTIFY_POLICYLOAD,
	KSU_SERVICES_COMPUTE_XPERMS_DECISION,
	KSU_SET_FS_PWD,
	KSU_SET_GROUPS,
	KSU_STATIC_KEY_COUNT,
	KSU_STRNCPY_FROM_UNSAFE_USER,
	KSU_STATIC_KEY_ENABLE,
	KSU_TASKLIST_LOCK,
	KSU_TASK_WORK_ADD,
	KSU_TRACEPOINT_SRCU,
	KSU_TRACEPOINT_SYS_ENTER,
	KSU_UNREGISTER_KRETPROBE,
	KSU_SET_MEMORY_RW,
	KSU_SET_MEMORY_RO,
	KSU_SELINUX_BPRM_SET_CREDS,
	KSU_SECURITY_SID_TO_CONTEXT,
	KSU_PREPARE_CREDS,
	KSU_ABORT_CREDS,
	KSU_REGISTER_KPROBE,
	KSU_UNREGISTER_KPROBE,
	KSU_STATIC_KEY_DISABLE,
	KSU_PREPARE_RO_CREDS,
	KSU_GET_TASK_CREDS,
	KSU_SET_TASK_CREDS,
	KSU_KDP_ASSIGN_PGD,
	KSU_KDP_USECOUNT_DEC_AND_TEST,
	KSU_INC_RLIMIT_UCOUNTS,
	KSU_DEC_RLIMIT_UCOUNTS,
	KSU_SECURITY_SB_UMOUNT,
	KSU_UMOUNT_TREE,
	KSU_CHANGE_MNT_PROPAGATION,
	KSU_NAMESPACE_UNLOCK,
	KSU_PROPAGATE_MOUNT_BUSY,
	KSU_SECURITY_DUMP_MASKED_AV,
	KSU_CONTEXT_STRUCT_COMPUTE_AV,
	KSU_NSYMS,
};

extern unsigned long ksu_symtab[];
noinline unsigned long ksu_sym_addr(int id);

struct kprobe;
struct kretprobe;
struct selinux_state;
struct common_audit_data;
int ksu_b_avc_has_perm(struct selinux_state *state, u32 ssid, u32 tsid,
		       u16 tclass, u32 requested,
		       struct common_audit_data *auditdata);
int ksu_b_register_kprobe(struct kprobe *p);
void ksu_b_unregister_kprobe(struct kprobe *p);
int ksu_b_register_kretprobe(struct kretprobe *rp);
void ksu_b_unregister_kretprobe(struct kretprobe *rp);
void ksu_b_avc_ss_reset(struct selinux_avc *avc, u32 seqno);
void ksu_b_selnl_notify_policyload(u32 seqno);
void ksu_b_selinux_status_update_policyload(struct selinux_state *state, int seqno);
void ksu_b_services_compute_xperms_decision(struct extended_perms_decision *xpermd, struct avtab_node *node);
void ksu_b_get_task_creds(struct task_struct *p, unsigned int *uid_ptr, unsigned int *fsuid_ptr, unsigned int *egid_ptr, unsigned short *cred_flags_ptr);
int ksu_b_set_task_creds(struct task_struct *p, unsigned int uid, unsigned int fsuid, unsigned int egid, unsigned short cred_flags);
int ksu_b_commit_creds(struct cred *new);
void ksu_b_abort_creds(struct cred *real);
struct group_info * ksu_b_groups_alloc(int gidsetsize);
void ksu_b_groups_free(struct group_info *group_info);
void ksu_b_groups_sort(struct group_info *group_info);
void ksu_b_set_groups(struct cred *cred, struct group_info *group_info);
struct user_struct * ksu_b_alloc_uid(kuid_t uid);
void ksu_b_free_uid(struct user_struct *user);
void ksu_b_put_seccomp_filter(struct task_struct *tsk);
int ksu_b_task_work_add(struct task_struct *task, struct callback_head *twork, bool notify);
const struct cred * ksu_b_get_task_cred(struct task_struct *task);
struct task_struct * ksu_b_find_task_by_vpid(pid_t vnr);
void ksu_b_change_pid(struct task_struct *task, enum pid_type type, struct pid *pid);
struct pid * ksu_b_find_pid_ns(int nr, struct pid_namespace *ns);
void * ksu_b_ns_get_path(struct path *path, struct task_struct *task, const struct proc_ns_operations *ns_ops);
void ksu_b_set_fs_pwd(struct fs_struct *fs, const struct path *path);
long ksu_b_ksys_unshare(unsigned long unshare_flags);
long ksu_b___arm64_sys_setns(const struct pt_regs *regs);
struct inode * ksu_b_alloc_anon_inode(struct super_block *sb);
struct file * ksu_b_alloc_file_pseudo(struct inode *inode, struct vfsmount *mnt, const char *name, int flags, const struct file_operations *fops);
void ksu_b_ext4_unregister_sysfs(struct super_block *sb);
struct fsnotify_group * ksu_b_fsnotify_alloc_group(const struct fsnotify_ops *ops);
void ksu_b_fsnotify_put_group(struct fsnotify_group *group);
void ksu_b_fsnotify_init_mark(struct fsnotify_mark *mark, struct fsnotify_group *group);
int ksu_b_fsnotify_add_mark(struct fsnotify_mark *mark, fsnotify_connp_t *connp, unsigned int type, int allow_dups, __kernel_fsid_t *fsid);
void ksu_b_fsnotify_destroy_mark(struct fsnotify_mark *mark, struct fsnotify_group *group);
void ksu_b_fsnotify_put_mark(struct fsnotify_mark *mark);
long ksu_b_probe_user_read(void *dst, const void __user *src, size_t size);
long ksu_b_probe_user_write(void __user *dst, const void *src, size_t size);
long ksu_b_strncpy_from_unsafe_user(char *dst, const void __user *src, long count);
void ksu_b_security_release_secctx(char *secdata, u32 seclen);
int ksu_b_security_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid);
int ksu_b_static_key_count(struct static_key *key);
void ksu_b_static_key_enable(struct static_key *key);
struct cred;
struct cred *ksu_b_prepare_creds(void);
void ksu_b_abort_creds(struct cred *real);
int ksu_b_commit_creds(struct cred *new);
int ksu_b_kallsyms_lookup_size_offset(unsigned long addr,
				      unsigned long *symbolsize,
				      unsigned long *offset);
int ksu_b_security_secid_to_secctx(const char *secdata, u32 seclen,
				   u32 *secid);
void ksu_b_static_key_disable(struct static_key *key);
struct audit_context;
struct linux_binprm;
int ksu_b_selinux_bprm_set_creds(struct linux_binprm *bprm);
struct selinux_state;
int ksu_b_security_sid_to_context(struct selinux_state *state, u32 sid,
				  char **scontext, u32 *scontext_len);
int ksu_b_set_memory_rw(unsigned long addr, int numpages);
int ksu_b_set_memory_ro(unsigned long addr, int numpages);
void ksu_b_audit_log(struct audit_context *ctx, gfp_t gfp_mask, int type,
		     const char *fmt, unsigned int auid, unsigned int ses);
struct cred;
struct task_struct;
struct cred *ksu_b_prepare_ro_creds(struct cred *old, int kdp_cmd, u64 task);
void ksu_b_kdp_assign_pgd(struct task_struct *task);
void ksu_mark(const char *name);
#define KSU_CALL(id, sym, ...) \
	(((typeof(sym) *)ksu_sym_addr(id))(__VA_ARGS__))
#define KSU_DATA(id, sym) ((typeof(sym) *)ksu_symtab[id])

#endif
