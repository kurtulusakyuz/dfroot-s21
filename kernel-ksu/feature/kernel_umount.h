#ifndef __KSU_H_KERNEL_UMOUNT
#define __KSU_H_KERNEL_UMOUNT

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rwsem.h>

void ksu_kernel_umount_init(void);
void ksu_kernel_umount_exit(void);

// Handler function to be called from setresuid hook
int ksu_handle_umount(uid_t old_uid, uid_t new_uid);

// Async trigger for tracepoint (task_work, sleepable)
int ksu_umount_async(uid_t old_uid, uid_t new_uid);

// Boot scan: set module flag when mountable modules exist
void ksu_umount_scan_modules(void);

// Lazy sync (sleepable): rescan modules + rebuild umount list
void ksu_umount_sync_state(void);

// Umount list management (shared with REPORT/ADD_TRY_UMOUNT ioctl)
int ksu_umount_add_entry(const char *path, unsigned int flags);
void ksu_umount_wipe_list(void);

// for the umount list
struct mount_entry {
    char *umountable;
    unsigned int flags;
    struct list_head list;
};
extern struct list_head mount_list;
extern struct rw_semaphore mount_list_lock;

#endif
