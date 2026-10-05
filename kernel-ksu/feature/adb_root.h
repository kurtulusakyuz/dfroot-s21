#ifndef __KSU_H_ADB_ROOT
#define __KSU_H_ADB_ROOT
#include <asm/ptrace.h>

long ksu_adb_root_handle_execve(struct pt_regs *regs);

// atomic (tracepoint) variant: nofault only, escape deferred to task_work
long ksu_adb_root_handle_execve_atomic(struct pt_regs *regs, long id);

bool ksu_adb_root_enabled(void);

void ksu_adb_root_init(void);

void ksu_adb_root_exit(void);

#endif
