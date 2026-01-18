use libseccomp::{ScmpFilterContext, ScmpAction, ScmpSyscall};

pub fn apply_filters() {
    println!("[*] Initializing Seccomp Prison...");

    let mut ctx = ScmpFilterContext::new_filter(ScmpAction::KillThread)
        .expect("Failed to initialize Seccomp filter");

    let allowed_syscalls = vec![
        "read",
        "write",
        "writev",
        "openat",
        "close",
        "ioctl",
        "fstat",
        "lseek",
        "exit_group",
        "brk",
        "mmap",
        "munmap",
        "mlockall",
        "mprotect",
        "madvise",
        "clone",
        "clone3",
        "set_robust_list",
        "futex",
        "nanosleep",
        "rt_sigreturn",
        "sigreturn",
        "rt_sigaction",
        "sigaltstack",
        "rt_sigprocmask",
        "getrandom",
        "prlimit64",
        "set_tid_address",
        "rseq",
        "tgkill",
        "poll",
    ];

    for syscall_name in allowed_syscalls {
        if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
            let _ = ctx.add_rule(ScmpAction::Allow, syscall);
        }
    }

    ctx.load().expect("Failed to load Seccomp filter into Kernel");
    println!("[*] Seccomp Prison: ACTIVE");
}
