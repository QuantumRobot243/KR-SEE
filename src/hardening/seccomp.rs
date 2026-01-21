use libseccomp::{ScmpFilterContext, ScmpAction, ScmpSyscall};

pub fn apply_filters() {
    println!("[*] Initializing Seccomp Prison...");

    let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Trap)
        .expect("Failed to initialize Seccomp filter");

    let allowed_syscalls = vec![
        "read", "write", "writev", "openat", "close", "exit_group", "exit",

        "brk", "mmap", "munmap", "mprotect", "mlockall", "madvise", "rseq",

        "fstat", "newfstatat", "statx", "lseek", "ioctl", "isatty", "fcntl",

        "clone", "clone3", "set_robust_list", "futex", "set_tid_address", "tgkill", "gettid",

        "nanosleep", "rt_sigreturn", "rt_sigaction", "sigaltstack", "rt_sigprocmask",
        "rt_sigsuspend", "sigprocmask",

        "getrandom", "prlimit64", "getuid", "getgid", "geteuid", "getegid",
        "ptrace", 

        "poll", "ppoll", "select", "pselect6", "epoll_pwait",

        "getpgrp", "getpid", "getppid", "arch_prctl", "sched_getaffinity",
    ];

    for syscall_name in allowed_syscalls {
        if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
            ctx.add_rule(ScmpAction::Allow, syscall)
                .unwrap_or_else(|_| panic!("Failed to allow syscall: {}", syscall_name));
        }
    }

    ctx.load().expect("Failed to load Seccomp filter into Kernel");

    println!("[*] Seccomp Prison: ACTIVE ");
}
