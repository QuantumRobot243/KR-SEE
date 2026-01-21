use libc::{ptrace, PTRACE_ATTACH, PTRACE_DETACH, pid_t};
use std::thread;
use std::time::Duration;
use std::process;
use std::io;
use crate::shutdown::secure_shutdown;

pub fn start_watchdog() {
    let pid = process::id() as pid_t;

    thread::spawn(move || {
        loop {
            unsafe {
                if ptrace(PTRACE_ATTACH, pid, 0, 0) < 0 {
                    let err = io::Error::last_os_error().raw_os_error();

                    if err == Some(libc::EPERM) {
                        eprintln!("\n[!] WATCHDOG ALERT: Process integrity compromised by external tracer.");
                        secure_shutdown();
                    }
                } else {
                    ptrace(PTRACE_DETACH, pid, 0, 0);
                }
            }
            thread::sleep(Duration::from_millis(500));
        }
    });
}
