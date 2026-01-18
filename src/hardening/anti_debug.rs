use libc::{ptrace, PTRACE_TRACEME};
use std::process;

pub fn block_debugger() {
    unsafe {
        if ptrace(PTRACE_TRACEME, 0, 1, 0) < 0 {
            eprintln!("[!] Alert: Debugger detected. Exiting.");
            process::exit(1);
        }
    }
}
