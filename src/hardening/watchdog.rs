use libc::{fork, ptrace, waitpid, PTRACE_TRACEME, PTRACE_CONT, SIGKILL, WIFEXITED, WIFSIGNALED};
use std::process;

pub fn secure_launch<F>(logic: F)
where
    F: FnOnce() -> Result<(), Box<dyn std::error::Error>>
{
    unsafe {
        let pid = fork();

        if pid < 0 {
            process::exit(1);
        }

        if pid == 0 {
            if ptrace(PTRACE_TRACEME, 0, 0, 0) < 0 {
                process::exit(1);
            }
            if let Err(_) = logic() {
                process::exit(1);
            }
            process::exit(0);
        } else {
            loop {
                let mut status = 0;
                waitpid(pid, &mut status, 0);

                if WIFEXITED(status) || WIFSIGNALED(status) {
                    process::exit(0);
                }
                if ptrace(PTRACE_CONT, pid, 0, 0) < 0 {
                    // If The Parents lose control, kill the child 
                    libc::kill(pid, SIGKILL);
                    process::exit(1);
                }
            }
        }
    }
}
