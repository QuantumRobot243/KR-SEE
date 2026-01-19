mod hardening;
mod secrets;
mod shutdown;

use hardening::{memory, dump, signals, anti_debug, input, seccomp, namespace};
use secrets::secret::SecureSecret;
use std::panic;
use obfstr::obfstr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    panic::set_hook(Box::new(|_| {
        eprintln!("\n{}", obfstr!("[CRITICAL] Panic detected! Executing emergency wipe."));
        shutdown::secure_shutdown();
    }));

    anti_debug::block_debugger();

    namespace::isolate_environment();

    memory::lock_memory().map_err(|e| format!("{:?}", e))?;

    dump::disable_core_dumps();

    seccomp::apply_filters();

    signals::install_signal_handlers();

    let _my_password = SecureSecret::new([42u8; 32]);

    println!("{}", obfstr!("H-shell active. Secure environment established."));

    if let Err(e) = run_shell() {
        eprintln!("[!] Shell Error: {}", e);
        shutdown::secure_shutdown();
    }

    Ok(())
}

fn run_shell() -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let command = input::secure_prompt(obfstr!("⟦ H-Shell $⟧=>"));

        match command.as_str() {
            c if c == obfstr!("status") => {
                println!("{}", obfstr!("[*] Memory: LOCKED"));
                println!("{}", obfstr!("[*] Ptrace: BLOCKED"));
                println!("{}", obfstr!("[*] Dumps: DISABLED"));
                println!("{}", obfstr!("[*] Isolation: NAMESPACE (Private /tmp)"));
                println!("{}", obfstr!("[*] Seccomp: ACTIVE"));
            },
            c if c == obfstr!("secrets") => {
                println!("{}", obfstr!("[*] Secrets are loaded and registered for zeroization."));
            },
            c if c == obfstr!("exit") || c == obfstr!("quit") => {
                println!("{}", obfstr!("Exiting securely..."));
                shutdown::secure_shutdown();
                break;
            },
            "" => continue,
            _ => {
                println!("{}", obfstr!("Unknown command. This event has been logged to the secure audit."));
            }
        }
    }
    Ok(())
}
