mod hardening;
mod secrets;
mod shutdown;

use hardening::{memory, dump, signals, anti_debug, input, seccomp, namespace, watchdog};
use secrets::secret::SecureSecret;
use std::panic;
use obfstr::obfstr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    panic::set_hook(Box::new(|_| {
        eprintln!("\n{}", obfstr!("[CRITICAL] Panic detected! Executing emergency wipe."));
        shutdown::secure_shutdown();
    }));
    anti_debug::block_debugger();
    dump::disable_core_dumps();

    watchdog::secure_launch(|| {
        namespace::isolate_environment();
        memory::lock_memory().map_err(|e| format!("{:?}", e))?;
        signals::install_signal_handlers();
        seccomp::apply_filters();
        let _session_key = SecureSecret::new([0x39u8; 32]);

        println!("{}", obfstr!("kr-see: Secure Environment Active:"));
        if let Err(e) = run_shell() {
            eprintln!("[!] Shell Error: {}", e);
            shutdown::secure_shutdown();
        }

        Ok(())
    });

    Ok(())
}

fn run_shell() -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let command = input::secure_prompt(obfstr!("kr-see $"));

        match command.as_str() {
            c if c == obfstr!("status") => {
                let internal_uid = unsafe { libc::getuid() };

                println!("\n--- Security Status ---");
                println!("{:<20} {}", obfstr!("[*] Memory:"), obfstr!("LOCKED (mlockall)"));
                println!("{:<20} {}", obfstr!("[*] Ptrace:"), obfstr!("ACTIVE (Parent-Child Tracer)"));
                println!("{:<20} {}", obfstr!("[*] Dumps:"), obfstr!("DISABLED"));
                println!("{:<20} {}", obfstr!("[*] Namespace:"), obfstr!("ACTIVE (User + Mount)"));
                println!("{:<20} {} (Mapped Root)", obfstr!("[*] Internal UID:"), internal_uid);
                println!("{:<20} {}", obfstr!("[*] Seccomp:"), obfstr!("ACTIVE (Trap Mode)"));
                println!("------------------------\n");
            },
            c if c == obfstr!("exit") || c == obfstr!("quit") => {
                println!("{}", obfstr!("Wiping memory and exiting..."));
                shutdown::secure_shutdown();
                break;
            },
            "" => continue,
            _ => {
                println!("{}", obfstr!("Unknown command."));
            }
        }
    }
    Ok(())
}
