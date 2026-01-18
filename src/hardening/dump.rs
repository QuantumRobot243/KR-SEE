use libc::{prctl, PR_SET_DUMPABLE, setrlimit, rlimit, RLIMIT_CORE};

pub fn disable_core_dumps() {
    unsafe {
        if prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {     //Kernel Flag
            panic!("Failed to disable core dumps");
        }
        
        let limit = rlimit {
            rlim_cur: 0,   // soft limit 0 bytes
            rlim_max: 0,   // hard limit 0 bytes
        };
        
        if setrlimit(RLIMIT_CORE, &limit) != 0 {
            panic!("Failed to set core limit RLMIT_CORE");
        }
    }
}
