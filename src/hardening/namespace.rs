use libc::{
    mount, umount2, unshare, CLONE_NEWNS, MCL_CURRENT, MCL_FUTURE, MNT_DETACH, MS_BIND,
    MS_NOSUID, MS_NOEXEC, MS_NODEV, MS_PRIVATE, MS_REC,
};
use std::ffi::CString;
use std::process;
use std::ptr;

pub fn isolate_environment() {
    println!("[*] Initializing Filesystem Isolation...");

    unsafe {
        if unshare(CLONE_NEWNS) != 0 {
            eprintln!("[!] Failed to unshare Mount Namespace. Run as Root?");
            return;
        }

        let root = CString::new("/").unwrap();
        if mount(
            ptr::null(),
            root.as_ptr(),
            ptr::null(),
            MS_PRIVATE | MS_REC,
            ptr::null(),
        ) != 0
        {
            eprintln!("[!] Failed to set filesystem to Private.");
            process::exit(1);
        }

        let tmp_path = CString::new("/tmp").unwrap();
        let tmpfs = CString::new("tmpfs").unwrap();

        let flags = MS_NOSUID | MS_NOEXEC | MS_NODEV;

        if mount(
            tmpfs.as_ptr(),
            tmp_path.as_ptr(),
            tmpfs.as_ptr(),
            flags,
            ptr::null(),
        ) != 0
        {
            eprintln!("[!] Warning: Failed to isolate /tmp.");
        } else {
            println!("[*] /tmp Isolation: ACTIVE (Private tmpfs)");
        }

        let proc_path = CString::new("/proc").unwrap();
        let proc_fs = CString::new("proc").unwrap();

        umount2(proc_path.as_ptr(), MNT_DETACH);

        if mount(
            proc_fs.as_ptr(),
            proc_path.as_ptr(),
            proc_fs.as_ptr(),
            MS_NOSUID | MS_NOEXEC | MS_NODEV,
            ptr::null(),
        ) != 0
        {
    
        }
    } 
} 
