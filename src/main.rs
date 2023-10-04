use std::ffi::CStr;
use std::ffi::CString;

use nix::sys::ptrace;
use nix::unistd::{fork, ForkResult};

mod debugger;

fn main() {
    let fork_result = unsafe { fork() }.expect("Failed to fork");
    match fork_result {
        ForkResult::Parent { child } => {
            debugger::run(child);
        }
        ForkResult::Child => {
            ptrace::traceme().expect("Failed to call traceme in child");
            let path: &CStr = &CString::new("../debugee/target/release/debugee").unwrap();
            nix::unistd::execve::<&CStr, &CStr>(path, &[], &[]).unwrap();
            unreachable!("Execve should have replaced the program");
        }
    }
}
