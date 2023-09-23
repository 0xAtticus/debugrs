use std::ffi::CStr;
use std::ffi::CString;

use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::{fork, ForkResult};

fn main() {
    let fork_result = unsafe { fork() }.expect("Failed to fork");
    match fork_result {
        ForkResult::Parent { child } => {
            let _ = waitpid(child, None).expect("Failed to wait");
            ptrace::syscall(child, None).expect("Failed to use PTRACE_SYSCALL");
            loop {
                let _ = waitpid(child, None).expect("Failed to wait");
                let before_call_registers = ptrace::getregs(child).expect("could not get child's registers");
                println!("Entering syscall #{}", before_call_registers.orig_rax);
                
                ptrace::syscall(child, None).expect("Failed to use PTRACE_SYSCALL");
                
                let _ = waitpid(child, None).expect("Failed to wait");
                let after_call_registers = ptrace::getregs(child).expect("could not get child's registers");
                println!("Syscall #{}, Result: ({}, {})", before_call_registers.orig_rax, after_call_registers.rax, after_call_registers.rdx);
                
                ptrace::syscall(child, None).expect("Failed to use PTRACE_SYSCALL");
            }
        }

        ForkResult::Child => {
            ptrace::traceme().expect("Failed to call traceme in child");
            let path: &CStr = &CString::new("../debugee/target/release/debugee").unwrap();
            nix::unistd::execve::<&CStr, &CStr>(path, &[], &[]).unwrap();
            unreachable!("Execve should have replaced the program");
        }
    }
}
