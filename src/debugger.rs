use std::io::Write;
use std::str::FromStr;

use nix::errno::Errno;
use nix::libc::user_regs_struct;
use nix::sys::ptrace::{self, AddressType};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use thiserror::Error;

use debugrs::context::{restore_breakpoint_if_needed, Breakpoint, Context};
use debugrs::user_instruction::{UserInstruction, UserInstructionParseError};

const PREFIX: &'static str = "(drs)";

pub fn run(child: Pid) -> () {
    let _ = waitpid(child, None).expect("Failed to wait");
    println!("Process started {child}");
    let mut context = Context::new();
    loop {
        match get_user_input() {
            Ok(user_instruction) => {
                process_user_instruction(child, &user_instruction, &mut context)
                    .unwrap_or_else(|err| println!("Encountered error: {err}"));
                match user_instruction {
                    UserInstruction::ContinueUntilBreakpoint
                    | UserInstruction::SingleStep
                    | UserInstruction::ContinueUntilSyscall => {}
                    _ => continue,
                };
                let wait_result = waitpid(child, None).expect("Failed to wait");
                match wait_result {
                    WaitStatus::Exited(child, status) => {
                        println!("Child {child} exited with status {status}, quitting...");
                        break;
                    }
                    WaitStatus::Stopped(_child, Signal::SIGTRAP) => {
                        context.remove_breakpoints(child); // Remove breakpoint so we can inspect memory without seeing them
                                                           // We need to check if we stopped on a breakpoint, and restore it in this case
                        let restored_breakpoint = restore_breakpoint_if_needed(child, &mut context)
                            .expect("Failed to check for breakpoints");
                        if let Some(breakpoint) = restored_breakpoint {
                            println!("Hit breakpoint at 0x{:x}", breakpoint.address)
                        }
                        continue;
                    }
                    wait_status => {
                        context.remove_breakpoints(child); // Remove breakpoint so we can inspect memory without seeing them
                        println!("{wait_status:?}");
                        continue;
                    }
                }
            }
            Err(err) => println!("{err}"),
        }
    }
}

#[derive(Error, Debug)]
enum InputError {
    #[error("Invalid input")]
    InvalidInput,
    #[error("Could not parse instruction: {0}")]
    UserInstructionParseError(#[from] UserInstructionParseError),
}

fn get_user_input() -> Result<UserInstruction, InputError> {
    use std::io::{stdin, stdout};
    print!("{PREFIX} ");
    let _ = stdout().flush();
    let mut raw_input = String::new();
    stdin()
        .read_line(&mut raw_input)
        .map_err(|_| InputError::InvalidInput)?;
    UserInstruction::from_str(&raw_input).map_err(InputError::UserInstructionParseError)
}

#[derive(Error, Debug)]
enum ProcessingError {
    #[error("Error using ptrace syscall: {0}")]
    Errno(#[from] Errno),
}

fn process_user_instruction(
    pid: Pid,
    user_instruction: &UserInstruction,
    context: &mut Context,
) -> Result<(), ProcessingError> {
    match user_instruction {
        UserInstruction::ContinueUntilBreakpoint => {
            ptrace::step(pid, None)?;
            let _ = waitpid(pid, None).expect("Failed to wait");
            context.apply_breakpoints(pid);
            ptrace::cont(pid, None)?;
        }
        UserInstruction::ContinueUntilSyscall => {
            ptrace::step(pid, None)?;
            let _ = waitpid(pid, None).expect("Failed to wait");
            context.apply_breakpoints(pid);
            ptrace::syscall(pid, None)?;
        }
        UserInstruction::ShowHelp => todo!(),
        UserInstruction::ShowMemory { address } => {
            let value = ptrace::read(pid, *address as AddressType)?;
            println!("{value:#018x}");
        }
        UserInstruction::ShowRegisters => {
            let regs = UserRegsStruct(ptrace::getregs(pid)?);
            println!("{regs}");
        }
        UserInstruction::SingleStep => ptrace::step(pid, None)?,
        UserInstruction::AddBreakpoint { address } => {
            let previous_word = ptrace::read(pid, *address as AddressType)?;
            let breakpoint = Breakpoint {
                address: *address,
                previous_byte: (previous_word & 0xff) as i8,
            };
            context.add_breakpoint(breakpoint);
        }
    };
    Ok(())
}

struct UserRegsStruct(user_regs_struct);

impl std::fmt::Display for UserRegsStruct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let user_regs_struct {
            r15,
            r14,
            r13,
            r12,
            rbp,
            rbx,
            r11,
            r10,
            r9,
            r8,
            rax,
            rcx,
            rdx,
            rsi,
            rdi,
            orig_rax,
            rip,
            cs,
            eflags,
            rsp,
            ss,
            fs_base,
            gs_base,
            ds,
            es,
            fs,
            gs,
        } = self.0;
        write!(f, "rax: {rax:#x}\norig_rax: {orig_rax:#x}\nrcx: {rcx:#x}\nrdx: {rdx:#x}\nrsi: {rsi:#x}\nrdi: {rdi:#x}\nrip: {rip:#x}\nrsp: {rsp:#x}\nr15: {r15:#x}\nr14: {r14:#x}")
    }
}
