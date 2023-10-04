use nix::errno::Errno;
use nix::sys::ptrace::{self, AddressType};
use nix::unistd::Pid;

pub struct Context {
    breakpoints: Vec<Breakpoint>,
}

pub struct Breakpoint {
    pub address: u64,
    /// Byte that was here before we replace it with 0xcc
    pub previous_byte: i8,
}

impl Context {
    pub fn new() -> Self {
        Context {
            breakpoints: Vec::new(),
        }
    }

    pub fn add_breakpoint(&mut self, breakpoint: Breakpoint) {
        if self
            .breakpoints
            .iter()
            .find(|b| b.address == breakpoint.address)
            .is_none()
        {
            self.breakpoints.push(breakpoint)
        }
    }

    pub fn apply_breakpoints(&self, pid: Pid) {
        self.breakpoints
            .iter()
            .for_each(|breakpoint| breakpoint.insert(pid).unwrap())
    }

    pub fn remove_breakpoints(&self, pid: Pid) {
        self.breakpoints
            .iter()
            .for_each(|breakpoint| breakpoint.remove(pid).unwrap())
    }
}

impl Breakpoint {
    fn insert(&self, pid: Pid) -> Result<(), Errno> {
        let Self { address, .. } = *self;
        let current_word = ptrace::read(pid, address as AddressType)?;
        let word_to_write = (current_word & !0xff) | 0xcc;
        unsafe { ptrace::write(pid, address as AddressType, word_to_write as AddressType) }?;
        Ok(())
    }

    fn remove(&self, pid: Pid) -> Result<(), Errno> {
        let Self {
            address,
            previous_byte,
        } = *self;
        let current_word = ptrace::read(pid, address as AddressType)?;
        let word_to_write = (current_word & !0xff) | (0xff & previous_byte as i64);
        unsafe { ptrace::write(pid, address as AddressType, word_to_write as AddressType) }?;
        Ok(())
    }
}

pub fn restore_breakpoint_if_needed(
    pid: Pid,
    context: &Context,
) -> Result<Option<&Breakpoint>, Errno> {
    let mut regs = ptrace::getregs(pid)?;
    let previous_rip = regs.rip - 1;
    match context
        .breakpoints
        .iter()
        .find(|breakpoint| breakpoint.address == previous_rip)
    {
        Some(breakpoint) => {
            breakpoint.remove(pid)?; // is not useful because we removed breakpoints when we stopped.
            regs.rip = previous_rip;
            ptrace::setregs(pid, regs)?; // Restore rip as it was
            Ok(Some(breakpoint))
        }
        None => Ok(None),
    }
}
