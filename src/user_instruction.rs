use std::num::ParseIntError;
use std::str::FromStr;
use thiserror::Error;

pub enum UserInstruction {
    AddBreakpoint { address: u64 },
    ContinueUntilBreakpoint,
    ContinueUntilSyscall,
    ShowHelp,
    ShowMemory { address: u64 },
    ShowRegisters,
    SingleStep,
}

#[derive(Error, Debug)]
pub enum UserInstructionParseError {
    #[error("Unknown instruction")]
    UnknownInstruction,
    #[error("Address should start with `0x`")]
    AddressShouldStartWith0x,
    #[error("Could not parse address: {0}")]
    UnparseableAddress(#[from] ParseIntError),
}

fn parse_hex_address(hex: &str) -> Result<u64, UserInstructionParseError> {
    if !hex.starts_with("0x") {
        return Err(UserInstructionParseError::AddressShouldStartWith0x);
    }
    let hex_address = hex.trim_start_matches("0x");
    u64::from_str_radix(hex_address, 16).map_err(UserInstructionParseError::UnparseableAddress)
}

impl FromStr for UserInstruction {
    type Err = UserInstructionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "c" => Ok(UserInstruction::ContinueUntilBreakpoint),
            "s" => Ok(UserInstruction::ContinueUntilSyscall),
            "h" => Ok(UserInstruction::ShowHelp),
            "r" => Ok(UserInstruction::ShowRegisters),
            "n" => Ok(UserInstruction::SingleStep),
            s if s.starts_with("m ") => {
                let hex_address = s.trim_start_matches("m ");
                let address = parse_hex_address(hex_address)?;
                Ok(UserInstruction::ShowMemory { address })
            }
            s if s.starts_with("b ") => {
                let hex_address = s.trim_start_matches("b ");
                let address = parse_hex_address(hex_address)?;
                Ok(UserInstruction::AddBreakpoint { address })
            }
            _ => Err(UserInstructionParseError::UnknownInstruction),
        }
    }
}
