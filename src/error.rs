use std::fmt;
use std::io;

pub enum Error {
    Io(io::Error),
    Hid(hidapi::HidError),
    MultipleCommands,
    MalformattedMsg,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<hidapi::HidError> for Error {
    fn from(e: hidapi::HidError) -> Self {
        Error::Hid(e)
    }
}

// Rust only supports `fn main() -> Result<(), E: Debug>`, so we implement `Debug`
// manually to provide the error output we want.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => writeln!(f, "Failed to set up device: {e:?}")?,
            Error::Hid(e) => writeln!(f, "Failed to set up device: {e:?}")?,
            Error::MultipleCommands => {
                writeln!(f, "One of --identity or --list should be specified.")?
            }
            Error::MalformattedMsg => writeln!(f, "Device returned malformated message.")?,
        }
        Ok(())
    }
}
