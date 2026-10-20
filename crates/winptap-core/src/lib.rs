//! Shared implementation types for winptap.
#![forbid(unsafe_code)]
pub mod backend;
pub mod buffer;
pub mod filter;
pub mod metadata;
pub mod wire;
pub use backend::*;
pub use buffer::*;
pub use filter::*;
pub use metadata::*;

/// A capture failure. Native error codes are preserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedPlatform,
    UnsupportedWindowsBuild { build: u32 },
    MissingApi(String),
    PermissionDenied,
    RevisionMismatch,
    Windows { operation: &'static str, code: u32 },
    InvalidConfig(&'static str),
    InvalidData(&'static str),
    InvalidState,
    Timeout,
    Cancelled,
    StreamFailed(u32),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Convert an HRESULT without discarding the original failure code.
pub fn hresult(operation: &'static str, value: i32) -> Result<()> {
    if value >= 0 {
        return Ok(());
    }
    Err(match value as u32 {
        0x80070005 => Error::PermissionDenied,
        0x80070519 | 0x8007051a => Error::RevisionMismatch,
        code => Error::Windows { operation, code },
    })
}
