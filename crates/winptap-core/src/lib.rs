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
        match self {
            Self::UnsupportedPlatform => {
                f.write_str("capture backend is not supported on this platform")
            }
            Self::UnsupportedWindowsBuild { build } => {
                write!(f, "unsupported Windows build {build}")
            }
            Self::MissingApi(api) => write!(f, "capture API unavailable: {api}"),
            Self::PermissionDenied => {
                f.write_str("packet capture requires administrator privileges")
            }
            Self::RevisionMismatch => f.write_str("Packet Monitor API revision is incompatible"),
            Self::Windows { operation, code } => {
                write!(f, "{operation} failed (Windows code 0x{code:08X})")
            }
            Self::InvalidConfig(reason) => write!(f, "invalid capture configuration: {reason}"),
            Self::InvalidData(reason) => write!(f, "invalid capture data: {reason}"),
            Self::InvalidState => f.write_str("operation is invalid in the current capture state"),
            Self::Timeout => f.write_str("packet receive timed out"),
            Self::Cancelled => f.write_str("packet capture was cancelled"),
            Self::StreamFailed(code) => write!(f, "capture stream failed (code 0x{code:08X})"),
        }
    }
}
impl std::error::Error for Error {}
/// Preserve the typed capture failure as the I/O error's source.
impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        use std::io::ErrorKind;
        let kind = match &error {
            Error::UnsupportedPlatform
            | Error::UnsupportedWindowsBuild { .. }
            | Error::RevisionMismatch => ErrorKind::Unsupported,
            Error::MissingApi(_) => ErrorKind::NotFound,
            Error::PermissionDenied => ErrorKind::PermissionDenied,
            Error::InvalidConfig(_) | Error::InvalidState => ErrorKind::InvalidInput,
            Error::InvalidData(_) => ErrorKind::InvalidData,
            Error::Timeout => ErrorKind::TimedOut,
            Error::Cancelled => ErrorKind::Interrupted,
            Error::Windows { code, .. } => std::io::Error::from_raw_os_error(*code as i32).kind(),
            Error::StreamFailed(_) => ErrorKind::Other,
        };
        Self::new(kind, error)
    }
}
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
