//! Dynamically loaded official Packet Monitor API, version 1.0.
pub mod ffi;
pub mod filter;
#[cfg(windows)]
mod loader;
#[cfg(windows)]
mod session;
#[cfg(windows)]
mod source;
pub mod stream;
#[cfg(windows)]
pub use session::PktmonSession;
use winptap_core::*;

pub fn devices() -> Result<Vec<Device>> {
    #[cfg(windows)]
    {
        source::enumerate(&loader::Context::new()?, false)
    }
    #[cfg(not(windows))]
    {
        Err(Error::UnsupportedPlatform)
    }
}
pub fn capabilities() -> Result<Capabilities> {
    #[cfg(windows)]
    {
        let _context = loader::Context::new()?;
    }
    #[cfg(not(windows))]
    {
        return Err(Error::UnsupportedPlatform);
    }
    #[allow(unreachable_code)]
    Ok(Capabilities {
        backend: Backend::Pktmon,
        ethernet: true,
        receive: true,
        transmit_observation: true,
        interface_selection: true,
        capture_filtering: true,
        max_snaplen: 9000,
        shared_memory: false,
        drop_statistics: true,
        asynchronous: true,
    })
}
pub fn open(config: Config) -> Result<Box<dyn Session>> {
    config.validate()?;
    #[cfg(windows)]
    {
        Ok(Box::new(PktmonSession::open(config)?))
    }
    #[cfg(not(windows))]
    {
        Err(Error::UnsupportedPlatform)
    }
}
