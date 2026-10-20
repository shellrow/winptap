//! Independent native Packet Monitor receive backend, for Windows x64.
#[cfg(windows)]
mod buffer;
pub mod compat;
#[cfg(windows)]
mod device;
#[cfg(windows)]
mod discovery;
#[cfg(windows)]
mod filter;
#[cfg(windows)]
mod ioctl;
pub mod protocol;
#[cfg(windows)]
mod session;
use winptap_core::*;
pub fn open(config: Config) -> Result<Box<dyn Session>> {
    config.validate()?;
    compat::require_supported_platform()?;
    #[cfg(windows)]
    {
        Ok(Box::new(session::NativeSession::open(config)?))
    }
    #[cfg(not(windows))]
    {
        Err(Error::UnsupportedPlatform)
    }
}
pub fn capabilities() -> Result<Capabilities> {
    compat::require_supported_platform()?;
    #[cfg(windows)]
    let _probe = device::DeviceHandle::open()?;
    Ok(Capabilities {
        backend: Backend::NativeIoctl,
        ethernet: true,
        receive: true,
        transmit_observation: false,
        interface_selection: true,
        capture_filtering: true,
        max_snaplen: 9000,
        shared_memory: true,
        drop_statistics: true,
        asynchronous: true,
    })
}
pub fn devices() -> Result<Vec<Device>> {
    #[cfg(windows)]
    {
        discovery::enumerate(&device::DeviceHandle::open()?)
    }
    #[cfg(not(windows))]
    {
        Err(Error::UnsupportedPlatform)
    }
}
