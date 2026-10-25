//! Windows Packet Monitor capture with bounded, byte-preserving delivery.
//!
//! The official backend requires administrator privileges and modern streaming
//! exports. Native IOCTL capture requires Windows x64 and administrator privileges.
//! See the repository compatibility document before deploying this library.
#![forbid(unsafe_code)]
mod capture;
mod device;
mod receiver;
pub use capture::*;
pub use device::InterfaceIdentity;
pub use receiver::PacketReceiver;
pub use winptap_core::{
    Backend, CancellationToken, Capabilities, Direction, DuplicatePolicy, Error, Filter, LinkType,
    OverflowPolicy, Packet, PacketMetadata, Result, Statistics, Truncation,
};

#[derive(Clone, Debug)]
pub struct CaptureDevice(pub winptap_core::Device);
impl CaptureDevice {
    pub fn list_with_backend(backend: Backend) -> Result<Vec<Self>> {
        let devices: Vec<winptap_core::Device> = match backend {
            Backend::Auto => {
                #[cfg(feature = "pktmon")]
                match winptap_pktmon::devices() {
                    Ok(d) => return Ok(d.into_iter().map(Self).collect()),
                    Err(Error::MissingApi(_) | Error::RevisionMismatch) => (),
                    Err(e) => return Err(e),
                }
                #[cfg(feature = "native")]
                {
                    winptap_native::devices()
                }
                #[cfg(not(feature = "native"))]
                {
                    Err(Error::MissingApi("no compatible enabled backend".into()))
                }
            }
            #[cfg(feature = "pktmon")]
            Backend::Pktmon => winptap_pktmon::devices(),
            #[cfg(feature = "native")]
            Backend::NativeIoctl => winptap_native::devices(),
            #[allow(unreachable_patterns)]
            _ => Err(Error::MissingApi(
                "requested backend feature is disabled".into(),
            )),
        }?;
        Ok(devices.into_iter().map(Self).collect())
    }
    pub fn list() -> Result<Vec<Self>> {
        Self::list_with_backend(Backend::Auto)
    }
}
impl std::ops::Deref for CaptureDevice {
    type Target = winptap_core::Device;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
/// Probe current API availability and privileges, not historical OS branding.
pub fn capabilities(backend: Backend) -> Result<Capabilities> {
    let mut capabilities: Capabilities = match backend {
        Backend::Auto => {
            #[cfg(feature = "pktmon")]
            match winptap_pktmon::capabilities() {
                Ok(mut c) => {
                    c.asynchronous = cfg!(feature = "tokio");
                    return Ok(c);
                }
                Err(Error::MissingApi(_) | Error::RevisionMismatch) => (),
                Err(e) => return Err(e),
            }
            #[cfg(feature = "native")]
            {
                winptap_native::capabilities()
            }
            #[cfg(not(feature = "native"))]
            {
                Err(Error::MissingApi("no compatible enabled backend".into()))
            }
        }
        #[cfg(feature = "pktmon")]
        Backend::Pktmon => winptap_pktmon::capabilities(),
        #[cfg(feature = "native")]
        Backend::NativeIoctl => winptap_native::capabilities(),
        #[allow(unreachable_patterns)]
        _ => Err(Error::MissingApi(
            "requested backend feature is disabled".into(),
        )),
    }?;
    capabilities.asynchronous = cfg!(feature = "tokio");
    Ok(capabilities)
}
