use winptap_core::*;
/// Require the architecture used by the native IOCTL wire layouts.
pub fn require_supported_platform() -> Result<()> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        Ok(())
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        Err(Error::UnsupportedPlatform)
    }
}
