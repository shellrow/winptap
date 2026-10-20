use winptap_core::*;
/// Builds with recorded independent native capture validation; informational only.
pub const VALIDATED_BUILDS: &[u32] = &[26200];
/// Revisions with recorded validation; this list is not a runtime allowlist.
pub const VALIDATED_REVISIONS: &[(u32, u32)] = &[(26200, 9457)];
#[cfg(windows)]
#[repr(C)]
struct Version {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    service_pack: [u16; 128],
}
#[cfg(windows)]
#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlGetVersion(version: *mut Version) -> i32;
}
pub fn current_build() -> Result<u32> {
    #[cfg(windows)]
    {
        let mut version = Version {
            size: std::mem::size_of::<Version>() as u32,
            major: 0,
            minor: 0,
            build: 0,
            platform: 0,
            service_pack: [0; 128],
        };
        // SAFETY: correctly sized writable OSVERSIONINFOW; no manifest-dependent version API.
        let status = unsafe { RtlGetVersion(&mut version) };
        if status < 0 {
            return Err(Error::Windows {
                operation: "RtlGetVersion",
                code: status as u32,
            });
        }
        Ok(version.build)
    }
    #[cfg(not(windows))]
    {
        Err(Error::UnsupportedPlatform)
    }
}
/// Require the architecture used by the native IOCTL wire layouts.
/// Windows build numbers and driver hashes do not restrict runtime access.
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
