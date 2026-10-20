use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING},
    System::IO::DeviceIoControl,
};
use winptap_core::*;
pub(crate) struct DeviceHandle(pub HANDLE);
impl DeviceHandle {
    pub fn open() -> Result<Self> {
        crate::compat::require_supported_platform()?;
        let name: Vec<_> = "\\\\.\\PktMonDev\0".encode_utf16().collect();
        let open = || {
            // SAFETY: terminated DOS device name; no borrowed security attributes or template handle.
            unsafe {
                CreateFileW(
                    name.as_ptr(),
                    0xc0000000,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                )
            }
        };
        let mut handle = open();
        if handle == INVALID_HANDLE_VALUE
            && std::io::Error::last_os_error().raw_os_error() == Some(2)
        {
            start_driver()?;
            handle = open();
        }
        if handle == INVALID_HANDLE_VALUE {
            return Err(last_error("CreateFileW(PktMonDev)"));
        }
        Ok(Self(handle))
    }
    pub fn ioctl(
        &self,
        control: crate::ioctl::Control,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        let input_len = u32::try_from(input.len())
            .map_err(|_| Error::InvalidConfig("IOCTL input too large"))?;
        let output_len = u32::try_from(output.len())
            .map_err(|_| Error::InvalidConfig("IOCTL output too large"))?;
        let mut returned = 0;
        // SAFETY: owned device, checked lengths, live input/output buffers,
        // synchronous request; only verified internal control codes reach here.
        let ok = unsafe {
            DeviceIoControl(
                self.0,
                control as u32,
                if input.is_empty() {
                    std::ptr::null()
                } else {
                    input.as_ptr().cast()
                },
                input_len,
                if output.is_empty() {
                    std::ptr::null_mut()
                } else {
                    output.as_mut_ptr().cast()
                },
                output_len,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error("DeviceIoControl"));
        }
        if returned > output_len {
            return Err(Error::InvalidData("IOCTL returned excessive bytes"));
        }
        Ok(returned as usize)
    }
}
fn start_driver() -> Result<()> {
    use windows_sys::Win32::System::Services::*;
    struct Service(SC_HANDLE);
    impl Drop for Service {
        fn drop(&mut self) {
            if self.0.is_null() {
                return;
            }
            // SAFETY: this wrapper owns a service-manager handle.
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
    // SAFETY: null server/database selects the local service manager.
    let manager =
        Service(unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) });
    if manager.0.is_null() {
        return Err(last_error("OpenSCManagerW"));
    }
    let name: Vec<_> = "PktMon\0".encode_utf16().collect();
    // SAFETY: valid manager handle and terminated built-in service name.
    let service = Service(unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_START) });
    if service.0.is_null() {
        return Err(last_error("OpenServiceW(PktMon)"));
    }
    // SAFETY: start the existing signed Windows service without arguments.
    if unsafe { StartServiceW(service.0, 0, std::ptr::null()) } == 0
        && std::io::Error::last_os_error().raw_os_error() != Some(1056)
    {
        return Err(last_error("StartServiceW(PktMon)"));
    }
    Ok(())
}
fn last_error(operation: &'static str) -> Error {
    let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
    if code == 5 {
        Error::PermissionDenied
    } else {
        Error::Windows { operation, code }
    }
}
impl Drop for DeviceHandle {
    fn drop(&mut self) {
        // SAFETY: this owner closes exactly one valid device handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}
