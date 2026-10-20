use crate::ffi::*;
use windows_sys::Win32::{
    Foundation::FreeLibrary,
    System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
};
use winptap_core::*;
struct Module(windows_sys::Win32::Foundation::HMODULE);
impl Drop for Module {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        // SAFETY: this module was loaded successfully and owns one loader reference.
        unsafe {
            FreeLibrary(self.0);
        }
    }
}
pub(crate) struct Api {
    pub initialize: Initialize,
    pub uninitialize: Close,
    pub enumerate: Enumerate,
    pub create_session: CreateSession,
    pub close_session: Close,
    pub add_source: AddSource,
    pub add_constraint: AddConstraint,
    pub create_stream: CreateStream,
    pub close_stream: Close,
    pub attach: Attach,
    pub active: Active,
    _module: Module,
}
impl Api {
    fn load() -> Result<Self> {
        let name: Vec<_> = "Pktmonapi.dll\0".encode_utf16().collect();
        // SAFETY: terminated name, no file handle, restricted System32 search.
        let module = Module(unsafe {
            LoadLibraryExW(
                name.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        });
        if module.0.is_null() {
            return Err(Error::MissingApi(format!(
                "Pktmonapi.dll: {}",
                std::io::Error::last_os_error()
            )));
        }
        macro_rules! load {
            ($name:literal, $ty:ty) => {{
                // SAFETY: module remains loaded; export name is NUL terminated.
                let p = unsafe { GetProcAddress(module.0, concat!($name, "\0").as_ptr()) }
                    .ok_or_else(|| Error::MissingApi($name.into()))?;
                // SAFETY: the named export's documented ABI is exactly $ty.
                unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(p) }
            }};
        }
        Ok(Self {
            initialize: load!("PacketMonitorInitialize", Initialize),
            uninitialize: load!("PacketMonitorUninitialize", Close),
            enumerate: load!("PacketMonitorEnumDataSources", Enumerate),
            create_session: load!("PacketMonitorCreateLiveSession", CreateSession),
            close_session: load!("PacketMonitorCloseSessionHandle", Close),
            add_source: load!("PacketMonitorAddSingleDataSourceToSession", AddSource),
            add_constraint: load!("PacketMonitorAddCaptureConstraint", AddConstraint),
            create_stream: load!("PacketMonitorCreateRealtimeStream", CreateStream),
            close_stream: load!("PacketMonitorCloseRealtimeStream", Close),
            attach: load!("PacketMonitorAttachOutputToSession", Attach),
            active: load!("PacketMonitorSetSessionActive", Active),
            _module: module,
        })
    }
}
pub(crate) struct Context {
    pub api: Api,
    pub handle: Handle,
}
impl Context {
    pub fn new() -> Result<Self> {
        let api = Api::load()?;
        let mut handle = std::ptr::null_mut();
        // SAFETY: correct API version, reserved null and valid output pointer.
        hresult("PacketMonitorInitialize", unsafe {
            (api.initialize)(0x10000, std::ptr::null_mut(), &mut handle)
        })?;
        if handle.is_null() {
            return Err(Error::InvalidData("null monitor handle"));
        }
        Ok(Self { api, handle })
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: owned monitor outlives all sessions and streams using it.
        unsafe {
            (self.api.uninitialize)(self.handle);
        }
    }
}
