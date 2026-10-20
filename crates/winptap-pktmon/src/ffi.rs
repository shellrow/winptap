//! ABI declarations transcribed from the Microsoft Packet Monitor reference.
//! Name capacities are additionally checked against the installed x64 DLL.
use std::ffi::c_void;
pub type Handle = *mut c_void;
pub type HResult = i32;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Source {
    pub kind: u32,
    pub name: [u16; 64],
    pub description: [u16; 128],
    pub id: u32,
    pub secondary_id: u32,
    pub parent_id: u32,
    pub present: u32,
    pub detail: [u64; 2],
}
#[repr(C)]
pub struct Constraint {
    pub name: [u16; 64],
    pub present: u32,
    pub mac1: [u8; 6],
    pub mac2: [u8; 6],
    pub vlan: u16,
    pub ether_type: u16,
    pub dscp: u16,
    pub protocol: u8,
    pub ip1: [u64; 2],
    pub ip2: [u64; 2],
    pub prefix1: u8,
    pub prefix2: u8,
    pub port1: u16,
    pub port2: u16,
    pub tcp_flags: u8,
    pub encap_type: u32,
    pub vxlan_port: u16,
    pub packets: u64,
    pub bytes: u64,
}
#[repr(C)]
pub struct StreamConfig {
    pub context: *mut c_void,
    pub event: unsafe extern "system" fn(*mut c_void, *const EventInfo, u32),
    pub data: unsafe extern "system" fn(*mut c_void, *const Descriptor),
    pub multiplier: u16,
    pub truncation: u16,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Descriptor {
    pub data: *const u8,
    pub size: u32,
    pub metadata_offset: u32,
    pub packet_offset: u32,
    pub packet_length: u32,
    pub missed_writes: u32,
    pub missed_reads: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Metadata {
    pub group: u64,
    pub count: u16,
    pub appearance: u16,
    pub direction: u16,
    pub packet_type: u16,
    pub component: u16,
    pub edge: u16,
    pub reserved: u16,
    pub drop_reason: u32,
    pub drop_location: u32,
    pub processor: u16,
    pub timestamp: i64,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StartInfo {
    pub buffer_size: u32,
    pub truncation: u16,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StopInfo {
    pub fatal: u8,
    pub reason: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessInfo {
    pub warning: u8,
    pub reason: u32,
    pub packet_length: u64,
}
#[repr(C)]
pub union EventInfo {
    pub start: StartInfo,
    pub stop: StopInfo,
    pub process: ProcessInfo,
}
pub type Initialize = unsafe extern "system" fn(u32, *mut c_void, *mut Handle) -> HResult;
pub type Close = unsafe extern "system" fn(Handle);
pub type Enumerate =
    unsafe extern "system" fn(Handle, u32, u8, usize, *mut usize, *mut c_void) -> HResult;
pub type CreateSession = unsafe extern "system" fn(Handle, *const u16, *mut Handle) -> HResult;
pub type AddSource = unsafe extern "system" fn(Handle, *const Source) -> HResult;
pub type AddConstraint = unsafe extern "system" fn(Handle, *const Constraint) -> HResult;
pub type CreateStream =
    unsafe extern "system" fn(Handle, *const StreamConfig, *mut Handle) -> HResult;
pub type Attach = unsafe extern "system" fn(Handle, Handle) -> HResult;
pub type Active = unsafe extern "system" fn(Handle, u8) -> HResult;
const _: () = {
    assert!(std::mem::size_of::<Source>() == 424);
    assert!(std::mem::offset_of!(Source, id) == 388);
    assert!(std::mem::size_of::<Constraint>() == 216);
    assert!(std::mem::offset_of!(Constraint, ip1) == 152);
    assert!(std::mem::size_of::<Metadata>() == 48);
    assert!(std::mem::offset_of!(Metadata, timestamp) == 40);
    assert!(std::mem::offset_of!(Metadata, drop_reason) == 24);
};
