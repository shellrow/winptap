//! Native Packet Monitor control codes.
#[repr(u32)]
#[derive(Clone, Copy)]
pub(crate) enum Control {
    EnumerateComponents = 0x220418,
    CreateSession = 0x228434,
    DeleteSession = 0x228438,
    AddConstraint = 0x228440,
    Activate = 0x228450,
    Deactivate = 0x228454,
    SelectComponents = 0x228460,
    AttachStream = 0x22042c,
    DetachStream = 0x220430,
}
