use winptap_core::*;
/// Serialize the verified session-ID-prefixed constraint without padding leaks.
pub(crate) fn encode(id: u64, filter: &Filter) -> Result<[u8; 224]> {
    let mut bytes = [0; 224];
    bytes[..8].copy_from_slice(&id.to_le_bytes());
    bytes[8..].copy_from_slice(&encode_constraint(filter)?);
    Ok(bytes)
}
