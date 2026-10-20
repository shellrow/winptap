//! Bounds-checked Packet Monitor wire decoding.
use crate::*;
/// Parse a descriptor's offsets without trusting pointer alignment.
pub fn decode_stream(
    bytes: &[u8],
    metadata_offset: u32,
    packet_offset: u32,
    packet_length: u32,
    snaplen: u16,
    backend: Backend,
) -> Result<Packet> {
    fn range(bytes: &[u8], start: u32, len: u32) -> Result<&[u8]> {
        let end = start
            .checked_add(len)
            .ok_or(Error::InvalidData("descriptor overflow"))?;
        bytes
            .get(start as usize..end as usize)
            .ok_or(Error::InvalidData("descriptor outside buffer"))
    }
    // The current driver emits the packed 40-byte wire form, despite the
    // naturally aligned 48-byte declaration in the public reference.
    let packed = packet_offset.checked_sub(metadata_offset) == Some(40);
    let metadata_size = if packed { 40 } else { 48 };
    let m = range(bytes, metadata_offset, metadata_size)?;
    if packet_length > u32::from(snaplen) {
        return Err(Error::InvalidData("packet exceeds snaplen"));
    }
    let payload = range(bytes, packet_offset, packet_length)?;
    if packet_length > 0
        && metadata_offset < packet_offset.saturating_add(packet_length)
        && packet_offset < metadata_offset.saturating_add(metadata_size)
    {
        return Err(Error::InvalidData("overlapping metadata and payload"));
    }
    let u16at = |i| u16::from_le_bytes([m[i], m[i + 1]]);
    let u32at = |i| u32::from_le_bytes(m[i..i + 4].try_into().unwrap());
    let packet_type = u16at(14);
    Packet::new(
        payload.into(),
        PacketMetadata {
            backend,
            link_type: LinkType::from_packet_type(packet_type),
            packet_type,
            timestamp_100ns: i64::from_le_bytes(
                m[if packed { 32..40 } else { 40..48 }].try_into().unwrap(),
            ),
            captured_len: packet_length,
            original_len: None,
            direction: Direction::from_tag(u16at(12)),
            direction_tag: u16at(12),
            component_id: u16at(16),
            interface_guid: None,
            edge_id: u16at(18),
            group_id: u64::from_le_bytes(m[..8].try_into().unwrap()),
            packet_count: u16at(8),
            appearance_count: u16at(10),
            processor: u16at(if packed { 30 } else { 32 }),
            drop_reason: u32at(if packed { 22 } else { 24 }),
            drop_location: u32at(if packed { 26 } else { 28 }),
            truncation: if packet_length == u32::from(snaplen) {
                Truncation::CaptureLimitReached
            } else {
                Truncation::NotIndicated
            },
        },
    )
}
