/// Requested or actual capture backend.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Backend {
    #[default]
    Auto,
    Pktmon,
    NativeIoctl,
}
/// The actual starting header of the delivered bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    Wifi,
    RawIp,
    Other(u16),
}
impl LinkType {
    pub fn from_packet_type(value: u16) -> Self {
        match value {
            1 => Self::Ethernet,
            2 => Self::Wifi,
            3 => Self::RawIp,
            n => Self::Other(n),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Receive,
    Transmit,
    Unknown(u16),
}
impl Direction {
    pub fn from_tag(tag: u16) -> Self {
        match tag {
            1 | 3 | 5 => Self::Receive,
            2 | 4 | 6 => Self::Transmit,
            n => Self::Unknown(n),
        }
    }
}
/// A limit being reached does not prove that the packet was truncated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Truncation {
    NotIndicated,
    CaptureLimitReached,
    Known,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub backend: Backend,
    pub id: u32,
    pub secondary_id: u32,
    pub parent_id: u32,
    pub name: String,
    pub description: String,
    pub network_interface: bool,
    /// Raw Windows GUID bytes, when the source supplies them.
    pub guid: Option<[u8; 16]>,
}
#[derive(Clone, Debug)]
pub struct PacketMetadata {
    pub backend: Backend,
    pub link_type: LinkType,
    pub packet_type: u16,
    /// Windows system time: 100-nanosecond intervals since 1601-01-01 UTC.
    pub timestamp_100ns: i64,
    pub captured_len: u32,
    pub original_len: Option<u32>,
    pub direction: Direction,
    pub direction_tag: u16,
    pub component_id: u16,
    /// Selected NIC identity when the source-to-interface mapping is known.
    pub interface_guid: Option<[u8; 16]>,
    pub edge_id: u16,
    pub group_id: u64,
    pub packet_count: u16,
    pub appearance_count: u16,
    pub processor: u16,
    pub drop_reason: u32,
    pub drop_location: u32,
    pub truncation: Truncation,
}
#[derive(Clone, Debug)]
pub struct Packet {
    data: Box<[u8]>,
    metadata: PacketMetadata,
}
impl Packet {
    pub fn new(data: Box<[u8]>, metadata: PacketMetadata) -> crate::Result<Self> {
        if data.len() != metadata.captured_len as usize {
            return Err(crate::Error::InvalidData("captured length mismatch"));
        }
        if metadata
            .original_len
            .is_some_and(|n| n < metadata.captured_len)
        {
            return Err(crate::Error::InvalidData(
                "original length smaller than capture",
            ));
        }
        Ok(Self { data, metadata })
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    pub fn metadata(&self) -> &PacketMetadata {
        &self.metadata
    }
    /// Associate a verified interface identity without modifying packet bytes.
    pub fn with_interface_guid(mut self, guid: Option<[u8; 16]>) -> Self {
        self.metadata.interface_guid = guid;
        self
    }
    /// Attach an original length supplied by the backend's record header.
    pub fn with_original_len(mut self, length: u32) -> crate::Result<Self> {
        if length < self.metadata.captured_len {
            return Err(crate::Error::InvalidData(
                "original length smaller than capture",
            ));
        }
        self.metadata.original_len = Some(length);
        self.metadata.truncation = if length > self.metadata.captured_len {
            Truncation::Known
        } else {
            Truncation::NotIndicated
        };
        Ok(self)
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statistics {
    pub received: u64,
    pub delivered: u64,
    pub queue_overflow: u64,
    pub missed_reads: u64,
    pub missed_writes: u64,
    pub parse_errors: u64,
    pub capture_limit_reached: u64,
    pub known_truncations: u64,
    pub filtered: u64,
    pub stream_warnings: u64,
    pub oversized_packets: u64,
}
