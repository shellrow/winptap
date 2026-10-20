//! Offline parsers for statically observed control replies.
//! These observations do not authorize issuing the corresponding IOCTLs.
use winptap_core::*;
/// Observed output size of the modern create-session call on the research DLL.
pub const CREATE_SESSION_REPLY_SIZE: usize = 0x210;
#[derive(Debug, PartialEq, Eq)]
pub struct SessionReply {
    pub identifier: u64,
    pub opaque: [u8; 520],
}
pub fn parse_session_reply(bytes: &[u8]) -> Result<SessionReply> {
    if bytes.len() != CREATE_SESSION_REPLY_SIZE {
        return Err(Error::InvalidData("native session reply size"));
    }
    Ok(SessionReply {
        identifier: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        opaque: bytes[8..].try_into().unwrap(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_every_wrong_size() {
        for size in 0..1024 {
            assert_eq!(
                parse_session_reply(&vec![0; size]).is_ok(),
                size == CREATE_SESSION_REPLY_SIZE
            );
        }
    }
}
