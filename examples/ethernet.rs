use winptap::*;
fn main() -> Result<()> {
    let mut capture = Capture::open(
        CaptureConfig::builder()
            .link_type(LinkType::Ethernet)
            .timeout(std::time::Duration::from_secs(5))
            .build()?,
    )?;
    capture.start()?;
    if let Some(packet) = capture.next_packet()? {
        if let Some(header) = packet.data().get(..14) {
            println!(
                "destination={:02x?} source={:02x?} type={:02x?}",
                &header[..6],
                &header[6..12],
                &header[12..14]
            );
        }
    }
    capture.stop()
}
