mod support;
use winptap::*;
fn main() -> support::Result<()> {
    let options = support::Options::parse(Backend::NativeIoctl, Some(10))?;
    let Some(device) = options.select()? else {
        return Ok(());
    };
    let mut capture = Capture::open(
        CaptureConfig::builder()
            .backend(options.backend)
            .device(device)
            .timeout(std::time::Duration::from_secs(5))
            .build()?,
    )?;
    capture.start()?;
    for _ in 0..options.count.unwrap_or(10) {
        match capture.next_packet() {
            Ok(Some(packet)) => println!("{} bytes: {:?}", packet.data().len(), packet.metadata()),
            Err(Error::Timeout) | Ok(None) => break,
            Err(e) => return Err(e.into()),
        }
    }
    capture.stop()?;
    println!("{:?}", capture.statistics());
    Ok(())
}
