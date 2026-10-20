use winptap::*;
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut capture = Capture::open(
        CaptureConfig::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?,
    )?;
    capture.start()?;
    match capture.next_packet_async().await {
        Ok(Some(p)) => println!("{} bytes", p.data().len()),
        Err(Error::Timeout) | Ok(None) => (),
        Err(e) => return Err(e),
    }
    capture.stop()
}
