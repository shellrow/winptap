use winptap::*;
fn main() -> Result<()> {
    let backend = if std::env::args().any(|a| a == "--native") {
        Backend::NativeIoctl
    } else {
        Backend::Pktmon
    };
    let mut capture = Capture::open(
        CaptureConfig::builder()
            .backend(backend)
            .timeout(std::time::Duration::from_millis(100))
            .build()?,
    )?;
    capture.start()?;
    let start = std::time::Instant::now();
    let mut bytes = 0u64;
    while start.elapsed().as_secs() < 10 {
        match capture.next_packet() {
            Ok(Some(p)) => bytes += p.data().len() as u64,
            Err(Error::Timeout) => (),
            Ok(None) => break,
            Err(e) => return Err(e),
        }
    }
    capture.stop()?;
    println!(
        "seconds={},bytes={},stats={:?}",
        start.elapsed().as_secs_f64(),
        bytes,
        capture.statistics()
    );
    Ok(())
}
