#[path = "support/dump_format.rs"]
mod dump_format;
mod support;
use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use winptap::{Backend, Capture, CaptureConfig, Error};

fn main() -> support::Result<()> {
    let options = support::Options::parse(Backend::Auto, None)?;
    let Some(device) = options.select()? else {
        return Ok(());
    };
    let running = Arc::new(AtomicBool::new(true));
    let interrupt = running.clone();
    ctrlc::set_handler(move || {
        interrupt.store(false, Ordering::Relaxed);
    })?;
    let mut capture = Capture::open(
        CaptureConfig::builder()
            .backend(options.backend)
            .device(device)
            .timeout(Duration::from_millis(250))
            .build()?,
    )?;
    capture.start()?;
    eprintln!("Listening; press Ctrl+C to stop.");
    let mut output = io::stdout().lock();
    let mut count = 0;
    while running.load(Ordering::Relaxed) && options.count.is_none_or(|limit| count < limit) {
        match capture.next_packet() {
            Ok(Some(packet)) => {
                let line = dump_format::format_packet(&packet);
                if let Err(error) = writeln!(output, "{line}").and_then(|()| output.flush()) {
                    if error.kind() == io::ErrorKind::BrokenPipe {
                        break;
                    }
                    return Err(error.into());
                }
                count += 1;
            }
            Err(Error::Timeout) => continue,
            Ok(None) => break,
            Err(error) => return Err(error.into()),
        }
    }
    capture.stop()?;
    eprintln!("{:?}", capture.statistics());
    Ok(())
}
