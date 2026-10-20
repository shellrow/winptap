fn main() -> winptap::Result<()> {
    for device in winptap::CaptureDevice::list()? {
        println!("{device:#?}");
    }
    Ok(())
}
