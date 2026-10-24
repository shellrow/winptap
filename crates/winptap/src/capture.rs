use crate::*;
use std::{sync::Arc, time::Duration};
#[derive(Clone, Debug, Default)]
pub struct CaptureConfig(pub(crate) winptap_core::Config);
impl CaptureConfig {
    pub fn builder() -> CaptureConfigBuilder {
        CaptureConfigBuilder::default()
    }
}
#[derive(Clone, Debug, Default)]
pub struct CaptureConfigBuilder(winptap_core::Config);
impl CaptureConfigBuilder {
    pub fn backend(mut self, value: Backend) -> Self {
        self.0.backend = value;
        self
    }
    pub fn device(mut self, value: CaptureDevice) -> Self {
        self.0.device = Some(value.0);
        self
    }
    pub fn link_type(mut self, value: LinkType) -> Self {
        self.0.link_type = Some(value);
        self
    }
    pub fn snaplen(mut self, value: u16) -> Self {
        self.0.snaplen = value;
        self
    }
    pub fn ring_multiplier(mut self, value: u16) -> Self {
        self.0.ring_multiplier = value;
        self
    }
    pub fn queue_capacity(mut self, value: usize) -> Self {
        self.0.queue_capacity = value;
        self
    }
    pub fn overflow_policy(mut self, value: OverflowPolicy) -> Self {
        self.0.overflow = value;
        self
    }
    pub fn duplicate_policy(mut self, value: DuplicatePolicy) -> Self {
        self.0.duplicates = value;
        self
    }
    pub fn capture_filter(mut self, value: Filter) -> Self {
        self.0.capture_filter = Some(value);
        self
    }
    pub fn application_filter(mut self, value: Filter) -> Self {
        self.0.application_filter = Some(value);
        self
    }
    pub fn timeout(mut self, value: Duration) -> Self {
        self.0.timeout = Some(value);
        self
    }
    pub fn build(self) -> Result<CaptureConfig> {
        self.0.validate()?;
        Ok(CaptureConfig(self.0))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureState {
    Configured,
    Running,
    Stopped,
}
/// A single-owner capture session. Use the cancellation token across threads.
pub struct Capture {
    session: Box<dyn winptap_core::Session>,
    queue: Arc<winptap_core::PacketQueue>,
    timeout: Option<Duration>,
    state: CaptureState,
}
impl Capture {
    pub fn open(config: CaptureConfig) -> Result<Self> {
        config.0.validate()?;
        let timeout = config.0.timeout;
        let session = open_backend(config.0)?;
        Ok(Self {
            queue: session.queue(),
            session,
            timeout,
            state: CaptureState::Configured,
        })
    }
    pub fn state(&self) -> CaptureState {
        self.state
    }
    pub fn start(&mut self) -> Result<()> {
        if self.state == CaptureState::Running {
            return Err(Error::InvalidState);
        }
        self.session.start()?;
        self.state = CaptureState::Running;
        Ok(())
    }
    /// Stop capture. Queued packets remain available, including across restart.
    pub fn stop(&mut self) -> Result<()> {
        self.session.stop()?;
        self.state = CaptureState::Stopped;
        Ok(())
    }
    pub fn next_packet(&mut self) -> Result<Option<Packet>> {
        if self.state == CaptureState::Configured {
            return Err(Error::InvalidState);
        }
        let result = self.queue.receive(self.timeout);
        self.finish_receive(result)
    }
    pub fn try_next_packet(&mut self) -> Result<Option<Packet>> {
        if self.state == CaptureState::Configured {
            return Err(Error::InvalidState);
        }
        let result = self.queue.receive(Some(Duration::ZERO));
        self.finish_receive(result)
    }
    #[cfg(feature = "tokio")]
    pub async fn next_packet_async(&mut self) -> Result<Option<Packet>> {
        if self.state == CaptureState::Configured {
            return Err(Error::InvalidState);
        }
        let result = match self.timeout {
            Some(t) => tokio::time::timeout(t, self.queue.receive_async())
                .await
                .map_err(|_| Error::Timeout)?,
            None => self.queue.receive_async().await,
        };
        self.finish_receive(result)
    }
    pub fn cancellation_token(&self) -> CancellationToken {
        CancellationToken(self.queue.clone())
    }
    pub fn statistics(&self) -> Statistics {
        self.queue.stats()
    }
    fn finish_receive(&mut self, result: Result<Option<Packet>>) -> Result<Option<Packet>> {
        if matches!(&result, Ok(None)) || matches!(&result,Err(e) if *e != Error::Timeout) {
            let stop_result = self.stop();
            if result.is_ok() {
                stop_result?;
            }
        }
        result
    }
}
pub(crate) fn open_backend(config: winptap_core::Config) -> Result<Box<dyn winptap_core::Session>> {
    let selected = if config.backend == Backend::Auto {
        config.device.as_ref().map_or(Backend::Auto, |d| d.backend)
    } else {
        config.backend
    };
    match selected {
        Backend::Auto => {
            #[cfg(feature = "pktmon")]
            match winptap_pktmon::open(config.clone()) {
                Ok(s) => return Ok(s),
                Err(Error::MissingApi(_) | Error::RevisionMismatch) => (),
                Err(e) => return Err(e),
            }
            #[cfg(feature = "native")]
            {
                winptap_native::open(config)
            }
            #[cfg(not(feature = "native"))]
            {
                Err(Error::MissingApi("no compatible enabled backend".into()))
            }
        }
        #[cfg(feature = "pktmon")]
        Backend::Pktmon => winptap_pktmon::open(config),
        #[cfg(feature = "native")]
        Backend::NativeIoctl => winptap_native::open(config),
        #[allow(unreachable_patterns)]
        _ => Err(Error::MissingApi(
            "requested backend feature is disabled".into(),
        )),
    }
}
