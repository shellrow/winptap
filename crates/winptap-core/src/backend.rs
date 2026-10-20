use crate::*;
use std::sync::Arc;
#[derive(Clone, Copy, Debug)]
pub struct Capabilities {
    pub backend: Backend,
    pub ethernet: bool,
    pub receive: bool,
    pub transmit_observation: bool,
    pub interface_selection: bool,
    pub capture_filtering: bool,
    pub max_snaplen: u16,
    pub shared_memory: bool,
    pub drop_statistics: bool,
    pub asynchronous: bool,
}
#[derive(Clone, Copy, Debug, Default)]
pub enum OverflowPolicy {
    #[default]
    DropNewest,
    DropOldest,
}
/// No heuristic deduplication is performed.
#[derive(Clone, Copy, Debug, Default)]
pub enum DuplicatePolicy {
    #[default]
    PreserveAll,
    Component(u16),
}
#[derive(Clone, Debug)]
pub struct Config {
    pub backend: Backend,
    pub device: Option<Device>,
    pub link_type: Option<LinkType>,
    pub snaplen: u16,
    pub ring_multiplier: u16,
    pub queue_capacity: usize,
    pub overflow: OverflowPolicy,
    pub duplicates: DuplicatePolicy,
    pub capture_filter: Option<Filter>,
    pub application_filter: Option<Filter>,
    pub timeout: Option<std::time::Duration>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            backend: Backend::Auto,
            device: None,
            link_type: None,
            snaplen: 9000,
            ring_multiplier: 1,
            queue_capacity: 1024,
            overflow: OverflowPolicy::DropNewest,
            duplicates: DuplicatePolicy::PreserveAll,
            capture_filter: None,
            application_filter: None,
            timeout: None,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.snaplen == 0 || self.snaplen > 9000 {
            return Err(Error::InvalidConfig("snaplen must be 1..=9000"));
        }
        if !(1..=10).contains(&self.ring_multiplier) {
            return Err(Error::InvalidConfig("ring multiplier must be 1..=10"));
        }
        if self.queue_capacity == 0 || self.queue_capacity > 1_048_576 {
            return Err(Error::InvalidConfig("queue capacity must be 1..=1048576"));
        }
        if let Some(f) = &self.capture_filter {
            f.validate()?;
        }
        if let Some(f) = &self.application_filter {
            f.validate()?;
        }
        Ok(())
    }
}
pub trait Session {
    fn start(&mut self) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
    fn queue(&self) -> Arc<PacketQueue>;
}
