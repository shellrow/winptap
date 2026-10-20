use crate::*;
use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};
struct State {
    packets: VecDeque<Packet>,
    terminal: Option<Result<()>>,
    stats: Statistics,
}
/// Bounded callback-to-consumer queue. Callbacks never wait for capacity.
pub struct PacketQueue {
    state: Mutex<State>,
    ready: Condvar,
    capacity: usize,
    policy: OverflowPolicy,
    #[cfg(feature = "tokio")]
    notify: tokio::sync::Notify,
}
impl PacketQueue {
    pub fn new(capacity: usize, policy: OverflowPolicy) -> Arc<Self> {
        assert!(capacity > 0);
        Arc::new(Self {
            state: Mutex::new(State {
                packets: VecDeque::new(),
                terminal: None,
                stats: Statistics::default(),
            }),
            ready: Condvar::new(),
            capacity,
            policy,
            #[cfg(feature = "tokio")]
            notify: tokio::sync::Notify::new(),
        })
    }
    fn wake(&self) {
        self.ready.notify_all();
        #[cfg(feature = "tokio")]
        self.notify.notify_one();
    }
    pub fn push(&self, packet: Packet) {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if s.terminal.is_some() {
            return;
        }
        if s.packets.len() == self.capacity {
            s.stats.queue_overflow += 1;
            match self.policy {
                OverflowPolicy::DropNewest => return,
                OverflowPolicy::DropOldest => {
                    s.packets.pop_front();
                }
            }
        }
        s.packets.push_back(packet);
        drop(s);
        self.wake();
    }
    pub fn update_stats(&self, f: impl FnOnce(&mut Statistics)) {
        f(&mut self.state.lock().unwrap_or_else(|p| p.into_inner()).stats);
    }
    pub fn stats(&self) -> Statistics {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).stats
    }
    pub fn is_closed(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .terminal
            .is_some()
    }
    pub fn close(&self, result: Result<()>) {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if s.terminal.is_none() {
            s.terminal = Some(result);
        }
        drop(s);
        self.wake();
    }
    /// Reopen a normally stopped queue; queued observations remain available.
    pub fn reopen(&self) -> Result<()> {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(Err(e)) = &s.terminal {
            return Err(e.clone());
        }
        s.terminal = None;
        Ok(())
    }
    /// Return Timeout when no packet is ready, including a zero-duration poll.
    pub fn receive(&self, timeout: Option<Duration>) -> Result<Option<Packet>> {
        let start = Instant::now();
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(Err(e)) = &s.terminal {
                return Err(e.clone());
            }
            if let Some(p) = s.packets.pop_front() {
                s.stats.delivered += 1;
                return Ok(Some(p));
            }
            if s.terminal.is_some() {
                return Ok(None);
            }
            s = match timeout {
                None => self.ready.wait(s).unwrap_or_else(|p| p.into_inner()),
                Some(t) => {
                    let remaining = t.checked_sub(start.elapsed()).ok_or(Error::Timeout)?;
                    self.ready
                        .wait_timeout(s, remaining)
                        .unwrap_or_else(|p| p.into_inner())
                        .0
                }
            };
        }
    }
    #[cfg(feature = "tokio")]
    pub async fn receive_async(&self) -> Result<Option<Packet>> {
        loop {
            let notified = self.notify.notified();
            match self.receive(Some(Duration::ZERO)) {
                Err(Error::Timeout) => notified.await,
                result => return result,
            }
        }
    }
}
/// Wakes blocked consumers. Drop the capture to release operating-system resources.
#[derive(Clone)]
pub struct CancellationToken(pub Arc<PacketQueue>);
impl CancellationToken {
    pub fn cancel(&self) {
        self.0.close(Err(Error::Cancelled));
    }
}
