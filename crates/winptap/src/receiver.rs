use crate::*;
use std::{
    sync::{Arc, mpsc},
    thread::JoinHandle,
    time::Duration,
};
use winptap_core::{PacketQueue, Session};

/// A movable receiver whose capture session lives on a dedicated owner thread.
///
/// Opening starts capture. Stopping or dropping joins the owner and releases its
/// resources. Normal stop preserves queued packets; cancellation and fatal errors
/// discard delivery. This receiver cannot restart. No extra packet queue or copy
/// is introduced. Unlike [`Capture`], this type implements `Send`.
pub struct PacketReceiver {
    queue: Arc<PacketQueue>,
    owner: Option<JoinHandle<Result<()>>>,
    timeout: Option<Duration>,
}

impl PacketReceiver {
    /// Open and start capture, returning initialization failures synchronously.
    pub fn open(config: CaptureConfig) -> Result<Self> {
        config.0.validate()?;
        let timeout = config.0.timeout;
        Self::open_with(timeout, move || crate::capture::open_backend(config.0))
    }

    fn open_with(
        timeout: Option<Duration>,
        factory: impl FnOnce() -> Result<Box<dyn Session>> + Send + 'static,
    ) -> Result<Self> {
        let (ready, started) = mpsc::sync_channel(1);
        let owner = std::thread::Builder::new()
            .name("winptap-session".into())
            .spawn(move || {
                let mut session = factory()?;
                session.start()?;
                let queue = session.queue();
                if ready.send(queue.clone()).is_ok() {
                    queue.wait_closed();
                }
                session.stop()
            })
            .map_err(|e| Error::Windows {
                operation: "spawn capture owner",
                code: e.raw_os_error().unwrap_or(8) as u32,
            })?;
        match started.recv() {
            Ok(queue) => Ok(Self {
                queue,
                owner: Some(owner),
                timeout,
            }),
            Err(_) => match owner.join() {
                Ok(Err(error)) => Err(error),
                _ => Err(Error::StreamFailed(1359)),
            },
        }
    }

    /// Wait for a packet, a configured timeout, or a terminal condition.
    pub fn next_packet(&mut self) -> Result<Option<Packet>> {
        self.queue.receive(self.timeout)
    }

    /// Poll without waiting. An empty active queue returns [`Error::Timeout`].
    pub fn try_next_packet(&mut self) -> Result<Option<Packet>> {
        self.queue.receive(Some(Duration::ZERO))
    }

    /// Receive without blocking the executor. Dropping the future consumes no packet.
    #[cfg(feature = "tokio")]
    pub async fn next_packet_async(&mut self) -> Result<Option<Packet>> {
        match self.timeout {
            Some(timeout) => tokio::time::timeout(timeout, self.queue.receive_async())
                .await
                .map_err(|_| Error::Timeout)?,
            None => self.queue.receive_async().await,
        }
    }

    /// Stop capture and join its owner. Queued packets remain readable.
    pub fn stop(&mut self) -> Result<()> {
        self.queue.close(Ok(()));
        match self.owner.take() {
            Some(owner) => owner.join().map_err(|_| Error::StreamFailed(1359))?,
            None => Ok(()),
        }
    }

    /// Cancellation wakes receivers and releases the session on its owner thread.
    pub fn cancellation_token(&self) -> CancellationToken {
        CancellationToken(self.queue.clone())
    }

    /// Return cumulative capture and delivery statistics.
    pub fn statistics(&self) -> Statistics {
        self.queue.stats()
    }
}

impl Drop for PacketReceiver {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        rc::Rc,
        sync::atomic::{AtomicBool, Ordering},
    };

    struct FakeSession {
        queue: Arc<PacketQueue>,
        dropped: Arc<AtomicBool>,
        // A non-Send session must be constructed and destroyed on its owner.
        _affinity: Rc<()>,
        owner: std::thread::ThreadId,
        start_error: bool,
    }
    impl Session for FakeSession {
        fn start(&mut self) -> Result<()> {
            if self.start_error {
                Err(Error::PermissionDenied)
            } else {
                Ok(())
            }
        }
        fn stop(&mut self) -> Result<()> {
            self.queue.close(Ok(()));
            Ok(())
        }
        fn queue(&self) -> Arc<PacketQueue> {
            self.queue.clone()
        }
    }
    impl Drop for FakeSession {
        fn drop(&mut self) {
            assert_eq!(self.owner, std::thread::current().id());
            self.dropped.store(true, Ordering::Release);
        }
    }
    fn fake(start_error: bool) -> (Result<PacketReceiver>, Arc<AtomicBool>) {
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = dropped.clone();
        let result = PacketReceiver::open_with(Some(Duration::ZERO), move || {
            Ok(Box::new(FakeSession {
                queue: PacketQueue::new(2, OverflowPolicy::DropNewest),
                dropped: flag,
                _affinity: Rc::new(()),
                owner: std::thread::current().id(),
                start_error,
            }))
        });
        (result, dropped)
    }
    #[test]
    fn movable_receiver_preserves_owner_affinity_and_joins() {
        let (receiver, dropped) = fake(false);
        std::thread::spawn(move || {
            let mut receiver = receiver.unwrap();
            assert_eq!(receiver.try_next_packet().unwrap_err(), Error::Timeout);
            receiver.stop().unwrap();
            assert!(receiver.next_packet().unwrap().is_none());
            receiver.stop().unwrap();
        })
        .join()
        .unwrap();
        assert!(dropped.load(Ordering::Acquire));
    }
    #[test]
    fn failed_start_releases_owner_before_return() {
        let (receiver, dropped) = fake(true);
        assert!(matches!(receiver, Err(Error::PermissionDenied)));
        assert!(dropped.load(Ordering::Acquire));
    }
    #[test]
    fn cancellation_and_drop_join_owner() {
        let (receiver, dropped) = fake(false);
        let mut receiver = receiver.unwrap();
        receiver.cancellation_token().cancel();
        assert_eq!(receiver.next_packet().unwrap_err(), Error::Cancelled);
        drop(receiver);
        assert!(dropped.load(Ordering::Acquire));
    }

    #[test]
    fn normal_stop_drains_packets_without_copying() {
        let (receiver, dropped) = fake(false);
        let mut receiver = receiver.unwrap();
        let mut bytes = [0; 41];
        bytes[40] = 123;
        let packet =
            winptap_core::wire::decode_stream(&bytes, 0, 40, 1, 9000, Backend::Pktmon).unwrap();
        let address = packet.data().as_ptr();
        receiver.queue.push(packet);
        receiver.stop().unwrap();
        assert!(dropped.load(Ordering::Acquire));
        let packet = receiver.next_packet().unwrap().unwrap();
        assert_eq!(packet.data().as_ptr(), address);
        assert_eq!(packet.data(), &[123]);
        assert!(receiver.next_packet().unwrap().is_none());
        assert_eq!(receiver.statistics().delivered, 1);
    }

    #[test]
    fn drop_stops_an_idle_capture_and_open_errors_propagate() {
        let (receiver, dropped) = fake(false);
        drop(receiver.unwrap());
        assert!(dropped.load(Ordering::Acquire));
        assert!(matches!(
            PacketReceiver::open_with(None, || Err(Error::RevisionMismatch)),
            Err(Error::RevisionMismatch)
        ));
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn async_receive_future_is_send() {
        fn assert_send<T: Send>(_: T) {}
        let (receiver, _) = fake(false);
        let mut receiver = receiver.unwrap();
        assert_send(receiver.next_packet_async());
    }
}
