use crate::{
    ffi::*,
    loader::Context,
    source,
    stream::{self, Callback},
};
use std::{
    ptr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use winptap_core::*;
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
/// Thread-affine owner. Callbacks only access the separate synchronized context.
pub struct PktmonSession {
    context: Context,
    session: Handle,
    stream: Handle,
    callback: Box<Callback>,
    started: bool,
    stopped: bool,
}
impl PktmonSession {
    pub fn open(config: Config) -> Result<Self> {
        config.validate()?;
        let constraint = config
            .capture_filter
            .as_ref()
            .map(crate::filter::compile)
            .transpose()?;
        let context = Context::new()?;
        let selected = if let Some(device) = &config.device {
            if device.backend != Backend::Pktmon {
                return Err(Error::InvalidConfig("device belongs to another backend"));
            }
            Some(
                source::sources(&context, false)?
                    .into_iter()
                    .find(|s| {
                        let fresh = source::device(s);
                        fresh.id == device.id
                            && fresh.guid == device.guid
                            && fresh.name == device.name
                    })
                    .ok_or(Error::InvalidConfig(
                        "capture device disappeared or identity changed",
                    ))?,
            )
        } else {
            None
        };
        let queue = PacketQueue::new(config.queue_capacity, config.overflow);
        let mut result = Self {
            context,
            session: ptr::null_mut(),
            stream: ptr::null_mut(),
            callback: Box::new(Callback {
                queue,
                config,
                missed_reads: Default::default(),
            }),
            started: false,
            stopped: false,
        };
        let name: Vec<_> = format!(
            "winptap-{}-{}\0",
            std::process::id(),
            NEXT_SESSION.fetch_add(1, Ordering::Relaxed)
        )
        .encode_utf16()
        .collect();
        // SAFETY: live monitor, terminated session name and valid output handle.
        hresult("PacketMonitorCreateLiveSession", unsafe {
            (result.context.api.create_session)(
                result.context.handle,
                name.as_ptr(),
                &mut result.session,
            )
        })?;
        if result.session.is_null() {
            return Err(Error::InvalidData("null session"));
        }
        if let Some(source) = selected {
            // SAFETY: source was enumerated from this monitor; the API copies it.
            hresult("PacketMonitorAddSingleDataSourceToSession", unsafe {
                (result.context.api.add_source)(result.session, &source)
            })?;
        }
        if let Some(constraint) = constraint {
            // SAFETY: initialized ABI-compatible constraint and live session.
            hresult("PacketMonitorAddCaptureConstraint", unsafe {
                (result.context.api.add_constraint)(result.session, constraint.as_ptr())
            })?;
        }
        let config = StreamConfig {
            context: (&mut *result.callback as *mut Callback).cast(),
            event: stream::event,
            data: stream::data,
            multiplier: result.callback.config.ring_multiplier,
            truncation: result.callback.config.snaplen,
        };
        // SAFETY: boxed callback address is stable until close_stream returns.
        hresult("PacketMonitorCreateRealtimeStream", unsafe {
            (result.context.api.create_stream)(result.context.handle, &config, &mut result.stream)
        })?;
        if result.stream.is_null() {
            return Err(Error::InvalidData("null stream"));
        }
        // SAFETY: both handles belong to this monitor and remain owned together.
        hresult("PacketMonitorAttachOutputToSession", unsafe {
            (result.context.api.attach)(result.session, result.stream)
        })?;
        Ok(result)
    }
}
impl Session for PktmonSession {
    fn start(&mut self) -> Result<()> {
        if self.started {
            return Err(Error::InvalidState);
        }
        self.callback.queue.reopen()?;
        // SAFETY: live configured session, exclusively controlled by its owner.
        hresult("PacketMonitorSetSessionActive", unsafe {
            (self.context.api.active)(self.session, 1)
        })?;
        self.started = true;
        self.stopped = false;
        Ok(())
    }
    fn stop(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        if self.started {
            // SAFETY: documented synchronous deactivation of this session only.
            hresult("PacketMonitorSetSessionActive", unsafe {
                (self.context.api.active)(self.session, 0)
            })?;
        }
        self.started = false;
        self.stopped = true;
        self.callback.queue.close(Ok(()));
        Ok(())
    }
    fn queue(&self) -> Arc<PacketQueue> {
        self.callback.queue.clone()
    }
}
impl Drop for PktmonSession {
    fn drop(&mut self) {
        if self.started {
            // SAFETY: best-effort deactivation before closing owned handles.
            unsafe {
                (self.context.api.active)(self.session, 0);
            }
        }
        if !self.stream.is_null() {
            // SAFETY: close joins the stream reader; context and DLL are still alive.
            unsafe {
                (self.context.api.close_stream)(self.stream);
            }
        }
        if !self.session.is_null() {
            // SAFETY: streams have detached; close only the session owned here.
            unsafe {
                (self.context.api.close_session)(self.session);
            }
        }
        self.callback.queue.close(Ok(()));
    }
}
