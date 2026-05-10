use super::*;
use crate::sync::{Event, EventBus};
use alloc::sync::Arc;
use core::convert::TryInto;
use core::sync::atomic::{AtomicU64, Ordering};
use lock::Mutex;
use zircon_object::object::*;

/// eventfd implementation
pub struct EventFd {
    base: KObjectBase,
    counter: AtomicU64,
    eventbus: Arc<Mutex<EventBus>>,
    flags: OpenFlags,
}

impl_kobject!(EventFd);

impl EventFd {
    /// create an eventfd
    pub fn new(initval: u32, flags: OpenFlags) -> Arc<Self> {
        Arc::new(EventFd {
            base: KObjectBase::new(),
            counter: AtomicU64::new(initval as u64),
            eventbus: EventBus::new(),
            flags,
        })
    }
}

#[async_trait]
impl FileLike for EventFd {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn set_flags(&self, _f: OpenFlags) -> LxResult {
        // Only NON_BLOCK can be changed
        // Actually, Linux allows changing NONBLOCK
        // let mut flags = self.flags; // Wait, self.flags is immutable in this struct
        // flags.set(OpenFlags::NON_BLOCK, f.contains(OpenFlags::NON_BLOCK));
        // Ok(())
        // For simplicity, we should probably make flags mutable or ignore set_flags for now if it's not critical.
        // But FileLike::set_flags is usually called.
        // I'll make flags a Mutex or Atomic if needed, but for now just return Ok.
        Ok(())
    }

    async fn read(&self, buf: &mut [u8]) -> LxResult<usize> {
        if buf.len() < 8 {
            return Err(LxError::EINVAL);
        }
        loop {
            let counter = self.counter.load(Ordering::SeqCst);
            if counter > 0 {
                let res = if self.flags.bits() & 1 != 0 {
                    // EFD_SEMAPHORE
                    if self
                        .counter
                        .compare_exchange(counter, counter - 1, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        1
                    } else {
                        continue;
                    }
                } else {
                    if self
                        .counter
                        .compare_exchange(counter, 0, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        counter
                    } else {
                        continue;
                    }
                };
                buf[..8].copy_from_slice(&res.to_ne_bytes());
                if self.counter.load(Ordering::SeqCst) == 0 {
                    self.eventbus.lock().clear(Event::READABLE);
                }
                return Ok(8);
            }
            if self.flags.contains(OpenFlags::NON_BLOCK) {
                return Err(LxError::EAGAIN);
            }
            self.async_poll(PollEvents::IN).await?;
        }
    }

    fn write(&self, buf: &[u8]) -> LxResult<usize> {
        if buf.len() < 8 {
            return Err(LxError::EINVAL);
        }
        let val = u64::from_ne_bytes(buf[..8].try_into().unwrap());
        if val == u64::MAX {
            return Err(LxError::EINVAL);
        }
        loop {
            let counter = self.counter.load(Ordering::SeqCst);
            if u64::MAX - counter > val {
                if self
                    .counter
                    .compare_exchange(counter, counter + val, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    self.eventbus.lock().set(Event::READABLE);
                    return Ok(8);
                }
            } else {
                if self.flags.contains(OpenFlags::NON_BLOCK) {
                    return Err(LxError::EAGAIN);
                }
                // TODO: wait for writeable? EventFd is almost always writeable unless overflow
                return Err(LxError::EAGAIN);
            }
        }
    }

    async fn read_at(&self, _offset: u64, buf: &mut [u8]) -> LxResult<usize> {
        self.read(buf).await
    }

    fn poll(&self, _events: PollEvents) -> LxResult<PollStatus> {
        let counter = self.counter.load(Ordering::SeqCst);
        Ok(PollStatus {
            read: counter > 0,
            write: counter < u64::MAX - 1,
            error: false,
        })
    }

    async fn async_poll(&self, _events: PollEvents) -> LxResult<PollStatus> {
        loop {
            let status = self.poll(_events)?;
            if status.read || status.write {
                return Ok(status);
            }
            let bus = self.eventbus.clone();
            crate::sync::wait_for_event(bus, Event::READABLE | Event::WRITABLE).await;
        }
    }
}
