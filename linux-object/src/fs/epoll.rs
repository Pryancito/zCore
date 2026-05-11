use super::*;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use lock::Mutex;
use zircon_object::object::*;

/// epoll implementation
pub struct Epoll {
    base: KObjectBase,
    inner: Mutex<EpollInner>,
    flags: OpenFlags,
}

#[derive(Debug)]
struct EpollInner {
    interest_list: BTreeMap<FileDesc, EpollEvent>,
}

/// epoll event
#[repr(C)]
#[cfg_attr(target_arch = "x86_64", repr(packed))]
#[derive(Clone, Copy, Debug)]
pub struct EpollEvent {
    /// events
    pub events: u32,
    /// data
    pub data: u64,
}

impl_kobject!(Epoll);

impl Epoll {
    /// create an epoll instance
    pub fn new(flags: OpenFlags) -> Arc<Self> {
        Arc::new(Epoll {
            base: KObjectBase::new(),
            inner: Mutex::new(EpollInner {
                interest_list: BTreeMap::new(),
            }),
            flags,
        })
    }

    /// add, modify, or remove a file descriptor from the interest list
    pub fn ctl(&self, op: i32, fd: FileDesc, event: EpollEvent) -> LxResult<usize> {
        let mut inner = self.inner.lock();
        match op {
            1 => { // EPOLL_CTL_ADD
                if inner.interest_list.contains_key(&fd) {
                    return Err(LxError::EEXIST);
                }
                inner.interest_list.insert(fd, event);
            }
            2 => { // EPOLL_CTL_DEL
                inner.interest_list.remove(&fd).ok_or(LxError::ENOENT)?;
            }
            3 => { // EPOLL_CTL_MOD
                let e = inner.interest_list.get_mut(&fd).ok_or(LxError::ENOENT)?;
                *e = event;
            }
            _ => return Err(LxError::EINVAL),
        }
        Ok(0)
    }
}

#[async_trait]
impl FileLike for Epoll {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn set_flags(&self, _f: OpenFlags) -> LxResult {
        Ok(())
    }

    fn dup(&self) -> Arc<dyn FileLike> {
        Arc::new(Self {
            base: KObjectBase::new(),
            inner: Mutex::new(EpollInner {
                interest_list: self.inner.lock().interest_list.clone(),
            }),
            flags: self.flags,
        })
    }

    async fn read(&self, _buf: &mut [u8]) -> LxResult<usize> {
        Err(LxError::ENOSYS)
    }

    fn write(&self, _buf: &[u8]) -> LxResult<usize> {
        Err(LxError::ENOSYS)
    }

    async fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> LxResult<usize> {
        Err(LxError::ENOSYS)
    }

    fn poll(&self, _events: PollEvents) -> LxResult<PollStatus> {
        // Epoll itself is usually not polled, but it can be.
        // For simplicity, return not ready.
        Ok(PollStatus::default())
    }

    async fn async_poll(&self, _events: PollEvents) -> LxResult<PollStatus> {
        Ok(PollStatus::default())
    }
}

impl Epoll {
    /// wait for events on the interest list
    pub async fn wait(&self, maxevents: usize, process: &crate::process::LinuxProcess) -> LxResult<Vec<EpollEvent>> {
        loop {
            let mut events = Vec::new();
            let interest_list = self.inner.lock().interest_list.clone();
            for (fd, event) in interest_list {
                if let Ok(file) = process.get_file_like(fd) {
                    let interest = PollEvents::from_bits_truncate(event.events as u16);
                    let status = file.poll(interest)?;
                    let mut ready_events = 0u32;
                    if status.read && interest.contains(PollEvents::IN) {
                        ready_events |= PollEvents::IN.bits() as u32;
                    }
                    if status.write && interest.contains(PollEvents::OUT) {
                        ready_events |= PollEvents::OUT.bits() as u32;
                    }
                    if status.error {
                        ready_events |= PollEvents::ERR.bits() as u32;
                    }
                    
                    if ready_events != 0 {
                        events.push(EpollEvent {
                            events: ready_events,
                            data: event.data,
                        });
                        if events.len() >= maxevents {
                            break;
                        }
                    }
                }
            }
            
            if !events.is_empty() {
                return Ok(events);
            }
            
            // TODO: properly wait for ANY of the files to become ready.
            // For now, we yield and try again. This is inefficient but avoids complex multi-wait logic for now.
            kernel_hal::thread::yield_now().await;
        }
    }
}
