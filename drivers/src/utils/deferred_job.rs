//! Deferred job queue.
//!
//! Allows interrupt / IRQ handlers to schedule work that should run outside of
//! an atomic context (e.g. in the next scheduler tick or poll loop).
//!
//! Jobs are closures pushed onto a global queue via [`push_deferred_job`] and
//! drained with [`drain_deferred_jobs`].

use alloc::boxed::Box;
use alloc::vec::Vec;
use lock::Mutex;

type Job = Box<dyn FnOnce() + Send + 'static>;

static JOBS: Mutex<Vec<Job>> = Mutex::new(Vec::new());

/// Enqueue a closure to be executed later outside of IRQ context.
pub fn push_deferred_job<F: FnOnce() + Send + 'static>(f: F) {
    JOBS.lock().push(Box::new(f));
}

/// Execute all currently queued deferred jobs.
///
/// Should be called from a non-atomic context (e.g. the kernel idle loop or a
/// timer tick handler).
pub fn drain_deferred_jobs() {
    let jobs: Vec<Job> = {
        let mut q = JOBS.lock();
        core::mem::take(&mut *q)
    };
    for job in jobs {
        job();
    }
}
