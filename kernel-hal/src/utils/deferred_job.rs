//! Deferred job system (Bottom half).
//! Re-exported from zcore-drivers to avoid circular dependencies.

pub use crate::drivers::utils::deferred_job::{push_deferred_job, drain_deferred_jobs};
