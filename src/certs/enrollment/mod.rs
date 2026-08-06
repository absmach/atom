//! Subject-driven certificate enrollment (PR-014).
//!
//! [`service`] owns every enrollment decision. [`http`] is the native protocol
//! adapter, while [`tls`] supplies the only trusted peer-certificate assertion.

pub mod http;
pub mod repo;
pub mod service;
pub mod tls;
