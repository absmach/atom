//! Subject-driven certificate enrollment (PR-014).
//!
//! [`service`] owns every enrollment decision. [`http`] is the native protocol
//! adapter, [`est`] is the RFC 7030 adapter, and [`tls`] supplies the only
//! trusted peer-certificate assertion.

pub mod est;
pub mod http;
pub mod repo;
pub mod service;
pub mod tls;
