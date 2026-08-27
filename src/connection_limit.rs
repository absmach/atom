use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use crate::rate_limit::aggregate_ip;

/// Counts active connections by source address, grouping IPv6 sources by the
/// configured prefix. The returned permit releases its slot on drop.
#[derive(Clone)]
pub(crate) struct PerIpConnectionLimiter {
    max_connections_per_ip: usize,
    ipv6_prefix_len: u8,
    active: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl PerIpConnectionLimiter {
    pub(crate) fn new(max_connections_per_ip: usize, ipv6_prefix_len: u8) -> Self {
        Self {
            max_connections_per_ip,
            ipv6_prefix_len,
            active: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn try_acquire(&self, ip: IpAddr) -> Option<PerIpConnectionPermit> {
        let ip = aggregate_ip(ip, self.ipv6_prefix_len);
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = active.entry(ip).or_default();
        if *count >= self.max_connections_per_ip {
            return None;
        }
        *count += 1;
        Some(PerIpConnectionPermit {
            limiter: self.clone(),
            ip,
        })
    }

    fn release(&self, ip: IpAddr) {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = active.get_mut(&ip) {
            if *count > 1 {
                *count -= 1;
            } else {
                active.remove(&ip);
            }
        }
    }
}

pub(crate) struct PerIpConnectionPermit {
    limiter: PerIpConnectionLimiter,
    ip: IpAddr,
}

impl Drop for PerIpConnectionPermit {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_cap_releases_when_a_connection_finishes() {
        let limiter = PerIpConnectionLimiter::new(1, 64);
        let ip = "203.0.113.8".parse().expect("IP address");

        let permit = limiter.try_acquire(ip).expect("first connection allowed");
        assert!(
            limiter.try_acquire(ip).is_none(),
            "second connection denied"
        );

        drop(permit);
        assert!(limiter.try_acquire(ip).is_some(), "slot released on drop");
    }

    #[test]
    fn ipv6_sources_share_the_configured_prefix() {
        let limiter = PerIpConnectionLimiter::new(1, 64);
        let first = "2001:db8:1:2::1".parse().expect("first IPv6 address");
        let same_prefix = "2001:db8:1:2::2".parse().expect("second IPv6 address");

        let permit = limiter
            .try_acquire(first)
            .expect("first connection allowed");
        assert!(limiter.try_acquire(same_prefix).is_none());
        drop(permit);
    }
}
