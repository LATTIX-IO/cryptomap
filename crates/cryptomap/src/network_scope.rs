//! Exact, explicitly pinned network target authorization.
//!
//! Network scopes never perform DNS resolution, port scanning, redirects, or
//! connection fallback to unapproved addresses. The caller provides approved
//! resolved addresses; the collector can only connect to one of those addresses.
use crate::scope::ScopeError;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr, TcpStream},
    time::Duration,
};

/// A caller-approved endpoint with an exact hostname/port and pinned IP list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkTarget {
    host: String,
    port: u16,
    sni: Option<String>,
    pinned_ips: BTreeSet<IpAddr>,
}

fn valid_dns_host(host: &str) -> bool {
    host.len() <= 253
        && !host.is_empty()
        && host.is_ascii()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

impl NetworkTarget {
    /// Construct a target and pin all approved addresses. For a DNS name the
    /// caller must supply an address set obtained via its own trusted resolver.
    /// An IP literal permits only that exact address.
    pub fn new(
        host: &str,
        port: u16,
        sni: Option<&str>,
        pinned: impl IntoIterator<Item = IpAddr>,
    ) -> Result<Self, ScopeError> {
        if port == 0 || host.trim() != host {
            return Err(ScopeError::InvalidInput);
        }
        let direct_ip = host.parse::<IpAddr>().ok();
        if direct_ip.is_none() && !valid_dns_host(host) {
            return Err(ScopeError::InvalidInput);
        }
        let host = if let Some(ip) = direct_ip {
            ip.to_string()
        } else {
            host.to_ascii_lowercase()
        };
        let sni = sni.map(|value| value.to_ascii_lowercase());
        if sni.as_deref().is_some_and(|value| !valid_dns_host(value)) {
            return Err(ScopeError::InvalidInput);
        }
        let mut pinned_ips: BTreeSet<IpAddr> = pinned.into_iter().collect();
        if let Some(ip) = direct_ip {
            if !pinned_ips.is_empty() && pinned_ips != BTreeSet::from([ip]) {
                return Err(ScopeError::OutOfScope);
            }
            pinned_ips.insert(ip);
        }
        if pinned_ips.is_empty() || pinned_ips.len() > 32 {
            return Err(ScopeError::InvalidInput);
        }
        Ok(Self { host, port, sni, pinned_ips })
    }

    /// Exact canonical endpoint name, bracketed for IPv6.
    pub fn id(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// The caller-approved SNI, if any. Never derived from redirects.
    pub fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }

    /// Exact approved IP set, without performing DNS resolution.
    pub fn pinned_ips(&self) -> &BTreeSet<IpAddr> {
        &self.pinned_ips
    }

    /// Caller-approved hostname, not a DNS discovery instruction.
    pub fn host(&self) -> &str {
        &self.host
    }
}

/// A table of exact approved targets. No CIDR, globs, redirects or wildcards.
#[derive(Debug, Default)]
pub struct NetworkScope {
    targets: BTreeMap<String, NetworkTarget>,
}

impl NetworkScope {
    /// Create an empty explicit allowlist.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register one exact target; reject duplicate registrations.
    pub fn grant(&mut self, target: NetworkTarget) -> Result<(), ScopeError> {
        let id = target.id();
        if self.targets.insert(id, target).is_some() {
            return Err(ScopeError::InvalidInput);
        }
        Ok(())
    }

    /// Issue a borrow-scoped connection capability for the exact target.
    pub fn authorize(&self, target: &str) -> Result<AuthorizedEndpoint<'_>, ScopeError> {
        let entry = self.targets.get(target).ok_or(ScopeError::OutOfScope)?;
        Ok(AuthorizedEndpoint { entry })
    }

    /// Whether the caller's requested target is approved.
    pub fn permits(&self, target: &str) -> bool {
        self.targets.contains_key(target)
    }
}

/// A network connection capability pinned to exactly one requested target.
#[derive(Debug)]
pub struct AuthorizedEndpoint<'a> {
    entry: &'a NetworkTarget,
}

impl AuthorizedEndpoint<'_> {
    /// Exact target string used as the permitted scope item.
    pub fn id(&self) -> String {
        self.entry.id()
    }

    /// Explicit SNI; no DNS-based target expansion.
    pub fn sni(&self) -> Option<&str> {
        self.entry.sni()
    }

    /// Explicit IP destinations, checked again on every connection.
    pub fn approved_destinations(&self) -> Vec<SocketAddr> {
        self.entry.pinned_ips.iter()
            .copied().map(|ip| SocketAddr::new(ip, self.entry.port)).collect()
    }

    /// Connect only to an approved IP and exact port with a finite timeout.
    ///
    /// Never resolves DNS and never follows redirects.
    pub fn connect(
        &self,
        destination: SocketAddr,
        timeout: Duration,
    ) -> Result<TcpStream, ScopeError> {
        if destination.port() != self.entry.port
            || !self.entry.pinned_ips.contains(&destination.ip())
        {
            return Err(ScopeError::OutOfScope);
        }
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(ScopeError::InvalidInput);
        }
        TcpStream::connect_timeout(&destination, timeout).map_err(|_| ScopeError::Io)
    }
}
