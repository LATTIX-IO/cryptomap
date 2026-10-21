//! Exact source-grant TLS probe planning; no network or TLS I/O on construction.
//!
//! This layer is intentionally independent of a TLS provider. A future
//! handshake collector must pass each connection through the existing
//! AuthorizedEndpoint capability and enforce the plan's finite budgets.
//! A plan never proves peer identity, availability or cryptographic use.

use crate::{
    collector::RequestedSource, network_scope::AuthorizedEndpoint, raw::RawSourceKind,
    scope::CollectionScope,
};
use std::{net::SocketAddr, time::Duration};

/// An opaque, non-secret reason why no valid plan could be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsProbePlanError {
    /// The requested item is not an exactly granted TLS endpoint.
    Unauthorized,
    /// One or more caller-defined resource budgets are invalid.
    InvalidLimits,
    /// The authority supplied no usable exact pinned IP-and-port destination.
    NoDestinations,
}

/// Explicit finite budgets for a future TLS client operation.
///
/// No value is a promise that a future TLS backend can enforce the limit.
/// B6.2 must establish that enforcement and test it before dialing sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsProbeLimits {
    /// Upper bound for one TCP connection attempt.
    pub connect_timeout: Duration,
    /// Upper bound for TLS negotiation after TCP connection.
    pub handshake_timeout: Duration,
    /// Maximum TLS handshake traffic bytes observed and processed.
    pub max_handshake_bytes: usize,
    /// Maximum cumulative public peer-certificate DER bytes.
    pub max_chain_der_bytes: usize,
    /// Maximum peer certificate count.
    pub max_certificates: usize,
    /// Maximum attempts drawn exclusively from the pinned endpoint IP set.
    pub max_attempts: usize,
}

impl Default for TlsProbeLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            handshake_timeout: Duration::from_secs(5),
            max_handshake_bytes: 256 * 1024,
            max_chain_der_bytes: 128 * 1024,
            max_certificates: 8,
            max_attempts: 1,
        }
    }
}

impl TlsProbeLimits {
    /// Refuse zero, oversized or internally inconsistent resource budgets.
    pub fn validate(self) -> Result<(), TlsProbePlanError> {
        if self.connect_timeout.is_zero()
            || self.connect_timeout > Duration::from_secs(30)
            || self.handshake_timeout.is_zero()
            || self.handshake_timeout > Duration::from_secs(30)
            || !(1..=1024 * 1024).contains(&self.max_handshake_bytes)
            || !(1..=1024 * 1024).contains(&self.max_chain_der_bytes)
            || self.max_chain_der_bytes > self.max_handshake_bytes
            || !(1..=16).contains(&self.max_certificates)
            || !(1..=32).contains(&self.max_attempts)
        {
            return Err(TlsProbePlanError::InvalidLimits);
        }
        Ok(())
    }
}

/// Borrowed, explicitly authorized TLS probe plan. Never serializable as a
/// privilege token and cannot outlive its host-granted CollectionScope.
///
/// Only the exact source item, SNI and pinned IP:port destinations chosen by
/// the host are represented. Construction does not open sockets, resolve DNS,
/// follow redirects, fetch certificates or attempt a handshake.
#[derive(Debug)]
pub struct TlsProbePlan<'a> {
    endpoint: AuthorizedEndpoint<'a>,
    destinations: Vec<SocketAddr>,
    limits: TlsProbeLimits,
}

impl<'a> TlsProbePlan<'a> {
    /// Prepare a finite plan from an existing host-owned exact source grant.
    ///
    /// A different source kind, ungranted target, malformed target label or
    /// missing pinned destination fails without network activity.
    pub fn prepare(
        scope: &'a CollectionScope,
        source: &RequestedSource,
        limits: TlsProbeLimits,
    ) -> Result<Self, TlsProbePlanError> {
        if source.kind != RawSourceKind::TlsEndpoint {
            return Err(TlsProbePlanError::Unauthorized);
        }
        limits.validate()?;
        let endpoint = scope
            .open_endpoint(&source.item)
            .map_err(|_| TlsProbePlanError::Unauthorized)?;
        if endpoint.id() != source.item {
            return Err(TlsProbePlanError::Unauthorized);
        }
        let destinations = endpoint
            .approved_destinations()
            .into_iter()
            .take(limits.max_attempts)
            .collect::<Vec<_>>();
        if destinations.is_empty() {
            return Err(TlsProbePlanError::NoDestinations);
        }
        Ok(Self {
            endpoint,
            destinations,
            limits,
        })
    }

    /// The exact authorized source label; IPv6 is bracketed.
    pub fn target_id(&self) -> String {
        self.endpoint.id()
    }

    /// The host-authorized SNI, or None; no implicit hostname-to-SNI fallback.
    pub fn sni(&self) -> Option<&str> {
        self.endpoint.sni()
    }

    /// A deterministic finite subset of the host-pinned destinations.
    ///
    /// Address ordering does not confer permission to select another address
    /// or port. Later transport code must still call AuthorizedEndpoint::connect.
    pub fn destinations(&self) -> &[SocketAddr] {
        &self.destinations
    }

    /// Check an exact approved destination within this finite plan.
    pub fn includes(&self, destination: SocketAddr) -> bool {
        self.destinations.contains(&destination)
    }

    /// The limits validated before any future attempted network activity.
    pub fn limits(&self) -> TlsProbeLimits {
        self.limits
    }
}
