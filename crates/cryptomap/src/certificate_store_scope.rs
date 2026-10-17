//! Cross-platform, inert authorization contract for explicitly named certificate stores.
//!
//! This module creates *no* operating-system access capability. Grant identity
//! and budgets are host supplied; native enumeration is a separate, opt-in adapter.
//! In particular, a grant never authorizes key access, certificate trust, or TLS use.
use crate::scope::ScopeError;
use serde::{Deserialize, Serialize};

/// Maximum certificate contexts a single store grant may permit.
pub const MAX_CERT_STORE_ENTRIES: usize = 1024;
/// Maximum total public encoded certificate bytes permitted by one grant.
pub const MAX_CERT_STORE_PUBLIC_BYTES: usize = 16 * 1024 * 1024;

/// Local certificate-store hive, with no ambient remote or service-store access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CertificateStoreLocation {
    /// The account associated with the explicitly authorized operation.
    CurrentUser,
    /// Machine store; only usable after separately authorized host consent.
    LocalMachine,
}

/// An allowlisted certificate store, not an arbitrary provider-specific string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CertificateStoreName {
    /// The conventional personal/public certificate store.
    My,
}

/// Typed, canonical source identity without a filesystem path or registry key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateStoreTarget {
    location: CertificateStoreLocation,
    name: CertificateStoreName,
}
impl CertificateStoreTarget {
    /// Construct an exact allowlisted store target. Root/CA/remote/all-stores
    /// and any mixed-case, wildcard, empty or malformed names are rejected.
    pub fn new(location: CertificateStoreLocation, name: &str) -> Result<Self, ScopeError> {
        let name = match name {
            "My" => CertificateStoreName::My,
            _ => return Err(ScopeError::InvalidInput),
        };
        Ok(Self { location, name })
    }

    /// Canonical, nonsecret identity for an approved store target.
    pub fn id(&self) -> &'static str {
        match (self.location, self.name) {
            (CertificateStoreLocation::CurrentUser, CertificateStoreName::My) => {
                "certstore:v1:CurrentUser/My"
            }
            (CertificateStoreLocation::LocalMachine, CertificateStoreName::My) => {
                "certstore:v1:LocalMachine/My"
            }
        }
    }

    /// Explicitly selected account/machine store location.
    pub fn location(&self) -> CertificateStoreLocation {
        self.location
    }

    /// Explicitly selected allowlisted certificate store name.
    pub fn name(&self) -> CertificateStoreName {
        self.name
    }
}

/// Validated, inert capability grant for one exact source item and store target.
///
/// The public byte ceiling is an inspection budget; the regular RawLimits
/// total_bytes ceiling applies separately to serialized emitted observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateStoreGrant {
    target: CertificateStoreTarget,
    max_entries: usize,
    max_public_bytes: usize,
}
impl CertificateStoreGrant {
    /// Construct a caller-controlled grant with mandatory finite, positive budgets.
    pub fn new(
        target: CertificateStoreTarget,
        max_entries: usize,
        max_public_bytes: usize,
    ) -> Result<Self, ScopeError> {
        let grant = Self {
            target,
            max_entries,
            max_public_bytes,
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Revalidate even when a grant was deserialized from untrusted input.
    pub fn validate(&self) -> Result<(), ScopeError> {
        if self.max_entries == 0
            || self.max_entries > MAX_CERT_STORE_ENTRIES
            || self.max_public_bytes == 0
            || self.max_public_bytes > MAX_CERT_STORE_PUBLIC_BYTES
        {
            return Err(ScopeError::ResourceLimit);
        }
        Ok(())
    }

    /// Typed source identity, never inferred from an untrusted request label.
    pub fn target(&self) -> CertificateStoreTarget {
        self.target
    }

    /// Maximum number of inspected public certificate contexts.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Maximum aggregate bytes of inspected public DER certificate data.
    pub fn max_public_bytes(&self) -> usize {
        self.max_public_bytes
    }
}
