//! Strongly typed metadata used to build safe inventory facts.
use serde::{Deserialize, Serialize};

/// Algorithm operation observed at a particular use site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlgorithmOperation {
    /// Encrypt data.
    Encrypt,
    /// Decrypt data.
    Decrypt,
    /// Sign a message or digest.
    Sign,
    /// Verify a signature.
    Verify,
    /// Establish shared key material.
    KeyEstablishment,
    /// Wrap a key.
    Wrap,
    /// Unwrap a key.
    Unwrap,
    /// Hash.
    Hash,
    /// Derive key material.
    Derive,
    /// Unrecognized or vendor-specific operation.
    Other(String),
}
/// Explicit availability of an observed fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Observed<T> {
    /// Observed and supported.
    Known(T),
    /// The source did not provide this field.
    Unknown,
    /// The field is not meaningful for this asset.
    NotApplicable,
}
/// Nonsecret key information suitable for an inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Observed key algorithm/profile.
    pub algorithm: Observed<String>,
    /// Public/private/symmetric classification, not secret bytes.
    pub role: Observed<String>,
    /// Key length where known.
    pub bits: Observed<u32>,
    /// Named elliptic curve or parameter set.
    pub curve_or_parameter: Observed<String>,
    /// Provider namespace.
    pub provider: Observed<String>,
    /// Key store name.
    pub store: Observed<String>,
    /// Whether export is possible, only where observed.
    pub exportable: Observed<bool>,
    /// Hardware/software protection label, only where observed.
    pub protection: Observed<String>,
    /// Nonsecret public fingerprint or stable provider reference.
    pub fingerprint_or_reference: Observed<String>,
}
/// Nonsecret X.509 certificate inventory metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateMetadata {
    /// SHA-256 fingerprint.
    pub fingerprint_sha256: String,
    /// Serial number representation.
    pub serial: Observed<String>,
    /// Issuer summary.
    pub issuer: Observed<String>,
    /// Subject summary.
    pub subject: Observed<String>,
    /// Not-before timestamp.
    pub not_before: Observed<String>,
    /// Not-after timestamp.
    pub not_after: Observed<String>,
    /// Public-key algorithm/profile.
    pub public_key_profile: Observed<String>,
    /// Signature algorithm/profile.
    pub signature_profile: Observed<String>,
}
/// Configuration versus live negotiation is explicit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolObservation {
    /// Enabled/supported configuration profile.
    Configured,
    /// Actually negotiated protocol profile.
    Negotiated,
}
/// Software dependency identity; presence does not imply algorithm use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyMetadata {
    /// Package ecosystem.
    pub ecosystem: String,
    /// Canonical package name.
    pub name: String,
    /// Exact version.
    pub version: String,
    /// PURL if observed.
    pub purl: Observed<String>,
    /// Whether a direct dependency.
    pub direct: Observed<bool>,
}

/// Detailed algorithm observation with explicit operation and profile metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorithmMetadata {
    /// Normalized family.
    pub family: String,
    /// Exact algorithm/profile/parameter set if known.
    pub profile: Observed<String>,
    /// Intended/observed operation class.
    pub operation: AlgorithmOperation,
    /// Source-specific cryptographic use-site.
    pub use_site: String,
    /// Unmodified source identifier if available.
    pub raw_identifier: Observed<String>,
    /// Key size when observed.
    pub key_bits: Observed<u32>,
}
/// Protocol metadata separating enabled configuration and live negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolMetadata {
    /// Protocol family (for example, TLS or SSH).
    pub family: String,
    /// Protocol version when observed.
    pub version: Observed<String>,
    /// Configured versus negotiated state.
    pub state: ProtocolObservation,
    /// Client/server or producer/consumer role.
    pub role: Observed<String>,
    /// Exact negotiated/configured profile when known.
    pub cryptographic_profile: Observed<String>,
}
/// A specific deployment instance of a cryptographic implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImplementationMetadata {
    /// Product/library/runtime name.
    pub product: String,
    /// Version when known.
    pub version: Observed<String>,
    /// Source/package identifier.
    pub source: Observed<String>,
}
