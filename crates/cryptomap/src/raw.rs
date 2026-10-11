//! Versioned, untrusted source observations produced by collectors.
//!
//! Raw observations do not confer authorization, prove runtime execution, or
//! become canonical assets until a later normalization pipeline validates them.
use crate::{
    CollectionRunId, CollectorId, Confidence, EvidenceKind, InventoryError, ProtocolState,
    validation,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Current raw-observation transport contract, independent of snapshot schema.
pub const RAW_CONTRACT_VERSION: u32 = 1;

/// Source category declared by a collector and authorized in a request.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RawSourceKind {
    /// Manifest or dependency lockfile supplied by the caller.
    Dependency,
    /// Public certificate file or authorized certificate store.
    Certificate,
    /// Explicitly authorized TLS network endpoint.
    TlsEndpoint,
    /// Repository source code or configuration file.
    Source,
    /// Supplied structured runtime telemetry file or stream.
    Telemetry,
}

/// Nonsecret source locator, with optional line/record offsets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSourceLocator {
    /// Category of the inspected source.
    pub kind: RawSourceKind,
    /// Exact requested item identifier (not an implicit glob).
    pub item: String,
    /// Optional zero-based input record/byte offset.
    pub offset: Option<u64>,
    /// Optional one-based source line.
    pub line: Option<u32>,
    /// Optional one-based source column.
    pub column: Option<u32>,
}

impl RawSourceLocator {
    /// Enforce source identity and bounded, nonsecret locator strings.
    pub fn validate(&self, limits: &RawLimits) -> Result<(), InventoryError> {
        if self.item.is_empty() || self.item.trim() != self.item {
            return Err(InventoryError::InvalidMetadata);
        }
        validation::safe_text(&self.item, limits.field_bytes)?;
        if self.line == Some(0) || self.column == Some(0) {
            return Err(InventoryError::InvalidMetadata);
        }
        Ok(())
    }
}

/// Fact supplied by a source, not yet normalized or reconciled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RawFactKind {
    /// Source evidence of a particular algorithm invocation/use-site.
    AlgorithmUse {
        /// Algorithm identifier as written in the source, without guessing.
        identifier: String,
        /// Optional exact profile, mode, curve or parameters.
        profile: Option<String>,
        /// Observed operation, if known.
        operation: Option<String>,
    },
    /// Library or package exists in dependency metadata; NOT proof of use.
    Dependency {
        /// Ecosystem such as cargo or npm.
        ecosystem: String,
        /// Package name.
        name: String,
        /// Declared or resolved package version.
        version: String,
    },
    /// Public certificate identity as SHA-256 of DER certificate bytes.
    Certificate {
        /// Exactly 64 hex characters, no certificate/key body.
        fingerprint_sha256: String,
    },
    /// Observed configuration versus negotiated protocol state.
    Protocol {
        /// Protocol family (for example TLS).
        family: String,
        /// Protocol version, if observed.
        version: Option<String>,
        /// Configured does not imply Negotiated.
        state: ProtocolState,
    },
    /// A key reference; never actual key bytes.
    KeyReference {
        /// Key provider or store identity.
        provider: String,
        /// Nonsecret key reference/fingerprint.
        reference: String,
    },
    /// Source configuration value observed without assuming active use.
    Configuration {
        /// Namespaced configuration property.
        property: String,
        /// Nonsecret value as supplied by source.
        value: String,
    },
}

/// Explicit size and count ceilings applied before accepting raw observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawLimits {
    /// Maximum accepted observations per collection invocation.
    pub observations: usize,
    /// Maximum bytes of all serialized observations combined.
    pub total_bytes: usize,
    /// Maximum serialized bytes per observation.
    pub record_bytes: usize,
    /// Maximum bytes of any individual string field.
    pub field_bytes: usize,
    /// Maximum number of custom metadata entries per observation.
    pub attributes: usize,
}

impl Default for RawLimits {
    fn default() -> Self {
        Self {
            observations: 10_000,
            total_bytes: 8 * 1024 * 1024,
            record_bytes: 16 * 1024,
            field_bytes: 2 * 1024,
            attributes: 32,
        }
    }
}

impl RawLimits {
    /// Reject impossible or unconstrained configurations.
    pub fn validate(&self) -> Result<(), InventoryError> {
        if self.observations == 0
            || self.total_bytes == 0
            || self.record_bytes == 0
            || self.field_bytes == 0
            || self.attributes == 0
            || self.record_bytes > self.total_bytes
            || self.field_bytes > self.record_bytes
        {
            return Err(InventoryError::InvalidMetadata);
        }
        Ok(())
    }
}

/// One source assertion with traceable collector and run identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawObservation {
    /// Wire contract version, currently 1.
    pub contract_version: u32,
    /// Source-specific deterministic event identity (for replay detection).
    pub event_id: String,
    /// Collector declaring the observation.
    pub collector: CollectorId,
    /// Exact collector release/version string.
    pub collector_version: String,
    /// Invocation that produced the observation.
    pub run: CollectionRunId,
    /// Exact inspected source locator.
    pub source: RawSourceLocator,
    /// RFC3339 timestamp with timezone.
    pub observed_at: String,
    /// Source assertion type.
    pub fact: RawFactKind,
    /// Direct versus inferred source information.
    pub evidence_kind: EvidenceKind,
    /// Collector-provided certainty, NOT a security judgment.
    pub confidence: Confidence,
    /// Required if evidence_kind is Inferred.
    pub inference_rule: Option<String>,
    /// Optional SHA-256 hex digest of the source content.
    pub source_sha256: Option<String>,
    /// Optional additional namespaced, nonsecret bounded attributes.
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

impl RawObservation {
    /// Validate supplied fields and exact raw record-size budgets.
    ///
    /// This is a best-effort secret marker guard, not general-purpose DLP.
    /// Source collectors must omit credentials and key material upstream.
    pub fn validate(&self, limits: &RawLimits) -> Result<usize, InventoryError> {
        limits.validate()?;
        if self.contract_version != RAW_CONTRACT_VERSION {
            return Err(InventoryError::UnsupportedSchema(self.contract_version));
        }
        if self.event_id.is_empty() || self.event_id.trim() != self.event_id {
            return Err(InventoryError::InvalidMetadata);
        }
        validation::safe_text(&self.event_id, limits.field_bytes)?;
        validation::safe_text(&self.collector_version, 128)?;
        self.source.validate(limits)?;
        validation::utc_seconds(&self.observed_at)?;
        if self.attributes.len() > limits.attributes {
            return Err(InventoryError::LimitExceeded("raw attributes"));
        }
        if matches!(self.evidence_kind, EvidenceKind::Inferred) {
            let rule = self
                .inference_rule
                .as_deref()
                .filter(|rule| !rule.is_empty())
                .ok_or(InventoryError::InvalidMetadata)?;
            validation::safe_text(rule, 128)?;
        }
        if let Some(rule) = &self.inference_rule {
            validation::safe_text(rule, 128)?;
        }
        if let Some(hash) = &self.source_sha256 {
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(InventoryError::InvalidMetadata);
            }
        }
        let encoded = serde_json::to_vec(self).map_err(|_| InventoryError::InvalidMetadata)?;
        if encoded.len() > limits.record_bytes {
            return Err(InventoryError::LimitExceeded("raw observation bytes"));
        }
        // Serialize to a value to inspect UNESCAPED string values; JSON
        // escaping must not conceal prohibited control characters or secrets.
        let value = serde_json::to_value(self).map_err(|_| InventoryError::InvalidMetadata)?;
        fn bounded(value: &serde_json::Value, max: usize) -> Result<(), InventoryError> {
            match value {
                serde_json::Value::String(s) => validation::safe_text(s, max),
                serde_json::Value::Array(items) => {
                    for item in items {
                        bounded(item, max)?;
                    }
                    Ok(())
                }
                serde_json::Value::Object(map) => {
                    for (key, value) in map {
                        validation::safe_text(key, max)?;
                        bounded(value, max)?;
                    }
                    Ok(())
                }
                _ => Ok(()),
            }
        }
        bounded(&value, limits.field_bytes)?;
        match &self.fact {
            RawFactKind::Certificate { fingerprint_sha256 } => {
                if fingerprint_sha256.len() != 64
                    || !fingerprint_sha256.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(InventoryError::InvalidMetadata);
                }
            }
            RawFactKind::KeyReference {
                provider,
                reference,
            } => {
                if provider.is_empty() || reference.is_empty() {
                    return Err(InventoryError::InvalidMetadata);
                }
            }
            RawFactKind::AlgorithmUse { identifier, .. } => {
                if identifier.is_empty() {
                    return Err(InventoryError::InvalidMetadata);
                }
            }
            RawFactKind::Dependency {
                ecosystem,
                name,
                version,
            } => {
                if ecosystem.is_empty() || name.is_empty() || version.is_empty() {
                    return Err(InventoryError::InvalidMetadata);
                }
            }
            RawFactKind::Protocol { family, .. } => {
                if family.is_empty() {
                    return Err(InventoryError::InvalidMetadata);
                }
            }
            RawFactKind::Configuration { property, .. } => {
                if !property.contains(':') {
                    return Err(InventoryError::InvalidMetadata);
                }
            }
        }
        Ok(encoded.len())
    }
}
