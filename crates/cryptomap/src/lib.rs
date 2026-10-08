//! Canonical evidence-backed cryptographic inventory.
//!
//! This crate represents observations, not compliance assessments or migration advice.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod coverage;
pub mod identity;
pub mod metadata;
pub mod privacy;
pub mod query;
pub use privacy::{RedactedAssetSummary, RedactedInventoryReport, RedactedRelation};
mod strict_json;
pub mod validation;
pub use coverage::{CollectionRun, CollectionScopeId, CoverageRecord, RunCompleteness};
pub use identity::{AssetIdentity, IdentityContext};
pub use metadata::{
    AlgorithmOperation, CertificateMetadata, DependencyMetadata, KeyMetadata, Observed,
    ProtocolObservation,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Errors returned by inventory validation and finalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryError {
    /// A supplied identifier is empty or malformed.
    InvalidIdentifier,
    /// An observation referred to an asset that is not present.
    MissingAsset(String),
    /// A relationship referred to a nonexistent asset.
    DanglingRelationship(String),
    /// Conflicting definitions used the same observation identifier.
    DuplicateObservation(String),
    /// The number of records exceeds configured limits.
    LimitExceeded(&'static str),
    /// Canonical encoding failed.
    Encoding(String),
    /// Identity attributes do not uniquely identify one asset.
    InsufficientIdentity,
    /// Bounded metadata failed validation.
    InvalidMetadata,
    /// A timestamp is not a valid timezone-aware RFC3339 value.
    InvalidTimestamp,
    /// Inventory content includes prohibited secret material.
    ProhibitedMaterial,
    /// An imported snapshot digest does not match its canonical contents.
    DigestMismatch,
    /// A serialized schema version is not supported.
    UnsupportedSchema(u32),
}
impl fmt::Display for InventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for InventoryError {}

macro_rules! identifier {
    ($name:ident) => {
        #[doc = concat!("Validated identifier for ", stringify!($name), ".")]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name {
            /// Construct a nonempty identifier without surrounding whitespace or control characters.
            pub fn new(value: impl Into<String>) -> Result<Self, InventoryError> {
                let value = value.into();
                if value.is_empty()
                    || value.len() > 512
                    || value.trim() != value
                    || value.chars().any(char::is_control)
                {
                    return Err(InventoryError::InvalidIdentifier);
                }
                Ok(Self(value))
            }
            /// Borrow the identifier string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl TryFrom<String> for $name {
            type Error = InventoryError;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}
identifier!(AssetId);
identifier!(ObservationId);
identifier!(EvidenceId);
identifier!(CollectionRunId);
identifier!(CollectorId);
identifier!(RelationshipId);
identifier!(ConflictId);
identifier!(SnapshotId);

/// Collector's explicitly reported confidence (not a security score).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    /// Unknown is one supported Confidence variant.
    Unknown,
    /// Low is one supported Confidence variant.
    Low,
    /// Medium is one supported Confidence variant.
    Medium,
    /// High is one supported Confidence variant.
    High,
    /// Confirmed is one supported Confidence variant.
    Confirmed,
}
/// Whether the source directly observed the fact or inferred it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    /// Direct is one supported EvidenceKind variant.
    Direct,
    /// Inferred is one supported EvidenceKind variant.
    Inferred,
}
/// Observed protocol state must distinguish configuration from negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolState {
    /// Configured is one supported ProtocolState variant.
    Configured,
    /// Negotiated is one supported ProtocolState variant.
    Negotiated,
}
/// Supported canonical asset families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetKind {
    /// Crypto operation at a particular use site.
    AlgorithmUse {
        /// family associated with this asset.
        family: String,
        /// profile associated with this asset.
        profile: Option<String>,
        /// use site associated with this asset.
        use_site: String,
    },
    /// Key metadata; raw key material is intentionally not part of this type.
    Key {
        /// algorithm associated with this asset.
        algorithm: Option<String>,
        /// provider associated with this asset.
        provider: Option<String>,
        /// fingerprint associated with this asset.
        fingerprint: Option<String>,
    },
    /// Certificate metadata; the certificate body is not stored by default.
    Certificate {
        /// fingerprint sha256 associated with this asset.
        fingerprint_sha256: String,
        /// public key profile associated with this asset.
        public_key_profile: Option<String>,
        /// signature profile associated with this asset.
        signature_profile: Option<String>,
    },
    /// Configured or negotiated protocol fact.
    Protocol {
        /// family associated with this asset.
        family: String,
        /// version associated with this asset.
        version: Option<String>,
        /// state associated with this asset.
        state: ProtocolState,
    },
    /// Scoped transport endpoint.
    Endpoint {
        /// transport associated with this asset.
        transport: String,
        /// host associated with this asset.
        host: String,
        /// port associated with this asset.
        port: u16,
        /// scope associated with this asset.
        scope: String,
    },
    /// Versioned package dependency.
    Library {
        /// ecosystem associated with this asset.
        ecosystem: String,
        /// name associated with this asset.
        name: String,
        /// version associated with this asset.
        version: String,
    },
    /// Runtime or cryptographic software implementation.
    Runtime {
        /// name associated with this asset.
        name: String,
        /// version associated with this asset.
        version: Option<String>,
    },
    /// Logical cryptographic key storage location.
    KeyStore {
        /// Provider identity.
        provider: String,
        /// Key store name.
        name: String,
    },
    /// Arbitrary source-location identification.
    SourceUse {
        /// Source file or resource identity.
        source: String,
        /// Concrete use-site position.
        location: String,
    },
    /// Named trust authority.
    TrustAnchor {
        /// Nonsecret certificate fingerprint.
        fingerprint: String,
    },
    /// Source-specific type that has no standardized mapping yet.
    Extension {
        /// Namespaced extension owner.
        namespace: String,
        /// Source-specific extension kind.
        kind: String,
    },
    /// Named crypto provider instance.
    Provider {
        /// Provider name.
        name: String,
        /// Provider instance identifier.
        instance: String,
    },
    /// A versioned cryptographic implementation.
    CryptoImplementation {
        /// Product identity.
        product: String,
        /// Product version.
        version: String,
    },
    /// Issuer/CA identity using a nonsecret certificate fingerprint.
    Authority {
        /// Issuing authority certificate fingerprint.
        certificate_fingerprint: String,
    },
    /// Detailed algorithm usage with typed operation and parameters.
    DetailedAlgorithm {
        /// metadata associated with this asset.
        metadata: metadata::AlgorithmMetadata,
    },
    /// Detailed secret-free key inventory.
    DetailedKey {
        /// Structured, nonsecret key metadata.
        metadata: metadata::KeyMetadata,
    },
    /// Detailed certificate metadata.
    DetailedCertificate {
        /// metadata associated with this asset.
        metadata: metadata::CertificateMetadata,
    },
    /// Detailed protocol observation.
    DetailedProtocol {
        /// metadata associated with this asset.
        metadata: metadata::ProtocolMetadata,
    },
    /// Detailed software/package dependency metadata.
    DetailedDependency {
        /// metadata associated with this asset.
        metadata: metadata::DependencyMetadata,
    },
    /// Detailed crypto implementation metadata.
    DetailedImplementation {
        /// metadata associated with this asset.
        metadata: metadata::ImplementationMetadata,
    },
}
/// Canonical asset identity and typed metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    /// Stable, caller-normalized identity key.
    pub id: AssetId,
    /// The asset's semantic type.
    pub kind: AssetKind,
    /// Namespaced non-secret metadata for forward-compatible integrations.
    #[serde(default)]
    pub extensions: BTreeMap<String, String>,
}
/// A source reference supporting an observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Evidence reference.
    pub id: EvidenceId,
    /// Collector producing the evidence.
    pub collector: CollectorId,
    /// Collector implementation version.
    pub collector_version: String,
    /// One collection/import execution.
    pub run: CollectionRunId,
    /// Source locator; may be sensitive and should be redacted at export boundaries.
    pub source: String,
    /// Timestamp supplied by the collector, formatted as RFC 3339.
    pub observed_at: String,
    /// Distinguishes direct collection from inference.
    pub kind: EvidenceKind,
    /// A collector-supplied confidence classification.
    pub confidence: Confidence,
    /// Optional content digest without embedding the source content.
    pub source_sha256: Option<String>,
    /// Inference-rule identifier, mandatory for inferred observations.
    #[serde(default)]
    pub inference_rule: Option<String>,
}
/// Immutable claim attached to one asset and supported by evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// Observation identity.
    pub id: ObservationId,
    /// Canonical asset to which the observation refers.
    pub asset: AssetId,
    /// Evidence identity.
    pub evidence: EvidenceId,
    /// Property observed; field names are namespaced to avoid ambiguity.
    pub property: String,
    /// Optional connection, configuration instance, or producer context.
    #[serde(default)]
    pub context: Option<String>,
    /// Observed value, which is not overwritten by later observations.
    pub value: String,
}
/// Relationship of two canonical assets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationshipKind {
    /// Asset A uses the algorithm represented by B.
    UsesAlgorithm,
    /// Asset A uses key B.
    UsesKey,
    /// Asset A uses certificate B.
    UsesCertificate,
    /// Asset A depends on B.
    DependsOn,
    /// Asset A is hosted or observed at B.
    ObservedAt,
    /// Asset A is provided by B.
    ProvidedBy,
    /// A related identity is possible but not proven.
    PossibleAlias,
    /// Generic typed relation pending a richer profile.
    RelatedTo,
    /// The protocol was observed negotiating at an endpoint.
    NegotiatedAt,
    /// A protocol or algorithm was configured for an asset.
    ConfiguredFor,
    /// A key was stored in a provider or key store.
    StoredIn,
    /// A certificate was issued by an authority.
    IssuedBy,
    /// An explicit validation relationship was observed.
    ValidatedBy,
    /// One logical asset contains another.
    Contains,
    /// An implementation provides a protocol.
    ImplementsProtocol,
}
/// Evidence-linked asset relationship.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relationship {
    /// Relationship identity.
    pub id: RelationshipId,
    /// Source asset.
    pub from: AssetId,
    /// Target asset.
    pub to: AssetId,
    /// Relationship semantics.
    pub kind: RelationshipKind,
    /// Supporting evidence identifiers.
    pub evidence: BTreeSet<EvidenceId>,
}
impl RelationshipId {
    /// Construct a direction-aware, type-specific edge identity independent
    /// of observation ordering and supporting evidence count.
    pub fn from_endpoints(
        kind: RelationshipKind,
        from: &AssetId,
        to: &AssetId,
    ) -> Result<Self, InventoryError> {
        if from == to && !matches!(kind, RelationshipKind::RelatedTo) {
            return Err(InventoryError::InvalidIdentifier);
        }
        let bytes = serde_json::to_vec(&("cryptomap:relationship:v1", kind, from, to))
            .map_err(|e| InventoryError::Encoding(e.to_string()))?;
        Self::new(format!("relationship:v1:{}", hex_digest(&bytes)))
    }
}
/// Distinct contradictory values for the same asset/property.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    /// Stable conflict identifier.
    pub id: ConflictId,
    /// Affected asset.
    pub asset: AssetId,
    /// Conflicting property.
    pub property: String,
    /// Context shared by the conflicting observations, if known.
    #[serde(default)]
    pub context: Option<String>,
    /// UTC hour bucket of the conflicting observations.
    #[serde(default)]
    pub utc_hour: i64,
    /// Values and the observations backing each value.
    pub values: BTreeMap<String, BTreeSet<ObservationId>>,
}
/// Collection coverage of an explicitly scoped source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum CoverageState {
    /// InspectedObserved is one supported CoverageState variant.
    InspectedObserved,
    /// InspectedNoObservation is one supported CoverageState variant.
    InspectedNoObservation,
    /// NotInspected is one supported CoverageState variant.
    NotInspected,
    /// Unsupported is one supported CoverageState variant.
    Unsupported,
    /// Failed is one supported CoverageState variant.
    Failed,
    /// Partial is one supported CoverageState variant.
    Partial,
}
/// Coverage state for a collector/scope item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// Source/scope identifier.
    pub scope_item: String,
    /// Collection status.
    pub state: CoverageState,
}
/// Limits enforced by the snapshot builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryLimits {
    /// Maximum asset count.
    pub assets: usize,
    /// Maximum observations.
    pub observations: usize,
    /// Maximum evidence entries.
    pub evidence: usize,
    /// Maximum relationships.
    pub relationships: usize,
    /// Maximum number of namespaced extension fields per asset.
    pub extension_entries: usize,
    /// Maximum bytes per metadata field.
    pub field_bytes: usize,
    /// Maximum serialized bytes in one asset.
    pub record_bytes: usize,
    /// Maximum canonical serialized snapshot bytes.
    pub snapshot_bytes: usize,
    /// Maximum collection runs.
    pub runs: usize,
    /// Maximum coverage records.
    pub coverage_records: usize,
}
impl Default for InventoryLimits {
    fn default() -> Self {
        Self {
            assets: 100_000,
            observations: 500_000,
            evidence: 500_000,
            relationships: 1_000_000,
            extension_entries: 32,
            field_bytes: 2048,
            record_bytes: 16384,
            snapshot_bytes: 256_000_000,
            runs: 10_000,
            coverage_records: 500_000,
        }
    }
}
/// Immutable, canonicalized evidence-backed inventory snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventorySnapshot {
    /// Canonical SHA-256 semantic identity, prefixed with sha256:.
    pub id: SnapshotId,
    /// Version of this crate's public snapshot schema.
    pub schema_version: u32,
    /// Canonical assets.
    pub assets: BTreeMap<AssetId, Asset>,
    /// Immutable observations.
    pub observations: BTreeMap<ObservationId, Observation>,
    /// Evidence records.
    pub evidence: BTreeMap<EvidenceId, Evidence>,
    /// Typed relationships.
    pub relationships: BTreeMap<RelationshipId, Relationship>,
    /// Automatically detected conflicts.
    pub conflicts: BTreeMap<ConflictId, Conflict>,
    /// Reported collection coverage.
    pub coverage: BTreeMap<String, CoverageState>,
    /// Collector runs identifying the scope and time of each observation.
    #[serde(default)]
    pub runs: BTreeMap<CollectionRunId, CollectionRun>,
    /// Typed source-item coverage records.
    #[serde(default)]
    pub coverage_records: Vec<CoverageRecord>,
}
/// Mutable accumulator; finalize validates and computes canonical snapshot identity.
#[derive(Debug, Default)]
pub struct InventoryBuilder {
    assets: BTreeMap<AssetId, Asset>,
    observations: BTreeMap<ObservationId, Observation>,
    evidence: BTreeMap<EvidenceId, Evidence>,
    relationships: BTreeMap<RelationshipId, Relationship>,
    coverage: BTreeMap<String, CoverageState>,
    runs: BTreeMap<CollectionRunId, CollectionRun>,
    coverage_records: Vec<CoverageRecord>,
}
impl InventoryBuilder {
    /// New empty builder.
    pub fn new() -> Self {
        Self::default()
    }
    /// Insert an asset; identical identities merge only if semantically equal.
    pub fn add_asset(&mut self, asset: Asset) -> Result<&mut Self, InventoryError> {
        if let Some(old) = self.assets.get(&asset.id) {
            if old != &asset {
                return Err(InventoryError::InvalidIdentifier);
            }
        }
        self.assets.insert(asset.id.clone(), asset);
        Ok(self)
    }
    /// Insert one immutable evidence record.
    pub fn add_evidence(&mut self, entry: Evidence) -> Result<&mut Self, InventoryError> {
        if let Some(old) = self.evidence.get(&entry.id) {
            if old != &entry {
                return Err(InventoryError::DuplicateObservation(entry.id.to_string()));
            }
        }
        self.evidence.insert(entry.id.clone(), entry);
        Ok(self)
    }
    /// Insert one observation without overwriting a conflicting observation ID.
    pub fn add_observation(&mut self, entry: Observation) -> Result<&mut Self, InventoryError> {
        if let Some(old) = self.observations.get(&entry.id) {
            if old != &entry {
                return Err(InventoryError::DuplicateObservation(entry.id.to_string()));
            }
        }
        self.observations.insert(entry.id.clone(), entry);
        Ok(self)
    }
    /// Insert typed asset relationship.
    pub fn add_relationship(&mut self, entry: Relationship) -> Result<&mut Self, InventoryError> {
        if let Some(old) = self.relationships.get_mut(&entry.id) {
            if old.from != entry.from || old.to != entry.to || old.kind != entry.kind {
                return Err(InventoryError::InvalidIdentifier);
            }
            old.evidence.extend(entry.evidence);
            return Ok(self);
        }
        self.relationships.insert(entry.id.clone(), entry);
        Ok(self)
    }
    /// Register an explicit collection run.
    pub fn add_run(&mut self, run: CollectionRun) -> Result<&mut Self, InventoryError> {
        run.validate()?;
        if let Some(old) = self.runs.get(&run.id) {
            if old != &run {
                return Err(InventoryError::InvalidMetadata);
            }
        }
        self.runs.insert(run.id.clone(), run);
        Ok(self)
    }
    /// Record collection scope and completeness for one item.
    pub fn add_coverage_record(&mut self, record: CoverageRecord) -> &mut Self {
        self.coverage_records.push(record);
        self
    }
    /// Accept a candidate with source-derived identity rather than trusting a caller ID.
    pub fn ingest_candidate(
        &mut self,
        kind: AssetKind,
        context: &IdentityContext,
        extensions: BTreeMap<String, String>,
    ) -> Result<AssetId, InventoryError> {
        let id = AssetId::from_kind(&kind, context)?;
        self.add_asset(Asset {
            id: id.clone(),
            kind,
            extensions,
        })?;
        Ok(id)
    }
    /// Record whether the requested scope item was inspected.
    pub fn set_coverage(&mut self, item: impl Into<String>, state: CoverageState) -> &mut Self {
        self.coverage.insert(item.into(), state);
        self
    }
    /// Validate references, detect divergent observations and finalize an immutable snapshot.
    pub fn finalize(
        mut self,
        limits: InventoryLimits,
    ) -> Result<InventorySnapshot, InventoryError> {
        for (label, count, max) in [
            ("assets", self.assets.len(), limits.assets),
            ("observations", self.observations.len(), limits.observations),
            ("evidence", self.evidence.len(), limits.evidence),
            (
                "relationships",
                self.relationships.len(),
                limits.relationships,
            ),
            ("runs", self.runs.len(), limits.runs),
            (
                "coverage records",
                self.coverage_records.len(),
                limits.coverage_records,
            ),
        ] {
            if count > max {
                return Err(InventoryError::LimitExceeded(label));
            }
        }
        for asset in self.assets.values() {
            asset.validate(&limits)?;
        }
        for evidence in self.evidence.values() {
            evidence.validate(&limits)?;
            let run = self
                .runs
                .get(&evidence.run)
                .ok_or(InventoryError::InvalidMetadata)?;
            if run.collector != evidence.collector
                || run.collector_version != evidence.collector_version
            {
                return Err(InventoryError::InvalidMetadata);
            }
        }
        for run in self.runs.values() {
            run.validate()?;
        }
        for record in &self.coverage_records {
            validation::safe_text(&record.source_item, limits.field_bytes)?;
            let run = self
                .runs
                .get(&record.run)
                .ok_or(InventoryError::InvalidMetadata)?;
            if !run.requested.contains(&record.source_item) {
                return Err(InventoryError::InvalidMetadata);
            }
            if matches!(run.completeness, RunCompleteness::Complete)
                && matches!(
                    record.state,
                    CoverageState::Failed | CoverageState::Partial | CoverageState::NotInspected
                )
            {
                return Err(InventoryError::InvalidMetadata);
            }
        }
        // Every requested item of a completed run needs an explicit successful outcome.
        let mut observed_coverage: BTreeMap<(CollectionRunId, String), CoverageState> =
            BTreeMap::new();
        for record in &self.coverage_records {
            let key = (record.run.clone(), record.source_item.clone());
            if let Some(existing) = observed_coverage.insert(key, record.state) {
                if existing != record.state {
                    return Err(InventoryError::InvalidMetadata);
                }
            }
        }
        for run in self.runs.values() {
            if matches!(run.completeness, RunCompleteness::Complete) {
                for item in &run.requested {
                    let key = (run.id.clone(), item.clone());
                    if !matches!(
                        observed_coverage.get(&key),
                        Some(
                            CoverageState::InspectedObserved
                                | CoverageState::InspectedNoObservation
                        )
                    ) {
                        return Err(InventoryError::InvalidMetadata);
                    }
                }
            }
        }
        self.coverage_records.sort();
        self.coverage_records.dedup();
        type ConflictContext = (AssetId, String, Option<String>, i64);
        type ConflictEvidence = BTreeMap<String, BTreeSet<ObservationId>>;
        let mut grouped: BTreeMap<ConflictContext, ConflictEvidence> = BTreeMap::new();
        for obs in self.observations.values() {
            if !self.assets.contains_key(&obs.asset) {
                return Err(InventoryError::MissingAsset(obs.asset.to_string()));
            }
            let evidence = self
                .evidence
                .get(&obs.evidence)
                .ok_or(InventoryError::InvalidIdentifier)?;
            obs.validate(&limits)?;
            // Only observations in the same UTC hour and with identical typed property
            // belong to one current-state conflict group; historical changes remain history.
            // Set-valued properties represent multiple compatible capabilities,
            // not contradictory scalar state.
            if matches!(
                obs.property.as_str(),
                "protocol:configured"
                    | "algorithm:supported"
                    | "certificate:san"
                    | "key:allowed-usage"
            ) {
                continue;
            }
            let bucket = validation::utc_seconds(&evidence.observed_at)?.div_euclid(3600);
            grouped
                .entry((
                    obs.asset.clone(),
                    obs.property.clone(),
                    obs.context.clone(),
                    bucket,
                ))
                .or_default()
                .entry(obs.value.clone())
                .or_default()
                .insert(obs.id.clone());
        }
        for rel in self.relationships.values() {
            if !self.assets.contains_key(&rel.from) || !self.assets.contains_key(&rel.to) {
                return Err(InventoryError::DanglingRelationship(rel.id.to_string()));
            }
            if rel
                .evidence
                .iter()
                .any(|id| !self.evidence.contains_key(id))
            {
                return Err(InventoryError::InvalidIdentifier);
            }
            let from = &self.assets[&rel.from].kind;
            let to = &self.assets[&rel.to].kind;
            let valid = match rel.kind {
                RelationshipKind::UsesAlgorithm => matches!(
                    to,
                    AssetKind::AlgorithmUse { .. } | AssetKind::DetailedAlgorithm { .. }
                ),
                RelationshipKind::UsesKey => {
                    matches!(to, AssetKind::Key { .. } | AssetKind::DetailedKey { .. })
                }
                RelationshipKind::UsesCertificate | RelationshipKind::ValidatedBy => matches!(
                    to,
                    AssetKind::Certificate { .. }
                        | AssetKind::DetailedCertificate { .. }
                        | AssetKind::TrustAnchor { .. }
                        | AssetKind::Authority { .. }
                ),
                RelationshipKind::StoredIn => {
                    matches!(from, AssetKind::Key { .. } | AssetKind::DetailedKey { .. })
                        && matches!(to, AssetKind::KeyStore { .. } | AssetKind::Provider { .. })
                }
                RelationshipKind::IssuedBy => {
                    matches!(
                        from,
                        AssetKind::Certificate { .. } | AssetKind::DetailedCertificate { .. }
                    ) && matches!(
                        to,
                        AssetKind::Authority { .. }
                            | AssetKind::Certificate { .. }
                            | AssetKind::DetailedCertificate { .. }
                            | AssetKind::TrustAnchor { .. }
                    )
                }
                RelationshipKind::NegotiatedAt => {
                    matches!(
                        from,
                        AssetKind::Protocol {
                            state: ProtocolState::Negotiated,
                            ..
                        } | AssetKind::DetailedProtocol {
                            metadata: metadata::ProtocolMetadata {
                                state: metadata::ProtocolObservation::Negotiated,
                                ..
                            }
                        }
                    ) && matches!(to, AssetKind::Endpoint { .. })
                }
                RelationshipKind::ConfiguredFor => matches!(
                    from,
                    AssetKind::Protocol {
                        state: ProtocolState::Configured,
                        ..
                    } | AssetKind::DetailedProtocol {
                        metadata: metadata::ProtocolMetadata {
                            state: metadata::ProtocolObservation::Configured,
                            ..
                        }
                    } | AssetKind::AlgorithmUse { .. }
                        | AssetKind::DetailedAlgorithm { .. }
                ),
                RelationshipKind::ImplementsProtocol => matches!(
                    to,
                    AssetKind::Protocol { .. } | AssetKind::DetailedProtocol { .. }
                ),
                _ => true,
            };
            if !valid {
                return Err(InventoryError::InvalidMetadata);
            }
        }
        let mut conflicts = BTreeMap::new();
        for ((asset, property, context, bucket), values) in grouped {
            if values.len() > 1 {
                let bytes =
                    serde_json::to_vec(&(asset.clone(), property.clone(), context.clone(), bucket))
                        .map_err(|e| InventoryError::Encoding(e.to_string()))?;
                let id = ConflictId::new(format!("sha256:{}", hex_digest(&bytes)))?;
                conflicts.insert(
                    id.clone(),
                    Conflict {
                        id,
                        asset,
                        property,
                        context,
                        utc_hour: bucket,
                        values,
                    },
                );
            }
        }
        let mut result = InventorySnapshot {
            id: SnapshotId::new("pending")?,
            schema_version: 2,
            assets: self.assets,
            observations: self.observations,
            evidence: self.evidence,
            relationships: self.relationships,
            conflicts,
            coverage: self.coverage,
            runs: self.runs,
            coverage_records: self.coverage_records,
        };
        let semantic_bytes = serde_json::to_vec(&(
            result.schema_version,
            &result.assets,
            &result.observations,
            &result.evidence,
            &result.relationships,
            &result.conflicts,
            &result.coverage,
            &result.runs,
            &result.coverage_records,
        ))
        .map_err(|e| InventoryError::Encoding(e.to_string()))?;
        if semantic_bytes.len() > limits.snapshot_bytes {
            return Err(InventoryError::LimitExceeded("snapshot bytes"));
        }
        result.id = SnapshotId::new(format!("sha256:{}", hex_digest(&semantic_bytes)))?;
        Ok(result)
    }
}
fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
/// Deterministic asset-level changes between snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSet {
    /// Newly present asset identifiers.
    pub added: BTreeSet<AssetId>,
    /// Asset identifiers no longer present.
    pub removed: BTreeSet<AssetId>,
    /// Asset identifiers whose canonical metadata changed.
    pub changed: BTreeSet<AssetId>,
    /// Canonical metadata is unchanged.
    pub unchanged: BTreeSet<AssetId>,
    /// Potential removals that cannot be confirmed under incomplete collection.
    pub tentative_removed: BTreeSet<AssetId>,
    /// Newly observed facts.
    pub observations_added: BTreeSet<ObservationId>,
    /// Removed observation identifiers.
    pub observations_removed: BTreeSet<ObservationId>,
    /// Observation absences not confirmed because collection is incomplete.
    pub observations_tentative_removed: BTreeSet<ObservationId>,
    /// Observations with changed content under the same identifier.
    pub observations_changed: BTreeSet<ObservationId>,
    /// Evidence entries newly available.
    pub evidence_added: BTreeSet<EvidenceId>,
    /// Evidence entries no longer referenced/present.
    pub evidence_removed: BTreeSet<EvidenceId>,
    /// Unconfirmed evidence absences under incomplete coverage.
    pub evidence_tentative_removed: BTreeSet<EvidenceId>,
    /// Evidence with updated confidence.
    pub confidence_changed: BTreeSet<EvidenceId>,
    /// New relationships.
    pub relationships_added: BTreeSet<RelationshipId>,
    /// Removed relationships.
    pub relationships_removed: BTreeSet<RelationshipId>,
    /// Unconfirmed relationship absences under incomplete coverage.
    pub relationships_tentative_removed: BTreeSet<RelationshipId>,
    /// Same relationship identifier with modified metadata.
    pub relationships_changed: BTreeSet<RelationshipId>,
    /// Conflict IDs whose competing evidence sets changed.
    pub conflicts_changed: BTreeSet<ConflictId>,
    /// Scope items with changed coverage state.
    pub coverage_changed: BTreeSet<String>,
    /// Conflicts newly present in the later snapshot.
    pub conflicts_introduced: BTreeSet<ConflictId>,
    /// Conflicts absent from the later snapshot.
    pub conflicts_resolved: BTreeSet<ConflictId>,
}
impl InventorySnapshot {
    /// Recalculate the digest and verify internal references on an imported snapshot.
    pub fn verify(&self, limits: InventoryLimits) -> Result<(), InventoryError> {
        if self.schema_version != 2 {
            return Err(InventoryError::UnsupportedSchema(self.schema_version));
        }
        let mut builder = InventoryBuilder::new();
        for run in self.runs.values() {
            builder.add_run(run.clone())?;
        }
        for asset in self.assets.values() {
            builder.add_asset(asset.clone())?;
        }
        for evidence in self.evidence.values() {
            builder.add_evidence(evidence.clone())?;
        }
        for observation in self.observations.values() {
            builder.add_observation(observation.clone())?;
        }
        for relationship in self.relationships.values() {
            builder.add_relationship(relationship.clone())?;
        }
        for (source, state) in &self.coverage {
            builder.set_coverage(source.clone(), *state);
        }
        for record in &self.coverage_records {
            builder.add_coverage_record(record.clone());
        }
        let verified = builder.finalize(limits)?;
        if verified.id != self.id || verified != *self {
            return Err(InventoryError::DigestMismatch);
        }
        Ok(())
    }
    /// Decode JSON only after verifying schema, source references and canonical digest.
    pub fn from_json_verified(
        input: &str,
        limits: InventoryLimits,
    ) -> Result<Self, InventoryError> {
        if input.len() > limits.snapshot_bytes {
            return Err(InventoryError::LimitExceeded("snapshot bytes"));
        }
        let strict: strict_json::StrictJson =
            serde_json::from_str(input).map_err(|e| InventoryError::Encoding(e.to_string()))?;
        let snapshot: Self = serde_json::from_value(strict.0)
            .map_err(|e| InventoryError::Encoding(e.to_string()))?;
        snapshot.verify(limits)?;
        Ok(snapshot)
    }
    /// Compare this snapshot (old) with a newer snapshot deterministically.
    pub fn diff(&self, newer: &Self) -> ChangeSet {
        let old: BTreeSet<_> = self.assets.keys().cloned().collect();
        let new: BTreeSet<_> = newer.assets.keys().cloned().collect();
        let common = old.intersection(&new);
        // A complete scan of only a SUBSET of prior sources cannot prove removals.
        // Scope equality is evaluated using normalized source keys, not run IDs.
        let old_scope: BTreeSet<(u8, String, String)> = self
            .coverage
            .keys()
            .map(|item| (0, String::new(), item.clone()))
            .chain(self.runs.values().flat_map(|run| {
                run.requested
                    .iter()
                    .map(move |item| (1, run.scope.as_str().to_owned(), item.clone()))
            }))
            .collect();
        let covered_now: BTreeSet<(u8, String, String)> = newer
            .coverage
            .iter()
            .filter(|(_, state)| {
                matches!(
                    state,
                    CoverageState::InspectedObserved | CoverageState::InspectedNoObservation
                )
            })
            .map(|(item, _)| (0, String::new(), item.clone()))
            .chain(
                newer
                    .coverage_records
                    .iter()
                    .filter(|record| {
                        matches!(
                            record.state,
                            CoverageState::InspectedObserved
                                | CoverageState::InspectedNoObservation
                        )
                    })
                    .filter_map(|record| {
                        newer.runs.get(&record.run).map(|run| {
                            (1, run.scope.as_str().to_owned(), record.source_item.clone())
                        })
                    }),
            )
            .collect();
        let complete = !old_scope.is_empty()
            && old_scope.is_subset(&covered_now)
            && newer.coverage.values().all(|state| {
                matches!(
                    state,
                    CoverageState::InspectedObserved | CoverageState::InspectedNoObservation
                )
            })
            && newer
                .runs
                .values()
                .all(|run| matches!(run.completeness, RunCompleteness::Complete))
            && newer.coverage_records.iter().all(|record| {
                matches!(
                    record.state,
                    CoverageState::InspectedObserved | CoverageState::InspectedNoObservation
                )
            });
        let old_obs: BTreeSet<_> = self.observations.keys().cloned().collect();
        let new_obs: BTreeSet<_> = newer.observations.keys().cloned().collect();
        let old_evidence: BTreeSet<_> = self.evidence.keys().cloned().collect();
        let new_evidence: BTreeSet<_> = newer.evidence.keys().cloned().collect();
        let old_rel: BTreeSet<_> = self.relationships.keys().cloned().collect();
        let new_rel: BTreeSet<_> = newer.relationships.keys().cloned().collect();
        ChangeSet {
            added: new.difference(&old).cloned().collect(),
            removed: if complete {
                old.difference(&new).cloned().collect()
            } else {
                BTreeSet::new()
            },
            tentative_removed: if complete {
                BTreeSet::new()
            } else {
                old.difference(&new).cloned().collect()
            },
            changed: common
                .clone()
                .filter(|id| self.assets.get(*id) != newer.assets.get(*id))
                .cloned()
                .collect(),
            unchanged: old
                .intersection(&new)
                .filter(|id| self.assets.get(*id) == newer.assets.get(*id))
                .cloned()
                .collect(),
            observations_added: new_obs.difference(&old_obs).cloned().collect(),
            observations_removed: if complete {
                old_obs.difference(&new_obs).cloned().collect()
            } else {
                BTreeSet::new()
            },
            observations_tentative_removed: if complete {
                BTreeSet::new()
            } else {
                old_obs.difference(&new_obs).cloned().collect()
            },
            observations_changed: old_obs
                .intersection(&new_obs)
                .filter(|id| self.observations.get(*id) != newer.observations.get(*id))
                .cloned()
                .collect(),
            evidence_added: new_evidence.difference(&old_evidence).cloned().collect(),
            evidence_removed: if complete {
                old_evidence.difference(&new_evidence).cloned().collect()
            } else {
                BTreeSet::new()
            },
            evidence_tentative_removed: if complete {
                BTreeSet::new()
            } else {
                old_evidence.difference(&new_evidence).cloned().collect()
            },
            confidence_changed: old_evidence
                .intersection(&new_evidence)
                .filter(|id| {
                    self.evidence.get(*id).map(|e| e.confidence)
                        != newer.evidence.get(*id).map(|e| e.confidence)
                })
                .cloned()
                .collect(),
            relationships_added: new_rel.difference(&old_rel).cloned().collect(),
            relationships_removed: if complete {
                old_rel.difference(&new_rel).cloned().collect()
            } else {
                BTreeSet::new()
            },
            relationships_tentative_removed: if complete {
                BTreeSet::new()
            } else {
                old_rel.difference(&new_rel).cloned().collect()
            },
            relationships_changed: old_rel
                .intersection(&new_rel)
                .filter(|id| self.relationships.get(*id) != newer.relationships.get(*id))
                .cloned()
                .collect(),
            conflicts_changed: self
                .conflicts
                .keys()
                .filter(|id| {
                    newer.conflicts.contains_key(*id)
                        && self.conflicts.get(*id) != newer.conflicts.get(*id)
                })
                .cloned()
                .collect(),
            coverage_changed: self
                .coverage
                .keys()
                .chain(newer.coverage.keys())
                .filter(|k| self.coverage.get(*k) != newer.coverage.get(*k))
                .cloned()
                .collect(),
            conflicts_introduced: newer
                .conflicts
                .keys()
                .filter(|id| !self.conflicts.contains_key(*id))
                .cloned()
                .collect(),
            conflicts_resolved: self
                .conflicts
                .keys()
                .filter(|id| !newer.conflicts.contains_key(*id))
                .cloned()
                .collect(),
        }
    }
    /// Iterate assets matching a caller-provided predicate.
    pub fn query_assets(&self, predicate: impl Fn(&Asset) -> bool) -> impl Iterator<Item = &Asset> {
        self.assets.values().filter(move |asset| predicate(asset))
    }
    /// Return all evidence-backed observations for one asset.
    pub fn observations_for(&self, id: &AssetId) -> impl Iterator<Item = &Observation> {
        self.observations
            .values()
            .filter(move |obs| &obs.asset == id)
    }
}
