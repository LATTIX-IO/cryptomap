//! Canonical evidence-backed cryptographic inventory.
//!
//! This crate represents observations, not compliance assessments or migration advice.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

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
}
impl fmt::Display for InventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
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
                if value.is_empty() || value.len() > 512 || value.trim() != value ||
                    value.chars().any(char::is_control) { return Err(InventoryError::InvalidIdentifier); }
                Ok(Self(value))
            }
            /// Borrow the identifier string.
            pub fn as_str(&self) -> &str { &self.0 }
        }
        impl TryFrom<String> for $name {
            type Error = InventoryError;
            fn try_from(value: String) -> Result<Self, Self::Error> { Self::new(value) }
        }
        impl From<$name> for String {
            fn from(value: $name) -> Self { value.0 }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
        }
    }
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
pub enum Confidence { Unknown, Low, Medium, High, Confirmed }
/// Whether the source directly observed the fact or inferred it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind { Direct, Inferred }
/// Observed protocol state must distinguish configuration from negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolState { Configured, Negotiated }
/// Supported canonical asset families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetKind {
    /// Crypto operation at a particular use site.
    AlgorithmUse { family: String, profile: Option<String>, use_site: String },
    /// Key metadata; raw key material is intentionally not part of this type.
    Key { algorithm: Option<String>, provider: Option<String>, fingerprint: Option<String> },
    /// Certificate metadata; the certificate body is not stored by default.
    Certificate { fingerprint_sha256: String, public_key_profile: Option<String>, signature_profile: Option<String> },
    /// Configured or negotiated protocol fact.
    Protocol { family: String, version: Option<String>, state: ProtocolState },
    /// Scoped transport endpoint.
    Endpoint { transport: String, host: String, port: u16, scope: String },
    /// Versioned package dependency.
    Library { ecosystem: String, name: String, version: String },
    /// Runtime or cryptographic software implementation.
    Runtime { name: String, version: Option<String> },
    /// Logical cryptographic key storage location.
    KeyStore { provider: String, name: String },
    /// Arbitrary source-location identification.
    SourceUse { source: String, location: String },
    /// Named trust authority.
    TrustAnchor { fingerprint: String },
    /// Source-specific type that has no standardized mapping yet.
    Extension { namespace: String, kind: String },
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
/// Distinct contradictory values for the same asset/property.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    /// Stable conflict identifier.
    pub id: ConflictId,
    /// Affected asset.
    pub asset: AssetId,
    /// Conflicting property.
    pub property: String,
    /// Values and the observations backing each value.
    pub values: BTreeMap<String, BTreeSet<ObservationId>>,
}
/// Collection coverage of an explicitly scoped source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageState { InspectedObserved, InspectedNoObservation, NotInspected, Unsupported, Failed, Partial }
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
}
impl Default for InventoryLimits {
    fn default() -> Self { Self { assets: 100_000, observations: 500_000, evidence: 500_000, relationships: 1_000_000 } }
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
}
/// Mutable accumulator; finalize validates and computes canonical snapshot identity.
#[derive(Debug, Default)]
pub struct InventoryBuilder {
    assets: BTreeMap<AssetId, Asset>,
    observations: BTreeMap<ObservationId, Observation>,
    evidence: BTreeMap<EvidenceId, Evidence>,
    relationships: BTreeMap<RelationshipId, Relationship>,
    coverage: BTreeMap<String, CoverageState>,
}
impl InventoryBuilder {
    /// New empty builder.
    pub fn new() -> Self { Self::default() }
    /// Insert an asset; identical identities merge only if semantically equal.
    pub fn add_asset(&mut self, asset: Asset) -> Result<&mut Self, InventoryError> {
        if let Some(old) = self.assets.get(&asset.id) {
            if old != &asset { return Err(InventoryError::InvalidIdentifier); }
        }
        self.assets.insert(asset.id.clone(), asset); Ok(self)
    }
    /// Insert one immutable evidence record.
    pub fn add_evidence(&mut self, entry: Evidence) -> Result<&mut Self, InventoryError> {
        if let Some(old) = self.evidence.get(&entry.id) {
            if old != &entry { return Err(InventoryError::DuplicateObservation(entry.id.to_string())); }
        }
        self.evidence.insert(entry.id.clone(), entry); Ok(self)
    }
    /// Insert one observation without overwriting a conflicting observation ID.
    pub fn add_observation(&mut self, entry: Observation) -> Result<&mut Self, InventoryError> {
        if let Some(old) = self.observations.get(&entry.id) {
            if old != &entry { return Err(InventoryError::DuplicateObservation(entry.id.to_string())); }
        }
        self.observations.insert(entry.id.clone(), entry); Ok(self)
    }
    /// Insert typed asset relationship.
    pub fn add_relationship(&mut self, entry: Relationship) -> Result<&mut Self, InventoryError> {
        if let Some(old) = self.relationships.get(&entry.id) {
            if old != &entry { return Err(InventoryError::InvalidIdentifier); }
        }
        self.relationships.insert(entry.id.clone(), entry); Ok(self)
    }
    /// Record whether the requested scope item was inspected.
    pub fn set_coverage(&mut self, item: impl Into<String>, state: CoverageState) -> &mut Self {
        self.coverage.insert(item.into(), state); self
    }
    /// Validate references, detect divergent observations and finalize an immutable snapshot.
    pub fn finalize(self, limits: InventoryLimits) -> Result<InventorySnapshot, InventoryError> {
        for (label, count, max) in [
            ("assets",self.assets.len(),limits.assets),
            ("observations",self.observations.len(),limits.observations),
            ("evidence",self.evidence.len(),limits.evidence),
            ("relationships",self.relationships.len(),limits.relationships)
        ] { if count > max { return Err(InventoryError::LimitExceeded(label)); } }
        let mut grouped: BTreeMap<(AssetId,String), BTreeMap<String,BTreeSet<ObservationId>>> = BTreeMap::new();
        for obs in self.observations.values() {
            if !self.assets.contains_key(&obs.asset) { return Err(InventoryError::MissingAsset(obs.asset.to_string())); }
            if !self.evidence.contains_key(&obs.evidence) { return Err(InventoryError::InvalidIdentifier); }
            grouped.entry((obs.asset.clone(),obs.property.clone())).or_default()
                .entry(obs.value.clone()).or_default().insert(obs.id.clone());
        }
        for rel in self.relationships.values() {
            if !self.assets.contains_key(&rel.from) || !self.assets.contains_key(&rel.to) {
                return Err(InventoryError::DanglingRelationship(rel.id.to_string()));
            }
            if rel.evidence.iter().any(|id| !self.evidence.contains_key(id)) { return Err(InventoryError::InvalidIdentifier); }
        }
        let mut conflicts = BTreeMap::new();
        for ((asset,property),values) in grouped {
            if values.len() > 1 {
                let bytes = serde_json::to_vec(&(asset.clone(),property.clone()))
                    .map_err(|e| InventoryError::Encoding(e.to_string()))?;
                let id = ConflictId::new(format!("sha256:{}",hex_digest(&bytes)))?;
                conflicts.insert(id.clone(),Conflict{id,asset,property,values});
            }
        }
        let mut result = InventorySnapshot {
            id: SnapshotId::new("pending")?,schema_version:1,assets:self.assets,
            observations:self.observations,evidence:self.evidence,
            relationships:self.relationships,conflicts,coverage:self.coverage
        };
        let semantic_bytes = serde_json::to_vec(&(
            result.schema_version,&result.assets,&result.observations,&result.evidence,
            &result.relationships,&result.conflicts,&result.coverage
        )).map_err(|e| InventoryError::Encoding(e.to_string()))?;
        result.id = SnapshotId::new(format!("sha256:{}",hex_digest(&semantic_bytes)))?;
        Ok(result)
    }
}
fn hex_digest(bytes:&[u8])->String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b|format!("{b:02x}")).collect()
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
    /// Scope items with changed coverage state.
    pub coverage_changed: BTreeSet<String>,
    /// Conflicts newly present in the later snapshot.
    pub conflicts_introduced: BTreeSet<ConflictId>,
    /// Conflicts absent from the later snapshot.
    pub conflicts_resolved: BTreeSet<ConflictId>,
}
impl InventorySnapshot {
    /// Compare this snapshot (old) with a newer snapshot deterministically.
    pub fn diff(&self, newer:&Self)->ChangeSet {
        let old: BTreeSet<_> = self.assets.keys().cloned().collect();
        let new: BTreeSet<_> = newer.assets.keys().cloned().collect();
        let common = old.intersection(&new);
        ChangeSet {
            added:new.difference(&old).cloned().collect(),
            removed:old.difference(&new).cloned().collect(),
            changed:common.clone().filter(|id|self.assets.get(*id)!=newer.assets.get(*id)).cloned().collect(),
            unchanged:old.intersection(&new).filter(|id|self.assets.get(*id)==newer.assets.get(*id)).cloned().collect(),
            coverage_changed:self.coverage.keys().chain(newer.coverage.keys()).filter(|k|self.coverage.get(*k)!=newer.coverage.get(*k)).cloned().collect(),
            conflicts_introduced:newer.conflicts.keys().filter(|id|!self.conflicts.contains_key(*id)).cloned().collect(),
            conflicts_resolved:self.conflicts.keys().filter(|id|!newer.conflicts.contains_key(*id)).cloned().collect(),
        }
    }
    /// Iterate assets matching a caller-provided predicate.
    pub fn query_assets(&self, predicate:impl Fn(&Asset)->bool)->impl Iterator<Item=&Asset> {
        self.assets.values().filter(move |asset|predicate(asset))
    }
    /// Return all evidence-backed observations for one asset.
    pub fn observations_for(&self, id:&AssetId)->impl Iterator<Item=&Observation> {
        self.observations.values().filter(move |obs|&obs.asset==id)
    }
}
