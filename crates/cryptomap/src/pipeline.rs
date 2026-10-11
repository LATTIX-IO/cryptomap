//! Bounded, deterministic raw-to-canonical collection pipeline.
//!
//! The host supplies an already-authorized CollectionScope and exact requested
//! source list. This first increment maps algorithm-use and dependency facts;
//! unsupported raw categories fail closed rather than disappearing.
use crate::{
    AssetId, AssetKind, CollectionRunId, CoverageState, Evidence, EvidenceId, IdentityContext,
    InventoryBuilder, InventoryError, InventoryLimits, InventorySnapshot, Observation,
    ObservationId, ProtocolState,
    collector::{
        CollectionOutcome, CollectionRequest, CollectionStatus, CollectorDescriptor,
        RequestedSource,
    },
    coverage::{CollectionRun, CoverageRecord, RunCompleteness},
    metadata::{Observed, ProtocolMetadata, ProtocolObservation},
    raw::{RawFactKind, RawLimits, RawObservation},
    registry::{Kind, Namespace, Registry, RegistryError, Resolution},
    scope::{CollectionScope, ScopeError},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

/// A typed pipeline failure that does not embed secret-bearing source contents.
pub enum PipelineError {
    /// The imported outcome is inconsistent with the request or collector.
    InvalidOutcome,
    /// A raw fact type has no reviewed canonical mapping in this increment.
    UnsupportedFact,
    /// Authorization of the supplied collection request failed.
    Scope(ScopeError),
    /// Inventory or raw contract validation failed.
    Inventory(InventoryError),
    /// Algorithm identifier or registry operation failed.
    Registry(RegistryError),
}
impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOutcome => f.write_str("invalid collector outcome"),
            Self::UnsupportedFact => f.write_str("unsupported raw fact category"),
            Self::Scope(_) => f.write_str("collection source authorization failed"),
            Self::Inventory(_) => f.write_str("invalid raw or canonical inventory"),
            Self::Registry(_) => f.write_str("algorithm registry resolution failed"),
        }
    }
}
// Public debug logs must not echo raw event IDs, paths or nested error
// payloads supplied by untrusted source data.
impl fmt::Debug for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl Error for PipelineError {}
impl From<ScopeError> for PipelineError {
    fn from(e: ScopeError) -> Self {
        Self::Scope(e)
    }
}
impl From<InventoryError> for PipelineError {
    fn from(e: InventoryError) -> Self {
        Self::Inventory(e)
    }
}
impl From<RegistryError> for PipelineError {
    fn from(e: RegistryError) -> Self {
        Self::Registry(e)
    }
}

/// Trusted host inputs required before any canonical state can be produced.
pub struct PipelineInput<'a> {
    /// Capability-rooted authorization; no collector can add to it.
    pub scope: &'a CollectionScope,
    /// Scope-bound canonical identity, required to match scope ID.
    pub identity: &'a IdentityContext,
    /// Versioned exact-alias registry.
    pub registry: &'a Registry,
    /// Trusted, host-pinned descriptor of the collector permitted for this run.
    pub expected_descriptor: &'a CollectorDescriptor,
    /// Trusted invocation ID; never inferred from the imported outcome.
    pub expected_run: &'a CollectionRunId,
    /// Exact requested sources, not a set inferred from emitted observations.
    pub sources: &'a [RequestedSource],
    /// Same raw limits used to collect the original data.
    pub raw_limits: RawLimits,
    /// Limits for snapshot finalization.
    pub inventory_limits: InventoryLimits,
    /// Collection-run start time (timezone-qualified RFC 3339).
    pub started_at: &'a str,
    /// Collection-run end time (timezone-qualified RFC 3339).
    pub ended_at: &'a str,
}

fn namespace(value: &str) -> Option<Namespace> {
    match value {
        "tls_cipher_suite" => Some(Namespace::TlsCipherSuite),
        "tls_group" => Some(Namespace::TlsGroup),
        "x509_oid" => Some(Namespace::X509Oid),
        "openssl" => Some(Namespace::OpenSsl),
        "ssh" => Some(Namespace::Ssh),
        _ => None,
    }
}
fn kind(value: &str) -> Option<Kind> {
    match value {
        "cipher_suite" => Some(Kind::CipherSuite),
        "group" => Some(Kind::Group),
        "key" => Some(Kind::Key),
        "signature" => Some(Kind::Signature),
        "encryption" => Some(Kind::Encryption),
        "hash" => Some(Kind::Hash),
        "kdf" => Some(Kind::Kdf),
        "protocol" => Some(Kind::Protocol),
        _ => None,
    }
}

// Hash typed tuples, not potentially ambiguous concatenated identifiers.
fn digest_id(parts: &[&str]) -> Result<String, InventoryError> {
    let bytes = serde_json::to_vec(parts).map_err(|_| InventoryError::InvalidMetadata)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// Unambiguous, source-bound identity for independently observed locations.
///
/// This deliberately excludes the event ID so independently emitted facts
/// from the same source position can be correlated without merging distinct
/// sources. The optional offsets keep absent and zero values distinct.
fn source_site(raw: &RawObservation) -> Result<String, InventoryError> {
    let location = serde_json::to_vec(&(
        "cryptomap:use-site:v1",
        &raw.collector,
        &raw.source.kind,
        &raw.source.item,
        raw.source.offset,
        raw.source.line,
        raw.source.column,
    ))
    .map_err(|_| InventoryError::InvalidMetadata)?;
    Ok(format!("use-site:v1:{:x}", Sha256::digest(location)))
}

/// Reject non-reference key material and sensitive configuration names before
/// representing source text as a canonical fact. This complements (not
/// replaces) upstream source redaction and RawObservation validation.
fn nonsecret_configuration(property: &str) -> Result<(), InventoryError> {
    let label = property.to_ascii_lowercase().replace('-', "_");
    let parts: Vec<&str> = label
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .collect();
    let credential_pair = parts
        .windows(2)
        .any(|pair| matches!(pair, ["api" | "access" | "secret" | "private", "key"]));
    if credential_pair
        || parts.iter().copied().any(|part| {
            matches!(
                part,
                "password"
                    | "passwd"
                    | "secret"
                    | "token"
                    | "credential"
                    | "credentials"
                    | "private"
                    | "passphrase"
                    | "apikey"
                    | "api_key"
            )
        })
    {
        return Err(InventoryError::ProhibitedMaterial);
    }
    Ok(())
}

fn evidence_for(raw: &RawObservation) -> Result<Evidence, InventoryError> {
    let id = EvidenceId::new(format!(
        "evidence:v1:{}",
        digest_id(&[raw.run.as_str(), raw.collector.as_str(), &raw.event_id])?
    ))?;
    Ok(Evidence {
        id,
        collector: raw.collector.clone(),
        collector_version: raw.collector_version.clone(),
        run: raw.run.clone(),
        source: format!("{:?}:{}", raw.source.kind, raw.source.item),
        observed_at: raw.observed_at.clone(),
        kind: raw.evidence_kind,
        confidence: raw.confidence,
        source_sha256: raw.source_sha256.clone(),
        inference_rule: raw.inference_rule.clone(),
    })
}

fn observe(
    builder: &mut InventoryBuilder,
    raw: &RawObservation,
    asset: &AssetId,
    evidence: &EvidenceId,
    property: &str,
    value: String,
) -> Result<(), InventoryError> {
    let id = ObservationId::new(format!(
        "observation:v1:{}",
        digest_id(&[
            raw.run.as_str(),
            raw.collector.as_str(),
            &raw.event_id,
            property
        ])?
    ))?;
    builder.add_observation(Observation {
        id,
        asset: asset.clone(),
        evidence: evidence.clone(),
        property: property.to_owned(),
        // Independent source events are not contradictory scalar claims merely
        // because they use different aliases for the same canonical profile.
        context: Some(raw.event_id.clone()),
        value,
    })?;
    Ok(())
}

fn map_fact(
    builder: &mut InventoryBuilder,
    raw: &RawObservation,
    identity: &IdentityContext,
    registry: &Registry,
    evidence: &EvidenceId,
) -> Result<AssetId, PipelineError> {
    let asset = match &raw.fact {
        RawFactKind::AlgorithmUse {
            identifier,
            profile,
            operation,
        } => {
            // A namespace and operation kind must be *source asserted*, never
            // guessed from identifier spelling or the collector name.
            let ns = raw
                .attributes
                .get("cryptomap:algorithm-namespace")
                .and_then(|v| namespace(v))
                .ok_or(PipelineError::InvalidOutcome)?;
            let k = raw
                .attributes
                .get("cryptomap:algorithm-kind")
                .and_then(|v| kind(v))
                .ok_or(PipelineError::InvalidOutcome)?;
            let resolution = registry.resolve(&ns, &k, identifier)?;
            let (family, normalized, rule, authority) = match resolution {
                Resolution::Known {
                    canonical,
                    family,
                    rule,
                    source,
                    ..
                } => (family, canonical, rule, source),
                Resolution::Unknown { .. } => (
                    "unrecognized".to_owned(),
                    format!("unmapped:{ns:?}:{k:?}:{identifier}"),
                    "registry:unmapped".to_owned(),
                    "registry:unmapped".to_owned(),
                ),
            };
            // Preserve source-supplied parameters without claiming the registry
            // has validated them. Incomplete RSA-PSS/EC parameters remain incomplete.
            let profile_key = match profile {
                Some(value) => format!("{normalized};source-parameters={value}"),
                None => normalized.clone(),
            };
            let use_site = source_site(raw)?;
            let asset = builder.ingest_candidate(
                AssetKind::AlgorithmUse {
                    family,
                    profile: Some(profile_key),
                    use_site,
                },
                identity,
                BTreeMap::new(),
            )?;
            observe(
                builder,
                raw,
                &asset,
                evidence,
                "algorithm:raw-identifier",
                identifier.clone(),
            )?;
            observe(
                builder,
                raw,
                &asset,
                evidence,
                "algorithm:normalized",
                normalized,
            )?;
            observe(
                builder,
                raw,
                &asset,
                evidence,
                "algorithm:normalization-rule",
                rule,
            )?;
            observe(
                builder,
                raw,
                &asset,
                evidence,
                "algorithm:registry-source",
                authority,
            )?;
            if let Some(op) = operation {
                observe(
                    builder,
                    raw,
                    &asset,
                    evidence,
                    "algorithm:source-operation",
                    op.clone(),
                )?;
            }
            if let Some(parameters) = profile {
                observe(
                    builder,
                    raw,
                    &asset,
                    evidence,
                    "algorithm:source-parameters",
                    parameters.clone(),
                )?;
            }
            asset
        }
        RawFactKind::Dependency {
            ecosystem,
            name,
            version,
        } => {
            // A dependency proves package presence, never actual crypto use.
            let asset = builder.ingest_candidate(
                AssetKind::Library {
                    ecosystem: ecosystem.clone(),
                    name: name.clone(),
                    version: version.clone(),
                },
                identity,
                BTreeMap::new(),
            )?;
            observe(
                builder,
                raw,
                &asset,
                evidence,
                "dependency:presence",
                "declared".into(),
            )?;
            asset
        }
        RawFactKind::Certificate { fingerprint_sha256 } => {
            // RawObservation validates the exact 64-character SHA-256 hex
            // fingerprint. Canonical lowercase avoids duplicate assets.
            let digest = fingerprint_sha256.to_ascii_lowercase();
            let asset = builder.ingest_candidate(
                AssetKind::Certificate {
                    fingerprint_sha256: digest.clone(),
                    public_key_profile: None,
                    signature_profile: None,
                },
                identity,
                BTreeMap::new(),
            )?;
            observe(
                builder,
                raw,
                &asset,
                evidence,
                "certificate:fingerprint-sha256",
                digest,
            )?;
            asset
        }
        RawFactKind::KeyReference {
            provider,
            reference,
        } => {
            // The host must explicitly pin the provider instance; a source's
            // declared provider name is not authority to merge key identities.
            if identity.provider_instance.is_none() {
                return Err(PipelineError::Inventory(
                    InventoryError::InsufficientIdentity,
                ));
            }
            let asset = builder.ingest_candidate(
                AssetKind::Key {
                    algorithm: None,
                    provider: Some(provider.clone()),
                    // FOSS-2 key identity folds fingerprint strings to ASCII
                    // lowercase. Hash the *exact* opaque reference first so
                    // case-sensitive provider IDs cannot silently collide.
                    // This digest identifies the reference, not key material.
                    fingerprint: Some(format!("opaque-ref:v1:{}", digest_id(&[reference])?)),
                },
                identity,
                BTreeMap::new(),
            )?;
            observe(
                builder,
                raw,
                &asset,
                evidence,
                "key:provider-reference",
                reference.clone(),
            )?;
            asset
        }
        RawFactKind::Protocol {
            family,
            version,
            state,
        } => {
            let site = source_site(raw)?;
            // IdentityContext::use_site must be specific to the observed
            // position rather than inherited from a different raw record.
            let context = identity.clone().with_use_site(site)?;
            let asset_kind = if version.is_some() {
                AssetKind::Protocol {
                    family: family.clone(),
                    version: version.clone(),
                    state: *state,
                }
            } else {
                // FOSS-2's basic Protocol identity requires an exact version.
                // Its detailed equivalent has an explicit Unknown version,
                // without inventing a sentinel or altering prior ID semantics.
                AssetKind::DetailedProtocol {
                    metadata: ProtocolMetadata {
                        family: family.clone(),
                        version: Observed::Unknown,
                        state: match state {
                            ProtocolState::Configured => ProtocolObservation::Configured,
                            ProtocolState::Negotiated => ProtocolObservation::Negotiated,
                        },
                        role: Observed::Unknown,
                        cryptographic_profile: Observed::Unknown,
                    },
                }
            };
            let asset = builder.ingest_candidate(asset_kind, &context, BTreeMap::new())?;
            observe(
                builder,
                raw,
                &asset,
                evidence,
                "protocol:observed-state",
                format!("{state:?}"),
            )?;
            observe(
                builder,
                raw,
                &asset,
                evidence,
                "protocol:family",
                family.clone(),
            )?;
            if let Some(version) = version {
                observe(
                    builder,
                    raw,
                    &asset,
                    evidence,
                    "protocol:version",
                    version.clone(),
                )?;
            } else {
                observe(
                    builder,
                    raw,
                    &asset,
                    evidence,
                    "protocol:version-availability",
                    "unknown".into(),
                )?;
            }
            asset
        }
        RawFactKind::Configuration { property, value } => {
            // Never convert a declared configuration value into algorithm
            // execution. Reject sensitive properties rather than persisting
            // secret-bearing configuration via the observation model.
            nonsecret_configuration(property)?;
            let asset = builder.ingest_candidate(
                AssetKind::SourceUse {
                    source: format!("{:?}:{}", raw.source.kind, raw.source.item),
                    location: source_site(raw)?,
                },
                identity,
                BTreeMap::new(),
            )?;
            observe(builder, raw, &asset, evidence, property, value.clone())?;
            asset
        }
    };
    Ok(asset)
}

/// Validate a collector outcome, resolve supported facts and produce a canonical snapshot.
///
/// Inputs and replay identity are checked before insertion. No unapproved path
/// or endpoint is opened by this stage. A failed/partial source never implies
/// the absence of cryptography.
pub fn normalize(
    input: PipelineInput<'_>,
    outcome: CollectionOutcome,
) -> Result<InventorySnapshot, PipelineError> {
    if input.identity.scope != input.scope.id().as_str()
        || outcome.run != *input.expected_run
        || outcome.descriptor != *input.expected_descriptor
    {
        return Err(PipelineError::InvalidOutcome);
    }
    input.raw_limits.validate()?;
    let request = CollectionRequest {
        run: input.expected_run.clone(),
        sources: input.sources.to_vec(),
        limits: input.raw_limits,
        options: BTreeMap::new(),
    };
    request.validate(input.expected_descriptor)?;
    input.scope.validate_request(&request)?;
    let requested: BTreeSet<String> = request.sources.iter().map(|s| s.item.clone()).collect();
    if outcome.coverage.keys().cloned().collect::<BTreeSet<_>>() != requested
        || outcome.observations.len() > input.raw_limits.observations
        || outcome.diagnostics.len()
            > input
                .raw_limits
                .observations
                .saturating_add(requested.len())
    {
        return Err(PipelineError::InvalidOutcome);
    }
    for diag in &outcome.diagnostics {
        if diag
            .source_item
            .as_ref()
            .is_some_and(|item| !requested.contains(item))
        {
            return Err(PipelineError::InvalidOutcome);
        }
    }
    let mut records = BTreeMap::new();
    let mut total_bytes = 0usize;
    for raw in outcome.observations {
        let bytes = raw.validate(&input.raw_limits)?;
        total_bytes = total_bytes
            .checked_add(bytes)
            .ok_or(InventoryError::LimitExceeded("raw bytes overflow"))?;
        if total_bytes > input.raw_limits.total_bytes
            || raw.run != outcome.run
            || raw.collector != outcome.descriptor.id
            || raw.collector_version != outcome.descriptor.version
            || !request
                .sources
                .iter()
                .any(|s| s.item == raw.source.item && s.kind == raw.source.kind)
        {
            return Err(PipelineError::InvalidOutcome);
        }
        match records.insert(raw.event_id.clone(), raw.clone()) {
            Some(existing) if existing != raw => {
                return Err(PipelineError::Inventory(
                    InventoryError::DuplicateObservation(raw.event_id),
                ));
            }
            _ => {}
        }
    }
    let observed: BTreeSet<&str> = records
        .values()
        .map(|raw| raw.source.item.as_str())
        .collect();
    for (source, state) in &outcome.coverage {
        let has_observations = observed.contains(source.as_str());
        // A partially inspected source may emit useful evidence, but must
        // remain Partial rather than claiming the source is fully covered.
        // Failed, unsupported and uninspected sources must never emit facts.
        if (matches!(state, CoverageState::InspectedObserved) && !has_observations)
            || (has_observations
                && !matches!(
                    state,
                    CoverageState::InspectedObserved | CoverageState::Partial
                ))
        {
            return Err(PipelineError::InvalidOutcome);
        }
    }
    let succeeded = outcome
        .coverage
        .values()
        .filter(|v| {
            matches!(
                v,
                CoverageState::InspectedObserved | CoverageState::InspectedNoObservation
            )
        })
        .count();
    let actual_status = if succeeded == requested.len() {
        CollectionStatus::Complete
    } else if succeeded > 0 {
        CollectionStatus::Partial
    } else {
        CollectionStatus::Failed
    };
    if actual_status != outcome.status {
        return Err(PipelineError::InvalidOutcome);
    }
    let completeness = match actual_status {
        CollectionStatus::Complete => RunCompleteness::Complete,
        CollectionStatus::Partial => RunCompleteness::Partial,
        CollectionStatus::Failed => RunCompleteness::Failed,
    };
    let mut builder = InventoryBuilder::new();
    builder.add_run(CollectionRun {
        id: outcome.run.clone(),
        collector: outcome.descriptor.id.clone(),
        collector_version: outcome.descriptor.version,
        scope: input.scope.id().clone(),
        requested,
        started_at: input.started_at.to_owned(),
        ended_at: input.ended_at.to_owned(),
        completeness,
    })?;
    for (source, state) in outcome.coverage {
        builder.add_coverage_record(CoverageRecord {
            run: outcome.run.clone(),
            source_item: source.clone(),
            state,
            reason_code: match state {
                CoverageState::Failed => Some("collection:failed".into()),
                CoverageState::Partial => Some("collection:partial".into()),
                CoverageState::Unsupported => Some("collection:unsupported".into()),
                CoverageState::NotInspected => Some("collection:not-inspected".into()),
                _ => None,
            },
        });
        builder.set_coverage(source, state);
    }
    let mut mapped_assets = BTreeMap::new();
    let mut mapped_evidence = BTreeMap::new();
    for raw in records.values() {
        let evidence = evidence_for(raw)?;
        let asset = map_fact(
            &mut builder,
            raw,
            input.identity,
            input.registry,
            &evidence.id,
        )?;
        mapped_assets.insert(raw.event_id.clone(), asset);
        mapped_evidence.insert(raw.event_id.clone(), evidence.id.clone());
        builder.add_evidence(evidence)?;
    }
    // Second pass: only events that passed host authorization and normalization
    // are addressable. Never synthesize edges from co-located or similar values.
    crate::correlation::link_explicit(&mut builder, &records, &mapped_assets, &mapped_evidence)?;
    Ok(builder.finalize(input.inventory_limits)?)
}
