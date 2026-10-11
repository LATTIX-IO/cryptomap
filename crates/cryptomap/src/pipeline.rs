//! Bounded, deterministic raw-to-canonical collection pipeline.
//!
//! The host supplies an already-authorized CollectionScope and exact requested
//! source list. This first increment maps algorithm-use and dependency facts;
//! unsupported raw categories fail closed rather than disappearing.
use crate::{
    AssetId, AssetKind, CollectionRunId, CoverageState, Evidence, EvidenceId, IdentityContext,
    InventoryBuilder, InventoryError, InventoryLimits, InventorySnapshot, Observation,
    ObservationId,
    collector::{
        CollectionOutcome, CollectionRequest, CollectionStatus, CollectorDescriptor,
        RequestedSource,
    },
    coverage::{CollectionRun, CoverageRecord, RunCompleteness},
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
#[derive(Debug)]
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
) -> Result<(), PipelineError> {
    match &raw.fact {
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
            // Serialize a typed tuple so source colons and absent versus zero
            // offsets cannot collapse distinct use sites into one asset.
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
            let use_site = format!("use-site:v1:{:x}", Sha256::digest(location));
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
        }
        _ => return Err(PipelineError::UnsupportedFact),
    }
    Ok(())
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
        if (matches!(state, CoverageState::InspectedObserved) && !has_observations)
            || (has_observations && !matches!(state, CoverageState::InspectedObserved))
            || (matches!(state, CoverageState::InspectedNoObservation) && has_observations)
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
    for raw in records.values() {
        let evidence = evidence_for(raw)?;
        map_fact(
            &mut builder,
            raw,
            input.identity,
            input.registry,
            &evidence.id,
        )?;
        builder.add_evidence(evidence)?;
    }
    Ok(builder.finalize(input.inventory_limits)?)
}
