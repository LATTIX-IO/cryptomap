//! Deterministic, bounded reconciliation of independently authorized collection runs.
//!
//! Every collector is first normalized through the existing host-pinned pipeline;
//! this module never acquires source access. Keyed issuer-candidate federation
//! requires the same host-owned authority for every independently normalized run.
use crate::{
    InventoryBuilder, InventoryError, InventoryLimits, InventorySnapshot,
    collector::{CollectionOutcome, CollectionRequest},
    pipeline::{PipelineError, PipelineInput, normalize},
};
use std::collections::BTreeSet;

/// One already-collected result and its independent, trusted host authority.
pub struct BatchRun<'a> {
    /// Host authorization, pinned collector identity, request and normalization context.
    pub input: PipelineInput<'a>,
    /// Potentially untrusted, unnormalized collector outcome.
    pub outcome: CollectionOutcome,
}

/// Independent aggregate limits enforced before per-run normalization.
#[derive(Debug, Clone, Copy)]
pub struct BatchLimits {
    /// Maximum run count in one batch.
    pub runs: usize,
    /// Maximum total requested source entries across all runs.
    pub sources: usize,
    /// Maximum raw observation entries across all runs.
    pub observations: usize,
    /// Maximum serialized raw observation bytes across all runs.
    pub raw_bytes: usize,
    /// Canonical final snapshot quotas (assets, relationships, runs and bytes).
    pub inventory: InventoryLimits,
}

impl Default for BatchLimits {
    fn default() -> Self {
        Self {
            runs: 100,
            sources: 10_000,
            observations: 100_000,
            raw_bytes: 64 * 1024 * 1024,
            inventory: InventoryLimits::default(),
        }
    }
}

impl BatchLimits {
    /// Reject disabled aggregate budget boundaries.
    pub fn validate(&self) -> Result<(), InventoryError> {
        if self.runs == 0
            || self.sources == 0
            || self.observations == 0
            || self.raw_bytes == 0
            || self.inventory.runs == 0
            || self.inventory.snapshot_bytes == 0
        {
            return Err(InventoryError::InvalidMetadata);
        }
        Ok(())
    }
}

fn charge(
    total: &mut usize,
    count: usize,
    maximum: usize,
    label: &'static str,
) -> Result<(), PipelineError> {
    *total = total
        .checked_add(count)
        .ok_or(InventoryError::LimitExceeded(label))?;
    if *total > maximum {
        return Err(InventoryError::LimitExceeded(label).into());
    }
    Ok(())
}

fn absorb_snapshot(
    builder: &mut InventoryBuilder,
    snapshot: InventorySnapshot,
) -> Result<(), PipelineError> {
    for item in snapshot.runs.into_values() {
        builder.add_run(item)?;
    }
    for asset in snapshot.assets.into_values() {
        builder.add_asset(asset)?;
    }
    for evidence in snapshot.evidence.into_values() {
        builder.add_evidence(evidence)?;
    }
    for observation in snapshot.observations.into_values() {
        builder.add_observation(observation)?;
    }
    for relationship in snapshot.relationships.into_values() {
        builder.add_relationship(relationship)?;
    }
    // Batch snapshots use only typed coverage. Writing synthetic legacy
    // entries keyed by ephemeral run IDs would make otherwise identical
    // reinspection batches appear to change coverage in snapshot diffs.
    // Typed records retain exact (run, source) provenance while the diff
    // projects stable (scope, collector, source) identities.
    for record in snapshot.coverage_records {
        builder.add_coverage_record(record);
    }
    Ok(())
}

fn check_batch<'a>(runs: &mut Vec<BatchRun<'a>>, limits: BatchLimits) -> Result<(), PipelineError> {
    limits.validate()?;
    if runs.is_empty() || runs.len() > limits.runs || runs.len() > limits.inventory.runs {
        return Err(InventoryError::LimitExceeded("batch runs").into());
    }
    // First pass: every run must be independently pinned and authorized before
    // reading any untrusted raw source data or constructing a canonical asset.
    let administrative_scope = runs[0].input.scope.id().clone();
    let mut run_ids = BTreeSet::new();
    let mut total_sources = 0;
    let mut total_records = 0;
    let mut total_bytes = 0;
    for run in runs.iter() {
        let input = &run.input;
        if input.scope.id() != &administrative_scope
            || input.identity.scope != administrative_scope.as_str()
            || run.outcome.run != *input.expected_run
            || run.outcome.descriptor != *input.expected_descriptor
            || !run_ids.insert(input.expected_run.clone())
        {
            return Err(PipelineError::InvalidOutcome);
        }
        let request = CollectionRequest {
            run: input.expected_run.clone(),
            sources: input.sources.to_vec(),
            limits: input.raw_limits,
            options: Default::default(),
        };
        request.validate(input.expected_descriptor)?;
        input.scope.validate_request(&request)?;
        charge(
            &mut total_sources,
            input.sources.len(),
            limits.sources,
            "batch sources",
        )?;
        charge(
            &mut total_records,
            run.outcome.observations.len(),
            limits.observations,
            "batch observations",
        )?;
        for raw in &run.outcome.observations {
            let bytes = raw.validate(&input.raw_limits)?;
            charge(&mut total_bytes, bytes, limits.raw_bytes, "batch raw bytes")?;
        }
    }
    // Order by independent host-pinned run IDs, not collector completion or
    // caller input order. Reject duplicate run IDs, even across collectors.
    runs.sort_by(|left, right| left.input.expected_run.cmp(right.input.expected_run));
    Ok(())
}

/// Normalize independently trusted collector outcomes and reconcile the resulting
/// canonical assets, evidence, relations and per-run coverage deterministically.
///
/// Fail-closed structural failures reject the whole batch. A *valid* failed or
/// partially complete collection outcome is retained alongside successful runs;
/// it does not erase previously observed evidence.
pub fn normalize_batch(
    mut runs: Vec<BatchRun<'_>>,
    limits: BatchLimits,
) -> Result<InventorySnapshot, PipelineError> {
    check_batch(&mut runs, limits)?;
    let mut builder = InventoryBuilder::new();
    for run in runs {
        let snapshot = normalize(run.input, run.outcome)?;
        absorb_snapshot(&mut builder, snapshot)?;
    }
    Ok(builder.finalize(limits.inventory)?)
}

// Comparability of independent collection windows is *not* certificate
// validity or path validation. Disjoint windows make issuer candidates
// temporally ambiguous; retain possible edges but mark coverage Partial.
#[cfg(feature = "certificate-identity")]
fn intersect_collection_windows(
    common: &mut Option<(crate::validation::UtcInstant, crate::validation::UtcInstant)>,
    start: &str,
    end: &str,
) -> Result<bool, InventoryError> {
    let start = crate::validation::utc_instant(start)?;
    let end = crate::validation::utc_instant(end)?;
    if start > end {
        return Err(InventoryError::InvalidTimestamp);
    }
    let next = common
        .map(|(latest, earliest)| (latest.max(start), earliest.min(end)))
        .unwrap_or((start, end));
    *common = Some(next);
    Ok(next.0 <= next.1)
}

/// Normalize a bounded collection batch using the *same* host-owned B5.5
/// authority for every run, then correlate X.509 issuer candidates across runs.
///
/// All run IDs, collector descriptors, source grants, event times and HMAC
/// receipts are revalidated against their independently pinned host input.
/// No imported snapshot or pseudonym-shape-only hint can authorize a join.
/// Inferred relationships are candidate-only; no signature or trust decision.
#[cfg(feature = "certificate-identity")]
pub fn normalize_batch_with_identity(
    mut runs: Vec<BatchRun<'_>>,
    limits: BatchLimits,
    authority: &crate::certificate_identity::CertificateIdentityAuthority,
) -> Result<InventorySnapshot, PipelineError> {
    use crate::{
        AssetId, AssetKind, EvidenceId,
        certificate_identity::IdentityError,
        issuer_candidates::{CandidateInput, CandidateLimits, link_issuer_candidates},
        pipeline::{evidence_for, normalize_with_identity_without_candidates},
        raw::{RawFactKind, RawLimits, RawObservation},
    };
    use std::collections::BTreeMap;

    check_batch(&mut runs, limits)?;
    authority
        .check_scope(runs[0].input.scope.id())
        .map_err(|_: IdentityError| PipelineError::InvalidOutcome)?;

    let candidates_limit = CandidateLimits::default();
    let mut builder = InventoryBuilder::new();
    let mut records: BTreeMap<String, RawObservation> = BTreeMap::new();
    let mut assets: BTreeMap<String, AssetId> = BTreeMap::new();
    let mut evidence: BTreeMap<String, EvidenceId> = BTreeMap::new();
    let mut complete = true;
    let mut common_window = None;
    let mut candidate_records = 0usize;
    let mut over_budget = false;

    for run in runs {
        let run_id = run.input.expected_run.clone();
        // Host-granted source/run identity remains borrowed only by the
        // current normalizer; never reconstruct it from an imported snapshot.
        let eligible = run
            .outcome
            .observations
            .iter()
            .filter(|raw| matches!(raw.fact, RawFactKind::Certificate { .. }));
        let mut raw_certificates = Vec::new();
        for raw in eligible {
            candidate_records = candidate_records
                .checked_add(1)
                .ok_or(InventoryError::LimitExceeded("candidate record count"))?;
            if candidate_records <= candidates_limit.certificates {
                raw_certificates.push(raw.clone());
            } else {
                over_budget = true;
            }
        }
        let snapshot =
            normalize_with_identity_without_candidates(run.input, run.outcome, authority)?;
        let metadata = snapshot
            .runs
            .get(&run_id)
            .ok_or(PipelineError::InvalidOutcome)?;
        complete &= matches!(
            metadata.completeness,
            crate::coverage::RunCompleteness::Complete
        );
        complete &= intersect_collection_windows(
            &mut common_window,
            &metadata.started_at,
            &metadata.ended_at,
        )?;

        if !over_budget {
            // Derive the *canonical* ID from the actual normalized evidence
            // and fingerprint observation, not a guessed filename or token.
            let mut mapped = BTreeMap::new();
            for observation in snapshot.observations.values() {
                if observation.property == "certificate:fingerprint-sha256"
                    && mapped
                        .insert(
                            observation.evidence.clone(),
                            (observation.asset.clone(), observation.value.clone()),
                        )
                        .is_some()
                {
                    return Err(PipelineError::InvalidOutcome);
                }
            }
            for raw in raw_certificates {
                // B5.5 is opt-in per collector. Unknown/unkeyed input is
                // retained as partial candidate coverage, not a forged token.
                // The normalizer has already authenticated every supplied
                // identity-bearing attribute; repeat verification here only
                // for records that actually carry those attributes.
                if raw
                    .attributes
                    .keys()
                    .any(|key| key.starts_with("x509:identity:"))
                    && !authority.verify_record(&raw)
                {
                    return Err(PipelineError::InvalidOutcome);
                }
                let RawFactKind::Certificate { fingerprint_sha256 } = &raw.fact else {
                    return Err(PipelineError::InvalidOutcome);
                };
                let direct_id = evidence_for(&raw)?.id;
                let (asset, observed_fingerprint) = mapped
                    .get(&direct_id)
                    .ok_or(PipelineError::InvalidOutcome)?;
                let expected_fingerprint = fingerprint_sha256.to_ascii_lowercase();
                if observed_fingerprint != &expected_fingerprint
                    || !matches!(
                        snapshot.assets.get(asset).map(|a| &a.kind),
                        Some(AssetKind::Certificate {
                            fingerprint_sha256: digest,
                            ..
                        }) if digest == &expected_fingerprint
                    )
                {
                    return Err(PipelineError::InvalidOutcome);
                }
                // Length-prefix the run so arbitrary event identifiers cannot
                // alias across runs. Raw event IDs remain unchanged for MACs.
                let event_key = format!(
                    "{}:{}:{}",
                    run_id.as_str().len(),
                    run_id.as_str(),
                    raw.event_id
                );
                if records.insert(event_key.clone(), raw).is_some()
                    || assets.insert(event_key.clone(), asset.clone()).is_some()
                    || evidence.insert(event_key, direct_id).is_some()
                {
                    return Err(PipelineError::InvalidOutcome);
                }
            }
        }
        absorb_snapshot(&mut builder, snapshot)?;
    }

    if over_budget {
        // Do not emit a misleading candidate subgraph for only the first
        // arbitrarily chosen N of a larger authorized batch.
        builder.set_coverage(
            "x509:issuer-candidate:v1:batch",
            crate::CoverageState::Partial,
        );
    } else {
        link_issuer_candidates(
            &mut builder,
            CandidateInput {
                records: &records,
                assets: &assets,
                evidence: &evidence,
                authority,
                raw_limits: RawLimits {
                    observations: limits.observations,
                    ..RawLimits::default()
                },
                inventory_limits: limits.inventory,
                limits: candidates_limit,
                collection_complete: complete,
                coverage_label: "batch",
            },
        )?;
    }
    Ok(builder.finalize(limits.inventory)?)
}

#[cfg(all(test, feature = "certificate-identity"))]
#[allow(clippy::unwrap_used)]
mod issuer_batch_window_tests {
    use super::*;

    #[test]
    fn windows_require_a_real_utc_intersection_not_similar_strings() {
        let mut common = None;
        assert!(
            intersect_collection_windows(
                &mut common,
                "2026-10-18T12:00:00Z",
                "2026-10-18T12:01:00Z",
            )
            .unwrap()
        );
        assert!(
            intersect_collection_windows(
                &mut common,
                "2026-10-18T08:00:30-04:00",
                "2026-10-18T12:00:45Z",
            )
            .unwrap()
        );
        assert!(
            !intersect_collection_windows(
                &mut common,
                "2026-10-18T12:02:00Z",
                "2026-10-18T12:03:00Z",
            )
            .unwrap()
        );
        let mut bad = None;
        assert!(
            intersect_collection_windows(&mut bad, "2026-10-18T12:00:01Z", "2026-10-18T12:00:00Z")
                .is_err()
        );
    }
}
