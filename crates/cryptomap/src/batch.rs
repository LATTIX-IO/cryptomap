//! Deterministic, bounded reconciliation of independently authorized collection runs.
//!
//! Every collector is first normalized through the existing host-pinned pipeline;
//! this module cannot inspect a source or synthesize cross-run relationships.
use crate::{
    CollectionRunId, InventoryBuilder, InventoryError, InventoryLimits, InventorySnapshot,
    collector::{CollectionOutcome, CollectionRequest},
    pipeline::{PipelineError, PipelineInput, normalize},
};
use sha2::{Digest, Sha256};
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

/// Stable legacy coverage key for the tuple (run, source).
///
/// The authoritative human-readable record is always `CoverageRecord`.
/// Hashing the JSON tuple prevents separators in user-supplied source labels
/// from conflating distinct run/source pairs.
fn coverage_key(run: &CollectionRunId, source: &str) -> Result<String, InventoryError> {
    let data = serde_json::to_vec(&("cryptomap:batch-coverage:v1", run, source))
        .map_err(|_| InventoryError::InvalidMetadata)?;
    Ok(format!("batch-source:v1:{:x}", Sha256::digest(data)))
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
    for run in &runs {
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
    let mut builder = InventoryBuilder::new();
    for run in runs {
        let snapshot = normalize(run.input, run.outcome)?;
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
        // A source label may be reused by different collectors. Only the
        // authoritative (run, source) coverage record identifies its outcome.
        for record in snapshot.coverage_records {
            builder.set_coverage(
                coverage_key(&record.run, &record.source_item)?,
                record.state,
            );
            builder.add_coverage_record(record);
        }
    }
    Ok(builder.finalize(limits.inventory)?)
}
