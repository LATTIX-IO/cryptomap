//! Host-pinned execution of trusted collectors through one canonical pipeline.
//!
//! This is orchestration, not a second normalizer or a source capability.
//! In-process collectors can still call ambient OS APIs; sandbox untrusted code.
use crate::{
    InventoryError, InventorySnapshot,
    batch::{BatchLimits, BatchRun, normalize_batch},
    collector::{CancellationToken, CollectionRequest, Collector},
    pipeline::{PipelineError, PipelineInput, normalize},
    scope::{collect_scoped, collect_scoped_isolated},
};
use std::collections::BTreeSet;

/// One trusted host invocation, including the independently pinned collector
/// identity, run, exact authorized sources, scope and canonical identity.
pub struct ScopedInvocation<'a> {
    /// Trusted in-process collector implementation (untrusted plugins require OS isolation).
    pub collector: &'a dyn Collector,
    /// Host-pinned canonical collection context; not supplied by the collector.
    pub input: PipelineInput<'a>,
}

fn preflight(invocation: &ScopedInvocation<'_>) -> Result<CollectionRequest, PipelineError> {
    let input = &invocation.input;
    // Check host inputs before invoking Collector::collect. Descriptor() is
    // still trusted in-process plugin code, not an OS security boundary.
    // It cannot replace the independently pinned expected descriptor.
    if input.identity.scope != input.scope.id().as_str()
        || invocation.collector.descriptor() != *input.expected_descriptor
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
    crate::scope::validate_collector_binding(input.scope, invocation.collector)?;
    input.scope.validate_request(&request)?;
    Ok(request)
}

/// Execute one host-authorized collector and immediately normalize its outcome.
///
/// Validation of collector identity, exact source grants and budgets occurs
/// before the collector is invoked. The existing sink verifies emitted records
/// and the existing pipeline independently validates the terminal result.
pub fn collect_normalized(
    invocation: ScopedInvocation<'_>,
    cancel: &CancellationToken,
) -> Result<InventorySnapshot, PipelineError> {
    let request = preflight(&invocation)?;
    let outcome = collect_scoped(
        invocation.input.scope,
        invocation.collector,
        request,
        cancel,
    )?;
    normalize(invocation.input, outcome)
}

/// Execute an authorized collector and authenticate each opt-in identity
/// receipt using the caller-held authority before canonical promotion.
#[cfg(feature = "certificate-identity")]
pub fn collect_normalized_with_identity(
    invocation: ScopedInvocation<'_>,
    authority: &crate::certificate_identity::CertificateIdentityAuthority,
    cancel: &CancellationToken,
) -> Result<InventorySnapshot, PipelineError> {
    authority
        .check_scope(invocation.input.scope.id())
        .map_err(|_| PipelineError::InvalidOutcome)?;
    let request = preflight(&invocation)?;
    let outcome = collect_scoped(
        invocation.input.scope,
        invocation.collector,
        request,
        cancel,
    )?;
    crate::pipeline::normalize_with_identity(invocation.input, outcome, authority)
}

/// Execute one authorized, cooperative collector with independent source failures.
///
/// The complete host-pinned request, scope and descriptor are validated before
/// **any** call. A source-local collector error becomes explicit failed coverage
/// while independent successful observations survive canonical normalization.
/// Rejected sink writes, forged events and aggregate budgets still abort.
/// This is not a sandbox or a compatibility guarantee for stateful collectors.
pub fn collect_normalized_isolated(
    invocation: ScopedInvocation<'_>,
    cancel: &CancellationToken,
) -> Result<InventorySnapshot, PipelineError> {
    let request = preflight(&invocation)?;
    let outcome = collect_scoped_isolated(
        invocation.input.scope,
        invocation.collector,
        request,
        cancel,
    )?;
    normalize(invocation.input, outcome)
}

fn preflight_batch(
    invocations: &[ScopedInvocation<'_>],
    limits: BatchLimits,
) -> Result<(), PipelineError> {
    limits.validate()?;
    if invocations.is_empty()
        || invocations.len() > limits.runs
        || invocations.len() > limits.inventory.runs
    {
        return Err(InventoryError::LimitExceeded("batch runs").into());
    }
    let expected_scope = invocations[0].input.scope.id().clone();
    let mut unique_runs = BTreeSet::new();
    let mut source_count = 0_usize;
    // Do not call collectors until ALL independent invocations are trusted.
    for invocation in invocations.iter() {
        preflight(invocation)?;
        if invocation.input.scope.id() != &expected_scope
            || !unique_runs.insert(invocation.input.expected_run.clone())
        {
            return Err(PipelineError::InvalidOutcome);
        }
        source_count = source_count
            .checked_add(invocation.input.sources.len())
            .ok_or(InventoryError::LimitExceeded("batch sources"))?;
        if source_count > limits.sources {
            return Err(InventoryError::LimitExceeded("batch sources").into());
        }
    }
    Ok(())
}

/// Execute heterogeneous authorized collectors and deterministically reconcile.
///
/// Preflight is **all-or-nothing**: a bad tenant, run, descriptor, source or
/// aggregate run/source budget prevents execution of *any* collector. Raw
/// observation and byte caps are independently enforced by the existing
/// per-run sinks and `normalize_batch` before canonical aggregation.
///
/// A valid Failed/Partial collector outcome remains evidence, not an
/// authorization or normalization error. If a collector returns a fatal
/// error, the function fails without producing a partial canonical snapshot.
pub fn collect_normalized_batch(
    mut invocations: Vec<ScopedInvocation<'_>>,
    limits: BatchLimits,
    cancel: &CancellationToken,
) -> Result<InventorySnapshot, PipelineError> {
    preflight_batch(&invocations, limits)?;
    invocations.sort_by(|a, b| a.input.expected_run.cmp(b.input.expected_run));
    let mut normalized_inputs = Vec::with_capacity(invocations.len());
    for invocation in invocations {
        let request = CollectionRequest {
            run: invocation.input.expected_run.clone(),
            sources: invocation.input.sources.to_vec(),
            limits: invocation.input.raw_limits,
            options: Default::default(),
        };
        let outcome = collect_scoped(
            invocation.input.scope,
            invocation.collector,
            request,
            cancel,
        )?;
        normalized_inputs.push(BatchRun {
            input: invocation.input,
            outcome,
        });
    }
    normalize_batch(normalized_inputs, limits)
}

/// Perform a heterogeneous authorized collection batch and correlate issuer
/// *candidates* using the same host-owned B5.5 scope-bound key.
///
/// All invocation grants and the common scope are checked BEFORE invoking
/// the first collector. Per-run normalization authenticates original record
/// receipts before the candidate graph is built. No ambient stores or AIA
/// network discovery are performed by this orchestration layer.
#[cfg(feature = "certificate-identity")]
pub fn collect_normalized_batch_with_identity(
    mut invocations: Vec<ScopedInvocation<'_>>,
    limits: BatchLimits,
    authority: &crate::certificate_identity::CertificateIdentityAuthority,
    cancel: &CancellationToken,
) -> Result<InventorySnapshot, PipelineError> {
    preflight_batch(&invocations, limits)?;
    authority
        .check_scope(invocations[0].input.scope.id())
        .map_err(|_| PipelineError::InvalidOutcome)?;
    invocations.sort_by(|a, b| a.input.expected_run.cmp(b.input.expected_run));
    let mut normalized_inputs = Vec::with_capacity(invocations.len());
    for invocation in invocations {
        let request = CollectionRequest {
            run: invocation.input.expected_run.clone(),
            sources: invocation.input.sources.to_vec(),
            limits: invocation.input.raw_limits,
            options: Default::default(),
        };
        let outcome = collect_scoped(
            invocation.input.scope,
            invocation.collector,
            request,
            cancel,
        )?;
        normalized_inputs.push(BatchRun {
            input: invocation.input,
            outcome,
        });
    }
    crate::batch::normalize_batch_with_identity(normalized_inputs, limits, authority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::ScopeError;

    #[test]
    fn empty_batch_fails_bounded_preflight() {
        assert!(matches!(
            collect_normalized_batch(
                Vec::new(),
                BatchLimits::default(),
                &CancellationToken::default()
            ),
            Err(PipelineError::Inventory(InventoryError::LimitExceeded(
                "batch runs"
            )))
        ));
    }

    #[test]
    fn nested_inventory_error_never_exposes_untrusted_event_identity() {
        let event = "private:customer:record-id";
        let error = PipelineError::Scope(ScopeError::Collection(
            InventoryError::DuplicateObservation(event.into()),
        ));
        assert!(!format!("{error:?}").contains(event));
        assert!(!error.to_string().contains(event));
    }
}
