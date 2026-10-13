//! Pure Rust collector extension boundary; no implicit I/O, runtime or permission grants.
//!
//! Implementors must inspect only exact items in the request. The sink independently
//! verifies submitted evidence identity and resource budgets, but FOSS-319 will
//! provide operating-system-enforced filesystem/network authorization.
use crate::{
    CollectionRunId, CollectorId, CoverageState, InventoryError,
    raw::{RawLimits, RawObservation, RawSourceKind},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Current public collector descriptor contract version.
pub const COLLECTOR_CONTRACT_VERSION: u32 = 1;

/// Passive sources do not actively connect to a network endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectionMode {
    /// Read only caller-provided files, data or authorized stores.
    Passive,
    /// Initiate an explicit network connection (requires host authorization).
    Active,
}

/// Versioned advertised abilities, not an authorization token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorCapabilities {
    /// Supported source families.
    pub sources: BTreeSet<RawSourceKind>,
    /// Whether network activity is required.
    pub mode: CollectionMode,
    /// Declared permission tags for the caller to enforce.
    pub required_permissions: BTreeSet<String>,
    /// Whether validated incremental checkpoints are supported.
    pub checkpoint: bool,
}

/// Identity and behavior of an independent collector implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorDescriptor {
    /// Descriptor API version.
    pub contract_version: u32,
    /// Globally identifiable collector name.
    pub id: CollectorId,
    /// Release version.
    pub version: String,
    /// What sources this implementation can inspect.
    pub capabilities: CollectorCapabilities,
}

impl CollectorDescriptor {
    /// Check bounded descriptor fields and supported version.
    pub fn validate(&self) -> Result<(), InventoryError> {
        if self.contract_version != COLLECTOR_CONTRACT_VERSION {
            return Err(InventoryError::UnsupportedSchema(self.contract_version));
        }
        if self.version.is_empty() || self.capabilities.sources.is_empty() {
            return Err(InventoryError::InvalidMetadata);
        }
        crate::validation::safe_text(&self.version, 128)?;
        for permission in &self.capabilities.required_permissions {
            crate::validation::safe_text(permission, 128)?;
        }
        Ok(())
    }
}

/// Exact source-item request, with no implicit globbing or target expansion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedSource {
    /// Source kind, must be declared by the collector.
    pub kind: RawSourceKind,
    /// Exact scope item identifier.
    pub item: String,
}

/// Deliberately bounded, already-authorized collection invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionRequest {
    /// Invocation ID associated with returned observations.
    pub run: CollectionRunId,
    /// Exactly authorized source items; FOSS-319 adds OS-level permission enforcement.
    pub sources: Vec<RequestedSource>,
    /// Resource limits for the current invocation.
    pub limits: RawLimits,
    /// Caller-supplied configuration, never implicitly interpreted as extra targets.
    pub options: BTreeMap<String, String>,
}

impl CollectionRequest {
    /// Validate a request against declared collector capabilities.
    pub fn validate(&self, descriptor: &CollectorDescriptor) -> Result<(), InventoryError> {
        descriptor.validate()?;
        self.limits.validate()?;
        if self.sources.is_empty() || self.sources.len() > self.limits.sources {
            return Err(InventoryError::InvalidMetadata);
        }
        let mut unique = BTreeSet::new();
        for src in &self.sources {
            if src.item.is_empty()
                || src.item.trim() != src.item
                || !descriptor.capabilities.sources.contains(&src.kind)
            {
                return Err(InventoryError::InvalidMetadata);
            }
            crate::validation::safe_text(&src.item, self.limits.field_bytes)?;
            // Coverage is keyed by item, so different kinds may not reuse the same name.
            if !unique.insert(src.item.clone()) {
                return Err(InventoryError::InvalidMetadata);
            }
        }
        for (key, value) in &self.options {
            crate::validation::safe_text(key, 128)?;
            crate::validation::safe_text(value, self.limits.field_bytes)?;
        }
        Ok(())
    }
}

/// Terminal status of attempted source inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectionStatus {
    /// Every requested source received an inspection outcome.
    Complete,
    /// Some sources were inspected, others were not or failed.
    Partial,
    /// No requested source completed inspection.
    Failed,
}

/// Typed diagnostic categories (not unbounded raw error strings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectorDiagnosticCode {
    /// Unsupported requested source or option.
    UnsupportedSource,
    /// Access denied by caller/source permissions.
    PermissionDenied,
    /// Source or collector timed out.
    Timeout,
    /// Malformed, unsupported or truncated source input.
    MalformedSource,
    /// Resource boundary exceeded.
    ResourceLimit,
    /// Source was only partially inspected.
    IncompleteScope,
    /// A duplicate ID contained different observation facts.
    ConflictingReplay,
    /// Caller interrupted collection.
    Cancelled,
    /// Failed collector result validation.
    InvalidObservation,
}

/// Bounded source-specific diagnostic without raw secret-bearing error output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorDiagnostic {
    /// Typed diagnostic code.
    pub code: CollectorDiagnosticCode,
    /// Exact requested source item, when applicable.
    pub source_item: Option<String>,
}

/// An immutable end-of-run representation; not a canonical snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionOutcome {
    /// Collector descriptor that produced the result.
    pub descriptor: CollectorDescriptor,
    /// Run identity.
    pub run: CollectionRunId,
    /// Raw facts; a later normalizer MUST validate before canonical insertion.
    pub observations: Vec<RawObservation>,
    /// Per-requested-item collection outcome.
    pub coverage: BTreeMap<String, CoverageState>,
    /// Typed diagnostics without raw source content.
    pub diagnostics: Vec<CollectorDiagnostic>,
    /// Derived completion state.
    pub status: CollectionStatus,
}

/// Cancellation handle that works without choosing a particular async runtime.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Request cancellation from another thread or host runtime.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    /// Check the current cancellation flag.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// A bounded accumulator owned by the caller; never a grant to inspect sources.
#[derive(Debug)]
pub struct CollectionSink {
    descriptor: CollectorDescriptor,
    request: CollectionRequest,
    observations: BTreeMap<String, RawObservation>,
    coverage: BTreeMap<String, CoverageState>,
    diagnostics: Vec<CollectorDiagnostic>,
    total_bytes: usize,
    // Any rejected sink mutation is fatal in fault-isolated mode, even when
    // a cooperative plugin catches and ignores the returned error.
    rejected: bool,
}

impl CollectionSink {
    /// Create a sink that enforces collector declarations and exact scope IDs.
    pub fn new(
        descriptor: CollectorDescriptor,
        request: CollectionRequest,
    ) -> Result<Self, InventoryError> {
        request.validate(&descriptor)?;
        Ok(Self {
            descriptor,
            request,
            observations: BTreeMap::new(),
            coverage: BTreeMap::new(),
            diagnostics: Vec::new(),
            total_bytes: 0,
            rejected: false,
        })
    }

    /// Accept one independently checked raw observation.
    pub fn emit(&mut self, observation: RawObservation) -> Result<(), InventoryError> {
        let result = self.emit_checked(observation);
        self.rejected |= result.is_err();
        result
    }

    fn emit_checked(&mut self, observation: RawObservation) -> Result<(), InventoryError> {
        let size = observation.validate(&self.request.limits)?;
        if observation.run != self.request.run
            || observation.collector != self.descriptor.id
            || observation.collector_version != self.descriptor.version
            || !self
                .request
                .sources
                .iter()
                .any(|s| s.kind == observation.source.kind && s.item == observation.source.item)
        {
            return Err(InventoryError::InvalidMetadata);
        }
        // A source-level terminal coverage assertion seals that source.
        // A later event (including an exact replay) must not silently extend
        // an inspection that the collector already declared complete.
        if self.coverage.contains_key(&observation.source.item) {
            return Err(InventoryError::InvalidMetadata);
        }
        if let Some(existing) = self.observations.get(&observation.event_id) {
            return if existing == &observation {
                Ok(())
            } else {
                Err(InventoryError::DuplicateObservation(observation.event_id))
            };
        }
        if self.observations.len() >= self.request.limits.observations {
            return Err(InventoryError::LimitExceeded("raw observations"));
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(size)
            .ok_or(InventoryError::LimitExceeded("raw bytes overflow"))?;
        if self.total_bytes > self.request.limits.total_bytes {
            self.total_bytes -= size;
            return Err(InventoryError::LimitExceeded("raw total bytes"));
        }
        self.observations
            .insert(observation.event_id.clone(), observation);
        Ok(())
    }

    /// Record an exact source outcome, checking request membership.
    pub fn cover(&mut self, source: &str, state: CoverageState) -> Result<(), InventoryError> {
        let result = self.cover_checked(source, state);
        self.rejected |= result.is_err();
        result
    }

    fn cover_checked(&mut self, source: &str, state: CoverageState) -> Result<(), InventoryError> {
        if !self.request.sources.iter().any(|s| s.item == source) {
            return Err(InventoryError::InvalidMetadata);
        }
        if self.coverage.contains_key(source) {
            return Err(InventoryError::InvalidMetadata);
        }
        self.coverage.insert(source.to_owned(), state);
        Ok(())
    }

    /// Record a bounded diagnostic code for a requested source.
    pub fn diagnose(&mut self, diagnostic: CollectorDiagnostic) -> Result<(), InventoryError> {
        let result = self.diagnose_checked(diagnostic);
        self.rejected |= result.is_err();
        result
    }

    fn diagnose_checked(&mut self, diagnostic: CollectorDiagnostic) -> Result<(), InventoryError> {
        if let Some(source) = &diagnostic.source_item {
            if !self.request.sources.iter().any(|s| &s.item == source) {
                return Err(InventoryError::InvalidMetadata);
            }
        }
        if self.diagnostics.len()
            >= self
                .request
                .limits
                .observations
                .saturating_add(self.request.limits.sources)
        {
            return Err(InventoryError::LimitExceeded("raw diagnostics"));
        }
        self.diagnostics.push(diagnostic);
        Ok(())
    }

    /// Finalize preserving coverage for all requested sources, including unattempted.
    pub fn finish(mut self) -> CollectionOutcome {
        for requested in &self.request.sources {
            self.coverage
                .entry(requested.item.clone())
                .or_insert(CoverageState::NotInspected);
        }
        // Success coverage must match the evidence that was actually emitted.
        // Downgrade contradictory states rather than claiming complete inspection.
        for requested in &self.request.sources {
            let observed = self
                .observations
                .values()
                .any(|item| item.source.item == requested.item);
            if let Some(state) = self.coverage.get_mut(&requested.item) {
                let consistent = match state {
                    CoverageState::InspectedObserved => observed,
                    CoverageState::InspectedNoObservation => !observed,
                    // Partially inspected sources are permitted to retain
                    // already collected evidence without claiming completion.
                    CoverageState::Partial => true,
                    _ => !observed,
                };
                if !consistent {
                    *state = CoverageState::Partial;
                    self.diagnostics.push(CollectorDiagnostic {
                        code: CollectorDiagnosticCode::InvalidObservation,
                        source_item: Some(requested.item.clone()),
                    });
                }
            }
        }
        let completed = self
            .coverage
            .values()
            .filter(|state| {
                matches!(
                    state,
                    CoverageState::InspectedObserved | CoverageState::InspectedNoObservation
                )
            })
            .count();
        let status = if completed == self.coverage.len() {
            CollectionStatus::Complete
        } else if completed > 0 {
            CollectionStatus::Partial
        } else {
            CollectionStatus::Failed
        };
        CollectionOutcome {
            descriptor: self.descriptor,
            run: self.request.run,
            observations: self.observations.into_values().collect(),
            coverage: self.coverage,
            diagnostics: self.diagnostics,
            status,
        }
    }
}

/// Implement this trait in third-party crates for additional source types.
///
/// A collector MUST NOT inspect anything not explicitly requested. The sink
/// validates records but does not enforce actual OS filesystem/network access.
pub trait Collector: Send + Sync {
    /// Return whether the supplied host scope is the *exact* authorized scope.
    ///
    /// Scope-carrying trusted collectors MUST override this. The default true
    /// preserves source compatibility for third-party collectors without an
    /// internally captured scope; it does not sandbox untrusted code.
    ///
    /// This predicate intentionally exposes no reference to the underlying
    /// source capability, which must remain owned by the host.
    fn matches_invocation_scope(&self, _scope: &crate::scope::CollectionScope) -> bool {
        true
    }

    /// The identity, version and declared capabilities of this implementation.
    fn descriptor(&self) -> CollectorDescriptor;
    /// Collect into a bounded sink, honoring cancellation and exact source IDs.
    fn collect(
        &self,
        request: &CollectionRequest,
        sink: &mut CollectionSink,
        cancel: &CancellationToken,
    ) -> Result<(), InventoryError>;
}

/// Execute a cooperative collector independently per requested source.
///
/// Unlike `collect`, an ordinary source-specific collector error records Failed
/// coverage and retains other successful sources. A failed source's partial
/// events are discarded. This is opt-in: collectors must support independent
/// single-source invocations, and it does not sandbox a malicious collector.
/// Authorization must be checked by the caller before this unscoped helper.
pub fn collect_isolated<C: Collector + ?Sized>(
    collector: &C,
    request: CollectionRequest,
    cancel: &CancellationToken,
) -> Result<CollectionOutcome, InventoryError> {
    let descriptor = collector.descriptor();
    request.validate(&descriptor)?;
    let mut combined = CollectionSink::new(descriptor.clone(), request.clone())?;
    let mut sources = request.sources.clone();
    sources.sort_by(|a, b| a.item.cmp(&b.item));
    for source in sources {
        if cancel.is_cancelled() {
            combined.diagnose(CollectorDiagnostic {
                code: CollectorDiagnosticCode::Cancelled,
                source_item: Some(source.item),
            })?;
            continue;
        }
        let single_request = CollectionRequest {
            run: request.run.clone(),
            sources: vec![source.clone()],
            limits: request.limits,
            options: request.options.clone(),
        };
        let mut individual = CollectionSink::new(descriptor.clone(), single_request.clone())?;
        let attempt = collector.collect(&single_request, &mut individual, cancel);
        // Do not reinterpret a forged event, undeclared source, duplicate
        // event or attempted grant expansion as a recoverable parse error.
        if individual.rejected {
            return Err(InventoryError::InvalidMetadata);
        }
        match attempt {
            Ok(()) => {
                let result = individual.finish();
                // Merge through the original bounded sink. Cross-source event
                // collisions or aggregate limits remain fatal, never partial.
                for fact in result.observations {
                    combined.emit(fact).map_err(|error| match error {
                        InventoryError::LimitExceeded(what) => InventoryError::LimitExceeded(what),
                        // Duplicate IDs may contain secrets. Fail without echoing them.
                        _ => InventoryError::InvalidMetadata,
                    })?;
                }
                for diagnostic in result.diagnostics {
                    combined.diagnose(diagnostic)?;
                }
                let state = result.coverage[&source.item];
                if state == CoverageState::NotInspected {
                    // A call that returned success but did not attest any
                    // inspection was attempted, not skipped. Never label it
                    // unattempted or silently convert it to a clean result.
                    combined.diagnose(CollectorDiagnostic {
                        code: CollectorDiagnosticCode::IncompleteScope,
                        source_item: Some(source.item.clone()),
                    })?;
                    combined.cover(&source.item, CoverageState::Failed)?;
                } else {
                    combined.cover(&source.item, state)?;
                }
            }
            Err(error) => {
                let (code, state) = match error {
                    InventoryError::LimitExceeded(_) => (
                        CollectorDiagnosticCode::ResourceLimit,
                        CoverageState::Failed,
                    ),
                    InventoryError::UnsupportedSchema(_) => (
                        CollectorDiagnosticCode::UnsupportedSource,
                        CoverageState::Unsupported,
                    ),
                    _ => (
                        CollectorDiagnosticCode::InvalidObservation,
                        CoverageState::Failed,
                    ),
                };
                // Never include the potentially secret-bearing error payload.
                combined.diagnose(CollectorDiagnostic {
                    code,
                    source_item: Some(source.item.clone()),
                })?;
                combined.cover(&source.item, state)?;
            }
        }
    }
    Ok(combined.finish())
}

/// Drive any collector through independent sink checks and terminal aggregation.
pub fn collect<C: Collector + ?Sized>(
    collector: &C,
    request: CollectionRequest,
    cancel: &CancellationToken,
) -> Result<CollectionOutcome, InventoryError> {
    let descriptor = collector.descriptor();
    let mut sink = CollectionSink::new(descriptor, request.clone())?;
    if cancel.is_cancelled() {
        for source in &request.sources {
            sink.diagnose(CollectorDiagnostic {
                code: CollectorDiagnosticCode::Cancelled,
                source_item: Some(source.item.clone()),
            })?;
        }
        return Ok(sink.finish());
    }
    // Strict mode remains fail-closed. For explicitly independent sources,
    // callers may instead opt into collect_isolated after scope validation.
    collector.collect(&request, &mut sink, cancel)?;
    Ok(sink.finish())
}
