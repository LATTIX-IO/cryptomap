//! Runtime-independent bounded intake for already-authorized collection events.
//!
//! A window is a bounded queue, not a second canonical inventory model. Every
//! drained record goes through CollectionSink, and the resulting CollectionOutcome
//! must still pass the host-pinned pipeline::normalize validation before use.
use crate::{
    CoverageState, InventoryError,
    collector::{
        CancellationToken, CollectionOutcome, CollectionRequest, CollectionSink,
        CollectorDescriptor, CollectorDiagnostic, CollectorDiagnosticCode,
    },
    raw::RawObservation,
    scope::{CollectionScope, ScopeError},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

/// Maximum unique records and serialized bytes buffered before the host drains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowLimits {
    /// Maximum distinct pending event identities in a window.
    pub records: usize,
    /// Maximum validated, serialized pending bytes.
    pub bytes: usize,
}
impl WindowLimits {
    /// Reject disabled windows or windows larger than a collector's total budget.
    pub fn validate(self, request: &CollectionRequest) -> Result<(), InventoryError> {
        if self.records == 0
            || self.bytes == 0
            || self.records > request.limits.observations
            || self.bytes > request.limits.total_bytes
        {
            return Err(InventoryError::InvalidMetadata);
        }
        Ok(())
    }
}

/// Safe intake failures; no untrusted raw contents are printed.
#[derive(Debug)]
pub enum StreamError {
    /// Pending capacity reached: drain and retry the *same* borrowed record.
    Backpressure,
    /// Cooperative cancellation forbids any additional event admission.
    Cancelled,
    /// A preceding flush irrecoverably violated the collector contract.
    Poisoned,
    /// Caller-granted source authorization failed.
    Scope(ScopeError),
    /// Raw schema, replay or bound was violated.
    Inventory(InventoryError),
}
impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backpressure => f.write_str("stream window full"),
            Self::Cancelled => f.write_str("collection cancelled"),
            Self::Poisoned => f.write_str("stream cannot be finalized after validation failure"),
            Self::Scope(_) => f.write_str("stream source authorization failed"),
            Self::Inventory(_) => f.write_str("stream contract validation failed"),
        }
    }
}
impl Error for StreamError {}
impl From<InventoryError> for StreamError {
    fn from(value: InventoryError) -> Self {
        Self::Inventory(value)
    }
}
impl From<ScopeError> for StreamError {
    fn from(value: ScopeError) -> Self {
        Self::Scope(value)
    }
}

/// Single-run, host-authorized bounded buffer with explicit drain backpressure.
///
/// Records are accepted by borrowed reference so a caller retains a rejected
/// record for retry after Backpressure. No networking, filesystem access,
/// worker threads, or asynchronous task scheduling occurs in this API.
pub struct StreamIntake {
    sink: CollectionSink,
    request: CollectionRequest,
    descriptor: CollectorDescriptor,
    cancel: CancellationToken,
    limits: WindowLimits,
    pending: BTreeMap<String, RawObservation>,
    pending_bytes: usize,
    observed: BTreeSet<String>,
    covered: BTreeSet<String>,
    poisoned: bool,
}
impl StreamIntake {
    /// Independently validate exact host-approved sources before intake begins.
    pub fn new(
        scope: &CollectionScope,
        descriptor: CollectorDescriptor,
        request: CollectionRequest,
        cancel: CancellationToken,
        limits: WindowLimits,
    ) -> Result<Self, StreamError> {
        request.validate(&descriptor)?;
        scope.validate_request(&request)?;
        limits.validate(&request)?;
        let sink = CollectionSink::new(descriptor.clone(), request.clone())?;
        Ok(Self {
            sink, request, descriptor, cancel, limits,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            observed: BTreeSet::new(),
            covered: BTreeSet::new(),
            poisoned: false,
        })
    }

    /// Number of unique records not yet transferred to the bounded sink.
    pub fn pending_records(&self) -> usize {
        self.pending.len()
    }

    /// Exact serialized bytes awaiting transfer; never exceeds WindowLimits.
    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    /// Validate and enqueue one source event, without taking ownership on retry.
    ///
    /// Identical pending replays are idempotent. Conflicting same-ID events
    /// fail closed, including when they cross window boundaries (on drain).
    /// When full, NO state is modified and the caller must drain before retry.
    pub fn try_push(&mut self, raw: &RawObservation) -> Result<(), StreamError> {
        if self.poisoned {
            return Err(StreamError::Poisoned);
        }
        if self.cancel.is_cancelled() {
            return Err(StreamError::Cancelled);
        }
        let bytes = raw.validate(&self.request.limits)?;
        if raw.run != self.request.run
            || raw.collector != self.descriptor.id
            || raw.collector_version != self.descriptor.version
            || !self.request.sources.iter().any(|s| {
                s.item == raw.source.item && s.kind == raw.source.kind
            })
            || self.covered.contains(&raw.source.item)
        {
            return Err(InventoryError::InvalidMetadata.into());
        }
        if let Some(existing) = self.pending.get(&raw.event_id) {
            return if existing == raw {
                Ok(())
            } else {
                Err(InventoryError::DuplicateObservation(raw.event_id.clone()).into())
            };
        }
        if bytes > self.limits.bytes {
            return Err(InventoryError::LimitExceeded("stream single record").into());
        }
        let total = self.pending_bytes.checked_add(bytes)
            .ok_or(InventoryError::LimitExceeded("stream byte overflow"))?;
        if self.pending.len() >= self.limits.records || total > self.limits.bytes {
            return Err(StreamError::Backpressure);
        }
        self.pending.insert(raw.event_id.clone(), raw.clone());
        self.pending_bytes = total;
        Ok(())
    }

    /// Transfer an entire accepted window to the existing validated sink.
    ///
    /// Cancellation does not discard already admitted records. On a contract
    /// violation the intake becomes poisoned and cannot produce a false result.
    pub fn drain(&mut self) -> Result<usize, StreamError> {
        if self.poisoned {
            return Err(StreamError::Poisoned);
        }
        let count = self.pending.len();
        for raw in self.pending.values() {
            if let Err(err) = self.sink.emit(raw.clone()) {
                self.poisoned = true;
                return Err(err.into());
            }
            self.observed.insert(raw.source.item.clone());
        }
        self.pending.clear();
        self.pending_bytes = 0;
        Ok(count)
    }

    /// Record terminal coverage only for a requested source that is not closed.
    ///
    /// A cancelled producer cannot retrospectively claim a source completed.
    pub fn cover(&mut self, source: &str, state: CoverageState) -> Result<(), StreamError> {
        if self.poisoned {
            return Err(StreamError::Poisoned);
        }
        if self.cancel.is_cancelled() {
            return Err(StreamError::Cancelled);
        }
        if !self.request.sources.iter().any(|s| s.item == source) {
            return Err(InventoryError::InvalidMetadata.into());
        }
        self.drain()?;
        self.sink.cover(source, state)?;
        self.covered.insert(source.to_owned());
        Ok(())
    }

    /// Flush admitted records and produce a terminal outcome with honest coverage.
    ///
    /// On cancellation, sources with unclosed observations are Partial; unseen
    /// sources are NotInspected. Closed, fully inspected sources remain valid.
    /// Missing source inspection never becomes confirmed absence.
    pub fn finish(mut self) -> Result<CollectionOutcome, StreamError> {
        self.drain()?;
        let cancelled = self.cancel.is_cancelled();
        for source in &self.request.sources {
            if !self.covered.contains(&source.item) {
                let state = if self.observed.contains(&source.item) {
                    CoverageState::Partial
                } else {
                    CoverageState::NotInspected
                };
                self.sink.cover(&source.item, state)?;
                if cancelled {
                    self.sink.diagnose(CollectorDiagnostic {
                        code: CollectorDiagnosticCode::Cancelled,
                        source_item: Some(source.item.clone()),
                    })?;
                }
            }
        }
        Ok(self.sink.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CollectionRunId, raw::RawLimits};

    fn request() -> CollectionRequest {
        CollectionRequest {
            run: CollectionRunId::new("unit-run").unwrap(),
            sources: vec![],
            limits: RawLimits::default(),
            options: BTreeMap::new(),
        }
    }

    #[test]
    fn window_limits_reject_unbounded_or_disabled_configuration() {
        let request = request();
        assert!(WindowLimits { records: 0, bytes: 1 }.validate(&request).is_err());
        assert!(WindowLimits { records: 1, bytes: 0 }.validate(&request).is_err());
        assert!(WindowLimits {
            records: request.limits.observations + 1, bytes: 1,
        }.validate(&request).is_err());
        assert!(WindowLimits {
            records: 1, bytes: request.limits.total_bytes + 1,
        }.validate(&request).is_err());
        assert!(WindowLimits {
            records: 1, bytes: 4096,
        }.validate(&request).is_ok());
    }

    #[test]
    fn user_facing_errors_do_not_echo_sensitive_untrusted_identifiers() {
        let error = StreamError::Inventory(InventoryError::DuplicateObservation(
            "sensitive-source-identifier".into(),
        ));
        assert_eq!(error.to_string(), "stream contract validation failed");
        assert!(!error.to_string().contains("sensitive-source-identifier"));
        assert_eq!(StreamError::Backpressure.to_string(), "stream window full");
        assert_eq!(StreamError::Cancelled.to_string(), "collection cancelled");
    }
}
