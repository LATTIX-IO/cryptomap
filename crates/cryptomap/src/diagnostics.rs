//! Deterministic, payload-free collection diagnostics and outcome accounting.
//!
//! Summaries intentionally omit source IDs, paths, errors and raw values. The
//! existing per-source coverage records remain the source of truth.
use crate::{
    CoverageState,
    collector::{CollectionOutcome, CollectorDiagnosticCode},
};
use serde::{Deserialize, Serialize};

/// Stable diagnostic severity classification, not cryptographic risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticSeverity {
    /// Source was not processed, or inspection cannot be trusted.
    Error,
    /// Some requested scope is missing or unsupported.
    Warning,
}

/// Classify diagnostics without exposing source input or arbitrary messages.
pub fn diagnostic_severity(code: CollectorDiagnosticCode) -> DiagnosticSeverity {
    match code {
        CollectorDiagnosticCode::IncompleteScope
        | CollectorDiagnosticCode::UnsupportedSource
        | CollectorDiagnosticCode::Cancelled => DiagnosticSeverity::Warning,
        _ => DiagnosticSeverity::Error,
    }
}

/// Whether a retry might help. This is not an instruction to retry automatically.
pub fn retryable(code: CollectorDiagnosticCode) -> bool {
    matches!(
        code,
        CollectorDiagnosticCode::Timeout | CollectorDiagnosticCode::Cancelled
    )
}

/// Bounded, deterministic per-run counts with no source-identifying fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionSummary {
    /// Number of exact sources requested and represented in coverage.
    pub requested: usize,
    /// Number of sources whose inspection was attempted.
    pub attempted: usize,
    /// Sources successfully inspected with at least one observation.
    pub inspected_observed: usize,
    /// Sources successfully inspected without observations.
    pub inspected_no_observation: usize,
    /// Sources reported partially inspected.
    pub partial: usize,
    /// Attempted sources that failed inspection.
    pub failed: usize,
    /// Requested source format unsupported.
    pub unsupported: usize,
    /// Requested sources not attempted.
    pub not_inspected: usize,
    /// Number of accepted raw observations.
    pub observations: usize,
    /// Number of bounded, typed diagnostics.
    pub diagnostics: usize,
}

impl CollectionSummary {
    /// Derive counts solely from already validated collector coverage states.
    ///
    /// A summary cannot independently authenticate an imported outcome;
    /// callers must use host-pinned normalization for that purpose.
    pub fn from_outcome(outcome: &CollectionOutcome) -> Self {
        let mut summary = Self {
            requested: outcome.coverage.len(),
            attempted: 0,
            inspected_observed: 0,
            inspected_no_observation: 0,
            partial: 0,
            failed: 0,
            unsupported: 0,
            not_inspected: 0,
            observations: outcome.observations.len(),
            diagnostics: outcome.diagnostics.len(),
        };
        for state in outcome.coverage.values() {
            match state {
                CoverageState::InspectedObserved => summary.inspected_observed += 1,
                CoverageState::InspectedNoObservation => summary.inspected_no_observation += 1,
                CoverageState::Partial => summary.partial += 1,
                CoverageState::Failed => summary.failed += 1,
                CoverageState::Unsupported => summary.unsupported += 1,
                CoverageState::NotInspected => summary.not_inspected += 1,
            }
        }
        summary.attempted = summary.requested - summary.not_inspected - summary.unsupported;
        summary
    }
}
