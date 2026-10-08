//! Explicit inventory collection runs, scope and coverage.
use crate::{CollectionRunId, CollectorId, CoverageState, InventoryError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Identity of one authorized collection scope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CollectionScopeId(String);
impl CollectionScopeId {
    /// Create a validated scope ID.
    pub fn new(value: impl Into<String>) -> Result<Self, InventoryError> {
        let value = value.into();
        if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
            return Err(InventoryError::InvalidIdentifier);
        }
        Ok(Self(value))
    }
    /// Borrow scope ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
/// Whether all requested collection scope items were inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunCompleteness {
    /// Every supported required scope item was inspected.
    Complete,
    /// At least one requested scope item could not be completed.
    Partial,
    /// No reliable collection result is available.
    Failed,
}
/// A single collector execution with explicit scope and outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionRun {
    /// Collection invocation ID.
    pub id: CollectionRunId,
    /// Collector implementation ID.
    pub collector: CollectorId,
    /// Collector version.
    pub collector_version: String,
    /// Scope to which the collector was restricted.
    pub scope: CollectionScopeId,
    /// Explicit list of requested source items.
    pub requested: BTreeSet<String>,
    /// Start of collection, RFC3339.
    pub started_at: String,
    /// End of collection, RFC3339.
    pub ended_at: String,
    /// Run outcome.
    pub completeness: RunCompleteness,
}
impl CollectionRun {
    /// Check time ordering and required string fields.
    pub fn validate(&self) -> Result<(), InventoryError> {
        let start = crate::validation::utc_seconds(&self.started_at)?;
        let end = crate::validation::utc_seconds(&self.ended_at)?;
        if start > end || self.collector_version.is_empty() || self.requested.len() > 100_000 {
            return Err(InventoryError::InvalidMetadata);
        }
        for requested in &self.requested {
            crate::validation::safe_text(requested, 2048)?;
        }
        Ok(())
    }
}
/// Typed coverage for one source item within one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageRecord {
    /// Collection run that inspected or attempted the source.
    pub run: CollectionRunId,
    /// Requested scope item.
    pub source_item: String,
    /// Inspection outcome.
    pub state: CoverageState,
    /// A safe diagnostic code for failure/partial/unsupported state.
    pub reason_code: Option<String>,
}
