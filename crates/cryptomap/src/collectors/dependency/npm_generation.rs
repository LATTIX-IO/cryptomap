//! Atomic in-memory handoff of verified npm inventory generations.
//!
//! Each reader holds one immutable generation containing the checkpoint and
//! snapshot together. This is not durable storage or a filesystem transaction.
use super::{
    npm_checkpoint::{NpmProjectionCheckpoint, verify_npm_checkpoint},
    npm_manifest::NpmReconciliationError,
};
use crate::{InventoryLimits, InventorySnapshot, raw::RawLimits, scope::CollectionScope};
use std::sync::{Arc, Mutex};

/// One immutable snapshot/checkpoint pair from a verified npm source generation.
///
/// Holding an `Arc` returned by the store preserves the same generation even
/// while a writer publishes a replacement.
#[derive(Debug, PartialEq, Eq)]
pub struct NpmVerifiedGeneration {
    sequence: u64,
    snapshot: Arc<InventorySnapshot>,
    checkpoint: NpmProjectionCheckpoint,
}

impl NpmVerifiedGeneration {
    /// Strictly increasing local publication sequence; not a persistent ID.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Immutable canonical snapshot from this exact generation.
    pub fn snapshot(&self) -> &InventorySnapshot {
        &self.snapshot
    }

    /// Source-bound checkpoint paired with the snapshot in this generation.
    pub fn checkpoint(&self) -> &NpmProjectionCheckpoint {
        &self.checkpoint
    }
}

/// Scope-bound in-memory generation store with compare-and-swap publication.
///
/// The store holds at most one current generation. Existing readers retain
/// their immutable `Arc` until they drop it. No graph is visible halfway
/// through publication. Verification reopens only exactly granted files;
/// hosts must prevent filesystem mutation between validation and publication
/// if stronger-than-point-in-time source freshness is needed.
#[derive(Debug)]
pub struct NpmGenerationStore {
    tenant: String,
    manifest_item: String,
    lock_item: String,
    current: Mutex<Option<Arc<NpmVerifiedGeneration>>>,
}

impl NpmGenerationStore {
    /// Bind a store permanently to one tenant and two distinct source items.
    ///
    /// File grants are checked at publication, not inferred at construction.
    pub fn new(
        scope: &CollectionScope,
        manifest_item: &str,
        lock_item: &str,
    ) -> Result<Self, NpmReconciliationError> {
        fn valid(item: &str) -> bool {
            !item.is_empty()
                && item.len() <= 512
                && item.trim() == item
                && !item.chars().any(char::is_control)
        }
        if !valid(manifest_item) || !valid(lock_item) || manifest_item == lock_item {
            return Err(NpmReconciliationError::UnboundEvidence);
        }
        Ok(Self {
            tenant: scope.id().as_str().to_owned(),
            manifest_item: manifest_item.to_owned(),
            lock_item: lock_item.to_owned(),
            current: Mutex::new(None),
        })
    }

    /// Load one immutable pair under the mutex and return it to the reader.
    ///
    /// The reader must use the snapshot and checkpoint from this same returned
    /// value, not combine fields from two separate `current()` calls.
    /// A poisoned lock fails closed rather than returning an unverified pair.
    pub fn current(
        &self,
    ) -> Result<Option<Arc<NpmVerifiedGeneration>>, NpmReconciliationError> {
        let guard = self
            .current
            .lock()
            .map_err(|_| NpmReconciliationError::UnboundEvidence)?;
        Ok(guard.clone())
    }

    /// Publish a fully revalidated snapshot and checkpoint atomically.
    ///
    /// `expected_sequence` is `None` for the initial empty store and
    /// `Some(current.sequence())` for a replacement. A concurrent writer
    /// invalidates a stale expectation; no partial or stale overwrite occurs.
    /// Verification happens before locking, keeping reads nonblocking while
    /// bounded file and graph checks run. Revalidation is point-in-time:
    /// the caller owns coordination with concurrent source-file mutations.
    ///
    /// Error leaves the currently published generation unchanged.
    pub fn publish(
        &self,
        checkpoint: NpmProjectionCheckpoint,
        snapshot: InventorySnapshot,
        scope: &CollectionScope,
        expected_sequence: Option<u64>,
        raw_limits: RawLimits,
        inventory_limits: InventoryLimits,
    ) -> Result<Arc<NpmVerifiedGeneration>, NpmReconciliationError> {
        if scope.id().as_str() != self.tenant
            || checkpoint.scope != self.tenant
            || checkpoint.manifest_item != self.manifest_item
            || checkpoint.lock_item != self.lock_item
        {
            return Err(NpmReconciliationError::UnboundEvidence);
        }
        verify_npm_checkpoint(&checkpoint, &snapshot, scope, raw_limits, inventory_limits)?;

        let mut guard = self
            .current
            .lock()
            .map_err(|_| NpmReconciliationError::UnboundEvidence)?;
        if guard.as_ref().map(|generation| generation.sequence) != expected_sequence {
            return Err(NpmReconciliationError::UnboundEvidence);
        }
        let sequence = expected_sequence
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(NpmReconciliationError::ResourceLimit)?;
        let generation = Arc::new(NpmVerifiedGeneration {
            sequence,
            snapshot: Arc::new(snapshot),
            checkpoint,
        });
        *guard = Some(Arc::clone(&generation));
        Ok(generation)
    }
}
