//! Versioned, source-bound checkpoints for canonical npm transitive projections.
//!
//! A checkpoint is a verification token, not a filesystem permission or a
//! substitute for reauthorizing sources and revalidating the canonical graph.
use super::{
    npm_installation_projection::project_npm_transitive_edges,
    npm_manifest::NpmReconciliationError,
    npm_transitive::resolve_npm_transitive,
};
use crate::{InventoryLimits, InventorySnapshot, SnapshotId, raw::RawLimits, scope::CollectionScope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Versioned checkpoint for an already projected, verified npm inventory.
///
/// Does not include raw lockfile bytes, source URLs or registry credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NpmProjectionCheckpoint {
    /// Checkpoint format (currently 1).
    pub version: u32,
    /// Host-authorized tenant scope bound to the snapshot.
    pub scope: String,
    /// Exact, independently granted npm manifest source identifier.
    pub manifest_item: String,
    /// Exact, independently granted npm lockfile source identifier.
    pub lock_item: String,
    /// Canonical digest of the complete projected snapshot.
    pub snapshot_id: SnapshotId,
    /// SHA-256 of the authorized npm manifest bytes.
    pub manifest_sha256: String,
    /// SHA-256 of the authorized npm lockfile bytes.
    pub lock_sha256: String,
    /// Domain-separated digest binding every checkpoint field above.
    pub fingerprint: String,
}

fn fingerprint(
    scope: &str,
    manifest_item: &str,
    lock_item: &str,
    snapshot_id: &SnapshotId,
    manifest_sha256: &str,
    lock_sha256: &str,
) -> Result<String, NpmReconciliationError> {
    let tuple = serde_json::to_vec(&(
        "cryptomap:npm-checkpoint:v1",
        scope,
        manifest_item,
        lock_item,
        snapshot_id,
        manifest_sha256,
        lock_sha256,
    ))
    .map_err(|_| NpmReconciliationError::UnboundEvidence)?;
    Ok(format!("sha256:{:x}", Sha256::digest(tuple)))
}

/// Produce a checkpoint only after every canonical installed node and edge
/// is already proven by independent scoped manifest/lockfile collection.
///
/// Reauthorizes both exact source files, validates all canonical evidence,
/// confirms complete lockfile runs and returns no checkpoint if graph
/// projection would add, delete, or change any canonical asset or edge.
///
/// The returned token is not a signature or authorization capability.
pub fn checkpoint_npm_projection(
    snapshot: &InventorySnapshot,
    scope: &CollectionScope,
    manifest_item: &str,
    lock_item: &str,
    raw_limits: RawLimits,
    inventory_limits: InventoryLimits,
) -> Result<NpmProjectionCheckpoint, NpmReconciliationError> {
    use NpmReconciliationError::UnboundEvidence;
    snapshot
        .verify_for_scope(scope.id(), inventory_limits)
        .map_err(|_| UnboundEvidence)?;
    let projected = project_npm_transitive_edges(
        snapshot, scope, manifest_item, lock_item, raw_limits, inventory_limits,
    )?;
    if projected != *snapshot {
        return Err(UnboundEvidence);
    }
    let proof = resolve_npm_transitive(scope, manifest_item, lock_item, raw_limits)?;
    let tenant = scope.id().as_str().to_owned();
    let fingerprint = fingerprint(
        &tenant, manifest_item, lock_item, &snapshot.id,
        &proof.manifest_sha256, &proof.lock_sha256,
    )?;
    Ok(NpmProjectionCheckpoint {
        version: 1,
        scope: tenant,
        manifest_item: manifest_item.to_owned(),
        lock_item: lock_item.to_owned(),
        snapshot_id: snapshot.id.clone(),
        manifest_sha256: proof.manifest_sha256,
        lock_sha256: proof.lock_sha256,
        fingerprint,
    })
}

/// Revalidate a checkpoint against the current tenant, exact file grants,
/// fresh source bytes, and canonical snapshot graph and provenance.
///
/// A stale, incomplete, tampered, cross-tenant, or cross-source token is
/// rejected. A legitimate source edit requires a fresh collection, verified
/// graph projection, and new checkpoint; no old proof is silently reused.
pub fn verify_npm_checkpoint(
    checkpoint: &NpmProjectionCheckpoint,
    snapshot: &InventorySnapshot,
    scope: &CollectionScope,
    raw_limits: RawLimits,
    inventory_limits: InventoryLimits,
) -> Result<(), NpmReconciliationError> {
    use NpmReconciliationError::UnboundEvidence;
    if checkpoint.version != 1
        || checkpoint.scope != scope.id().as_str()
        || checkpoint.fingerprint != fingerprint(
            &checkpoint.scope,
            &checkpoint.manifest_item,
            &checkpoint.lock_item,
            &checkpoint.snapshot_id,
            &checkpoint.manifest_sha256,
            &checkpoint.lock_sha256,
        )?
    {
        return Err(UnboundEvidence);
    }
    let fresh = checkpoint_npm_projection(
        snapshot, scope, &checkpoint.manifest_item, &checkpoint.lock_item,
        raw_limits, inventory_limits,
    )?;
    if &fresh != checkpoint {
        return Err(UnboundEvidence);
    }
    Ok(())
}
