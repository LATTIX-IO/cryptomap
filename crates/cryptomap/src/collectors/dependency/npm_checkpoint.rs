//! Versioned, source-bound checkpoints for canonical npm transitive projections.
//!
//! A checkpoint is a verification token, not a filesystem permission or a
//! substitute for reauthorizing sources and revalidating the canonical graph.
use super::{
    npm_installation_projection::project_npm_transitive_edges,
    npm_manifest::NpmReconciliationError,
    npm_transitive::{NpmTransitiveProof, resolve_npm_transitive},
};
use crate::{
    AssetId, AssetKind, InventoryLimits, InventorySnapshot, RelationshipKind, SnapshotId,
    raw::RawLimits, scope::CollectionScope,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

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

// Require *exactly* the fresh installation graph for this lock source.
// The projection preserves preexisting relationships; without this check,
// obsolete path-scoped assets or edges could be incorrectly checkpointed.
fn matches_fresh_graph(
    snapshot: &InventorySnapshot,
    lock_item: &str,
    proof: &NpmTransitiveProof,
) -> bool {
    let expected_paths: BTreeSet<&str> =
        proof.nodes.iter().map(|node| node.path.as_str()).collect();
    let mut installed: BTreeMap<&str, &AssetId> = BTreeMap::new();
    for asset in snapshot.assets.values() {
        if matches!(&asset.kind, AssetKind::Extension { namespace, kind }
            if namespace == "cryptomap:npm-install" && kind == "installed-dependency:v1")
            && asset.extensions.get("npm:lock-item").map(String::as_str) == Some(lock_item)
        {
            let Some(path) = asset.extensions.get("npm:install-path") else {
                return false;
            };
            if installed.insert(path.as_str(), &asset.id).is_some() {
                return false;
            }
        }
    }
    if installed.keys().copied().collect::<BTreeSet<_>>() != expected_paths {
        return false;
    }
    let mut expected_edges = BTreeSet::new();
    for edge in &proof.edges {
        let (Some(from), Some(to)) = (
            installed.get(edge.from_path.as_str()),
            installed.get(edge.to_path.as_str()),
        ) else {
            return false;
        };
        expected_edges.insert(((*from).clone(), (*to).clone()));
    }
    let installed_ids: BTreeSet<&AssetId> = installed.values().copied().collect();
    let mut actual_edges = BTreeSet::new();
    for edge in snapshot.relationships.values() {
        if edge.kind != RelationshipKind::DependsOn {
            continue;
        }
        let from = installed_ids.contains(&edge.from);
        let to = installed_ids.contains(&edge.to);
        if from || to {
            if !from || !to {
                return false;
            }
            actual_edges.insert((edge.from.clone(), edge.to.clone()));
        }
    }
    expected_edges == actual_edges
}

// A fresh source hash must correspond to independently persisted evidence,
// not merely to an extra read taken after a different graph was validated.
fn source_hash_is_recorded(
    snapshot: &InventorySnapshot,
    item: &str,
    digest: &str,
    collector: &str,
) -> bool {
    let source = format!("Dependency:{item}");
    snapshot.evidence.values().any(|record| {
        record.source == source
            && record.source_sha256.as_deref() == Some(digest)
            && record.collector.as_str() == collector
            && record.kind == crate::EvidenceKind::Direct
            && record.confidence == crate::Confidence::Confirmed
            && snapshot.runs.get(&record.run).is_some_and(|run| {
                matches!(run.completeness, crate::RunCompleteness::Complete)
                    && run.requested.contains(item)
            })
    })
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
    // Capture one complete proof first, then require the canonical
    // projection and its persisted evidence to match those same digests.
    let proof = resolve_npm_transitive(scope, manifest_item, lock_item, raw_limits)?;
    let projected = project_npm_transitive_edges(
        snapshot,
        scope,
        manifest_item,
        lock_item,
        raw_limits,
        inventory_limits,
    )?;
    if projected != *snapshot
        || !matches_fresh_graph(snapshot, lock_item, &proof)
        || !source_hash_is_recorded(
            snapshot,
            manifest_item,
            &proof.manifest_sha256,
            "cryptomap:npm-manifest",
        )
        || !source_hash_is_recorded(
            snapshot,
            lock_item,
            &proof.lock_sha256,
            "cryptomap:npm-lockfile",
        )
    {
        return Err(UnboundEvidence);
    }
    let tenant = scope.id().as_str().to_owned();
    let fingerprint = fingerprint(
        &tenant,
        manifest_item,
        lock_item,
        &snapshot.id,
        &proof.manifest_sha256,
        &proof.lock_sha256,
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
        || checkpoint.fingerprint
            != fingerprint(
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
        snapshot,
        scope,
        &checkpoint.manifest_item,
        &checkpoint.lock_item,
        raw_limits,
        inventory_limits,
    )?;
    if &fresh != checkpoint {
        return Err(UnboundEvidence);
    }
    Ok(())
}

/// A bounded, advisory decision about reusing one canonical npm snapshot.
///
/// Only ReuseVerified authorizes the caller to skip a new collector run;
/// it is issued after current source and canonical evidence revalidation.
/// Recollect never carries trusted new graph evidence or permits cache reuse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmIncrementalPlan {
    /// Current files and complete canonical graph still match the checkpoint.
    ReuseVerified {
        /// Independently verified immutable snapshot ID.
        snapshot_id: SnapshotId,
    },
    /// At least one explicitly granted file differs; recollect both source
    /// inputs and reproject before any new checkpoint can be minted.
    Recollect {
        /// Manifest content digest differs from checkpoint.
        manifest_changed: bool,
        /// Lockfile content digest differs from checkpoint.
        lock_changed: bool,
    },
}

/// Inspect two exact, independently authorized source files to determine
/// whether an existing canonical npm graph can be reused safely.
///
/// This is a point-in-time, fail-closed planner, not a filesystem watcher,
/// resumable executor or permission capability. It validates scope, snapshot
/// canonical identity and checkpoint envelope before reading either file.
/// For changed inputs it emits only an advisory Recollect decision, never
/// reuses stale observations. For unchanged inputs it runs the full
/// verify_npm_checkpoint provenance check, including fresh graph projection
/// and source-digest matching; the host may then reuse the returned snapshot
/// identity rather than repeat collection and normalization.
///
/// Missing grants, oversized files, modified cache metadata, wrong tenant,
/// unsupported profiles and invalid snapshots never produce ReuseVerified.
/// The caller must serialize filesystem changes against subsequent use when
/// stronger-than-point-in-time freshness is required.
pub fn plan_npm_incremental(
    checkpoint: &NpmProjectionCheckpoint,
    snapshot: &InventorySnapshot,
    scope: &CollectionScope,
    raw_limits: RawLimits,
    inventory_limits: InventoryLimits,
) -> Result<NpmIncrementalPlan, NpmReconciliationError> {
    use NpmReconciliationError::{
        InvalidSource, ResourceLimit, UnauthorizedSource, UnboundEvidence,
    };
    raw_limits.validate().map_err(|_| InvalidSource)?;
    snapshot
        .verify_for_scope(scope.id(), inventory_limits)
        .map_err(|_| UnboundEvidence)?;
    if checkpoint.version != 1
        || checkpoint.scope != scope.id().as_str()
        || checkpoint.snapshot_id != snapshot.id
        || checkpoint.manifest_item == checkpoint.lock_item
        || checkpoint.fingerprint
            != fingerprint(
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
    let manifest_file = scope
        .open_file(crate::raw::RawSourceKind::Dependency, &checkpoint.manifest_item)
        .map_err(|_| UnauthorizedSource)?;
    let (manifest_sha256, manifest_bytes) = manifest_file
        .sha256_bounded(raw_limits.total_bytes)
        .map_err(|error| match error {
            crate::scope::ScopeError::ResourceLimit => ResourceLimit,
            _ => UnauthorizedSource,
        })?;
    let remaining = raw_limits
        .total_bytes
        .checked_sub(manifest_bytes)
        .ok_or(ResourceLimit)?;
    let lock_file = scope
        .open_file(crate::raw::RawSourceKind::Dependency, &checkpoint.lock_item)
        .map_err(|_| UnauthorizedSource)?;
    let (lock_sha256, _lock_bytes) = lock_file
        .sha256_bounded(remaining)
        .map_err(|error| match error {
            crate::scope::ScopeError::ResourceLimit => ResourceLimit,
            _ => UnauthorizedSource,
        })?;
    let manifest_changed = manifest_sha256 != checkpoint.manifest_sha256;
    let lock_changed = lock_sha256 != checkpoint.lock_sha256;
    if manifest_changed || lock_changed {
        return Ok(NpmIncrementalPlan::Recollect {
            manifest_changed,
            lock_changed,
        });
    }
    // Digest equality alone never permits reuse: the snapshot must still have
    // complete, authorized, matching independently persisted evidence and
    // an exact, nonstale canonical source-scoped installation graph.
    verify_npm_checkpoint(checkpoint, snapshot, scope, raw_limits, inventory_limits)?;
    Ok(NpmIncrementalPlan::ReuseVerified {
        snapshot_id: snapshot.id.clone(),
    })
}
