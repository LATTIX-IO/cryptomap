//! Verified Cargo direct dependencies projected into canonical DependsOn edges.
//!
//! Both source files are independently authorized and freshly re-read.
//! The existing canonical snapshot must contain matching, successful,
//! same-run Cargo.lock package-presence evidence for both endpoints.
use super::manifest::{CargoReconciliationError, reconcile_cargo_direct};
use crate::{
    AssetId, AssetKind, CollectionRunId, Confidence, CoverageState, EvidenceId, EvidenceKind,
    IdentityContext, InventoryBuilder, InventoryLimits, InventorySnapshot, Relationship,
    RelationshipId, RelationshipKind, raw::RawLimits, scope::CollectionScope,
};
use std::collections::{BTreeMap, BTreeSet};

fn bound_evidence(
    snapshot: &InventorySnapshot,
    asset: &AssetId,
    source: &str,
    sha256: &str,
    source_item: &str,
) -> BTreeMap<CollectionRunId, BTreeSet<EvidenceId>> {
    let mut per_run: BTreeMap<CollectionRunId, BTreeSet<EvidenceId>> = BTreeMap::new();
    for observation in snapshot.observations.values() {
        if observation.asset != *asset
            || observation.property != "dependency:presence"
            || observation.value != "declared"
        {
            continue;
        }
        let Some(evidence) = snapshot.evidence.get(&observation.evidence) else {
            continue;
        };
        if evidence.source != source
            || evidence.source_sha256.as_deref() != Some(sha256)
            || evidence.collector.as_str() != "cryptomap:cargo-lockfile"
            || evidence.kind != EvidenceKind::Direct
            || evidence.confidence != Confidence::Confirmed
        {
            continue;
        }
        let Some(run) = snapshot.runs.get(&evidence.run) else {
            continue;
        };
        if !run.requested.contains(source_item)
            || !snapshot.coverage_records.iter().any(|record| {
                record.run == evidence.run
                    && record.source_item == source_item
                    && record.state == CoverageState::InspectedObserved
            })
        {
            continue;
        }
        per_run
            .entry(evidence.run.clone())
            .or_default()
            .insert(evidence.id.clone());
    }
    per_run
}

/// Project verified direct dependencies into evidence-linked canonical
/// RelationshipKind::DependsOn edges.
///
/// Both manifest_item and lock_item must be exact granted items in scope.
/// Reconciles current on-disk bytes and requires a verified tenant-bound
/// snapshot with directly observed Cargo.lock package evidence, matching
/// lockfile digest, a successful coverage record, and same-run root/target
/// provenance. No package execution, network, new synthetic package evidence,
/// or inferred algorithm-use fact is introduced.
///
/// This is a conservative incremental projection: the relationship points to
/// existing Cargo.lock evidence. Manifest authorization/reconciliation is
/// checked at call time, but a separate canonical manifest Evidence record
/// is not produced by this function. Future work should persist manifest
/// evidence and support broader Cargo.toml syntax.
pub fn project_cargo_direct_edges(
    snapshot: &InventorySnapshot,
    scope: &CollectionScope,
    manifest_item: &str,
    lock_item: &str,
    raw_limits: RawLimits,
    inventory_limits: InventoryLimits,
) -> Result<InventorySnapshot, CargoReconciliationError> {
    use CargoReconciliationError::{UnboundEvidence, UnresolvedDependency};

    snapshot
        .verify_for_scope(scope.id(), inventory_limits)
        .map_err(|_| UnboundEvidence)?;
    let proven = reconcile_cargo_direct(scope, manifest_item, lock_item, raw_limits)?;
    let context = IdentityContext::new(scope.id().as_str()).map_err(|_| UnboundEvidence)?;
    let id_for = |name: &str, version: &str| {
        let kind = AssetKind::Library {
            ecosystem: "cargo".into(),
            name: name.into(),
            version: version.into(),
        };
        let id = AssetId::from_kind(&kind, &context).map_err(|_| UnboundEvidence)?;
        if snapshot
            .assets
            .get(&id)
            .is_none_or(|asset| asset.kind != kind)
        {
            return Err(UnboundEvidence);
        }
        Ok(id)
    };
    let root = id_for(&proven.root_name, &proven.root_version)?;
    let source = format!("Dependency:{lock_item}");
    let root_by_run = bound_evidence(snapshot, &root, &source, &proven.lock_sha256, lock_item);
    if root_by_run.is_empty() {
        return Err(UnboundEvidence);
    }

    // Build every edge before modifying a builder. Errors return no partially
    // projected snapshot or relationship.
    let mut additions = Vec::new();
    for dependency in &proven.direct {
        let target = id_for(&dependency.name, &dependency.version)?;
        if target == root {
            return Err(UnresolvedDependency);
        }
        let target_by_run =
            bound_evidence(snapshot, &target, &source, &proven.lock_sha256, lock_item);
        let mut supporting = BTreeSet::new();
        for (run, root_evidence) in &root_by_run {
            if let Some(target_evidence) = target_by_run.get(run) {
                supporting.extend(root_evidence.iter().cloned());
                supporting.extend(target_evidence.iter().cloned());
            }
        }
        if supporting.len() < 2 {
            return Err(UnboundEvidence);
        }
        let id = RelationshipId::from_endpoints(RelationshipKind::DependsOn, &root, &target)
            .map_err(|_| UnboundEvidence)?;
        additions.push(Relationship {
            id,
            from: root.clone(),
            to: target,
            kind: RelationshipKind::DependsOn,
            evidence: supporting,
        });
    }

    // Existing edges merge evidence without consuming another relationship
    // slot. Count only novel identities to preserve idempotent replay at the
    // exact configured relationship limit.
    let new_edges = additions
        .iter()
        .filter(|edge| !snapshot.relationships.contains_key(&edge.id))
        .count();
    if new_edges > inventory_limits.relationships.saturating_sub(snapshot.relationships.len()) {
        return Err(CargoReconciliationError::ResourceLimit);
    }

    let mut builder = InventoryBuilder::new();
    for run in snapshot.runs.values() {
        builder.add_run(run.clone()).map_err(|_| UnboundEvidence)?;
    }
    for asset in snapshot.assets.values() {
        builder
            .add_asset(asset.clone())
            .map_err(|_| UnboundEvidence)?;
    }
    for evidence in snapshot.evidence.values() {
        builder
            .add_evidence(evidence.clone())
            .map_err(|_| UnboundEvidence)?;
    }
    for observation in snapshot.observations.values() {
        builder
            .add_observation(observation.clone())
            .map_err(|_| UnboundEvidence)?;
    }
    for relation in snapshot.relationships.values() {
        builder
            .add_relationship(relation.clone())
            .map_err(|_| UnboundEvidence)?;
    }
    for relation in additions {
        builder
            .add_relationship(relation)
            .map_err(|_| UnboundEvidence)?;
    }
    for (item, state) in &snapshot.coverage {
        builder.set_coverage(item.clone(), *state);
    }
    for record in &snapshot.coverage_records {
        builder.add_coverage_record(record.clone());
    }
    let projected = builder
        .finalize(inventory_limits)
        .map_err(|_| UnboundEvidence)?;
    projected
        .verify_for_scope(scope.id(), inventory_limits)
        .map_err(|_| UnboundEvidence)?;
    Ok(projected)
}
