//! Verified npm direct dependencies projected into canonical DependsOn edges.
//!
//! Both source files are independently authorized and freshly re-read.
//! The existing canonical snapshot must contain matching, successful,
//! same-run evidence within each of the npm lockfile and manifest runs.
use super::npm_manifest::{NpmReconciliationError, reconcile_npm_direct};
use crate::{
    AssetId, AssetKind, CollectionRunId, Confidence, CoverageState, EvidenceId, EvidenceKind,
    IdentityContext, InventoryBuilder, InventoryLimits, InventorySnapshot, Relationship,
    RelationshipId, RelationshipKind, raw::RawLimits, scope::CollectionScope,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

fn role_event(
    tag: &str,
    prefix: &str,
    item: &str,
    name: &str,
    version: &str,
    role: &str,
) -> Result<String, NpmReconciliationError> {
    let fields = serde_json::to_vec(&(tag, item, name, version, role))
        .map_err(|_| NpmReconciliationError::UnboundEvidence)?;
    Ok(format!("{prefix}{:x}", Sha256::digest(fields)))
}

fn lock_event(item: &str, path: &str, version: &str) -> Result<String, NpmReconciliationError> {
    let fields = serde_json::to_vec(&("cryptomap:npm-dependency:v1", item, path, version))
        .map_err(|_| NpmReconciliationError::UnboundEvidence)?;
    Ok(format!("npm:v1:{:x}", Sha256::digest(fields)))
}

fn bound_evidence(
    snapshot: &InventorySnapshot,
    asset: &AssetId,
    source: &str,
    sha256: &str,
    source_item: &str,
    collector_id: &str,
    collector_version: &str,
    expected_event: &str,
) -> BTreeMap<CollectionRunId, BTreeSet<EvidenceId>> {
    let mut per_run: BTreeMap<CollectionRunId, BTreeSet<EvidenceId>> = BTreeMap::new();
    for observation in snapshot.observations.values() {
        if observation.asset != *asset
            || observation.property != "dependency:presence"
            || observation.value != "declared"
            || observation.context.as_deref() != Some(expected_event)
        {
            continue;
        }
        let Some(evidence) = snapshot.evidence.get(&observation.evidence) else {
            continue;
        };
        if evidence.source != source
            || evidence.source_sha256.as_deref() != Some(sha256)
            || evidence.collector.as_str() != collector_id
            || evidence.collector_version != collector_version
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
/// snapshot with independently collected direct package-lock.json AND package.json
/// package evidence, matching both file digests, successful coverage records,
/// and same-run root/target provenance within each collector. No package execution, network, new synthetic package evidence,
/// or inferred algorithm-use fact is introduced.
///
/// Relationships reference four pre-existing evidence IDs at minimum: two
/// lockfile observations and two manifest observations. Both documents must
/// have been collected independently by the host-authorized pipeline. There
/// is no runtime-use inference or implicit schema migration.
pub fn project_npm_direct_edges(
    snapshot: &InventorySnapshot,
    scope: &CollectionScope,
    manifest_item: &str,
    lock_item: &str,
    raw_limits: RawLimits,
    inventory_limits: InventoryLimits,
) -> Result<InventorySnapshot, NpmReconciliationError> {
    use NpmReconciliationError::{UnboundEvidence, UnresolvedDependency};

    snapshot
        .verify_for_scope(scope.id(), inventory_limits)
        .map_err(|_| UnboundEvidence)?;
    let proven = reconcile_npm_direct(scope, manifest_item, lock_item, raw_limits)?;
    let context = IdentityContext::new(scope.id().as_str()).map_err(|_| UnboundEvidence)?;
    let id_for = |name: &str, version: &str| {
        let kind = AssetKind::Library {
            ecosystem: "npm".into(),
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
    let root_lock_event = lock_event(lock_item, "npm:root", &proven.root_version)?;
    let root_manifest_event = role_event(
        "cryptomap:npm-manifest:v1",
        "npm-manifest:v1:",
        manifest_item,
        &proven.root_name,
        &proven.root_version,
        "root",
    )?;
    let source = format!("Dependency:{lock_item}");
    let root_by_run = bound_evidence(
        snapshot,
        &root,
        &source,
        &proven.lock_sha256,
        lock_item,
        "cryptomap:npm-lockfile",
        "0.2.0",
        &root_lock_event,
    );
    let manifest_source = format!("Dependency:{manifest_item}");
    let manifest_root_by_run = bound_evidence(
        snapshot,
        &root,
        &manifest_source,
        &proven.manifest_sha256,
        manifest_item,
        "cryptomap:npm-manifest",
        "0.1.0",
        &root_manifest_event,
    );
    if root_by_run.is_empty() || manifest_root_by_run.is_empty() {
        return Err(UnboundEvidence);
    }

    // Build every edge before modifying a builder. Errors return no partially
    // projected snapshot or relationship.
    let mut additions = Vec::new();
    for dependency in &proven.direct {
        let target = id_for(&dependency.name, &dependency.version)?;
        let target_lock_event = lock_event(
            lock_item,
            &format!("node_modules/{}", dependency.name),
            &dependency.version,
        )?;
        let target_manifest_event = role_event(
            "cryptomap:npm-manifest:v1",
            "npm-manifest:v1:",
            manifest_item,
            &dependency.name,
            &dependency.version,
            "direct",
        )?;
        if target == root {
            return Err(UnresolvedDependency);
        }
        let target_by_run = bound_evidence(
            snapshot,
            &target,
            &source,
            &proven.lock_sha256,
            lock_item,
            "cryptomap:npm-lockfile",
            "0.2.0",
            &target_lock_event,
        );
        let manifest_target_by_run = bound_evidence(
            snapshot,
            &target,
            &manifest_source,
            &proven.manifest_sha256,
            manifest_item,
            "cryptomap:npm-manifest",
            "0.1.0",
            &target_manifest_event,
        );
        let mut supporting = BTreeSet::new();
        for (run, root_evidence) in &root_by_run {
            if let Some(target_evidence) = target_by_run.get(run) {
                supporting.extend(root_evidence.iter().cloned());
                supporting.extend(target_evidence.iter().cloned());
            }
        }
        let mut manifest_supporting = BTreeSet::new();
        for (run, root_evidence) in &manifest_root_by_run {
            if let Some(target_evidence) = manifest_target_by_run.get(run) {
                manifest_supporting.extend(root_evidence.iter().cloned());
                manifest_supporting.extend(target_evidence.iter().cloned());
            }
        }
        if supporting.len() < 2 || manifest_supporting.len() < 2 {
            return Err(UnboundEvidence);
        }
        supporting.extend(manifest_supporting);
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
    if new_edges
        > inventory_limits
            .relationships
            .saturating_sub(snapshot.relationships.len())
    {
        return Err(NpmReconciliationError::ResourceLimit);
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
