//! Canonical path-aware npm dependency edges using persisted lockfile evidence.
//!
//! This deliberately adds a namespaced, versioned Extension asset family rather
//! than changing existing Library IDs or historic package observations.
use super::{
    npm_manifest::{NpmReconciliationError, reconcile_npm_direct},
    npm_projection::{bound_evidence, lock_event, project_npm_direct_edges},
    npm_transitive::{NpmInstalledNode, resolve_npm_transitive},
};
use crate::{
    Asset, AssetId, AssetKind, CollectionRunId, EvidenceId, IdentityContext, InventoryBuilder,
    InventoryLimits, InventorySnapshot, Relationship, RelationshipId, RelationshipKind,
    raw::RawLimits, scope::CollectionScope,
};
use std::collections::{BTreeMap, BTreeSet};

fn path_asset(
    node: &NpmInstalledNode,
    source_item: &str,
    identity: &IdentityContext,
) -> Result<Asset, NpmReconciliationError> {
    // Schema-v2's existing Extension family avoids breaking exhaustive
    // AssetKind matches or changing the canonical snapshot schema. The typed
    // tuple (never a delimiter-joined string) prevents identity collisions.
    let site = serde_json::to_string(&(
        "npm-install:v1",
        source_item,
        &node.path,
        &node.name,
        &node.version,
    ))
    .map_err(|_| NpmReconciliationError::UnboundEvidence)?;
    let scoped = identity
        .clone()
        .with_use_site(site)
        .map_err(|_| NpmReconciliationError::UnboundEvidence)?;
    let kind = AssetKind::Extension {
        namespace: "cryptomap:npm-install".into(),
        kind: "installed-dependency:v1".into(),
    };
    let id = AssetId::from_kind(&kind, &scoped)
        .map_err(|_| NpmReconciliationError::UnboundEvidence)?;
    let extensions = BTreeMap::from([
        ("npm:install-path".into(), node.path.clone()),
        ("npm:name".into(), node.name.clone()),
        ("npm:version".into(), node.version.clone()),
        ("npm:lock-item".into(), source_item.to_owned()),
    ]);
    Ok(Asset { id, kind, extensions })
}

fn evidence_for_node(
    snapshot: &InventorySnapshot,
    node: &NpmInstalledNode,
    lock_item: &str,
    lock_sha256: &str,
    identity: &IdentityContext,
) -> Result<BTreeMap<CollectionRunId, BTreeSet<EvidenceId>>, NpmReconciliationError> {
    use NpmReconciliationError::UnboundEvidence;
    let library = AssetKind::Library {
        ecosystem: "npm".into(),
        name: node.name.clone(),
        version: node.version.clone(),
    };
    let library_id = AssetId::from_kind(&library, identity).map_err(|_| UnboundEvidence)?;
    if snapshot.assets.get(&library_id).is_none_or(|asset| asset.kind != library) {
        return Err(UnboundEvidence);
    }
    let event = lock_event(lock_item, &node.path, &node.version)?;
    let result = bound_evidence(
        snapshot,
        &library_id,
        &format!("Dependency:{lock_item}"),
        lock_sha256,
        lock_item,
        ("cryptomap:npm-lockfile", "0.2.0"),
        &event,
    );
    if result.is_empty() {
        return Err(UnboundEvidence);
    }
    Ok(result)
}

/// Build path-distinct npm installation assets and proof-backed transitive edges.
///
/// Requires a canonical tenant-bound snapshot, independently approved exact
/// package.json and package-lock.json files, a valid root + direct dual-source
/// attestation and direct-confirmed lock evidence for *every* installed node.
/// The source-path typed lock events must match the re-read file SHA-256,
/// collector version, source item, authorized successful coverage and same-run
/// parent/child evidence. Missing or stale evidence rejects the entire result.
///
/// Legacy Library identities and observations remain unchanged; legacy direct
/// DependsOn relationships are preserved, while path-scoped edges join
/// versioned npm-install Extension assets. No synthetic evidence, npm execution, network
/// calls or runtime cryptographic-use inference occurs.
pub fn project_npm_transitive_edges(
    snapshot: &InventorySnapshot,
    scope: &CollectionScope,
    manifest_item: &str,
    lock_item: &str,
    raw_limits: RawLimits,
    inventory_limits: InventoryLimits,
) -> Result<InventorySnapshot, NpmReconciliationError> {
    use NpmReconciliationError::{ResourceLimit, UnboundEvidence};

    // Validates the snapshot, tenant ownership, independent manifest + lock
    // collection, direct root/dependency observations and successful coverage.
    let direct_snapshot = project_npm_direct_edges(
        snapshot, scope, manifest_item, lock_item, raw_limits, inventory_limits,
    )?;
    let direct = reconcile_npm_direct(scope, manifest_item, lock_item, raw_limits)?;
    let graph = resolve_npm_transitive(scope, manifest_item, lock_item, raw_limits)?;
    if direct.manifest_sha256 != graph.manifest_sha256
        || direct.lock_sha256 != graph.lock_sha256
    {
        return Err(UnboundEvidence);
    }
    let identity = IdentityContext::new(scope.id().as_str()).map_err(|_| UnboundEvidence)?;

    let mut assets = BTreeMap::new();
    let mut by_path = BTreeMap::new();
    let mut evidence = BTreeMap::new();
    for node in &graph.nodes {
        let asset = path_asset(node, lock_item, &identity)?;
        if let Some(original) = direct_snapshot.assets.get(&asset.id) {
            if original != &asset {
                return Err(UnboundEvidence);
            }
        }
        let per_run = evidence_for_node(snapshot, node, lock_item, &graph.lock_sha256, &identity)?;
        evidence.insert(node.path.clone(), per_run);
        by_path.insert(node.path.clone(), asset.id.clone());
        assets.insert(asset.id.clone(), asset);
    }

    let mut relations = BTreeMap::new();
    for link in &graph.edges {
        let from = by_path.get(&link.from_path).ok_or(UnboundEvidence)?;
        let to = by_path.get(&link.to_path).ok_or(UnboundEvidence)?;
        let parent_evidence = evidence.get(&link.from_path).ok_or(UnboundEvidence)?;
        let child_evidence = evidence.get(&link.to_path).ok_or(UnboundEvidence)?;
        let mut witnesses = BTreeSet::new();
        for (run, parent) in parent_evidence {
            if let Some(child) = child_evidence.get(run) {
                witnesses.extend(parent.iter().cloned());
                witnesses.extend(child.iter().cloned());
            }
        }
        if witnesses.len() < 2 {
            return Err(UnboundEvidence);
        }
        let id = RelationshipId::from_endpoints(RelationshipKind::DependsOn, from, to)
            .map_err(|_| UnboundEvidence)?;
        relations.insert(id.clone(), Relationship {
            id,
            from: from.clone(),
            to: to.clone(),
            kind: RelationshipKind::DependsOn,
            evidence: witnesses,
        });
    }

    let added_assets = assets.keys()
        .filter(|id| !direct_snapshot.assets.contains_key(*id))
        .count();
    let added_edges = relations.keys()
        .filter(|id| !direct_snapshot.relationships.contains_key(*id))
        .count();
    if added_assets > inventory_limits.assets.saturating_sub(direct_snapshot.assets.len())
        || added_edges > inventory_limits.relationships.saturating_sub(direct_snapshot.relationships.len())
    {
        return Err(ResourceLimit);
    }
    let mut builder = InventoryBuilder::new();
    for run in direct_snapshot.runs.values() {
        builder.add_run(run.clone()).map_err(|_| UnboundEvidence)?;
    }
    for asset in direct_snapshot.assets.values().chain(assets.values()) {
        builder.add_asset(asset.clone()).map_err(|_| UnboundEvidence)?;
    }
    for entry in direct_snapshot.evidence.values() {
        builder.add_evidence(entry.clone()).map_err(|_| UnboundEvidence)?;
    }
    for observation in direct_snapshot.observations.values() {
        builder.add_observation(observation.clone()).map_err(|_| UnboundEvidence)?;
    }
    for edge in direct_snapshot.relationships.values().chain(relations.values()) {
        builder.add_relationship(edge.clone()).map_err(|_| UnboundEvidence)?;
    }
    for (item, state) in &direct_snapshot.coverage {
        builder.set_coverage(item.clone(), *state);
    }
    for record in &direct_snapshot.coverage_records {
        builder.add_coverage_record(record.clone());
    }
    let output = builder.finalize(inventory_limits).map_err(|_| ResourceLimit)?;
    output.verify_for_scope(scope.id(), inventory_limits).map_err(|_| UnboundEvidence)?;
    Ok(output)
}
