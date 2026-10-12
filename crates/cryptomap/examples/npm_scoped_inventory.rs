//! End-to-end passive, explicitly authorized npm package.json/lockfile inventory.
//!
//! Usage: cargo run --example npm_scoped_inventory -- PATH RFC3339-TIMESTAMP SCOPE-ID RUN-PREFIX
//! See examples/fixtures/npm for a bounded supported fixture.
//! No npm execution, script running, package fetch, network access or implicit scanning.

use cryptomap::{
    AssetKind, CollectionRunId, IdentityContext, InventoryLimits, InventorySnapshot,
    batch::{BatchLimits, BatchRun, normalize_batch},
    collector::{CancellationToken, CollectionRequest, Collector, RequestedSource},
    collectors::dependency::{
        npm::NpmLockfileCollector, npm_manifest_collector::NpmManifestCollector,
        npm_projection::project_npm_direct_edges,
    },
    coverage::CollectionScopeId,
    pipeline::PipelineInput,
    raw::{RawLimits, RawSourceKind},
    registry::Registry,
    scope::{CollectionScope, collect_scoped},
};
use std::{error::Error, path::Path};

/// Collect two explicitly authorized npm files and verify direct dependency edges.
///
/// The supplied timestamp is host-reported RFC3339, not inferred from the
/// filesystem. Unsupported npm syntax fails closed instead of reporting
/// the repository as free of cryptographic dependencies.
pub fn collect_npm(
    root: &Path,
    observed_at: &str,
    scope_id: &str,
    run_prefix: &str,
) -> Result<InventorySnapshot, Box<dyn Error>> {
    // Provenance identities MUST be caller-provided, not fixed across hosts
    // and independent collection runs. Validate the prefix before derivation.
    let run_prefix = CollectionRunId::new(run_prefix)?;
    let mut scope = CollectionScope::new(CollectionScopeId::new(scope_id)?);
    for (source, name) in [
        ("npm:manifest", "package.json"),
        ("npm:lock", "package-lock.json"),
    ] {
        scope.grant_file(RawSourceKind::Dependency, source, root, name, 1_048_576)?;
    }

    let manifest = NpmManifestCollector::new(&scope, observed_at);
    let lock = NpmLockfileCollector::new(&scope, observed_at);
    let manifest_descriptor = manifest.descriptor();
    let lock_descriptor = lock.descriptor();
    let manifest_run = CollectionRunId::new(format!("{}:manifest", run_prefix.as_str()))?;
    let lock_run = CollectionRunId::new(format!("{}:lock", run_prefix.as_str()))?;
    let manifest_sources = vec![RequestedSource {
        kind: RawSourceKind::Dependency,
        item: "npm:manifest".into(),
    }];
    let lock_sources = vec![RequestedSource {
        kind: RawSourceKind::Dependency,
        item: "npm:lock".into(),
    }];
    let limits = RawLimits::default();
    let inventory_limits = InventoryLimits::default();
    let cancel = CancellationToken::default();

    let manifest_outcome = collect_scoped(
        &scope,
        &manifest,
        CollectionRequest {
            run: manifest_run.clone(),
            sources: manifest_sources.clone(),
            limits,
            options: Default::default(),
        },
        &cancel,
    )?;
    let lock_outcome = collect_scoped(
        &scope,
        &lock,
        CollectionRequest {
            run: lock_run.clone(),
            sources: lock_sources.clone(),
            limits,
            options: Default::default(),
        },
        &cancel,
    )?;
    let identity = IdentityContext::new(scope.id().as_str())?;
    let registry = Registry::builtin();
    let snapshot = normalize_batch(
        vec![
            BatchRun {
                input: PipelineInput {
                    scope: &scope,
                    identity: &identity,
                    registry: &registry,
                    expected_descriptor: &manifest_descriptor,
                    expected_run: &manifest_run,
                    sources: &manifest_sources,
                    raw_limits: limits,
                    inventory_limits,
                    started_at: observed_at,
                    ended_at: observed_at,
                },
                outcome: manifest_outcome,
            },
            BatchRun {
                input: PipelineInput {
                    scope: &scope,
                    identity: &identity,
                    registry: &registry,
                    expected_descriptor: &lock_descriptor,
                    expected_run: &lock_run,
                    sources: &lock_sources,
                    raw_limits: limits,
                    inventory_limits,
                    started_at: observed_at,
                    ended_at: observed_at,
                },
                outcome: lock_outcome,
            },
        ],
        BatchLimits::default(),
    )?;
    let projected = project_npm_direct_edges(
        &snapshot,
        &scope,
        "npm:manifest",
        "npm:lock",
        limits,
        inventory_limits,
    )?;
    projected.verify_for_scope(scope.id(), inventory_limits)?;
    Ok(projected)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let (Some(root), Some(timestamp), Some(scope_id), Some(run_prefix), None) = (
        args.next(),
        args.next(),
        args.next(),
        args.next(),
        args.next(),
    ) else {
        return Err(
            "usage: npm_scoped_inventory <explicit-directory> <RFC3339-timestamp> <tenant-scope-id> <unique-run-prefix>".into(),
        );
    };
    let timestamp = timestamp
        .to_str()
        .ok_or("timestamp must be valid UTF-8 RFC3339")?;
    let scope_id = scope_id.to_str().ok_or("scope ID must be valid UTF-8")?;
    let run_prefix = run_prefix
        .to_str()
        .ok_or("run prefix must be valid UTF-8")?;
    let snapshot = collect_npm(Path::new(&root), timestamp, scope_id, run_prefix)?;
    let libraries = snapshot
        .query_assets(|asset| matches!(asset.kind, AssetKind::Library { .. }))
        .count();
    println!(
        "verified snapshot={} libraries={} direct_dependencies={} coverage_records={}",
        snapshot.id,
        libraries,
        snapshot.relationships.len(),
        snapshot.coverage_records.len()
    );
    println!("dependency presence does not prove cryptographic algorithm execution");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn packaged_fixture_produces_verified_source_bound_inventory() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixtures/npm");
        let a = collect_npm(
            &root,
            "2026-10-12T12:00:00Z",
            "fixture-scope",
            "fixture-run",
        )
        .unwrap();
        let b = collect_npm(
            &root,
            "2026-10-12T12:00:00Z",
            "fixture-scope",
            "fixture-run",
        )
        .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.relationships.len(), 1);
        assert_eq!(a.coverage_records.len(), 2);
        assert_eq!(
            a.query_assets(|asset| matches!(asset.kind, AssetKind::Library { .. }))
                .count(),
            2
        );
        let serialized = serde_json::to_string(&a).unwrap();
        let scope = CollectionScopeId::new("fixture-scope").unwrap();
        let imported = InventorySnapshot::from_json_verified_for_scope(
            &serialized,
            &scope,
            InventoryLimits::default(),
        )
        .unwrap();
        assert_eq!(a, imported);
    }

    #[test]
    fn independent_host_namespaces_do_not_reuse_authorized_provenance() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixtures/npm");
        let a = collect_npm(&root, "2026-10-12T12:00:00Z", "tenant-a", "run-001").unwrap();
        let b = collect_npm(&root, "2026-10-12T12:00:00Z", "tenant-b", "run-002").unwrap();
        assert_ne!(a.id, b.id);
        let a_scope = CollectionScopeId::new("tenant-a").unwrap();
        let b_scope = CollectionScopeId::new("tenant-b").unwrap();
        a.verify_for_scope(&a_scope, InventoryLimits::default())
            .unwrap();
        b.verify_for_scope(&b_scope, InventoryLimits::default())
            .unwrap();
        assert!(
            a.verify_for_scope(&b_scope, InventoryLimits::default())
                .is_err()
        );
        let c = collect_npm(&root, "2026-10-12T12:00:00Z", "tenant-a", "run-002").unwrap();
        assert_ne!(a.id, c.id);
        assert!(collect_npm(&root, "2026-10-12T12:00:00Z", "tenant-a", "").is_err());
    }

    #[test]
    fn missing_source_and_bad_timestamp_fail_without_snapshot() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixtures/npm");
        assert!(collect_npm(&root, "not-a-timestamp", "fixture-scope", "fixture-run").is_err());
        assert!(
            collect_npm(
                &root.join("missing"),
                "2026-10-12T12:00:00Z",
                "fixture-scope",
                "fixture-run"
            )
            .is_err()
        );
    }
}
