//! Independent npm manifest + lockfile collection and canonical edge contracts.
#![allow(clippy::unwrap_used)]
use cryptomap::{
    AssetKind, CollectionRunId, IdentityContext, InventoryBuilder, InventoryLimits,
    InventorySnapshot, RelationshipKind, RunCompleteness,
    batch::{BatchLimits, BatchRun, normalize_batch},
    collector::{CancellationToken, CollectionRequest, Collector, RequestedSource},
    collectors::dependency::{
        npm::NpmLockfileCollector,
        npm_checkpoint::{
            NpmIncrementalPlan, checkpoint_npm_projection, plan_npm_incremental,
            verify_npm_checkpoint,
        },
        npm_installation_projection::project_npm_transitive_edges,
        npm_manifest::NpmReconciliationError,
        npm_manifest_collector::NpmManifestCollector,
        npm_projection::project_npm_direct_edges,
    },
    coverage::CollectionScopeId,
    pipeline::PipelineInput,
    raw::{RawLimits, RawSourceKind},
    registry::Registry,
    scope::{CollectionScope, collect_scoped},
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
const MANIFEST: &str =
    r#"{"name":"app","version":"1.0.0","dependencies":{"a":"1.0.0","b":"1.0.0"}}"#;
const LOCK: &str = r#"{"lockfileVersion":3,"packages":{
    "":{"name":"app","version":"1.0.0","dependencies":{"a":"1.0.0","b":"1.0.0"}},
    "node_modules/a":{"version":"1.0.0","dependencies":{"shared":"1.0.0"}},
    "node_modules/b":{"version":"1.0.0","dependencies":{"shared":"2.0.0"}},
    "node_modules/shared":{"version":"1.0.0"},
    "node_modules/b/node_modules/shared":{"version":"2.0.0"}
}}"#;

struct Fixture {
    path: PathBuf,
}
impl Fixture {
    fn new(manifest: &str, lock: &str) -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cryptomap-npm-evidence-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("package.json"), manifest).unwrap();
        fs::write(path.join("package-lock.json"), lock).unwrap();
        Self { path }
    }
    fn scope(&self, tenant: &str, manifest: bool, lock_item: &str) -> CollectionScope {
        let mut scope = CollectionScope::new(CollectionScopeId::new(tenant).unwrap());
        scope
            .grant_file(
                RawSourceKind::Dependency,
                lock_item,
                &self.path,
                "package-lock.json",
                4096,
            )
            .unwrap();
        if manifest {
            scope
                .grant_file(
                    RawSourceKind::Dependency,
                    "npm:manifest",
                    &self.path,
                    "package.json",
                    4096,
                )
                .unwrap();
        }
        scope
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn requested(item: &str) -> Vec<RequestedSource> {
    vec![RequestedSource {
        kind: RawSourceKind::Dependency,
        item: item.into(),
    }]
}
fn request(run: &str, source: &str) -> CollectionRequest {
    CollectionRequest {
        run: CollectionRunId::new(run).unwrap(),
        sources: requested(source),
        limits: RawLimits::default(),
        options: Default::default(),
    }
}
fn collect_both(scope: &CollectionScope, lock_item: &str) -> InventorySnapshot {
    collect_both_with_root(scope, lock_item, true, None)
}

fn collect_both_with_root(
    scope: &CollectionScope,
    lock_item: &str,
    retain_real_root: bool,
    drop_path: Option<&str>,
) -> InventorySnapshot {
    let lock = NpmLockfileCollector::new(scope, "2026-10-11T12:00:00Z");
    let manifest = NpmManifestCollector::new(scope, "2026-10-11T12:00:00Z");
    let lock_descriptor = lock.descriptor();
    let manifest_descriptor = manifest.descriptor();
    let identity = IdentityContext::new(scope.id().as_str()).unwrap();
    let registry = Registry::builtin();
    let lock_run = CollectionRunId::new("run-npm-lock").unwrap();
    let manifest_run = CollectionRunId::new("run-npm-manifest").unwrap();
    let lock_sources = requested(lock_item);
    let manifest_sources = requested("npm:manifest");
    let cancel = CancellationToken::default();
    let mut lock_outcome =
        collect_scoped(scope, &lock, request("run-npm-lock", lock_item), &cancel).unwrap();
    if !retain_real_root {
        // Simulate legacy/tampered collector output: a matching installed app
        // record must not substitute for the true package-lock root event.
        lock_outcome.observations.retain(|observation| {
            observation
                .attributes
                .get("npm:lockfile-path")
                .map(String::as_str)
                != Some("npm:root")
        });
    }
    if let Some(path) = drop_path {
        lock_outcome.observations.retain(|obs| {
            obs.attributes.get("npm:lockfile-path").map(String::as_str) != Some(path)
        });
    }
    let manifest_outcome = collect_scoped(
        scope,
        &manifest,
        request("run-npm-manifest", "npm:manifest"),
        &cancel,
    )
    .unwrap();
    normalize_batch(
        vec![
            BatchRun {
                input: PipelineInput {
                    scope,
                    identity: &identity,
                    registry: &registry,
                    expected_descriptor: &lock_descriptor,
                    expected_run: &lock_run,
                    sources: &lock_sources,
                    raw_limits: RawLimits::default(),
                    inventory_limits: InventoryLimits::default(),
                    started_at: "2026-10-11T11:59:00Z",
                    ended_at: "2026-10-11T12:01:00Z",
                },
                outcome: lock_outcome,
            },
            BatchRun {
                input: PipelineInput {
                    scope,
                    identity: &identity,
                    registry: &registry,
                    expected_descriptor: &manifest_descriptor,
                    expected_run: &manifest_run,
                    sources: &manifest_sources,
                    raw_limits: RawLimits::default(),
                    inventory_limits: InventoryLimits::default(),
                    started_at: "2026-10-11T11:59:00Z",
                    ended_at: "2026-10-11T12:01:00Z",
                },
                outcome: manifest_outcome,
            },
        ],
        BatchLimits::default(),
    )
    .unwrap()
}

fn project(
    snapshot: &InventorySnapshot,
    scope: &CollectionScope,
) -> Result<InventorySnapshot, NpmReconciliationError> {
    project_npm_direct_edges(
        snapshot,
        scope,
        "npm:manifest",
        "npm:lock",
        RawLimits::default(),
        InventoryLimits::default(),
    )
}

fn transitive(
    snapshot: &InventorySnapshot,
    scope: &CollectionScope,
) -> Result<InventorySnapshot, NpmReconciliationError> {
    project_npm_transitive_edges(
        snapshot,
        scope,
        "npm:manifest",
        "npm:lock",
        RawLimits::default(),
        InventoryLimits::default(),
    )
}
fn extension_paths(snapshot: &InventorySnapshot) -> std::collections::BTreeSet<String> {
    snapshot
        .assets
        .values()
        .filter(|asset| {
            matches!(&asset.kind, AssetKind::Extension {
            namespace, kind
        } if namespace == "cryptomap:npm-install" && kind == "installed-dependency:v1")
        })
        .map(|asset| asset.extensions["npm:install-path"].clone())
        .collect()
}

#[test]
fn two_source_npm_transitive_edges_are_persisted_and_replay_stably() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let source = collect_both(&scope, "npm:lock");
    let direct_only = project(&source, &scope).unwrap();
    assert_eq!(direct_only.relationships.len(), 2);
    let projected = transitive(&source, &scope).unwrap();
    projected
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    assert_eq!(source.assets.len(), 5);
    assert_eq!(source.evidence.len(), 8);
    assert_eq!(projected.assets.len(), 10);
    assert_eq!(projected.relationships.len(), 6);
    assert_eq!(projected.schema_version, source.schema_version);
    assert_eq!(projected.observations, source.observations);
    assert_eq!(projected.evidence, source.evidence);
    for (id, asset) in &source.assets {
        assert_eq!(&projected.assets[id], asset);
    }
    assert_eq!(transitive(&source, &scope).unwrap(), projected);
    let exact = InventoryLimits {
        assets: projected.assets.len(),
        relationships: projected.relationships.len(),
        ..InventoryLimits::default()
    };
    assert_eq!(
        project_npm_transitive_edges(
            &projected,
            &scope,
            "npm:manifest",
            "npm:lock",
            RawLimits::default(),
            exact
        )
        .unwrap(),
        projected
    );

    let paths = extension_paths(&projected);
    assert_eq!(
        paths,
        std::collections::BTreeSet::from([
            "npm:root".into(),
            "node_modules/a".into(),
            "node_modules/b".into(),
            "node_modules/shared".into(),
            "node_modules/b/node_modules/shared".into(),
        ])
    );
    let mut pairs = std::collections::BTreeSet::new();
    for edge in projected.relationships.values() {
        if let (Some(a), Some(b)) = (
            projected.assets[&edge.from]
                .extensions
                .get("npm:install-path"),
            projected.assets[&edge.to]
                .extensions
                .get("npm:install-path"),
        ) {
            assert_eq!(edge.kind, RelationshipKind::DependsOn);
            assert!(edge.evidence.len() >= 2);
            for id in &edge.evidence {
                let ev = &projected.evidence[id];
                assert_eq!(ev.collector.as_str(), "cryptomap:npm-lockfile");
                assert_eq!(ev.collector_version, "0.2.0");
                assert_eq!(ev.source_sha256.as_ref().map(String::len), Some(64));
            }
            pairs.insert((a.clone(), b.clone()));
        }
    }
    assert_eq!(
        pairs,
        std::collections::BTreeSet::from([
            ("npm:root".into(), "node_modules/a".into()),
            ("npm:root".into(), "node_modules/b".into()),
            ("node_modules/a".into(), "node_modules/shared".into()),
            (
                "node_modules/b".into(),
                "node_modules/b/node_modules/shared".into()
            ),
        ])
    );
    let json = serde_json::to_string(&projected).unwrap();
    assert_eq!(
        InventorySnapshot::from_json_verified_for_scope(
            &json,
            scope.id(),
            InventoryLimits::default()
        )
        .unwrap(),
        projected
    );
}

#[test]
fn same_name_and_version_different_install_paths_have_distinct_canonical_ids() {
    let changed = LOCK
        .replace(r#""shared":"2.0.0""#, r#""shared":"1.0.0""#)
        .replace(
            r#""node_modules/b/node_modules/shared":{"version":"2.0.0"}"#,
            r#""node_modules/b/node_modules/shared":{"version":"1.0.0"}"#,
        );
    assert_ne!(changed, LOCK);
    let fixture = Fixture::new(MANIFEST, &changed);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let projected = transitive(&collect_both(&scope, "npm:lock"), &scope).unwrap();
    let matching: Vec<_> = projected
        .assets
        .values()
        .filter(|asset| {
            asset
                .extensions
                .get("npm:name")
                .is_some_and(|name| name == "shared")
                && asset
                    .extensions
                    .get("npm:version")
                    .is_some_and(|version| version == "1.0.0")
        })
        .collect();
    assert_eq!(matching.len(), 2);
    assert_ne!(matching[0].id, matching[1].id);
    assert_ne!(
        matching[0].extensions["npm:install-path"],
        matching[1].extensions["npm:install-path"]
    );
    assert_eq!(projected.relationships.len(), 6);
}

#[test]
fn missing_nested_lock_observation_and_cross_tenant_fail_closed() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let missing = collect_both_with_root(
        &scope,
        "npm:lock",
        true,
        Some("node_modules/b/node_modules/shared"),
    );
    missing
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    assert_eq!(
        transitive(&missing, &scope),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let full = collect_both(&scope, "npm:lock");
    let other = fixture.scope("tenant-b", true, "npm:lock");
    assert_eq!(
        transitive(&full, &other),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let other_item = fixture.scope("tenant-a", true, "npm:other");
    let other_snapshot = collect_both(&other_item, "npm:other");
    assert_eq!(
        transitive(&other_snapshot, &scope),
        Err(NpmReconciliationError::UnboundEvidence)
    );
}

#[test]
fn stale_manifest_and_lockfile_evidence_cannot_be_reused() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let original = collect_both(&scope, "npm:lock");
    let changed_manifest = Fixture::new(&format!("{MANIFEST} "), LOCK);
    assert_eq!(
        transitive(
            &original,
            &changed_manifest.scope("tenant-a", true, "npm:lock")
        ),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let changed_lock = Fixture::new(MANIFEST, &format!("{LOCK} "));
    assert_eq!(
        transitive(&original, &changed_lock.scope("tenant-a", true, "npm:lock")),
        Err(NpmReconciliationError::UnboundEvidence)
    );
}

#[test]
fn partial_lock_run_cannot_attest_canonical_transitive_installations() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let original = collect_both(&scope, "npm:lock");
    let mut builder = InventoryBuilder::new();
    for run in original.runs.values() {
        let mut copied = run.clone();
        if copied.id.as_str() == "run-npm-lock" {
            copied.completeness = RunCompleteness::Partial;
        }
        builder.add_run(copied).unwrap();
    }
    for asset in original.assets.values() {
        builder.add_asset(asset.clone()).unwrap();
    }
    for evidence in original.evidence.values() {
        builder.add_evidence(evidence.clone()).unwrap();
    }
    for observation in original.observations.values() {
        builder.add_observation(observation.clone()).unwrap();
    }
    for relationship in original.relationships.values() {
        builder.add_relationship(relationship.clone()).unwrap();
    }
    for (item, state) in &original.coverage {
        builder.set_coverage(item.clone(), *state);
    }
    for coverage in &original.coverage_records {
        builder.add_coverage_record(coverage.clone());
    }
    let partial = builder.finalize(InventoryLimits::default()).unwrap();
    partial
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    assert_eq!(
        transitive(&partial, &scope),
        Err(NpmReconciliationError::UnboundEvidence)
    );
}

#[test]
fn zero_asset_and_relationship_budgets_reject_without_partial_projection() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let original = collect_both(&scope, "npm:lock");
    let insufficient = InventoryLimits {
        assets: original.assets.len(),
        ..InventoryLimits::default()
    };
    assert_eq!(
        project_npm_transitive_edges(
            &original,
            &scope,
            "npm:manifest",
            "npm:lock",
            RawLimits::default(),
            insufficient
        ),
        Err(NpmReconciliationError::ResourceLimit)
    );
    let relationships = InventoryLimits {
        relationships: 2,
        ..InventoryLimits::default()
    };
    assert_eq!(
        project_npm_transitive_edges(
            &original,
            &scope,
            "npm:manifest",
            "npm:lock",
            RawLimits::default(),
            relationships
        ),
        Err(NpmReconciliationError::ResourceLimit)
    );
}

#[test]
fn checkpoint_is_stable_serializable_and_revalidates_current_graph() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let input = collect_both(&scope, "npm:lock");
    // Never checkpoint a still-unprojected source snapshot.
    assert_eq!(
        checkpoint_npm_projection(
            &input,
            &scope,
            "npm:manifest",
            "npm:lock",
            RawLimits::default(),
            InventoryLimits::default()
        ),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let projected = transitive(&input, &scope).unwrap();
    let make = || {
        checkpoint_npm_projection(
            &projected,
            &scope,
            "npm:manifest",
            "npm:lock",
            RawLimits::default(),
            InventoryLimits::default(),
        )
    };
    let first = make().unwrap();
    assert_eq!(first, make().unwrap());
    assert_eq!(first.version, 1);
    assert_eq!(first.scope, "tenant-a");
    assert_eq!(first.manifest_sha256.len(), 64);
    assert_eq!(first.lock_sha256.len(), 64);
    assert_eq!(first.fingerprint.len(), 71);
    assert!(!format!("{first:?}").contains("registry.example"));
    let json = serde_json::to_string(&first).unwrap();
    let restored: cryptomap::collectors::dependency::npm_checkpoint::NpmProjectionCheckpoint =
        serde_json::from_str(&json).unwrap();
    assert_eq!(restored, first);
    verify_npm_checkpoint(
        &restored,
        &projected,
        &scope,
        RawLimits::default(),
        InventoryLimits::default(),
    )
    .unwrap();
}

#[test]
fn checkpoint_rejects_obsolete_installed_asset_even_when_new_graph_is_present() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let valid = transitive(&collect_both(&scope, "npm:lock"), &scope).unwrap();
    let mut obsolete = valid
        .assets
        .values()
        .find(|asset| {
            asset
                .extensions
                .get("npm:install-path")
                .is_some_and(|path| path == "node_modules/shared")
        })
        .unwrap()
        .clone();
    obsolete
        .extensions
        .insert("npm:install-path".into(), "node_modules/removed".into());
    let identity = IdentityContext::new(scope.id().as_str())
        .unwrap()
        .with_use_site("npm-install:v1:obsolete-fixture")
        .unwrap();
    obsolete.id = cryptomap::AssetId::from_kind(&obsolete.kind, &identity).unwrap();
    let mut builder = InventoryBuilder::new();
    for run in valid.runs.values() {
        builder.add_run(run.clone()).unwrap();
    }
    for asset in valid.assets.values() {
        builder.add_asset(asset.clone()).unwrap();
    }
    builder.add_asset(obsolete).unwrap();
    for evidence in valid.evidence.values() {
        builder.add_evidence(evidence.clone()).unwrap();
    }
    for observation in valid.observations.values() {
        builder.add_observation(observation.clone()).unwrap();
    }
    for relation in valid.relationships.values() {
        builder.add_relationship(relation.clone()).unwrap();
    }
    for (item, state) in &valid.coverage {
        builder.set_coverage(item.clone(), *state);
    }
    for record in &valid.coverage_records {
        builder.add_coverage_record(record.clone());
    }
    let stale = builder.finalize(InventoryLimits::default()).unwrap();
    stale
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    assert_eq!(
        checkpoint_npm_projection(
            &stale,
            &scope,
            "npm:manifest",
            "npm:lock",
            RawLimits::default(),
            InventoryLimits::default()
        ),
        Err(NpmReconciliationError::UnboundEvidence)
    );
}

#[test]
fn checkpoint_rejects_source_mutation_cross_tenant_and_tampering() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let projected = transitive(&collect_both(&scope, "npm:lock"), &scope).unwrap();
    let checkpoint = checkpoint_npm_projection(
        &projected,
        &scope,
        "npm:manifest",
        "npm:lock",
        RawLimits::default(),
        InventoryLimits::default(),
    )
    .unwrap();
    let verify =
        |token: &cryptomap::collectors::dependency::npm_checkpoint::NpmProjectionCheckpoint| {
            verify_npm_checkpoint(
                token,
                &projected,
                &scope,
                RawLimits::default(),
                InventoryLimits::default(),
            )
        };
    let mut forged = checkpoint.clone();
    forged.lock_sha256 = "0".repeat(64);
    assert_eq!(
        verify(&forged),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let mut forged = checkpoint.clone();
    forged.snapshot_id = cryptomap::SnapshotId::new(format!("sha256:{}", "0".repeat(64))).unwrap();
    assert_eq!(
        verify(&forged),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let mut forged = checkpoint.clone();
    forged.version = 2;
    assert_eq!(
        verify(&forged),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let mut forged = checkpoint.clone();
    forged.manifest_item = "npm:other".into();
    assert_eq!(
        verify(&forged),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let other_scope = fixture.scope("tenant-b", true, "npm:lock");
    assert_eq!(
        verify_npm_checkpoint(
            &checkpoint,
            &projected,
            &other_scope,
            RawLimits::default(),
            InventoryLimits::default()
        ),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let new_manifest = Fixture::new(&format!("{MANIFEST} "), LOCK);
    assert_eq!(
        verify_npm_checkpoint(
            &checkpoint,
            &projected,
            &new_manifest.scope("tenant-a", true, "npm:lock"),
            RawLimits::default(),
            InventoryLimits::default()
        ),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let new_lock = Fixture::new(MANIFEST, &format!("{LOCK} "));
    assert_eq!(
        verify_npm_checkpoint(
            &checkpoint,
            &projected,
            &new_lock.scope("tenant-a", true, "npm:lock"),
            RawLimits::default(),
            InventoryLimits::default()
        ),
        Err(NpmReconciliationError::UnboundEvidence)
    );
}

#[test]
fn incremental_reuse_requires_current_complete_graph_and_matching_sources() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let projected = transitive(&collect_both(&scope, "npm:lock"), &scope).unwrap();
    let checkpoint = checkpoint_npm_projection(
        &projected,
        &scope,
        "npm:manifest",
        "npm:lock",
        RawLimits::default(),
        InventoryLimits::default(),
    )
    .unwrap();
    let plan = || {
        plan_npm_incremental(
            &checkpoint,
            &projected,
            &scope,
            RawLimits::default(),
            InventoryLimits::default(),
        )
    };
    let expected = NpmIncrementalPlan::ReuseVerified {
        snapshot_id: projected.id.clone(),
    };
    assert_eq!(plan().unwrap(), expected);
    assert_eq!(plan().unwrap(), expected);
    let json = serde_json::to_string(&expected).unwrap();
    let parsed: NpmIncrementalPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, expected);
    assert!(!json.contains("token"));
    assert_eq!(
        projected,
        transitive(&collect_both(&scope, "npm:lock"), &scope).unwrap()
    );
}

#[test]
fn incremental_changed_files_trigger_exact_invalidation_without_cache_reuse() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let projected = transitive(&collect_both(&scope, "npm:lock"), &scope).unwrap();
    let checkpoint = checkpoint_npm_projection(
        &projected,
        &scope,
        "npm:manifest",
        "npm:lock",
        RawLimits::default(),
        InventoryLimits::default(),
    )
    .unwrap();
    for (manifest, lock, expected) in [
        (
            format!("{MANIFEST} "),
            LOCK.to_owned(),
            NpmIncrementalPlan::Recollect {
                manifest_changed: true,
                lock_changed: false,
            },
        ),
        (
            MANIFEST.to_owned(),
            format!("{LOCK} "),
            NpmIncrementalPlan::Recollect {
                manifest_changed: false,
                lock_changed: true,
            },
        ),
        (
            format!("{MANIFEST} "),
            format!("{LOCK} "),
            NpmIncrementalPlan::Recollect {
                manifest_changed: true,
                lock_changed: true,
            },
        ),
    ] {
        let changed = Fixture::new(&manifest, &lock);
        let changed_scope = changed.scope("tenant-a", true, "npm:lock");
        assert_eq!(
            plan_npm_incremental(
                &checkpoint,
                &projected,
                &changed_scope,
                RawLimits::default(),
                InventoryLimits::default()
            )
            .unwrap(),
            expected
        );
        // Invalidation itself conveys no valid new evidence and never mints
        // a new checkpoint against the old canonical snapshot.
        assert!(
            checkpoint_npm_projection(
                &projected,
                &changed_scope,
                "npm:manifest",
                "npm:lock",
                RawLimits::default(),
                InventoryLimits::default()
            )
            .is_err()
        );
    }
}

#[test]
fn incremental_plan_rejects_cache_poisoning_tenant_mismatch_and_missing_grants() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let projected = transitive(&collect_both(&scope, "npm:lock"), &scope).unwrap();
    let checkpoint = checkpoint_npm_projection(
        &projected,
        &scope,
        "npm:manifest",
        "npm:lock",
        RawLimits::default(),
        InventoryLimits::default(),
    )
    .unwrap();
    let plan =
        |token: &cryptomap::collectors::dependency::npm_checkpoint::NpmProjectionCheckpoint,
         snapshot: &InventorySnapshot,
         scoped: &CollectionScope,
         limits: RawLimits| {
            plan_npm_incremental(token, snapshot, scoped, limits, InventoryLimits::default())
        };
    let mut tampered = checkpoint.clone();
    tampered.fingerprint = format!("sha256:{}", "0".repeat(64));
    assert_eq!(
        plan(&tampered, &projected, &scope, RawLimits::default()),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let mut tampered = checkpoint.clone();
    tampered.lock_sha256 = "0".repeat(64);
    assert_eq!(
        plan(&tampered, &projected, &scope, RawLimits::default()),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let mut poisoned = projected.clone();
    poisoned
        .assets
        .values_mut()
        .next()
        .unwrap()
        .extensions
        .insert("invalid:cache".into(), "poisoned".into());
    assert_eq!(
        plan(&checkpoint, &poisoned, &scope, RawLimits::default()),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let foreign = fixture.scope("tenant-b", true, "npm:lock");
    assert_eq!(
        plan(&checkpoint, &projected, &foreign, RawLimits::default()),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let ungranted = fixture.scope("tenant-a", false, "npm:lock");
    assert_eq!(
        plan(&checkpoint, &projected, &ungranted, RawLimits::default()),
        Err(NpmReconciliationError::UnauthorizedSource)
    );
    let budget = RawLimits {
        total_bytes: MANIFEST.len() + LOCK.len() - 1,
        record_bytes: 128,
        field_bytes: 64,
        ..RawLimits::default()
    };
    assert_eq!(
        plan(&checkpoint, &projected, &scope, budget),
        Err(NpmReconciliationError::ResourceLimit)
    );
}
