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

#[test]
fn authorized_stream_digest_enforces_stricter_per_call_budget() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let manifest = scope
        .open_file(RawSourceKind::Dependency, "npm:manifest")
        .unwrap();
    let (sha, bytes) = manifest.sha256_bounded(MANIFEST.len()).unwrap();
    assert_eq!(bytes, MANIFEST.len());
    assert_eq!(sha.len(), 64);
    assert!(matches!(
        manifest.sha256_bounded(MANIFEST.len() - 1),
        Err(cryptomap::scope::ScopeError::ResourceLimit)
    ));
    let lock = scope
        .open_file(RawSourceKind::Dependency, "npm:lock")
        .unwrap();
    let (sha, bytes) = lock.sha256_bounded(LOCK.len()).unwrap();
    assert_eq!(bytes, LOCK.len());
    assert_eq!(sha.len(), 64);
    assert!(matches!(
        lock.sha256_bounded(1),
        Err(cryptomap::scope::ScopeError::ResourceLimit)
    ));
}

#[test]
fn generation_handoff_keeps_checkpoint_and_snapshot_in_one_immutable_view() {
    use cryptomap::collectors::dependency::npm_generation::NpmGenerationStore;
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
    let store = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    assert!(store.current().unwrap().is_none());
    let first = store
        .publish(
            checkpoint.clone(),
            projected.clone(),
            &scope,
            None,
            RawLimits::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    assert_eq!(first.sequence(), 1);
    assert_eq!(first.snapshot(), &projected);
    assert_eq!(first.checkpoint(), &checkpoint);
    let reader = store.current().unwrap().unwrap();
    assert!(std::sync::Arc::ptr_eq(&reader, &first));

    // A replacement is a single pointer swap, not a graph mutation.
    let second = store
        .publish(
            checkpoint.clone(),
            projected.clone(),
            &scope,
            Some(first.sequence()),
            RawLimits::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    assert_eq!(second.sequence(), 2);
    assert_eq!(store.current().unwrap().unwrap().sequence(), 2);
    assert_eq!(reader.sequence(), 1);
    assert_eq!(reader.snapshot(), &projected);
    assert_eq!(reader.checkpoint(), &checkpoint);
    assert_eq!(
        store.publish(
            checkpoint.clone(),
            projected.clone(),
            &scope,
            Some(1),
            RawLimits::default(),
            InventoryLimits::default(),
        ),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    assert_eq!(store.current().unwrap().unwrap().sequence(), 2);
}

#[test]
fn generation_handoff_rejects_tampering_cross_tenant_and_ungranted_sources() {
    use cryptomap::collectors::dependency::npm_generation::NpmGenerationStore;
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
    assert!(NpmGenerationStore::new(&scope, "npm:manifest", "npm:manifest").is_err());
    assert!(NpmGenerationStore::new(&scope, "", "npm:lock").is_err());
    let store = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    let publish = |token, snapshot, authorized: &CollectionScope| {
        store.publish(
            token,
            snapshot,
            authorized,
            None,
            RawLimits::default(),
            InventoryLimits::default(),
        )
    };
    let mut tampered = checkpoint.clone();
    tampered.fingerprint = "sha256:invalid".to_owned();
    assert_eq!(
        publish(tampered, projected.clone(), &scope),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let mut poisoned = projected.clone();
    poisoned
        .assets
        .values_mut()
        .next()
        .unwrap()
        .extensions
        .insert("invalid:cache".to_owned(), "poisoned".to_owned());
    assert_eq!(
        publish(checkpoint.clone(), poisoned, &scope),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let foreign_scope = fixture.scope("tenant-b", true, "npm:lock");
    assert_eq!(
        publish(checkpoint.clone(), projected.clone(), &foreign_scope),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let ungranted = fixture.scope("tenant-a", false, "npm:lock");
    assert_eq!(
        publish(checkpoint.clone(), projected.clone(), &ungranted),
        Err(NpmReconciliationError::UnauthorizedSource)
    );
    let changed = Fixture::new(&format!("{MANIFEST} "), LOCK);
    assert_eq!(
        publish(
            checkpoint.clone(),
            projected.clone(),
            &changed.scope("tenant-a", true, "npm:lock"),
        ),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    assert!(store.current().unwrap().is_none());

    let valid = publish(checkpoint.clone(), projected.clone(), &scope).unwrap();
    assert_eq!(valid.sequence(), 1);
    let result = store.publish(
        checkpoint,
        projected,
        &scope,
        Some(0),
        RawLimits::default(),
        InventoryLimits::default(),
    );
    assert_eq!(result, Err(NpmReconciliationError::UnboundEvidence));
    assert!(std::sync::Arc::ptr_eq(
        &valid,
        &store.current().unwrap().unwrap()
    ));
}

#[test]
fn generation_handoff_concurrent_writers_are_compare_and_swap_serialized() {
    use cryptomap::collectors::dependency::npm_generation::NpmGenerationStore;
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
    let store = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    std::thread::scope(|threads| {
        let left = threads.spawn(|| {
            store.publish(
                checkpoint.clone(),
                projected.clone(),
                &scope,
                None,
                RawLimits::default(),
                InventoryLimits::default(),
            )
        });
        let right = threads.spawn(|| {
            store.publish(
                checkpoint.clone(),
                projected.clone(),
                &scope,
                None,
                RawLimits::default(),
                InventoryLimits::default(),
            )
        });
        let results = [left.join().unwrap(), right.join().unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(NpmReconciliationError::UnboundEvidence)))
                .count(),
            1
        );
        let live = store.current().unwrap().unwrap();
        assert_eq!(live.sequence(), 1);
        assert_eq!(live.checkpoint(), &checkpoint);
        assert_eq!(live.snapshot(), &projected);
    });
}

#[test]
fn generation_recovery_roundtrip_is_bounded_revalidated_and_deterministic() {
    use cryptomap::collectors::dependency::{
        npm_generation::NpmGenerationStore,
        npm_generation_codec::{encode_npm_generation, restore_npm_generation},
    };
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
    let original = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    let published = original
        .publish(
            checkpoint.clone(),
            projected.clone(),
            &scope,
            None,
            RawLimits::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    let encode = || encode_npm_generation(&published, 256 * 1024).unwrap();
    let bytes = encode();
    assert_eq!(bytes, encode());
    let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(envelope["version"], 1);
    assert!(envelope.get("sequence").is_none());
    assert_eq!(
        envelope["checkpoint"]["snapshot_id"],
        serde_json::to_value(&projected.id).unwrap()
    );
    assert_eq!(
        encode_npm_generation(&published, bytes.len()).unwrap(),
        bytes
    );
    assert_eq!(
        encode_npm_generation(&published, bytes.len() - 1),
        Err(NpmReconciliationError::ResourceLimit),
    );

    let restored_store = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    let restored = restore_npm_generation(
        &restored_store,
        &bytes,
        &scope,
        None,
        bytes.len(),
        RawLimits::default(),
        InventoryLimits::default(),
    )
    .unwrap();
    assert_eq!(restored.sequence(), 1);
    assert_eq!(restored.snapshot(), &projected);
    assert_eq!(restored.checkpoint(), &checkpoint);
    assert_eq!(
        encode_npm_generation(&restored, bytes.len()).unwrap(),
        bytes
    );
    assert_eq!(
        restore_npm_generation(
            &restored_store,
            &bytes,
            &scope,
            None,
            bytes.len(),
            RawLimits::default(),
            InventoryLimits::default(),
        ),
        Err(NpmReconciliationError::UnboundEvidence),
    );
    assert_eq!(restored_store.current().unwrap().unwrap().sequence(), 1);
    let next = restore_npm_generation(
        &restored_store,
        &bytes,
        &scope,
        Some(1),
        bytes.len(),
        RawLimits::default(),
        InventoryLimits::default(),
    )
    .unwrap();
    assert_eq!(next.sequence(), 2);
    assert_eq!(restored.sequence(), 1);
    assert_eq!(restored.checkpoint(), &checkpoint);
    assert!(std::sync::Arc::ptr_eq(
        &next,
        &restored_store.current().unwrap().unwrap()
    ));
}

#[test]
fn generation_recovery_rejects_malformed_duplicate_or_foreign_envelopes() {
    use cryptomap::collectors::dependency::{
        npm_generation::NpmGenerationStore,
        npm_generation_codec::{encode_npm_generation, restore_npm_generation},
    };
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
    let seed = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    let published = seed
        .publish(
            checkpoint,
            projected,
            &scope,
            None,
            RawLimits::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    let bytes = encode_npm_generation(&published, 256 * 1024).unwrap();
    let str_json = String::from_utf8(bytes.clone()).unwrap();
    let duplicate = str_json.replacen(r#"{"version":1,"#, r#"{"version":1,"version":1,"#, 1);
    assert_ne!(duplicate, str_json);
    let mut extra: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    extra["unexpected"] = serde_json::json!("untrusted");
    let extra_json = serde_json::to_vec(&extra).unwrap();
    let mut unsupported: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unsupported["version"] = serde_json::json!(2);
    let unsupported_json = serde_json::to_vec(&unsupported).unwrap();
    let mut tampered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    tampered["checkpoint"]["fingerprint"] = serde_json::json!("sha256:fake");
    let tampered_json = serde_json::to_vec(&tampered).unwrap();

    let restore = |input: &[u8], authorized: &CollectionScope| {
        let store = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
        let result = restore_npm_generation(
            &store,
            input,
            authorized,
            None,
            256 * 1024,
            RawLimits::default(),
            InventoryLimits::default(),
        );
        assert!(store.current().unwrap().is_none());
        result
    };
    for candidate in [
        duplicate.as_bytes(),
        extra_json.as_slice(),
        unsupported_json.as_slice(),
        tampered_json.as_slice(),
        b"{\"version\":1,",
        b"\0binary",
    ] {
        assert_eq!(
            restore(candidate, &scope),
            Err(NpmReconciliationError::UnboundEvidence)
        );
    }
    assert_eq!(
        restore(&bytes, &fixture.scope("tenant-b", true, "npm:lock")),
        Err(NpmReconciliationError::UnboundEvidence),
    );
    assert_eq!(
        restore(&bytes, &fixture.scope("tenant-a", false, "npm:lock")),
        Err(NpmReconciliationError::UnauthorizedSource),
    );
    let changed = Fixture::new(MANIFEST, &format!("{LOCK} "));
    assert_eq!(
        restore(&bytes, &changed.scope("tenant-a", true, "npm:lock")),
        Err(NpmReconciliationError::UnboundEvidence),
    );
    let store = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    assert_eq!(
        restore_npm_generation(
            &store,
            &bytes,
            &scope,
            None,
            bytes.len() - 1,
            RawLimits::default(),
            InventoryLimits::default(),
        ),
        Err(NpmReconciliationError::ResourceLimit)
    );
    assert!(store.current().unwrap().is_none());
}

#[test]
fn generation_recovery_rejects_duplicate_nested_evidence_and_noncanonical_snapshot() {
    use cryptomap::collectors::dependency::{
        npm_generation::NpmGenerationStore,
        npm_generation_codec::{encode_npm_generation, restore_npm_generation},
    };
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
    let seed = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    let published = seed
        .publish(
            checkpoint,
            projected,
            &scope,
            None,
            RawLimits::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    let bytes = encode_npm_generation(&published, 256 * 1024).unwrap();
    let original = String::from_utf8(bytes.clone()).unwrap();
    let nested = original.replacen(
        r#""checkpoint":{"version":1,"#,
        r#""checkpoint":{"version":1,"version":1,"#,
        1,
    );
    assert_ne!(nested, original);
    let mut poisoned: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    poisoned["snapshot"]["schema_version"] = serde_json::json!(999);
    let poisoned_json = serde_json::to_vec(&poisoned).unwrap();
    let store = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    for candidate in [nested.as_bytes(), poisoned_json.as_slice()] {
        assert_eq!(
            restore_npm_generation(
                &store,
                candidate,
                &scope,
                None,
                256 * 1024,
                RawLimits::default(),
                InventoryLimits::default()
            ),
            Err(NpmReconciliationError::UnboundEvidence)
        );
        assert!(store.current().unwrap().is_none());
    }
}

#[test]
fn pinned_recovery_requires_external_snapshot_and_checkpoint_anchor() {
    use cryptomap::collectors::dependency::{
        npm_generation::NpmGenerationStore,
        npm_generation_codec::{
            NpmRecoveryLimits, NpmTrustedRecoveryAnchor, encode_npm_generation,
            restore_npm_generation_pinned,
        },
    };
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let snapshot = transitive(&collect_both(&scope, "npm:lock"), &scope).unwrap();
    let checkpoint = checkpoint_npm_projection(
        &snapshot,
        &scope,
        "npm:manifest",
        "npm:lock",
        RawLimits::default(),
        InventoryLimits::default(),
    )
    .unwrap();
    assert!(NpmTrustedRecoveryAnchor::new(snapshot.id.clone(), "sha256:bad").is_err());
    assert!(
        NpmTrustedRecoveryAnchor::new(snapshot.id.clone(), format!("sha256:{}", "F".repeat(64)),)
            .is_err()
    );
    let anchor =
        NpmTrustedRecoveryAnchor::new(snapshot.id.clone(), checkpoint.fingerprint.clone()).unwrap();
    assert_eq!(anchor.snapshot_id(), &snapshot.id);
    assert_eq!(anchor.checkpoint_fingerprint(), checkpoint.fingerprint);
    let seed = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    let published = seed
        .publish(
            checkpoint,
            snapshot.clone(),
            &scope,
            None,
            RawLimits::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    let bytes = encode_npm_generation(&published, 256 * 1024).unwrap();
    let target = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    let restore = |pin: &NpmTrustedRecoveryAnchor, authorized: &CollectionScope| {
        restore_npm_generation_pinned(
            &target,
            &bytes,
            pin,
            authorized,
            None,
            NpmRecoveryLimits {
                max_bytes: bytes.len(),
                raw: RawLimits::default(),
                inventory: InventoryLimits::default(),
            },
        )
    };
    let forged =
        NpmTrustedRecoveryAnchor::new(snapshot.id.clone(), format!("sha256:{}", "0".repeat(64)))
            .unwrap();
    assert_eq!(
        restore(&forged, &scope),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    assert!(target.current().unwrap().is_none());
    assert_eq!(
        restore(&anchor, &fixture.scope("tenant-a", false, "npm:lock")),
        Err(NpmReconciliationError::UnauthorizedSource)
    );
    assert!(target.current().unwrap().is_none());
    let recovered = restore(&anchor, &scope).unwrap();
    assert_eq!(recovered.snapshot(), &snapshot);
    assert_eq!(
        recovered.checkpoint().fingerprint,
        anchor.checkpoint_fingerprint()
    );
    assert_eq!(recovered.sequence(), 1);
    assert_eq!(
        restore(&anchor, &scope),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    assert!(std::sync::Arc::ptr_eq(
        &recovered,
        &target.current().unwrap().unwrap()
    ));
}

#[test]
fn pinned_recovery_blocks_valid_older_generation_when_files_are_rolled_back() {
    use cryptomap::collectors::dependency::{
        npm_generation::NpmGenerationStore,
        npm_generation_codec::{
            NpmRecoveryLimits, NpmTrustedRecoveryAnchor, encode_npm_generation,
            restore_npm_generation, restore_npm_generation_pinned,
        },
    };
    let old_fixture = Fixture::new(MANIFEST, LOCK);
    let old_scope = old_fixture.scope("tenant-a", true, "npm:lock");
    let old_snapshot = transitive(&collect_both(&old_scope, "npm:lock"), &old_scope).unwrap();
    let old_checkpoint = checkpoint_npm_projection(
        &old_snapshot,
        &old_scope,
        "npm:manifest",
        "npm:lock",
        RawLimits::default(),
        InventoryLimits::default(),
    )
    .unwrap();
    let old_seed = NpmGenerationStore::new(&old_scope, "npm:manifest", "npm:lock").unwrap();
    let old_generation = old_seed
        .publish(
            old_checkpoint,
            old_snapshot.clone(),
            &old_scope,
            None,
            RawLimits::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    let old_bytes = encode_npm_generation(&old_generation, 256 * 1024).unwrap();

    // A distinct legitimate generation from the same tenant/source grants:
    // source-byte changes alter the independently evidenced canonical digest.
    let new_fixture = Fixture::new(&format!("{MANIFEST} "), LOCK);
    let new_scope = new_fixture.scope("tenant-a", true, "npm:lock");
    let new_snapshot = transitive(&collect_both(&new_scope, "npm:lock"), &new_scope).unwrap();
    assert_ne!(new_snapshot.id, old_snapshot.id);
    let new_checkpoint = checkpoint_npm_projection(
        &new_snapshot,
        &new_scope,
        "npm:manifest",
        "npm:lock",
        RawLimits::default(),
        InventoryLimits::default(),
    )
    .unwrap();
    let anchor =
        NpmTrustedRecoveryAnchor::new(new_snapshot.id.clone(), new_checkpoint.fingerprint.clone())
            .unwrap();
    let new_seed = NpmGenerationStore::new(&new_scope, "npm:manifest", "npm:lock").unwrap();
    let new_generation = new_seed
        .publish(
            new_checkpoint,
            new_snapshot.clone(),
            &new_scope,
            None,
            RawLimits::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    let new_bytes = encode_npm_generation(&new_generation, 256 * 1024).unwrap();

    // The old bundle still passes ordinary integrity/source revalidation if
    // the attacker also reverts the two source files. A trusted independent
    // newer anchor must reject this otherwise-valid stale generation.
    let unsafe_target = NpmGenerationStore::new(&old_scope, "npm:manifest", "npm:lock").unwrap();
    assert!(
        restore_npm_generation(
            &unsafe_target,
            &old_bytes,
            &old_scope,
            None,
            256 * 1024,
            RawLimits::default(),
            InventoryLimits::default(),
        )
        .is_ok()
    );
    let pinned_target = NpmGenerationStore::new(&old_scope, "npm:manifest", "npm:lock").unwrap();
    assert_eq!(
        restore_npm_generation_pinned(
            &pinned_target,
            &old_bytes,
            &anchor,
            &old_scope,
            None,
            NpmRecoveryLimits {
                max_bytes: 256 * 1024,
                raw: RawLimits::default(),
                inventory: InventoryLimits::default(),
            },
        ),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    assert!(pinned_target.current().unwrap().is_none());
    let current_target = NpmGenerationStore::new(&new_scope, "npm:manifest", "npm:lock").unwrap();
    let current = restore_npm_generation_pinned(
        &current_target,
        &new_bytes,
        &anchor,
        &new_scope,
        None,
        NpmRecoveryLimits {
            max_bytes: 256 * 1024,
            raw: RawLimits::default(),
            inventory: InventoryLimits::default(),
        },
    )
    .unwrap();
    assert_eq!(current.snapshot(), &new_snapshot);
    assert_eq!(current.sequence(), 1);
}

#[test]
fn bounded_generation_io_roundtrip_revalidates_and_respects_exact_size() {
    use cryptomap::collectors::dependency::{
        npm_generation::NpmGenerationStore,
        npm_generation_codec::{NpmRecoveryLimits, NpmTrustedRecoveryAnchor},
        npm_generation_io::{
            read_bounded_npm_generation, restore_npm_generation_pinned_from_reader,
            write_bounded_npm_generation,
        },
    };
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let snapshot = transitive(&collect_both(&scope, "npm:lock"), &scope).unwrap();
    let checkpoint = checkpoint_npm_projection(
        &snapshot,
        &scope,
        "npm:manifest",
        "npm:lock",
        RawLimits::default(),
        InventoryLimits::default(),
    )
    .unwrap();
    let anchor =
        NpmTrustedRecoveryAnchor::new(snapshot.id.clone(), checkpoint.fingerprint.clone()).unwrap();
    let seed = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    let source = seed
        .publish(
            checkpoint.clone(),
            snapshot.clone(),
            &scope,
            None,
            RawLimits::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    let mut output = Vec::new();
    let size = write_bounded_npm_generation(&source, &mut output, 256 * 1024).unwrap();
    assert_eq!(size, output.len());
    assert_eq!(
        read_bounded_npm_generation(&mut std::io::Cursor::new(&output), size).unwrap(),
        output
    );
    let mut too_small = Vec::new();
    assert_eq!(
        write_bounded_npm_generation(&source, &mut too_small, size - 1),
        Err(NpmReconciliationError::ResourceLimit),
    );
    assert!(too_small.is_empty());

    let target = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    let limits = NpmRecoveryLimits {
        max_bytes: size,
        raw: RawLimits::default(),
        inventory: InventoryLimits::default(),
    };
    let restored = restore_npm_generation_pinned_from_reader(
        &target,
        &mut std::io::Cursor::new(&output),
        &anchor,
        &scope,
        None,
        limits,
    )
    .unwrap();
    assert_eq!(restored.sequence(), 1);
    assert_eq!(restored.snapshot(), &snapshot);
    assert_eq!(restored.checkpoint(), &checkpoint);
    assert_eq!(
        restore_npm_generation_pinned_from_reader(
            &target,
            &mut std::io::Cursor::new(&output),
            &anchor,
            &scope,
            None,
            limits,
        ),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    assert_eq!(target.current().unwrap().unwrap().sequence(), 1);
}

#[test]
fn bounded_generation_io_failures_do_not_publish_or_authorize_sources() {
    use cryptomap::collectors::dependency::{
        npm_generation::NpmGenerationStore,
        npm_generation_codec::{NpmRecoveryLimits, NpmTrustedRecoveryAnchor},
        npm_generation_io::{
            restore_npm_generation_pinned_from_reader, write_bounded_npm_generation,
        },
    };
    use std::io::{self, Read, Write};

    struct FailingSink {
        written: usize,
    }
    impl Write for FailingSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.written > 0 {
                return Err(io::Error::other("injected write failure"));
            }
            let n = bytes.len().min(8);
            self.written += n;
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let snapshot = transitive(&collect_both(&scope, "npm:lock"), &scope).unwrap();
    let checkpoint = checkpoint_npm_projection(
        &snapshot,
        &scope,
        "npm:manifest",
        "npm:lock",
        RawLimits::default(),
        InventoryLimits::default(),
    )
    .unwrap();
    let anchor =
        NpmTrustedRecoveryAnchor::new(snapshot.id.clone(), checkpoint.fingerprint.clone()).unwrap();
    let seed = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    let source = seed
        .publish(
            checkpoint,
            snapshot,
            &scope,
            None,
            RawLimits::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    let mut bytes = Vec::new();
    write_bounded_npm_generation(&source, &mut bytes, 256 * 1024).unwrap();
    let mut failing = FailingSink { written: 0 };
    assert_eq!(
        write_bounded_npm_generation(&source, &mut failing, 256 * 1024),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    assert_eq!(failing.written, 8);

    let target = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    let limits = NpmRecoveryLimits {
        max_bytes: bytes.len(),
        raw: RawLimits::default(),
        inventory: InventoryLimits::default(),
    };
    struct FailedReader(bool);
    impl Read for FailedReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.0 {
                return Err(io::Error::other("injected midstream read failure"));
            }
            self.0 = true;
            output[0] = b'{';
            Ok(1)
        }
    }
    assert_eq!(
        restore_npm_generation_pinned_from_reader(
            &target,
            &mut FailedReader(false),
            &anchor,
            &scope,
            None,
            limits,
        ),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    assert!(target.current().unwrap().is_none());
    let truncated = &bytes[..bytes.len() - 1];
    assert_eq!(
        restore_npm_generation_pinned_from_reader(
            &target,
            &mut std::io::Cursor::new(truncated),
            &anchor,
            &scope,
            None,
            limits,
        ),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let mut oversized = bytes.clone();
    oversized.push(b' ');
    assert_eq!(
        restore_npm_generation_pinned_from_reader(
            &target,
            &mut std::io::Cursor::new(&oversized),
            &anchor,
            &scope,
            None,
            limits,
        ),
        Err(NpmReconciliationError::ResourceLimit)
    );
    let denied = fixture.scope("tenant-a", false, "npm:lock");
    assert_eq!(
        restore_npm_generation_pinned_from_reader(
            &target,
            &mut std::io::Cursor::new(&bytes),
            &anchor,
            &denied,
            None,
            limits,
        ),
        Err(NpmReconciliationError::UnauthorizedSource)
    );
    assert!(target.current().unwrap().is_none());
}

#[test]
fn framed_generation_roundtrip_requires_pinned_source_and_rejects_replay() {
    use cryptomap::collectors::dependency::{
        npm_generation::NpmGenerationStore,
        npm_generation_codec::{NpmRecoveryLimits, NpmTrustedRecoveryAnchor},
        npm_generation_frame::{restore_framed_npm_generation_pinned, write_framed_npm_generation},
    };
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let snapshot = transitive(&collect_both(&scope, "npm:lock"), &scope).unwrap();
    let checkpoint = checkpoint_npm_projection(
        &snapshot,
        &scope,
        "npm:manifest",
        "npm:lock",
        RawLimits::default(),
        InventoryLimits::default(),
    )
    .unwrap();
    let anchor =
        NpmTrustedRecoveryAnchor::new(snapshot.id.clone(), checkpoint.fingerprint.clone()).unwrap();
    let seed = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    let original = seed
        .publish(
            checkpoint.clone(),
            snapshot.clone(),
            &scope,
            None,
            RawLimits::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    let mut framed = Vec::new();
    let size = write_framed_npm_generation(&original, &mut framed, 256 * 1024).unwrap();
    assert_eq!(size, framed.len());
    let limits = NpmRecoveryLimits {
        max_bytes: 256 * 1024,
        raw: RawLimits::default(),
        inventory: InventoryLimits::default(),
    };
    let target = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    let denied = fixture.scope("tenant-a", false, "npm:lock");
    assert_eq!(
        restore_framed_npm_generation_pinned(
            &target,
            &mut std::io::Cursor::new(&framed),
            &anchor,
            &denied,
            None,
            limits,
        ),
        Err(NpmReconciliationError::UnauthorizedSource)
    );
    assert!(target.current().unwrap().is_none());
    let mut damaged = framed.clone();
    damaged[16] ^= 0x80;
    assert_eq!(
        restore_framed_npm_generation_pinned(
            &target,
            &mut std::io::Cursor::new(damaged),
            &anchor,
            &scope,
            None,
            limits,
        ),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    assert!(target.current().unwrap().is_none());
    let restored = restore_framed_npm_generation_pinned(
        &target,
        &mut std::io::Cursor::new(&framed),
        &anchor,
        &scope,
        None,
        limits,
    )
    .unwrap();
    assert_eq!(restored.snapshot(), &snapshot);
    assert_eq!(restored.checkpoint(), &checkpoint);
    assert_eq!(restored.sequence(), 1);
    assert_eq!(
        restore_framed_npm_generation_pinned(
            &target,
            &mut std::io::Cursor::new(&framed),
            &anchor,
            &scope,
            None,
            limits,
        ),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    assert_eq!(target.current().unwrap().unwrap().sequence(), 1);
}

#[test]
fn immutable_recovery_slot_rejects_overwrites_and_recovers_verified_generation() {
    use cap_std::{ambient_authority, fs::Dir};
    use cryptomap::collectors::dependency::{
        npm_generation::NpmGenerationStore,
        npm_generation_codec::{NpmRecoveryLimits, NpmTrustedRecoveryAnchor},
        npm_generation_frame::restore_framed_npm_generation_pinned,
        npm_generation_slot::publish_immutable_npm_generation_slot,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    let location = std::env::temp_dir().join(format!(
        "cryptomap-foss322-slot-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&location).unwrap();
    let dir = Dir::open_ambient_dir(&location, ambient_authority()).unwrap();

    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let snapshot = transitive(&collect_both(&scope, "npm:lock"), &scope).unwrap();
    let checkpoint = checkpoint_npm_projection(
        &snapshot,
        &scope,
        "npm:manifest",
        "npm:lock",
        RawLimits::default(),
        InventoryLimits::default(),
    )
    .unwrap();
    let anchor =
        NpmTrustedRecoveryAnchor::new(snapshot.id.clone(), checkpoint.fingerprint.clone()).unwrap();
    let source = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    let generation = source
        .publish(
            checkpoint.clone(),
            snapshot.clone(),
            &scope,
            None,
            RawLimits::default(),
            InventoryLimits::default(),
        )
        .unwrap();

    // Invalid path input is rejected before touching the capability.
    assert_eq!(
        publish_immutable_npm_generation_slot(&dir, &generation, "../escaped", "slotA", 256 * 1024),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    assert_eq!(
        publish_immutable_npm_generation_slot(&dir, &generation, "stageA", "stageA", 256 * 1024),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    assert_eq!(
        publish_immutable_npm_generation_slot(&dir, &generation, "stageA", "slotA", 1),
        Err(NpmReconciliationError::ResourceLimit)
    );
    assert!(!location.join("stageA").exists());
    assert!(!location.join("slotA").exists());

    let len =
        publish_immutable_npm_generation_slot(&dir, &generation, "stageA", "slotA", 256 * 1024)
            .unwrap();
    let stored = std::fs::read(location.join("slotA")).unwrap();
    assert_eq!(stored.len(), len);
    assert!(!location.join("stageA").exists());

    // A second legitimate publication cannot replace the existing slot.
    assert_eq!(
        publish_immutable_npm_generation_slot(&dir, &generation, "stageB", "slotA", 256 * 1024),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    assert_eq!(std::fs::read(location.join("slotA")).unwrap(), stored);
    assert!(!location.join("stageB").exists());

    // Even a preexisting destination outside the library's format cannot be
    // overwritten; it is not trusted as a generation.
    std::fs::write(location.join("occupied"), b"sentinel").unwrap();
    assert_eq!(
        publish_immutable_npm_generation_slot(&dir, &generation, "stageC", "occupied", 256 * 1024),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    assert_eq!(
        std::fs::read(location.join("occupied")).unwrap(),
        b"sentinel"
    );
    assert!(!location.join("stageC").exists());

    // A stage-name collision fails before any write or unlink of the
    // existing file. Other storage tenants cannot be silently overwritten.
    std::fs::write(location.join("stageD"), b"occupied-stage").unwrap();
    assert_eq!(
        publish_immutable_npm_generation_slot(&dir, &generation, "stageD", "slotB", 256 * 1024),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    assert_eq!(
        std::fs::read(location.join("stageD")).unwrap(),
        b"occupied-stage"
    );
    assert!(!location.join("slotB").exists());

    let target = NpmGenerationStore::new(&scope, "npm:manifest", "npm:lock").unwrap();
    let limits = NpmRecoveryLimits {
        max_bytes: 256 * 1024,
        raw: RawLimits::default(),
        inventory: InventoryLimits::default(),
    };
    let restored = restore_framed_npm_generation_pinned(
        &target,
        &mut std::io::Cursor::new(stored),
        &anchor,
        &scope,
        None,
        limits,
    )
    .unwrap();
    assert_eq!(restored.sequence(), 1);
    assert_eq!(restored.snapshot(), &snapshot);
    assert_eq!(restored.checkpoint(), &checkpoint);

    drop(dir);
    std::fs::remove_dir_all(&location).unwrap();
}
