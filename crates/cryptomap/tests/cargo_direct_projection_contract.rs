//! FOSS-322.4 end-to-end canonical Cargo edge projection and security gates.
#![allow(clippy::unwrap_used)]
use cryptomap::{
    CollectionRunId, IdentityContext, InventoryLimits, InventorySnapshot, RelationshipKind,
    batch::{BatchLimits, BatchRun, normalize_batch},
    collector::{CancellationToken, CollectionRequest, Collector, RequestedSource},
    collectors::dependency::{
        cargo::CargoLockfileCollector, manifest::CargoReconciliationError,
        manifest_collector::CargoManifestCollector, projection::project_cargo_direct_edges,
    },
    coverage::CollectionScopeId,
    orchestration::{ScopedInvocation, collect_normalized},
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
    "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nring = \"=0.17.12\"\n";
const LOCK: &str = "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"ring\",\n]\n[[package]]\nname = \"ring\"\nversion = \"0.17.12\"\nsource = \"registry+https://user:secret@private.example.invalid/index\"\n";

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new(manifest: &str, lock: &str) -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("cryptomap-projection-{}-{id}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("Cargo.toml"), manifest).unwrap();
        fs::write(root.join("Cargo.lock"), lock).unwrap();
        Self { root }
    }
    fn scope(&self, tenant: &str, source_id: &str, manifest: bool) -> CollectionScope {
        let mut scope = CollectionScope::new(CollectionScopeId::new(tenant).unwrap());
        scope
            .grant_file(
                RawSourceKind::Dependency,
                source_id,
                &self.root,
                "Cargo.lock",
                16_384,
            )
            .unwrap();
        if manifest {
            scope
                .grant_file(
                    RawSourceKind::Dependency,
                    "cargo:manifest",
                    &self.root,
                    "Cargo.toml",
                    16_384,
                )
                .unwrap();
        }
        scope
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn collected(scope: &CollectionScope, source_id: &str) -> InventorySnapshot {
    let lock_collector = CargoLockfileCollector::new(scope, "2026-10-11T12:00:00Z");
    let manifest_collector = CargoManifestCollector::new(scope, "2026-10-11T12:00:00Z");
    let lock_descriptor = lock_collector.descriptor();
    let manifest_descriptor = manifest_collector.descriptor();
    let identity = IdentityContext::new(scope.id().as_str()).unwrap();
    let registry = Registry::builtin();
    let lock_run = CollectionRunId::new("run-lock").unwrap();
    let manifest_run = CollectionRunId::new("run-manifest").unwrap();
    let lock_sources = vec![RequestedSource {
        kind: RawSourceKind::Dependency,
        item: source_id.to_owned(),
    }];
    let manifest_sources = vec![RequestedSource {
        kind: RawSourceKind::Dependency,
        item: "cargo:manifest".into(),
    }];
    let cancellation = CancellationToken::default();
    let lock_outcome = collect_scoped(
        scope,
        &lock_collector,
        CollectionRequest {
            run: lock_run.clone(),
            sources: lock_sources.clone(),
            limits: RawLimits::default(),
            options: Default::default(),
        },
        &cancellation,
    )
    .unwrap();
    let manifest_outcome = collect_scoped(
        scope,
        &manifest_collector,
        CollectionRequest {
            run: manifest_run.clone(),
            sources: manifest_sources.clone(),
            limits: RawLimits::default(),
            options: Default::default(),
        },
        &cancellation,
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

fn collected_lock_only(scope: &CollectionScope, source_id: &str) -> InventorySnapshot {
    let collector = CargoLockfileCollector::new(scope, "2026-10-11T12:00:00Z");
    let descriptor = collector.descriptor();
    let identity = IdentityContext::new(scope.id().as_str()).unwrap();
    let registry = Registry::builtin();
    let run = CollectionRunId::new("run-lock").unwrap();
    let requested = vec![RequestedSource {
        kind: RawSourceKind::Dependency,
        item: source_id.to_owned(),
    }];
    collect_normalized(
        ScopedInvocation {
            collector: &collector,
            input: PipelineInput {
                scope,
                identity: &identity,
                registry: &registry,
                expected_descriptor: &descriptor,
                expected_run: &run,
                sources: &requested,
                raw_limits: RawLimits::default(),
                inventory_limits: InventoryLimits::default(),
                started_at: "2026-10-11T11:59:00Z",
                ended_at: "2026-10-11T12:01:00Z",
            },
        },
        &CancellationToken::default(),
    )
    .unwrap()
}

fn project(
    snapshot: &InventorySnapshot,
    scope: &CollectionScope,
) -> Result<InventorySnapshot, CargoReconciliationError> {
    project_cargo_direct_edges(
        snapshot,
        scope,
        "cargo:manifest",
        "cargo:lock",
        RawLimits::default(),
        InventoryLimits::default(),
    )
}

#[test]
fn direct_edge_uses_existing_root_and_target_evidence_and_is_replay_stable() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", "cargo:lock", true);
    let snapshot = collected(&scope, "cargo:lock");
    assert_eq!(snapshot.relationships.len(), 0);
    let projected = project(&snapshot, &scope).unwrap();
    let second = project(&snapshot, &scope).unwrap();
    assert_eq!(projected, second);
    assert_eq!(projected.assets, snapshot.assets);
    assert_eq!(projected.observations, snapshot.observations);
    assert_eq!(projected.evidence, snapshot.evidence);
    assert_eq!(projected.relationships.len(), 1);
    let edge = projected.relationships.values().next().unwrap();
    assert_eq!(edge.kind, RelationshipKind::DependsOn);
    assert_eq!(edge.evidence.len(), 4);
    let mut sources = std::collections::BTreeSet::new();
    let mut runs = std::collections::BTreeSet::new();
    for id in &edge.evidence {
        let evidence = projected.evidence.get(id).unwrap();
        sources.insert(evidence.source.as_str());
        runs.insert(evidence.run.as_str());
        assert_eq!(evidence.source_sha256.as_ref().map(String::len), Some(64));
    }
    assert_eq!(
        sources,
        std::collections::BTreeSet::from(["Dependency:cargo:lock", "Dependency:cargo:manifest",])
    );
    assert_eq!(
        runs,
        std::collections::BTreeSet::from(["run-lock", "run-manifest"])
    );
    assert_ne!(projected.id, snapshot.id);
    projected
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    assert_eq!(project(&projected, &scope).unwrap(), projected);
    // Idempotent replay at the exact relationship count must not consume
    // another slot or falsely report an exhausted budget.
    let exact = InventoryLimits {
        relationships: projected.relationships.len(),
        ..InventoryLimits::default()
    };
    assert_eq!(
        project_cargo_direct_edges(
            &projected,
            &scope,
            "cargo:manifest",
            "cargo:lock",
            RawLimits::default(),
            exact,
        )
        .unwrap(),
        projected
    );
    assert!(!format!("{projected:?}").contains("user:secret"));
    assert!(!format!("{projected:?}").contains("private.example.invalid"));
}

#[test]
fn scope_isolation_and_ungranted_manifest_fail_closed() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let tenant_a = fixture.scope("tenant-a", "cargo:lock", true);
    let baseline = collected(&tenant_a, "cargo:lock");
    let tenant_b = fixture.scope("tenant-b", "cargo:lock", true);
    assert!(matches!(
        project(&baseline, &tenant_b),
        Err(CargoReconciliationError::UnboundEvidence)
    ));
    let no_manifest = fixture.scope("tenant-a", "cargo:lock", false);
    assert_eq!(
        project(&baseline, &no_manifest),
        Err(CargoReconciliationError::UnauthorizedSource)
    );
}

#[test]
fn matching_package_names_from_unrequested_source_do_not_authorize_graph() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let collection_scope = fixture.scope("tenant-a", "cargo:other", true);
    let snapshot = collected(&collection_scope, "cargo:other");
    let projection_scope = fixture.scope("tenant-a", "cargo:lock", true);
    assert_eq!(
        project(&snapshot, &projection_scope),
        Err(CargoReconciliationError::UnboundEvidence)
    );
}

#[test]
fn stale_lockfile_digest_and_mutated_canonical_snapshot_are_rejected() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", "cargo:lock", true);
    let original = collected(&scope, "cargo:lock");
    let other = Fixture::new(MANIFEST, &LOCK.replace("secret@", "updated@"));
    let new_scope = other.scope("tenant-a", "cargo:lock", true);
    assert_eq!(
        project(&original, &new_scope),
        Err(CargoReconciliationError::UnboundEvidence)
    );
    let mut tampered = original.clone();
    tampered.observations.clear();
    assert_eq!(
        project(&tampered, &scope),
        Err(CargoReconciliationError::UnboundEvidence)
    );
}

#[test]
fn ambiguous_pin_and_reduced_relationship_budget_cannot_emit_edges() {
    let fixture = Fixture::new(
        MANIFEST,
        &format!("{LOCK}\n[[package]]\nname = \"ring\"\nversion = \"0.17.11\"\n"),
    );
    let scope = fixture.scope("tenant-a", "cargo:lock", true);
    let snapshot = collected(&scope, "cargo:lock");
    assert_eq!(
        project(&snapshot, &scope),
        Err(CargoReconciliationError::UnresolvedDependency)
    );
    let valid = Fixture::new(MANIFEST, LOCK);
    let scope = valid.scope("tenant-a", "cargo:lock", true);
    let snapshot = collected(&scope, "cargo:lock");
    let limit = InventoryLimits {
        relationships: 0,
        ..InventoryLimits::default()
    };
    assert_eq!(
        project_cargo_direct_edges(
            &snapshot,
            &scope,
            "cargo:manifest",
            "cargo:lock",
            RawLimits::default(),
            limit,
        ),
        Err(CargoReconciliationError::ResourceLimit)
    );
}

#[test]
fn lock_only_snapshot_cannot_invent_manifest_attestation() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", "cargo:lock", true);
    let lock_only = collected_lock_only(&scope, "cargo:lock");
    assert_eq!(lock_only.evidence.len(), 2);
    lock_only
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    assert_eq!(
        project(&lock_only, &scope),
        Err(CargoReconciliationError::UnboundEvidence)
    );
}

#[test]
fn changed_manifest_digest_must_not_reuse_old_canonical_attestation() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", "cargo:lock", true);
    let collected = collected(&scope, "cargo:lock");
    let modified_manifest = format!("{MANIFEST}\n# independently modified after collection\n");
    let modified = Fixture::new(&modified_manifest, LOCK);
    let modified_scope = modified.scope("tenant-a", "cargo:lock", true);
    // The lockfile still resolves the same exact dependency: the manifest
    // content hash, not package-name equality, must reject stale evidence.
    assert_eq!(
        project(&collected, &modified_scope),
        Err(CargoReconciliationError::UnboundEvidence)
    );
}

#[test]
fn failed_manifest_collection_never_produces_direct_edges() {
    let valid = Fixture::new(MANIFEST, LOCK);
    let scope = valid.scope("tenant-a", "cargo:lock", true);
    let snapshot = collected(&scope, "cargo:lock");
    let invalid = Fixture::new(
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nring = \"0.17\"\n",
        LOCK,
    );
    let invalid_scope = invalid.scope("tenant-a", "cargo:lock", true);
    assert_eq!(
        project(&snapshot, &invalid_scope),
        Err(CargoReconciliationError::UnsupportedProfile)
    );
}
