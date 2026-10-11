//! Independent npm manifest + lockfile collection and canonical edge contracts.
#![allow(clippy::unwrap_used)]
use cryptomap::{
    CollectionRunId, IdentityContext, InventoryLimits, InventorySnapshot, RelationshipKind,
    batch::{BatchLimits, BatchRun, normalize_batch},
    collector::{CancellationToken, CollectionRequest, Collector, RequestedSource},
    collectors::dependency::{
        npm::NpmLockfileCollector, npm_manifest::NpmReconciliationError,
        npm_manifest_collector::NpmManifestCollector, npm_projection::project_npm_direct_edges,
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
const MANIFEST: &str = r#"{"name":"app","version":"1.0.0","dependencies":{"@scope/ring":"1.2.3"}}"#;
const LOCK: &str = r#"{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"@scope/ring":"1.2.3"}},"node_modules/@scope/ring":{"version":"1.2.3","resolved":"https://user:token@registry.example.invalid/ring.tgz"}}}"#;

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
    let lock_outcome =
        collect_scoped(scope, &lock, request("run-npm-lock", lock_item), &cancel).unwrap();
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
#[test]
fn npm_two_source_edge_is_deterministic_and_persistently_evidence_backed() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let snapshot = collect_both(&scope, "npm:lock");
    assert_eq!(snapshot.assets.len(), 2);
    assert_eq!(snapshot.evidence.len(), 4);
    assert!(snapshot.relationships.is_empty());
    let projected = project(&snapshot, &scope).unwrap();
    assert_eq!(projected, project(&snapshot, &scope).unwrap());
    assert_eq!(projected, project(&projected, &scope).unwrap());
    assert_eq!(projected.assets, snapshot.assets);
    assert_eq!(projected.observations, snapshot.observations);
    assert_eq!(projected.evidence, snapshot.evidence);
    assert_eq!(projected.relationships.len(), 1);
    let edge = projected.relationships.values().next().unwrap();
    assert_eq!(edge.kind, RelationshipKind::DependsOn);
    assert_eq!(edge.evidence.len(), 4);
    let sources: std::collections::BTreeSet<_> = edge
        .evidence
        .iter()
        .map(|id| projected.evidence[id].source.as_str())
        .collect();
    assert_eq!(
        sources,
        std::collections::BTreeSet::from(["Dependency:npm:manifest", "Dependency:npm:lock"])
    );
    for id in &edge.evidence {
        assert_eq!(
            projected.evidence[id]
                .source_sha256
                .as_ref()
                .map(String::len),
            Some(64)
        );
    }
    projected
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    assert!(!format!("{projected:?}").contains("user:token"));
    assert!(!format!("{projected:?}").contains("registry.example.invalid"));
    let exact = InventoryLimits {
        relationships: projected.relationships.len(),
        ..InventoryLimits::default()
    };
    assert_eq!(
        project_npm_direct_edges(
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
}

#[test]
fn missing_manifest_and_cross_tenant_are_not_authorized() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let snapshot = collect_both(&scope, "npm:lock");
    let no_manifest = fixture.scope("tenant-a", false, "npm:lock");
    assert_eq!(
        project(&snapshot, &no_manifest),
        Err(NpmReconciliationError::UnauthorizedSource)
    );
    let other_tenant = fixture.scope("tenant-b", true, "npm:lock");
    assert_eq!(
        project(&snapshot, &other_tenant),
        Err(NpmReconciliationError::UnboundEvidence)
    );
}

#[test]
fn lock_only_snapshot_cannot_invent_manifest_evidence() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let collector = NpmLockfileCollector::new(&scope, "2026-10-11T12:00:00Z");
    let descriptor = collector.descriptor();
    let run = CollectionRunId::new("run-npm-lock").unwrap();
    let sources = requested("npm:lock");
    let identity = IdentityContext::new("tenant-a").unwrap();
    let registry = Registry::builtin();
    let snapshot = collect_normalized(
        ScopedInvocation {
            collector: &collector,
            input: PipelineInput {
                scope: &scope,
                identity: &identity,
                registry: &registry,
                expected_descriptor: &descriptor,
                expected_run: &run,
                sources: &sources,
                raw_limits: RawLimits::default(),
                inventory_limits: InventoryLimits::default(),
                started_at: "2026-10-11T11:59:00Z",
                ended_at: "2026-10-11T12:01:00Z",
            },
        },
        &CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(snapshot.evidence.len(), 2);
    assert_eq!(
        project(&snapshot, &scope),
        Err(NpmReconciliationError::UnboundEvidence)
    );
}

#[test]
fn changed_document_bytes_and_mismatched_source_items_cannot_reuse_attestation() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let snapshot = collect_both(&scope, "npm:lock");
    let changed_manifest = Fixture::new(&format!("{MANIFEST} "), LOCK);
    let changed_scope = changed_manifest.scope("tenant-a", true, "npm:lock");
    assert_eq!(
        project(&snapshot, &changed_scope),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let changed_lock = Fixture::new(MANIFEST, &LOCK.replace("token@", "replacement@"));
    let changed_scope = changed_lock.scope("tenant-a", true, "npm:lock");
    assert_eq!(
        project(&snapshot, &changed_scope),
        Err(NpmReconciliationError::UnboundEvidence)
    );
    let other_source = fixture.scope("tenant-a", true, "npm:other");
    let snapshot_other = collect_both(&other_source, "npm:other");
    assert_eq!(
        project(&snapshot_other, &scope),
        Err(NpmReconciliationError::UnboundEvidence)
    );
}

#[test]
fn invalid_manifest_and_relationship_limit_fail_closed() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, "npm:lock");
    let snapshot = collect_both(&scope, "npm:lock");
    let bad = Fixture::new(
        r#"{"name":"app","version":"1.0.0","dependencies":{"@scope/ring":"^1.2.3"}}"#,
        LOCK,
    );
    let bad_scope = bad.scope("tenant-a", true, "npm:lock");
    assert_eq!(
        project(&snapshot, &bad_scope),
        Err(NpmReconciliationError::UnsupportedProfile)
    );
    let zero = InventoryLimits {
        relationships: 0,
        ..InventoryLimits::default()
    };
    assert_eq!(
        project_npm_direct_edges(
            &snapshot,
            &scope,
            "npm:manifest",
            "npm:lock",
            RawLimits::default(),
            zero
        ),
        Err(NpmReconciliationError::ResourceLimit)
    );
}
