//! FOSS-322.1 scoped npm lockfile end-to-end and adversarial contracts.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    AssetKind, CollectionRunId, CoverageState, IdentityContext, InventoryLimits,
    collector::{
        CancellationToken, CollectionRequest, CollectionStatus, Collector, RequestedSource,
    },
    collectors::dependency::npm::NpmLockfileCollector,
    coverage::CollectionScopeId,
    orchestration::{ScopedInvocation, collect_normalized},
    pipeline::PipelineInput,
    raw::{RawFactKind, RawLimits, RawSourceKind},
    registry::Registry,
    scope::{CollectionScope, collect_scoped},
};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(content: &str) -> Self {
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("cryptomap-npm-{}-{unique}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("package-lock.json"), content).unwrap();
        Self { root }
    }
    fn scope(&self, tenant: &str) -> CollectionScope {
        let mut scope = CollectionScope::new(CollectionScopeId::new(tenant).unwrap());
        scope
            .grant_file(
                RawSourceKind::Dependency,
                "npm:lock",
                &self.root,
                "package-lock.json",
                16 * 1024,
            )
            .unwrap();
        scope
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn requested() -> Vec<RequestedSource> {
    vec![RequestedSource {
        kind: RawSourceKind::Dependency,
        item: "npm:lock".into(),
    }]
}

fn request(run: &str) -> CollectionRequest {
    CollectionRequest {
        run: CollectionRunId::new(run).unwrap(),
        sources: requested(),
        limits: RawLimits::default(),
        options: BTreeMap::new(),
    }
}

const VALID: &str = r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/openssl":{"version":"1.0.1"},"node_modules/@scope/ring":{"version":"2.3.4"}}}"#;

#[test]
fn scoped_lockfile_collects_deterministic_evidence_and_normalizes_without_use_inference() {
    let fixture = Fixture::new(VALID);
    let scope = fixture.scope("tenant-a");
    let collector = NpmLockfileCollector::new(&scope, "2026-10-11T12:00:00Z");
    let cancel = CancellationToken::default();
    let first = collect_scoped(&scope, &collector, request("run-1"), &cancel).unwrap();
    let second = collect_scoped(&scope, &collector, request("run-1"), &cancel).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.status, CollectionStatus::Complete);
    assert_eq!(first.observations.len(), 2);
    assert!(first.observations.iter().all(|observation| {
        matches!(observation.fact, RawFactKind::Dependency { .. })
            && observation.source_sha256.is_some()
            && observation.attributes.contains_key("npm:lockfile-path")
    }));
    assert_eq!(first.coverage["npm:lock"], CoverageState::InspectedObserved);
    let run = CollectionRunId::new("run-1").unwrap();
    let identity = IdentityContext::new("tenant-a").unwrap();
    let registry = Registry::builtin();
    let expected = collector.descriptor();
    let sources = requested();
    let snapshot = collect_normalized(
        ScopedInvocation {
            collector: &collector,
            input: PipelineInput {
                scope: &scope,
                identity: &identity,
                registry: &registry,
                expected_descriptor: &expected,
                expected_run: &run,
                sources: &sources,
                raw_limits: RawLimits::default(),
                inventory_limits: InventoryLimits::default(),
                started_at: "2026-10-11T11:59:00Z",
                ended_at: "2026-10-11T12:01:00Z",
            },
        },
        &cancel,
    )
    .unwrap();
    assert_eq!(snapshot.assets.len(), 2);
    assert_eq!(snapshot.evidence.len(), 2);
    assert_eq!(snapshot.observations.len(), 2);
    assert!(
        snapshot
            .assets
            .values()
            .all(|asset| matches!(asset.kind, AssetKind::Library { .. }))
    );
    snapshot
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
}

#[test]
fn workspace_entries_cannot_silently_upgrade_partial_coverage() {
    let fixture = Fixture::new(
        r#"{"lockfileVersion":2,"packages":{"":{},"packages/local":{"version":"1"},"node_modules/ring":{"version":"1"}}}"#,
    );
    let scope = fixture.scope("tenant-a");
    let collector = NpmLockfileCollector::new(&scope, "2026-10-11T12:00:00Z");
    let outcome = collect_scoped(
        &scope,
        &collector,
        request("run-2"),
        &CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(outcome.observations.len(), 1);
    assert_eq!(outcome.coverage["npm:lock"], CoverageState::Partial);
    assert_eq!(outcome.status, CollectionStatus::Failed);
    assert_eq!(outcome.diagnostics.len(), 1);
}

#[test]
fn ungranted_file_fails_before_any_collector_execution() {
    let scope = CollectionScope::new(CollectionScopeId::new("tenant-a").unwrap());
    let collector = NpmLockfileCollector::new(&scope, "2026-10-11T12:00:00Z");
    assert!(
        collect_scoped(
            &scope,
            &collector,
            request("run-3"),
            &CancellationToken::default()
        )
        .is_err()
    );
}

#[test]
fn rejected_and_unsupported_files_never_claim_absence() {
    for document in [
        r#"{"lockfileVersion":1,"dependencies":{}}"#,
        r#"{"lockfileVersion":3,"packages":{"node_modules/foo":{}}}"#,
        r#"{"lockfileVersion":3,"packages":{"node_modules/../bad":{"version":"1"}}}"#,
        r#"{"lockfileVersion":3,"packages":{"node_modules/foo":{"version":"1"},"node_modules/foo":{"version":"2"}}}"#,
    ] {
        let fixture = Fixture::new(document);
        let scope = fixture.scope("tenant-a");
        let collector = NpmLockfileCollector::new(&scope, "2026-10-11T12:00:00Z");
        let outcome = collect_scoped(
            &scope,
            &collector,
            request("run-negative"),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(outcome.observations.is_empty());
        assert_eq!(outcome.coverage["npm:lock"], CoverageState::Failed);
        assert_eq!(outcome.status, CollectionStatus::Failed);
        assert_eq!(outcome.diagnostics.len(), 1);
    }
}

#[test]
fn cancellation_and_file_budget_fail_closed() {
    let fixture = Fixture::new(VALID);
    let scope = fixture.scope("tenant-a");
    let collector = NpmLockfileCollector::new(&scope, "2026-10-11T12:00:00Z");
    let cancel = CancellationToken::default();
    cancel.cancel();
    let outcome = collect_scoped(&scope, &collector, request("run-4"), &cancel).unwrap();
    assert!(outcome.observations.is_empty());
    assert_eq!(outcome.coverage["npm:lock"], CoverageState::NotInspected);

    let mut denied = CollectionScope::new(CollectionScopeId::new("tenant-a").unwrap());
    assert!(
        denied
            .grant_file(
                RawSourceKind::Dependency,
                "npm:lock",
                &fixture.root,
                "package-lock.json",
                8,
            )
            .is_err()
    );
}
