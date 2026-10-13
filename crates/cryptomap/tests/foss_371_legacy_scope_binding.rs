//! Security regression: no built-in file collector may cross a host grant.
//! Raw, isolated, normalized and batch APIs must reject a scope mismatch
//! *before* reading any source, even if tenant and source labels are identical.
#![allow(clippy::unwrap_used)]
use cryptomap::{
    CollectionRunId, CoverageState, IdentityContext, InventoryLimits,
    batch::BatchLimits,
    collector::{
        CancellationToken, CollectionRequest, CollectionStatus, Collector, RequestedSource,
    },
    collectors::dependency::{
        cargo::CargoLockfileCollector, manifest_collector::CargoManifestCollector,
        npm::NpmLockfileCollector, npm_manifest_collector::NpmManifestCollector,
    },
    coverage::CollectionScopeId,
    orchestration::{
        ScopedInvocation, collect_normalized, collect_normalized_batch,
    },
    pipeline::{PipelineError, PipelineInput},
    raw::{RawLimits, RawSourceKind},
    registry::Registry,
    scope::{CollectionScope, ScopeError, collect_scoped, collect_scoped_isolated},
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

const AT: &str = "2026-10-13T15:00:00Z";
const ITEM: &str = "shared:dependency";
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct TempRoot(PathBuf);
impl TempRoot {
    fn new(file: &str) -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "cryptomap-dependency-scope-{}-{n}", std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        // This file is an actual grant but must never be opened by
        // the collector captured under a different CollectionScope.
        fs::write(root.join(file), b"untrusted-but-authorized-other-scope").unwrap();
        Self(root)
    }
}
impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scope(root: &Path, file: &str) -> CollectionScope {
    let mut approved = CollectionScope::new(CollectionScopeId::new("same-tenant").unwrap());
    approved
        .grant_file(RawSourceKind::Dependency, ITEM, root, file, 1_048_576)
        .unwrap();
    approved
}

fn request(run: &str) -> CollectionRequest {
    CollectionRequest {
        run: CollectionRunId::new(run).unwrap(),
        sources: vec![RequestedSource {
            kind: RawSourceKind::Dependency,
            item: ITEM.into(),
        }],
        limits: RawLimits::default(),
        options: Default::default(),
    }
}

/// Exercise the identical misuse through *all* host execution surfaces.
/// A subsequent regression removing one binding will fail before merge.
fn assert_scope_isolation(collector: &dyn Collector, grant_a: &CollectionScope, grant_b: &CollectionScope) {
    assert!(collector.matches_invocation_scope(grant_a));
    assert!(!collector.matches_invocation_scope(grant_b));
    let req = request("dep-scope-run");
    let cancel = CancellationToken::default();
    grant_a.validate_request(&req).unwrap();
    grant_b.validate_request(&req).unwrap();

    assert!(matches!(
        collect_scoped(grant_b, collector, req.clone(), &cancel),
        Err(ScopeError::OutOfScope)
    ));
    assert!(matches!(
        collect_scoped_isolated(grant_b, collector, req.clone(), &cancel),
        Err(ScopeError::OutOfScope)
    ));

    let registry = Registry::builtin();
    let identity = IdentityContext::new("same-tenant").unwrap();
    let descriptor = collector.descriptor();
    let sources = req.sources.clone();
    let run = req.run.clone();
    let mismatch = || ScopedInvocation {
        collector,
        input: PipelineInput {
            scope: grant_b,
            identity: &identity,
            registry: &registry,
            expected_descriptor: &descriptor,
            expected_run: &run,
            sources: &sources,
            raw_limits: RawLimits::default(),
            inventory_limits: InventoryLimits::default(),
            started_at: AT,
            ended_at: AT,
        },
    };
    assert!(matches!(
        collect_normalized(mismatch(), &cancel),
        Err(PipelineError::Scope(ScopeError::OutOfScope))
    ));
    assert!(matches!(
        collect_normalized_batch(vec![mismatch()], BatchLimits::default(), &cancel),
        Err(PipelineError::Scope(ScopeError::OutOfScope))
    ));
    // Positive control: exactly the original grant remains usable.
    let accepted = collect_scoped(grant_a, collector, req, &cancel).unwrap();
    assert_eq!(accepted.status, CollectionStatus::Complete);
    assert_eq!(accepted.coverage[ITEM], CoverageState::InspectedObserved);
    assert!(!accepted.observations.is_empty());
}

#[test]
fn cargo_lock_collector_does_not_read_another_scopes_file() {
    let original = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixtures/cargo");
    let other = TempRoot::new("Cargo.lock");
    let a = scope(&original, "Cargo.lock");
    let b = scope(&other.0, "Cargo.lock");
    assert_scope_isolation(&CargoLockfileCollector::new(&a, AT), &a, &b);
}

#[test]
fn cargo_manifest_collector_does_not_read_another_scopes_file() {
    let original = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixtures/cargo");
    let other = TempRoot::new("Cargo.toml");
    let a = scope(&original, "Cargo.toml");
    let b = scope(&other.0, "Cargo.toml");
    assert_scope_isolation(&CargoManifestCollector::new(&a, AT), &a, &b);
}

#[test]
fn npm_lock_collector_does_not_read_another_scopes_file() {
    let original = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixtures/npm");
    let other = TempRoot::new("package-lock.json");
    let a = scope(&original, "package-lock.json");
    let b = scope(&other.0, "package-lock.json");
    assert_scope_isolation(&NpmLockfileCollector::new(&a, AT), &a, &b);
}

#[test]
fn npm_manifest_collector_does_not_read_another_scopes_file() {
    let original = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixtures/npm");
    let other = TempRoot::new("package.json");
    let a = scope(&original, "package.json");
    let b = scope(&other.0, "package.json");
    assert_scope_isolation(&NpmManifestCollector::new(&a, AT), &a, &b);
}
