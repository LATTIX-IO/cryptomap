//! FOSS-322.5 passive Cargo.toml manifest collector security contracts.
#![allow(clippy::unwrap_used)]
use cryptomap::{
    CollectionRunId, CoverageState,
    collector::{
        CancellationToken, CollectionRequest, CollectionStatus, Collector, RequestedSource,
    },
    collectors::dependency::manifest_collector::CargoManifestCollector,
    coverage::CollectionScopeId,
    raw::{RawFactKind, RawLimits, RawSourceKind},
    scope::{CollectionScope, collect_scoped},
};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const VALID: &str =
    "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nring = \"=0.17.12\"\n";
struct Fixture(PathBuf);
impl Fixture {
    fn new(content: &str) -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "cryptomap-cargo-manifest-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("Cargo.toml"), content).unwrap();
        Self(root)
    }
    fn scope(&self, grant: bool, max_bytes: usize) -> CollectionScope {
        let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-a").unwrap());
        if grant {
            scope.grant_file(
                RawSourceKind::Dependency,
                "cargo:manifest",
                &self.0,
                "Cargo.toml",
                max_bytes,
            ).unwrap();
        }
        scope
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn request(limits: RawLimits) -> CollectionRequest {
    CollectionRequest {
        run: CollectionRunId::new("manifest-run").unwrap(),
        sources: vec![RequestedSource {
            kind: RawSourceKind::Dependency,
            item: "cargo:manifest".into(),
        }],
        limits,
        options: BTreeMap::new(),
    }
}

#[test]
fn root_and_exact_direct_pin_have_independent_hashed_manifest_evidence() {
    let fixture = Fixture::new(VALID);
    let scope = fixture.scope(true, 4096);
    let collector = CargoManifestCollector::new(&scope, "2026-10-11T12:00:00Z");
    let one = collect_scoped(&scope, &collector, request(RawLimits::default()),
        &CancellationToken::default()).unwrap();
    let two = collect_scoped(&scope, &collector, request(RawLimits::default()),
        &CancellationToken::default()).unwrap();
    assert_eq!(one, two);
    assert_eq!(one.status, CollectionStatus::Complete);
    assert_eq!(one.coverage["cargo:manifest"], CoverageState::InspectedObserved);
    assert_eq!(one.observations.len(), 2);
    for record in &one.observations {
        assert_eq!(record.source.item, "cargo:manifest");
        assert_eq!(record.source_sha256.as_ref().map(String::len), Some(64));
        assert!(matches!(record.fact, RawFactKind::Dependency { .. }));
        assert!(matches!(record.attributes.get("cargo:manifest-role").map(String::as_str),
            Some("root" | "direct")));
    }
    assert_ne!(one.observations[0].event_id, one.observations[1].event_id);
}

#[test]
fn invalid_and_unsupported_manifests_fail_without_false_absence() {
    for bad in [
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nring = \"0.17\"\n",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nring = \"=0.17.12\"\nring = \"=0.17.12\"\n",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nring = { version = \"0.17\" }\n",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[target.'cfg(windows)'.dependencies]\nring = \"=0.17.12\"\n",
    ] {
        let fixture = Fixture::new(bad);
        let scope = fixture.scope(true, 4096);
        let collector = CargoManifestCollector::new(&scope, "2026-10-11T12:00:00Z");
        let result = collect_scoped(&scope, &collector, request(RawLimits::default()),
            &CancellationToken::default()).unwrap();
        assert_eq!(result.status, CollectionStatus::Failed);
        assert_eq!(result.coverage["cargo:manifest"], CoverageState::Failed);
        assert!(result.observations.is_empty());
        assert_eq!(result.diagnostics.len(), 1);
    }
}

#[test]
fn exact_file_authority_and_read_budget_fail_closed() {
    let fixture = Fixture::new(VALID);
    let no_grant = fixture.scope(false, 4096);
    let collector = CargoManifestCollector::new(&no_grant, "2026-10-11T12:00:00Z");
    assert!(collect_scoped(&no_grant, &collector, request(RawLimits::default()),
        &CancellationToken::default()).is_err());

    let small = fixture.scope(true, 8);
    let collector = CargoManifestCollector::new(&small, "2026-10-11T12:00:00Z");
    let outcome = collect_scoped(&small, &collector, request(RawLimits::default()),
        &CancellationToken::default()).unwrap();
    assert_eq!(outcome.coverage["cargo:manifest"], CoverageState::Failed);
    assert!(outcome.observations.is_empty());
}

#[test]
fn total_observation_limit_accounts_for_root_and_dependency() {
    let fixture = Fixture::new(VALID);
    let scope = fixture.scope(true, 4096);
    let collector = CargoManifestCollector::new(&scope, "2026-10-11T12:00:00Z");
    let limits = RawLimits {
        observations: 1,
        ..RawLimits::default()
    };
    let outcome = collect_scoped(&scope, &collector, request(limits),
        &CancellationToken::default()).unwrap();
    assert_eq!(outcome.coverage["cargo:manifest"], CoverageState::Failed);
    assert!(outcome.observations.is_empty());
}

#[test]
fn pre_cancelled_run_proves_no_manifest_inspection() {
    let fixture = Fixture::new(VALID);
    let scope = fixture.scope(true, 4096);
    let collector = CargoManifestCollector::new(&scope, "2026-10-11T12:00:00Z");
    let cancel = CancellationToken::default();
    cancel.cancel();
    let result = collect_scoped(&scope, &collector, request(RawLimits::default()), &cancel).unwrap();
    assert!(result.observations.is_empty());
    assert_eq!(result.coverage["cargo:manifest"], CoverageState::NotInspected);
}
