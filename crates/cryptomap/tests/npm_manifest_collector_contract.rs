//! Npm manifest collector resource, authorization, and malformed-data contracts.
#![allow(clippy::unwrap_used)]
use cryptomap::{
    CollectionRunId, CoverageState,
    collector::{CancellationToken, CollectionRequest, CollectionStatus, RequestedSource},
    collectors::dependency::npm_manifest_collector::NpmManifestCollector,
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
const VALID: &str = r#"{"name":"app","version":"1.0.0","dependencies":{"@scope/ring":"1.2.3"}}"#;
struct Fixture(PathBuf);
impl Fixture {
    fn new(data: &str) -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("cryptomap-npm-manifest-{}-{id}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("package.json"), data).unwrap();
        Self(path)
    }
    fn scope(&self, grant: bool, budget: usize) -> CollectionScope {
        let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-a").unwrap());
        if grant {
            scope.grant_file(
                RawSourceKind::Dependency, "npm:manifest", &self.0, "package.json", budget
            ).unwrap();
        }
        scope
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn request(limits: RawLimits) -> CollectionRequest {
    CollectionRequest {
        run: CollectionRunId::new("manifest-run").unwrap(),
        sources: vec![RequestedSource {
            kind: RawSourceKind::Dependency,
            item: "npm:manifest".into(),
        }],
        limits,
        options: BTreeMap::new(),
    }
}
#[test]
fn exact_root_and_direct_pins_have_separate_deterministic_confirmed_events() {
    let fixture = Fixture::new(VALID);
    let scope = fixture.scope(true, 4096);
    let collector = NpmManifestCollector::new(&scope, "2026-10-11T12:00:00Z");
    let first = collect_scoped(
        &scope, &collector, request(RawLimits::default()), &CancellationToken::default()
    ).unwrap();
    let second = collect_scoped(
        &scope, &collector, request(RawLimits::default()), &CancellationToken::default()
    ).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.status, CollectionStatus::Complete);
    assert_eq!(first.observations.len(), 2);
    assert_eq!(first.coverage["npm:manifest"], CoverageState::InspectedObserved);
    assert_ne!(first.observations[0].event_id, first.observations[1].event_id);
    for item in &first.observations {
        assert!(matches!(item.fact, RawFactKind::Dependency { .. }));
        assert_eq!(item.source_sha256.as_ref().map(String::len), Some(64));
        assert_eq!(item.collector.as_str(), "cryptomap:npm-manifest");
        assert!(matches!(item.attributes.get("npm:manifest-role").map(String::as_str),
            Some("root" | "direct")));
    }
}
#[test]
fn unsupported_metadata_duplicate_keys_and_invalid_names_never_confirm_coverage() {
    for data in [
        r#"{"name":"app","version":"1.0.0","dependencies":{"ring":"^1.2.3"}}"#,
        r#"{"name":"app","version":"1.0.0","dependencies":{"_invalid":"1.2.3"}}"#,
        r#"{"name":"app","version":"1.0.0","dependencies":{"ring":"1.2.3","ring":"1.2.4"}}"#,
        r#"{"name":"app","version":"1.0.0","dependencies":{"ring":"1.2.3"},"scripts":{"postinstall":"curl https://bad"}}"#,
        r#"{"name":"app","version":"1.0.0","dependencies":{"ring":"1.2.3"},"workspaces":["packages/*"]}"#,
        r#"{"name":"app","version":"1.0.0","dependencies":{"ring":"1.2.3"},"optionalDependencies":{"extra":"1.0.0"}}"#,
    ] {
        let fixture = Fixture::new(data);
        let scope = fixture.scope(true, 4096);
        let collector = NpmManifestCollector::new(&scope, "2026-10-11T12:00:00Z");
        let result = collect_scoped(
            &scope, &collector, request(RawLimits::default()), &CancellationToken::default()
        ).unwrap();
        assert_eq!(result.coverage["npm:manifest"], CoverageState::Failed);
        assert!(result.observations.is_empty());
        assert_eq!(result.diagnostics.len(), 1);
    }
}
#[test]
fn missing_grant_read_budget_and_root_observation_ceiling_fail_closed() {
    let fixture = Fixture::new(VALID);
    let ungranted = fixture.scope(false, 4096);
    let collector = NpmManifestCollector::new(&ungranted, "2026-10-11T12:00:00Z");
    assert!(collect_scoped(
        &ungranted, &collector, request(RawLimits::default()),
        &CancellationToken::default()
    ).is_err());

    let undersized = fixture.scope(true, 8);
    let collector = NpmManifestCollector::new(&undersized, "2026-10-11T12:00:00Z");
    let outcome = collect_scoped(
        &undersized, &collector, request(RawLimits::default()),
        &CancellationToken::default()
    ).unwrap();
    assert_eq!(outcome.coverage["npm:manifest"], CoverageState::Failed);
    assert!(outcome.observations.is_empty());

    let valid = fixture.scope(true, 4096);
    let collector = NpmManifestCollector::new(&valid, "2026-10-11T12:00:00Z");
    let tight = RawLimits { observations: 1, ..RawLimits::default() };
    let outcome = collect_scoped(
        &valid, &collector, request(tight), &CancellationToken::default()
    ).unwrap();
    assert_eq!(outcome.coverage["npm:manifest"], CoverageState::Failed);
    assert!(outcome.observations.is_empty());
}
#[test]
fn pre_cancelled_collection_never_claims_inspection() {
    let fixture = Fixture::new(VALID);
    let scope = fixture.scope(true, 4096);
    let collector = NpmManifestCollector::new(&scope, "2026-10-11T12:00:00Z");
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let result = collect_scoped(
        &scope, &collector, request(RawLimits::default()), &cancellation
    ).unwrap();
    assert!(result.observations.is_empty());
    assert_eq!(result.coverage["npm:manifest"], CoverageState::NotInspected);
}
