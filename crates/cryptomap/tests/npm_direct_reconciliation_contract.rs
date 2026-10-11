//! Scoped npm manifest/lock direct dependency proof acceptance and adversarial tests.
#![allow(clippy::unwrap_used)]
use cryptomap::{
    collectors::dependency::npm_manifest::{
        NpmDirectReconciliation, NpmReconciliationError, reconcile_npm_direct,
    },
    coverage::CollectionScopeId,
    raw::{RawLimits, RawSourceKind},
    scope::CollectionScope,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
const MANIFEST: &str = r#"{"name":"app","version":"1.0.0","dependencies":{"@scope/ring":"1.2.3"}}"#;
const LOCK: &str = r#"{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"@scope/ring":"1.2.3"}},"node_modules/@scope/ring":{"version":"1.2.3","resolved":"https://user:token@registry.example.invalid/pkg.tgz"}}}"#;

struct Fixture(PathBuf);
impl Fixture {
    fn new(manifest: &str, lock: &str) -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("cryptomap-npm-proof-{}-{id}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("package.json"), manifest).unwrap();
        fs::write(path.join("package-lock.json"), lock).unwrap();
        Self(path)
    }
    fn scope(&self, manifest: bool, lock: bool, byte_limit: usize) -> CollectionScope {
        let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-a").unwrap());
        if manifest {
            scope
                .grant_file(
                    RawSourceKind::Dependency,
                    "npm:manifest",
                    &self.0,
                    "package.json",
                    byte_limit,
                )
                .unwrap();
        }
        if lock {
            scope
                .grant_file(
                    RawSourceKind::Dependency,
                    "npm:lock",
                    &self.0,
                    "package-lock.json",
                    byte_limit,
                )
                .unwrap();
        }
        scope
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn prove(scope: &CollectionScope) -> Result<NpmDirectReconciliation, NpmReconciliationError> {
    reconcile_npm_direct(scope, "npm:manifest", "npm:lock", RawLimits::default())
}

#[test]
fn explicit_root_level_scoped_pin_yields_deterministic_hashed_proof() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope(true, true, 4096);
    let first = prove(&scope).unwrap();
    let second = prove(&scope).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.root_name, "app");
    assert_eq!(first.root_version, "1.0.0");
    assert_eq!(first.manifest_sha256.len(), 64);
    assert_eq!(first.lock_sha256.len(), 64);
    assert_eq!(first.direct.len(), 1);
    assert_eq!(first.direct[0].name, "@scope/ring");
    assert_eq!(first.direct[0].version, "1.2.3");
    assert!(!format!("{first:?}").contains("token@"));
    assert!(!format!("{first:?}").contains("registry.example.invalid"));
}

#[test]
fn missing_file_grants_and_reused_grant_identifier_fail_closed() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    for (manifest, lock) in [(false, false), (false, true), (true, false)] {
        let scope = fixture.scope(manifest, lock, 4096);
        assert_eq!(
            prove(&scope),
            Err(NpmReconciliationError::UnauthorizedSource)
        );
    }
    let scope = fixture.scope(true, true, 4096);
    assert_eq!(
        reconcile_npm_direct(&scope, "npm:manifest", "npm:manifest", RawLimits::default(),),
        Err(NpmReconciliationError::InvalidSource)
    );
    assert_eq!(
        reconcile_npm_direct(&scope, "../package.json", "npm:lock", RawLimits::default(),),
        Err(NpmReconciliationError::UnauthorizedSource)
    );
}

#[test]
fn malicious_lock_and_manifest_disagreements_never_infer_graph() {
    for lock in [
        LOCK.replace("1.2.3\"},\"node_modules", "2.0.0\"},\"node_modules"),
        LOCK.replace("node_modules/@scope/ring", "packages/ring"),
        LOCK.replace(
            "\"version\":\"1.2.3\",\"resolved\"",
            "\"version\":\"1.2.4\",\"resolved\"",
        ),
        LOCK.replace("\"resolved\":", "\"link\":true,\"resolved\":"),
        LOCK.replace("\"lockfileVersion\":3", "\"lockfileVersion\":1"),
        LOCK.replace("\"version\":\"1.0.0\"", "\"version\":\"2.0.0\""),
    ] {
        let fixture = Fixture::new(MANIFEST, &lock);
        let scope = fixture.scope(true, true, 4096);
        assert!(prove(&scope).is_err());
    }
    let ranged = MANIFEST.replace("\"1.2.3\"", "\"^1.2.3\"");
    let fixture = Fixture::new(&ranged, LOCK);
    assert_eq!(
        prove(&fixture.scope(true, true, 4096)),
        Err(NpmReconciliationError::UnsupportedProfile)
    );
}

#[test]
fn bounded_source_read_and_aggregate_budget_both_enforced() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let too_small = fixture.scope(true, true, 8);
    assert_eq!(
        prove(&too_small),
        Err(NpmReconciliationError::UnauthorizedSource)
    );
    let scope = fixture.scope(true, true, 4096);
    let budget = MANIFEST.len() + LOCK.len() - 1;
    let limits = RawLimits {
        total_bytes: budget,
        record_bytes: 128,
        field_bytes: 64,
        ..RawLimits::default()
    };
    assert_eq!(
        reconcile_npm_direct(&scope, "npm:manifest", "npm:lock", limits),
        Err(NpmReconciliationError::ResourceLimit)
    );
}

#[test]
fn duplicate_json_and_unsupported_optional_workspace_semantics_denied() {
    let duplicate = r#"{"name":"app","version":"1.0.0","dependencies":{"@scope/ring":"1.2.3","@scope/ring":"2.0.0"}}"#;
    let optional = r#"{"name":"app","version":"1.0.0","dependencies":{"@scope/ring":"1.2.3"},"optionalDependencies":{"x":"1.0.0"}}"#;
    let workspace = r#"{"name":"app","version":"1.0.0","dependencies":{"@scope/ring":"1.2.3"},"workspaces":["packages/*"]}"#;
    for manifest in [duplicate, optional, workspace] {
        let fixture = Fixture::new(manifest, LOCK);
        assert!(prove(&fixture.scope(true, true, 4096)).is_err());
    }
}
