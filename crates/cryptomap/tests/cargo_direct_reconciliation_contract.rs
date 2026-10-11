//! FOSS-322.3 scoped manifest-to-lockfile proof, regression and security cases.
#![allow(clippy::unwrap_used)]
use cryptomap::{
    collectors::dependency::manifest::{
        CargoReconciliationError, reconcile_cargo_direct,
    },
    coverage::CollectionScopeId,
    raw::{RawLimits, RawSourceKind},
    scope::CollectionScope,
};
use std::{fs, path::PathBuf, sync::atomic::{AtomicUsize, Ordering}};

const MANIFEST: &str =
    "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nring = \"=0.17.12\"\n";
const LOCK: &str = "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"ring\",\n]\n[[package]]\nname = \"ring\"\nversion = \"0.17.12\"\nsource = \"registry+https://user:token@private.example.invalid/index\"\n";

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    path: PathBuf,
}
impl Fixture {
    fn new(manifest: &str, lock: &str) -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("cryptomap-manifest-{}-{id}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("Cargo.toml"), manifest).unwrap();
        fs::write(path.join("Cargo.lock"), lock).unwrap();
        Self { path }
    }
    fn scope(&self, manifest: bool, lock: bool, budget: usize) -> CollectionScope {
        let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-a").unwrap());
        if manifest {
            scope
                .grant_file(
                    RawSourceKind::Dependency,
                    "cargo:manifest",
                    &self.path,
                    "Cargo.toml",
                    budget,
                )
                .unwrap();
        }
        if lock {
            scope
                .grant_file(
                    RawSourceKind::Dependency,
                    "cargo:lock",
                    &self.path,
                    "Cargo.lock",
                    budget,
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

#[test]
fn unique_direct_dependency_is_stable_and_never_leaks_registry_credentials() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope(true, true, 4096);
    let first = reconcile_cargo_direct(
        &scope,
        "cargo:manifest",
        "cargo:lock",
        RawLimits::default(),
    )
    .unwrap();
    let again = reconcile_cargo_direct(
        &scope,
        "cargo:manifest",
        "cargo:lock",
        RawLimits::default(),
    )
    .unwrap();
    assert_eq!(first, again);
    assert_eq!(first.direct.len(), 1);
    assert_eq!(first.direct[0].name, "ring");
    assert_eq!(first.direct[0].version, "0.17.12");
    assert_eq!(first.lock_sha256.len(), 64);
    assert_eq!(first.manifest_sha256.len(), 64);
    assert!(!format!("{first:?}").contains("token"));
    assert!(!format!("{first:?}").contains("private.example.invalid"));
}

#[test]
fn no_implicit_grants_or_other_source_access() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    for (manifest, lock) in [(false, false), (true, false), (false, true)] {
        let scope = fixture.scope(manifest, lock, 4096);
        assert_eq!(
            reconcile_cargo_direct(
                &scope,
                "cargo:manifest",
                "cargo:lock",
                RawLimits::default()
            ),
            Err(CargoReconciliationError::UnauthorizedSource)
        );
    }
    let scope = fixture.scope(true, true, 4096);
    assert_eq!(
        reconcile_cargo_direct(&scope, "cargo:manifest", "cargo:manifest", RawLimits::default()),
        Err(CargoReconciliationError::InvalidSource)
    );
    assert_eq!(
        reconcile_cargo_direct(&scope, "cargo:lock", "../Cargo.toml", RawLimits::default()),
        Err(CargoReconciliationError::UnauthorizedSource)
    );
}

#[test]
fn ambiguous_lock_resolution_fails_without_partial_graph() {
    let lock = format!(
        "{LOCK}\n[[package]]\nname = \"ring\"\nversion = \"0.17.11\"\n"
    );
    let fixture = Fixture::new(MANIFEST, &lock);
    let scope = fixture.scope(true, true, 4096);
    assert_eq!(
        reconcile_cargo_direct(&scope, "cargo:manifest", "cargo:lock", RawLimits::default()),
        Err(CargoReconciliationError::UnresolvedDependency)
    );
}

#[test]
fn out_of_budget_file_and_combined_limit_are_denied() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let small = fixture.scope(true, true, 24);
    assert_eq!(
        reconcile_cargo_direct(&small, "cargo:manifest", "cargo:lock", RawLimits::default()),
        Err(CargoReconciliationError::UnauthorizedSource)
    );
    let scope = fixture.scope(true, true, 4096);
    let limits = RawLimits {
        total_bytes: MANIFEST.len() + LOCK.len() - 1,
        ..RawLimits::default()
    };
    assert_eq!(
        reconcile_cargo_direct(&scope, "cargo:manifest", "cargo:lock", limits),
        Err(CargoReconciliationError::ResourceLimit)
    );
}

#[test]
fn tampered_lock_or_unsupported_manifest_cannot_fabricate_direct_edge() {
    let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nring = \"0.17\"\n";
    let fixture = Fixture::new(manifest, LOCK);
    let scope = fixture.scope(true, true, 4096);
    assert_eq!(
        reconcile_cargo_direct(&scope, "cargo:manifest", "cargo:lock", RawLimits::default()),
        Err(CargoReconciliationError::UnsupportedProfile)
    );
    let changed = LOCK.replace("\"ring\",", "\"aes-gcm\",");
    let fixture = Fixture::new(MANIFEST, &changed);
    let scope = fixture.scope(true, true, 4096);
    assert_eq!(
        reconcile_cargo_direct(&scope, "cargo:manifest", "cargo:lock", RawLimits::default()),
        Err(CargoReconciliationError::UnresolvedDependency)
    );
}
