//! FOSS-322.8 authorized npm transitive install-path proof regression/security tests.
#![allow(clippy::unwrap_used)]
use cryptomap::{
    collectors::dependency::{
        npm_manifest::NpmReconciliationError,
        npm_transitive::{NpmTransitiveProof, resolve_npm_transitive},
    },
    coverage::CollectionScopeId,
    raw::{RawLimits, RawSourceKind},
    scope::CollectionScope,
};
use serde_json::Value;
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
    "node_modules/shared":{"version":"1.0.0","resolved":"https://user:token@registry.example.invalid/pkg.tgz"},
    "node_modules/b/node_modules/shared":{"version":"2.0.0"}
}}"#;

struct Fixture(PathBuf);
impl Fixture {
    fn new(manifest: &str, lock: &str) -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("cryptomap-transitive-{}-{id}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("package.json"), manifest).unwrap();
        fs::write(path.join("package-lock.json"), lock).unwrap();
        Self(path)
    }
    fn scope(&self, tenant: &str, manifest: bool, lock: bool, bytes: usize) -> CollectionScope {
        let mut scope = CollectionScope::new(CollectionScopeId::new(tenant).unwrap());
        if manifest {
            scope
                .grant_file(
                    RawSourceKind::Dependency,
                    "npm:manifest",
                    &self.0,
                    "package.json",
                    bytes,
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
                    bytes,
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
fn proof(scope: &CollectionScope) -> Result<NpmTransitiveProof, NpmReconciliationError> {
    resolve_npm_transitive(scope, "npm:manifest", "npm:lock", RawLimits::default())
}
fn changed_lock(mutator: impl FnOnce(&mut Value)) -> String {
    let mut document: Value = serde_json::from_str(LOCK).unwrap();
    mutator(&mut document);
    serde_json::to_string(&document).unwrap()
}
fn is_rejected(lock: &str) {
    let fixture = Fixture::new(MANIFEST, lock);
    let scope = fixture.scope("tenant-a", true, true, 8192);
    assert!(proof(&scope).is_err(), "corrupt lockfile was accepted");
}

#[test]
fn nested_and_hoisted_versions_remain_distinct_with_stable_exact_edges() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    let scope = fixture.scope("tenant-a", true, true, 8192);
    let one = proof(&scope).unwrap();
    assert_eq!(one, proof(&scope).unwrap());
    assert_eq!(one.manifest_sha256.len(), 64);
    assert_eq!(one.lock_sha256.len(), 64);
    assert_eq!(one.nodes.len(), 5);
    assert_eq!(one.edges.len(), 4);
    let shared: Vec<_> = one
        .nodes
        .iter()
        .filter(|node| node.name == "shared")
        .collect();
    assert_eq!(shared.len(), 2);
    assert_eq!(shared[0].path, "node_modules/b/node_modules/shared");
    assert_eq!(shared[0].version, "2.0.0");
    assert_eq!(shared[1].path, "node_modules/shared");
    assert_eq!(shared[1].version, "1.0.0");
    let edges: std::collections::BTreeSet<_> = one
        .edges
        .iter()
        .map(|edge| (edge.from_path.as_str(), edge.to_path.as_str()))
        .collect();
    assert!(edges.contains(&("node_modules/a", "node_modules/shared")));
    assert!(edges.contains(&("node_modules/b", "node_modules/b/node_modules/shared")));
    assert!(edges.contains(&("npm:root", "node_modules/a")));
    assert!(edges.contains(&("npm:root", "node_modules/b")));
    assert!(!format!("{one:?}").contains("user:token"));
    assert!(!format!("{one:?}").contains("registry.example.invalid"));
}

#[test]
fn same_name_same_version_installs_retain_separate_paths() {
    let lock = changed_lock(|document| {
        document["packages"]["node_modules/b"]["dependencies"]["shared"] = "1.0.0".into();
        document["packages"]["node_modules/b/node_modules/shared"]["version"] = "1.0.0".into();
    });
    let fixture = Fixture::new(MANIFEST, &lock);
    let scope = fixture.scope("tenant-a", true, true, 8192);
    let graph = proof(&scope).unwrap();
    assert_eq!(
        graph
            .nodes
            .iter()
            .filter(|node| node.name == "shared")
            .count(),
        2
    );
    assert!(graph.edges.iter().any(|edge| {
        edge.from_path == "node_modules/b" && edge.to_path == "node_modules/b/node_modules/shared"
    }));
}

#[test]
fn file_grants_and_resource_budgets_are_enforced_before_proof() {
    let fixture = Fixture::new(MANIFEST, LOCK);
    for (manifest, lock) in [(false, true), (true, false), (false, false)] {
        let scope = fixture.scope("tenant-a", manifest, lock, 8192);
        assert_eq!(
            proof(&scope),
            Err(NpmReconciliationError::UnauthorizedSource)
        );
    }
    let scope = fixture.scope("tenant-a", true, true, 12);
    assert_eq!(
        proof(&scope),
        Err(NpmReconciliationError::UnauthorizedSource)
    );
    let scope = fixture.scope("tenant-a", true, true, 8192);
    assert_eq!(
        resolve_npm_transitive(&scope, "npm:manifest", "npm:manifest", RawLimits::default()),
        Err(NpmReconciliationError::InvalidSource)
    );
    let quota = RawLimits {
        observations: 4,
        ..RawLimits::default()
    };
    assert!(resolve_npm_transitive(&scope, "npm:manifest", "npm:lock", quota).is_err());
    let bytes = RawLimits {
        total_bytes: MANIFEST.len() + LOCK.len() - 1,
        ..RawLimits::default()
    };
    assert_eq!(
        resolve_npm_transitive(&scope, "npm:manifest", "npm:lock", bytes),
        Err(NpmReconciliationError::ResourceLimit)
    );
}

#[test]
fn path_traversal_workspace_and_missing_parent_are_never_accepted() {
    is_rejected(&changed_lock(|json| {
        json["packages"]["node_modules/a/node_modules/../leak"] =
            json["packages"]["node_modules/b/node_modules/shared"].take();
    }));
    is_rejected(&changed_lock(|json| {
        json["packages"]["node_modules/a/node_modules/shared"] =
            json["packages"]["node_modules/b/node_modules/shared"].take();
    }));
    is_rejected(&changed_lock(|json| {
        json["packages"]["packages/workspace"] = serde_json::json!({"version":"1.0.0"});
    }));
}

#[test]
fn unresolved_versions_unsupported_roles_and_orphans_fail_closed() {
    is_rejected(&changed_lock(|json| {
        json["packages"]["node_modules/b"]["dependencies"]["shared"] = "3.0.0".into();
    }));
    is_rejected(&changed_lock(|json| {
        json["packages"]["node_modules/b/node_modules/shared"]["optional"] = true.into();
    }));
    is_rejected(&changed_lock(|json| {
        json["packages"]["node_modules/a"]["peerDependencies"] =
            serde_json::json!({"missing":"1.0.0"});
    }));
    is_rejected(&changed_lock(|json| {
        json["packages"]["node_modules/orphan"] = serde_json::json!({"version":"1.0.0"});
    }));
    is_rejected(&changed_lock(|json| {
        json["packages"]["node_modules/a"]["dependencies"]["shared"] = "^1.0.0".into();
    }));
}

#[test]
fn reachable_cycle_is_detected_without_recursion_or_hanging() {
    let manifest = r#"{"name":"app","version":"1.0.0","dependencies":{"a":"1.0.0"}}"#;
    let lock = r#"{"lockfileVersion":3,"packages":{
        "":{"name":"app","version":"1.0.0","dependencies":{"a":"1.0.0"}},
        "node_modules/a":{"version":"1.0.0","dependencies":{"b":"1.0.0"}},
        "node_modules/b":{"version":"1.0.0","dependencies":{"a":"1.0.0"}}
    }}"#;
    let fixture = Fixture::new(manifest, lock);
    let scope = fixture.scope("tenant-a", true, true, 8192);
    assert_eq!(
        proof(&scope),
        Err(NpmReconciliationError::UnsupportedProfile)
    );
}

#[test]
fn duplicate_json_keys_and_invalid_nested_structure_are_rejected() {
    let duplicate = LOCK.replace(
        "\"node_modules/shared\":{\"version\":\"1.0.0\"",
        "\"node_modules/shared\":{\"version\":\"1.0.0\",\"version\":\"2.0.0\"",
    );
    assert_ne!(duplicate, LOCK);
    is_rejected(&duplicate);
    is_rejected(&changed_lock(|json| {
        json["packages"]["node_modules/b/node_modules/shared"]["version"] = "malformed".into();
    }));
}
