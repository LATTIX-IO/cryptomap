//! Path-scoped npm transitive dependency resolution without canonical identity loss.
//! Never asserts algorithm use or writes name/version-only canonical relationships.
use super::{
    npm::parse_lock,
    npm_manifest::{NpmReconciliationError, package_name, numeric_version, reconcile_npm_direct},
};
use crate::{
    collector::CollectorDiagnosticCode,
    raw::{RawLimits, RawSourceKind},
    scope::CollectionScope,
    strict_json::StrictJson,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// A package identified by its unique lockfile installation path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmInstalledNode {
    /// npm:root for the project, otherwise a canonical node_modules path.
    pub path: String,
    /// Name including scope if present.
    pub name: String,
    /// Exactly resolved version.
    pub version: String,
}

/// An exact pinned dependency between unique installed paths.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NpmPathEdge {
    /// Requiring installation path, or npm:root.
    pub from_path: String,
    /// Resolved installed path.
    pub to_path: String,
}

/// Sorted, immutable path-scoped proof, not canonical inventory edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmTransitiveProof {
    /// Exact authorized package.json SHA-256.
    pub manifest_sha256: String,
    /// Exact authorized package-lock.json SHA-256.
    pub lock_sha256: String,
    /// All reachable installed nodes, including root, sorted by path.
    pub nodes: Vec<NpmInstalledNode>,
    /// All proven production edges sorted by path.
    pub edges: Vec<NpmPathEdge>,
}

fn installed_path(path: &str, limit: usize) -> Result<String, NpmReconciliationError> {
    use NpmReconciliationError::InvalidSource;
    if path.len() > limit {
        return Err(NpmReconciliationError::ResourceLimit);
    }
    let segments: Vec<&str> = path.split('/').collect();
    let mut cursor = 0;
    let mut last_name = String::new();
    while cursor < segments.len() {
        if segments[cursor] != "node_modules" {
            return Err(InvalidSource);
        }
        cursor += 1;
        let first = *segments.get(cursor).ok_or(InvalidSource)?;
        let name = if first.starts_with('@') {
            let second = *segments.get(cursor + 1).ok_or(InvalidSource)?;
            cursor += 2;
            format!("{first}/{second}")
        } else {
            cursor += 1;
            first.to_owned()
        };
        if !package_name(&name) {
            return Err(InvalidSource);
        }
        last_name = name;
    }
    if last_name.is_empty() {
        return Err(InvalidSource);
    }
    Ok(last_name)
}

fn parent_path(path: &str) -> &str {
    path.rfind("/node_modules/")
        .map_or("npm:root", |index| &path[..index])
}

fn installed_for(
    nodes: &BTreeMap<String, NpmInstalledNode>,
    parent: &str,
    dependency: &str,
) -> Result<String, NpmReconciliationError> {
    let mut at = parent;
    loop {
        let candidate = if at == "npm:root" {
            format!("node_modules/{dependency}")
        } else {
            format!("{at}/node_modules/{dependency}")
        };
        if nodes.contains_key(&candidate) {
            return Ok(candidate);
        }
        if at == "npm:root" {
            return Err(NpmReconciliationError::UnresolvedDependency);
        }
        at = parent_path(at);
    }
}

fn dependencies(
    package: &Map<String, Value>,
    limits: RawLimits,
) -> Result<BTreeMap<String, String>, NpmReconciliationError> {
    use NpmReconciliationError::{InvalidSource, ResourceLimit, UnsupportedProfile};
    for key in [
        "optionalDependencies", "peerDependencies", "devDependencies",
        "bundleDependencies", "bundledDependencies", "peerDependenciesMeta",
    ] {
        if package.contains_key(key) {
            return Err(UnsupportedProfile);
        }
    }
    for flag in ["dev", "optional", "devOptional", "peer", "link", "inBundle"] {
        match package.get(flag) {
            Some(Value::Bool(false)) | None => {}
            Some(Value::Bool(true)) => return Err(UnsupportedProfile),
            Some(_) => return Err(InvalidSource),
        }
    }
    let Some(value) = package.get("dependencies") else {
        return Ok(BTreeMap::new());
    };
    let map = value.as_object().ok_or(UnsupportedProfile)?;
    if map.len() > limits.observations {
        return Err(ResourceLimit);
    }
    let mut deps = BTreeMap::new();
    for (name, pin) in map {
        if name.len() > limits.field_bytes || !package_name(name) {
            return Err(InvalidSource);
        }
        let version = pin.as_str().ok_or(UnsupportedProfile)?;
        if version.len() > limits.field_bytes || !numeric_version(version) {
            return Err(UnsupportedProfile);
        }
        deps.insert(name.clone(), version.to_owned());
    }
    Ok(deps)
}

fn validate_graph(
    nodes: &BTreeMap<String, NpmInstalledNode>,
    edges: &BTreeSet<NpmPathEdge>,
) -> Result<(), NpmReconciliationError> {
    use NpmReconciliationError::{ResourceLimit, UnsupportedProfile, UnresolvedDependency};
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut indegree: BTreeMap<&str, usize> =
        nodes.keys().map(|path| (path.as_str(), 0)).collect();
    for edge in edges {
        adjacency.entry(&edge.from_path).or_default().push(&edge.to_path);
        let degree = indegree.get_mut(edge.to_path.as_str()).ok_or(UnresolvedDependency)?;
        *degree = degree.checked_add(1).ok_or(ResourceLimit)?;
    }
    let mut reachable = BTreeSet::new();
    let mut pending = VecDeque::from(["npm:root"]);
    while let Some(path) = pending.pop_front() {
        if reachable.insert(path) {
            if let Some(children) = adjacency.get(path) {
                pending.extend(children.iter().copied());
            }
        }
    }
    if reachable.len() != nodes.len() {
        return Err(UnresolvedDependency);
    }
    // Bounded nonrecursive topological scan rejects cycles instead of
    // silently projecting a truncated dependency graph.
    let mut queue: VecDeque<&str> = indegree
        .iter()
        .filter_map(|(&path, &degree)| (degree == 0).then_some(path))
        .collect();
    let mut processed = 0;
    while let Some(path) = queue.pop_front() {
        processed += 1;
        if let Some(children) = adjacency.get(path) {
            for &child in children {
                let degree = indegree.get_mut(child).ok_or(UnresolvedDependency)?;
                *degree -= 1;
                if *degree == 0 {
                    queue.push_back(child);
                }
            }
        }
    }
    if processed != nodes.len() {
        return Err(UnsupportedProfile);
    }
    Ok(())
}

/// Produce a complete, path-unique proof of exact-pinned npm production edges.
///
/// Both files require independently granted exact file capabilities. The lock
/// is re-read and its hash compared against the existing direct proof, so
/// changed data cannot be mixed into one result. Traversal, missing ancestors,
/// unsupported optional/dev/peer/link semantics, cycles, unreachable packages,
/// and incorrect resolved versions are rejected. No npm execution or network.
///
/// This is not a canonical DependsOn projection: canonical Library IDs omit
/// install path and would conflate distinct installations.
pub fn resolve_npm_transitive(
    scope: &CollectionScope,
    manifest_item: &str,
    lock_item: &str,
    limits: RawLimits,
) -> Result<NpmTransitiveProof, NpmReconciliationError> {
    use NpmReconciliationError::{
        InvalidSource, ResourceLimit, UnauthorizedSource, UnresolvedDependency, UnsupportedProfile,
    };
    let direct = reconcile_npm_direct(scope, manifest_item, lock_item, limits)?;
    let bytes = scope
        .open_file(RawSourceKind::Dependency, lock_item)
        .and_then(|file| file.read_bounded())
        .map_err(|_| UnauthorizedSource)?;
    if format!("{:x}", Sha256::digest(&bytes)) != direct.lock_sha256 {
        return Err(UnresolvedDependency);
    }
    let (packages, incomplete) = parse_lock(&bytes, limits).map_err(|error| match error {
        CollectorDiagnosticCode::ResourceLimit => ResourceLimit,
        CollectorDiagnosticCode::UnsupportedSource => UnsupportedProfile,
        _ => InvalidSource,
    })?;
    if incomplete {
        return Err(UnsupportedProfile);
    }
    let strict: StrictJson = serde_json::from_slice(&bytes).map_err(|_| InvalidSource)?;
    let lock = strict.0.as_object().ok_or(InvalidSource)?;
    let table = lock.get("packages").and_then(Value::as_object).ok_or(InvalidSource)?;
    let mut nodes = BTreeMap::new();
    let mut declared = BTreeMap::new();
    for package in packages {
        let path = package.path;
        let name = if path == "npm:root" {
            if package.name != direct.root_name || package.version != direct.root_version {
                return Err(UnresolvedDependency);
            }
            package.name
        } else {
            let name = installed_path(&path, limits.field_bytes)?;
            if name != package.name {
                return Err(UnresolvedDependency);
            }
            if let Some(parent) = path.rfind("/node_modules/") {
                if !table.contains_key(&path[..parent]) {
                    return Err(UnresolvedDependency);
                }
            }
            name
        };
        if !numeric_version(&package.version) {
            return Err(UnsupportedProfile);
        }
        let key = if path == "npm:root" { "" } else { &path };
        let record = table.get(key).and_then(Value::as_object).ok_or(InvalidSource)?;
        if record.get("name").is_some_and(|value| value.as_str() != Some(&name)) {
            return Err(UnresolvedDependency);
        }
        let deps = dependencies(record, limits)?;
        declared.insert(path.clone(), deps);
        nodes.insert(path.clone(), NpmInstalledNode {
            path,
            name,
            version: package.version,
        });
    }
    if !nodes.contains_key("npm:root") || nodes.len() > limits.observations {
        return Err(UnresolvedDependency);
    }
    let mut edges = BTreeSet::new();
    for (path, deps) in &declared {
        for (dependency, pin) in deps {
            let target = installed_for(&nodes, path, dependency)?;
            if nodes.get(&target).is_none_or(|node| &node.version != pin) {
                return Err(UnresolvedDependency);
            }
            edges.insert(NpmPathEdge {
                from_path: path.clone(),
                to_path: target,
            });
            if edges.len() > limits.observations {
                return Err(ResourceLimit);
            }
        }
    }
    validate_graph(&nodes, &edges)?;
    Ok(NpmTransitiveProof {
        manifest_sha256: direct.manifest_sha256,
        lock_sha256: direct.lock_sha256,
        nodes: nodes.into_values().collect(),
        edges: edges.into_iter().collect(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn path_parser_rejects_noncanonical_and_escaped_segments() {
        for invalid in [
            "node_modules", "node_modules/../secret",
            "lib/node_modules/ring", "node_modules/a/lib/node_modules/b",
            "node_modules//a", "node_modules/@scope",
            "node_modules/a/node_modules/._bad",
            "node_modules/a\\node_modules/b",
        ] {
            assert!(installed_path(invalid, 512).is_err(), "{invalid}");
        }
        assert_eq!(
            installed_path("node_modules/a/node_modules/@scope/b", 512).unwrap(),
            "@scope/b"
        );
    }

    #[test]
    fn nearest_nested_ancestor_precedes_hoisted_root() {
        let nodes: BTreeMap<String, NpmInstalledNode> = [
            ("npm:root", "app", "1.0.0"),
            ("node_modules/x", "x", "1.0.0"),
            ("node_modules/y", "y", "2.0.0"),
            ("node_modules/x/node_modules/y", "y", "1.0.0"),
        ].into_iter().map(|(path, name, version)| (
            path.to_owned(),
            NpmInstalledNode {
                path: path.to_owned(), name: name.to_owned(), version: version.to_owned(),
            },
        )).collect();
        assert_eq!(
            installed_for(&nodes, "node_modules/x", "y").unwrap(),
            "node_modules/x/node_modules/y"
        );
        assert_eq!(installed_for(&nodes, "npm:root", "y").unwrap(), "node_modules/y");
    }
}
