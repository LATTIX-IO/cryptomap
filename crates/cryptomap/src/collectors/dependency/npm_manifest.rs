//! Fail-closed npm package.json to package-lock v2/v3 exact direct matching.
//!
//! Bounded, passive two-file proof only. Never runs npm or infers runtime use.
use super::npm::parse_lock;
use crate::{
    raw::{RawLimits, RawSourceKind},
    scope::CollectionScope,
    strict_json::StrictJson,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, error::Error, fmt};

/// Sanitized error variant; neither raw source nor package credentials leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NpmReconciliationError {
    /// Required file grant missing or bounded file read denied.
    UnauthorizedSource,
    /// File or package-count limit exceeded.
    ResourceLimit,
    /// JSON, required fields or package metadata invalid.
    InvalidSource,
    /// Valid syntax uses deliberately unsupported npm semantics.
    UnsupportedProfile,
    /// Manifest pin does not uniquely resolve at the root lock path.
    UnresolvedDependency,
}
impl fmt::Display for NpmReconciliationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for NpmReconciliationError {}

/// Exact-pinned production dependency proven at root node_modules location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmDirectDependency {
    /// Npm name, preserving its explicit scope.
    pub name: String,
    /// Exact numeric installed version.
    pub version: String,
}
/// Source-hashed, immutable direct-dependency proof; not a runtime graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmDirectReconciliation {
    /// Verified root package name.
    pub root_name: String,
    /// Verified root package version.
    pub root_version: String,
    /// SHA-256 of the exact approved package.json contents.
    pub manifest_sha256: String,
    /// SHA-256 of the exact approved package-lock.json contents.
    pub lock_sha256: String,
    /// Sorted root-level dependencies with explicit exact matches.
    pub direct: Vec<NpmDirectDependency>,
}

#[derive(Debug, Clone)]
struct Manifest {
    name: String,
    version: String,
    deps: BTreeMap<String, String>,
}

fn numeric_version(version: &str) -> bool {
    let mut parts = version.split('.');
    (0..3).all(|_| {
        parts.next().is_some_and(|part| {
            !part.is_empty()
                && (part.len() == 1 || !part.starts_with('0'))
                && part.bytes().all(|b| b.is_ascii_digit())
                && part.parse::<u64>().is_ok()
        })
    }) && parts.next().is_none()
}

fn package_name(name: &str) -> bool {
    fn segment(s: &str) -> bool {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
            })
    }
    if let Some(scoped) = name.strip_prefix('@') {
        scoped
            .split_once('/')
            .is_some_and(|(scope, pkg)| segment(scope) && segment(pkg))
    } else {
        segment(name)
    }
}
fn string_field<'a>(
    obj: &'a serde_json::Map<String, Value>,
    key: &str,
    limit: usize,
) -> Result<&'a str, NpmReconciliationError> {
    let value = obj
        .get(key)
        .and_then(Value::as_str)
        .ok_or(NpmReconciliationError::InvalidSource)?;
    if value.len() > limit || value.trim() != value {
        return Err(NpmReconciliationError::InvalidSource);
    }
    crate::validation::safe_text(value, limit)
        .map_err(|_| NpmReconciliationError::InvalidSource)?;
    Ok(value)
}
fn parse_json(bytes: &[u8]) -> Result<Value, NpmReconciliationError> {
    let document: StrictJson =
        serde_json::from_slice(bytes).map_err(|_| NpmReconciliationError::InvalidSource)?;
    Ok(document.0)
}
fn parse_manifest(bytes: &[u8], limits: RawLimits) -> Result<Manifest, NpmReconciliationError> {
    use NpmReconciliationError::{InvalidSource, ResourceLimit, UnsupportedProfile};
    if bytes.len() > limits.total_bytes {
        return Err(ResourceLimit);
    }
    let json = parse_json(bytes)?;
    let obj = json.as_object().ok_or(InvalidSource)?;
    // Optional, peer, dev, override and workspace semantics may change the
    // actual installation. Never silently claim complete direct coverage.
    if obj
        .keys()
        .any(|key| !matches!(key.as_str(), "name" | "version" | "dependencies"))
    {
        return Err(UnsupportedProfile);
    }
    let name = string_field(obj, "name", limits.field_bytes)?;
    let version = string_field(obj, "version", limits.field_bytes)?;
    if !package_name(name) || !numeric_version(version) {
        return Err(UnsupportedProfile);
    }
    let values = obj
        .get("dependencies")
        .and_then(Value::as_object)
        .ok_or(UnsupportedProfile)?;
    // Reserve a separate record for root metadata and cap before cloning.
    if values.len() >= limits.observations {
        return Err(ResourceLimit);
    }
    let mut deps = BTreeMap::new();
    for (name, spec) in values {
        if name.len() > limits.field_bytes || !package_name(name) {
            return Err(InvalidSource);
        }
        let pinned = spec.as_str().ok_or(UnsupportedProfile)?;
        if pinned.len() > limits.field_bytes || !numeric_version(pinned) {
            return Err(UnsupportedProfile);
        }
        deps.insert(name.clone(), pinned.to_owned());
    }
    Ok(Manifest {
        name: name.to_owned(),
        version: version.to_owned(),
        deps,
    })
}
fn prove(
    manifest: &Manifest,
    bytes: &[u8],
    limits: RawLimits,
) -> Result<Vec<NpmDirectDependency>, NpmReconciliationError> {
    use NpmReconciliationError::{
        InvalidSource, ResourceLimit, UnresolvedDependency, UnsupportedProfile,
    };
    let json = parse_json(bytes)?;
    let obj = json.as_object().ok_or(InvalidSource)?;
    if !matches!(
        obj.get("lockfileVersion").and_then(Value::as_u64),
        Some(2 | 3)
    ) {
        return Err(UnsupportedProfile);
    }
    // Top-level npm lock identity, when present, cannot contradict the
    // package table root: otherwise the apparent root may be substituted.
    if obj.get("name").is_some_and(|value| value.as_str() != Some(&manifest.name))
        || obj
            .get("version")
            .is_some_and(|value| value.as_str() != Some(&manifest.version))
    {
        return Err(UnresolvedDependency);
    }
    let root = obj
        .get("packages")
        .and_then(Value::as_object)
        .and_then(|packages| packages.get(""))
        .and_then(Value::as_object)
        .ok_or(InvalidSource)?;
    if root
        .keys()
        .any(|key| !matches!(key.as_str(), "name" | "version" | "dependencies"))
    {
        return Err(UnsupportedProfile);
    }
    if string_field(root, "name", limits.field_bytes)? != manifest.name
        || string_field(root, "version", limits.field_bytes)? != manifest.version
    {
        return Err(UnresolvedDependency);
    }
    let declared = root
        .get("dependencies")
        .and_then(Value::as_object)
        .ok_or(UnsupportedProfile)?;
    if declared.len() != manifest.deps.len() {
        return Err(UnresolvedDependency);
    }
    for (name, version) in &manifest.deps {
        if declared.get(name).and_then(Value::as_str) != Some(version.as_str()) {
            return Err(UnresolvedDependency);
        }
    }
    // This independent strict parser rejects duplicate JSON keys, invalid
    // node_modules locations, unsupported local links and package-count abuse.
    let (installed, incomplete) = parse_lock(bytes, limits).map_err(|code| match code {
        crate::collector::CollectorDiagnosticCode::ResourceLimit => ResourceLimit,
        crate::collector::CollectorDiagnosticCode::UnsupportedSource => UnsupportedProfile,
        _ => InvalidSource,
    })?;
    if incomplete {
        return Err(UnsupportedProfile);
    }
    let mut direct = Vec::with_capacity(manifest.deps.len());
    let package_table = obj
        .get("packages")
        .and_then(Value::as_object)
        .ok_or(InvalidSource)?;
    for (name, version) in &manifest.deps {
        let path = format!("node_modules/{name}");
        let package = package_table
            .get(&path)
            .and_then(Value::as_object)
            .ok_or(UnresolvedDependency)?;
        if package
            .get("name")
            .is_some_and(|value| value.as_str() != Some(name.as_str()))
        {
            return Err(UnresolvedDependency);
        }
        let matches: Vec<_> = installed
            .iter()
            .filter(|package| package.path == path)
            .collect();
        if matches.len() != 1 || matches[0].name != *name || matches[0].version != *version {
            return Err(UnresolvedDependency);
        }
        direct.push(NpmDirectDependency {
            name: name.clone(),
            version: version.clone(),
        });
    }
    Ok(direct)
}

/// Match an exact-pinned npm package manifest to a root-installed v2/v3 lock.
///
/// Caller must separately grant both exact dependency files to the same
/// CollectionScope. This conservative profile accepts only a root name,
/// numeric version and exact numeric dependencies. It rejects additional
/// package.json keys, optional/dev/peer/workspace/alias/range semantics,
/// mismatched root lock declarations, local links, and unsupported lockfiles.
/// No npm process, network, implicit traversal, or algorithm use inference.
pub fn reconcile_npm_direct(
    scope: &CollectionScope,
    manifest_item: &str,
    lock_item: &str,
    limits: RawLimits,
) -> Result<NpmDirectReconciliation, NpmReconciliationError> {
    use NpmReconciliationError::{InvalidSource, ResourceLimit, UnauthorizedSource};
    limits.validate().map_err(|_| InvalidSource)?;
    if manifest_item == lock_item {
        return Err(InvalidSource);
    }
    let manifest_bytes = scope
        .open_file(RawSourceKind::Dependency, manifest_item)
        .and_then(|file| file.read_bounded())
        .map_err(|_| UnauthorizedSource)?;
    let lock_bytes = scope
        .open_file(RawSourceKind::Dependency, lock_item)
        .and_then(|file| file.read_bounded())
        .map_err(|_| UnauthorizedSource)?;
    if manifest_bytes
        .len()
        .checked_add(lock_bytes.len())
        .ok_or(ResourceLimit)?
        > limits.total_bytes
    {
        return Err(ResourceLimit);
    }
    let manifest = parse_manifest(&manifest_bytes, limits)?;
    let direct = prove(&manifest, &lock_bytes, limits)?;
    Ok(NpmDirectReconciliation {
        root_name: manifest.name,
        root_version: manifest.version,
        manifest_sha256: format!("{:x}", Sha256::digest(&manifest_bytes)),
        lock_sha256: format!("{:x}", Sha256::digest(&lock_bytes)),
        direct,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    const MANIFEST: &[u8] =
        br#"{"name":"app","version":"1.0.0","dependencies":{"@scope/ring":"1.2.3"}}"#;
    const LOCK: &[u8] =
        br#"{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"@scope/ring":"1.2.3"}},"node_modules/@scope/ring":{"version":"1.2.3"}}}"#;

    #[test]
    fn exact_scoped_root_direct_dependency_is_proven() {
        let manifest = parse_manifest(MANIFEST, RawLimits::default()).unwrap();
        let direct = prove(&manifest, LOCK, RawLimits::default()).unwrap();
        assert_eq!(
            direct,
            vec![NpmDirectDependency {
                name: "@scope/ring".into(),
                version: "1.2.3".into(),
            }]
        );
    }

    #[test]
    fn duplicate_json_and_unsafe_manifest_semantics_fail_closed() {
        for document in [
            br#"{"name":"app","name":"override","version":"1.0.0","dependencies":{}}"#.as_slice(),
            br#"{"name":"app","version":"1.0.0","dependencies":{"ring":"1.0.0","ring":"2.0.0"}}"#.as_slice(),
            br#"{"name":"app","version":"1.0.0","dependencies":{"../ring":"1.0.0"}}"#.as_slice(),
            br#"{"name":"app","version":"1.0.0","dependencies":{"ring":"^1.0.0"}}"#.as_slice(),
            br#"{"name":"app","version":"bad","dependencies":{}}"#.as_slice(),
            br#"{"name":"app","version":"1.0.0","dependencies":{},"scripts":{"postinstall":"hello"}}"#.as_slice(),
        ] {
            assert!(parse_manifest(document, RawLimits::default()).is_err());
        }
    }

    #[test]
    fn root_version_and_installed_package_drift_fail_closed() {
        let manifest = parse_manifest(MANIFEST, RawLimits::default()).unwrap();
        for lock in [
            br#"{"lockfileVersion":3,"packages":{"":{"name":"app","version":"2.0.0","dependencies":{"@scope/ring":"1.2.3"}},"node_modules/@scope/ring":{"version":"1.2.3"}}}"#.as_slice(),
            br#"{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"@scope/ring":"1.2.3"}},"node_modules/@scope/ring":{"version":"1.2.4"}}}"#.as_slice(),
            br#"{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"@scope/ring":"^1.2.3"}},"node_modules/@scope/ring":{"version":"1.2.3"}}}"#.as_slice(),
            br#"{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"@scope/ring":"1.2.3"}},"node_modules/@scope/ring":{"version":"1.2.3","link":true}}}"#.as_slice(),
        ] {
            assert!(prove(&manifest, lock, RawLimits::default()).is_err());
        }
    }

    #[test]
    fn numeric_versions_and_count_budgets_are_strict() {
        assert!(numeric_version("0.0.0"));
        assert!(!numeric_version("1.2.3-alpha"));
        assert!(!numeric_version("18446744073709551616.1.2"));
        assert!(!package_name("../outside"));
        let cap = RawLimits {
            observations: 1,
            ..RawLimits::default()
        };
        assert_eq!(
            parse_manifest(MANIFEST, cap).err(),
            Some(NpmReconciliationError::ResourceLimit)
        );
    }
}
