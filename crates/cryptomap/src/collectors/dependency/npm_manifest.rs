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
    /// Persisted dual-source proof or canonical tenant/run provenance is missing.
    UnboundEvidence,
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
pub(super) struct Manifest {
    pub(super) name: String,
    pub(super) version: String,
    pub(super) deps: BTreeMap<String, String>,
}

pub(super) fn numeric_version(version: &str) -> bool {
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

pub(super) fn package_name(name: &str) -> bool {
    // npm's complete package name is bounded even if raw field_bytes permits
    // longer metadata; root and dependency paths must use valid names.
    if name.len() > 214 {
        return false;
    }
    fn segment(s: &str) -> bool {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.bytes().next().is_some_and(|b| b != b'.' && b != b'_')
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
pub(super) fn parse_manifest(
    bytes: &[u8],
    limits: RawLimits,
) -> Result<Manifest, NpmReconciliationError> {
    use NpmReconciliationError::{InvalidSource, ResourceLimit, UnsupportedProfile};
    if bytes.len() > limits.total_bytes {
        return Err(ResourceLimit);
    }
    let json = parse_json(bytes)?;
    let obj = json.as_object().ok_or(InvalidSource)?;
    // Optional, peer, dev, override and workspace semantics may change the
    // actual installation. Never silently claim complete direct coverage.
    if obj.keys().any(|key| {
        !matches!(
            key.as_str(),
            "name" | "version" | "dependencies" | "private" | "type"
        )
    }) {
        return Err(UnsupportedProfile);
    }
    // Explicitly ignore validated non-dependency project metadata. Never
    // reinterpret these fields as evidence of runtime dependency or crypto use.
    if obj.get("private").is_some_and(|value| !value.is_boolean()) {
        return Err(UnsupportedProfile);
    }
    if let Some(module_type) = obj.get("type") {
        let module_type = module_type.as_str().ok_or(UnsupportedProfile)?;
        if module_type.len() > limits.field_bytes || !matches!(module_type, "commonjs" | "module") {
            return Err(UnsupportedProfile);
        }
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
    if obj
        .get("name")
        .is_some_and(|value| value.as_str() != Some(&manifest.name))
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
    if root.keys().any(|key| {
        !matches!(
            key.as_str(),
            "name" | "version" | "dependencies" | "license"
        )
    }) {
        return Err(UnsupportedProfile);
    }
    // A source-hashed root license declaration is inert package metadata, not
    // a dependency, authorization grant or cryptographic runtime-use signal.
    // Do not allow malformed, empty, oversized or non-string declarations.
    if root.contains_key("license") && string_field(root, "license", limits.field_bytes)?.is_empty()
    {
        return Err(InvalidSource);
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
        // Declared direct production pins cannot rely on dev-only, optional,
        // linked or bundled records. Malformed flags never default to false.
        for flag in ["dev", "optional", "devOptional", "peer", "link", "inBundle"] {
            match package.get(flag) {
                Some(Value::Bool(false)) | None => {}
                Some(Value::Bool(true)) => return Err(UnsupportedProfile),
                Some(_) => return Err(InvalidSource),
            }
        }
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
/// CollectionScope. This conservative profile accepts root name, numeric
/// version, exact numeric dependencies, plus validated nondependency
/// `private` (boolean) and `type` ("commonjs" or "module") metadata.
/// It rejects other package.json keys, optional/dev/peer/workspace/alias/range semantics,
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
    fn validated_root_metadata_does_not_change_npm_dependency_proof() {
        let baseline = parse_manifest(MANIFEST, RawLimits::default()).unwrap();
        let direct = prove(&baseline, LOCK, RawLimits::default()).unwrap();
        for (private, module_type) in [
            (true, "commonjs"),
            (false, "module"),
            (true, "module"),
            (false, "commonjs"),
        ] {
            let candidate = format!(
                "{{\"name\":\"app\",\"version\":\"1.0.0\",\"private\":{private},\"type\":\"{module_type}\",\"dependencies\":{{\"@scope/ring\":\"1.2.3\"}}}}"
            );
            let manifest = parse_manifest(candidate.as_bytes(), RawLimits::default()).unwrap();
            assert_eq!(manifest.name, baseline.name);
            assert_eq!(manifest.version, baseline.version);
            assert_eq!(manifest.deps, baseline.deps);
            assert_eq!(
                prove(&manifest, LOCK, RawLimits::default()).unwrap(),
                direct
            );
        }
        for metadata in [r#""private":true"#, r#""type":"module""#] {
            let candidate = format!(
                "{{\"name\":\"app\",\"version\":\"1.0.0\",{metadata},\"dependencies\":{{\"@scope/ring\":\"1.2.3\"}}}}"
            );
            let manifest = parse_manifest(candidate.as_bytes(), RawLimits::default()).unwrap();
            assert_eq!(
                prove(&manifest, LOCK, RawLimits::default()).unwrap(),
                direct
            );
        }
    }

    #[test]
    fn invalid_metadata_and_unsupported_installation_semantics_fail_closed() {
        for metadata in [
            r#""private":"true""#,
            r#""private":1"#,
            r#""private":null"#,
            r#""private":[]"#,
            r#""private":true,"private":false"#,
            r#""type":true"#,
            r#""type":null"#,
            r#""type":"amd""#,
            r#""type":"" "#,
            r#""type":"MODULE""#,
            r#""type":"module","type":"commonjs""#,
            r#""scripts":{"postinstall":"ignored"}"#,
            r#""devDependencies":{"other":"1.0.0"}"#,
            r#""optionalDependencies":{"other":"1.0.0"}"#,
            r#""peerDependencies":{"other":"1.0.0"}"#,
            r#""workspaces":["packages/*"]"#,
            r#""overrides":{"other":"1.0.0"}"#,
            r#""type":"module","dependencies":{"evil":"1.0.0"}"#,
        ] {
            let candidate = format!(
                "{{\"name\":\"app\",\"version\":\"1.0.0\",{metadata},\"dependencies\":{{\"@scope/ring\":\"1.2.3\"}}}}"
            );
            assert!(
                parse_manifest(candidate.as_bytes(), RawLimits::default()).is_err(),
                "unsupported metadata may not establish a direct dependency: {metadata}"
            );
        }
        // Allow name and root version within budget, but deny the longer
        // module type specifically instead of failing on an unrelated field.
        let tiny = RawLimits {
            field_bytes: 6,
            ..RawLimits::default()
        };
        let long_type = br#"{"name":"app","version":"1.0.0","type":"commonjs","dependencies":{}}"#;
        assert!(parse_manifest(long_type, tiny).is_err());
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
    fn validated_lock_root_license_does_not_change_dependency_proof() {
        let manifest = parse_manifest(MANIFEST, RawLimits::default()).unwrap();
        let baseline = prove(&manifest, LOCK, RawLimits::default()).unwrap();
        for license in ["MIT", "Apache-2.0", "UNLICENSED", "MIT OR Apache-2.0"] {
            let mut lock: Value = serde_json::from_slice(LOCK).unwrap();
            lock["packages"][""]["license"] = Value::String(license.into());
            let bytes = serde_json::to_vec(&lock).unwrap();
            assert_eq!(
                prove(&manifest, &bytes, RawLimits::default()).unwrap(),
                baseline
            );
        }
    }

    #[test]
    fn invalid_lock_root_license_and_unknown_fields_fail_closed() {
        let manifest = parse_manifest(MANIFEST, RawLimits::default()).unwrap();
        for value in [
            Value::Null,
            Value::Bool(true),
            serde_json::json!(7),
            serde_json::json!([]),
            serde_json::json!({"type": "MIT"}),
            Value::String(String::new()),
            Value::String(" MIT".into()),
            Value::String("MIT ".into()),
            Value::String("A".repeat(RawLimits::default().field_bytes + 1)),
        ] {
            let mut lock: Value = serde_json::from_slice(LOCK).unwrap();
            lock["packages"][""]["license"] = value;
            let bytes = serde_json::to_vec(&lock).unwrap();
            assert!(prove(&manifest, &bytes, RawLimits::default()).is_err());
        }
        let duplicate = std::str::from_utf8(LOCK).unwrap().replace(
            r#""name":"app","version":"1.0.0","dependencies""#,
            r#""name":"app","version":"1.0.0","license":"MIT","license":"GPL","dependencies""#,
        );
        assert_ne!(duplicate.as_bytes(), LOCK);
        assert!(prove(&manifest, duplicate.as_bytes(), RawLimits::default()).is_err());

        let mut unsupported: Value = serde_json::from_slice(LOCK).unwrap();
        unsupported["packages"][""]["scripts"] = serde_json::json!({"postinstall": "run"});
        assert!(
            prove(
                &manifest,
                &serde_json::to_vec(&unsupported).unwrap(),
                RawLimits::default()
            )
            .is_err()
        );

        let mut oversized: Value = serde_json::from_slice(LOCK).unwrap();
        oversized["packages"][""]["license"] = Value::String("Apache-2.0".into());
        let tight = RawLimits {
            field_bytes: 6,
            ..RawLimits::default()
        };
        assert!(prove(&manifest, &serde_json::to_vec(&oversized).unwrap(), tight).is_err());
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
    fn package_names_have_npm_bounds_and_safe_leading_chars() {
        assert!(package_name("ring"));
        assert!(package_name("@scope/ring"));
        for invalid in [".foo", "_foo", "@scope/.foo", "@_scope/pkg", "../bad"] {
            assert!(!package_name(invalid));
        }
        assert!(!package_name(&"a".repeat(215)));
    }

    #[test]
    fn dev_optional_and_other_classification_flags_cannot_prove_production() {
        let manifest = parse_manifest(MANIFEST, RawLimits::default()).unwrap();
        for flag in ["dev", "optional", "devOptional", "peer", "link", "inBundle"] {
            let mut document: Value = serde_json::from_slice(LOCK).unwrap();
            document["packages"]["node_modules/@scope/ring"][flag] = Value::Bool(true);
            let encoded = serde_json::to_vec(&document).unwrap();
            assert_eq!(
                prove(&manifest, &encoded, RawLimits::default()),
                Err(NpmReconciliationError::UnsupportedProfile)
            );
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
