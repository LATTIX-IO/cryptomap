//! Strict, read-only direct Cargo manifest-to-lockfile reconciliation.
//!
//! Only exact version pins and an unambiguous root dependency edge are proven.
//! Unsupported TOML, optional/target/workspace/renamed dependencies and version
//! ranges return an explicit failure, not a fabricated dependency graph.
use crate::{
    raw::{RawLimits, RawSourceKind},
    scope::CollectionScope,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use super::cargo::{LockedPackage, parse_lock, quoted};

/// Sanitized parser or matching error without user-controlled manifest text,
/// registry URL, filesystem path, token or lockfile bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoReconciliationError {
    /// Exact manifest or lockfile grant is absent, or bounded file I/O failed.
    UnauthorizedSource,
    /// Resource budget was exceeded.
    ResourceLimit,
    /// A manifest or lockfile cannot be parsed under the documented profile.
    InvalidSource,
    /// Valid syntax uses an intentionally unsupported dependency feature.
    UnsupportedProfile,
    /// Candidate packages, root identity, pin or dependency reference disagree.
    UnresolvedDependency,
    /// Snapshot identity, source digest, collector, or run-level provenance was unbound.
    UnboundEvidence,
}

impl fmt::Display for CargoReconciliationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for CargoReconciliationError {}

/// One *declared* direct Cargo dependency, backed by a unique exact-pinned
/// manifest declaration AND an explicit Cargo.lock root dependency reference.
/// This does not prove execution or cryptographic algorithm usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoDirectDependency {
    /// Manifest and resolved lockfile package name.
    pub name: String,
    /// Exact resolved version, not an unconstrained semver match.
    pub version: String,
}

/// Immutable declaration-to-resolution evidence. This is not a canonical
/// inventory or a runtime dependency graph; FOSS-322's later edge increment
/// will project this evidence into existing inventory relationships.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoDirectReconciliation {
    /// Root package from the authorized manifest.
    pub root_name: String,
    /// Root package version.
    pub root_version: String,
    /// Hash of manifest bytes, without embedding source content.
    pub manifest_sha256: String,
    /// Hash of lockfile bytes, without embedding source content.
    pub lock_sha256: String,
    /// Lexically sorted, uniquely resolved direct dependencies.
    pub direct: Vec<CargoDirectDependency>,
}

#[derive(Default)]
pub(super) struct Manifest {
    pub(super) root_name: Option<String>,
    pub(super) root_version: Option<String>,
    pub(super) direct: BTreeMap<String, String>,
}

#[derive(Clone, Copy)]
enum Section {
    None,
    Package,
    Dependencies,
}

fn name_ok(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

// Deliberately narrow supported Cargo version profile: three nonnegative
// semver numeric components, without leading zeroes or u64 overflow.
// Valid prerelease/build metadata belongs to the future full-TOML increment.
fn exact_numeric_version(version: &str) -> bool {
    let mut components = version.split('.');
    (0..3).all(|_| {
        components.next().is_some_and(|component| {
            !component.is_empty()
                && (component.len() == 1 || !component.starts_with('0'))
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && component.parse::<u64>().is_ok()
        })
    }) && components.next().is_none()
}

// Supported optional rust-version profile: 1.MINOR or 1.MINOR.PATCH only.
// Reject pre-release, ranges, leading zeroes and integers outside u64.
fn supported_rust_version(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("1.") else {
        return false;
    };
    fn component(value: &str) -> bool {
        !value.is_empty()
            && (value.len() == 1 || !value.starts_with('0'))
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && value.parse::<u64>().is_ok()
    }
    let mut parts = rest.split('.');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(minor), None, None) => component(minor),
        (Some(minor), Some(patch), None) => component(minor) && component(patch),
        _ => false,
    }
}

// Support only the semantically equivalent, version-only Cargo inline table:
// dependency = { version = "=MAJOR.MINOR.PATCH" }.
// No features, alias, optional/dev, git/path, workspace or target semantics.
fn inline_exact_version(value: &str, max_bytes: usize) -> Result<&str, CargoReconciliationError> {
    use CargoReconciliationError::UnsupportedProfile;
    let inner = value
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .ok_or(UnsupportedProfile)?;
    let (name, declaration) = inner.trim().split_once('=').ok_or(UnsupportedProfile)?;
    if name.trim() != "version" {
        return Err(UnsupportedProfile);
    }
    quoted(declaration.trim(), max_bytes).map_err(|_| UnsupportedProfile)
}

/// Parse the conservative Cargo.toml profile with fail-closed extensions.
/// Optional package metadata never alters dependency identity or evidence.
pub(super) fn parse_manifest(
    input: &[u8],
    limits: RawLimits,
) -> Result<Manifest, CargoReconciliationError> {
    use CargoReconciliationError::{InvalidSource, ResourceLimit, UnsupportedProfile};
    if input.len() > limits.total_bytes {
        return Err(ResourceLimit);
    }
    let text = std::str::from_utf8(input).map_err(|_| InvalidSource)?;
    let mut manifest = Manifest::default();
    let mut section = Section::None;
    let mut seen_package = false;
    let mut seen_dependencies = false;
    let mut seen_metadata = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() > limits.record_bytes {
            return Err(ResourceLimit);
        }
        if line.starts_with('[') {
            section = match line {
                "[package]" if !seen_package => {
                    seen_package = true;
                    Section::Package
                }
                "[dependencies]" if !seen_dependencies => {
                    seen_dependencies = true;
                    Section::Dependencies
                }
                _ => return Err(UnsupportedProfile),
            };
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(InvalidSource)?;
        let key = key.trim();
        let value = value.trim();
        // Cargo's optional publish flag is a literal boolean; it is metadata,
        // not a dependency signal. Reject both duplicate and non-boolean forms.
        if matches!(section, Section::Package) && key == "publish" {
            if !seen_metadata.insert(key.to_owned()) || !matches!(value, "true" | "false") {
                return Err(UnsupportedProfile);
            }
            continue;
        }
        let decoded = if matches!(section, Section::Dependencies) && value.starts_with('{') {
            inline_exact_version(value, limits.field_bytes)?
        } else {
            quoted(value, limits.field_bytes).map_err(|_| UnsupportedProfile)?
        };
        match section {
            Section::None => return Err(UnsupportedProfile),
            Section::Package => match key {
                "name" if manifest.root_name.is_none() && name_ok(decoded) => {
                    manifest.root_name = Some(decoded.to_owned());
                }
                "version" if manifest.root_version.is_none() && exact_numeric_version(decoded) => {
                    manifest.root_version = Some(decoded.to_owned());
                }
                "edition"
                    if matches!(decoded, "2015" | "2018" | "2021" | "2024")
                        && seen_metadata.insert(key.to_owned()) => {}
                "rust-version"
                    if supported_rust_version(decoded) && seen_metadata.insert(key.to_owned()) => {}
                _ => return Err(UnsupportedProfile),
            },
            Section::Dependencies => {
                if !name_ok(key) {
                    return Err(InvalidSource);
                }
                let pinned = decoded.strip_prefix('=').ok_or(UnsupportedProfile)?;
                if !exact_numeric_version(pinned) || pinned.len() > limits.field_bytes {
                    return Err(UnsupportedProfile);
                }
                if manifest.direct.len() >= limits.observations {
                    return Err(ResourceLimit);
                }
                if manifest
                    .direct
                    .insert(key.to_owned(), pinned.to_owned())
                    .is_some()
                {
                    return Err(InvalidSource);
                }
            }
        }
    }
    if manifest.root_name.is_none() || manifest.root_version.is_none() || !seen_dependencies {
        return Err(UnsupportedProfile);
    }
    Ok(manifest)
}

fn prove_direct(
    manifest: Manifest,
    packages: &[LockedPackage],
    manifest_sha256: String,
    lock_sha256: String,
) -> Result<CargoDirectReconciliation, CargoReconciliationError> {
    use CargoReconciliationError::UnresolvedDependency;
    let root_name = manifest.root_name.ok_or(UnresolvedDependency)?;
    let root_version = manifest.root_version.ok_or(UnresolvedDependency)?;
    // Workspace/local root only: never infer a root from a registry package.
    let roots: Vec<_> = packages
        .iter()
        .filter(|p| p.name == root_name && p.version == root_version && p.source_digest.is_none())
        .collect();
    if roots.len() != 1 {
        return Err(UnresolvedDependency);
    }
    let root = roots[0];
    if root.dependencies.len() != manifest.direct.len() {
        // A lockfile may include target, build or optional declarations
        // absent from the supported manifest profile: fail closed.
        return Err(UnresolvedDependency);
    }
    let mut direct = Vec::with_capacity(manifest.direct.len());
    for (name, version) in manifest.direct {
        // Reject multiple locked candidate packages even when a source differs.
        // A name/version alone is not a unique package identity.
        let candidates: Vec<_> = packages
            .iter()
            .filter(|p| p.name == name && p.version == version)
            .collect();
        if candidates.len() != 1 {
            return Err(UnresolvedDependency);
        }
        let other_versions = packages
            .iter()
            .any(|p| p.name == name && p.version != version);
        let explicit = format!("{name} {version}");
        let matches = root
            .dependencies
            .iter()
            .filter(|entry| {
                entry.as_str() == explicit || (!other_versions && entry.as_str() == name)
            })
            .count();
        if matches != 1 || name == root_name {
            return Err(UnresolvedDependency);
        }
        direct.push(CargoDirectDependency { name, version });
    }
    Ok(CargoDirectReconciliation {
        root_name,
        root_version,
        manifest_sha256,
        lock_sha256,
        direct,
    })
}

/// Reconcile exactly two independently authorized dependency files.
///
/// Returns successful direct matches ONLY for single-scope, unambiguous, exact
/// version pins under the strict Cargo.toml profile. Grant both exact items
/// with CollectionScope::grant_file before invoking this API. A missing or
/// unsupported file never means a dependency is absent. No I/O outside those
/// grants, no package execution and no network use occurs.
pub fn reconcile_cargo_direct(
    scope: &CollectionScope,
    manifest_item: &str,
    lock_item: &str,
    limits: RawLimits,
) -> Result<CargoDirectReconciliation, CargoReconciliationError> {
    use CargoReconciliationError::{InvalidSource, ResourceLimit, UnauthorizedSource};
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
    let total = manifest_bytes
        .len()
        .checked_add(lock_bytes.len())
        .ok_or(ResourceLimit)?;
    if total > limits.total_bytes {
        return Err(ResourceLimit);
    }
    let manifest = parse_manifest(&manifest_bytes, limits)?;
    let lock = parse_lock(&lock_bytes, limits).map_err(|code| match code {
        crate::collector::CollectorDiagnosticCode::ResourceLimit => ResourceLimit,
        crate::collector::CollectorDiagnosticCode::UnsupportedSource => {
            CargoReconciliationError::UnsupportedProfile
        }
        _ => InvalidSource,
    })?;
    prove_direct(
        manifest,
        &lock,
        format!("{:x}", Sha256::digest(&manifest_bytes)),
        format!("{:x}", Sha256::digest(&lock_bytes)),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const MANIFEST: &[u8] =
        b"[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nring = \"=0.17.12\"\n";
    const LOCK: &[u8] = b"version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"ring\",\n]\n[[package]]\nname = \"ring\"\nversion = \"0.17.12\"\n";

    #[test]
    fn exact_pinned_direct_reference_has_a_unique_proof() {
        let manifest = parse_manifest(MANIFEST, RawLimits::default()).unwrap();
        let locked = parse_lock(LOCK, RawLimits::default()).unwrap();
        let result = prove_direct(manifest, &locked, "manifest".into(), "lock".into()).unwrap();
        assert_eq!(result.root_name, "app");
        assert_eq!(result.direct.len(), 1);
        assert_eq!(result.direct[0].name, "ring");
        assert_eq!(result.direct[0].version, "0.17.12");
    }

    #[test]
    fn optional_cargo_package_metadata_does_not_change_dependency_proof() {
        let base = parse_manifest(MANIFEST, RawLimits::default()).unwrap();
        let enriched = b"[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"1.85.0\"\npublish = false\n[dependencies]\nring = \"=0.17.12\"\n";
        let actual = parse_manifest(enriched, RawLimits::default()).unwrap();
        assert_eq!(actual.root_name, base.root_name);
        assert_eq!(actual.root_version, base.root_version);
        assert_eq!(actual.direct, base.direct);
        let locked = parse_lock(LOCK, RawLimits::default()).unwrap();
        let proof = prove_direct(actual, &locked, "manifest".into(), "lock".into()).unwrap();
        assert_eq!(proof.direct.len(), 1);
        assert_eq!(proof.direct[0].name, "ring");
        assert_eq!(proof.direct[0].version, "0.17.12");
        // Absent optional metadata, earlier source semantics remain unchanged.
        assert_eq!(
            prove_direct(base, &locked, "manifest".into(), "lock".into())
                .unwrap()
                .direct,
            proof.direct
        );
    }

    #[test]
    fn cargo_metadata_profile_rejects_duplicates_wrong_types_and_unsupported_extensions() {
        const PRE: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n";
        const POST: &str = "[dependencies]\nring = \"=0.17.12\"\n";
        for declaration in [
            "edition = \"1999\"\n",
            "edition = \"2027\"\n",
            "edition = 2024\n",
            "edition = \"2024\"\nedition = \"2021\"\n",
            "rust-version = \"1\"\n",
            "rust-version = \"2.85\"\n",
            "rust-version = \"1.085\"\n",
            "rust-version = \"1.85.00\"\n",
            "rust-version = \"1.85.0-preview\"\n",
            "rust-version = \"1.85.0.0\"\n",
            "rust-version = \"1.18446744073709551616\"\n",
            "rust-version = \"1.85\"\nrust-version = \"1.85.0\"\n",
            "publish = [\"private\"]\n",
            "publish = \"false\"\n",
            "publish = false\npublish = true\n",
            "edition = \"2024\" # ignored comment\n",
            "authors = [\"Example\"]\n",
        ] {
            let input = format!("{PRE}{declaration}{POST}");
            assert!(
                parse_manifest(input.as_bytes(), RawLimits::default()).is_err(),
                "unsupported metadata must not prove a dependency: {declaration:?}"
            );
        }
        for (edition, rust_version, publish) in [
            ("2015", "1.0", "true"),
            ("2018", "1.56", "false"),
            ("2021", "1.85.0", "false"),
            ("2024", "1.85", "true"),
        ] {
            let input = format!(
                "{PRE}edition = \"{edition}\"\nrust-version = \"{rust_version}\"\npublish = {publish}\n{POST}"
            );
            let parsed = parse_manifest(input.as_bytes(), RawLimits::default()).unwrap();
            assert_eq!(parsed.direct["ring"], "0.17.12");
        }
        // Cargo optional and target-specific dependency profiles still fail
        // instead of being silently projected as unconditional runtime use.
        let optional = format!(
            "{PRE}edition = \"2024\"\n{POST}[target.'cfg(unix)'.dependencies]\nother = \"=1.0.0\"\n"
        );
        assert!(parse_manifest(optional.as_bytes(), RawLimits::default()).is_err());
    }

    #[test]
    fn non_exact_and_extended_manifests_never_claim_direct_links() {
        for bytes in [
            b"[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nring = \"0.17\"\n".as_slice(),
            b"[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nring = { version = \"0.17\" }\n".as_slice(),
            b"[package]\nname = \"app\"\nversion = \"0.1.0\"\n[target.'cfg(unix)'.dependencies]\nring = \"=0.17.12\"\n".as_slice(),
            b"[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nring = \"=0.17.12\"\nring = \"=0.17.12\"\n".as_slice(),
            b"[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nring = \"=0.17.12\"\n[features]\ndefault = []\n".as_slice(),
        ] {
            assert!(parse_manifest(bytes, RawLimits::default()).is_err());
        }
    }

    #[test]
    fn strict_numeric_version_profile_rejects_nonsense_and_overflow() {
        for invalid in [
            "not-a-version",
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "-1.2.3",
            "1.2.3-alpha",
            "18446744073709551616.0.0",
        ] {
            assert!(!exact_numeric_version(invalid));
        }
        for version in ["0.0.0", "0.17.12", "1.2.3"] {
            assert!(exact_numeric_version(version));
        }
        let root =
            b"[package]\nname = \"app\"\nversion = \"bad\"\n[dependencies]\nring = \"=0.17.12\"\n";
        let pin = b"[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nring = \"=not-a-version\"\n";
        assert!(parse_manifest(root, RawLimits::default()).is_err());
        assert!(parse_manifest(pin, RawLimits::default()).is_err());
    }

    #[test]
    fn unresolved_or_ambiguous_lockfile_never_yields_an_edge() {
        for lock in [
            b"version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n[[package]]\nname = \"ring\"\nversion = \"0.17.12\"\n".as_slice(),
            b"version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"ring\",\n]\n[[package]]\nname = \"ring\"\nversion = \"0.17.11\"\n".as_slice(),
            b"version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"ring\",\n]\n[[package]]\nname = \"ring\"\nversion = \"0.17.12\"\n[[package]]\nname = \"ring\"\nversion = \"0.17.11\"\n".as_slice(),
        ] {
            let parsed = parse_lock(lock, RawLimits::default()).unwrap();
            let manifest = parse_manifest(MANIFEST, RawLimits::default()).unwrap();
            assert_eq!(
                prove_direct(manifest, &parsed, String::new(), String::new()),
                Err(CargoReconciliationError::UnresolvedDependency)
            );
        }
    }

    #[test]
    fn budgets_and_binary_inputs_fail_closed() {
        assert!(parse_manifest(&[0xff, 0x00], RawLimits::default()).is_err());
        let tiny = RawLimits {
            total_bytes: 4,
            ..RawLimits::default()
        };
        assert!(matches!(
            parse_manifest(MANIFEST, tiny),
            Err(CargoReconciliationError::ResourceLimit)
        ));
    }
}
