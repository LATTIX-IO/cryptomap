//! Read-only Cargo.lock v3/v4 package discovery using exact file capabilities.
//!
//! This deliberately recognizes a bounded subset of Cargo's lockfile TOML
//! syntax. Unsupported constructs fail closed; they are not skipped as evidence
//! of an empty repository. No package build, resolution, or network access.
use crate::{
    Confidence, CoverageState, EvidenceKind, InventoryError,
    collector::{
        COLLECTOR_CONTRACT_VERSION, CancellationToken, CollectionMode, CollectionRequest,
        CollectionSink, Collector, CollectorCapabilities, CollectorDescriptor, CollectorDiagnostic,
        CollectorDiagnosticCode,
    },
    raw::{
        RAW_CONTRACT_VERSION, RawFactKind, RawLimits, RawObservation, RawSourceKind,
        RawSourceLocator,
    },
    scope::{CollectionScope, ScopeError},
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const COLLECTOR_ID: &str = "cryptomap:cargo-lockfile";
const COLLECTOR_VERSION: &str = "0.1.0";

#[derive(Debug, PartialEq, Eq)]
pub(super) struct LockedPackage {
    pub(super) name: String,
    pub(super) version: String,
    // A digest avoids leaking tokens from Git/registry source URLs.
    pub(super) source_digest: Option<String>,
    pub(super) dependencies: Vec<String>,
}

#[derive(Default)]
struct PendingPackage {
    name: Option<String>,
    version: Option<String>,
    source_digest: Option<String>,
    fields: BTreeSet<String>,
    dependencies: Vec<String>,
}

impl PendingPackage {
    fn finish(self) -> Result<LockedPackage, CollectorDiagnosticCode> {
        let name = self.name.ok_or(CollectorDiagnosticCode::MalformedSource)?;
        let version = self
            .version
            .ok_or(CollectorDiagnosticCode::MalformedSource)?;
        Ok(LockedPackage {
            name,
            version,
            source_digest: self.source_digest,
            dependencies: self.dependencies,
        })
    }
}

fn append_package(
    pending: PendingPackage,
    packages: &mut Vec<LockedPackage>,
    identities: &mut BTreeSet<(String, String, Option<String>)>,
) -> Result<(), CollectorDiagnosticCode> {
    let package = pending.finish()?;
    if !identities.insert((
        package.name.clone(),
        package.version.clone(),
        package.source_digest.clone(),
    )) {
        return Err(CollectorDiagnosticCode::MalformedSource);
    }
    packages.push(package);
    Ok(())
}

pub(super) fn quoted(input: &str, limit: usize) -> Result<&str, CollectorDiagnosticCode> {
    let inside = input
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(CollectorDiagnosticCode::MalformedSource)?;
    // Full TOML escape/Unicode handling belongs to a reviewed TOML parser.
    // Reject it rather than silently changing the value or accepting ambiguity.
    if inside.is_empty() || inside.contains(['"', '\\']) {
        return Err(CollectorDiagnosticCode::UnsupportedSource);
    }
    crate::validation::safe_text(inside, limit)
        .map_err(|_| CollectorDiagnosticCode::MalformedSource)?;
    Ok(inside)
}

pub(super) fn parse_lock(
    input: &[u8],
    limits: RawLimits,
) -> Result<Vec<LockedPackage>, CollectorDiagnosticCode> {
    use CollectorDiagnosticCode::{MalformedSource, ResourceLimit, UnsupportedSource};
    if input.len() > limits.total_bytes {
        return Err(ResourceLimit);
    }
    let input = std::str::from_utf8(input).map_err(|_| MalformedSource)?;
    let mut version = None;
    let mut current: Option<PendingPackage> = None;
    let mut packages = Vec::new();
    let mut identities = BTreeSet::new();
    let mut dependencies = false;
    let mut seen_package = false;
    for raw in input.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() > limits.record_bytes {
            return Err(ResourceLimit);
        }
        if dependencies {
            if line == "]" {
                dependencies = false;
                continue;
            }
            let entry = line.strip_suffix(',').unwrap_or(line);
            if current.as_ref().ok_or(MalformedSource)?.dependencies.len() >= limits.observations {
                return Err(ResourceLimit);
            }
            let dependency = quoted(entry.trim(), limits.field_bytes)?.to_owned();
            current
                .as_mut()
                .ok_or(MalformedSource)?
                .dependencies
                .push(dependency);
            continue;
        }
        if line == "[[package]]" {
            if version.is_none() {
                return Err(MalformedSource);
            }
            if let Some(previous) = current.take() {
                append_package(previous, &mut packages, &mut identities)?;
            }
            if packages.len() >= limits.observations {
                return Err(ResourceLimit);
            }
            current = Some(PendingPackage::default());
            seen_package = true;
            continue;
        }
        if line.starts_with('[') {
            // No unknown TOML sections may be treated as inspected.
            return Err(UnsupportedSource);
        }
        let (key, value) = line.split_once('=').ok_or(MalformedSource)?;
        let key = key.trim();
        let value = value.trim();
        if current.is_none() {
            if key != "version" || version.is_some() || seen_package {
                return Err(UnsupportedSource);
            }
            version = Some(match value {
                "3" => 3_u8,
                "4" => 4_u8,
                _ => return Err(UnsupportedSource),
            });
            continue;
        }
        let pending = current.as_mut().ok_or(MalformedSource)?;
        if !pending.fields.insert(key.to_owned()) {
            return Err(MalformedSource);
        }
        match key {
            "name" => pending.name = Some(quoted(value, limits.field_bytes)?.to_owned()),
            "version" => pending.version = Some(quoted(value, limits.field_bytes)?.to_owned()),
            "source" => {
                let source = quoted(value, limits.field_bytes)?;
                pending.source_digest = Some(format!("{:x}", Sha256::digest(source.as_bytes())));
            }
            "checksum" => {
                let checksum = quoted(value, limits.field_bytes)?;
                if checksum.len() != 64 || !checksum.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(MalformedSource);
                }
            }
            "dependencies" if value == "[" => dependencies = true,
            "dependencies" => return Err(UnsupportedSource),
            _ => return Err(UnsupportedSource),
        }
    }
    if dependencies || version.is_none() {
        return Err(MalformedSource);
    }
    if let Some(last) = current {
        append_package(last, &mut packages, &mut identities)?;
    }
    if !seen_package {
        return Err(MalformedSource);
    }
    Ok(packages)
}

fn code_for_io(error: &ScopeError) -> CollectorDiagnosticCode {
    match error {
        ScopeError::ResourceLimit => CollectorDiagnosticCode::ResourceLimit,
        ScopeError::OutOfScope | ScopeError::InvalidInput => {
            CollectorDiagnosticCode::PermissionDenied
        }
        ScopeError::Io | ScopeError::Collection(_) => CollectorDiagnosticCode::MalformedSource,
    }
}

/// Passive, capability-rooted collector of package-presence facts in Cargo.lock.
///
/// The caller authorizes each exact file in 'CollectionScope'. This adapter
/// never expands targets, opens arbitrary paths, or invokes Cargo. The observed
/// time must belong to the independent, host-pinned collection run interval.
pub struct CargoLockfileCollector<'a> {
    scope: &'a CollectionScope,
    observed_at: String,
}

impl<'a> CargoLockfileCollector<'a> {
    /// Construct without performing I/O or extending the authorization scope.
    pub fn new(scope: &'a CollectionScope, observed_at: impl Into<String>) -> Self {
        Self {
            scope,
            observed_at: observed_at.into(),
        }
    }
}

impl Collector for CargoLockfileCollector<'_> {
    fn matches_invocation_scope(&self, scope: &CollectionScope) -> bool {
        std::ptr::eq(self.scope, scope)
    }

    fn descriptor(&self) -> CollectorDescriptor {
        CollectorDescriptor {
            contract_version: COLLECTOR_CONTRACT_VERSION,
            id: crate::CollectorId::new(COLLECTOR_ID)
                .unwrap_or_else(|_| unreachable!("static collector identifier")),
            version: COLLECTOR_VERSION.into(),
            capabilities: CollectorCapabilities {
                sources: BTreeSet::from([RawSourceKind::Dependency]),
                mode: CollectionMode::Passive,
                required_permissions: BTreeSet::new(),
                checkpoint: false,
            },
        }
    }

    fn collect(
        &self,
        request: &CollectionRequest,
        sink: &mut CollectionSink,
        cancel: &CancellationToken,
    ) -> Result<(), InventoryError> {
        self.scope
            .validate_request(request)
            .map_err(|_| InventoryError::InvalidMetadata)?;
        let descriptor = self.descriptor();
        for source in &request.sources {
            if cancel.is_cancelled() {
                sink.diagnose(CollectorDiagnostic {
                    code: CollectorDiagnosticCode::Cancelled,
                    source_item: Some(source.item.clone()),
                })?;
                sink.cover(&source.item, CoverageState::NotInspected)?;
                continue;
            }
            let read = self
                .scope
                .open_file(RawSourceKind::Dependency, &source.item)
                .and_then(|file| file.read_bounded());
            let (bytes, packages) = match read {
                Err(error) => {
                    sink.diagnose(CollectorDiagnostic {
                        code: code_for_io(&error),
                        source_item: Some(source.item.clone()),
                    })?;
                    sink.cover(&source.item, CoverageState::Failed)?;
                    continue;
                }
                Ok(bytes) => match parse_lock(&bytes, request.limits) {
                    Ok(packages) => (bytes, packages),
                    Err(code) => {
                        sink.diagnose(CollectorDiagnostic {
                            code,
                            source_item: Some(source.item.clone()),
                        })?;
                        sink.cover(&source.item, CoverageState::Failed)?;
                        continue;
                    }
                },
            };
            let source_sha256 = format!("{:x}", Sha256::digest(&bytes));
            let mut seen = BTreeSet::new();
            let mut emitted = 0_usize;
            let mut cancelled = false;
            for package in packages {
                if cancel.is_cancelled() {
                    cancelled = true;
                    break;
                }
                let event_material = serde_json::to_vec(&(
                    "cryptomap:cargo-lock:v1",
                    &source.item,
                    &package.name,
                    &package.version,
                    &package.source_digest,
                ))
                .map_err(|_| InventoryError::InvalidMetadata)?;
                let event_id = format!("cargo:v1:{:x}", Sha256::digest(event_material));
                // Multiple indistinguishable source-package tuples cannot
                // reuse an event identity or silently discard evidence.
                if !seen.insert(event_id.clone()) {
                    return Err(InventoryError::InvalidMetadata);
                }
                let mut attributes = BTreeMap::new();
                if let Some(source_digest) = package.source_digest {
                    attributes.insert("cargo:source-sha256".into(), source_digest);
                }
                sink.emit(RawObservation {
                    contract_version: RAW_CONTRACT_VERSION,
                    event_id,
                    collector: descriptor.id.clone(),
                    collector_version: descriptor.version.clone(),
                    run: request.run.clone(),
                    source: RawSourceLocator {
                        kind: RawSourceKind::Dependency,
                        item: source.item.clone(),
                        offset: None,
                        line: None,
                        column: None,
                    },
                    observed_at: self.observed_at.clone(),
                    fact: RawFactKind::Dependency {
                        ecosystem: "cargo".into(),
                        name: package.name,
                        version: package.version,
                    },
                    evidence_kind: EvidenceKind::Direct,
                    confidence: Confidence::Confirmed,
                    inference_rule: None,
                    source_sha256: Some(source_sha256.clone()),
                    attributes,
                })?;
                emitted += 1;
            }
            if cancelled {
                sink.diagnose(CollectorDiagnostic {
                    code: CollectorDiagnosticCode::Cancelled,
                    source_item: Some(source.item.clone()),
                })?;
                sink.cover(&source.item, CoverageState::Partial)?;
            } else {
                sink.cover(
                    &source.item,
                    if emitted == 0 {
                        CoverageState::InspectedNoObservation
                    } else {
                        CoverageState::InspectedObserved
                    },
                )?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const VALID: &[u8] = b"# Cargo generated\nversion = 4\n\n[[package]]\nname = \"aes-gcm\"\nversion = \"0.10.3\"\nsource = \"registry+https://example.invalid/index\"\nchecksum = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\ndependencies = [\n \"aead\",\n]\n\n[[package]]\nname = \"local\"\nversion = \"0.1.0\"\n";

    #[test]
    fn parses_registry_and_workspace_package_with_dependency_list() {
        let records = parse_lock(VALID, RawLimits::default()).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].name, "aes-gcm");
        assert_eq!(records[0].version, "0.10.3");
        assert_eq!(records[0].source_digest.as_ref().map(String::len), Some(64));
        assert_eq!(records[1].name, "local");
        assert!(records[1].source_digest.is_none());
    }

    #[test]
    fn recognizes_v3_and_rejects_unknown_versions_or_sections() {
        let v3 = b"version = 3\n[[package]]\nname = \"x\"\nversion = \"1\"\n";
        assert_eq!(parse_lock(v3, RawLimits::default()).unwrap().len(), 1);
        for input in [
            b"version = 2\n[[package]]\nname = \"x\"\nversion = \"1\"\n".as_slice(),
            b"version = 4\n[[unknown]]\nname = \"x\"\n".as_slice(),
            b"version = 4\n".as_slice(),
        ] {
            assert!(parse_lock(input, RawLimits::default()).is_err());
        }
    }

    #[test]
    fn duplicate_fields_truncated_lists_and_secret_bearing_paths_fail_closed() {
        for input in [
            b"version = 4\n[[package]]\nname = \"one\"\nname = \"two\"\nversion = \"1\"\n".as_slice(),
            b"version = 4\n[[package]]\nname = \"one\"\nversion = \"1\"\ndependencies = [\n \"two\",\n".as_slice(),
            b"version = 4\n[[package]]\nname = \"one\"\nversion = \"1\"\nsource = \"git+https://name\\\\secret@host\"\n".as_slice(),
            b"version = 4\n[[package]]\nname = \"one\"\n".as_slice(),
        ] {
            assert!(parse_lock(input, RawLimits::default()).is_err());
        }
    }

    #[test]
    fn duplicate_package_identity_rejected_before_emission() {
        let duplicated = b"version = 4\n[[package]]\nname = \"ring\"\nversion = \"1\"\n[[package]]\nname = \"ring\"\nversion = \"1\"\n";
        assert_eq!(
            parse_lock(duplicated, RawLimits::default()),
            Err(CollectorDiagnosticCode::MalformedSource)
        );
        let distinct_sources = b"version = 4\n[[package]]\nname = \"ring\"\nversion = \"1\"\nsource = \"registry+https://a.invalid\"\n[[package]]\nname = \"ring\"\nversion = \"1\"\nsource = \"registry+https://b.invalid\"\n";
        assert_eq!(
            parse_lock(distinct_sources, RawLimits::default())
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn bounded_before_allocation_and_syntax_parse() {
        let limits = RawLimits {
            total_bytes: 32,
            ..RawLimits::default()
        };
        assert_eq!(
            parse_lock(VALID, limits),
            Err(CollectorDiagnosticCode::ResourceLimit)
        );
        let limits = RawLimits {
            observations: 1,
            ..RawLimits::default()
        };
        assert_eq!(
            parse_lock(VALID, limits),
            Err(CollectorDiagnosticCode::ResourceLimit)
        );
    }
}
