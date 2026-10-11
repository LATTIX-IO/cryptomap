//! Read-only npm lockfile v2/v3 dependency discovery using explicit file grants.
//!
//! This collector does not run npm, resolve packages over the network, or infer
//! runtime algorithm use from dependency metadata. It emits only dependency facts.
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
    strict_json::StrictJson,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const COLLECTOR_ID: &str = "cryptomap:npm-lockfile";
const COLLECTOR_VERSION: &str = "0.1.0";

#[derive(Debug, PartialEq, Eq)]
pub(super) struct LockedPackage {
    pub(super) path: String,
    pub(super) name: String,
    pub(super) version: String,
}

fn package_name(path: &str) -> Option<&str> {
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
        || path.contains(['\\', '\0', '*', '?'])
    {
        return None;
    }
    let (_, name) = path.rsplit_once("node_modules/")?;
    if name.is_empty() {
        return None;
    }
    let parts: Vec<&str> = name.split('/').collect();
    match parts.as_slice() {
        [package] if !package.starts_with('@') => Some(name),
        [scope, package] if scope.starts_with('@') && scope.len() > 1 && !package.is_empty() => {
            Some(name)
        }
        _ => None,
    }
}

pub(super) fn parse_lock(
    bytes: &[u8],
    limits: RawLimits,
) -> Result<(Vec<LockedPackage>, bool), CollectorDiagnosticCode> {
    use CollectorDiagnosticCode::{MalformedSource, ResourceLimit, UnsupportedSource};
    // A strict parser rejects overwritten duplicate package keys at any depth.
    let json: StrictJson = serde_json::from_slice(bytes).map_err(|_| MalformedSource)?;
    let object = json.0.as_object().ok_or(MalformedSource)?;
    let version = object
        .get("lockfileVersion")
        .and_then(Value::as_u64)
        .ok_or(MalformedSource)?;
    if !matches!(version, 2 | 3) {
        return Err(UnsupportedSource);
    }
    let packages = object
        .get("packages")
        .and_then(Value::as_object)
        .ok_or(MalformedSource)?;
    if packages.len() > limits.observations.saturating_add(1) {
        return Err(ResourceLimit);
    }
    let mut found = Vec::new();
    let mut unsupported = false;
    for (path, detail) in packages {
        if path.is_empty() {
            continue;
        }
        // Workspace/local-link records need additional semantics and must
        // not be silently reported as complete dependency coverage.
        if !path.contains("node_modules/") {
            unsupported = true;
            continue;
        }
        if path.len() > limits.field_bytes {
            return Err(ResourceLimit);
        }
        let name = package_name(path).ok_or(MalformedSource)?;
        if name.len() > limits.field_bytes {
            return Err(ResourceLimit);
        }
        let entry = detail.as_object().ok_or(MalformedSource)?;
        if entry.get("link") == Some(&Value::Bool(true)) {
            unsupported = true;
            continue;
        }
        let resolved = entry
            .get("version")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.trim() == *value)
            .ok_or(MalformedSource)?;
        if resolved.len() > limits.field_bytes {
            return Err(ResourceLimit);
        }
        crate::validation::safe_text(name, limits.field_bytes).map_err(|_| MalformedSource)?;
        crate::validation::safe_text(resolved, limits.field_bytes).map_err(|_| MalformedSource)?;
        found.push(LockedPackage {
            path: path.clone(),
            name: name.to_owned(),
            version: resolved.to_owned(),
        });
    }
    Ok((found, unsupported))
}

fn diagnostic_for_scope_error(error: &ScopeError) -> CollectorDiagnosticCode {
    match error {
        ScopeError::ResourceLimit => CollectorDiagnosticCode::ResourceLimit,
        ScopeError::OutOfScope | ScopeError::InvalidInput => {
            CollectorDiagnosticCode::PermissionDenied
        }
        ScopeError::Io | ScopeError::Collection(_) => CollectorDiagnosticCode::MalformedSource,
    }
}

/// Explicit npm package-lock v2/v3 collector bound to a host-granted scope.
///
/// The caller must provide an observation time within the host-pinned run
/// interval. Use with 'scope::collect_scoped' or 'orchestration::collect_normalized';
/// a collector descriptor never grants file permissions by itself.
pub struct NpmLockfileCollector<'a> {
    scope: &'a CollectionScope,
    observed_at: String,
}

impl<'a> NpmLockfileCollector<'a> {
    /// Prepare a passive collector. Does not access any file or run a command.
    pub fn new(scope: &'a CollectionScope, observed_at: impl Into<String>) -> Self {
        Self {
            scope,
            observed_at: observed_at.into(),
        }
    }
}

impl Collector for NpmLockfileCollector<'_> {
    fn descriptor(&self) -> CollectorDescriptor {
        CollectorDescriptor {
            contract_version: COLLECTOR_CONTRACT_VERSION,
            id: crate::CollectorId::new(COLLECTOR_ID)
                .unwrap_or_else(|_| unreachable!("static collector ID is valid")),
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
        // Enforce the host's exact file grants even if called outside orchestration.
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
            let bytes = self
                .scope
                .open_file(RawSourceKind::Dependency, &source.item)
                .and_then(|file| file.read_bounded());
            let result = match bytes {
                Ok(bytes) => {
                    let parsed = parse_lock(&bytes, request.limits);
                    parsed.map(|(packages, partial)| (bytes, packages, partial))
                }
                Err(error) => Err(diagnostic_for_scope_error(&error)),
            };
            let (bytes, packages, incomplete) = match result {
                Ok(value) => value,
                Err(code) => {
                    sink.diagnose(CollectorDiagnostic {
                        code,
                        source_item: Some(source.item.clone()),
                    })?;
                    sink.cover(&source.item, CoverageState::Failed)?;
                    continue;
                }
            };
            let digest = format!("{:x}", Sha256::digest(&bytes));
            let mut emitted = 0_usize;
            let mut cancelled = false;
            for package in packages {
                if cancel.is_cancelled() {
                    cancelled = true;
                    break;
                }
                let event = serde_json::to_vec(&(
                    "cryptomap:npm-dependency:v1",
                    &source.item,
                    &package.path,
                    &package.version,
                ))
                .map_err(|_| InventoryError::InvalidMetadata)?;
                let event_id = format!("npm:v1:{:x}", Sha256::digest(event));
                let mut attributes = BTreeMap::new();
                attributes.insert("npm:lockfile-path".into(), package.path);
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
                        ecosystem: "npm".into(),
                        name: package.name,
                        version: package.version,
                    },
                    evidence_kind: EvidenceKind::Direct,
                    confidence: Confidence::Confirmed,
                    inference_rule: None,
                    source_sha256: Some(digest.clone()),
                    attributes,
                })?;
                emitted += 1;
            }
            if cancelled || incomplete {
                sink.diagnose(CollectorDiagnostic {
                    code: if cancelled {
                        CollectorDiagnosticCode::Cancelled
                    } else {
                        CollectorDiagnosticCode::UnsupportedSource
                    },
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
    fn limits() -> RawLimits {
        RawLimits::default()
    }

    #[test]
    fn extracts_flat_nested_and_scoped_packages() {
        let data = br#"{"lockfileVersion":3,"packages":{"":{},"node_modules/ring":{"version":"1.1"},"node_modules/a/node_modules/@scope/crypto":{"version":"2.0"}}}"#;
        let (packages, partial) = parse_lock(data, limits()).unwrap();
        assert!(!partial);
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "@scope/crypto");
        assert_eq!(packages[1].name, "ring");
    }

    #[test]
    fn rejects_duplicate_keys_and_unsupported_versions() {
        let duplicate = br#"{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1"},"node_modules/a":{"version":"2"}}}"#;
        assert_eq!(
            parse_lock(duplicate, limits()),
            Err(CollectorDiagnosticCode::MalformedSource)
        );
        let old = br#"{"lockfileVersion":1,"dependencies":{}}"#;
        assert_eq!(
            parse_lock(old, limits()),
            Err(CollectorDiagnosticCode::UnsupportedSource)
        );
    }

    #[test]
    fn rejects_traversal_and_missing_versions() {
        let traversal =
            br#"{"lockfileVersion":3,"packages":{"node_modules/../secret":{"version":"1"}}}"#;
        assert_eq!(
            parse_lock(traversal, limits()),
            Err(CollectorDiagnosticCode::MalformedSource)
        );
        let missing = br#"{"lockfileVersion":3,"packages":{"node_modules/a":{}}}"#;
        assert_eq!(
            parse_lock(missing, limits()),
            Err(CollectorDiagnosticCode::MalformedSource)
        );
    }

    #[test]
    fn unsupported_workspaces_cause_explicit_partial_coverage() {
        let data = br#"{"lockfileVersion":2,"packages":{"":{},"packages/app":{"version":"1"},"node_modules/ring":{"version":"1"}}}"#;
        let (packages, partial) = parse_lock(data, limits()).unwrap();
        assert_eq!(packages.len(), 1);
        assert!(partial);
    }

    #[test]
    fn bounds_package_count_before_emitting() {
        let data = br#"{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1"},"node_modules/b":{"version":"2"}}}"#;
        let caps = RawLimits {
            observations: 1,
            ..RawLimits::default()
        };
        assert_eq!(
            parse_lock(data, caps),
            Err(CollectorDiagnosticCode::ResourceLimit)
        );
    }
}
