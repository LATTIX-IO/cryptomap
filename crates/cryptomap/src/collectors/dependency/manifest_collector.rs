//! Read-only Cargo.toml exact-pin declarations with independent provenance.
//!
//! Emits package-presence facts only for a bounded, strict manifest profile.
//! The manifest is never executed and does not establish runtime algorithm use.
use super::manifest::{CargoReconciliationError, parse_manifest};
use crate::{
    Confidence, CoverageState, EvidenceKind, InventoryError,
    collector::{
        COLLECTOR_CONTRACT_VERSION, CancellationToken, CollectionMode, CollectionRequest,
        CollectionSink, Collector, CollectorCapabilities, CollectorDescriptor, CollectorDiagnostic,
        CollectorDiagnosticCode,
    },
    raw::{RAW_CONTRACT_VERSION, RawFactKind, RawObservation, RawSourceKind, RawSourceLocator},
    scope::{CollectionScope, ScopeError},
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const ID: &str = "cryptomap:cargo-manifest";
const VERSION: &str = "0.1.0";

fn parse_code(error: CargoReconciliationError) -> CollectorDiagnosticCode {
    match error {
        CargoReconciliationError::ResourceLimit => CollectorDiagnosticCode::ResourceLimit,
        CargoReconciliationError::UnsupportedProfile => CollectorDiagnosticCode::UnsupportedSource,
        _ => CollectorDiagnosticCode::MalformedSource,
    }
}
fn io_code(error: &ScopeError) -> CollectorDiagnosticCode {
    match error {
        ScopeError::ResourceLimit => CollectorDiagnosticCode::ResourceLimit,
        ScopeError::OutOfScope | ScopeError::InvalidInput => {
            CollectorDiagnosticCode::PermissionDenied
        }
        ScopeError::Io | ScopeError::Collection(_) => CollectorDiagnosticCode::MalformedSource,
    }
}

/// Passive manifest collector; no authority is obtained by construction.
/// Caller must grant each exact Cargo.toml file and independently pin the run.
pub struct CargoManifestCollector<'a> {
    scope: &'a CollectionScope,
    observed_at: String,
}
impl<'a> CargoManifestCollector<'a> {
    /// Construct a collector without touching the filesystem.
    pub fn new(scope: &'a CollectionScope, observed_at: impl Into<String>) -> Self {
        Self {
            scope,
            observed_at: observed_at.into(),
        }
    }
}
impl Collector for CargoManifestCollector<'_> {
    fn descriptor(&self) -> CollectorDescriptor {
        CollectorDescriptor {
            contract_version: COLLECTOR_CONTRACT_VERSION,
            id: crate::CollectorId::new(ID)
                .unwrap_or_else(|_| unreachable!("constant manifest collector ID")),
            version: VERSION.into(),
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
            let (bytes, manifest) = match read {
                Err(error) => {
                    sink.diagnose(CollectorDiagnostic {
                        code: io_code(&error),
                        source_item: Some(source.item.clone()),
                    })?;
                    sink.cover(&source.item, CoverageState::Failed)?;
                    continue;
                }
                Ok(bytes) => match parse_manifest(&bytes, request.limits) {
                    Ok(manifest) => (bytes, manifest),
                    Err(error) => {
                        sink.diagnose(CollectorDiagnostic {
                            code: parse_code(error),
                            source_item: Some(source.item.clone()),
                        })?;
                        sink.cover(&source.item, CoverageState::Failed)?;
                        continue;
                    }
                },
            };
            // Root is a separately observed package declaration, so reserve
            // one additional record beyond each direct dependency.
            if manifest.direct.len() >= request.limits.observations {
                sink.diagnose(CollectorDiagnostic {
                    code: CollectorDiagnosticCode::ResourceLimit,
                    source_item: Some(source.item.clone()),
                })?;
                sink.cover(&source.item, CoverageState::Failed)?;
                continue;
            }
            let Some(root_name) = manifest.root_name else {
                return Err(InventoryError::InvalidMetadata);
            };
            let Some(root_version) = manifest.root_version else {
                return Err(InventoryError::InvalidMetadata);
            };
            let digest = format!("{:x}", Sha256::digest(&bytes));
            let entries = std::iter::once((root_name, root_version, "root")).chain(
                manifest
                    .direct
                    .into_iter()
                    .map(|(name, version)| (name, version, "direct")),
            );
            let mut cancelled = false;
            let mut emitted = 0;
            for (name, version, role) in entries {
                if cancel.is_cancelled() {
                    cancelled = true;
                    break;
                }
                let identity = serde_json::to_vec(&(
                    "cryptomap:cargo-manifest:v1",
                    &source.item,
                    &name,
                    &version,
                    role,
                ))
                .map_err(|_| InventoryError::InvalidMetadata)?;
                let event_id = format!("cargo-manifest:v1:{:x}", Sha256::digest(identity));
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
                        name,
                        version,
                    },
                    evidence_kind: EvidenceKind::Direct,
                    confidence: Confidence::Confirmed,
                    inference_rule: None,
                    source_sha256: Some(digest.clone()),
                    attributes: BTreeMap::from([("cargo:manifest-role".into(), role.into())]),
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
