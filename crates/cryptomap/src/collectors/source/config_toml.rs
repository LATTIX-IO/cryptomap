//! Passive, exact-file, fail-closed TOML TLS configuration evidence.
//!
//! Only the explicit versioned profile with a [tls] table is inspected.
//! Configured-only evidence is not live negotiation, execution or compliance.
use crate::{
    CollectorId, Confidence, CoverageState, EvidenceKind, InventoryError, ProtocolState,
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

/// Maximum bytes per exact TOML profile.
pub const MAX_TOML_TLS_BYTES: usize = 16 * 1024;
/// The approved schema discriminator, shared with JSON.
pub const PROFILE: &str = super::config_json::PROFILE;
const ID: &str = "cryptomap:toml-tls-config";
const VERSION: &str = "0.1.0";

fn validated_facts(
    bytes: &[u8],
) -> Result<Vec<(&'static str, &'static str)>, CollectorDiagnosticCode> {
    let text = std::str::from_utf8(bytes).map_err(|_| CollectorDiagnosticCode::MalformedSource)?;
    // Require the table *syntax*, not merely a root inline-table value.
    // The profile and whitelist reject attempted multiline-value ambiguity.
    if !text.lines().any(|line| line.trim() == "[tls]") {
        return Err(CollectorDiagnosticCode::MalformedSource);
    }
    let document: super::config_json::ProfileDocument =
        toml::from_str(text).map_err(|_| CollectorDiagnosticCode::MalformedSource)?;
    super::config_json::validated_document(document)
}

fn io_diagnostic(err: &ScopeError) -> CollectorDiagnosticCode {
    match err {
        ScopeError::ResourceLimit => CollectorDiagnosticCode::ResourceLimit,
        ScopeError::InvalidInput | ScopeError::OutOfScope => {
            CollectorDiagnosticCode::PermissionDenied
        }
        ScopeError::Io | ScopeError::Collection(_) => CollectorDiagnosticCode::MalformedSource,
    }
}

fn report(
    sink: &mut CollectionSink,
    item: &str,
    code: CollectorDiagnosticCode,
    state: CoverageState,
) -> Result<(), InventoryError> {
    sink.diagnose(CollectorDiagnostic {
        code,
        source_item: Some(item.to_owned()),
    })?;
    sink.cover(item, state)
}

/// In-process, passive collector for an explicitly granted, exact TOML file.
///
/// Does not use ambient filesystem authority, discover files, parse secrets
/// into facts, resolve TLS interoperability, or initiate network connections.
pub struct TomlTlsConfigCollector<'a> {
    scope: &'a CollectionScope,
    observed_at: String,
}
impl<'a> TomlTlsConfigCollector<'a> {
    /// Bind only to the caller's explicit source grants; no I/O is performed.
    pub fn new(scope: &'a CollectionScope, observed_at: impl Into<String>) -> Self {
        Self {
            scope,
            observed_at: observed_at.into(),
        }
    }
}
impl Collector for TomlTlsConfigCollector<'_> {
    fn matches_invocation_scope(&self, scope: &CollectionScope) -> bool {
        std::ptr::eq(self.scope, scope)
    }

    fn descriptor(&self) -> CollectorDescriptor {
        CollectorDescriptor {
            contract_version: COLLECTOR_CONTRACT_VERSION,
            id: CollectorId::new(ID).unwrap_or_else(|_| unreachable!("fixed descriptor")),
            version: VERSION.to_owned(),
            capabilities: CollectorCapabilities {
                sources: BTreeSet::from([RawSourceKind::Source]),
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
        // All requested files must be granted BEFORE opening even the first.
        self.scope
            .validate_request(request)
            .map_err(|_| InventoryError::InvalidMetadata)?;
        let descriptor = self.descriptor();
        for source in &request.sources {
            if cancel.is_cancelled() {
                report(
                    sink,
                    &source.item,
                    CollectorDiagnosticCode::Cancelled,
                    CoverageState::NotInspected,
                )?;
                continue;
            }
            let file = match self.scope.open_file(RawSourceKind::Source, &source.item) {
                Ok(file) => file,
                Err(error) => {
                    report(
                        sink,
                        &source.item,
                        io_diagnostic(&error),
                        CoverageState::Failed,
                    )?;
                    continue;
                }
            };
            if file.relative().extension().and_then(|ext| ext.to_str()) != Some("toml") {
                report(
                    sink,
                    &source.item,
                    CollectorDiagnosticCode::UnsupportedSource,
                    CoverageState::Unsupported,
                )?;
                continue;
            }
            let bytes = match file.read_limited(MAX_TOML_TLS_BYTES) {
                Ok(bytes) => bytes,
                Err(error) => {
                    report(
                        sink,
                        &source.item,
                        io_diagnostic(&error),
                        CoverageState::Failed,
                    )?;
                    continue;
                }
            };
            let facts = match validated_facts(&bytes) {
                Ok(facts) => facts,
                Err(code) => {
                    let state = if code == CollectorDiagnosticCode::UnsupportedSource {
                        CoverageState::Unsupported
                    } else {
                        CoverageState::Failed
                    };
                    report(sink, &source.item, code, state)?;
                    continue;
                }
            };
            // All-or-nothing per file on malformed profiles or source budget.
            if facts.len() > request.limits.observations {
                report(
                    sink,
                    &source.item,
                    CollectorDiagnosticCode::ResourceLimit,
                    CoverageState::Failed,
                )?;
                continue;
            }
            if cancel.is_cancelled() {
                report(
                    sink,
                    &source.item,
                    CollectorDiagnosticCode::Cancelled,
                    CoverageState::NotInspected,
                )?;
                continue;
            }
            let digest = format!("{:x}", Sha256::digest(&bytes));
            let mut emitted = 0_usize;
            for (kind, value) in &facts {
                if cancel.is_cancelled() {
                    break;
                }
                // Canonical facts and digest are fixed/whitelisted. Do not
                // interpolate user-provided source content into metadata.
                let key = serde_json::to_vec(&(
                    "cryptomap:toml-tls-fact:v1",
                    &source.item,
                    &digest,
                    kind,
                    value,
                ))
                .map_err(|_| InventoryError::InvalidMetadata)?;
                let fact = if *kind == "tls-version" {
                    RawFactKind::Protocol {
                        family: "TLS".into(),
                        version: Some((*value).into()),
                        state: ProtocolState::Configured,
                    }
                } else {
                    RawFactKind::Configuration {
                        property: "tls:configured-cipher-suite".into(),
                        value: (*value).into(),
                    }
                };
                sink.emit(RawObservation {
                    contract_version: RAW_CONTRACT_VERSION,
                    event_id: format!("toml-tls:v1:{:x}", Sha256::digest(key)),
                    collector: descriptor.id.clone(),
                    collector_version: descriptor.version.clone(),
                    run: request.run.clone(),
                    // No fabricated token position: the evidence is
                    // document-level until a verified TOML span parser exists.
                    source: RawSourceLocator {
                        kind: RawSourceKind::Source,
                        item: source.item.clone(),
                        offset: None,
                        line: None,
                        column: None,
                    },
                    observed_at: self.observed_at.clone(),
                    fact,
                    evidence_kind: EvidenceKind::Direct,
                    confidence: Confidence::High,
                    inference_rule: None,
                    source_sha256: Some(digest.clone()),
                    attributes: BTreeMap::from([
                        ("source:parser-profile".into(), PROFILE.into()),
                        ("source:evidence-semantics".into(), "configured-only".into()),
                    ]),
                })?;
                emitted += 1;
            }
            if cancel.is_cancelled() {
                report(
                    sink,
                    &source.item,
                    CollectorDiagnosticCode::Cancelled,
                    if emitted == 0 {
                        CoverageState::NotInspected
                    } else {
                        CoverageState::Partial
                    },
                )?;
            } else {
                sink.cover(
                    &source.item,
                    if facts.is_empty() {
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
