//! Passive, exact-file, fail-closed JSON TLS configuration evidence.
//!
//! The explicit cryptomap:tls-config:v1 profile is not general application
//! configuration analysis. Declared TLS settings do not prove actual runtime
//! negotiation, algorithm use, policy compliance, or even process deployment.
//! Input values are never emitted unless matched to this module's whitelist.
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
use serde::{
    Deserialize, Deserializer,
    de::{SeqAccess, Visitor},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

/// Maximum bytes per authorized JSON configuration file (irrespective of host grant).
pub const MAX_JSON_TLS_BYTES: usize = 16 * 1024;
/// Exact discriminator required for supported JSON source inputs.
pub const PROFILE: &str = "cryptomap:tls-config:v1";
const ID: &str = "cryptomap:json-tls-config";
const VERSION: &str = "0.1.0";
const MAX_VERSIONS: usize = 2;
const MAX_CIPHER_SUITES: usize = 8;

/// Deserialize a small array without allocating a potentially huge Vec.
/// The separate overall file limit bounds even individual JSON string values.
fn bounded_strings<'de, D, const N: usize>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Strings<const N: usize>;
    impl<'de, const N: usize> Visitor<'de> for Strings<N> {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "array of at most {N} names")
        }
        fn visit_seq<A>(self, mut values: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut accepted = Vec::new();
            while let Some(value) = values.next_element::<String>()? {
                if accepted.len() == N {
                    return Err(serde::de::Error::custom("too many profile entries"));
                }
                accepted.push(value);
            }
            Ok(accepted)
        }
    }
    deserializer.deserialize_seq(Strings::<N>)
}

fn read_versions<'de, D: Deserializer<'de>>(input: D) -> Result<Vec<String>, D::Error> {
    bounded_strings::<D, MAX_VERSIONS>(input)
}

fn read_suites<'de, D: Deserializer<'de>>(input: D) -> Result<Vec<String>, D::Error> {
    bounded_strings::<D, MAX_CIPHER_SUITES>(input)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileDocument {
    profile: String,
    tls: TlsSettings,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsSettings {
    #[serde(default, deserialize_with = "read_versions")]
    versions: Vec<String>,
    #[serde(default, deserialize_with = "read_suites")]
    cipher_suites: Vec<String>,
}

fn reviewed_version(value: &str) -> Option<&'static str> {
    match value {
        "1.2" => Some("1.2"),
        "1.3" => Some("1.3"),
        _ => None,
    }
}

fn reviewed_suite(value: &str) -> Option<&'static str> {
    match value {
        "TLS_AES_128_GCM_SHA256" => Some("TLS_AES_128_GCM_SHA256"),
        "TLS_AES_256_GCM_SHA384" => Some("TLS_AES_256_GCM_SHA384"),
        "TLS_CHACHA20_POLY1305_SHA256" => Some("TLS_CHACHA20_POLY1305_SHA256"),
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => {
            Some("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
        }
        _ => None,
    }
}

/// Parse an exact profile into whitelisted nonsecret facts, without emitting
/// records until the complete input has been checked. Wrong profiles are
/// Unsupported; malformed content, duplicates and rejected keys are failures.
fn validated_facts(
    bytes: &[u8],
) -> Result<Vec<(&'static str, &'static str)>, CollectorDiagnosticCode> {
    let document: ProfileDocument =
        serde_json::from_slice(bytes).map_err(|_| CollectorDiagnosticCode::MalformedSource)?;
    if document.profile != PROFILE {
        return Err(CollectorDiagnosticCode::UnsupportedSource);
    }
    let mut facts = Vec::new();
    let mut unique = BTreeSet::new();
    for candidate in document.tls.versions {
        let approved =
            reviewed_version(&candidate).ok_or(CollectorDiagnosticCode::MalformedSource)?;
        if !unique.insert(("tls-version", approved)) {
            return Err(CollectorDiagnosticCode::MalformedSource);
        }
        facts.push(("tls-version", approved));
    }
    for candidate in document.tls.cipher_suites {
        let approved =
            reviewed_suite(&candidate).ok_or(CollectorDiagnosticCode::MalformedSource)?;
        if !unique.insert(("cipher-suite", approved)) {
            return Err(CollectorDiagnosticCode::MalformedSource);
        }
        facts.push(("cipher-suite", approved));
    }
    facts.sort_unstable();
    Ok(facts)
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

/// In-process, passive collector for an explicitly granted, exact JSON file.
///
/// Does not use ambient filesystem authority, discover files, parse secrets
/// into facts, resolve TLS interoperability, or initiate network connections.
pub struct JsonTlsConfigCollector<'a> {
    scope: &'a CollectionScope,
    observed_at: String,
}
impl<'a> JsonTlsConfigCollector<'a> {
    /// Bind only to the caller's explicit source grants; no I/O is performed.
    pub fn new(scope: &'a CollectionScope, observed_at: impl Into<String>) -> Self {
        Self {
            scope,
            observed_at: observed_at.into(),
        }
    }
}
impl Collector for JsonTlsConfigCollector<'_> {
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
            if file.relative().extension().and_then(|ext| ext.to_str()) != Some("json") {
                report(
                    sink,
                    &source.item,
                    CollectorDiagnosticCode::UnsupportedSource,
                    CoverageState::Unsupported,
                )?;
                continue;
            }
            let bytes = match file.read_limited(MAX_JSON_TLS_BYTES) {
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
                    "cryptomap:json-tls-fact:v1",
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
                    event_id: format!("json-tls:v1:{:x}", Sha256::digest(key)),
                    collector: descriptor.id.clone(),
                    collector_version: descriptor.version.clone(),
                    run: request.run.clone(),
                    // No fabricated token position: the evidence is
                    // document-level until a verified JSON span parser exists.
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
