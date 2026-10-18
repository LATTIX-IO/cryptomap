//! Portable, trust-separated read-only X.509 certificate-store evidence collector.
//!
//! A trusted host MUST bind this collector to an exact scope and provider. The
//! provider receives only a typed, approved store target; request options never
//! select hives, store names, file paths, or network destinations. No unsafe or
//! operating-system code exists here. A separate Windows adapter implements the
//! provider and owns its narrowly reviewed native FFI boundary.
use crate::{
    CollectorId, Confidence, CoverageState, EvidenceKind, InventoryError,
    certificate_store_scope::CertificateStoreTarget,
    collector::{
        COLLECTOR_CONTRACT_VERSION, CancellationToken, CollectionMode, CollectionRequest,
        CollectionSink, Collector, CollectorCapabilities, CollectorDescriptor, CollectorDiagnostic,
        CollectorDiagnosticCode,
    },
    collectors::certificate::{MAX_CERT_DER_BYTES, PublicCertificate, parse_der},
    raw::{RAW_CONTRACT_VERSION, RawFactKind, RawObservation, RawSourceKind, RawSourceLocator},
    scope::CollectionScope,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, time::Instant};

const ID: &str = "cryptomap:x509-store";
const VERSION: &str = "0.1.0";

/// Sanitized provider outcomes. Raw Windows error messages are never evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreProviderError {
    /// The OS denied access to an explicitly approved store.
    PermissionDenied,
    /// The source is not supported by this provider/operating system.
    Unsupported,
    /// A malformed public certificate was returned.
    Malformed,
    /// An entry/byte limit or arithmetic ceiling was reached.
    ResourceLimit,
    /// An OS enumeration or handle operation failed.
    Io,
    /// Inspection was interrupted by the caller.
    Cancelled,
    /// The caller's monotonic deadline elapsed.
    Timeout,
}
impl StoreProviderError {
    fn diagnostic(self) -> CollectorDiagnosticCode {
        match self {
            Self::PermissionDenied => CollectorDiagnosticCode::PermissionDenied,
            Self::Unsupported => CollectorDiagnosticCode::UnsupportedSource,
            Self::Malformed => CollectorDiagnosticCode::MalformedSource,
            Self::ResourceLimit => CollectorDiagnosticCode::ResourceLimit,
            Self::Io => CollectorDiagnosticCode::IncompleteScope,
            Self::Cancelled => CollectorDiagnosticCode::Cancelled,
            Self::Timeout => CollectorDiagnosticCode::Timeout,
        }
    }
}

/// Trusted platform adapter that streams *only public certificate DER*.
///
/// The callback MUST be invoked once per encountered context. The provider
/// must stop immediately on callback failure; callers independently enforce
/// per-grant entry/byte budgets before copying or parsing input. A provider
/// must return Ok only after exhaustive inspection of the exact store.
/// No private-key access, network validation, revocation or store mutation.
pub trait PublicCertificateStoreBackend: Send + Sync {
    /// Enumerate a host-selected, typed store and report explicit completion.
    fn visit(
        &self,
        target: CertificateStoreTarget,
        visitor: &mut dyn FnMut(&[u8]) -> Result<(), StoreProviderError>,
    ) -> Result<(), StoreProviderError>;
}

/// Secure certificate-store observation via a host-authorized backend.
///
/// Public evidence is held in bounded memory only until the provider returns;
/// incomplete enumeration yields Failed/Partial instead of a false absence.
/// Untrusted provider code still requires process isolation.
pub struct CertificateStoreCollector<'a, B: PublicCertificateStoreBackend + ?Sized> {
    scope: &'a CollectionScope,
    backend: &'a B,
    observed_at: String,
    deadline: Option<Instant>,
    #[cfg(feature = "certificate-identity")]
    identity: Option<&'a crate::certificate_identity::CertificateIdentityAuthority>,
}
impl<'a, B: PublicCertificateStoreBackend + ?Sized> CertificateStoreCollector<'a, B> {
    /// Pin the exact host authorization object and an independently chosen provider.
    pub fn new(scope: &'a CollectionScope, backend: &'a B, observed_at: impl Into<String>) -> Self {
        Self {
            scope,
            backend,
            observed_at: observed_at.into(),
            deadline: None,
            #[cfg(feature = "certificate-identity")]
            identity: None,
        }
    }

    /// Add a host-owned monotonic deadline; no request option can extend it.
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Host-authorized keyed candidate identities; never a trust verdict.
    #[cfg(feature = "certificate-identity")]
    pub fn with_identity(
        mut self,
        authority: &'a crate::certificate_identity::CertificateIdentityAuthority,
    ) -> Result<Self, crate::certificate_identity::IdentityError> {
        authority.check_scope(self.scope.id())?;
        self.identity = Some(authority);
        Ok(self)
    }

    fn interrupted(&self, cancel: &CancellationToken) -> Option<StoreProviderError> {
        if cancel.is_cancelled() {
            Some(StoreProviderError::Cancelled)
        } else if self.deadline.is_some_and(|end| Instant::now() >= end) {
            Some(StoreProviderError::Timeout)
        } else {
            None
        }
    }
}
fn cover_failure(
    sink: &mut CollectionSink,
    item: &str,
    error: StoreProviderError,
    emitted: usize,
) -> Result<(), InventoryError> {
    sink.diagnose(CollectorDiagnostic {
        code: error.diagnostic(),
        source_item: Some(item.to_owned()),
    })?;
    let state = if emitted > 0 {
        CoverageState::Partial
    } else {
        match error {
            StoreProviderError::Cancelled | StoreProviderError::Timeout => {
                CoverageState::NotInspected
            }
            StoreProviderError::Unsupported => CoverageState::Unsupported,
            _ => CoverageState::Failed,
        }
    };
    sink.cover(item, state)
}

impl<B: PublicCertificateStoreBackend + ?Sized> Collector for CertificateStoreCollector<'_, B> {
    fn matches_invocation_scope(&self, scope: &CollectionScope) -> bool {
        std::ptr::eq(self.scope, scope)
    }

    fn descriptor(&self) -> CollectorDescriptor {
        CollectorDescriptor {
            contract_version: COLLECTOR_CONTRACT_VERSION,
            id: CollectorId::new(ID).unwrap_or_else(|_| unreachable!("fixed collector id")),
            version: VERSION.to_owned(),
            capabilities: CollectorCapabilities {
                sources: BTreeSet::from([RawSourceKind::CertificateStore]),
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
        #[cfg(feature = "certificate-identity")]
        if let Some(a) = self.identity {
            a.check_scope(self.scope.id())
                .map_err(|_| InventoryError::InvalidMetadata)?;
        }
        let descriptor = self.descriptor();
        let mut total_emitted = 0_usize;
        for source in &request.sources {
            if let Some(error) = self.interrupted(cancel) {
                cover_failure(sink, &source.item, error, 0)?;
                continue;
            }
            let grant = self
                .scope
                .authorize_certificate_store(&source.item)
                .map_err(|_| InventoryError::InvalidMetadata)?;
            let max_entries = grant.max_entries();
            let max_bytes = grant.max_public_bytes();
            let target = grant.target();
            let mut visited = 0_usize;
            let mut copied_bytes = 0_usize;
            let mut collected: Vec<PublicCertificate> = Vec::new();
            let mut unique = BTreeSet::new();
            // Latch every callback refusal. An injected provider MUST not
            // be able to swallow a ResourceLimit, Cancelled or malformed
            // certificate error and then report exhaustive enumeration.
            let mut callback_failure: Option<StoreProviderError> = None;
            let provider_result = self.backend.visit(target, &mut |bytes| {
                if let Some(error) = callback_failure {
                    return Err(error);
                }
                let checked = (|| -> Result<(), StoreProviderError> {
                    if let Some(error) = self.interrupted(cancel) {
                        return Err(error);
                    }
                    visited = visited
                        .checked_add(1)
                        .ok_or(StoreProviderError::ResourceLimit)?;
                    if visited > max_entries || bytes.len() > MAX_CERT_DER_BYTES {
                        return Err(StoreProviderError::ResourceLimit);
                    }
                    copied_bytes = copied_bytes
                        .checked_add(bytes.len())
                        .ok_or(StoreProviderError::ResourceLimit)?;
                    if copied_bytes > max_bytes {
                        return Err(StoreProviderError::ResourceLimit);
                    }
                    #[cfg(feature = "certificate-identity")]
                    let parsed = match self.identity {
                        Some(a) => {
                            crate::collectors::certificate::parse_der_with_identity(bytes, a)
                        }
                        None => parse_der(bytes),
                    };
                    #[cfg(not(feature = "certificate-identity"))]
                    let parsed = parse_der(bytes);
                    let cert = parsed.map_err(|code| match code {
                        CollectorDiagnosticCode::ResourceLimit => StoreProviderError::ResourceLimit,
                        _ => StoreProviderError::Malformed,
                    })?;
                    if unique.insert(cert.fingerprint_sha256().to_owned()) {
                        if collected.len()
                            >= request.limits.observations.saturating_sub(total_emitted)
                        {
                            return Err(StoreProviderError::ResourceLimit);
                        }
                        collected.push(cert);
                    }
                    Ok(())
                })();
                if let Err(error) = checked {
                    callback_failure = Some(error);
                }
                checked
            });
            let result = match callback_failure {
                Some(error) => Err(error),
                None => provider_result,
            };
            let mut emitted = 0_usize;
            // Even after a provider error, retain previously verified public
            // evidence, but the source cannot be marked fully inspected.
            for cert in collected {
                if self.interrupted(cancel).is_some() {
                    break;
                }
                let key = serde_json::to_vec(&(
                    "cryptomap:x509-store-fact:v1",
                    &source.item,
                    target.id(),
                    cert.fingerprint_sha256(),
                ))
                .map_err(|_| InventoryError::InvalidMetadata)?;
                sink.emit(RawObservation {
                    contract_version: RAW_CONTRACT_VERSION,
                    event_id: format!("x509-store:v1:{:x}", Sha256::digest(key)),
                    collector: descriptor.id.clone(),
                    collector_version: descriptor.version.clone(),
                    run: request.run.clone(),
                    source: RawSourceLocator {
                        kind: RawSourceKind::CertificateStore,
                        item: source.item.clone(),
                        offset: None,
                        line: None,
                        column: None,
                    },
                    observed_at: self.observed_at.clone(),
                    fact: RawFactKind::Certificate {
                        fingerprint_sha256: cert.fingerprint_sha256().to_owned(),
                    },
                    evidence_kind: EvidenceKind::Direct,
                    confidence: Confidence::High,
                    inference_rule: None,
                    source_sha256: Some(cert.fingerprint_sha256().to_owned()),
                    attributes: {
                        let mut attributes = cert.profile().evidence_attributes();
                        #[cfg(feature = "certificate-identity")]
                        if let Some(hints) = cert.identity_hints() {
                            attributes.extend(hints.attributes());
                        }
                        attributes.insert("x509:source-encoding".into(), "der".into());
                        attributes.insert("x509:store-target".into(), target.id().into());
                        attributes
                    },
                })?;
                emitted += 1;
                total_emitted += 1;
            }
            if let Some(error) = self.interrupted(cancel) {
                cover_failure(sink, &source.item, error, emitted)?;
            } else if let Err(error) = result {
                cover_failure(sink, &source.item, error, emitted)?;
            } else if emitted == 0 {
                sink.cover(&source.item, CoverageState::InspectedNoObservation)?;
            } else {
                sink.cover(&source.item, CoverageState::InspectedObserved)?;
            }
        }
        Ok(())
    }
}
