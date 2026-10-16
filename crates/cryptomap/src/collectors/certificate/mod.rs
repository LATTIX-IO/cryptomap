//! Passive exact-file X.509 public certificate observation, not PKI validation.
//!
//! Parses only caller-authorized certificate files, never private keys or stores.
use crate::{
    CollectorId, Confidence, CoverageState, EvidenceKind, InventoryError,
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
use x509_cert::{
    Certificate,
    der::{Decode, DecodePem, Encode},
};

/// Maximum source bytes permitted in one explicitly granted certificate file.
pub const MAX_CERT_FILE_BYTES: usize = 256 * 1024;
/// Maximum decoded DER bytes per public certificate.
pub const MAX_CERT_DER_BYTES: usize = 64 * 1024;
/// Maximum number of certificates that one file can contribute.
pub const MAX_CERTS_PER_FILE: usize = 16;
const ID: &str = "cryptomap:x509-file";
const VERSION: &str = "0.1.0";

#[derive(Debug)]
struct PublicCertificate {
    fingerprint: String,
    signature_oid: String,
    public_key_oid: String,
}

fn public_oid(oid: String) -> Result<String, CollectorDiagnosticCode> {
    if oid.is_empty() || oid.len() > 128 || !oid.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return Err(CollectorDiagnosticCode::MalformedSource);
    }
    Ok(oid)
}

fn parse_der(der: &[u8]) -> Result<PublicCertificate, CollectorDiagnosticCode> {
    if der.is_empty() {
        return Err(CollectorDiagnosticCode::MalformedSource);
    }
    if der.len() > MAX_CERT_DER_BYTES {
        return Err(CollectorDiagnosticCode::ResourceLimit);
    }
    // A complete, canonical DER certificate is required. Decoding into a
    // typed RustCrypto certificate and verifying canonical re-encoding
    // rejects trailing bytes, BER and ambiguous alternate encodings.
    let certificate =
        Certificate::from_der(der).map_err(|_| CollectorDiagnosticCode::MalformedSource)?;
    let canonical = certificate
        .to_der()
        .map_err(|_| CollectorDiagnosticCode::MalformedSource)?;
    if canonical.as_slice() != der {
        return Err(CollectorDiagnosticCode::MalformedSource);
    }
    let signature_oid = public_oid(certificate.signature_algorithm.oid.to_string())?;
    let public_key_oid = public_oid(
        certificate
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid
            .to_string(),
    )?;
    Ok(PublicCertificate {
        fingerprint: format!("{:x}", Sha256::digest(der)),
        signature_oid,
        public_key_oid,
    })
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    &bytes[start..end]
}

fn parse_public_certificates(
    source: &[u8],
    extension: &str,
) -> Result<(Vec<PublicCertificate>, &'static str), CollectorDiagnosticCode> {
    // PEM block headers are inspected BEFORE decoding any base64. A private
    // key, CSR, encrypted key or unknown PEM label is never parsed or emitted.
    let pem =
        extension == "pem" || (extension != "der" && trim_ascii(source).starts_with(b"-----BEGIN"));
    if pem {
        let mut rest = trim_ascii(source);
        if rest.is_empty() {
            return Err(CollectorDiagnosticCode::MalformedSource);
        }
        let mut certificates = Vec::new();
        let mut seen = BTreeSet::new();
        while !rest.is_empty() {
            if !rest.starts_with(b"-----BEGIN CERTIFICATE-----") {
                return Err(CollectorDiagnosticCode::MalformedSource);
            }
            if certificates.len() >= MAX_CERTS_PER_FILE {
                return Err(CollectorDiagnosticCode::ResourceLimit);
            }
            // Validate exact public-only PEM armor independently of the
            // decoder. Its label and framing may never substitute for the
            // host's explicit Certificate file grant.
            const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
            const END: &[u8] = b"-----END CERTIFICATE-----";
            let end_start = rest[BEGIN.len()..]
                .windows(END.len())
                .position(|window| window == END)
                .map(|position| position + BEGIN.len())
                .ok_or(CollectorDiagnosticCode::MalformedSource)?;
            let encoded = &rest[BEGIN.len()..end_start];
            if !(encoded.starts_with(b"\n") || encoded.starts_with(b"\r\n"))
                || !encoded.ends_with(b"\n")
                || !encoded.iter().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(*byte, b'+' | b'/' | b'=' | b'\n' | b'\r')
                })
            {
                return Err(CollectorDiagnosticCode::MalformedSource);
            }
            // Bound the decoded certificate BEFORE invoking the ASN.1/PEM
            // decoder. Base64 expands at most 3 bytes per four characters;
            // a file under the 256 KiB source cap may still contain a much
            // larger certificate than the permitted 64 KiB DER budget.
            let base64_bytes = encoded
                .iter()
                .filter(|&&byte| byte != b'\n' && byte != b'\r')
                .count();
            if base64_bytes > MAX_CERT_DER_BYTES.div_ceil(3) * 4 {
                return Err(CollectorDiagnosticCode::ResourceLimit);
            }
            let footer_end = end_start + END.len();
            let tail = &rest[footer_end..];
            let after_newline = if tail.starts_with(b"\r\n") {
                2
            } else if tail.starts_with(b"\n") {
                1
            } else {
                0
            };
            let block_end = footer_end + after_newline;
            let decoded = Certificate::from_pem(&rest[..block_end])
                .map_err(|_| CollectorDiagnosticCode::MalformedSource)?;
            let der = decoded
                .to_der()
                .map_err(|_| CollectorDiagnosticCode::MalformedSource)?;
            let certificate = parse_der(&der)?;
            if !seen.insert(certificate.fingerprint.clone()) {
                return Err(CollectorDiagnosticCode::MalformedSource);
            }
            certificates.push(certificate);
            rest = trim_ascii(&rest[block_end..]);
        }
        Ok((certificates, "pem"))
    } else {
        let certificate = parse_der(source)?;
        Ok((vec![certificate], "der"))
    }
}

fn diagnostic(err: &ScopeError) -> CollectorDiagnosticCode {
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

/// Passive collector that emits public X.509 certificate fingerprints only.
///
/// A certificate fingerprint identifies DER bytes, **not** trust, validity,
/// successful signature verification, private-key possession or live TLS use.
pub struct CertificateFileCollector<'a> {
    scope: &'a CollectionScope,
    observed_at: String,
}
impl<'a> CertificateFileCollector<'a> {
    /// Bind to one exact previously authorized source scope, without I/O.
    pub fn new(scope: &'a CollectionScope, observed_at: impl Into<String>) -> Self {
        Self {
            scope,
            observed_at: observed_at.into(),
        }
    }
}
impl Collector for CertificateFileCollector<'_> {
    fn matches_invocation_scope(&self, scope: &CollectionScope) -> bool {
        std::ptr::eq(self.scope, scope)
    }

    fn descriptor(&self) -> CollectorDescriptor {
        CollectorDescriptor {
            contract_version: COLLECTOR_CONTRACT_VERSION,
            id: CollectorId::new(ID).unwrap_or_else(|_| unreachable!("fixed descriptor")),
            version: VERSION.into(),
            capabilities: CollectorCapabilities {
                sources: BTreeSet::from([RawSourceKind::Certificate]),
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
        // RawLimits.observations applies to the entire requested collection,
        // not independently to each file. Preflight each file's observations
        // before emission to avoid partially emitting a source on exhaustion.
        let mut total_emitted = 0_usize;
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
            let file = match self
                .scope
                .open_file(RawSourceKind::Certificate, &source.item)
            {
                Ok(file) => file,
                Err(error) => {
                    report(
                        sink,
                        &source.item,
                        diagnostic(&error),
                        CoverageState::Failed,
                    )?;
                    continue;
                }
            };
            let extension = file
                .relative()
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            if !matches!(extension, "pem" | "crt" | "cer" | "der") {
                report(
                    sink,
                    &source.item,
                    CollectorDiagnosticCode::UnsupportedSource,
                    CoverageState::Unsupported,
                )?;
                continue;
            }
            let bytes = match file.read_limited(MAX_CERT_FILE_BYTES) {
                Ok(bytes) => bytes,
                Err(error) => {
                    report(
                        sink,
                        &source.item,
                        diagnostic(&error),
                        CoverageState::Failed,
                    )?;
                    continue;
                }
            };
            let (certificates, encoding) = match parse_public_certificates(&bytes, extension) {
                Ok(certificates) => certificates,
                Err(code) => {
                    report(sink, &source.item, code, CoverageState::Failed)?;
                    continue;
                }
            };
            if certificates.len() > request.limits.observations.saturating_sub(total_emitted) {
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
            let source_sha256 = format!("{:x}", Sha256::digest(&bytes));
            let mut emitted = 0_usize;
            for cert in certificates {
                if cancel.is_cancelled() {
                    break;
                }
                let key = serde_json::to_vec(&(
                    "cryptomap:x509-file-fact:v1",
                    &source.item,
                    &source_sha256,
                    &cert.fingerprint,
                ))
                .map_err(|_| InventoryError::InvalidMetadata)?;
                sink.emit(RawObservation {
                    contract_version: RAW_CONTRACT_VERSION,
                    event_id: format!("x509-file:v1:{:x}", Sha256::digest(key)),
                    collector: descriptor.id.clone(),
                    collector_version: descriptor.version.clone(),
                    run: request.run.clone(),
                    source: RawSourceLocator {
                        kind: RawSourceKind::Certificate,
                        item: source.item.clone(),
                        offset: None,
                        line: None,
                        column: None,
                    },
                    observed_at: self.observed_at.clone(),
                    fact: RawFactKind::Certificate {
                        fingerprint_sha256: cert.fingerprint,
                    },
                    evidence_kind: EvidenceKind::Direct,
                    confidence: Confidence::High,
                    inference_rule: None,
                    source_sha256: Some(source_sha256.clone()),
                    attributes: BTreeMap::from([
                        ("x509:source-encoding".into(), encoding.into()),
                        ("x509:public-key-algorithm-oid".into(), cert.public_key_oid),
                        ("x509:signature-algorithm-oid".into(), cert.signature_oid),
                    ]),
                })?;
                emitted += 1;
                total_emitted += 1;
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
                sink.cover(&source.item, CoverageState::InspectedObserved)?;
            }
        }
        Ok(())
    }
}
