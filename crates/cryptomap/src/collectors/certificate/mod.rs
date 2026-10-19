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
    certificate::Version,
    der::{Decode, Encode, asn1::ObjectIdentifier, pem},
    time::Time,
};

/// Maximum source bytes permitted in one explicitly granted certificate file.
pub const MAX_CERT_FILE_BYTES: usize = 256 * 1024;
/// Maximum decoded DER bytes per public certificate.
pub const MAX_CERT_DER_BYTES: usize = 64 * 1024;
/// Maximum number of certificates that one file can contribute.
pub const MAX_CERTS_PER_FILE: usize = 16;
const ID: &str = "cryptomap:x509-file";
const VERSION: &str = "0.1.0";

/// Public-only canonical X.509 identity, with no secret or identifying DN data.
///
/// Parsing does not establish validity, issuer trust, revocation or key possession.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicCertificate {
    fingerprint: String,
    signature_oid: String,
    public_key_oid: String,
    profile: PublicCertificateProfile,
    #[cfg(feature = "certificate-identity")]
    identity_hints: Option<crate::certificate_identity::CertificateIdentityHints>,
}

/// Strictly allowlisted, non-identifying X.509 v1 metadata projection.
///
/// A validity interval is *observed certificate content*, not a statement of
/// current validity, path building, signature verification, revocation or trust.
/// Fields are derived from one bounded canonical DER decode. Private keys,
/// distinguished names, SANs, SKI/AKI, serials and extensions are excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicCertificateProfile {
    /// ASN.1 certificate version as human-readable 1, 2 or 3.
    pub version: u8,
    /// Observed not-before value normalized to RFC 3339 UTC second precision.
    pub not_before_utc: String,
    /// Observed not-after value normalized to RFC 3339 UTC second precision.
    pub not_after_utc: String,
    /// Public signature algorithm OID.
    pub signature_oid: String,
    /// Public SubjectPublicKeyInfo algorithm OID.
    pub public_key_oid: String,
    /// Known algorithm family; None if this OID is not explicitly recognized.
    pub public_key_family: Option<&'static str>,
    /// Known named curve OID, not a key or identifying certificate extension.
    pub named_curve_oid: Option<String>,
    /// Public key field width ONLY for explicitly recognized fixed-width curves.
    ///
    /// RSA modulus bits are Unknown rather than guessed from the encoded SPKI
    /// BIT STRING length. No key material is exported to derive this value.
    pub public_key_bits: Option<u16>,
}

impl PublicCertificateProfile {
    /// Versioned, finite, privacy-allowlisted observation attributes.
    ///
    /// Retains the original v1 algorithm OID keys for existing consumers.
    pub fn evidence_attributes(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::from([
            (
                "x509:signature-algorithm-oid".into(),
                self.signature_oid.clone(),
            ),
            (
                "x509:public-key-algorithm-oid".into(),
                self.public_key_oid.clone(),
            ),
            ("x509:profile:v1:version".into(), self.version.to_string()),
            (
                "x509:profile:v1:not-before-utc".into(),
                self.not_before_utc.clone(),
            ),
            (
                "x509:profile:v1:not-after-utc".into(),
                self.not_after_utc.clone(),
            ),
        ]);
        if let Some(family) = self.public_key_family {
            out.insert("x509:profile:v1:public-key-family".into(), family.into());
        }
        if let Some(ref curve) = self.named_curve_oid {
            out.insert("x509:profile:v1:named-curve-oid".into(), curve.clone());
        }
        if let Some(bits) = self.public_key_bits {
            out.insert("x509:profile:v1:public-key-bits".into(), bits.to_string());
        }
        out
    }
}

/// Normalize a validated ASN.1 Time without wall-clock lookups.
///
/// RFC 5280 requires UTCTime for dates through 2049 and GeneralizedTime
/// starting with 2050; the chosen parser may reject older years itself.
fn normalized_utc(value: &Time) -> Result<String, CollectorDiagnosticCode> {
    let dt = value.to_date_time();
    match value {
        Time::UtcTime(_) if !(1950..=2049).contains(&dt.year()) => {
            return Err(CollectorDiagnosticCode::MalformedSource);
        }
        Time::GeneralTime(_) if dt.year() < 2050 => {
            return Err(CollectorDiagnosticCode::MalformedSource);
        }
        _ => {}
    }
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minutes(),
        dt.seconds()
    ))
}

/// Parse explicitly recognized, non-identifying SPKI algorithm parameters.
///
/// An unknown EC parameter OID remains Unknown rather than being interpreted
/// as a key length. It is not valid to use SPKI encoded size as key strength.
fn public_key_profile(
    oid: &str,
    params: Option<&x509_cert::der::asn1::Any>,
) -> (Option<&'static str>, Option<String>, Option<u16>) {
    match oid {
        "1.2.840.113549.1.1.1" => (Some("rsa"), None, None),
        "1.2.840.10045.2.1" => {
            // A valid ASN.1 OID can be longer than our public metadata
            // field ceiling once expanded into dotted-decimal text. Drop
            // that optional curve hint rather than poisoning normalization
            // and losing unrelated, already-authorized observations.
            let curve = params
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
                .map(|oid| oid.to_string())
                .filter(|text| text.len() <= 128);
            let bits = match curve.as_deref() {
                Some("1.2.840.10045.3.1.7") => Some(256), // secp256r1
                Some("1.3.132.0.34") => Some(384),        // secp384r1
                Some("1.3.132.0.35") => Some(521),        // secp521r1
                _ => None,
            };
            (Some("ec"), curve, bits)
        }
        "1.3.101.112" => (Some("ed25519"), None, None),
        "1.3.101.113" => (Some("ed448"), None, None),
        _ => (None, None, None),
    }
}

impl PublicCertificate {
    /// Lowercase SHA-256 of complete original canonical DER bytes.
    pub fn fingerprint_sha256(&self) -> &str {
        &self.fingerprint
    }

    /// Signed certificate's public signature algorithm OID.
    pub fn signature_oid(&self) -> &str {
        &self.signature_oid
    }

    /// Certificate's SubjectPublicKeyInfo algorithm OID, not a key export.
    pub fn public_key_oid(&self) -> &str {
        &self.public_key_oid
    }

    /// Observed public-only profile without subject, issuer or serial.
    pub fn profile(&self) -> &PublicCertificateProfile {
        &self.profile
    }

    /// Opaque opt-in identity hints, never a verified issuer/trust statement.
    #[cfg(feature = "certificate-identity")]
    pub fn identity_hints(&self) -> Option<&crate::certificate_identity::CertificateIdentityHints> {
        self.identity_hints.as_ref()
    }

    /// Return explicitly opted-in, opaque pseudonyms through the existing
    /// typed certificate metadata fields. A pseudonym is not a verified
    /// subject/issuer identity or a human-readable DN.
    #[cfg(feature = "certificate-identity")]
    pub fn certificate_metadata_with_identity(&self) -> crate::metadata::CertificateMetadata {
        use crate::metadata::Observed;
        let mut metadata = self.certificate_metadata();
        if let Some(hints) = &self.identity_hints {
            metadata.subject = hints
                .subject_dn
                .clone()
                .map_or(Observed::Unknown, Observed::Known);
            metadata.issuer = hints
                .issuer_dn
                .clone()
                .map_or(Observed::Unknown, Observed::Known);
            metadata.serial = hints
                .issuer_serial
                .clone()
                .map_or(Observed::Unknown, Observed::Known);
        }
        metadata
    }

    /// Project into the SDK's existing nonsecret typed certificate metadata.
    ///
    /// This does not change AssetKind, certificate identity or policy state.
    /// Privacy-sensitive identity fields remain explicitly Unknown until
    /// a distinct host-authorized B5.5 projection is implemented.
    pub fn certificate_metadata(&self) -> crate::metadata::CertificateMetadata {
        use crate::metadata::{CertificateMetadata, Observed};
        CertificateMetadata {
            fingerprint_sha256: self.fingerprint.clone(),
            serial: Observed::Unknown,
            issuer: Observed::Unknown,
            subject: Observed::Unknown,
            not_before: Observed::Known(self.profile.not_before_utc.clone()),
            not_after: Observed::Known(self.profile.not_after_utc.clone()),
            public_key_profile: Observed::Known(self.profile.public_key_oid.clone()),
            signature_profile: Observed::Known(self.profile.signature_oid.clone()),
        }
    }
}

fn public_oid(oid: String) -> Result<String, CollectorDiagnosticCode> {
    if oid.is_empty() || oid.len() > 128 || !oid.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return Err(CollectorDiagnosticCode::MalformedSource);
    }
    Ok(oid)
}

/// Inspect exactly one bounded canonical public DER certificate in memory.
/// Rejects trailing bytes and BER, and never exposes DN, subject or private keys.
pub fn parse_der(der: &[u8]) -> Result<PublicCertificate, CollectorDiagnosticCode> {
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
    let tbs = &certificate.tbs_certificate;
    let spki = &tbs.subject_public_key_info;
    let public_key_oid = public_oid(spki.algorithm.oid.to_string())?;
    let version = match tbs.version {
        Version::V1 => 1,
        Version::V2 => 2,
        Version::V3 => 3,
    };
    let not_before_utc = normalized_utc(&tbs.validity.not_before)?;
    let not_after_utc = normalized_utc(&tbs.validity.not_after)?;
    // Reject contradictory validity intervals; do not compare to current time.
    if tbs.validity.not_before.to_date_time() > tbs.validity.not_after.to_date_time() {
        return Err(CollectorDiagnosticCode::MalformedSource);
    }
    let (public_key_family, named_curve_oid, public_key_bits) =
        public_key_profile(&public_key_oid, spki.algorithm.parameters.as_ref());
    let profile = PublicCertificateProfile {
        version,
        not_before_utc,
        not_after_utc,
        signature_oid: signature_oid.clone(),
        public_key_oid: public_key_oid.clone(),
        public_key_family,
        named_curve_oid,
        public_key_bits,
    };
    Ok(PublicCertificate {
        fingerprint: format!("{:x}", Sha256::digest(der)),
        signature_oid,
        public_key_oid,
        profile,
        #[cfg(feature = "certificate-identity")]
        identity_hints: None,
    })
}

/// Parse the same canonical DER while deriving tenant-keyed identity hints.
#[cfg(feature = "certificate-identity")]
pub fn parse_der_with_identity(
    der: &[u8],
    authority: &crate::certificate_identity::CertificateIdentityAuthority,
) -> Result<PublicCertificate, CollectorDiagnosticCode> {
    let mut cert = parse_der(der)?;
    cert.identity_hints = Some(
        authority
            .project_der(der)
            .map_err(|_| CollectorDiagnosticCode::MalformedSource)?,
    );
    Ok(cert)
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
    #[cfg(feature = "certificate-identity")] authority: Option<
        &crate::certificate_identity::CertificateIdentityAuthority,
    >,
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
            // Decode the ORIGINAL PEM payload, not a certificate re-encoding.
            // A certificate decoder may consume one valid DER sequence while
            // silently ignoring extra decoded bytes. parse_der verifies the
            // complete original input with canonical DER round-trip checking.
            let (label, der) = pem::decode_vec(&rest[..block_end])
                .map_err(|_| CollectorDiagnosticCode::MalformedSource)?;
            if label != "CERTIFICATE" {
                return Err(CollectorDiagnosticCode::MalformedSource);
            }
            #[cfg(feature = "certificate-identity")]
            let certificate = match authority {
                Some(a) => parse_der_with_identity(&der, a)?,
                None => parse_der(&der)?,
            };
            #[cfg(not(feature = "certificate-identity"))]
            let certificate = parse_der(&der)?;
            if !seen.insert(certificate.fingerprint.clone()) {
                return Err(CollectorDiagnosticCode::MalformedSource);
            }
            certificates.push(certificate);
            rest = trim_ascii(&rest[block_end..]);
        }
        Ok((certificates, "pem"))
    } else {
        #[cfg(feature = "certificate-identity")]
        let certificate = match authority {
            Some(a) => parse_der_with_identity(source, a)?,
            None => parse_der(source)?,
        };
        #[cfg(not(feature = "certificate-identity"))]
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
    #[cfg(feature = "certificate-identity")]
    identity: Option<&'a crate::certificate_identity::CertificateIdentityAuthority>,
}
impl<'a> CertificateFileCollector<'a> {
    /// Bind to one exact previously authorized source scope, without I/O.
    pub fn new(scope: &'a CollectionScope, observed_at: impl Into<String>) -> Self {
        Self {
            scope,
            observed_at: observed_at.into(),
            #[cfg(feature = "certificate-identity")]
            identity: None,
        }
    }

    /// Explicitly opt into host-owned, exact-scope keyed identities.
    #[cfg(feature = "certificate-identity")]
    pub fn with_identity(
        mut self,
        authority: &'a crate::certificate_identity::CertificateIdentityAuthority,
    ) -> Result<Self, crate::certificate_identity::IdentityError> {
        authority.check_scope(self.scope.id())?;
        self.identity = Some(authority);
        Ok(self)
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
        #[cfg(feature = "certificate-identity")]
        if let Some(a) = self.identity {
            a.check_scope(self.scope.id())
                .map_err(|_| InventoryError::InvalidMetadata)?;
        }
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
            let (certificates, encoding) = match parse_public_certificates(
                &bytes,
                extension,
                #[cfg(feature = "certificate-identity")]
                self.identity,
            ) {
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
                let mut observation = RawObservation {
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
                        fingerprint_sha256: cert.fingerprint.clone(),
                    },
                    evidence_kind: EvidenceKind::Direct,
                    confidence: Confidence::High,
                    inference_rule: None,
                    source_sha256: Some(source_sha256.clone()),
                    attributes: {
                        let mut attributes = cert.profile.evidence_attributes();
                        #[cfg(feature = "certificate-identity")]
                        if let Some(hints) = cert.identity_hints() {
                            attributes.extend(hints.attributes());
                        }
                        attributes.insert("x509:source-encoding".into(), encoding.into());
                        attributes
                    },
                };
                #[cfg(feature = "certificate-identity")]
                if let Some(authority) = self.identity {
                    authority
                        .seal_record(&mut observation)
                        .map_err(|_| InventoryError::InvalidMetadata)?;
                }
                sink.emit(observation)?;
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
