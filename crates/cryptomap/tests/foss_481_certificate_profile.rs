//! FOSS-481 B5.4: bounded, public-only X.509 profile and UTC validity.
#![cfg(feature = "certificate-store-grants")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    AssetKind, CollectionRunId, CollectionScopeId, CoverageState, IdentityContext, InventoryLimits,
    Observed,
    certificate_store_scope::{
        CertificateStoreGrant, CertificateStoreLocation, CertificateStoreTarget,
    },
    collector::{
        CancellationToken, CollectionRequest, Collector, CollectorDiagnosticCode, RequestedSource,
    },
    collectors::{
        certificate::{
            CertificateFileCollector, MAX_CERT_DER_BYTES, MAX_CERT_FILE_BYTES, parse_der,
        },
        certificate_store::{
            CertificateStoreCollector, PublicCertificateStoreBackend, StoreProviderError,
        },
    },
    orchestration::{ScopedInvocation, collect_normalized},
    pipeline::PipelineInput,
    raw::{RawLimits, RawSourceKind},
    registry::Registry,
    scope::{CollectionScope, collect_scoped},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use x509_cert::{
    Certificate,
    der::{
        DateTime, DecodePem, Encode,
        asn1::{Any, GeneralizedTime, ObjectIdentifier, UtcTime},
    },
    time::Time,
};
const RSA_PEM: &[u8] = include_bytes!("../examples/fixtures/certificate/rsa.pem");
const EC_PEM: &[u8] = include_bytes!("../examples/fixtures/certificate/ec.pem");
const AT: &str = "2026-10-17T14:00:00Z";
static NEXT: AtomicUsize = AtomicUsize::new(0);

fn fixture(pem: &[u8]) -> Certificate {
    Certificate::from_pem(pem).unwrap()
}
fn der(cert: &Certificate) -> Vec<u8> {
    cert.to_der().unwrap()
}
fn set_validity(cert: &mut Certificate, start: Time, end: Time) {
    cert.tbs_certificate.validity.not_before = start;
    cert.tbs_certificate.validity.not_after = end;
}
fn date(y: u16, m: u8, d: u8, hh: u8, mm: u8, ss: u8) -> DateTime {
    DateTime::new(y, m, d, hh, mm, ss).unwrap()
}
fn utc(y: u16, m: u8, d: u8, hh: u8, mm: u8, ss: u8) -> Time {
    Time::UtcTime(UtcTime::from_date_time(date(y, m, d, hh, mm, ss)).unwrap())
}
fn general(y: u16, m: u8, d: u8, hh: u8, mm: u8, ss: u8) -> Time {
    Time::GeneralTime(GeneralizedTime::from_date_time(date(y, m, d, hh, mm, ss)))
}
#[test]
fn fixture_fingerprints_and_existing_algorithm_oid_keys_remain_frozen() {
    for (pem, identity, family) in [
        (
            RSA_PEM,
            "95975a1556fce045c69d7007c7c9926fc1087466046edefe38639929fa015f6e",
            "rsa",
        ),
        (
            EC_PEM,
            "8917ddbd31342a86dfbb705d0897af3b154d20dc3180c0f453bd6fccadcaefbc",
            "ec",
        ),
    ] {
        let cert = fixture(pem);
        let parsed = parse_der(&der(&cert)).unwrap();
        assert_eq!(parsed.fingerprint_sha256(), identity);
        let p = parsed.profile();
        let metadata = parsed.certificate_metadata();
        assert_eq!(metadata.fingerprint_sha256, identity);
        assert_eq!(metadata.serial, Observed::Unknown);
        assert_eq!(metadata.issuer, Observed::Unknown);
        assert_eq!(metadata.subject, Observed::Unknown);
        assert_eq!(
            metadata.not_before,
            Observed::Known(p.not_before_utc.clone())
        );
        assert_eq!(metadata.not_after, Observed::Known(p.not_after_utc.clone()));
        assert_eq!(p.version, 3);
        assert_eq!(p.signature_oid, parsed.signature_oid());
        assert_eq!(p.public_key_oid, parsed.public_key_oid());
        assert_eq!(p.public_key_family, Some(family));
        assert_eq!(p.not_before_utc.len(), 20);
        assert_eq!(p.not_after_utc.len(), 20);
        assert!(p.not_before_utc.ends_with('Z') && p.not_after_utc.ends_with('Z'));
        assert!(p.not_before_utc <= p.not_after_utc);
        let attributes = p.evidence_attributes();
        assert_eq!(attributes["x509:signature-algorithm-oid"], p.signature_oid);
        assert_eq!(
            attributes["x509:public-key-algorithm-oid"],
            p.public_key_oid
        );
        assert_eq!(attributes["x509:profile:v1:version"], "3");
        assert_eq!(attributes.len(), if family == "ec" { 8 } else { 6 });
        assert!(
            attributes
                .keys()
                .all(|k| !k.contains("subject") && !k.contains("issuer") && !k.contains("serial"))
        );
    }
    // RSA modulus bit length cannot be inferred from DER SPKI encoding length.
    assert_eq!(
        parse_der(&der(&fixture(RSA_PEM)))
            .unwrap()
            .profile()
            .public_key_bits,
        None
    );
    let ec = parse_der(&der(&fixture(EC_PEM))).unwrap();
    assert_eq!(
        ec.profile().named_curve_oid.as_deref(),
        Some("1.2.840.10045.3.1.7")
    );
    assert_eq!(ec.profile().public_key_bits, Some(256));
}
#[test]
fn utc_time_and_generalized_time_boundary_is_exact_and_clock_independent() {
    let mut cert = fixture(RSA_PEM);
    set_validity(
        &mut cert,
        utc(2049, 12, 31, 23, 59, 59),
        general(2050, 1, 1, 0, 0, 0),
    );
    let p = parse_der(&der(&cert)).unwrap();
    assert_eq!(p.profile().not_before_utc, "2049-12-31T23:59:59Z");
    assert_eq!(p.profile().not_after_utc, "2050-01-01T00:00:00Z");
    assert_eq!(
        p.fingerprint_sha256(),
        format!("{:x}", Sha256::digest(der(&cert)))
    );
    // Certificate validity may lie outside "now": collection is not a policy decision.
    set_validity(
        &mut cert,
        utc(2020, 1, 1, 0, 0, 0),
        utc(2021, 1, 1, 0, 0, 0),
    );
    assert_eq!(
        parse_der(&der(&cert)).unwrap().profile().not_after_utc,
        "2021-01-01T00:00:00Z"
    );
}
#[test]
fn contradictory_or_non_rfc5280_time_encodings_fail_closed() {
    let mut cert = fixture(RSA_PEM);
    set_validity(
        &mut cert,
        general(2052, 1, 1, 0, 0, 0),
        general(2051, 1, 1, 0, 0, 0),
    );
    assert_eq!(
        parse_der(&der(&cert)),
        Err(CollectorDiagnosticCode::MalformedSource)
    );
    // DER GeneralizedTime in 2049 is representable but not RFC 5280 compliant.
    set_validity(
        &mut cert,
        general(2049, 1, 1, 0, 0, 0),
        general(2050, 1, 1, 0, 0, 0),
    );
    assert_eq!(
        parse_der(&der(&cert)),
        Err(CollectorDiagnosticCode::MalformedSource)
    );
    assert!(DateTime::new(2050, 2, 30, 0, 0, 0).is_err());
    assert!(DateTime::new(2049, 13, 1, 0, 0, 0).is_err());
    set_validity(
        &mut cert,
        general(2050, 1, 1, 0, 0, 0),
        general(2051, 1, 1, 0, 0, 0),
    );
    let mut invalid = der(&cert);
    let time = b"20500101000000Z";
    let position = invalid.windows(time.len()).position(|w| w == time).unwrap();
    // Create the impossible calendar date 2050-02-30 in canonical-looking DER.
    invalid[position + 4] = b'0';
    invalid[position + 5] = b'2';
    invalid[position + 6] = b'3';
    invalid[position + 7] = b'0';
    assert_eq!(
        parse_der(&invalid),
        Err(CollectorDiagnosticCode::MalformedSource)
    );
    let mut extra = der(&cert);
    extra.push(0);
    assert_eq!(
        parse_der(&extra),
        Err(CollectorDiagnosticCode::MalformedSource)
    );
    assert_eq!(
        parse_der(&vec![0x55; MAX_CERT_DER_BYTES + 1]),
        Err(CollectorDiagnosticCode::ResourceLimit)
    );
}
#[test]
fn unfamiliar_spki_oid_or_curve_does_not_generate_fake_key_parameters() {
    let mut cert = fixture(EC_PEM);
    let unknown_curve: ObjectIdentifier = "1.3.6.1.4.1.55555.99".parse().unwrap();
    cert.tbs_certificate
        .subject_public_key_info
        .algorithm
        .parameters = Some(Any::from(unknown_curve));
    let parsed = parse_der(&der(&cert)).unwrap();
    assert_eq!(parsed.profile().public_key_family, Some("ec"));
    assert_eq!(
        parsed.profile().named_curve_oid.as_deref(),
        Some("1.3.6.1.4.1.55555.99")
    );
    assert_eq!(parsed.profile().public_key_bits, None);
    let unknown_algorithm: ObjectIdentifier = "1.3.6.1.4.1.55555.101".parse().unwrap();
    cert.tbs_certificate.subject_public_key_info.algorithm.oid = unknown_algorithm;
    let parsed = parse_der(&der(&cert)).unwrap();
    assert_eq!(parsed.profile().public_key_family, None);
    assert_eq!(parsed.profile().public_key_bits, None);
    assert_eq!(parsed.profile().named_curve_oid, None);
    assert!(
        !parsed
            .profile()
            .evidence_attributes()
            .contains_key("x509:profile:v1:public-key-family")
    );
}
struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let count = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("cryptomap-foss481-{}-{count}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct InMemoryStore(Vec<u8>);
impl PublicCertificateStoreBackend for InMemoryStore {
    fn visit(
        &self,
        _target: CertificateStoreTarget,
        visitor: &mut dyn FnMut(&[u8]) -> Result<(), StoreProviderError>,
    ) -> Result<(), StoreProviderError> {
        visitor(&self.0)
    }
}
fn scope_and_input(pem: &[u8]) -> (Sandbox, CollectionScope) {
    let sandbox = Sandbox::new();
    fs::write(sandbox.0.join("public.pem"), pem).unwrap();
    let mut scope = CollectionScope::new(CollectionScopeId::new("b54-tenant").unwrap());
    scope
        .grant_file(
            RawSourceKind::Certificate,
            "b54:file",
            &sandbox.0,
            "public.pem",
            MAX_CERT_FILE_BYTES,
        )
        .unwrap();
    let target = CertificateStoreTarget::new(CertificateStoreLocation::CurrentUser, "My").unwrap();
    scope
        .grant_certificate_store(
            "b54:store",
            CertificateStoreGrant::new(target, 4, 256 * 1024).unwrap(),
        )
        .unwrap();
    (sandbox, scope)
}
fn collection_request(item: &str, kind: RawSourceKind) -> CollectionRequest {
    CollectionRequest {
        run: CollectionRunId::new("b54-run").unwrap(),
        sources: vec![RequestedSource {
            kind,
            item: item.into(),
        }],
        // Store-only requests must fit the host grant's aggregate entry cap.
        limits: RawLimits {
            observations: 4,
            ..RawLimits::default()
        },
        options: BTreeMap::new(),
    }
}
#[test]
fn same_public_profile_file_and_store_keep_distinct_provenance_and_no_private_fields() {
    let (sandbox, scope) = scope_and_input(RSA_PEM);
    let cert = fixture(RSA_PEM);
    let backend = InMemoryStore(der(&cert));
    let file = collect_scoped(
        &scope,
        &CertificateFileCollector::new(&scope, AT),
        collection_request("b54:file", RawSourceKind::Certificate),
        &CancellationToken::default(),
    )
    .unwrap();
    let store = collect_scoped(
        &scope,
        &CertificateStoreCollector::new(&scope, &backend, AT),
        collection_request("b54:store", RawSourceKind::CertificateStore),
        &CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(file.coverage["b54:file"], CoverageState::InspectedObserved);
    assert_eq!(
        store.coverage["b54:store"],
        CoverageState::InspectedObserved
    );
    let from_file = &file.observations[0];
    let from_store = &store.observations[0];
    assert_eq!(from_file.fact, from_store.fact);
    assert_ne!(from_file.event_id, from_store.event_id);
    assert_ne!(from_file.source.kind, from_store.source.kind);
    for key in [
        "x509:profile:v1:version",
        "x509:profile:v1:not-before-utc",
        "x509:profile:v1:not-after-utc",
        "x509:profile:v1:public-key-family",
        "x509:signature-algorithm-oid",
        "x509:public-key-algorithm-oid",
    ] {
        assert_eq!(from_file.attributes[key], from_store.attributes[key]);
    }
    assert_eq!(from_file.attributes["x509:source-encoding"], "pem");
    assert_eq!(from_store.attributes["x509:source-encoding"], "der");
    let report = format!(
        "{}{}",
        serde_json::to_string(&file).unwrap(),
        serde_json::to_string(&store).unwrap()
    );
    for forbidden in [
        "-----BEGIN CERTIFICATE",
        "PRIVATE KEY",
        "\"issuer\"",
        "\"subject\"",
        "\"serial\"",
        "x509:SAN",
        "x509:SKI",
        "x509:AKI",
    ] {
        assert!(!report.contains(forbidden), "privacy leak: {forbidden}");
    }
    // Normalization retains the frozen canonical certificate identity.
    let collector = CertificateFileCollector::new(&scope, AT);
    let descriptor = collector.descriptor();
    let run = CollectionRunId::new("b54-run").unwrap();
    let registry = Registry::builtin();
    let identity = IdentityContext::new("b54-tenant").unwrap();
    let sources = [RequestedSource {
        kind: RawSourceKind::Certificate,
        item: "b54:file".into(),
    }];
    let snapshot = collect_normalized(
        ScopedInvocation {
            collector: &collector,
            input: PipelineInput {
                scope: &scope,
                identity: &identity,
                registry: &registry,
                expected_descriptor: &descriptor,
                expected_run: &run,
                sources: &sources,
                raw_limits: RawLimits::default(),
                inventory_limits: InventoryLimits::default(),
                started_at: AT,
                ended_at: AT,
            },
        },
        &CancellationToken::default(),
    )
    .unwrap();
    let assets: Vec<_> = snapshot
        .query_assets(|a| matches!(a.kind, AssetKind::Certificate { .. }))
        .collect();
    assert_eq!(assets.len(), 1);
    // New public observations enrich the frozen certificate asset without
    // switching AssetKind to DetailedCertificate or changing its identity.
    for (property, key) in [
        ("certificate:x509-version", "x509:profile:v1:version"),
        (
            "certificate:not-before-utc",
            "x509:profile:v1:not-before-utc",
        ),
        ("certificate:not-after-utc", "x509:profile:v1:not-after-utc"),
        (
            "certificate:public-key-family",
            "x509:profile:v1:public-key-family",
        ),
        (
            "certificate:signature-algorithm-oid",
            "x509:signature-algorithm-oid",
        ),
    ] {
        assert!(
            snapshot
                .observations
                .values()
                .any(|obs| { obs.property == property && obs.value == from_file.attributes[key] }),
            "missing normalized public field: {property}"
        );
    }
    let serialized = serde_json::to_string(&snapshot).unwrap();
    assert!(!serialized.contains("-----BEGIN CERTIFICATE"));
    assert!(!serialized.contains("\"issuer\""));
    assert!(!serialized.contains("\"subject\""));
    drop(sandbox);
}

#[test]
fn normalization_rejects_forged_inconsistent_public_profile_attributes() {
    let (_sandbox, scope) = scope_and_input(RSA_PEM);
    let collector = CertificateFileCollector::new(&scope, AT);
    let descriptor = collector.descriptor();
    let registry = Registry::builtin();
    let identity = IdentityContext::new("b54-tenant").unwrap();
    let run = CollectionRunId::new("b54-run").unwrap();
    let sources = [RequestedSource {
        kind: RawSourceKind::Certificate,
        item: "b54:file".into(),
    }];
    for (key, value) in [
        ("x509:profile:v1:version", "9"),
        ("x509:profile:v1:not-before-utc", "2026-02-30T00:00:00Z"),
        ("x509:profile:v1:public-key-family", "ed25519"),
        ("x509:profile:v1:public-key-bits", "4096"),
        (
            "x509:profile:v1:unexpected",
            "malicious-unreviewed-attribute",
        ),
        ("x509:signature-algorithm-oid", "1..2"),
        ("x509:signature-algorithm-oid", "1.02.3"),
        ("x509:signature-algorithm-oid", "."),
        ("x509:public-key-algorithm-oid", "3.1.2"),
        ("x509:profile:v1:named-curve-oid", "1..2"),
        ("x509:profile:v1:named-curve-oid", "1.02.3"),
    ] {
        let mut outcome = collect_scoped(
            &scope,
            &collector,
            collection_request("b54:file", RawSourceKind::Certificate),
            &CancellationToken::default(),
        )
        .unwrap();
        outcome.observations[0]
            .attributes
            .insert(key.into(), value.into());
        let result = cryptomap::pipeline::normalize(
            PipelineInput {
                scope: &scope,
                identity: &identity,
                registry: &registry,
                expected_descriptor: &descriptor,
                expected_run: &run,
                sources: &sources,
                raw_limits: RawLimits::default(),
                inventory_limits: InventoryLimits::default(),
                started_at: AT,
                ended_at: AT,
            },
            outcome,
        );
        assert!(
            matches!(
                result,
                Err(cryptomap::pipeline::PipelineError::InvalidOutcome)
            ),
            "forged profile field incorrectly trusted: {key}"
        );
    }
}
