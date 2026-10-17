//! FOSS-406: passive, bounded, public-only X.509 DER/PEM certificate evidence.
#![cfg(feature = "certificate-files")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    AssetKind, CollectionRunId, CoverageState, EvidenceKind, IdentityContext, InventoryLimits,
    InventorySnapshot,
    batch::BatchLimits,
    collector::{
        CancellationToken, CollectionRequest, CollectionSink, CollectionStatus, Collector,
        CollectorDiagnosticCode, RequestedSource,
    },
    collectors::certificate::{CertificateFileCollector, MAX_CERT_DER_BYTES, MAX_CERT_FILE_BYTES},
    coverage::CollectionScopeId,
    orchestration::{ScopedInvocation, collect_normalized, collect_normalized_batch},
    pipeline::{PipelineError, PipelineInput},
    raw::{RawFactKind, RawLimits, RawSourceKind},
    registry::Registry,
    scope::{CollectionScope, ScopeError, collect_scoped, collect_scoped_isolated},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};
use x509_cert::der::{DecodePem, Encode};
static NEXT: AtomicUsize = AtomicUsize::new(0);
const AT: &str = "2026-10-13T15:00:00Z";
const BASIC: &str = include_str!("../examples/fixtures/certificate/rsa.pem");
const EC: &str = include_str!("../examples/fixtures/certificate/ec.pem");
struct Sandbox {
    root: PathBuf,
}
impl Sandbox {
    fn new() -> Self {
        let root = (0..128)
            .find_map(|_| {
                let count = NEXT.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("cryptomap-foss406-{}-{count}", std::process::id()));
                match fs::create_dir(&path) {
                    Ok(()) => Some(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => panic!("cannot create isolated test directory: {error}"),
                }
            })
            .unwrap();
        Self { root }
    }
    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) {
        fs::write(self.root.join(name), bytes).unwrap();
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn scope_for(root: &Path, grants: &[(&str, &str)]) -> CollectionScope {
    let mut scope = CollectionScope::new(CollectionScopeId::new("cert-tenant").unwrap());
    for (item, relative) in grants {
        scope
            .grant_file(
                RawSourceKind::Certificate,
                *item,
                root,
                relative,
                MAX_CERT_FILE_BYTES + 4096,
            )
            .unwrap();
    }
    scope
}
fn sources(items: &[&str]) -> Vec<RequestedSource> {
    items
        .iter()
        .map(|item| RequestedSource {
            kind: RawSourceKind::Certificate,
            item: (*item).into(),
        })
        .collect()
}
fn request(items: &[&str], limits: RawLimits) -> CollectionRequest {
    CollectionRequest {
        run: CollectionRunId::new("cert-run").unwrap(),
        sources: sources(items),
        limits,
        options: Default::default(),
    }
}
fn raw(
    scope: &CollectionScope,
    items: &[&str],
    limits: RawLimits,
) -> cryptomap::collector::CollectionOutcome {
    collect_scoped(
        scope,
        &CertificateFileCollector::new(scope, AT),
        request(items, limits),
        &CancellationToken::default(),
    )
    .unwrap()
}
fn normalized(
    scope: &CollectionScope,
    items: &[&str],
    tenant: &str,
) -> Result<InventorySnapshot, PipelineError> {
    let collector = CertificateFileCollector::new(scope, AT);
    let descriptor = collector.descriptor();
    let run = CollectionRunId::new("cert-run").unwrap();
    let identity = IdentityContext::new(tenant).unwrap();
    let registry = Registry::builtin();
    let sources = sources(items);
    collect_normalized(
        ScopedInvocation {
            collector: &collector,
            input: PipelineInput {
                scope,
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
}
fn single_input(payload: impl AsRef<[u8]>) -> (Sandbox, CollectionScope) {
    let sandbox = Sandbox::new();
    sandbox.write("leaf.pem", payload);
    let scope = scope_for(&sandbox.root, &[("cert:one", "leaf.pem")]);
    (sandbox, scope)
}
fn assert_failed(bytes: impl AsRef<[u8]>, expected: CollectorDiagnosticCode) {
    let (_sandbox, scope) = single_input(bytes);
    let outcome = raw(&scope, &["cert:one"], RawLimits::default());
    assert_eq!(outcome.status, CollectionStatus::Failed);
    assert_eq!(outcome.coverage["cert:one"], CoverageState::Failed);
    assert!(outcome.observations.is_empty());
    assert_eq!(outcome.diagnostics.len(), 1);
    assert_eq!(outcome.diagnostics[0].code, expected);
}

#[test]
fn rsa_fingerprint_and_public_oid_metadata_are_source_backed() {
    let (_box, scope) = single_input(BASIC);
    let out = raw(&scope, &["cert:one"], RawLimits::default());
    assert_eq!(out.status, CollectionStatus::Complete);
    assert_eq!(out.coverage["cert:one"], CoverageState::InspectedObserved);
    assert_eq!(out.observations.len(), 1);
    let observation = &out.observations[0];
    assert_eq!(observation.source.item, "cert:one");
    assert_eq!(observation.source.kind, RawSourceKind::Certificate);
    assert_eq!(observation.source.line, None);
    assert_eq!(observation.source.offset, None);
    assert!(observation.event_id.starts_with("x509-file:v1:"));
    assert_eq!(observation.evidence_kind, EvidenceKind::Direct);
    assert_eq!(
        observation.source_sha256.as_deref(),
        Some(format!("{:x}", Sha256::digest(BASIC.as_bytes())).as_str())
    );
    assert_eq!(
        observation.attributes["x509:public-key-algorithm-oid"],
        "1.2.840.113549.1.1.1"
    );
    assert_eq!(
        observation.attributes["x509:signature-algorithm-oid"],
        "1.2.840.113549.1.1.11"
    );
    match &observation.fact {
        RawFactKind::Certificate { fingerprint_sha256 } => assert_eq!(
            fingerprint_sha256,
            "95975a1556fce045c69d7007c7c9926fc1087466046edefe38639929fa015f6e"
        ),
        other => panic!("unexpected fact: {other:?}"),
    }
    let snapshot = normalized(&scope, &["cert:one"], "cert-tenant").unwrap();
    snapshot
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    assert_eq!(snapshot.evidence.len(), 1);
    assert_eq!(
        snapshot
            .query_assets(|a| matches!(a.kind, AssetKind::Certificate { .. }))
            .count(),
        1
    );
    assert_eq!(
        snapshot
            .query_assets(|a| matches!(a.kind, AssetKind::AlgorithmUse { .. }))
            .count(),
        0
    );
}
#[test]
fn ec_der_matches_pem_fingerprint_and_has_distinct_provenance() {
    let der = x509_cert::Certificate::from_pem(EC.as_bytes())
        .unwrap()
        .to_der()
        .unwrap();
    let sandbox = Sandbox::new();
    sandbox.write("public.pem", EC);
    sandbox.write("public.der", &der);
    let scope = scope_for(
        &sandbox.root,
        &[("pem", "public.pem"), ("der", "public.der")],
    );
    let out = raw(&scope, &["der", "pem"], RawLimits::default());
    assert_eq!(out.status, CollectionStatus::Complete);
    assert_eq!(out.observations.len(), 2);
    for obs in &out.observations {
        let RawFactKind::Certificate { fingerprint_sha256 } = &obs.fact else {
            panic!("noncertificate fact")
        };
        assert_eq!(
            fingerprint_sha256,
            "8917ddbd31342a86dfbb705d0897af3b154d20dc3180c0f453bd6fccadcaefbc"
        );
        assert_eq!(
            obs.attributes["x509:public-key-algorithm-oid"],
            "1.2.840.10045.2.1"
        );
        assert_eq!(
            obs.attributes["x509:signature-algorithm-oid"],
            "1.2.840.10045.4.3.2"
        );
    }
    assert_ne!(out.observations[0].event_id, out.observations[1].event_id);
    let snapshot = normalized(&scope, &["pem", "der"], "cert-tenant").unwrap();
    snapshot
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    assert_eq!(
        snapshot
            .query_assets(|a| matches!(a.kind, AssetKind::Certificate { .. }))
            .count(),
        1
    );
    assert_eq!(snapshot.evidence.len(), 2);
}
#[test]
fn two_public_pem_certificates_in_one_file_are_bounded() {
    let (_dir, scope) = single_input(format!("{BASIC}{EC}"));
    let out = raw(&scope, &["cert:one"], RawLimits::default());
    assert_eq!(out.status, CollectionStatus::Complete);
    assert_eq!(out.observations.len(), 2);
    assert_ne!(out.observations[0].event_id, out.observations[1].event_id);
}
#[test]
fn duplicate_certificates_are_not_silent_replayed_duplicates() {
    assert_failed(
        format!("{BASIC}{BASIC}"),
        CollectorDiagnosticCode::MalformedSource,
    );
}
#[test]
fn reject_private_key_and_noncertificate_pem_headers_before_decoding() {
    for header in [
        "PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "RSA PRIVATE KEY",
        "PUBLIC KEY",
        "CERTIFICATE REQUEST",
    ] {
        let private = format!("-----BEGIN {header}-----\nZG9udC1sb2c=\n-----END {header}-----\n");
        let (_dir, scope) = single_input(private);
        let out = raw(&scope, &["cert:one"], RawLimits::default());
        assert_eq!(out.coverage["cert:one"], CoverageState::Failed);
        assert!(out.observations.is_empty());
        let report = serde_json::to_string(&out).unwrap();
        assert!(!report.contains("ZG9udC1sb2c="));
        assert!(!report.contains("PRIVATE KEY"));
    }
}
#[test]
fn reject_trailing_junk_mixed_private_or_truncated_pem() {
    for bad in [
        format!("garbage\n{BASIC}"),
        format!("{BASIC}garbage"),
        format!("{BASIC}-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n"),
        BASIC.replace("-----END CERTIFICATE-----", "-----END CERT"),
    ] {
        assert_failed(bad, CollectorDiagnosticCode::MalformedSource);
    }
}
#[test]
fn exact_pem_footer_and_public_only_armor_are_required() {
    for bad in [
        BASIC.replace("-----END CERTIFICATE-----", "-----END CERT"),
        BASIC.replace("-----END CERTIFICATE-----", "-----END PUBLIC KEY-----"),
        BASIC.replace("-----END CERTIFICATE-----", ""),
        BASIC.replace(
            "-----END CERTIFICATE-----",
            "-----END CERTIFICATE-----trailing content",
        ),
        BASIC.replace(
            "-----END CERTIFICATE-----",
            "-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----",
        ),
        BASIC.replace(
            "\n-----END CERTIFICATE-----",
            "\nnot-base64:secret\n-----END CERTIFICATE-----",
        ),
    ] {
        assert_failed(bad, CollectorDiagnosticCode::MalformedSource);
    }
}

#[test]
fn reject_extra_der_bytes_inside_otherwise_valid_pem_armor() {
    // PEM framing and base64 are valid, but the decoded payload has bytes
    // after the canonical X.509 certificate sequence. No evidence may emit.
    let mut der = x509_cert::Certificate::from_pem(BASIC.as_bytes())
        .unwrap()
        .to_der()
        .unwrap();
    der.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
    let pem = x509_cert::der::pem::encode_string(
        "CERTIFICATE",
        x509_cert::der::pem::LineEnding::LF,
        &der,
    )
    .unwrap();
    assert_failed(pem, CollectorDiagnosticCode::MalformedSource);
}

#[test]
fn crt_encoding_supports_public_pem_but_rejects_private_armor() {
    let sandbox = Sandbox::new();
    sandbox.write("public.crt", BASIC);
    sandbox.write(
        "not-public.cer",
        "-----BEGIN PRIVATE KEY-----\nZG9udC1sb2c=\n-----END PRIVATE KEY-----\n",
    );
    let scope = scope_for(
        &sandbox.root,
        &[("public", "public.crt"), ("private", "not-public.cer")],
    );
    let out = raw(&scope, &["private", "public"], RawLimits::default());
    assert_eq!(out.status, CollectionStatus::Partial);
    assert_eq!(out.coverage["public"], CoverageState::InspectedObserved);
    assert_eq!(out.coverage["private"], CoverageState::Failed);
    assert_eq!(out.observations.len(), 1);
}

#[test]
fn malformed_and_trailing_der_are_rejected_without_partial_false_facts() {
    let der = x509_cert::Certificate::from_pem(BASIC.as_bytes())
        .unwrap()
        .to_der()
        .unwrap();
    for der in [vec![0x30, 0x82, 0xff, 0xff], vec![0x00, 0x01]] {
        let sandbox = Sandbox::new();
        sandbox.write("bad.der", der);
        let scope = scope_for(&sandbox.root, &[("bad", "bad.der")]);
        let out = raw(&scope, &["bad"], RawLimits::default());
        assert_eq!(out.coverage["bad"], CoverageState::Failed);
        assert!(out.observations.is_empty());
    }
    let mut trailing = der;
    trailing.extend_from_slice(b"not part of certificate");
    let sandbox = Sandbox::new();
    sandbox.write("bad.der", trailing);
    let scope = scope_for(&sandbox.root, &[("bad", "bad.der")]);
    assert_eq!(
        raw(&scope, &["bad"], RawLimits::default()).coverage["bad"],
        CoverageState::Failed
    );
}
#[test]
fn oversized_pem_der_payload_is_bounded_before_certificate_decode() {
    // ASCII/base64 armor remains below the source-file byte ceiling, but
    // its decoded payload exceeds the per-certificate DER ceiling.
    let encoded = "A".repeat(MAX_CERT_DER_BYTES.div_ceil(3) * 4 + 4);
    let oversized = format!("-----BEGIN CERTIFICATE-----\n{encoded}\n-----END CERTIFICATE-----\n");
    assert!(oversized.len() < MAX_CERT_FILE_BYTES);
    assert_failed(oversized, CollectorDiagnosticCode::ResourceLimit);
}

#[test]
fn empty_source_and_overbudget_source_fail_explicitly() {
    assert_failed("", CollectorDiagnosticCode::MalformedSource);
    assert_failed(
        "x".repeat(MAX_CERT_FILE_BYTES + 1),
        CollectorDiagnosticCode::ResourceLimit,
    );
}
#[test]
fn unsupported_extension_uses_granted_real_file_not_item_label() {
    let sandbox = Sandbox::new();
    sandbox.write("not-a-cert.txt", BASIC);
    let scope = scope_for(&sandbox.root, &[("looks.pem", "not-a-cert.txt")]);
    let out = raw(&scope, &["looks.pem"], RawLimits::default());
    assert_eq!(out.coverage["looks.pem"], CoverageState::Unsupported);
    assert!(out.observations.is_empty());
}
#[test]
fn malformed_source_and_valid_source_keep_partial_coverage() {
    let sandbox = Sandbox::new();
    sandbox.write("good.pem", BASIC);
    sandbox.write(
        "bad.pem",
        "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n",
    );
    let scope = scope_for(&sandbox.root, &[("good", "good.pem"), ("bad", "bad.pem")]);
    let out = raw(&scope, &["bad", "good"], RawLimits::default());
    assert_eq!(out.status, CollectionStatus::Partial);
    assert_eq!(out.coverage["bad"], CoverageState::Failed);
    assert_eq!(out.coverage["good"], CoverageState::InspectedObserved);
    assert_eq!(out.observations.len(), 1);
    let snapshot = normalized(&scope, &["good", "bad"], "cert-tenant").unwrap();
    snapshot
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    assert_eq!(snapshot.evidence.len(), 1);
}
#[test]
fn deterministic_replay_and_changed_source_digest() {
    let (_dir, scope) = single_input(BASIC);
    assert_eq!(
        raw(&scope, &["cert:one"], RawLimits::default()),
        raw(&scope, &["cert:one"], RawLimits::default())
    );
    let first = normalized(&scope, &["cert:one"], "cert-tenant").unwrap();
    let second = normalized(&scope, &["cert:one"], "cert-tenant").unwrap();
    assert_eq!(first, second);
    assert!(normalized(&scope, &["cert:one"], "other-tenant").is_err());
}
#[test]
fn no_unauthorized_reads_even_when_other_granted_file_is_deleted() {
    let sandbox = Sandbox::new();
    sandbox.write("deleted.pem", BASIC);
    let scope = scope_for(&sandbox.root, &[("granted", "deleted.pem")]);
    fs::remove_file(sandbox.root.join("deleted.pem")).unwrap();
    let collector = CertificateFileCollector::new(&scope, AT);
    assert!(
        collect_scoped(
            &scope,
            &collector,
            request(&["granted", "ungranted"], RawLimits::default()),
            &CancellationToken::default()
        )
        .is_err()
    );
    assert_eq!(
        raw(&scope, &["granted"], RawLimits::default()).coverage["granted"],
        CoverageState::Failed
    );
}
#[test]
fn low_fact_budget_rejects_multicert_file_atomically() {
    let (_dir, scope) = single_input(format!("{BASIC}{EC}"));
    let out = raw(
        &scope,
        &["cert:one"],
        RawLimits {
            observations: 1,
            ..RawLimits::default()
        },
    );
    assert_eq!(out.coverage["cert:one"], CoverageState::Failed);
    assert_eq!(
        out.diagnostics[0].code,
        CollectorDiagnosticCode::ResourceLimit
    );
    assert!(out.observations.is_empty());
}
#[test]
fn observation_limit_is_global_across_authorized_certificate_files() {
    let sandbox = Sandbox::new();
    sandbox.write("first.pem", BASIC);
    sandbox.write("second.pem", EC);
    let scope = scope_for(
        &sandbox.root,
        &[("cert:first", "first.pem"), ("cert:second", "second.pem")],
    );
    let out = raw(
        &scope,
        &["cert:first", "cert:second"],
        RawLimits {
            observations: 1,
            ..RawLimits::default()
        },
    );
    assert_eq!(out.status, CollectionStatus::Partial);
    assert_eq!(out.coverage["cert:first"], CoverageState::InspectedObserved);
    assert_eq!(out.coverage["cert:second"], CoverageState::Failed);
    assert_eq!(out.observations.len(), 1);
    assert_eq!(out.diagnostics.len(), 1);
    assert_eq!(
        out.diagnostics[0].code,
        CollectorDiagnosticCode::ResourceLimit
    );
}

#[test]
fn cancellation_does_not_turn_certificate_into_absence() {
    let (_dir, scope) = single_input(BASIC);
    let collector = CertificateFileCollector::new(&scope, AT);
    let req = request(&["cert:one"], RawLimits::default());
    let mut sink = CollectionSink::new(collector.descriptor(), req.clone()).unwrap();
    let cancel = CancellationToken::default();
    cancel.cancel();
    collector.collect(&req, &mut sink, &cancel).unwrap();
    let out = sink.finish();
    assert_eq!(out.coverage["cert:one"], CoverageState::NotInspected);
    assert!(out.observations.is_empty());
    assert_eq!(out.diagnostics[0].code, CollectorDiagnosticCode::Cancelled);
}
#[cfg(unix)]
#[test]
fn symlink_escape_is_rejected_before_cert_contents_are_read() {
    use std::os::unix::fs::symlink;
    let sandbox = Sandbox::new();
    sandbox.write("real.pem", BASIC);
    symlink(sandbox.root.join("real.pem"), sandbox.root.join("link.pem")).unwrap();
    let mut scope = CollectionScope::new(CollectionScopeId::new("cert-tenant").unwrap());
    assert!(
        scope
            .grant_file(
                RawSourceKind::Certificate,
                "link",
                &sandbox.root,
                "link.pem",
                4096
            )
            .is_err()
    );
}
#[test]
fn wrong_scope_is_rejected_across_strict_isolated_normalized_and_batch_paths() {
    let a = Sandbox::new();
    let b = Sandbox::new();
    a.write("leaf.pem", BASIC);
    b.write("leaf.pem", EC);
    let scope_a = scope_for(&a.root, &[("same", "leaf.pem")]);
    let scope_b = scope_for(&b.root, &[("same", "leaf.pem")]);
    let collector = CertificateFileCollector::new(&scope_a, AT);
    assert!(collector.matches_invocation_scope(&scope_a));
    assert!(!collector.matches_invocation_scope(&scope_b));
    let req = request(&["same"], RawLimits::default());
    let cancel = CancellationToken::default();
    assert!(matches!(
        collect_scoped(&scope_b, &collector, req.clone(), &cancel),
        Err(ScopeError::OutOfScope)
    ));
    assert!(matches!(
        collect_scoped_isolated(&scope_b, &collector, req.clone(), &cancel),
        Err(ScopeError::OutOfScope)
    ));
    let descriptor = collector.descriptor();
    let run = req.run.clone();
    let identity = IdentityContext::new("cert-tenant").unwrap();
    let registry = Registry::builtin();
    let sources = sources(&["same"]);
    let inv = || ScopedInvocation {
        collector: &collector,
        input: PipelineInput {
            scope: &scope_b,
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
    };
    assert!(matches!(
        collect_normalized(inv(), &cancel),
        Err(PipelineError::Scope(ScopeError::OutOfScope))
    ));
    assert!(matches!(
        collect_normalized_batch(vec![inv()], BatchLimits::default(), &cancel),
        Err(PipelineError::Scope(ScopeError::OutOfScope))
    ));
    assert_eq!(
        collect_scoped(&scope_a, &collector, req, &cancel)
            .unwrap()
            .status,
        CollectionStatus::Complete
    );
}
