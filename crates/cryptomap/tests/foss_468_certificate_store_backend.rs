//! FOSS-468: deterministic portable certificate-store provider contract tests.
//! No real user/machine stores are read or modified by this suite.
#![cfg(feature = "certificate-store-grants")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    CollectionRunId, CollectionScopeId, CoverageState,
    certificate_store_scope::{CertificateStoreGrant, CertificateStoreLocation, CertificateStoreTarget},
    collector::{
        CancellationToken, CollectionRequest, Collector, CollectorDiagnosticCode, RequestedSource,
    },
    collectors::certificate_store::{
        CertificateStoreCollector, PublicCertificateStoreBackend, StoreProviderError,
    },
    raw::{RawFactKind, RawLimits, RawSourceKind},
    scope::{CollectionScope, ScopeError, collect_scoped},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
};

const ITEM: &str = "approved-store";
const TIME: &str = "2026-10-17T12:00:00Z";
fn der(pem: &[u8]) -> Vec<u8> {
    use x509_cert::{Certificate, der::{DecodePem, Encode}};
    Certificate::from_pem(pem).unwrap().to_der().unwrap()
}
fn rsa() -> Vec<u8> {
    der(include_bytes!("../examples/fixtures/certificate/rsa.pem"))
}
fn ec() -> Vec<u8> {
    der(include_bytes!("../examples/fixtures/certificate/ec.pem"))
}
fn target() -> CertificateStoreTarget {
    CertificateStoreTarget::new(CertificateStoreLocation::CurrentUser, "My").unwrap()
}
fn scope(max_entries: usize, max_bytes: usize) -> CollectionScope {
    let mut scope = CollectionScope::new(CollectionScopeId::new("store-tenant").unwrap());
    scope
        .grant_certificate_store(
            ITEM,
            CertificateStoreGrant::new(target(), max_entries, max_bytes).unwrap(),
        )
        .unwrap();
    scope
}
fn request(items: &[&str], observations: usize) -> CollectionRequest {
    CollectionRequest {
        run: CollectionRunId::new("store-run").unwrap(),
        sources: items.iter().map(|item| RequestedSource {
            kind: RawSourceKind::CertificateStore,
            item: (*item).into(),
        }).collect(),
        limits: RawLimits {
            sources: 8,
            observations,
            ..RawLimits::default()
        },
        options: BTreeMap::new(),
    }
}
struct FakeBackend {
    certs: Vec<Vec<u8>>,
    after: Result<(), StoreProviderError>,
    calls: AtomicUsize,
    observed: AtomicUsize,
}
impl FakeBackend {
    fn new(certs: Vec<Vec<u8>>) -> Self {
        Self {
            certs,
            after: Ok(()),
            calls: AtomicUsize::new(0),
            observed: AtomicUsize::new(0),
        }
    }
    fn failing(certs: Vec<Vec<u8>>, error: StoreProviderError) -> Self {
        Self { after: Err(error), ..Self::new(certs) }
    }
}
impl PublicCertificateStoreBackend for FakeBackend {
    fn visit(
        &self,
        target: CertificateStoreTarget,
        visitor: &mut dyn FnMut(&[u8]) -> Result<(), StoreProviderError>,
    ) -> Result<(), StoreProviderError> {
        assert_eq!(target, target());
        self.calls.fetch_add(1, Ordering::SeqCst);
        for cert in &self.certs {
            self.observed.fetch_add(1, Ordering::SeqCst);
            visitor(cert)?;
        }
        self.after
    }
}
#[test]
fn fully_inspected_public_der_has_canonical_identity_but_distinct_store_provenance() {
    let der = rsa();
    let expected = format!("{:x}", Sha256::digest(&der));
    let scope = scope(2, 128 * 1024);
    let provider = FakeBackend::new(vec![der]);
    let collector = CertificateStoreCollector::new(&scope, &provider, TIME);
    let out = collect_scoped(&scope, &collector, request(&[ITEM], 2), &CancellationToken::default()).unwrap();
    assert_eq!(out.coverage[ITEM], CoverageState::InspectedObserved);
    assert_eq!(out.observations.len(), 1);
    let fact = &out.observations[0];
    assert!(matches!(&fact.fact, RawFactKind::Certificate { fingerprint_sha256 } if fingerprint_sha256 == &expected));
    assert_eq!(fact.source.kind, RawSourceKind::CertificateStore);
    assert_eq!(fact.source_sha256.as_deref(), Some(expected.as_str()));
    assert!(fact.event_id.starts_with("x509-store:v1:"));
    assert_eq!(fact.attributes["x509:store-target"], target().id());
    assert_eq!(fact.attributes["x509:source-encoding"], "der");
    assert!(!format!("{:?}", out.diagnostics).contains("BEGIN CERTIFICATE"));
}
#[test]
fn empty_complete_store_is_no_observation_but_error_is_never_absence() {
    let scope = scope(2, 128 * 1024);
    let empty = FakeBackend::new(vec![]);
    let complete = collect_scoped(
        &scope, &CertificateStoreCollector::new(&scope, &empty, TIME),
        request(&[ITEM], 2), &CancellationToken::default()
    ).unwrap();
    assert_eq!(complete.coverage[ITEM], CoverageState::InspectedNoObservation);
    let denied = FakeBackend::failing(vec![], StoreProviderError::PermissionDenied);
    let failure = collect_scoped(
        &scope, &CertificateStoreCollector::new(&scope, &denied, TIME),
        request(&[ITEM], 2), &CancellationToken::default()
    ).unwrap();
    assert_eq!(failure.coverage[ITEM], CoverageState::Failed);
    assert_eq!(failure.diagnostics[0].code, CollectorDiagnosticCode::PermissionDenied);
    assert!(failure.observations.is_empty());
}
#[test]
fn partial_error_preserves_fingerprint_and_never_marks_complete() {
    let scope = scope(2, 128 * 1024);
    let provider = FakeBackend::failing(vec![rsa()], StoreProviderError::Io);
    let out = collect_scoped(
        &scope, &CertificateStoreCollector::new(&scope, &provider, TIME),
        request(&[ITEM], 2), &CancellationToken::default()
    ).unwrap();
    assert_eq!(out.coverage[ITEM], CoverageState::Partial);
    assert_eq!(out.observations.len(), 1);
    assert_eq!(out.diagnostics[0].code, CollectorDiagnosticCode::IncompleteScope);
}
#[test]
fn entry_and_global_record_budgets_limit_observation_and_report_partial() {
    let scope = scope(1, 128 * 1024);
    let provider = FakeBackend::new(vec![rsa(), ec()]);
    let out = collect_scoped(
        &scope, &CertificateStoreCollector::new(&scope, &provider, TIME),
        request(&[ITEM], 1), &CancellationToken::default()
    ).unwrap();
    assert_eq!(out.coverage[ITEM], CoverageState::Partial);
    assert_eq!(out.observations.len(), 1);
    assert_eq!(out.diagnostics[0].code, CollectorDiagnosticCode::ResourceLimit);
}
#[test]
fn cumulative_der_budget_rejects_additional_public_contexts() {
    let rsa = rsa();
    let ec = ec();
    let scope = scope(2, rsa.len() + ec.len() - 1);
    let provider = FakeBackend::new(vec![rsa, ec]);
    let out = collect_scoped(
        &scope, &CertificateStoreCollector::new(&scope, &provider, TIME),
        request(&[ITEM], 2), &CancellationToken::default()
    ).unwrap();
    assert_eq!(out.coverage[ITEM], CoverageState::Partial);
    assert_eq!(out.observations.len(), 1);
    assert_eq!(out.diagnostics[0].code, CollectorDiagnosticCode::ResourceLimit);
}
#[test]
fn malformed_and_trailing_der_fail_without_fabricating_evidence() {
    let mut bad = rsa();
    bad.extend_from_slice(&[0, 1, 2]);
    let scope = scope(2, 128 * 1024);
    let provider = FakeBackend::new(vec![bad]);
    let out = collect_scoped(
        &scope, &CertificateStoreCollector::new(&scope, &provider, TIME),
        request(&[ITEM], 2), &CancellationToken::default()
    ).unwrap();
    assert_eq!(out.coverage[ITEM], CoverageState::Failed);
    assert!(out.observations.is_empty());
    assert_eq!(out.diagnostics[0].code, CollectorDiagnosticCode::MalformedSource);
}
#[test]
fn repeated_contexts_emit_one_canonical_certificate_fact() {
    let rsa = rsa();
    let scope = scope(2, 128 * 1024);
    let provider = FakeBackend::new(vec![rsa.clone(), rsa]);
    let out = collect_scoped(
        &scope, &CertificateStoreCollector::new(&scope, &provider, TIME),
        request(&[ITEM], 2), &CancellationToken::default()
    ).unwrap();
    assert_eq!(out.coverage[ITEM], CoverageState::InspectedObserved);
    assert_eq!(out.observations.len(), 1);
}
#[test]
fn wrong_scope_or_extra_source_fails_before_backend_call() {
    let scope = scope(2, 128 * 1024);
    let other_scope = scope(2, 128 * 1024);
    let provider = FakeBackend::new(vec![rsa()]);
    let collector = CertificateStoreCollector::new(&scope, &provider, TIME);
    let cancel = CancellationToken::default();
    assert!(matches!(
        collect_scoped(&other_scope, &collector, request(&[ITEM], 2), &cancel),
        Err(ScopeError::OutOfScope)
    ));
    assert!(matches!(
        collect_scoped(&scope, &collector, request(&[ITEM, "unapproved"], 2), &cancel),
        Err(ScopeError::OutOfScope)
    ));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
}
#[test]
fn cancellation_and_deadline_do_not_read_store_or_claim_clean_absence() {
    let scope = scope(2, 128 * 1024);
    let provider = FakeBackend::new(vec![rsa()]);
    let cancel = CancellationToken::default();
    cancel.cancel();
    let out = collect_scoped(
        &scope, &CertificateStoreCollector::new(&scope, &provider, TIME),
        request(&[ITEM], 2), &cancel
    ).unwrap();
    assert_eq!(out.coverage[ITEM], CoverageState::NotInspected);
    assert_eq!(out.diagnostics[0].code, CollectorDiagnosticCode::Cancelled);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    let expired = CertificateStoreCollector::new(&scope, &provider, TIME)
        .with_deadline(std::time::Instant::now());
    let out = collect_scoped(&scope, &expired, request(&[ITEM], 2), &CancellationToken::default()).unwrap();
    assert_eq!(out.coverage[ITEM], CoverageState::NotInspected);
    assert_eq!(out.diagnostics[0].code, CollectorDiagnosticCode::Timeout);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
}
