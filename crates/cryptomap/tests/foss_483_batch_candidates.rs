//! B5.6 cross-run issuer-candidate federation from independently authorized
//! PEM, DER and in-memory Windows certificate-store collectors.
#![cfg(all(feature = "certificate-identity", feature = "certificate-store-grants"))]
#![allow(clippy::unwrap_used)]

use cryptomap::{
    CollectionRunId, CollectionScopeId, CoverageState, EvidenceKind, IdentityContext,
    InventoryLimits, RelationshipKind,
    batch::{BatchLimits, BatchRun, normalize_batch_with_identity},
    certificate_identity::CertificateIdentityAuthority,
    certificate_store_scope::{
        CertificateStoreGrant, CertificateStoreLocation, CertificateStoreTarget,
    },
    collector::{
        CancellationToken, CollectionRequest, CollectionStatus, Collector, CollectorDescriptor,
        RequestedSource,
    },
    collectors::{
        certificate::{CertificateFileCollector, MAX_CERT_FILE_BYTES},
        certificate_store::{
            CertificateStoreCollector, PublicCertificateStoreBackend, StoreProviderError,
        },
    },
    pipeline::{PipelineError, PipelineInput},
    raw::{RawLimits, RawSourceKind},
    registry::Registry,
    scope::{CollectionScope, collect_scoped},
};
use std::{collections::BTreeMap, fs, path::PathBuf};
use x509_cert::{
    Certificate,
    der::{DecodePem, Encode},
};

const RSA: &[u8] = include_bytes!("../examples/fixtures/certificate/rsa.pem");
const EC: &[u8] = include_bytes!("../examples/fixtures/certificate/ec.pem");
const AT: &str = "2026-10-18T12:00:00Z";
const LEAF: &str = "b56:file:leaf";
const ROOT: &str = "b56:file:root";
const STORE: &str = "b56:store:root";

struct Memory(Vec<u8>);
impl PublicCertificateStoreBackend for Memory {
    fn visit(
        &self,
        _target: CertificateStoreTarget,
        visitor: &mut dyn FnMut(&[u8]) -> Result<(), StoreProviderError>,
    ) -> Result<(), StoreProviderError> {
        visitor(&self.0)
    }
}
fn pinned_input<'a>(
    scope: &'a CollectionScope,
    identity: &'a IdentityContext,
    registry: &'a Registry,
    descriptor: &'a CollectorDescriptor,
    run: &'a CollectionRunId,
    sources: &'a [RequestedSource],
    raw_limits: RawLimits,
) -> PipelineInput<'a> {
    PipelineInput {
        scope,
        identity,
        registry,
        expected_descriptor: descriptor,
        expected_run: run,
        sources,
        raw_limits,
        inventory_limits: InventoryLimits::default(),
        started_at: AT,
        ended_at: AT,
    }
}

struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn authorized_three_run_pem_der_store_federation_is_candidate_only() {
    let root = Certificate::from_pem(RSA).unwrap();
    let mut leaf = Certificate::from_pem(EC).unwrap();
    // Intentionally NOT re-signed: an issuer-name candidate is not issuance.
    leaf.tbs_certificate.issuer = root.tbs_certificate.subject.clone();

    let directory =
        std::env::temp_dir().join(format!("cryptomap-b56-cross-run-{}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    let _cleanup = Cleanup(directory.clone());
    fs::write(directory.join("leaf.der"), leaf.to_der().unwrap()).unwrap();
    fs::write(directory.join("root.pem"), RSA).unwrap();

    let mut scope = CollectionScope::new(CollectionScopeId::new("b56-batch-scope").unwrap());
    scope
        .grant_file(
            RawSourceKind::Certificate,
            LEAF,
            &directory,
            "leaf.der",
            MAX_CERT_FILE_BYTES,
        )
        .unwrap();
    scope
        .grant_file(
            RawSourceKind::Certificate,
            ROOT,
            &directory,
            "root.pem",
            MAX_CERT_FILE_BYTES,
        )
        .unwrap();
    let target = CertificateStoreTarget::new(CertificateStoreLocation::CurrentUser, "My").unwrap();
    scope
        .grant_certificate_store(
            STORE,
            CertificateStoreGrant::new(target, 4, 256 * 1024).unwrap(),
        )
        .unwrap();

    let authority =
        CertificateIdentityAuthority::new(scope.id().clone(), "tenant-a", "v1", [27u8; 32])
            .unwrap();
    let identity = IdentityContext::new(scope.id().as_str()).unwrap();
    let registry = Registry::builtin();
    let file = CertificateFileCollector::new(&scope, AT)
        .with_identity(&authority)
        .unwrap();
    let backend = Memory(root.to_der().unwrap());
    let store = CertificateStoreCollector::new(&scope, &backend, AT)
        .with_identity(&authority)
        .unwrap();
    let file_descriptor = file.descriptor();
    let store_descriptor = store.descriptor();

    let leaf_run = CollectionRunId::new("b56-run-leaf").unwrap();
    let root_run = CollectionRunId::new("b56-run-root").unwrap();
    let store_run = CollectionRunId::new("b56-run-store").unwrap();
    let leaf_sources = vec![RequestedSource {
        kind: RawSourceKind::Certificate,
        item: LEAF.into(),
    }];
    let root_sources = vec![RequestedSource {
        kind: RawSourceKind::Certificate,
        item: ROOT.into(),
    }];
    let store_sources = vec![RequestedSource {
        kind: RawSourceKind::CertificateStore,
        item: STORE.into(),
    }];
    let raw_limits = RawLimits {
        observations: 4,
        ..RawLimits::default()
    };
    let cancel = CancellationToken::default();
    let collect =
        |collector: &dyn Collector, run: &CollectionRunId, sources: &[RequestedSource]| {
            collect_scoped(
                &scope,
                collector,
                CollectionRequest {
                    run: run.clone(),
                    sources: sources.to_vec(),
                    limits: raw_limits,
                    options: BTreeMap::new(),
                },
                &cancel,
            )
            .unwrap()
        };
    let leaf_outcome = collect(&file, &leaf_run, &leaf_sources);
    let root_outcome = collect(&file, &root_run, &root_sources);
    let store_outcome = collect(&store, &store_run, &store_sources);
    assert_eq!(
        leaf_outcome.coverage[LEAF],
        CoverageState::InspectedObserved
    );
    assert_eq!(
        root_outcome.coverage[ROOT],
        CoverageState::InspectedObserved
    );
    assert_eq!(
        store_outcome.coverage[STORE],
        CoverageState::InspectedObserved
    );

    let inputs = |reverse: bool, leaf: cryptomap::collector::CollectionOutcome| {
        // Inline contexts retain independent host-pinned run and source refs.
        let mut runs = vec![
            BatchRun {
                input: pinned_input(
                    &scope,
                    &identity,
                    &registry,
                    &file_descriptor,
                    &leaf_run,
                    &leaf_sources,
                    raw_limits,
                ),
                outcome: leaf,
            },
            BatchRun {
                input: pinned_input(
                    &scope,
                    &identity,
                    &registry,
                    &file_descriptor,
                    &root_run,
                    &root_sources,
                    raw_limits,
                ),
                outcome: root_outcome.clone(),
            },
            BatchRun {
                input: pinned_input(
                    &scope,
                    &identity,
                    &registry,
                    &store_descriptor,
                    &store_run,
                    &store_sources,
                    raw_limits,
                ),
                outcome: store_outcome.clone(),
            },
        ];
        if reverse {
            runs.reverse();
        }
        runs
    };
    let first = normalize_batch_with_identity(
        inputs(false, leaf_outcome.clone()),
        BatchLimits::default(),
        &authority,
    )
    .unwrap();
    let second = normalize_batch_with_identity(
        inputs(true, leaf_outcome.clone()),
        BatchLimits::default(),
        &authority,
    )
    .unwrap();
    assert_eq!(first, second);

    // Identical event replays are valid in normalize_inner and must not
    // consume additional candidate slots or fabricate separate provenance.
    let mut replayed_runs = inputs(false, leaf_outcome.clone());
    let replay = replayed_runs[1].outcome.observations[0].clone();
    replayed_runs[1].outcome.observations.push(replay);
    let replayed = normalize_batch_with_identity(
        replayed_runs,
        BatchLimits::default(),
        &authority,
    )
    .unwrap();
    assert_eq!(replayed, first);

    // Differing records under one event ID remain a normalization violation.
    let mut divergent_runs = inputs(false, leaf_outcome.clone());
    let mut conflicting = divergent_runs[1].outcome.observations[0].clone();
    conflicting.source.offset = Some(1);
    divergent_runs[1].outcome.observations.push(conflicting);
    assert!(normalize_batch_with_identity(
        divergent_runs,
        BatchLimits::default(),
        &authority,
    )
    .is_err());

    assert_eq!(first.assets.len(), 2);
    assert_eq!(first.relationships.len(), 1);
    assert_eq!(
        first.coverage["x509:issuer-candidate:v1:batch"],
        CoverageState::InspectedObserved
    );
    let edge = first.relationships.values().next().unwrap();
    assert_eq!(edge.kind, RelationshipKind::RelatedTo);
    assert_ne!(edge.from, edge.to);
    // Leaf DER, issuer PEM and approved in-memory store all retain provenance.
    assert_eq!(edge.evidence.len(), 4);
    assert_eq!(
        first
            .evidence
            .values()
            .filter(|entry| entry.kind == EvidenceKind::Inferred)
            .count(),
        1,
    );
    assert!(first.evidence.values().any(|entry| {
        entry.kind == EvidenceKind::Inferred
            && entry.inference_rule.as_deref() == Some("x509:issuer-candidate:v1")
            && entry.run == leaf_run
    }));
    assert!(first.relationships.values().all(|rel| {
        rel.kind != RelationshipKind::IssuedBy && rel.kind != RelationshipKind::ValidatedBy
    }));
    first
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();

    // A failed/partially collected run can retain positive evidence but must
    // not upgrade the aggregate candidate search to an exhaustive negative.
    let mut partial_leaf = leaf_outcome.clone();
    partial_leaf
        .coverage
        .insert(LEAF.into(), CoverageState::Partial);
    partial_leaf.status = CollectionStatus::Failed;
    let partial = normalize_batch_with_identity(
        inputs(false, partial_leaf),
        BatchLimits::default(),
        &authority,
    )
    .unwrap();
    assert_eq!(
        partial.coverage["x509:issuer-candidate:v1:batch"],
        CoverageState::Partial
    );
    assert_eq!(partial.relationships.len(), 1);
    let wrong_authority =
        CertificateIdentityAuthority::new(scope.id().clone(), "tenant-b", "v1", [27u8; 32])
            .unwrap();
    assert!(matches!(
        normalize_batch_with_identity(
            inputs(false, leaf_outcome),
            BatchLimits::default(),
            &wrong_authority,
        ),
        Err(PipelineError::InvalidOutcome),
    ));
    let text = serde_json::to_string(&first).unwrap();
    for forbidden in [
        "-----BEGIN CERTIFICATE",
        "PRIVATE KEY",
        "CN=",
        "serialNumber=",
    ] {
        assert!(!text.contains(forbidden));
    }
}
