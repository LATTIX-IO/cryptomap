//! B5.6 live authorized store -> authenticated pseudonyms -> inferred graph.
//! Uses an in-memory backend only; no Windows user or machine store is opened.
#![cfg(all(feature = "certificate-identity", feature = "certificate-store-grants"))]
#![allow(clippy::unwrap_used)]

use cryptomap::{
    CollectionRunId, CollectionScopeId, CoverageState, EvidenceKind, IdentityContext,
    InventoryLimits, RelationshipKind,
    certificate_identity::CertificateIdentityAuthority,
    certificate_store_scope::{
        CertificateStoreGrant, CertificateStoreLocation, CertificateStoreTarget,
    },
    collector::{CancellationToken, CollectionRequest, Collector, RequestedSource},
    collectors::certificate_store::{
        CertificateStoreCollector, PublicCertificateStoreBackend, StoreProviderError,
    },
    pipeline::{self, PipelineError, PipelineInput},
    raw::{RawLimits, RawSourceKind},
    registry::Registry,
    scope::{CollectionScope, collect_scoped},
};
use std::collections::BTreeMap;
use x509_cert::{
    Certificate,
    der::{DecodePem, Encode},
};

const RSA: &[u8] = include_bytes!("../examples/fixtures/certificate/rsa.pem");
const EC: &[u8] = include_bytes!("../examples/fixtures/certificate/ec.pem");
const TIME: &str = "2026-10-18T12:00:00Z";
const ITEM: &str = "b56:authorized-in-memory-store";

struct Memory(Vec<Vec<u8>>);
impl PublicCertificateStoreBackend for Memory {
    fn visit(
        &self,
        _target: CertificateStoreTarget,
        visitor: &mut dyn FnMut(&[u8]) -> Result<(), StoreProviderError>,
    ) -> Result<(), StoreProviderError> {
        for der in &self.0 {
            visitor(der)?;
        }
        Ok(())
    }
}

#[test]
fn real_der_parser_yields_candidate_but_never_verified_issuance() {
    let issuer = Certificate::from_pem(RSA).unwrap();
    let mut leaf = Certificate::from_pem(EC).unwrap();
    // Deliberately change TBS issuer without re-signing. Even an exact
    // issuer/subject DN match must NOT become cryptographically verified.
    leaf.tbs_certificate.issuer = issuer.tbs_certificate.subject.clone();
    let memory = Memory(vec![issuer.to_der().unwrap(), leaf.to_der().unwrap()]);
    let mut scope = CollectionScope::new(CollectionScopeId::new("b56-authorized-scope").unwrap());
    let target = CertificateStoreTarget::new(CertificateStoreLocation::CurrentUser, "My").unwrap();
    scope
        .grant_certificate_store(
            ITEM,
            CertificateStoreGrant::new(target, 8, 256 * 1024).unwrap(),
        )
        .unwrap();
    let identity = IdentityContext::new(scope.id().as_str()).unwrap();
    let authority =
        CertificateIdentityAuthority::new(scope.id().clone(), "tenant", "v1", [31; 32]).unwrap();
    let collector = CertificateStoreCollector::new(&scope, &memory, TIME)
        .with_identity(&authority)
        .unwrap();
    let descriptor = collector.descriptor();
    let run = CollectionRunId::new("b56-store-run").unwrap();
    let sources = [RequestedSource {
        kind: RawSourceKind::CertificateStore,
        item: ITEM.into(),
    }];
    let limits = RawLimits {
        observations: 8,
        ..RawLimits::default()
    };
    let registry = Registry::builtin();
    let make_input = || PipelineInput {
        scope: &scope,
        identity: &identity,
        registry: &registry,
        expected_descriptor: &descriptor,
        expected_run: &run,
        sources: &sources,
        raw_limits: limits,
        inventory_limits: InventoryLimits::default(),
        started_at: TIME,
        ended_at: TIME,
    };
    let outcome = collect_scoped(
        &scope,
        &collector,
        CollectionRequest {
            run: run.clone(),
            sources: sources.to_vec(),
            limits,
            options: BTreeMap::new(),
        },
        &CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(outcome.coverage[ITEM], CoverageState::InspectedObserved);
    assert_eq!(outcome.observations.len(), 2);
    assert!(outcome.observations.iter().all(|o| {
        o.attributes.contains_key("x509:identity:v1:receipt")
    }));
    assert!(matches!(
        pipeline::normalize(make_input(), outcome.clone()),
        Err(PipelineError::InvalidOutcome)
    ));
    let wrong =
        CertificateIdentityAuthority::new(scope.id().clone(), "tenant", "v2", [31; 32]).unwrap();
    assert!(matches!(
        pipeline::normalize_with_identity(make_input(), outcome.clone(), &wrong),
        Err(PipelineError::InvalidOutcome)
    ));

    let inventory = pipeline::normalize_with_identity(make_input(), outcome, &authority).unwrap();
    assert_eq!(inventory.assets.len(), 2);
    assert_eq!(inventory.relationships.len(), 1);
    assert_eq!(
        inventory.coverage["x509:issuer-candidate:v1:b56-store-run"],
        CoverageState::InspectedObserved
    );
    let edge = inventory.relationships.values().next().unwrap();
    assert_eq!(edge.kind, RelationshipKind::RelatedTo);
    assert_ne!(edge.from, edge.to);
    assert_eq!(edge.evidence.len(), 3);
    assert!(inventory.evidence.values().any(|e| {
        e.kind == EvidenceKind::Inferred
            && e.inference_rule.as_deref() == Some("x509:issuer-candidate:v1")
    }));
    assert!(inventory.relationships.values().all(|relation| {
        relation.kind != RelationshipKind::IssuedBy
            && relation.kind != RelationshipKind::ValidatedBy
    }));
    inventory
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    // Store evidence is an exact requested, positively covered source even
    // after import. Re-hashing must not launder an unauthorized store name.
    let mut forged = inventory.clone();
    forged
        .evidence
        .values_mut()
        .find(|entry| entry.kind == EvidenceKind::Inferred)
        .unwrap()
        .source = "CertificateStore:unrequested-store".into();
    assert!(forged
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .is_err());
    let json = serde_json::to_string(&inventory).unwrap();
    for forbidden in [
        "-----BEGIN", "PRIVATE KEY", "certificate:identity-subject-dn:v1=CN",
        "certificate:identity-issuer-dn:v1=CN",
    ] {
        assert!(!json.contains(forbidden));
    }
    // The baseline without host-keyed identity data keeps the old inventory
    // behavior and must not emit inferred issuer candidate relationships.
    let ordinary = CertificateStoreCollector::new(&scope, &memory, TIME);
    let ordinary_descriptor = ordinary.descriptor();
    let normal_input = PipelineInput {
        expected_descriptor: &ordinary_descriptor,
        ..make_input()
    };
    let baseline = collect_scoped(
        &scope,
        &ordinary,
        CollectionRequest {
            run: run.clone(),
            sources: sources.to_vec(),
            limits,
            options: BTreeMap::new(),
        },
        &CancellationToken::default(),
    )
    .unwrap();
    let old = pipeline::normalize(normal_input, baseline).unwrap();
    assert!(old.relationships.is_empty());
    assert!(!old
        .coverage
        .contains_key("x509:issuer-candidate:v1:b56-store-run"));
}
