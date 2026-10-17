//! FOSS-467: deterministic, inert certificate-store authorization conformance.
//! No test enumerates, modifies or opens a real Windows or other OS store.
#![cfg(feature = "certificate-store-grants")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    CollectionRunId, CollectionScopeId, CollectorId, CoverageState, IdentityContext,
    InventoryError, InventoryLimits,
    batch::BatchLimits,
    certificate_store_scope::{
        CertificateStoreGrant, CertificateStoreLocation, CertificateStoreTarget,
        MAX_CERT_STORE_ENTRIES, MAX_CERT_STORE_PUBLIC_BYTES,
    },
    collector::{
        COLLECTOR_CONTRACT_VERSION, CancellationToken, CollectionMode, CollectionRequest,
        CollectionSink, Collector, CollectorCapabilities, CollectorDescriptor, CollectorDiagnostic,
        CollectorDiagnosticCode, RequestedSource,
    },
    orchestration::{ScopedInvocation, collect_normalized, collect_normalized_batch},
    pipeline::{PipelineError, PipelineInput},
    raw::{RawLimits, RawSourceKind},
    registry::Registry,
    scope::{CollectionScope, ScopeError, collect_scoped, collect_scoped_isolated},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicUsize, Ordering},
};

const ITEM: &str = "authorized:CurrentUser/My";
const NOW: &str = "2026-10-16T18:00:00Z";

fn target() -> CertificateStoreTarget {
    CertificateStoreTarget::new(CertificateStoreLocation::CurrentUser, "My").unwrap()
}
fn grant() -> CertificateStoreGrant {
    CertificateStoreGrant::new(target(), 4, 512 * 1024).unwrap()
}
fn scope(item: &str) -> CollectionScope {
    let mut s = CollectionScope::new(CollectionScopeId::new("foss467-tenant").unwrap());
    s.grant_certificate_store(item, grant()).unwrap();
    s
}
fn limits() -> RawLimits {
    RawLimits {
        sources: 4,
        observations: 4,
        total_bytes: 1024 * 1024,
        record_bytes: 16 * 1024,
        field_bytes: 2048,
        attributes: 32,
    }
}
fn sources(items: &[&str], kind: RawSourceKind) -> Vec<RequestedSource> {
    items
        .iter()
        .map(|item| RequestedSource {
            kind: kind.clone(),
            item: (*item).into(),
        })
        .collect()
}
fn request(items: &[&str]) -> CollectionRequest {
    CollectionRequest {
        run: CollectionRunId::new("store-run").unwrap(),
        sources: sources(items, RawSourceKind::CertificateStore),
        limits: limits(),
        options: BTreeMap::new(),
    }
}

/// Deliberately inert fake. Only host grants are read; no platform APIs exist.
struct InertStoreCollector<'a> {
    scope: &'a CollectionScope,
    calls: AtomicUsize,
}
impl<'a> InertStoreCollector<'a> {
    fn new(scope: &'a CollectionScope) -> Self {
        Self {
            scope,
            calls: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}
impl Collector for InertStoreCollector<'_> {
    fn matches_invocation_scope(&self, scope: &CollectionScope) -> bool {
        std::ptr::eq(self.scope, scope)
    }
    fn descriptor(&self) -> CollectorDescriptor {
        CollectorDescriptor {
            contract_version: COLLECTOR_CONTRACT_VERSION,
            id: CollectorId::new("cryptomap:foss467-inert-fake").unwrap(),
            version: "0.1".into(),
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
        self.calls.fetch_add(1, Ordering::SeqCst);
        for source in &request.sources {
            let grant = self
                .scope
                .authorize_certificate_store(&source.item)
                .map_err(|_| InventoryError::InvalidMetadata)?;
            assert!(grant.max_entries() > 0);
            let cancelled = cancel.is_cancelled();
            sink.diagnose(CollectorDiagnostic {
                code: if cancelled {
                    CollectorDiagnosticCode::Cancelled
                } else {
                    CollectorDiagnosticCode::UnsupportedSource
                },
                source_item: Some(source.item.clone()),
            })?;
            sink.cover(
                &source.item,
                if cancelled {
                    CoverageState::NotInspected
                } else {
                    CoverageState::Unsupported
                },
            )?;
        }
        Ok(())
    }
}

#[test]
fn allowed_target_has_canonical_identity_and_legacy_names_fail_closed() {
    assert_eq!(target().id(), "certstore:v1:CurrentUser/My");
    let machine =
        CertificateStoreTarget::new(CertificateStoreLocation::LocalMachine, "My").unwrap();
    assert_eq!(machine.id(), "certstore:v1:LocalMachine/My");
    assert_ne!(machine, target());
    let long_name = "M".repeat(500);
    for name in [
        "",
        "my",
        "MY",
        "Root",
        "CA",
        "MY\\",
        "My/../Root",
        "My*",
        "My?",
        "My\0",
        "My ",
        long_name.as_str(),
    ] {
        assert!(CertificateStoreTarget::new(CertificateStoreLocation::CurrentUser, name).is_err());
    }
    assert!(CertificateStoreGrant::new(target(), 0, 4096).is_err());
    assert!(CertificateStoreGrant::new(target(), 1, 0).is_err());
    assert!(CertificateStoreGrant::new(target(), MAX_CERT_STORE_ENTRIES + 1, 4096).is_err());
    assert!(CertificateStoreGrant::new(target(), 1, MAX_CERT_STORE_PUBLIC_BYTES + 1).is_err());
}

#[test]
fn typed_grants_roundtrip_with_strict_external_serialization() {
    let approved = grant();
    let json = serde_json::to_string(&approved).unwrap();
    let decoded: CertificateStoreGrant = serde_json::from_str(&json).unwrap();
    assert_eq!(approved, decoded);
    assert_eq!(
        approved.target().location(),
        CertificateStoreLocation::CurrentUser
    );
    assert_eq!(approved.max_public_bytes(), 512 * 1024);
    let mut invalid: serde_json::Value = serde_json::from_str(&json).unwrap();
    invalid["target"]["name"] = serde_json::json!("Root");
    assert!(serde_json::from_value::<CertificateStoreGrant>(invalid).is_err());
    let mut invalid: serde_json::Value = serde_json::from_str(&json).unwrap();
    invalid["extra_grant"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CertificateStoreGrant>(invalid).is_err());
    let mut invalid: serde_json::Value = serde_json::from_str(&json).unwrap();
    invalid["max_entries"] = serde_json::json!(0);
    let bypassed: CertificateStoreGrant = serde_json::from_value(invalid).unwrap();
    assert!(matches!(
        bypassed.validate(),
        Err(ScopeError::ResourceLimit)
    ));
    let mut s = CollectionScope::new(CollectionScopeId::new("foss467-tenant").unwrap());
    assert!(matches!(
        s.grant_certificate_store(ITEM, bypassed),
        Err(ScopeError::ResourceLimit)
    ));
}

#[test]
fn source_item_grant_is_exact_unique_and_non_expanding() {
    let mut s = scope(ITEM);
    assert_eq!(
        s.authorize_certificate_store(ITEM).unwrap().target(),
        target()
    );
    assert!(matches!(
        s.authorize_certificate_store("authorized:LocalMachine/My"),
        Err(ScopeError::OutOfScope)
    ));
    assert!(matches!(
        s.grant_certificate_store(ITEM, grant()),
        Err(ScopeError::InvalidInput)
    ));
    for bad in ["", "*", "store?", " leading", "trailing ", "nul\0item"] {
        assert!(s.grant_certificate_store(bad, grant()).is_err());
    }
    assert!(
        s.grant_certificate_store("X".repeat(2049), grant())
            .is_err()
    );
    assert!(s.validate_request(&request(&[ITEM])).is_ok());
    assert!(matches!(
        s.validate_request(&request(&["authorized:LocalMachine/My"])),
        Err(ScopeError::OutOfScope)
    ));
    let mut too_many = request(&[ITEM]);
    too_many.limits.observations = 5;
    assert!(matches!(
        s.validate_request(&too_many),
        Err(ScopeError::ResourceLimit)
    ));
}

#[test]
fn multiple_exact_store_grants_use_global_budget_without_false_denial() {
    let mut s = scope(ITEM);
    let machine =
        CertificateStoreTarget::new(CertificateStoreLocation::LocalMachine, "My").unwrap();
    s.grant_certificate_store(
        "machine:My",
        CertificateStoreGrant::new(machine, 4, 512 * 1024).unwrap(),
    )
    .unwrap();
    let fake = InertStoreCollector::new(&s);
    let cancel = CancellationToken::default();
    let mut request = request(&[ITEM, "machine:My"]);
    // Each store permits 4 certificate contexts; the complete request may
    // permit 8 even though no individual store grants 8.
    request.limits.observations = 8;
    assert!(s.validate_request(&request).is_ok());
    let out = collect_scoped(&s, &fake, request.clone(), &cancel).unwrap();
    assert_eq!(out.coverage[ITEM], CoverageState::Unsupported);
    assert_eq!(out.coverage["machine:My"], CoverageState::Unsupported);
    assert!(out.observations.is_empty());
    assert_eq!(fake.calls(), 1);
    request.limits.observations = 9;
    assert!(matches!(
        s.validate_request(&request),
        Err(ScopeError::ResourceLimit)
    ));
    assert_eq!(fake.calls(), 1);
}

#[test]
fn certificate_file_and_store_kinds_are_not_interchangeable() {
    let mut s = scope(ITEM);
    let mut file_spoof = request(&[ITEM]);
    file_spoof.sources[0].kind = RawSourceKind::Certificate;
    assert!(matches!(
        s.validate_request(&file_spoof),
        Err(ScopeError::OutOfScope)
    ));
    assert!(matches!(
        s.open_file(RawSourceKind::CertificateStore, ITEM),
        Err(ScopeError::OutOfScope)
    ));
    assert!(matches!(
        s.open_file(RawSourceKind::Certificate, ITEM),
        Err(ScopeError::OutOfScope)
    ));
    assert!(matches!(
        s.grant_logical(RawSourceKind::Certificate, ITEM),
        Err(ScopeError::InvalidInput)
    ));
    let mut legacy = CollectionScope::new(CollectionScopeId::new("foss467-tenant").unwrap());
    legacy
        .grant_logical(RawSourceKind::Certificate, ITEM)
        .unwrap();
    assert!(matches!(
        legacy.validate_request(&request(&[ITEM])),
        Err(ScopeError::OutOfScope)
    ));
    assert!(matches!(
        legacy.grant_certificate_store(ITEM, grant()),
        Err(ScopeError::InvalidInput)
    ));
}

#[test]
fn raw_and_isolated_paths_preflight_all_grants_before_fake_runs() {
    let s = scope(ITEM);
    let fake = InertStoreCollector::new(&s);
    let cancel = CancellationToken::default();
    let denied = request(&[ITEM, "ungranted"]);
    assert!(matches!(
        collect_scoped(&s, &fake, denied.clone(), &cancel),
        Err(ScopeError::OutOfScope)
    ));
    assert!(matches!(
        collect_scoped_isolated(&s, &fake, denied, &cancel),
        Err(ScopeError::OutOfScope)
    ));
    assert_eq!(fake.calls(), 0);
    let done = collect_scoped(&s, &fake, request(&[ITEM]), &cancel).unwrap();
    assert!(done.observations.is_empty());
    assert_eq!(done.coverage[ITEM], CoverageState::Unsupported);
    assert_eq!(fake.calls(), 1);
    let isolated = collect_scoped_isolated(&s, &fake, request(&[ITEM]), &cancel).unwrap();
    assert!(isolated.observations.is_empty());
    assert_eq!(isolated.coverage[ITEM], CoverageState::Unsupported);
    assert_eq!(fake.calls(), 2);
}

#[test]
fn same_tenant_label_never_allows_cross_scope_collector_replay() {
    let a = scope(ITEM);
    let b = scope(ITEM);
    let fake = InertStoreCollector::new(&a);
    let cancel = CancellationToken::default();
    assert!(fake.matches_invocation_scope(&a));
    assert!(!fake.matches_invocation_scope(&b));
    assert!(matches!(
        collect_scoped(&b, &fake, request(&[ITEM]), &cancel),
        Err(ScopeError::OutOfScope)
    ));
    assert!(matches!(
        collect_scoped_isolated(&b, &fake, request(&[ITEM]), &cancel),
        Err(ScopeError::OutOfScope)
    ));
    assert_eq!(fake.calls(), 0);
}

#[test]
fn cancellation_never_produces_fake_absence_or_certificate_evidence() {
    let s = scope(ITEM);
    let fake = InertStoreCollector::new(&s);
    let cancel = CancellationToken::default();
    cancel.cancel();
    let result = collect_scoped(&s, &fake, request(&[ITEM]), &cancel).unwrap();
    assert_eq!(result.coverage[ITEM], CoverageState::NotInspected);
    assert!(result.observations.is_empty());
    assert_eq!(
        result.diagnostics[0].code,
        CollectorDiagnosticCode::Cancelled
    );
}

fn invocation<'a>(
    scope: &'a CollectionScope,
    collector: &'a InertStoreCollector<'_>,
    identity: &'a IdentityContext,
    registry: &'a Registry,
    descriptor: &'a CollectorDescriptor,
    run: &'a CollectionRunId,
    items: &'a [RequestedSource],
) -> ScopedInvocation<'a> {
    ScopedInvocation {
        collector,
        input: PipelineInput {
            scope,
            identity,
            registry,
            expected_descriptor: descriptor,
            expected_run: run,
            sources: items,
            raw_limits: limits(),
            inventory_limits: InventoryLimits::default(),
            started_at: NOW,
            ended_at: NOW,
        },
    }
}

#[test]
fn normalized_scope_and_batch_preflight_reject_wrong_item_without_execution() {
    let s = scope(ITEM);
    let fake = InertStoreCollector::new(&s);
    let identity = IdentityContext::new("foss467-tenant").unwrap();
    let registry = Registry::builtin();
    let descriptor = fake.descriptor();
    let run = CollectionRunId::new("store-run").unwrap();
    let valid = sources(&[ITEM], RawSourceKind::CertificateStore);
    let bad = sources(&["ungranted"], RawSourceKind::CertificateStore);
    let cancel = CancellationToken::default();
    assert!(matches!(
        collect_normalized(
            invocation(&s, &fake, &identity, &registry, &descriptor, &run, &bad),
            &cancel
        ),
        Err(PipelineError::Scope(ScopeError::OutOfScope))
    ));
    assert!(matches!(
        collect_normalized_batch(
            vec![
                invocation(&s, &fake, &identity, &registry, &descriptor, &run, &valid),
                invocation(&s, &fake, &identity, &registry, &descriptor, &run, &bad),
            ],
            BatchLimits::default(),
            &cancel
        ),
        Err(PipelineError::Scope(ScopeError::OutOfScope))
    ));
    assert_eq!(fake.calls(), 0);
    let snapshot = collect_normalized(
        invocation(&s, &fake, &identity, &registry, &descriptor, &run, &valid),
        &cancel,
    )
    .unwrap();
    assert!(snapshot.assets.is_empty());
    assert!(snapshot.evidence.is_empty());
    assert_eq!(snapshot.coverage[ITEM], CoverageState::Unsupported);
    snapshot
        .verify_for_scope(s.id(), InventoryLimits::default())
        .unwrap();
    assert_eq!(fake.calls(), 1);
}
