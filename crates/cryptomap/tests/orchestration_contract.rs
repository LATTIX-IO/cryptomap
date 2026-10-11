//! End-to-end third-party collector orchestration without ambient source access.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    CollectionRunId, CollectorId, Confidence, CoverageState, EvidenceKind, IdentityContext,
    InventoryError, InventoryLimits,
    batch::BatchLimits,
    collector::{
        COLLECTOR_CONTRACT_VERSION, CancellationToken, CollectionMode, CollectionRequest,
        CollectionSink, Collector, CollectorCapabilities, CollectorDescriptor,
        RequestedSource,
    },
    coverage::CollectionScopeId,
    orchestration::{ScopedInvocation, collect_normalized, collect_normalized_batch},
    pipeline::{PipelineError, PipelineInput},
    raw::{RawFactKind, RawLimits, RawObservation, RawSourceKind, RawSourceLocator},
    registry::Registry,
    scope::{CollectionScope, ScopeError},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Copy)]
enum Behavior {
    Certificate,
    Linked,
    Partial,
    ForgedRun,
    ForbiddenSource,
    Fatal,
    ConflictingReplay,
    CancelMidRun,
}
struct MockCollector {
    descriptor: CollectorDescriptor,
    behavior: Behavior,
    reverse: bool,
    calls: AtomicUsize,
}
impl MockCollector {
    fn new(descriptor: CollectorDescriptor, behavior: Behavior) -> Self {
        Self {
            descriptor,
            behavior,
            reverse: false,
            calls: AtomicUsize::new(0),
        }
    }
    fn count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
    fn fact(
        &self,
        request: &CollectionRequest,
        source: &RequestedSource,
        event: &str,
        fact: RawFactKind,
    ) -> RawObservation {
        RawObservation {
            contract_version: 1,
            event_id: event.into(),
            collector: self.descriptor.id.clone(),
            collector_version: self.descriptor.version.clone(),
            run: request.run.clone(),
            source: RawSourceLocator {
                kind: source.kind.clone(),
                item: source.item.clone(),
                offset: None,
                line: None,
                column: None,
            },
            observed_at: "2026-10-11T12:00:00Z".into(),
            fact,
            evidence_kind: EvidenceKind::Direct,
            confidence: Confidence::Confirmed,
            inference_rule: None,
            source_sha256: None,
            attributes: BTreeMap::new(),
        }
    }
}
fn certificate() -> RawFactKind {
    RawFactKind::Certificate {
        fingerprint_sha256: "ab".repeat(32),
    }
}
impl Collector for MockCollector {
    fn descriptor(&self) -> CollectorDescriptor {
        self.descriptor.clone()
    }

    fn collect(
        &self,
        request: &CollectionRequest,
        sink: &mut CollectionSink,
        cancel: &CancellationToken,
    ) -> Result<(), InventoryError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut sources: Vec<_> = request.sources.iter().collect();
        if self.reverse {
            sources.reverse();
        }
        match self.behavior {
            Behavior::Certificate => {
                for source in sources {
                    sink.emit(self.fact(request, source, &format!("cert:{}", source.item), certificate()))?;
                    sink.cover(&source.item, CoverageState::InspectedObserved)?;
                }
            }
            Behavior::Linked => {
                let source = sources[0];
                let mut protocol = self.fact(
                    request,
                    source,
                    "protocol",
                    RawFactKind::Protocol {
                        family: "TLS".into(),
                        version: Some("1.3".into()),
                        state: cryptomap::ProtocolState::Negotiated,
                    },
                );
                protocol.attributes.insert(
                    "cryptomap:relation-kind".into(),
                    "uses_certificate".into(),
                );
                protocol.attributes.insert(
                    "cryptomap:relation-target-event".into(),
                    "certificate".into(),
                );
                sink.emit(protocol)?;
                sink.emit(self.fact(request, source, "certificate", certificate()))?;
                sink.cover(&source.item, CoverageState::InspectedObserved)?;
            }
            Behavior::Partial => {
                let first = sources[0];
                let second = sources[1];
                sink.emit(self.fact(request, first, "done", certificate()))?;
                sink.cover(&first.item, CoverageState::InspectedObserved)?;
                sink.emit(self.fact(
                    request,
                    second,
                    "partial",
                    RawFactKind::Dependency {
                        ecosystem: "cargo".into(),
                        name: "rustls".into(),
                        version: "0.23".into(),
                    },
                ))?;
                sink.cover(&second.item, CoverageState::Partial)?;
            }
            Behavior::ForgedRun => {
                let source = sources[0];
                let mut record = self.fact(request, source, "forged", certificate());
                record.run = CollectionRunId::new("forged-run").unwrap();
                sink.emit(record)?;
            }
            Behavior::ForbiddenSource => {
                let source = sources[0];
                let mut record = self.fact(request, source, "forbidden", certificate());
                record.source.item = "ungranted:source".into();
                sink.emit(record)?;
            }
            Behavior::Fatal => return Err(InventoryError::InvalidMetadata),
            Behavior::ConflictingReplay => {
                let source = sources[0];
                let original = self.fact(request, source, "repeated", certificate());
                let mut changed = original.clone();
                changed.fact = RawFactKind::Certificate {
                    fingerprint_sha256: "cd".repeat(32),
                };
                sink.emit(original)?;
                sink.emit(changed)?;
            }
            Behavior::CancelMidRun => {
                let source = sources[0];
                sink.emit(self.fact(request, source, "partial-cancel", certificate()))?;
                sink.cover(&source.item, CoverageState::Partial)?;
                cancel.cancel();
            }
        }
        Ok(())
    }
}
struct Fixture {
    scope: CollectionScope,
    identity: IdentityContext,
    registry: Registry,
    descriptor: CollectorDescriptor,
    run: CollectionRunId,
    sources: Vec<RequestedSource>,
}
impl Fixture {
    fn new(tenant: &str, run: &str, collector: &str, items: &[&str]) -> Self {
        let mut scope = CollectionScope::new(CollectionScopeId::new(tenant).unwrap());
        for item in items {
            scope.grant_logical(RawSourceKind::Telemetry, *item).unwrap();
        }
        Self {
            scope,
            identity: IdentityContext::new(tenant).unwrap(),
            registry: Registry::builtin(),
            descriptor: CollectorDescriptor {
                contract_version: COLLECTOR_CONTRACT_VERSION,
                id: CollectorId::new(collector).unwrap(),
                version: "1.0".into(),
                capabilities: CollectorCapabilities {
                    sources: BTreeSet::from([RawSourceKind::Telemetry]),
                    mode: CollectionMode::Passive,
                    required_permissions: BTreeSet::new(),
                    checkpoint: false,
                },
            },
            run: CollectionRunId::new(run).unwrap(),
            sources: items
                .iter()
                .map(|item| RequestedSource {
                    kind: RawSourceKind::Telemetry,
                    item: (*item).into(),
                })
                .collect(),
        }
    }
    fn invocation<'a>(&'a self, collector: &'a MockCollector) -> ScopedInvocation<'a> {
        ScopedInvocation {
            collector,
            input: PipelineInput {
                scope: &self.scope,
                identity: &self.identity,
                registry: &self.registry,
                expected_descriptor: &self.descriptor,
                expected_run: &self.run,
                sources: &self.sources,
                raw_limits: RawLimits::default(),
                inventory_limits: InventoryLimits::default(),
                started_at: "2026-10-11T11:59:00Z",
                ended_at: "2026-10-11T12:01:00Z",
            },
        }
    }
    fn mock(&self, behavior: Behavior) -> MockCollector {
        MockCollector::new(self.descriptor.clone(), behavior)
    }
}
#[test]
fn third_party_collector_uses_existing_canonical_evidence_and_coverage() {
    let fixture = Fixture::new("tenant-1", "run-1", "partner-adapter", &["stream:a"]);
    let collector = fixture.mock(Behavior::Certificate);
    let snapshot = collect_normalized(
        fixture.invocation(&collector),
        &CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(collector.count(), 1);
    assert_eq!(snapshot.assets.len(), 1);
    assert_eq!(snapshot.evidence.len(), 1);
    assert_eq!(snapshot.runs.len(), 1);
    assert_eq!(snapshot.coverage_records.len(), 1);
    assert_eq!(snapshot.coverage["stream:a"], CoverageState::InspectedObserved);
    snapshot.verify(InventoryLimits::default()).unwrap();
}
#[test]
fn explicit_runtime_relationships_survive_third_party_adapter() {
    let fixture = Fixture::new("tenant-1", "run-link", "partner-adapter", &["stream:tls"]);
    let collector = fixture.mock(Behavior::Linked);
    let snapshot = collect_normalized(
        fixture.invocation(&collector),
        &CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(snapshot.assets.len(), 2);
    assert_eq!(snapshot.evidence.len(), 2);
    assert_eq!(snapshot.relationships.len(), 1);
    let edge = snapshot.relationships.values().next().unwrap();
    assert_eq!(edge.kind, cryptomap::RelationshipKind::UsesCertificate);
    assert_eq!(edge.evidence.len(), 1);
    snapshot.verify(InventoryLimits::default()).unwrap();
}
#[test]
fn heterogeneous_batch_merges_canonical_identity_not_source_or_run() {
    let first = Fixture::new("tenant-1", "run-a", "partner-one", &["stream:a"]);
    let second = Fixture::new("tenant-1", "run-b", "partner-two", &["stream:b"]);
    let a = first.mock(Behavior::Certificate);
    let b = second.mock(Behavior::Certificate);
    let merged = collect_normalized_batch(
        vec![second.invocation(&b), first.invocation(&a)],
        BatchLimits::default(),
        &CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(merged.assets.len(), 1);
    assert_eq!(merged.evidence.len(), 2);
    assert_eq!(merged.runs.len(), 2);
    assert_eq!(merged.coverage_records.len(), 2);
    assert!(merged.coverage.is_empty());
    merged.verify(InventoryLimits::default()).unwrap();
}
#[test]
fn batch_output_is_deterministic_under_collector_order_permutation() {
    let a = Fixture::new("tenant-1", "run-a", "partner-one", &["stream:a"]);
    let b = Fixture::new("tenant-1", "run-b", "partner-two", &["stream:b"]);
    let left = a.mock(Behavior::Certificate);
    let right = b.mock(Behavior::Certificate);
    let cancellation = CancellationToken::default();
    let forward = collect_normalized_batch(
        vec![a.invocation(&left), b.invocation(&right)],
        BatchLimits::default(),
        &cancellation,
    )
    .unwrap();
    let backward = collect_normalized_batch(
        vec![b.invocation(&right), a.invocation(&left)],
        BatchLimits::default(),
        &cancellation,
    )
    .unwrap();
    assert_eq!(forward.id, backward.id);
    assert_eq!(forward, backward);
}
#[test]
fn failed_and_partial_sources_keep_original_evidence_and_coverage() {
    let partial = Fixture::new("tenant-1", "run-a", "partner-partial", &["stream:a", "stream:b"]);
    let complete = Fixture::new("tenant-1", "run-b", "partner-ok", &["stream:c"]);
    let first = partial.mock(Behavior::Partial);
    let second = complete.mock(Behavior::Certificate);
    let snap = collect_normalized_batch(
        vec![partial.invocation(&first), complete.invocation(&second)],
        BatchLimits::default(),
        &CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(snap.runs.len(), 2);
    assert_eq!(snap.evidence.len(), 3);
    assert_eq!(snap.coverage_records.len(), 3);
    assert!(snap.coverage_records.iter().any(|r| r.state == CoverageState::Partial));
    snap.verify(InventoryLimits::default()).unwrap();
}
#[test]
fn all_invalid_batch_authorities_fail_before_any_collector_execution() {
    // A failed preflight may NOT inspect even the first otherwise-valid source.
    let first = Fixture::new("tenant-1", "run-a", "partner-a", &["stream:a"]);
    let foreign = Fixture::new("tenant-2", "run-b", "partner-b", &["stream:b"]);
    let a = first.mock(Behavior::Certificate);
    let b = foreign.mock(Behavior::Certificate);
    assert!(matches!(collect_normalized_batch(
        vec![first.invocation(&a), foreign.invocation(&b)],
        BatchLimits::default(),
        &CancellationToken::default(),
    ), Err(PipelineError::InvalidOutcome)));
    assert_eq!(a.count(), 0);
    assert_eq!(b.count(), 0);
    let duplicate = Fixture::new("tenant-1", "run-a", "partner-b", &["stream:b"]);
    let c = duplicate.mock(Behavior::Certificate);
    assert!(matches!(collect_normalized_batch(
        vec![first.invocation(&a), duplicate.invocation(&c)],
        BatchLimits::default(),
        &CancellationToken::default(),
    ), Err(PipelineError::InvalidOutcome)));
    assert_eq!(a.count(), 0);
    assert_eq!(c.count(), 0);
    let cap = BatchLimits {
        sources: 1,
        ..BatchLimits::default()
    };
    assert!(matches!(collect_normalized_batch(
        vec![first.invocation(&a), duplicate.invocation(&c)],
        cap,
        &CancellationToken::default(),
    ), Err(PipelineError::InvalidOutcome)));
    assert_eq!(a.count(), 0);
    assert_eq!(c.count(), 0);
}
#[test]
fn forged_collector_descriptor_or_ungranted_source_never_executes() {
    let fixture = Fixture::new("tenant-1", "run-a", "host-pinned", &["stream:a"]);
    let mut forged = fixture.mock(Behavior::Certificate);
    forged.descriptor.version = "2.0".into();
    assert!(matches!(collect_normalized(
        fixture.invocation(&forged),
        &CancellationToken::default(),
    ), Err(PipelineError::InvalidOutcome)));
    assert_eq!(forged.count(), 0);

    let mut scope_fixture = Fixture::new("tenant-1", "run-b", "host-pinned", &["stream:a"]);
    scope_fixture.sources[0].item = "stream:ungranted".into();
    let good = scope_fixture.mock(Behavior::Certificate);
    assert!(matches!(collect_normalized(
        scope_fixture.invocation(&good),
        &CancellationToken::default(),
    ), Err(PipelineError::Scope(ScopeError::OutOfScope))));
    assert_eq!(good.count(), 0);
}
#[test]
fn forged_emission_and_conflicting_replay_rejected_by_same_sink() {
    for behavior in [
        Behavior::ForgedRun,
        Behavior::ForbiddenSource,
        Behavior::ConflictingReplay,
    ] {
        let fixture = Fixture::new("tenant-1", "run-a", "partner", &["stream:a"]);
        let collector = fixture.mock(behavior);
        assert!(matches!(collect_normalized(
            fixture.invocation(&collector),
            &CancellationToken::default(),
        ), Err(PipelineError::Scope(ScopeError::Collection(_)))));
        assert_eq!(collector.count(), 1);
    }
}
#[test]
fn pre_cancel_skips_all_collector_code_and_preserves_not_inspected_state() {
    let fixture = Fixture::new("tenant-1", "run-a", "partner", &["stream:a"]);
    let collector = fixture.mock(Behavior::Certificate);
    let cancel = CancellationToken::default();
    cancel.cancel();
    let snapshot = collect_normalized(fixture.invocation(&collector), &cancel).unwrap();
    assert_eq!(collector.count(), 0);
    assert!(snapshot.assets.is_empty());
    assert!(snapshot.evidence.is_empty());
    assert_eq!(snapshot.coverage["stream:a"], CoverageState::NotInspected);
    snapshot.verify(InventoryLimits::default()).unwrap();
}
#[test]
fn cooperative_cancel_mid_run_does_not_claim_complete_coverage() {
    let fixture = Fixture::new("tenant-1", "run-a", "partner", &["stream:a"]);
    let collector = fixture.mock(Behavior::CancelMidRun);
    let cancel = CancellationToken::default();
    let snapshot = collect_normalized(fixture.invocation(&collector), &cancel).unwrap();
    assert!(cancel.is_cancelled());
    assert_eq!(snapshot.evidence.len(), 1);
    assert_eq!(snapshot.coverage["stream:a"], CoverageState::Partial);
    snapshot.verify(InventoryLimits::default()).unwrap();
}
#[test]
fn fatal_collector_error_yields_no_normalized_snapshot() {
    let fixture = Fixture::new("tenant-1", "run-a", "partner", &["stream:a"]);
    let collector = fixture.mock(Behavior::Fatal);
    assert!(matches!(collect_normalized(
        fixture.invocation(&collector),
        &CancellationToken::default(),
    ), Err(PipelineError::Scope(ScopeError::Collection(_)))));
    assert_eq!(collector.count(), 1);
}
