//! FOSS-320.7 temporal provenance and terminal source lifecycle conformance.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    CollectionRunId, CollectorId, Confidence, CoverageState, EvidenceKind, IdentityContext,
    InventoryError, InventoryLimits,
    batch::{BatchLimits, BatchRun, normalize_batch},
    collector::{
        COLLECTOR_CONTRACT_VERSION, CancellationToken, CollectionMode, CollectionOutcome,
        CollectionRequest, CollectionSink, CollectionStatus, Collector, CollectorCapabilities,
        CollectorDescriptor, RequestedSource,
    },
    coverage::CollectionScopeId,
    orchestration::{ScopedInvocation, collect_normalized},
    pipeline::{PipelineError, PipelineInput, normalize},
    raw::{RawFactKind, RawLimits, RawObservation, RawSourceKind, RawSourceLocator},
    registry::Registry,
    scope::{CollectionScope, ScopeError},
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};

fn descriptor() -> CollectorDescriptor {
    CollectorDescriptor {
        contract_version: COLLECTOR_CONTRACT_VERSION,
        id: CollectorId::new("time-fixture").unwrap(),
        version: "1.0".into(),
        capabilities: CollectorCapabilities {
            sources: BTreeSet::from([RawSourceKind::Telemetry]),
            mode: CollectionMode::Passive,
            required_permissions: BTreeSet::new(),
            checkpoint: false,
        },
    }
}
fn source() -> RequestedSource {
    RequestedSource {
        kind: RawSourceKind::Telemetry,
        item: "stream:time".into(),
    }
}
fn observation(id: &str, run: &str, when: &str) -> RawObservation {
    RawObservation {
        contract_version: 1,
        event_id: id.into(),
        collector: descriptor().id,
        collector_version: "1.0".into(),
        run: CollectionRunId::new(run).unwrap(),
        source: RawSourceLocator {
            kind: RawSourceKind::Telemetry,
            item: source().item,
            offset: None,
            line: None,
            column: None,
        },
        observed_at: when.into(),
        fact: RawFactKind::Certificate {
            fingerprint_sha256: "ab".repeat(32),
        },
        evidence_kind: EvidenceKind::Direct,
        confidence: Confidence::Confirmed,
        inference_rule: None,
        source_sha256: None,
        attributes: BTreeMap::new(),
    }
}
fn outcome(run: &str, facts: Vec<RawObservation>) -> CollectionOutcome {
    let has_observation = !facts.is_empty();
    CollectionOutcome {
        descriptor: descriptor(),
        run: CollectionRunId::new(run).unwrap(),
        observations: facts,
        coverage: BTreeMap::from([(
            source().item,
            if has_observation {
                CoverageState::InspectedObserved
            } else {
                CoverageState::InspectedNoObservation
            },
        )]),
        diagnostics: Vec::new(),
        status: CollectionStatus::Complete,
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
    fn new(run: &str) -> Self {
        let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-time").unwrap());
        scope
            .grant_logical(RawSourceKind::Telemetry, &source().item)
            .unwrap();
        Self {
            scope,
            identity: IdentityContext::new("tenant-time").unwrap(),
            registry: Registry::builtin(),
            descriptor: descriptor(),
            run: CollectionRunId::new(run).unwrap(),
            sources: vec![source()],
        }
    }
    fn input<'a>(&'a self, start: &'a str, end: &'a str) -> PipelineInput<'a> {
        PipelineInput {
            scope: &self.scope,
            identity: &self.identity,
            registry: &self.registry,
            expected_descriptor: &self.descriptor,
            expected_run: &self.run,
            sources: &self.sources,
            raw_limits: RawLimits::default(),
            inventory_limits: InventoryLimits::default(),
            started_at: start,
            ended_at: end,
        }
    }
}
#[test]
fn boundary_observations_and_timezone_equivalent_instants_are_accepted() {
    let fixture = Fixture::new("run-a");
    for observed_at in [
        "2026-10-11T11:59:00Z",
        "2026-10-11T12:01:00Z",
        "2026-10-11T13:00:00+01:00",
        "2026-10-11T08:00:00-04:00",
    ] {
        let result = normalize(
            fixture.input("2026-10-11T11:59:00Z", "2026-10-11T12:01:00Z"),
            outcome("run-a", vec![observation("event-a", "run-a", observed_at)]),
        )
        .unwrap();
        assert_eq!(result.assets.len(), 1);
        assert_eq!(result.evidence.len(), 1);
        result.verify(InventoryLimits::default()).unwrap();
    }
}
#[test]
fn timestamps_before_start_and_after_end_fail_closed_without_snapshot() {
    let fixture = Fixture::new("run-a");
    for when in [
        "2026-10-11T11:58:59Z",
        "2026-10-11T12:01:01Z",
        "2026-10-11T13:01:01+01:00",
    ] {
        let err = normalize(
            fixture.input("2026-10-11T11:59:00Z", "2026-10-11T12:01:00Z"),
            outcome(
                "run-a",
                vec![observation("private:customer-event", "run-a", when)],
            ),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PipelineError::Inventory(InventoryError::InvalidTimestamp)
        ));
        assert!(!format!("{err:?}").contains("private:customer-event"));
    }
}
#[test]
fn inverted_or_malformed_host_window_rejected_even_for_empty_run() {
    let fixture = Fixture::new("run-a");
    for (start, end) in [
        ("2026-10-11T12:02:00Z", "2026-10-11T12:01:00Z"),
        ("not-a-time", "2026-10-11T12:01:00Z"),
        ("2026-10-11T11:59:00Z", "not-a-time"),
    ] {
        assert!(matches!(
            normalize(fixture.input(start, end), outcome("run-a", vec![])),
            Err(PipelineError::Inventory(InventoryError::InvalidTimestamp))
        ));
    }
}
#[test]
fn batch_rejects_one_temporally_forged_run_atomically() {
    let a = Fixture::new("run-a");
    let b = Fixture::new("run-b");
    let valid = BatchRun {
        input: a.input("2026-10-11T11:59:00Z", "2026-10-11T12:01:00Z"),
        outcome: outcome(
            "run-a",
            vec![observation("valid", "run-a", "2026-10-11T12:00:00Z")],
        ),
    };
    let forged = BatchRun {
        input: b.input("2026-10-11T11:59:00Z", "2026-10-11T12:01:00Z"),
        outcome: outcome(
            "run-b",
            vec![observation("forged", "run-b", "2026-10-11T12:05:00Z")],
        ),
    };
    assert!(matches!(
        normalize_batch(vec![valid, forged], BatchLimits::default()),
        Err(PipelineError::Inventory(InventoryError::InvalidTimestamp))
    ));
}
#[test]
fn sink_seals_every_terminal_coverage_state_against_late_facts() {
    for state in [
        CoverageState::InspectedObserved,
        CoverageState::InspectedNoObservation,
        CoverageState::Partial,
        CoverageState::Failed,
        CoverageState::Unsupported,
        CoverageState::NotInspected,
    ] {
        let request = CollectionRequest {
            run: CollectionRunId::new("run-a").unwrap(),
            sources: vec![source()],
            limits: RawLimits::default(),
            options: BTreeMap::new(),
        };
        let mut sink = CollectionSink::new(descriptor(), request).unwrap();
        let prior = observation("early", "run-a", "2026-10-11T12:00:00Z");
        if matches!(
            state,
            CoverageState::InspectedObserved | CoverageState::Partial
        ) {
            sink.emit(prior.clone()).unwrap();
        }
        sink.cover(&source().item, state).unwrap();
        assert!(matches!(
            sink.emit(prior.clone()),
            Err(InventoryError::InvalidMetadata)
        ));
        assert!(matches!(
            sink.emit(observation("late", "run-a", "2026-10-11T12:00:01Z")),
            Err(InventoryError::InvalidMetadata)
        ));
        assert!(matches!(
            sink.cover(&source().item, state),
            Err(InventoryError::InvalidMetadata)
        ));
        let finished = sink.finish();
        assert!(finished.observations.len() <= 1);
    }
}
struct LateCollector {
    calls: AtomicUsize,
}
impl Collector for LateCollector {
    fn descriptor(&self) -> CollectorDescriptor {
        descriptor()
    }
    fn collect(
        &self,
        request: &CollectionRequest,
        sink: &mut CollectionSink,
        _: &CancellationToken,
    ) -> Result<(), InventoryError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        sink.emit(observation(
            "before",
            request.run.as_str(),
            "2026-10-11T12:00:00Z",
        ))?;
        sink.cover(&source().item, CoverageState::InspectedObserved)?;
        sink.emit(observation(
            "after",
            request.run.as_str(),
            "2026-10-11T12:00:01Z",
        ))?;
        Ok(())
    }
}
#[test]
fn late_third_party_emission_cannot_be_canonicalized() {
    let fixture = Fixture::new("run-a");
    let plugin = LateCollector {
        calls: AtomicUsize::new(0),
    };
    let invocation = ScopedInvocation {
        collector: &plugin,
        input: fixture.input("2026-10-11T11:59:00Z", "2026-10-11T12:01:00Z"),
    };
    assert!(matches!(
        collect_normalized(invocation, &CancellationToken::default()),
        Err(PipelineError::Scope(ScopeError::Collection(
            InventoryError::InvalidMetadata
        )))
    ));
    assert_eq!(plugin.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn live_pipeline_rejects_fractional_timestamp_outside_host_window() {
    let fixture = Fixture::new("run-a");
    for rejected in [
        "2026-10-11T12:00:00.249999999999Z",
        "2026-10-11T12:00:00.750000000001Z",
    ] {
        assert!(matches!(
            normalize(
                fixture.input("2026-10-11T12:00:00.250Z", "2026-10-11T12:00:00.750Z"),
                outcome("run-a", vec![observation("event", "run-a", rejected)]),
            ),
            Err(PipelineError::Inventory(InventoryError::InvalidTimestamp))
        ));
    }
}

#[test]
fn live_pipeline_accepts_fractional_timestamp_exact_boundaries() {
    let fixture = Fixture::new("run-a");
    for allowed in [
        "2026-10-11T12:00:00.25Z",
        "2026-10-11T12:00:00.750000000000Z",
        "2026-10-11T08:00:00.500-04:00",
    ] {
        let snap = normalize(
            fixture.input("2026-10-11T12:00:00.250Z", "2026-10-11T12:00:00.750Z"),
            outcome("run-a", vec![observation("event", "run-a", allowed)]),
        )
        .unwrap();
        snap.verify(InventoryLimits::default()).unwrap();
    }
}

#[test]
fn live_pipeline_rejects_inverted_fractional_host_window_without_events() {
    let fixture = Fixture::new("run-a");
    assert!(matches!(
        normalize(
            fixture.input("2026-10-11T12:00:00.9Z", "2026-10-11T12:00:00.1Z"),
            outcome("run-a", vec![]),
        ),
        Err(PipelineError::Inventory(InventoryError::InvalidTimestamp))
    ));
}
