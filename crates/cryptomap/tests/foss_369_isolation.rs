//! FOSS-369: fault-isolated collection, scope preflight and secret-safe diagnostics.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    CollectionRunId, CollectorId, Confidence, CoverageState, EvidenceKind, IdentityContext,
    InventoryError, InventoryLimits,
    collector::{
        self, COLLECTOR_CONTRACT_VERSION, CancellationToken, CollectionMode, CollectionOutcome,
        CollectionRequest, CollectionSink, CollectionStatus, Collector, CollectorCapabilities,
        CollectorDescriptor, CollectorDiagnostic, CollectorDiagnosticCode, RequestedSource,
    },
    coverage::CollectionScopeId,
    diagnostics::{CollectionSummary, DiagnosticSeverity, diagnostic_severity, retryable},
    orchestration::{ScopedInvocation, collect_normalized_isolated},
    pipeline::PipelineInput,
    raw::{
        RAW_CONTRACT_VERSION, RawFactKind, RawLimits, RawObservation, RawSourceKind,
        RawSourceLocator,
    },
    registry::Registry,
    scope::{CollectionScope, collect_scoped_isolated},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
};

#[derive(Clone, Copy)]
enum Mode {
    Observed,
    Clean,
    NoCoverage,
    Fail,
    FailAfterEmit,
    Partial,
    CancelPartial,
    Unsupported,
    UnsupportedSchema,
    ResourceLimit,
    InvalidEvent,
    InvalidCover,
    IgnoredInvalidEvent,
    IgnoredInvalidCover,
    IgnoredInvalidDiagnostic,
    FakeRun,
    SharedEvent,
    SecretError,
    Contradictory,
}

struct ProbeCollector {
    modes: BTreeMap<String, Mode>,
    calls: Mutex<Vec<String>>,
}
impl ProbeCollector {
    fn new(entries: &[(&str, Mode)]) -> Self {
        Self {
            modes: entries
                .iter()
                .map(|(item, mode)| ((*item).into(), *mode))
                .collect(),
            calls: Mutex::new(Vec::new()),
        }
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

fn descriptor() -> CollectorDescriptor {
    CollectorDescriptor {
        contract_version: COLLECTOR_CONTRACT_VERSION,
        id: CollectorId::new("foss-369-probe").unwrap(),
        version: "1.0".into(),
        capabilities: CollectorCapabilities {
            sources: BTreeSet::from([RawSourceKind::Telemetry]),
            mode: CollectionMode::Passive,
            required_permissions: BTreeSet::new(),
            checkpoint: false,
        },
    }
}

fn observation(request: &CollectionRequest, item: &str) -> RawObservation {
    RawObservation {
        contract_version: RAW_CONTRACT_VERSION,
        event_id: format!("event:{item}"),
        collector: descriptor().id,
        collector_version: "1.0".into(),
        run: request.run.clone(),
        source: RawSourceLocator {
            kind: RawSourceKind::Telemetry,
            item: item.into(),
            offset: None,
            line: Some(1),
            column: Some(1),
        },
        observed_at: "2026-10-13T14:00:00Z".into(),
        fact: RawFactKind::Certificate {
            fingerprint_sha256: "ab".repeat(32),
        },
        evidence_kind: EvidenceKind::Direct,
        confidence: Confidence::High,
        inference_rule: None,
        source_sha256: None,
        attributes: BTreeMap::new(),
    }
}

impl Collector for ProbeCollector {
    fn descriptor(&self) -> CollectorDescriptor {
        descriptor()
    }
    fn collect(
        &self,
        request: &CollectionRequest,
        sink: &mut CollectionSink,
        cancel: &CancellationToken,
    ) -> Result<(), InventoryError> {
        for source in &request.sources {
            let item = source.item.as_str();
            self.calls.lock().unwrap().push(item.to_string());
            match self.modes.get(item).copied().unwrap_or(Mode::Observed) {
                Mode::Observed => {
                    sink.emit(observation(request, item))?;
                    sink.cover(item, CoverageState::InspectedObserved)?;
                }
                Mode::Clean => sink.cover(item, CoverageState::InspectedNoObservation)?,
                Mode::NoCoverage => {}
                Mode::Fail => return Err(InventoryError::InvalidMetadata),
                Mode::FailAfterEmit => {
                    sink.emit(observation(request, item))?;
                    return Err(InventoryError::InvalidMetadata);
                }
                Mode::Partial => {
                    sink.emit(observation(request, item))?;
                    sink.cover(item, CoverageState::Partial)?;
                }
                Mode::CancelPartial => {
                    sink.emit(observation(request, item))?;
                    sink.cover(item, CoverageState::Partial)?;
                    cancel.cancel();
                }
                Mode::Unsupported => {
                    sink.cover(item, CoverageState::Unsupported)?;
                    sink.diagnose(CollectorDiagnostic {
                        code: CollectorDiagnosticCode::UnsupportedSource,
                        source_item: Some(item.into()),
                    })?;
                }
                Mode::UnsupportedSchema => return Err(InventoryError::UnsupportedSchema(999)),
                Mode::ResourceLimit => return Err(InventoryError::LimitExceeded("fixture limit")),
                Mode::InvalidEvent => {
                    let mut fact = observation(request, item);
                    fact.source.item = "not:granted".into();
                    sink.emit(fact)?;
                }
                Mode::InvalidCover => {
                    sink.cover("not:granted", CoverageState::InspectedNoObservation)?;
                }
                Mode::IgnoredInvalidEvent => {
                    let mut fact = observation(request, item);
                    fact.source.item = "not:granted".into();
                    let _ = sink.emit(fact);
                    sink.cover(item, CoverageState::InspectedNoObservation)?;
                }
                Mode::IgnoredInvalidCover => {
                    let _ = sink.cover("not:granted", CoverageState::InspectedNoObservation);
                    sink.cover(item, CoverageState::InspectedNoObservation)?;
                }
                Mode::IgnoredInvalidDiagnostic => {
                    let _ = sink.diagnose(CollectorDiagnostic {
                        code: CollectorDiagnosticCode::InvalidObservation,
                        source_item: Some("not:granted".into()),
                    });
                    sink.cover(item, CoverageState::InspectedNoObservation)?;
                }
                Mode::FakeRun => {
                    let mut fact = observation(request, item);
                    fact.run = CollectionRunId::new("foreign-run").unwrap();
                    sink.emit(fact)?;
                }
                Mode::SharedEvent => {
                    let mut fact = observation(request, item);
                    fact.event_id = "same:event".into();
                    sink.emit(fact)?;
                    sink.cover(item, CoverageState::InspectedObserved)?;
                }
                Mode::SecretError => {
                    return Err(InventoryError::DuplicateObservation(
                        "secret:must-not-leak".into(),
                    ));
                }
                Mode::Contradictory => {
                    sink.emit(observation(request, item))?;
                    sink.cover(item, CoverageState::InspectedNoObservation)?;
                }
            }
        }
        Ok(())
    }
}

struct Fixture {
    scope: CollectionScope,
    identity: IdentityContext,
    registry: Registry,
    run: CollectionRunId,
    sources: Vec<RequestedSource>,
}
impl Fixture {
    fn new(items: &[&str]) -> Self {
        let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-369").unwrap());
        for item in items {
            scope
                .grant_logical(RawSourceKind::Telemetry, *item)
                .unwrap();
        }
        Self {
            scope,
            identity: IdentityContext::new("tenant-369").unwrap(),
            registry: Registry::builtin(),
            run: CollectionRunId::new("test-run-369").unwrap(),
            sources: items
                .iter()
                .map(|item| RequestedSource {
                    kind: RawSourceKind::Telemetry,
                    item: (*item).into(),
                })
                .collect(),
        }
    }
    fn request(&self) -> CollectionRequest {
        CollectionRequest {
            run: self.run.clone(),
            sources: self.sources.clone(),
            limits: RawLimits::default(),
            options: BTreeMap::new(),
        }
    }
    fn isolated(
        &self,
        collector: &ProbeCollector,
        cancel: &CancellationToken,
    ) -> CollectionOutcome {
        collect_scoped_isolated(&self.scope, collector, self.request(), cancel).unwrap()
    }
    fn normalized(
        &self,
        collector: &ProbeCollector,
        cancel: &CancellationToken,
    ) -> Result<cryptomap::InventorySnapshot, cryptomap::pipeline::PipelineError> {
        let expected_descriptor = descriptor();
        collect_normalized_isolated(
            ScopedInvocation {
                collector,
                input: PipelineInput {
                    scope: &self.scope,
                    identity: &self.identity,
                    registry: &self.registry,
                    expected_descriptor: &expected_descriptor,
                    expected_run: &self.run,
                    sources: &self.sources,
                    raw_limits: RawLimits::default(),
                    inventory_limits: InventoryLimits::default(),
                    started_at: "2026-10-13T13:59:00Z",
                    ended_at: "2026-10-13T14:01:00Z",
                },
            },
            cancel,
        )
    }
}

#[test]
fn two_successes_survive_one_failed_source_with_exact_coverage() {
    let fixture = Fixture::new(&["c:ok", "b:failed", "a:ok"]);
    let collector = ProbeCollector::new(&[("b:failed", Mode::FailAfterEmit)]);
    let outcome = fixture.isolated(&collector, &CancellationToken::default());
    assert_eq!(outcome.status, CollectionStatus::Partial);
    assert_eq!(outcome.observations.len(), 2);
    assert_eq!(outcome.coverage["b:failed"], CoverageState::Failed);
    assert_eq!(outcome.coverage["a:ok"], CoverageState::InspectedObserved);
    assert_eq!(outcome.coverage["c:ok"], CoverageState::InspectedObserved);
    assert_eq!(outcome.diagnostics.len(), 1);
    assert_eq!(
        outcome.diagnostics[0].code,
        CollectorDiagnosticCode::InvalidObservation
    );
    assert_eq!(collector.calls(), vec!["a:ok", "b:failed", "c:ok"]);
    let summary = CollectionSummary::from_outcome(&outcome);
    assert_eq!(summary.requested, 3);
    assert_eq!(summary.attempted, 3);
    assert_eq!(summary.inspected_observed, 2);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.not_inspected, 0);
    assert_eq!(summary.observations, 2);
    assert_eq!(summary.diagnostics, 1);

    let snapshot = fixture
        .normalized(&collector, &CancellationToken::default())
        .unwrap();
    snapshot.verify(InventoryLimits::default()).unwrap();
    assert_eq!(snapshot.evidence.len(), 2);
    assert_eq!(snapshot.observations.len(), 2);
    assert_eq!(snapshot.coverage_records.len(), 3);
    assert_eq!(snapshot.coverage["b:failed"], CoverageState::Failed);
    assert_eq!(snapshot.coverage["a:ok"], CoverageState::InspectedObserved);
}

#[test]
fn request_order_permutations_preserve_output_and_json_counts() {
    let first = Fixture::new(&["c", "a", "b"]);
    let second = Fixture::new(&["a", "b", "c"]);
    let cases = [("a", Mode::Observed), ("b", Mode::Fail), ("c", Mode::Clean)];
    let a = first.isolated(&ProbeCollector::new(&cases), &CancellationToken::default());
    let b = second.isolated(&ProbeCollector::new(&cases), &CancellationToken::default());
    assert_eq!(a, b);
    assert_eq!(
        serde_json::to_string(&CollectionSummary::from_outcome(&a)).unwrap(),
        serde_json::to_string(&CollectionSummary::from_outcome(&b)).unwrap(),
    );
}

#[test]
fn authorization_failure_happens_before_any_collector_call() {
    let fixture = Fixture::new(&["granted"]);
    let collector = ProbeCollector::new(&[]);
    let mut request = fixture.request();
    request.sources.push(RequestedSource {
        kind: RawSourceKind::Telemetry,
        item: "not:granted".into(),
    });
    assert!(
        collect_scoped_isolated(
            &fixture.scope,
            &collector,
            request,
            &CancellationToken::default(),
        )
        .is_err()
    );
    assert!(collector.calls().is_empty());

    let mut invalid = Fixture::new(&["allowed"]);
    invalid.sources.push(RequestedSource {
        kind: RawSourceKind::Telemetry,
        item: "outside".into(),
    });
    assert!(
        invalid
            .normalized(&collector, &CancellationToken::default())
            .is_err()
    );
    assert!(collector.calls().is_empty());
}

#[test]
fn sink_rejection_is_fatal_even_when_plugin_ignores_its_error() {
    for mode in [
        Mode::InvalidEvent,
        Mode::InvalidCover,
        Mode::IgnoredInvalidEvent,
        Mode::IgnoredInvalidCover,
        Mode::IgnoredInvalidDiagnostic,
        Mode::FakeRun,
    ] {
        let fixture = Fixture::new(&["a", "b"]);
        let collector = ProbeCollector::new(&[("a", mode)]);
        let error = collector::collect_isolated(
            &collector,
            fixture.request(),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert_eq!(error, InventoryError::InvalidMetadata);
        assert_eq!(collector.calls(), vec!["a"]);
    }
}

#[test]
fn cross_source_duplicate_event_identity_aborts_whole_run() {
    let fixture = Fixture::new(&["a", "b"]);
    let collector = ProbeCollector::new(&[("a", Mode::SharedEvent), ("b", Mode::SharedEvent)]);
    assert_eq!(
        collector::collect_isolated(&collector, fixture.request(), &CancellationToken::default())
            .unwrap_err(),
        InventoryError::InvalidMetadata,
    );
}

#[test]
fn aggregate_budget_limit_cannot_be_reclassified_as_partial_success() {
    let fixture = Fixture::new(&["a", "b"]);
    let collector = ProbeCollector::new(&[]);
    let mut request = fixture.request();
    request.limits.observations = 1;
    assert!(matches!(
        collector::collect_isolated(&collector, request, &CancellationToken::default()),
        Err(InventoryError::LimitExceeded("raw observations"))
    ));
}

#[test]
fn cancellation_preserves_partial_evidence_and_marks_future_sources_uninspected() {
    let fixture = Fixture::new(&["c", "b", "a"]);
    let collector = ProbeCollector::new(&[("a", Mode::CancelPartial)]);
    let cancel = CancellationToken::default();
    let outcome = fixture.isolated(&collector, &cancel);
    assert!(cancel.is_cancelled());
    assert_eq!(collector.calls(), vec!["a"]);
    assert_eq!(outcome.observations.len(), 1);
    assert_eq!(outcome.coverage["a"], CoverageState::Partial);
    assert_eq!(outcome.coverage["b"], CoverageState::NotInspected);
    assert_eq!(outcome.coverage["c"], CoverageState::NotInspected);
    assert_eq!(outcome.status, CollectionStatus::Failed);
    let counts = CollectionSummary::from_outcome(&outcome);
    assert_eq!(counts.attempted, 1);
    assert_eq!(counts.partial, 1);
    assert_eq!(counts.not_inspected, 2);
    assert_eq!(counts.diagnostics, 2);
    let second_cancel = CancellationToken::default();
    let snapshot = fixture
        .normalized(
            &ProbeCollector::new(&[("a", Mode::CancelPartial)]),
            &second_cancel,
        )
        .unwrap();
    assert!(second_cancel.is_cancelled());
    assert_eq!(snapshot.evidence.len(), 1);
    assert_eq!(snapshot.coverage["a"], CoverageState::Partial);
    assert_eq!(snapshot.coverage["b"], CoverageState::NotInspected);
    assert_eq!(snapshot.coverage["c"], CoverageState::NotInspected);
    snapshot.verify(InventoryLimits::default()).unwrap();
}

#[test]
fn pre_cancelled_run_does_not_invoke_collector_or_assert_clean_coverage() {
    let fixture = Fixture::new(&["a", "b"]);
    let collector = ProbeCollector::new(&[]);
    let token = CancellationToken::default();
    token.cancel();
    let output = fixture.isolated(&collector, &token);
    assert!(collector.calls().is_empty());
    assert!(output.observations.is_empty());
    assert_eq!(output.status, CollectionStatus::Failed);
    assert!(
        output
            .coverage
            .values()
            .all(|state| *state == CoverageState::NotInspected)
    );
    assert_eq!(CollectionSummary::from_outcome(&output).attempted, 0);
    assert_eq!(output.diagnostics.len(), 2);
}

#[test]
fn strict_existing_api_still_fails_entire_run_on_collector_error() {
    let fixture = Fixture::new(&["a", "b"]);
    let collector = ProbeCollector::new(&[("b", Mode::Fail)]);
    assert_eq!(
        collector::collect(&collector, fixture.request(), &CancellationToken::default())
            .unwrap_err(),
        InventoryError::InvalidMetadata,
    );
}

#[test]
fn unsupported_and_resource_failures_are_typed_without_false_absence() {
    let fixture = Fixture::new(&["a:unsupported", "b:limit", "c:clean"]);
    let collector = ProbeCollector::new(&[
        ("a:unsupported", Mode::Unsupported),
        ("b:limit", Mode::ResourceLimit),
        ("c:clean", Mode::Clean),
    ]);
    let result = fixture.isolated(&collector, &CancellationToken::default());
    let summary = CollectionSummary::from_outcome(&result);
    assert_eq!(summary.requested, 3);
    assert_eq!(summary.attempted, 3);
    assert_eq!(summary.unsupported, 1);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.inspected_no_observation, 1);
    assert_eq!(result.status, CollectionStatus::Partial);
    assert_eq!(result.diagnostics.len(), 2);
    assert_eq!(
        result.diagnostics[0].code,
        CollectorDiagnosticCode::UnsupportedSource
    );
    assert_eq!(
        result.diagnostics[1].code,
        CollectorDiagnosticCode::ResourceLimit
    );
}

#[test]
fn contradictory_clean_assertion_becomes_partial_not_false_absence() {
    let fixture = Fixture::new(&["a"]);
    let collector = ProbeCollector::new(&[("a", Mode::Contradictory)]);
    let out = fixture.isolated(&collector, &CancellationToken::default());
    assert_eq!(out.coverage["a"], CoverageState::Partial);
    assert_eq!(out.observations.len(), 1);
    assert_eq!(
        out.diagnostics[0].code,
        CollectorDiagnosticCode::InvalidObservation
    );
}

#[test]
fn source_error_payloads_cannot_leak_through_summary_or_diagnostics() {
    let fixture = Fixture::new(&["a", "b"]);
    let collector = ProbeCollector::new(&[("a", Mode::SecretError)]);
    let out = fixture.isolated(&collector, &CancellationToken::default());
    let debug = format!("{out:?}");
    let json = serde_json::to_string(&out).unwrap();
    let summary = serde_json::to_string(&CollectionSummary::from_outcome(&out)).unwrap();
    for text in [&debug, &json, &summary] {
        assert!(!text.contains("secret:must-not-leak"));
    }
    assert_eq!(out.coverage["a"], CoverageState::Failed);
    assert_eq!(
        out.diagnostics[0].code,
        CollectorDiagnosticCode::InvalidObservation
    );
}

#[test]
fn diagnostic_classification_is_stable_and_never_a_risk_score() {
    assert_eq!(
        diagnostic_severity(CollectorDiagnosticCode::Timeout),
        DiagnosticSeverity::Error
    );
    assert_eq!(
        diagnostic_severity(CollectorDiagnosticCode::IncompleteScope),
        DiagnosticSeverity::Warning
    );
    assert!(retryable(CollectorDiagnosticCode::Timeout));
    assert!(retryable(CollectorDiagnosticCode::Cancelled));
    assert!(!retryable(CollectorDiagnosticCode::InvalidObservation));
}

#[test]
fn unsupported_schema_is_explicitly_unsupported_and_never_clean() {
    let fixture = Fixture::new(&["a:unsupported", "b:success"]);
    let collector = ProbeCollector::new(&[("a:unsupported", Mode::UnsupportedSchema)]);
    let outcome = fixture.isolated(&collector, &CancellationToken::default());
    assert_eq!(
        outcome.coverage["a:unsupported"],
        CoverageState::Unsupported
    );
    assert_eq!(
        outcome.coverage["b:success"],
        CoverageState::InspectedObserved
    );
    assert_eq!(outcome.status, CollectionStatus::Partial);
    assert_eq!(outcome.diagnostics.len(), 1);
    assert_eq!(
        outcome.diagnostics[0].code,
        CollectorDiagnosticCode::UnsupportedSource
    );
    let counts = CollectionSummary::from_outcome(&outcome);
    assert_eq!(counts.unsupported, 1);
    assert_eq!(counts.attempted, 2);
}

#[test]
fn successful_return_without_explicit_coverage_is_not_unattempted() {
    let fixture = Fixture::new(&["a"]);
    let collector = ProbeCollector::new(&[("a", Mode::NoCoverage)]);
    let outcome = fixture.isolated(&collector, &CancellationToken::default());
    assert_eq!(outcome.coverage["a"], CoverageState::Failed);
    assert_eq!(outcome.status, CollectionStatus::Failed);
    assert_eq!(outcome.diagnostics.len(), 1);
    assert_eq!(
        outcome.diagnostics[0].code,
        CollectorDiagnosticCode::IncompleteScope
    );
    let summary = CollectionSummary::from_outcome(&outcome);
    assert_eq!(summary.attempted, 1);
    assert_eq!(summary.not_inspected, 0);
    assert_eq!(summary.inspected_no_observation, 0);
}
