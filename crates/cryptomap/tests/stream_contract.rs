//! FOSS-320.5 bounded streaming acceptance and adversarial regression tests.
//! All sources are in-memory logical streams: these tests perform no I/O.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    CollectionRunId, CollectorId, Confidence, CoverageState, EvidenceKind, IdentityContext,
    InventoryError, InventoryLimits,
    collector::{
        COLLECTOR_CONTRACT_VERSION, CancellationToken, CollectionMode, CollectionRequest,
        CollectionStatus, CollectorCapabilities, CollectorDescriptor, RequestedSource,
    },
    coverage::CollectionScopeId,
    pipeline::{PipelineInput, normalize},
    raw::{RawFactKind, RawLimits, RawObservation, RawSourceKind, RawSourceLocator},
    registry::Registry,
    scope::{CollectionScope, ScopeError},
    stream::{StreamError, StreamIntake, WindowLimits},
};
use std::collections::{BTreeMap, BTreeSet};

struct Fixture {
    scope: CollectionScope,
    desc: CollectorDescriptor,
    request: CollectionRequest,
    cancellation: CancellationToken,
}
impl Fixture {
    fn new() -> Self {
        let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-stream").unwrap());
        for item in ["logical:a", "logical:b"] {
            scope.grant_logical(RawSourceKind::Telemetry, item).unwrap();
        }
        let desc = CollectorDescriptor {
            contract_version: COLLECTOR_CONTRACT_VERSION,
            id: CollectorId::new("streaming-fixture").unwrap(),
            version: "1.0".into(),
            capabilities: CollectorCapabilities {
                sources: BTreeSet::from([RawSourceKind::Telemetry]),
                mode: CollectionMode::Passive,
                required_permissions: BTreeSet::new(),
                checkpoint: false,
            },
        };
        let request = CollectionRequest {
            run: CollectionRunId::new("stream-run").unwrap(),
            sources: vec![
                RequestedSource {
                    kind: RawSourceKind::Telemetry,
                    item: "logical:a".into(),
                },
                RequestedSource {
                    kind: RawSourceKind::Telemetry,
                    item: "logical:b".into(),
                },
            ],
            limits: RawLimits::default(),
            options: BTreeMap::new(),
        };
        Self {
            scope,
            desc,
            request,
            cancellation: CancellationToken::default(),
        }
    }
    fn intake(&self, limits: WindowLimits) -> Result<StreamIntake, StreamError> {
        StreamIntake::new(
            &self.scope,
            self.desc.clone(),
            self.request.clone(),
            self.cancellation.clone(),
            limits,
        )
    }
    fn observation(&self, id: &str, source: &str) -> RawObservation {
        RawObservation {
            contract_version: 1,
            event_id: id.into(),
            collector: self.desc.id.clone(),
            collector_version: self.desc.version.clone(),
            run: self.request.run.clone(),
            source: RawSourceLocator {
                kind: RawSourceKind::Telemetry,
                item: source.into(),
                offset: None,
                line: None,
                column: None,
            },
            observed_at: "2026-10-11T12:00:00Z".into(),
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
    fn window() -> WindowLimits {
        WindowLimits {
            records: 2,
            bytes: 8192,
        }
    }
    fn normalize(
        &self,
        outcome: cryptomap::collector::CollectionOutcome,
    ) -> cryptomap::InventorySnapshot {
        let identity = IdentityContext::new(self.scope.id().as_str()).unwrap();
        normalize(
            PipelineInput {
                scope: &self.scope,
                identity: &identity,
                registry: &Registry::builtin(),
                expected_descriptor: &self.desc,
                expected_run: &self.request.run,
                sources: &self.request.sources,
                raw_limits: self.request.limits,
                inventory_limits: InventoryLimits::default(),
                started_at: "2026-10-11T11:59:00Z",
                ended_at: "2026-10-11T12:01:00Z",
            },
            outcome,
        )
        .unwrap()
    }
}
#[test]
fn backpressure_has_no_side_effects_and_rejected_borrowed_record_can_be_retried() {
    let f = Fixture::new();
    let mut intake = f
        .intake(WindowLimits {
            records: 1,
            bytes: 8192,
        })
        .unwrap();
    let a = f.observation("one", "logical:a");
    let b = f.observation("two", "logical:a");
    intake.try_push(&a).unwrap();
    assert_eq!(intake.pending_records(), 1);
    let before = intake.pending_bytes();
    assert!(matches!(
        intake.try_push(&b),
        Err(StreamError::Backpressure)
    ));
    assert_eq!(intake.pending_records(), 1);
    assert_eq!(intake.pending_bytes(), before);
    assert_eq!(intake.drain().unwrap(), 1);
    intake.try_push(&b).unwrap();
    assert_eq!(intake.drain().unwrap(), 1);
    intake
        .cover("logical:a", CoverageState::InspectedObserved)
        .unwrap();
    let outcome = intake.finish().unwrap();
    assert_eq!(outcome.observations.len(), 2);
    assert_eq!(outcome.coverage["logical:b"], CoverageState::NotInspected);
    assert_eq!(outcome.status, CollectionStatus::Partial);
    assert!(outcome.diagnostics.is_empty());
}
#[test]
fn byte_backpressure_and_too_large_record_fail_without_admission() {
    let f = Fixture::new();
    let one = f.observation("one", "logical:a");
    let two = f.observation("two", "logical:a");
    let bytes = one.validate(&f.request.limits).unwrap();
    let mut intake = f.intake(WindowLimits { records: 2, bytes }).unwrap();
    intake.try_push(&one).unwrap();
    assert!(matches!(
        intake.try_push(&two),
        Err(StreamError::Backpressure)
    ));
    assert_eq!(intake.pending_bytes(), bytes);
    intake.drain().unwrap();
    intake.try_push(&two).unwrap();
    assert_eq!(intake.pending_records(), 1);
    let mut small = f
        .intake(WindowLimits {
            records: 2,
            bytes: bytes - 1,
        })
        .unwrap();
    assert!(matches!(
        small.try_push(&one),
        Err(StreamError::Inventory(InventoryError::LimitExceeded(_)))
    ));
    assert_eq!(small.pending_records(), 0);
}
#[test]
fn duplicate_replay_is_idempotent_both_within_and_across_windows() {
    let f = Fixture::new();
    let mut intake = f.intake(Fixture::window()).unwrap();
    let one = f.observation("repeat", "logical:a");
    intake.try_push(&one).unwrap();
    intake.try_push(&one).unwrap();
    assert_eq!(intake.pending_records(), 1);
    intake.drain().unwrap();
    intake.try_push(&one).unwrap();
    intake.drain().unwrap();
    intake
        .cover("logical:a", CoverageState::InspectedObserved)
        .unwrap();
    let result = intake.finish().unwrap();
    assert_eq!(result.observations.len(), 1);
    assert!(result.diagnostics.is_empty());
}
#[test]
fn conflicting_pending_replay_poisoned_and_cannot_be_finalized() {
    let f = Fixture::new();
    let first = f.observation("private:event:conflict", "logical:a");
    let mut conflicting = first.clone();
    conflicting.fact = RawFactKind::Certificate {
        fingerprint_sha256: "cd".repeat(32),
    };
    let mut intake = f.intake(Fixture::window()).unwrap();
    intake.try_push(&first).unwrap();
    let err = intake.try_push(&conflicting).unwrap_err();
    assert!(matches!(err, StreamError::ReplayConflict));
    assert!(!format!("{err:?}").contains("private:event:conflict"));
    assert!(matches!(intake.drain(), Err(StreamError::Poisoned)));
    assert!(matches!(intake.finish(), Err(StreamError::Poisoned)));
}

#[test]
fn conflicting_replay_across_drained_windows_poisoned_and_redacted() {
    let f = Fixture::new();
    let first = f.observation("private:event:conflict", "logical:a");
    let mut conflicting = first.clone();
    conflicting.fact = RawFactKind::Certificate {
        fingerprint_sha256: "cd".repeat(32),
    };
    let mut intake = f.intake(Fixture::window()).unwrap();
    intake.try_push(&first).unwrap();
    intake.drain().unwrap();
    intake.try_push(&conflicting).unwrap();
    let err = intake.drain().unwrap_err();
    assert!(matches!(err, StreamError::ReplayConflict));
    assert!(!format!("{err:?}").contains("private:event:conflict"));
    assert!(matches!(intake.finish(), Err(StreamError::Poisoned)));
}
#[test]
fn cancellation_before_intake_accepts_no_records_or_false_absence() {
    let f = Fixture::new();
    f.cancellation.cancel();
    let mut intake = f.intake(Fixture::window()).unwrap();
    assert!(matches!(
        intake.try_push(&f.observation("a", "logical:a")),
        Err(StreamError::Cancelled)
    ));
    assert!(matches!(
        intake.cover("logical:a", CoverageState::InspectedNoObservation),
        Err(StreamError::Cancelled)
    ));
    let outcome = intake.finish().unwrap();
    assert_eq!(outcome.status, CollectionStatus::Failed);
    assert!(outcome.observations.is_empty());
    assert_eq!(outcome.diagnostics.len(), 2);
    assert!(
        outcome
            .coverage
            .values()
            .all(|s| *s == CoverageState::NotInspected)
    );
    let snap = f.normalize(outcome);
    assert!(snap.assets.is_empty());
    snap.verify(InventoryLimits::default()).unwrap();
}
#[test]
fn cancellation_after_admission_preserves_buffered_evidence_and_partial_coverage() {
    let f = Fixture::new();
    let mut intake = f.intake(Fixture::window()).unwrap();
    intake
        .try_push(&f.observation("buffered", "logical:a"))
        .unwrap();
    f.cancellation.cancel();
    assert!(matches!(
        intake.try_push(&f.observation("late", "logical:a")),
        Err(StreamError::Cancelled)
    ));
    assert!(matches!(
        intake.cover("logical:a", CoverageState::InspectedObserved),
        Err(StreamError::Cancelled)
    ));
    let outcome = intake.finish().unwrap();
    assert_eq!(outcome.observations.len(), 1);
    assert_eq!(outcome.coverage["logical:a"], CoverageState::Partial);
    assert_eq!(outcome.coverage["logical:b"], CoverageState::NotInspected);
    assert_eq!(outcome.status, CollectionStatus::Failed);
    assert_eq!(outcome.diagnostics.len(), 2);
    let snap = f.normalize(outcome);
    assert_eq!(snap.evidence.len(), 1);
    assert_eq!(snap.assets.len(), 1);
    assert_eq!(snap.coverage["logical:a"], CoverageState::Partial);
    snap.verify(InventoryLimits::default()).unwrap();
}
#[test]
fn cancellation_after_one_completed_source_keeps_that_source_complete() {
    let f = Fixture::new();
    let mut intake = f.intake(Fixture::window()).unwrap();
    intake
        .try_push(&f.observation("done", "logical:a"))
        .unwrap();
    intake
        .cover("logical:a", CoverageState::InspectedObserved)
        .unwrap();
    intake
        .try_push(&f.observation("partial", "logical:b"))
        .unwrap();
    f.cancellation.cancel();
    let outcome = intake.finish().unwrap();
    assert_eq!(outcome.status, CollectionStatus::Partial);
    assert_eq!(
        outcome.coverage["logical:a"],
        CoverageState::InspectedObserved
    );
    assert_eq!(outcome.coverage["logical:b"], CoverageState::Partial);
    assert_eq!(outcome.diagnostics.len(), 1);
    assert_eq!(outcome.observations.len(), 2);
    let snap = f.normalize(outcome);
    assert_eq!(snap.evidence.len(), 2);
}
#[test]
fn chunk_permutation_produces_identical_canonical_snapshot() {
    let f = Fixture::new();
    let records = [
        f.observation("a", "logical:a"),
        f.observation("b", "logical:b"),
        f.observation("c", "logical:a"),
    ];
    let mut small = f
        .intake(WindowLimits {
            records: 1,
            bytes: 8192,
        })
        .unwrap();
    for record in &records {
        small.try_push(record).unwrap();
        small.drain().unwrap();
    }
    small
        .cover("logical:a", CoverageState::InspectedObserved)
        .unwrap();
    small
        .cover("logical:b", CoverageState::InspectedObserved)
        .unwrap();
    let a = f.normalize(small.finish().unwrap());

    let mut large = f
        .intake(WindowLimits {
            records: 3,
            bytes: 8192,
        })
        .unwrap();
    for record in records.iter().rev() {
        large.try_push(record).unwrap();
    }
    large
        .cover("logical:b", CoverageState::InspectedObserved)
        .unwrap();
    large
        .cover("logical:a", CoverageState::InspectedObserved)
        .unwrap();
    let b = f.normalize(large.finish().unwrap());
    assert_eq!(a.id, b.id);
    assert_eq!(a, b);
}
#[test]
fn source_run_collector_and_secret_substitution_fail_before_admission() {
    let f = Fixture::new();
    let mut intake = f.intake(Fixture::window()).unwrap();
    let mut wrong = f.observation("x", "not-granted");
    assert!(matches!(
        intake.try_push(&wrong),
        Err(StreamError::Inventory(InventoryError::InvalidMetadata))
    ));
    wrong.source.item = "logical:a".into();
    wrong.run = CollectionRunId::new("forged-run").unwrap();
    assert!(matches!(
        intake.try_push(&wrong),
        Err(StreamError::Inventory(InventoryError::InvalidMetadata))
    ));
    wrong.run = f.request.run.clone();
    wrong.collector = CollectorId::new("rogue").unwrap();
    assert!(matches!(
        intake.try_push(&wrong),
        Err(StreamError::Inventory(InventoryError::InvalidMetadata))
    ));
    let mut secret = f.observation("secret", "logical:a");
    secret
        .attributes
        .insert("source:raw".into(), "-----BEGIN PRIVATE KEY-----".into());
    assert!(matches!(
        intake.try_push(&secret),
        Err(StreamError::Inventory(InventoryError::ProhibitedMaterial))
    ));
    assert_eq!(intake.pending_records(), 0);
}
#[test]
fn nonexistent_authority_and_invalid_window_budget_are_rejected() {
    let mut f = Fixture::new();
    f.request.sources.push(RequestedSource {
        kind: RawSourceKind::Telemetry,
        item: "not-granted".into(),
    });
    assert!(matches!(
        f.intake(Fixture::window()),
        Err(StreamError::Scope(ScopeError::OutOfScope))
    ));
    f.request.sources.pop();
    assert!(matches!(
        f.intake(WindowLimits {
            records: 0,
            bytes: 8192
        }),
        Err(StreamError::Inventory(InventoryError::InvalidMetadata))
    ));
    assert!(matches!(
        f.intake(WindowLimits {
            records: f.request.limits.observations + 1,
            bytes: 8192,
        }),
        Err(StreamError::Inventory(InventoryError::InvalidMetadata))
    ));
}
#[test]
fn completed_source_cannot_receive_new_records_or_duplicate_coverage() {
    let f = Fixture::new();
    let mut intake = f.intake(Fixture::window()).unwrap();
    intake
        .cover("logical:a", CoverageState::InspectedNoObservation)
        .unwrap();
    assert!(matches!(
        intake.try_push(&f.observation("late", "logical:a")),
        Err(StreamError::Inventory(InventoryError::InvalidMetadata))
    ));
    assert!(matches!(
        intake.cover("logical:a", CoverageState::InspectedObserved),
        Err(StreamError::Inventory(InventoryError::InvalidMetadata))
    ));
}

#[test]
fn cumulative_record_quota_cannot_be_evaded_by_draining_windows() {
    let mut f = Fixture::new();
    f.request.limits.observations = 1;
    let mut intake = f
        .intake(WindowLimits {
            records: 1,
            bytes: 8192,
        })
        .unwrap();
    intake
        .try_push(&f.observation("first", "logical:a"))
        .unwrap();
    assert_eq!(intake.drain().unwrap(), 1);
    intake
        .try_push(&f.observation("second", "logical:a"))
        .unwrap();
    assert!(matches!(
        intake.drain(),
        Err(StreamError::Inventory(InventoryError::LimitExceeded(_)))
    ));
    assert!(matches!(intake.finish(), Err(StreamError::Poisoned)));
}

#[test]
fn cumulative_byte_quota_cannot_be_evaded_by_draining_windows() {
    let mut f = Fixture::new();
    let first = f.observation("first", "logical:a");
    let record_bytes = first.validate(&f.request.limits).unwrap();
    f.request.limits.total_bytes = record_bytes + 1;
    f.request.limits.record_bytes = record_bytes + 1;
    f.request.limits.field_bytes = 128;
    let mut intake = f
        .intake(WindowLimits {
            records: 1,
            bytes: record_bytes + 1,
        })
        .unwrap();
    intake.try_push(&first).unwrap();
    intake.drain().unwrap();
    intake
        .try_push(&f.observation("other", "logical:a"))
        .unwrap();
    assert!(matches!(
        intake.drain(),
        Err(StreamError::Inventory(InventoryError::LimitExceeded(_)))
    ));
    assert!(matches!(intake.finish(), Err(StreamError::Poisoned)));
}
