//! Public collector contract acceptance tests, without network or disk access.
// Static test preconditions are deliberately unwrapped in fixtures.
#![allow(clippy::unwrap_used)]
use cryptomap::{
    CollectionRunId, CollectorId, Confidence, CoverageState, EvidenceKind, InventoryError,
    collector::{
        self, COLLECTOR_CONTRACT_VERSION, CancellationToken, CollectionMode, CollectionRequest,
        CollectionSink, CollectionStatus, Collector, CollectorCapabilities, CollectorDescriptor,
        RequestedSource,
    },
    raw::{
        RAW_CONTRACT_VERSION, RawFactKind, RawLimits, RawObservation, RawSourceKind,
        RawSourceLocator,
    },
};
use std::collections::{BTreeMap, BTreeSet};

fn descriptor() -> CollectorDescriptor {
    CollectorDescriptor {
        contract_version: COLLECTOR_CONTRACT_VERSION,
        id: CollectorId::new("fixture-collector").unwrap(),
        version: "1.0".into(),
        capabilities: CollectorCapabilities {
            sources: BTreeSet::from([RawSourceKind::Dependency]),
            mode: CollectionMode::Passive,
            required_permissions: BTreeSet::new(),
            checkpoint: false,
        },
    }
}

fn request() -> CollectionRequest {
    CollectionRequest {
        run: CollectionRunId::new("fixture-run").unwrap(),
        sources: vec![
            RequestedSource {
                kind: RawSourceKind::Dependency,
                item: "Cargo.lock".into(),
            },
            RequestedSource {
                kind: RawSourceKind::Dependency,
                item: "package-lock.json".into(),
            },
        ],
        limits: RawLimits::default(),
        options: BTreeMap::new(),
    }
}

fn observation(source: &str) -> RawObservation {
    RawObservation {
        contract_version: RAW_CONTRACT_VERSION,
        event_id: "source-1".into(),
        collector: descriptor().id,
        collector_version: "1.0".into(),
        run: request().run,
        source: RawSourceLocator {
            kind: RawSourceKind::Dependency,
            item: source.into(),
            offset: None,
            line: Some(1),
            column: Some(1),
        },
        observed_at: "2026-10-10T10:00:00Z".into(),
        fact: RawFactKind::Dependency {
            ecosystem: "cargo".into(),
            name: "openssl".into(),
            version: "0.10".into(),
        },
        evidence_kind: EvidenceKind::Direct,
        confidence: Confidence::High,
        inference_rule: None,
        source_sha256: None,
        attributes: BTreeMap::new(),
    }
}

struct MockCollector;
impl Collector for MockCollector {
    fn descriptor(&self) -> CollectorDescriptor {
        descriptor()
    }
    fn collect(
        &self,
        _: &CollectionRequest,
        sink: &mut CollectionSink,
        _: &CancellationToken,
    ) -> Result<(), InventoryError> {
        sink.emit(observation("Cargo.lock"))?;
        sink.emit(observation("Cargo.lock"))?;
        sink.cover("Cargo.lock", CoverageState::InspectedObserved)?;
        Ok(())
    }
}

#[test]
fn mock_collector_replays_identically_and_preserves_missing_source_coverage() {
    let output =
        collector::collect(&MockCollector, request(), &CancellationToken::default()).unwrap();
    assert_eq!(output.observations.len(), 1);
    assert_eq!(output.status, CollectionStatus::Partial);
    assert_eq!(
        output.coverage["package-lock.json"],
        CoverageState::NotInspected
    );
    let json = serde_json::to_string(&output).unwrap();
    let rebuilt: collector::CollectionOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(rebuilt, output);
}

#[test]
fn unauthorized_or_incompatible_source_is_rejected() {
    let mut sink = CollectionSink::new(descriptor(), request()).unwrap();
    assert!(sink.emit(observation("other.toml")).is_err());
    assert!(
        sink.cover("not-requested", CoverageState::InspectedObserved)
            .is_err()
    );
    let mut wrong = observation("Cargo.lock");
    wrong.collector_version = "different".into();
    assert!(sink.emit(wrong).is_err());
    let mut bad_request = request();
    bad_request.sources[0].kind = RawSourceKind::Certificate;
    assert!(CollectionSink::new(descriptor(), bad_request).is_err());
}

#[test]
fn cross_kind_same_item_cannot_create_ambiguous_coverage() {
    let mut desc = descriptor();
    desc.capabilities.sources.insert(RawSourceKind::Certificate);
    let mut req = request();
    req.sources.push(RequestedSource {
        kind: RawSourceKind::Certificate,
        item: "Cargo.lock".into(),
    });
    assert!(CollectionSink::new(desc, req).is_err());
}

#[test]
fn conflicting_event_identity_is_refused() {
    let mut sink = CollectionSink::new(descriptor(), request()).unwrap();
    sink.emit(observation("Cargo.lock")).unwrap();
    let mut conflicting = observation("Cargo.lock");
    conflicting.fact = RawFactKind::Dependency {
        ecosystem: "cargo".into(),
        name: "openssl".into(),
        version: "999".into(),
    };
    assert!(matches!(
        sink.emit(conflicting),
        Err(InventoryError::DuplicateObservation(_))
    ));
}

#[test]
fn bounded_fields_and_secret_material_fail() {
    let mut oversized = observation("Cargo.lock");
    oversized.fact = RawFactKind::Configuration {
        property: "config:setting".into(),
        value: "X".repeat(16_385),
    };
    assert!(oversized.validate(&RawLimits::default()).is_err());
    let mut secret = observation("Cargo.lock");
    secret
        .attributes
        .insert("source:raw".into(), "-----BEGIN PRIVATE KEY-----".into());
    assert!(matches!(
        secret.validate(&RawLimits::default()),
        Err(InventoryError::ProhibitedMaterial)
    ));
    let mut inferred = observation("Cargo.lock");
    inferred.evidence_kind = EvidenceKind::Inferred;
    assert!(inferred.validate(&RawLimits::default()).is_err());
    let mut unsupported = observation("Cargo.lock");
    unsupported.contract_version = 9;
    assert!(matches!(
        unsupported.validate(&RawLimits::default()),
        Err(InventoryError::UnsupportedSchema(9))
    ));
}

#[test]
fn limits_are_rollback_safe() {
    let mut constrained = request();
    constrained.limits.observations = 2;
    constrained.limits.total_bytes = 100;
    constrained.limits.record_bytes = 100;
    constrained.limits.field_bytes = 50;
    let mut sink = CollectionSink::new(descriptor(), constrained).unwrap();
    assert!(sink.emit(observation("Cargo.lock")).is_err());
    let result = sink.finish();
    assert!(result.observations.is_empty());
}

#[test]
fn cancellation_short_circuits_before_collector_runs() {
    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let output = collector::collect(&MockCollector, request(), &cancelled).unwrap();
    assert!(output.observations.is_empty());
    assert_eq!(output.diagnostics.len(), 2);
    assert_eq!(output.status, CollectionStatus::Failed);
}

#[test]
fn serialize_rejects_undeclared_fields_and_invalid_source_positions() {
    let value = serde_json::to_value(observation("Cargo.lock")).unwrap();
    let mut mutated = value.clone();
    mutated
        .as_object_mut()
        .unwrap()
        .insert("unexpected".into(), serde_json::json!("ignored"));
    assert!(serde_json::from_value::<RawObservation>(mutated).is_err());
    let mut invalid = observation("Cargo.lock");
    invalid.source.line = Some(0);
    assert!(invalid.validate(&RawLimits::default()).is_err());
}
