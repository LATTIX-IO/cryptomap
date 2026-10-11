//! FOSS-320: a bounded, explicitly scoped raw-to-canonical vertical slice.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    CollectionRunId, CollectorId, Confidence, CoverageState, EvidenceKind, IdentityContext,
    InventoryError, InventoryLimits,
    collector::{
        COLLECTOR_CONTRACT_VERSION, CollectionMode, CollectionOutcome, CollectionStatus,
        CollectorCapabilities, CollectorDescriptor, RequestedSource,
    },
    coverage::CollectionScopeId,
    pipeline::{PipelineError, PipelineInput, normalize},
    raw::{RawFactKind, RawLimits, RawObservation, RawSourceKind, RawSourceLocator},
    registry::Registry,
    scope::CollectionScope,
};
use std::collections::{BTreeMap, BTreeSet};

fn descriptor() -> CollectorDescriptor {
    CollectorDescriptor {
        contract_version: COLLECTOR_CONTRACT_VERSION,
        id: CollectorId::new("fixture-collector").unwrap(),
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
        item: "stream:test".into(),
    }
}
fn raw(event: &str, name: &str) -> RawObservation {
    RawObservation {
        contract_version: 1,
        event_id: event.into(),
        collector: CollectorId::new("fixture-collector").unwrap(),
        collector_version: "1.0".into(),
        run: CollectionRunId::new("run-a").unwrap(),
        source: RawSourceLocator {
            kind: RawSourceKind::Telemetry,
            item: "stream:test".into(),
            offset: None,
            line: None,
            column: None,
        },
        observed_at: "2026-10-11T12:00:00Z".into(),
        fact: RawFactKind::AlgorithmUse {
            identifier: name.into(),
            profile: None,
            operation: Some("encrypt".into()),
        },
        evidence_kind: EvidenceKind::Direct,
        confidence: Confidence::Confirmed,
        inference_rule: None,
        source_sha256: None,
        attributes: BTreeMap::from([
            (
                "cryptomap:algorithm-namespace".into(),
                "tls_cipher_suite".into(),
            ),
            ("cryptomap:algorithm-kind".into(), "cipher_suite".into()),
        ]),
    }
}
fn outcome(records: Vec<RawObservation>) -> CollectionOutcome {
    CollectionOutcome {
        descriptor: descriptor(),
        run: CollectionRunId::new("run-a").unwrap(),
        observations: records,
        coverage: BTreeMap::from([("stream:test".into(), CoverageState::InspectedObserved)]),
        diagnostics: Vec::new(),
        status: CollectionStatus::Complete,
    }
}
fn normalize_fixture(
    scope: &CollectionScope,
    identity: &IdentityContext,
    registry: &Registry,
    data: CollectionOutcome,
) -> Result<cryptomap::InventorySnapshot, PipelineError> {
    let expected_descriptor = descriptor();
    let expected_run = CollectionRunId::new("run-a").unwrap();
    normalize(
        PipelineInput {
            scope,
            identity,
            registry,
            expected_descriptor: &expected_descriptor,
            expected_run: &expected_run,
            sources: &[source()],
            raw_limits: RawLimits::default(),
            inventory_limits: InventoryLimits::default(),
            started_at: "2026-10-11T11:59:00Z",
            ended_at: "2026-10-11T12:01:00Z",
        },
        data,
    )
}
fn setup() -> (CollectionScope, IdentityContext, Registry) {
    let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-1").unwrap());
    scope
        .grant_logical(RawSourceKind::Telemetry, "stream:test")
        .unwrap();
    (
        scope,
        IdentityContext::new("tenant-1").unwrap(),
        Registry::builtin(),
    )
}

#[test]
fn checked_algorithm_result_creates_canonical_evidence_and_coverage() {
    let (scope, identity, registry) = setup();
    let snapshot = normalize_fixture(
        &scope,
        &identity,
        &registry,
        outcome(vec![raw("event-1", "0x1301")]),
    )
    .unwrap();
    assert_eq!(snapshot.assets.len(), 1);
    assert_eq!(snapshot.evidence.len(), 1);
    assert!(
        snapshot
            .observations
            .values()
            .any(|o| o.property == "algorithm:normalized" && o.value == "TLS_AES_128_GCM_SHA256")
    );
    assert!(
        snapshot
            .observations
            .values()
            .any(|o| o.property == "algorithm:raw-identifier" && o.value == "0x1301")
    );
    assert_eq!(
        snapshot.coverage.get("stream:test"),
        Some(&CoverageState::InspectedObserved)
    );
    snapshot.verify(InventoryLimits::default()).unwrap();
}

#[test]
fn reversed_raw_record_order_produces_identical_snapshot_digest() {
    let (scope, identity, registry) = setup();
    let first = raw("event-1", "0x1301");
    let second = raw("event-2", "0x1302");
    let a = normalize_fixture(
        &scope,
        &identity,
        &registry,
        outcome(vec![first.clone(), second.clone()]),
    )
    .unwrap();
    let b = normalize_fixture(&scope, &identity, &registry, outcome(vec![second, first])).unwrap();
    assert_eq!(a.id, b.id);
    assert_eq!(a, b);
}

#[test]
fn unknown_identifier_is_not_coerced_to_a_known_profile() {
    let (scope, identity, registry) = setup();
    let snap = normalize_fixture(
        &scope,
        &identity,
        &registry,
        outcome(vec![raw("x", "0xFFFF")]),
    )
    .unwrap();
    assert!(
        snap.observations
            .values()
            .any(|o| o.property == "algorithm:normalized" && o.value.contains("unmapped:"))
    );
    assert!(
        !snap
            .observations
            .values()
            .any(|o| o.value == "TLS_AES_128_GCM_SHA256")
    );
}

#[test]
fn unauthorized_source_and_inconsistent_coverage_fail_closed() {
    let (scope, identity, registry) = setup();
    let mut wrong_source = outcome(vec![raw("event-1", "0x1301")]);
    wrong_source.observations[0].source.item = "stream:other".into();
    assert!(matches!(
        normalize_fixture(&scope, &identity, &registry, wrong_source),
        Err(PipelineError::InvalidOutcome)
    ));
    let mut inconsistent = outcome(vec![raw("event-1", "0x1301")]);
    inconsistent
        .coverage
        .insert("stream:test".into(), CoverageState::InspectedNoObservation);
    assert!(matches!(
        normalize_fixture(&scope, &identity, &registry, inconsistent),
        Err(PipelineError::InvalidOutcome)
    ));
}

#[test]
fn conflicting_replay_and_unsupported_facts_are_not_silently_ignored() {
    let (scope, identity, registry) = setup();
    let conflicting = outcome(vec![raw("duplicate", "0x1301"), raw("duplicate", "0x1302")]);
    assert!(matches!(
        normalize_fixture(&scope, &identity, &registry, conflicting),
        Err(PipelineError::Inventory(
            InventoryError::DuplicateObservation(_)
        ))
    ));
    let mut unsupported = raw("event-config", "0x1301");
    unsupported.fact = RawFactKind::Configuration {
        property: "test:key".into(),
        value: "nonsecret".into(),
    };
    assert!(matches!(
        normalize_fixture(&scope, &identity, &registry, outcome(vec![unsupported])),
        Err(PipelineError::UnsupportedFact)
    ));
}

#[test]
fn identity_context_cannot_cross_an_authorized_scope() {
    let (scope, _, registry) = setup();
    let foreign = IdentityContext::new("different-tenant").unwrap();
    assert!(matches!(
        normalize_fixture(
            &scope,
            &foreign,
            &registry,
            outcome(vec![raw("one", "0x1301")])
        ),
        Err(PipelineError::InvalidOutcome)
    ));
}

#[test]
fn partial_collection_keeps_unrelated_successful_evidence() {
    let (mut scope, identity, registry) = setup();
    scope
        .grant_logical(RawSourceKind::Certificate, "store:denied")
        .unwrap();
    let mut data = outcome(vec![raw("event-1", "0x1301")]);
    data.descriptor
        .capabilities
        .sources
        .insert(RawSourceKind::Certificate);
    data.coverage
        .insert("store:denied".into(), CoverageState::Failed);
    data.status = CollectionStatus::Partial;
    let sources = vec![
        source(),
        RequestedSource {
            kind: RawSourceKind::Certificate,
            item: "store:denied".into(),
        },
    ];
    let expected_descriptor = data.descriptor.clone();
    let expected_run = CollectionRunId::new("run-a").unwrap();
    let snapshot = normalize(
        PipelineInput {
            scope: &scope,
            identity: &identity,
            registry: &registry,
            expected_descriptor: &expected_descriptor,
            expected_run: &expected_run,
            sources: &sources,
            raw_limits: RawLimits::default(),
            inventory_limits: InventoryLimits::default(),
            started_at: "2026-10-11T11:59:00Z",
            ended_at: "2026-10-11T12:01:00Z",
        },
        data,
    )
    .unwrap();
    assert_eq!(snapshot.assets.len(), 1);
    assert_eq!(snapshot.evidence.len(), 1);
    assert_eq!(
        snapshot.coverage.get("store:denied"),
        Some(&CoverageState::Failed)
    );
    assert_eq!(
        snapshot.runs.values().next().unwrap().completeness,
        cryptomap::coverage::RunCompleteness::Partial
    );
}

#[test]
fn dependency_presence_does_not_infer_algorithm_execution() {
    use cryptomap::AssetKind;
    use std::fs;
    let temp = std::env::temp_dir().join(format!(
        "cryptomap-pipeline-dependency-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp).unwrap();
    fs::write(temp.join("Cargo.lock"), b"fixture").unwrap();
    let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-1").unwrap());
    scope
        .grant_file(
            RawSourceKind::Dependency,
            "lockfile-1",
            &temp,
            "Cargo.lock",
            1024,
        )
        .unwrap();
    let mut data = outcome(vec![raw("dependency-1", "0x1301")]);
    data.descriptor.capabilities.sources = BTreeSet::from([RawSourceKind::Dependency]);
    data.observations[0].source.kind = RawSourceKind::Dependency;
    data.observations[0].source.item = "lockfile-1".into();
    data.observations[0].attributes.clear();
    data.observations[0].fact = RawFactKind::Dependency {
        ecosystem: "cargo".into(),
        name: "ring".into(),
        version: "0.17.0".into(),
    };
    data.coverage = BTreeMap::from([("lockfile-1".into(), CoverageState::InspectedObserved)]);
    let sources = [RequestedSource {
        kind: RawSourceKind::Dependency,
        item: "lockfile-1".into(),
    }];
    let identity = IdentityContext::new("tenant-1").unwrap();
    let registry = Registry::builtin();
    let expected_descriptor = data.descriptor.clone();
    let expected_run = CollectionRunId::new("run-a").unwrap();
    let snapshot = normalize(
        PipelineInput {
            scope: &scope,
            identity: &identity,
            registry: &registry,
            expected_descriptor: &expected_descriptor,
            expected_run: &expected_run,
            sources: &sources,
            raw_limits: RawLimits::default(),
            inventory_limits: InventoryLimits::default(),
            started_at: "2026-10-11T11:59:00Z",
            ended_at: "2026-10-11T12:01:00Z",
        },
        data,
    )
    .unwrap();
    assert!(
        snapshot
            .assets
            .values()
            .all(|asset| matches!(asset.kind, AssetKind::Library { .. }))
    );
    assert!(
        snapshot
            .observations
            .values()
            .all(|obs| obs.property == "dependency:presence" && obs.value == "declared")
    );
    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn forged_run_and_collector_provenance_are_rejected() {
    let (scope, identity, registry) = setup();
    let mut forged_run = outcome(vec![raw("event", "0x1301")]);
    forged_run.run = CollectionRunId::new("forged-run").unwrap();
    forged_run.observations[0].run = forged_run.run.clone();
    assert!(matches!(
        normalize_fixture(&scope, &identity, &registry, forged_run),
        Err(PipelineError::InvalidOutcome)
    ));

    let mut forged_collector = outcome(vec![raw("event", "0x1301")]);
    forged_collector.descriptor.id = CollectorId::new("rogue-collector").unwrap();
    forged_collector.observations[0].collector = forged_collector.descriptor.id.clone();
    assert!(matches!(
        normalize_fixture(&scope, &identity, &registry, forged_collector),
        Err(PipelineError::InvalidOutcome)
    ));
}

#[test]
fn absent_location_and_explicit_zero_remain_distinct_assets() {
    let (scope, identity, registry) = setup();
    let a = raw("no-offset", "0x1301");
    let mut b = raw("zero-offset", "0x1301");
    b.source.offset = Some(0);
    let snap = normalize_fixture(
        &scope, &identity, &registry,
        outcome(vec![a, b]),
    ).unwrap();
    assert_eq!(snap.assets.len(), 2);
}
