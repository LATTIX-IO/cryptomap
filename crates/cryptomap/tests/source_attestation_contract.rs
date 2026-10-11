//! FOSS-320.9 canonical source and coverage attestation conformance.
//! Test the existing public InventoryBuilder and verified snapshot import APIs.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::*;

const WHEN: &str = "2026-10-11T12:00:00Z";
fn run(name: &str, requested: &[&str]) -> CollectionRun {
    CollectionRun {
        id: CollectionRunId::new(name).unwrap(),
        collector: CollectorId::new("authorized-collector").unwrap(),
        collector_version: "1.0".into(),
        scope: CollectionScopeId::new("tenant-a").unwrap(),
        requested: requested.iter().map(|s| (*s).to_owned()).collect(),
        started_at: "2026-10-11T11:59:00Z".into(),
        ended_at: "2026-10-11T12:01:00Z".into(),
        completeness: RunCompleteness::Partial,
    }
}
fn evidence(run: &str, source: &str) -> Evidence {
    Evidence {
        id: EvidenceId::new(format!("evidence-{run}")).unwrap(),
        run: CollectionRunId::new(run).unwrap(),
        collector: CollectorId::new("authorized-collector").unwrap(),
        collector_version: "1.0".into(),
        source: source.into(),
        observed_at: WHEN.into(),
        kind: EvidenceKind::Direct,
        confidence: Confidence::Confirmed,
        source_sha256: None,
        inference_rule: None,
    }
}
fn build(
    run_id: &str,
    requested: &[&str],
    source: &str,
    covered: &[(&str, CoverageState)],
) -> Result<InventorySnapshot, InventoryError> {
    let mut builder = InventoryBuilder::new();
    builder.add_run(run(run_id, requested))?;
    for (item, state) in covered {
        builder.add_coverage_record(CoverageRecord {
            run: CollectionRunId::new(run_id).unwrap(),
            source_item: (*item).into(),
            state: *state,
            reason_code: None,
        });
    }
    builder.add_evidence(evidence(run_id, source))?;
    builder.finalize(InventoryLimits::default())
}
#[test]
fn exact_authorized_typed_source_survives_verified_json_roundtrip() {
    for kind in [
        "Dependency",
        "Certificate",
        "TlsEndpoint",
        "Source",
        "Telemetry",
    ] {
        let src = format!("{kind}:logical:stream:item");
        let snapshot = build(
            "run-a",
            &["logical:stream:item"],
            &src,
            &[("logical:stream:item", CoverageState::InspectedObserved)],
        )
        .unwrap();
        snapshot.verify(InventoryLimits::default()).unwrap();
        let encoded = serde_json::to_string(&snapshot).unwrap();
        assert_eq!(
            snapshot,
            InventorySnapshot::from_json_verified(&encoded, InventoryLimits::default()).unwrap()
        );
    }
}
#[test]
fn fabricated_typed_source_outside_requested_scope_fails_closed() {
    for forged in [
        "Telemetry:ungranted",
        "Source:logical:stream:item:extra",
        "Certificate:logical:stream:item2",
        "TlsEndpoint:ungranted",
    ] {
        assert!(matches!(
            build(
                "run-a",
                &["logical:stream:item"],
                forged,
                &[("logical:stream:item", CoverageState::InspectedObserved)]
            ),
            Err(InventoryError::InvalidMetadata)
        ));
    }
}
#[test]
fn legitimate_partial_source_retains_evidence_without_false_absence() {
    let snap = build(
        "run-a",
        &["logical:stream:item"],
        "Telemetry:logical:stream:item",
        &[("logical:stream:item", CoverageState::Partial)],
    )
    .unwrap();
    assert_eq!(snap.evidence.len(), 1);
    assert_eq!(snap.coverage_records[0].state, CoverageState::Partial);
    snap.verify(InventoryLimits::default()).unwrap();
}
#[test]
fn failed_uninspected_or_no_observation_source_cannot_sponsor_evidence() {
    for state in [
        CoverageState::Failed,
        CoverageState::Unsupported,
        CoverageState::NotInspected,
        CoverageState::InspectedNoObservation,
    ] {
        assert!(matches!(
            build(
                "run-a",
                &["logical:stream:item"],
                "Telemetry:logical:stream:item",
                &[("logical:stream:item", state)]
            ),
            Err(InventoryError::InvalidMetadata)
        ));
    }
    assert!(matches!(
        build(
            "run-a",
            &["logical:stream:item"],
            "Telemetry:logical:stream:item",
            &[]
        ),
        Err(InventoryError::InvalidMetadata)
    ));
}
#[test]
fn coverage_from_another_run_cannot_authorize_evidence() {
    let mut builder = InventoryBuilder::new();
    builder.add_run(run("run-a", &["shared"])).unwrap();
    builder.add_run(run("run-b", &["shared"])).unwrap();
    builder.add_coverage_record(CoverageRecord {
        run: CollectionRunId::new("run-b").unwrap(),
        source_item: "shared".into(),
        state: CoverageState::InspectedObserved,
        reason_code: None,
    });
    builder
        .add_evidence(evidence("run-a", "Telemetry:shared"))
        .unwrap();
    assert!(matches!(
        builder.finalize(InventoryLimits::default()),
        Err(InventoryError::InvalidMetadata)
    ));
}
#[test]
fn snapshot_tampering_with_unrequested_source_cannot_be_reverified() {
    let original = build(
        "run-a",
        &["a"],
        "Telemetry:a",
        &[("a", CoverageState::InspectedObserved)],
    )
    .unwrap();
    let mut tampered = original.clone();
    tampered.evidence.values_mut().next().unwrap().source = "Telemetry:foreign".into();
    assert!(matches!(
        tampered.verify(InventoryLimits::default()),
        Err(InventoryError::InvalidMetadata)
    ));
    let json = serde_json::to_string(&tampered).unwrap();
    assert!(InventorySnapshot::from_json_verified(&json, InventoryLimits::default()).is_err());
}
#[test]
fn source_matching_never_borrows_similar_prefix_or_suffix() {
    // An explicitly approved source with a kind-like prefix must not
    // authorize similarly spelled/extended names.
    let allowed = "Telemetry:shared";
    assert!(matches!(
        build(
            "run-a",
            &[allowed],
            "Telemetry:shared:suffix",
            &[(allowed, CoverageState::InspectedObserved)]
        ),
        Err(InventoryError::InvalidMetadata)
    ));
}
#[test]
fn unprefixed_legacy_evidence_preserves_schema_two_compatibility() {
    // Existing FOSS-2 snapshot consumers have arbitrary unprefixed source
    // labels; changing them requires a versioned schema migration.
    let snapshot = build("run-a", &["current"], "historical-source-label", &[]).unwrap();
    snapshot.verify(InventoryLimits::default()).unwrap();
}
#[test]
fn independent_permutations_of_identical_authorized_sources_are_deterministic() {
    let one = build(
        "run-a",
        &["a", "b"],
        "Telemetry:a",
        &[
            ("a", CoverageState::InspectedObserved),
            ("b", CoverageState::Partial),
        ],
    )
    .unwrap();
    let another = build(
        "run-a",
        &["b", "a"],
        "Telemetry:a",
        &[
            ("b", CoverageState::Partial),
            ("a", CoverageState::InspectedObserved),
        ],
    )
    .unwrap();
    assert_eq!(one, another);
    assert_eq!(one.id, another.id);
}

#[test]
fn failed_run_cannot_launder_typed_evidence_with_positive_item_coverage() {
    let mut r = run("run-failed", &["authorized-source"]);
    r.completeness = RunCompleteness::Failed;
    let mut builder = InventoryBuilder::new();
    builder.add_run(r).unwrap();
    builder.add_coverage_record(CoverageRecord {
        run: CollectionRunId::new("run-failed").unwrap(),
        source_item: "authorized-source".into(),
        state: CoverageState::InspectedObserved,
        reason_code: None,
    });
    builder
        .add_evidence(evidence("run-failed", "Telemetry:authorized-source"))
        .unwrap();
    assert!(matches!(
        builder.finalize(InventoryLimits::default()),
        Err(InventoryError::InvalidMetadata)
    ));
}
