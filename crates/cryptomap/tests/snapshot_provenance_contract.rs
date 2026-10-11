//! FOSS-320.8 immutable canonical snapshot provenance and tampering regression.
//! These fixtures intentionally exercise the public FOSS-2 snapshot API.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::*;
use std::collections::BTreeSet;

const START: &str = "2026-10-11T11:59:00Z";
const END: &str = "2026-10-11T12:01:00Z";

fn run(id: &str) -> CollectionRun {
    CollectionRun {
        id: CollectionRunId::new(id).unwrap(),
        collector: CollectorId::new("inventory-conformance").unwrap(),
        collector_version: "1.0".into(),
        scope: CollectionScopeId::new("tenant-conformance").unwrap(),
        requested: BTreeSet::from(["authorized-source".into()]),
        started_at: START.into(),
        ended_at: END.into(),
        completeness: RunCompleteness::Partial,
    }
}
fn evidence(run_id: &str, time: &str) -> Evidence {
    Evidence {
        id: EvidenceId::new(format!("evidence-{run_id}")).unwrap(),
        collector: CollectorId::new("inventory-conformance").unwrap(),
        collector_version: "1.0".into(),
        run: CollectionRunId::new(run_id).unwrap(),
        source: "authorized-source".into(),
        observed_at: time.into(),
        kind: EvidenceKind::Direct,
        confidence: Confidence::Confirmed,
        source_sha256: None,
        inference_rule: None,
    }
}
fn assemble(rows: &[(&str, &str)]) -> Result<InventorySnapshot, InventoryError> {
    let mut builder = InventoryBuilder::new();
    for &(run_id, time) in rows {
        builder.add_run(run(run_id))?;
        builder.add_evidence(evidence(run_id, time))?;
    }
    builder.finalize(InventoryLimits::default())
}

#[test]
fn exact_boundaries_and_equivalent_utc_offsets_survive_verified_round_trip() {
    for instant in [
        START,
        END,
        "2026-10-11T08:00:00-04:00",
        "2026-10-11T13:00:00+01:00",
    ] {
        let snap = assemble(&[("run-a", instant)]).unwrap();
        snap.verify(InventoryLimits::default()).unwrap();
        let json = serde_json::to_string(&snap).unwrap();
        assert_eq!(
            InventorySnapshot::from_json_verified(&json, InventoryLimits::default(),).unwrap(),
            snap
        );
    }
}

#[test]
fn future_past_and_malformed_evidence_cannot_finalize_canonical_snapshot() {
    for invalid in [
        "2026-10-11T11:58:59Z",
        "2026-10-11T12:01:01Z",
        "2026-10-11T13:01:01+01:00",
        "2026-10-11T07:58:59-04:00",
        "malformed-raw-clock",
    ] {
        let error = assemble(&[("run-a", invalid)]).unwrap_err();
        assert!(matches!(error, InventoryError::InvalidTimestamp));
        assert!(!format!("{error:?}").contains(invalid));
    }
}

#[test]
fn a_valid_snapshot_cannot_be_rehashed_to_launder_temporally_forged_evidence() {
    let original = assemble(&[("run-a", "2026-10-11T12:00:00Z")]).unwrap();
    let mut forged = original.clone();
    forged.evidence.values_mut().next().unwrap().observed_at = "2026-10-11T12:05:00Z".into();
    assert!(matches!(
        forged.verify(InventoryLimits::default()),
        Err(InventoryError::InvalidTimestamp)
    ));
    let wire = serde_json::to_string(&forged).unwrap();
    assert!(matches!(
        InventorySnapshot::from_json_verified(&wire, InventoryLimits::default(),),
        Err(InventoryError::InvalidTimestamp)
    ));
    original.verify(InventoryLimits::default()).unwrap();
}

#[test]
fn changing_the_host_run_window_also_invalidates_its_evidence() {
    let original = assemble(&[("run-a", "2026-10-11T12:00:00Z")]).unwrap();
    let mut forged = original.clone();
    forged.runs.values_mut().next().unwrap().started_at = "2026-10-11T12:00:01Z".into();
    assert!(matches!(
        forged.verify(InventoryLimits::default()),
        Err(InventoryError::InvalidTimestamp)
    ));
    let mut malformed = original.clone();
    malformed.runs.values_mut().next().unwrap().ended_at = "source-supplied-invalid-date".into();
    assert!(malformed.verify(InventoryLimits::default()).is_err());
}

#[test]
fn one_forged_run_rejects_multi_run_snapshot_atomically() {
    for invalid in ["2026-10-11T11:58:59Z", "2026-10-11T12:01:01Z"] {
        let err = assemble(&[("run-a", "2026-10-11T12:00:00Z"), ("run-b", invalid)]).unwrap_err();
        assert!(matches!(err, InventoryError::InvalidTimestamp));
    }
}

#[test]
fn independent_run_order_preserves_canonical_digest_and_verified_provenance() {
    let forward = assemble(&[
        ("run-a", "2026-10-11T11:59:00Z"),
        ("run-b", "2026-10-11T12:00:00Z"),
        ("run-c", "2026-10-11T12:01:00Z"),
    ])
    .unwrap();
    let reverse = assemble(&[
        ("run-c", "2026-10-11T12:01:00Z"),
        ("run-b", "2026-10-11T12:00:00Z"),
        ("run-a", "2026-10-11T11:59:00Z"),
    ])
    .unwrap();
    assert_eq!(forward.id, reverse.id);
    assert_eq!(forward, reverse);
    reverse.verify(InventoryLimits::default()).unwrap();
}

#[test]
fn boundary_check_does_not_convert_failed_or_partial_coverage_to_absence() {
    let mut builder = InventoryBuilder::new();
    let run = run("run-partial");
    builder.add_run(run.clone()).unwrap();
    builder.add_coverage_record(CoverageRecord {
        run: run.id.clone(),
        source_item: "authorized-source".into(),
        state: CoverageState::Partial,
        reason_code: Some("collection:partial".into()),
    });
    builder
        .add_evidence(evidence("run-partial", "2026-10-11T12:00:00Z"))
        .unwrap();
    let snapshot = builder.finalize(InventoryLimits::default()).unwrap();
    assert_eq!(snapshot.coverage_records[0].state, CoverageState::Partial);
    assert_eq!(snapshot.evidence.len(), 1);
    snapshot.verify(InventoryLimits::default()).unwrap();
}

#[test]
fn fractional_evidence_outside_same_second_is_rejected_exactly() {
    let mut builder = InventoryBuilder::new();
    let mut r = run("fractional-run");
    r.started_at = "2026-10-11T12:00:00.250Z".into();
    r.ended_at = "2026-10-11T12:00:00.750Z".into();
    builder.add_run(r).unwrap();
    builder.add_evidence(evidence(
        "fractional-run",
        "2026-10-11T12:00:00.7500000000001Z",
    )).unwrap();
    assert!(matches!(
        builder.finalize(InventoryLimits::default()),
        Err(InventoryError::InvalidTimestamp)
    ));
}

#[test]
fn fractional_inclusive_bounds_and_timezone_offsets_are_comparable() {
    for time in [
        "2026-10-11T12:00:00.250Z",
        "2026-10-11T12:00:00.25Z",
        "2026-10-11T13:00:00.750+01:00",
        "2026-10-11T08:00:00.500-04:00",
    ] {
        let mut r = run("fractional-run");
        r.started_at = "2026-10-11T12:00:00.250Z".into();
        r.ended_at = "2026-10-11T12:00:00.750Z".into();
        let mut builder = InventoryBuilder::new();
        builder.add_run(r).unwrap();
        builder.add_evidence(evidence("fractional-run", time)).unwrap();
        let snap = builder.finalize(InventoryLimits::default()).unwrap();
        snap.verify(InventoryLimits::default()).unwrap();
    }
}

#[test]
fn inverted_fractional_run_interval_is_rejected_without_evidence() {
    let mut invalid = run("run-empty");
    invalid.started_at = "2026-10-11T12:00:00.900Z".into();
    invalid.ended_at = "2026-10-11T12:00:00.100Z".into();
    let mut builder = InventoryBuilder::new();
    assert!(matches!(
        builder.add_run(invalid),
        Err(InventoryError::InvalidMetadata)
    ));
}

#[test]
fn snapshot_import_rejects_fractionally_forged_evidence() {
    let original = assemble(&[("run-a", "2026-10-11T12:00:00Z")]).unwrap();
    let mut tampered = original.clone();
    let run = tampered.runs.values_mut().next().unwrap();
    run.started_at = "2026-10-11T12:00:00.500Z".into();
    run.ended_at = "2026-10-11T12:00:00.900Z".into();
    tampered.evidence.values_mut().next().unwrap().observed_at =
        "2026-10-11T12:00:00.400Z".into();
    assert!(matches!(
        tampered.verify(InventoryLimits::default()),
        Err(InventoryError::InvalidTimestamp)
    ));
    let wire = serde_json::to_string(&tampered).unwrap();
    assert!(InventorySnapshot::from_json_verified(
        &wire,
        InventoryLimits::default()
    ).is_err());
}
