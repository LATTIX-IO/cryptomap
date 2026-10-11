//! FOSS-320.10 cross-tenant canonical snapshot isolation acceptance tests.
//! No network, filesystem access or external collectors are needed.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::*;
use std::collections::BTreeSet;

fn run(run_id: &str, scope: &str) -> CollectionRun {
    CollectionRun {
        id: CollectionRunId::new(run_id).unwrap(),
        collector: CollectorId::new("fixture-collector").unwrap(),
        collector_version: "1.0".into(),
        scope: CollectionScopeId::new(scope).unwrap(),
        requested: BTreeSet::from(["telemetry:shared".into()]),
        started_at: "2026-10-11T11:59:00Z".into(),
        ended_at: "2026-10-11T12:01:00Z".into(),
        completeness: RunCompleteness::Partial,
    }
}

fn evidence(run_id: &str) -> Evidence {
    Evidence {
        id: EvidenceId::new(format!("evidence-{run_id}")).unwrap(),
        run: CollectionRunId::new(run_id).unwrap(),
        collector: CollectorId::new("fixture-collector").unwrap(),
        collector_version: "1.0".into(),
        source: "Telemetry:telemetry:shared".into(),
        observed_at: "2026-10-11T12:00:00.123Z".into(),
        kind: EvidenceKind::Direct,
        confidence: Confidence::Confirmed,
        source_sha256: None,
        inference_rule: None,
    }
}

fn checked_snapshot(rows: &[(&str, &str)]) -> Result<InventorySnapshot, InventoryError> {
    let mut builder = InventoryBuilder::new();
    for &(run_id, tenant) in rows {
        builder.add_run(run(run_id, tenant))?;
        builder.add_coverage_record(CoverageRecord {
            run: CollectionRunId::new(run_id).unwrap(),
            source_item: "telemetry:shared".into(),
            state: CoverageState::Partial,
            reason_code: Some("collection:partial".into()),
        });
        builder.add_evidence(evidence(run_id))?;
    }
    builder.finalize(InventoryLimits::default())
}

#[test]
fn same_tenant_multiple_runs_and_permutations_are_valid() {
    let forward = checked_snapshot(&[("run-one", "tenant-a"), ("run-two", "tenant-a")]).unwrap();
    let backward = checked_snapshot(&[("run-two", "tenant-a"), ("run-one", "tenant-a")]).unwrap();
    assert_eq!(forward.id, backward.id);
    assert_eq!(forward, backward);
    assert_eq!(forward.runs.len(), 2);
    assert_eq!(forward.evidence.len(), 2);
    assert_eq!(forward.coverage_records.len(), 2);
    assert!(
        forward
            .coverage_records
            .iter()
            .all(|x| x.state == CoverageState::Partial)
    );
    forward.verify(InventoryLimits::default()).unwrap();
}

#[test]
fn mixed_tenant_runs_cannot_finalize_even_with_individually_valid_evidence() {
    let error = checked_snapshot(&[("run-one", "tenant-a"), ("run-two", "tenant-b")]).unwrap_err();
    assert!(matches!(error, InventoryError::InvalidMetadata));
    assert!(!format!("{error:?}").contains("tenant-a"));
    assert!(!format!("{error:?}").contains("tenant-b"));
}

#[test]
fn mixed_tenants_are_rejected_even_when_no_evidence_exists() {
    let mut builder = InventoryBuilder::new();
    builder.add_run(run("run-one", "tenant-a")).unwrap();
    builder.add_run(run("run-two", "tenant-b")).unwrap();
    assert!(matches!(
        builder.finalize(InventoryLimits::default()),
        Err(InventoryError::InvalidMetadata)
    ));
}

#[test]
fn imported_snapshot_cannot_launder_foreign_tenant_by_rehashing() {
    let original = checked_snapshot(&[("run-one", "tenant-a"), ("run-two", "tenant-a")]).unwrap();
    let mut tampered = original.clone();
    tampered.runs.values_mut().last().unwrap().scope =
        CollectionScopeId::new("foreign-tenant").unwrap();
    assert!(matches!(
        tampered.verify(InventoryLimits::default()),
        Err(InventoryError::InvalidMetadata)
    ));
    let json = serde_json::to_string(&tampered).unwrap();
    assert!(matches!(
        InventorySnapshot::from_json_verified(&json, InventoryLimits::default(),),
        Err(InventoryError::InvalidMetadata)
    ));
    original.verify(InventoryLimits::default()).unwrap();
}

#[test]
fn an_explicitly_single_tenant_snapshot_round_trips_through_verified_import() {
    let snap = checked_snapshot(&[("run-a", "tenant-a"), ("run-b", "tenant-a")]).unwrap();
    let json = serde_json::to_string(&snap).unwrap();
    assert_eq!(
        InventorySnapshot::from_json_verified(&json, InventoryLimits::default()).unwrap(),
        snap
    );
}

#[test]
fn legacy_runless_empty_snapshot_stays_supported() {
    let snap = InventoryBuilder::new()
        .finalize(InventoryLimits::default())
        .unwrap();
    assert!(snap.runs.is_empty());
    snap.verify(InventoryLimits::default()).unwrap();
}
