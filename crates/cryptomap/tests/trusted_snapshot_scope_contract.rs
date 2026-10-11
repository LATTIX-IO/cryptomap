//! FOSS-320.11 trusted host-scope snapshot verification contracts.
#![allow(clippy::unwrap_used)]
use cryptomap::*;
use std::collections::BTreeSet;

fn snapshot(scope: &str) -> InventorySnapshot {
    let mut builder = InventoryBuilder::new();
    for id in ["first", "second"] {
        builder
            .add_run(CollectionRun {
                id: CollectionRunId::new(id).unwrap(),
                collector: CollectorId::new("fixture").unwrap(),
                collector_version: "1".into(),
                scope: CollectionScopeId::new(scope).unwrap(),
                requested: BTreeSet::new(),
                started_at: "2026-10-11T12:00:00Z".into(),
                ended_at: "2026-10-11T12:01:00Z".into(),
                completeness: RunCompleteness::Partial,
            })
            .unwrap();
    }
    builder.finalize(InventoryLimits::default()).unwrap()
}

#[test]
fn authorized_scope_accepts_deterministic_multiple_runs() {
    let snap = snapshot("tenant-a");
    let expected = CollectionScopeId::new("tenant-a").unwrap();
    snap.verify_for_scope(&expected, InventoryLimits::default())
        .unwrap();
    let json = serde_json::to_string(&snap).unwrap();
    assert_eq!(
        InventorySnapshot::from_json_verified_for_scope(
            &json,
            &expected,
            InventoryLimits::default()
        )
        .unwrap(),
        snap
    );
}

#[test]
fn internally_valid_foreign_tenant_is_rejected_by_trusted_scope_gate() {
    let snap = snapshot("attacker-tenant");
    snap.verify(InventoryLimits::default()).unwrap();
    let expected = CollectionScopeId::new("tenant-a").unwrap();
    assert!(matches!(
        snap.verify_for_scope(&expected, InventoryLimits::default()),
        Err(InventoryError::InvalidMetadata)
    ));
    let json = serde_json::to_string(&snap).unwrap();
    let error = InventorySnapshot::from_json_verified_for_scope(
        &json,
        &expected,
        InventoryLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(error, InventoryError::InvalidMetadata));
    assert!(!format!("{error:?}").contains("attacker-tenant"));
}

#[test]
fn runless_legacy_snapshot_has_no_tenant_proof() {
    let snap = InventoryBuilder::new()
        .finalize(InventoryLimits::default())
        .unwrap();
    snap.verify(InventoryLimits::default()).unwrap();
    let expected = CollectionScopeId::new("tenant-a").unwrap();
    assert!(matches!(
        snap.verify_for_scope(&expected, InventoryLimits::default()),
        Err(InventoryError::InvalidMetadata)
    ));
}

#[test]
fn digest_tampering_is_rejected_even_when_scope_matches() {
    let mut snap = snapshot("tenant-a");
    let expected = CollectionScopeId::new("tenant-a").unwrap();
    snap.runs.values_mut().next().unwrap().collector_version = "2".into();
    assert!(matches!(
        snap.verify_for_scope(&expected, InventoryLimits::default()),
        Err(InventoryError::DigestMismatch)
    ));
}

#[test]
fn strict_json_and_byte_limits_precede_authorized_import() {
    let snap = snapshot("tenant-a");
    let expected = CollectionScopeId::new("tenant-a").unwrap();
    let json = serde_json::to_string(&snap).unwrap();
    let limits = InventoryLimits {
        snapshot_bytes: json.len() - 1,
        ..InventoryLimits::default()
    };
    assert!(matches!(
        InventorySnapshot::from_json_verified_for_scope(&json, &expected, limits),
        Err(InventoryError::LimitExceeded("snapshot bytes"))
    ));
    let duplicate = json.replacen(
        "\"schema_version\":2",
        "\"schema_version\":2,\"schema_version\":2",
        1,
    );
    assert_ne!(duplicate, json);
    assert!(
        InventorySnapshot::from_json_verified_for_scope(
            &duplicate,
            &expected,
            InventoryLimits::default()
        )
        .is_err()
    );
}
