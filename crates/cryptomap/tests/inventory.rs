use cryptomap::*;
use std::collections::{BTreeMap, BTreeSet};

fn id(s: &str) -> AssetId {
    AssetId::new(s).unwrap()
}
fn asset(name: &str) -> Asset {
    Asset {
        id: id(name),
        kind: AssetKind::Library {
            ecosystem: "cargo".into(),
            name: name.into(),
            version: "1.0".into(),
        },
        extensions: BTreeMap::new(),
    }
}
fn test_run() -> CollectionRun {
    CollectionRun {
        id: CollectionRunId::new("run1").unwrap(),
        collector: CollectorId::new("unit").unwrap(),
        collector_version: "1".into(),
        scope: CollectionScopeId::new("fixture-scope").unwrap(),
        requested: BTreeSet::from(["fixture".into()]),
        started_at: "2026-10-08T00:00:00Z".into(),
        ended_at: "2026-10-08T01:00:00Z".into(),
        completeness: RunCompleteness::Complete,
    }
}

fn evidence() -> Evidence {
    Evidence {
        id: EvidenceId::new("ev1").unwrap(),
        collector: CollectorId::new("unit").unwrap(),
        collector_version: "1".into(),
        run: CollectionRunId::new("run1").unwrap(),
        source: "fixture".into(),
        observed_at: "2026-10-08T00:00:00Z".into(),
        kind: EvidenceKind::Direct,
        confidence: Confidence::Confirmed,
        source_sha256: None,
        inference_rule: None,
    }
}
fn observation(name: &str, value: &str) -> Observation {
    Observation {
        id: ObservationId::new(name).unwrap(),
        asset: id("library"),
        evidence: EvidenceId::new("ev1").unwrap(),
        property: "config:crypto".into(),
        value: value.into(),
    }
}
#[test]
fn id_validation_and_serde() {
    assert!(AssetId::new("").is_err());
    assert!(AssetId::new(" bad").is_err());
    assert!(AssetId::new("bad\n").is_err());
    let x = id("valid");
    let encoded = serde_json::to_string(&x).unwrap();
    assert_eq!(encoded, "\"valid\"");
    assert_eq!(serde_json::from_str::<AssetId>(&encoded).unwrap(), x);
    assert!(serde_json::from_str::<AssetId>("\"\"").is_err());
}
#[test]
fn insertion_order_does_not_change_snapshot_digest() {
    let mut a = InventoryBuilder::new();
    a.add_run(test_run()).unwrap();
    a.add_asset(asset("library")).unwrap();
    a.add_evidence(evidence()).unwrap();
    a.add_observation(observation("a", "AES")).unwrap();
    a.add_observation(observation("b", "SHA")).unwrap();
    let mut b = InventoryBuilder::new();
    b.add_run(test_run()).unwrap();
    b.add_observation(observation("b", "SHA")).unwrap();
    b.add_evidence(evidence()).unwrap();
    b.add_observation(observation("a", "AES")).unwrap();
    b.add_asset(asset("library")).unwrap();
    let first = a.finalize(InventoryLimits::default()).unwrap();
    let second = b.finalize(InventoryLimits::default()).unwrap();
    assert_eq!(first.id, second.id);
    assert_eq!(first, second);
    assert_eq!(first.conflicts.len(), 1);
    let conflict = first.conflicts.values().next().unwrap();
    assert_eq!(conflict.values.len(), 2);
    assert_eq!(first.observations_for(&id("library")).count(), 2);
}
#[test]
fn duplicate_and_dangling_references_are_rejected() {
    let mut b = InventoryBuilder::new();
    b.add_run(test_run()).unwrap();
    b.add_asset(asset("library")).unwrap();
    b.add_asset(asset("library")).unwrap();
    let mut changed = asset("library");
    changed.kind = AssetKind::Extension {
        namespace: "x".into(),
        kind: "y".into(),
    };
    assert!(b.add_asset(changed).is_err());
    b.add_evidence(evidence()).unwrap();
    b.add_observation(observation("a", "AES")).unwrap();
    assert!(b.add_observation(observation("a", "SHA")).is_err());
    b.add_relationship(Relationship {
        id: RelationshipId::new("rel1").unwrap(),
        from: id("library"),
        to: id("missing"),
        kind: RelationshipKind::DependsOn,
        evidence: BTreeSet::new(),
    })
    .unwrap();
    assert!(matches!(
        b.finalize(InventoryLimits::default()),
        Err(InventoryError::DanglingRelationship(_))
    ));
}
#[test]
fn limits_coverage_diff_and_round_trip() {
    let mut a = InventoryBuilder::new();
    a.add_run(test_run()).unwrap();
    a.add_asset(asset("library")).unwrap();
    a.set_coverage("repo", CoverageState::InspectedObserved);
    let one = a.finalize(InventoryLimits::default()).unwrap();
    assert_eq!(
        one.query_assets(|a| matches!(a.kind, AssetKind::Library { .. }))
            .count(),
        1
    );
    let json = serde_json::to_string(&one).unwrap();
    let restored =
        InventorySnapshot::from_json_verified(&json, InventoryLimits::default()).unwrap();
    assert_eq!(one, restored);
    let mut b = InventoryBuilder::new();
    b.add_run(test_run()).unwrap();
    b.add_asset(asset("other")).unwrap();
    b.set_coverage("repo", CoverageState::Partial);
    let two = b.finalize(InventoryLimits::default()).unwrap();
    let diff = one.diff(&two);
    assert!(diff.tentative_removed.contains(&id("library")));
    assert!(diff.removed.is_empty());
    assert!(diff.added.contains(&id("other")));
    assert!(diff.coverage_changed.contains("repo"));
    let mut limited = InventoryBuilder::new();
    limited.add_run(test_run()).unwrap();
    limited.add_asset(asset("library")).unwrap();
    assert!(matches!(
        limited.finalize(InventoryLimits {
            assets: 0,
            ..InventoryLimits::default()
        }),
        Err(InventoryError::LimitExceeded("assets"))
    ));
}
