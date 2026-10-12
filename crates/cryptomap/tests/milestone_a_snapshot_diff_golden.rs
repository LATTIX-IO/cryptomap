//! Milestone A normative schema-v2 canonical snapshot and ChangeSet vectors.
//! These are reviewed release contracts; changes require explicit migration,
//! not regenerating constants from whatever a modified implementation emits.
#![allow(clippy::unwrap_used)]

use cryptomap::{
    Asset, AssetId, AssetKind, ChangeSet, CollectionScopeId, CoverageState, InventoryBuilder,
    InventoryError, InventoryLimits, InventorySnapshot,
};
use std::collections::BTreeSet;

fn library(id: &str, name: &str, version: &str) -> Asset {
    Asset {
        id: AssetId::new(id).unwrap(),
        kind: AssetKind::Library {
            ecosystem: "cargo".into(),
            name: name.into(),
            version: version.into(),
        },
        extensions: Default::default(),
    }
}

/// An intentionally run-less compatibility fixture, not trusted tenant evidence.
/// Snapshot digest input is the canonical serde_json tuple of schema, assets,
/// observations, evidence, relationships, conflicts, coverage, runs and records.
fn snapshot(with_aes: bool, cover_b: bool, reverse: bool) -> InventorySnapshot {
    let mut builder = InventoryBuilder::new();
    let mut assets = vec![library("lib-ring", "ring", "0.17.12")];
    if with_aes {
        assets.push(library("lib-aes", "aes-gcm", "0.10.3"));
    }
    if reverse {
        assets.reverse();
        if cover_b {
            builder.set_coverage("source:b", CoverageState::InspectedObserved);
        }
    }
    for asset in assets {
        builder.add_asset(asset).unwrap();
    }
    builder.set_coverage("source:a", CoverageState::InspectedObserved);
    if cover_b && !reverse {
        builder.set_coverage("source:b", CoverageState::InspectedObserved);
    }
    builder.finalize(InventoryLimits::default()).unwrap()
}

#[test]
fn schema_v2_snapshot_sha256_vectors_are_frozen() {
    let baseline = snapshot(true, true, false);
    assert_eq!(
        baseline.id.as_str(),
        "sha256:5d991351e46de34e77386bd11522615afbdda026bad212fad80402000a33cb2f"
    );
    assert_eq!(
        snapshot(false, true, false).id.as_str(),
        "sha256:743cc61790dea17a2aea81ea5216fb04d56f613789f7de49bd717e5bf8f6d177"
    );
    assert_eq!(
        snapshot(false, false, false).id.as_str(),
        "sha256:dfa8d22d54f5d46a6e38bf3702d0ae2964092b4e30ab25299a3be715d09a1783"
    );
    assert_eq!(baseline, snapshot(true, true, true));
    assert_eq!(baseline.id, snapshot(true, true, true).id);
    let encoded = serde_json::to_string(&baseline).unwrap();
    let imported =
        InventorySnapshot::from_json_verified(&encoded, InventoryLimits::default()).unwrap();
    assert_eq!(baseline, imported);
}

/// Specify every ChangeSet field to detect silent addition/omission of
/// observations, evidence, conflicts or coverage changes in the release API.
fn expected_diff(confirmed: bool) -> ChangeSet {
    let gone = AssetId::new("lib-aes").unwrap();
    ChangeSet {
        added: BTreeSet::new(),
        removed: if confirmed {
            BTreeSet::from([gone.clone()])
        } else {
            BTreeSet::new()
        },
        changed: BTreeSet::new(),
        unchanged: BTreeSet::from([AssetId::new("lib-ring").unwrap()]),
        tentative_removed: if confirmed {
            BTreeSet::new()
        } else {
            BTreeSet::from([gone])
        },
        observations_added: BTreeSet::new(),
        observations_removed: BTreeSet::new(),
        observations_tentative_removed: BTreeSet::new(),
        observations_changed: BTreeSet::new(),
        evidence_added: BTreeSet::new(),
        evidence_removed: BTreeSet::new(),
        evidence_tentative_removed: BTreeSet::new(),
        confidence_changed: BTreeSet::new(),
        relationships_added: BTreeSet::new(),
        relationships_removed: BTreeSet::new(),
        relationships_tentative_removed: BTreeSet::new(),
        relationships_changed: BTreeSet::new(),
        conflicts_changed: BTreeSet::new(),
        coverage_changed: if confirmed {
            BTreeSet::new()
        } else {
            BTreeSet::from(["source:b".to_owned()])
        },
        conflicts_introduced: BTreeSet::new(),
        conflicts_resolved: BTreeSet::new(),
        conflicts_tentative_resolved: BTreeSet::new(),
    }
}

#[test]
fn diff_golden_vectors_retain_tentative_absence_under_partial_coverage() {
    let old = snapshot(true, true, false);
    let fully_inspected = snapshot(false, true, false);
    let partial = snapshot(false, false, false);

    assert_eq!(old.diff(&fully_inspected), expected_diff(true));
    assert_eq!(old.diff(&partial), expected_diff(false));

    // BTreeMap insertion order is not part of the public ChangeSet contract.
    assert_eq!(old.diff(&snapshot(false, true, true)), expected_diff(true));
    assert_eq!(
        old.diff(&snapshot(false, false, true)),
        expected_diff(false)
    );
}

#[test]
fn release_snapshot_import_requires_valid_schema_digest_and_independent_scope() {
    let baseline = snapshot(true, true, false);
    let mut tampered = baseline.clone();
    tampered
        .assets
        .get_mut(&AssetId::new("lib-ring").unwrap())
        .unwrap()
        .extensions
        .insert("source:owner".into(), "forged".into());
    assert!(tampered.verify(InventoryLimits::default()).is_err());
    assert!(
        InventorySnapshot::from_json_verified(
            &serde_json::to_string(&tampered).unwrap(),
            InventoryLimits::default(),
        )
        .is_err()
    );

    let mut future_schema = baseline.clone();
    future_schema.schema_version = 3;
    assert!(matches!(
        future_schema.verify(InventoryLimits::default()),
        Err(InventoryError::UnsupportedSchema(3))
    ));

    // A digest is integrity, not authorization: run-less legacy compatibility
    // fixtures do not prove tenant ownership on scope-verified import.
    let tenant = CollectionScopeId::new("tenant-a").unwrap();
    assert!(
        baseline
            .verify_for_scope(&tenant, InventoryLimits::default())
            .is_err()
    );
    assert!(
        InventorySnapshot::from_json_verified_for_scope(
            &serde_json::to_string(&baseline).unwrap(),
            &tenant,
            InventoryLimits::default(),
        )
        .is_err()
    );
}
