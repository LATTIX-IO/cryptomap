//! Milestone A normative schema-v2 canonical snapshot and ChangeSet vectors.
//! These are reviewed release contracts; changes require explicit migration,
//! not regenerating constants from whatever a modified implementation emits.
#![allow(clippy::unwrap_used)]

use cryptomap::{
    Asset, AssetId, AssetKind, CollectionScopeId, CoverageState, InventoryBuilder, InventoryError,
    InventoryLimits, InventorySnapshot,
};

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

#[test]
fn diff_golden_vectors_retain_tentative_absence_under_partial_coverage() {
    let old = snapshot(true, true, false);
    let fully_inspected = snapshot(false, true, false);
    let partial = snapshot(false, false, false);
    let gone = AssetId::new("lib-aes").unwrap();
    let retained = AssetId::new("lib-ring").unwrap();

    let complete_delta = old.diff(&fully_inspected);
    assert_eq!(complete_delta.removed.len(), 1);
    assert!(complete_delta.removed.contains(&gone));
    assert!(complete_delta.tentative_removed.is_empty());
    assert!(complete_delta.unchanged.contains(&retained));
    assert!(complete_delta.added.is_empty());

    let partial_delta = old.diff(&partial);
    assert!(partial_delta.removed.is_empty());
    assert_eq!(partial_delta.tentative_removed.len(), 1);
    assert!(partial_delta.tentative_removed.contains(&gone));
    assert!(partial_delta.unchanged.contains(&retained));
    assert!(partial_delta.coverage_changed.contains("source:b"));

    assert_eq!(
        old.diff(&fully_inspected),
        old.diff(&snapshot(false, true, true))
    );
    assert_eq!(old.diff(&partial), old.diff(&snapshot(false, false, true)));
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
