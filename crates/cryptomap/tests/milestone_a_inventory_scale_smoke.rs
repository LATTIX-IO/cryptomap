//! Milestone A bounded snapshot-finalization smoke and elapsed-time record.
//! No fixed timing assertion: shared runner variance makes it a smoke, not a SLO.
#![allow(clippy::unwrap_used)]

use cryptomap::{Asset, AssetId, AssetKind, InventoryBuilder, InventoryLimits, InventorySnapshot};
use std::{collections::BTreeSet, time::Instant};

const SIZE: usize = 1024;

fn inventory(ids: impl IntoIterator<Item = usize>) -> InventorySnapshot {
    let mut builder = InventoryBuilder::new();
    for index in ids {
        builder
            .add_asset(Asset {
                id: AssetId::new(format!("asset-{index:04}")).unwrap(),
                kind: AssetKind::Library {
                    ecosystem: "cargo".into(),
                    name: format!("package-{index:04}"),
                    version: "0.1.0".into(),
                },
                extensions: Default::default(),
            })
            .unwrap();
    }
    builder.finalize(InventoryLimits::default()).unwrap()
}

#[test]
fn snapshot_finalization_thousand_assets_is_bounded_and_order_independent() {
    let start = Instant::now();
    let ascending = inventory(0..SIZE);
    let descending = inventory((0..SIZE).rev());
    assert_eq!(ascending, descending);
    assert_eq!(ascending.id, descending.id);
    assert_eq!(ascending.assets.len(), SIZE);

    let document = serde_json::to_string(&ascending).unwrap();
    let imported =
        InventorySnapshot::from_json_verified(&document, InventoryLimits::default()).unwrap();
    assert_eq!(imported, ascending);

    let too_few = InventoryLimits {
        assets: SIZE - 1,
        ..InventoryLimits::default()
    };
    assert!(InventorySnapshot::from_json_verified(&document, too_few).is_err());

    let smaller = inventory(0..SIZE / 2);
    let delta = smaller.diff(&ascending);
    assert_eq!(delta.added.len(), SIZE / 2);
    assert_eq!(delta.unchanged.len(), SIZE / 2);
    assert!(delta.removed.is_empty());
    assert!(delta.tentative_removed.is_empty());
    let expected_additions: BTreeSet<_> = (SIZE / 2..SIZE)
        .map(|index| AssetId::new(format!("asset-{index:04}")).unwrap())
        .collect();
    assert_eq!(delta.added, expected_additions);

    eprintln!(
        "Milestone A snapshot-finalization smoke: {} assets, {} JSON bytes, {:?} elapsed",
        SIZE,
        document.len(),
        start.elapsed()
    );
}
