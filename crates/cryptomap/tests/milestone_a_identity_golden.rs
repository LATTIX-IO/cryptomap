//! Frozen Milestone A public identity vectors for the asset:v2 contract.
//! Update these only alongside an explicit identity/schema version migration.
#![allow(clippy::unwrap_used)]

use cryptomap::{AssetId, AssetKind, IdentityContext};

#[test]
fn asset_v2_identity_golden_vectors_cannot_silently_change() {
    let tenant = IdentityContext::new("tenant-a").unwrap();
    let library = AssetKind::Library {
        ecosystem: "CARGO".into(),
        name: "Ring".into(),
        version: "0.17.12".into(),
    };
    let actual = AssetId::from_kind(&library, &tenant).unwrap();
    assert_eq!(
        actual.as_str(),
        "asset:v2:0c73ffe49cdb3398f5024c46858f5321a769b1ee9dd5f5d0cddcba3213cdcf3f"
    );

    let endpoint = AssetKind::Endpoint {
        transport: "TCP".into(),
        host: "EXAMPLE.com.".into(),
        port: 443,
        scope: "prod".into(),
    };
    assert_eq!(
        AssetId::from_kind(&endpoint, &tenant).unwrap().as_str(),
        "asset:v2:85e78bf3a84092d09e219bd9d48e082aeb5d093afa28e098b66c0af76f66d0d3"
    );

    let foreign = IdentityContext::new("tenant-b").unwrap();
    assert_eq!(
        AssetId::from_kind(&library, &foreign).unwrap().as_str(),
        "asset:v2:cba24345919b3d8ab56a08345b6164a7a006a8a5439d152ce23e7881fb635ba2"
    );
    assert_ne!(
        AssetId::from_kind(&library, &tenant).unwrap(),
        AssetId::from_kind(&library, &foreign).unwrap()
    );
}

#[test]
fn normalized_aliases_keep_the_same_frozen_asset_v2_id() {
    let tenant = IdentityContext::new("tenant-a").unwrap();
    let lowercase = AssetKind::Library {
        ecosystem: "cargo".into(),
        name: "ring".into(),
        version: "0.17.12".into(),
    };
    let uppercase = AssetKind::Library {
        ecosystem: "CARGO".into(),
        name: "Ring".into(),
        version: "0.17.12".into(),
    };
    assert_eq!(
        AssetId::from_kind(&lowercase, &tenant).unwrap(),
        AssetId::from_kind(&uppercase, &tenant).unwrap()
    );
}
