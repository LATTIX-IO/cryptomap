// Deterministic property-style test corpus. Seeds are fixed for reproducibility.
#![allow(clippy::unwrap_used)]
use cryptomap::*;
use std::collections::BTreeMap;

fn observed(run: &str, src: &str) -> Evidence {
    Evidence {
        id: EvidenceId::new(format!("e:{src}")).unwrap(),
        collector: CollectorId::new("property-collector").unwrap(),
        collector_version: "1".into(),
        run: CollectionRunId::new(run).unwrap(),
        source: src.into(),
        observed_at: "2026-10-08T00:00:00Z".into(),
        kind: EvidenceKind::Direct,
        confidence: Confidence::High,
        source_sha256: None,
        inference_rule: None,
    }
}
fn runner() -> CollectionRun {
    CollectionRun {
        id: CollectionRunId::new("run").unwrap(),
        collector: CollectorId::new("property-collector").unwrap(),
        collector_version: "1".into(),
        scope: CollectionScopeId::new("test").unwrap(),
        requested: (0..20).map(|i| format!("file{i}")).collect(),
        started_at: "2026-10-08T00:00:00Z".into(),
        ended_at: "2026-10-08T01:00:00Z".into(),
        completeness: RunCompleteness::Partial,
    }
}
fn assemble(order: &[usize]) -> InventorySnapshot {
    let mut b = InventoryBuilder::new();
    b.add_run(runner()).unwrap();
    for &i in order {
        b.add_asset(Asset {
            id: AssetId::new(format!("a{i}")).unwrap(),
            kind: AssetKind::Library {
                ecosystem: "cargo".into(),
                name: format!("pkg{i}"),
                version: "1.0".into(),
            },
            extensions: BTreeMap::new(),
        })
        .unwrap();
        b.add_evidence(observed("run", &format!("file{i}")))
            .unwrap();
        b.add_observation(Observation {
            id: ObservationId::new(format!("o{i}")).unwrap(),
            asset: AssetId::new(format!("a{i}")).unwrap(),
            evidence: EvidenceId::new(format!("e:file{i}")).unwrap(),
            property: "package:version".into(),
            value: "1.0".into(),
        })
        .unwrap();
    }
    b.set_coverage("test", CoverageState::Partial);
    b.finalize(InventoryLimits::default()).unwrap()
}
#[test]
fn permutation_property_for_snapshots() {
    let expected = assemble(&(0..20).collect::<Vec<_>>());
    for seed in 1..=64u64 {
        let mut order = (0..20).collect::<Vec<_>>();
        let mut state = seed;
        for i in (1..order.len()).rev() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            order.swap(i, (state as usize) % (i + 1));
        }
        let candidate = assemble(&order);
        assert_eq!(expected.id, candidate.id, "seed {seed}");
        assert_eq!(expected, candidate, "seed {seed}");
        let encoded = serde_json::to_string(&candidate).unwrap();
        let verified =
            InventorySnapshot::from_json_verified(&encoded, InventoryLimits::default()).unwrap();
        assert_eq!(candidate, verified);
    }
}
#[test]
fn derived_identity_unknown_and_explicit_sites() {
    let context = IdentityContext::new("a").unwrap();
    let protocol = AssetKind::Protocol {
        family: "TLS".into(),
        version: Some("1.3".into()),
        state: ProtocolState::Configured,
    };
    assert!(AssetId::from_kind(&protocol, &context).is_err());
    let a = context.clone().with_use_site("service-a").unwrap();
    let b = context.with_use_site("service-b").unwrap();
    assert_ne!(
        AssetId::from_kind(&protocol, &a).unwrap(),
        AssetId::from_kind(&protocol, &b).unwrap()
    );
}
#[test]
fn inferred_evidence_needs_inference_rule() {
    let mut b = InventoryBuilder::new();
    b.add_run(runner()).unwrap();
    let mut e = observed("run", "file1");
    e.kind = EvidenceKind::Inferred;
    b.add_evidence(e).unwrap();
    assert!(matches!(
        b.finalize(InventoryLimits::default()),
        Err(InventoryError::InvalidMetadata)
    ));
}
#[test]
fn incomplete_collection_marks_observation_removal_tentative() {
    let old = assemble(&(0..20).collect::<Vec<_>>());
    let new = assemble(&(0..10).collect::<Vec<_>>());
    let diff = old.diff(&new);
    assert_eq!(diff.observations_removed.len(), 0);
    assert_eq!(diff.observations_tentative_removed.len(), 10);
    assert_eq!(diff.evidence_tentative_removed.len(), 10);
    assert_eq!(diff.tentative_removed.len(), 10);
}
#[test]
fn prohibited_key_material_cannot_enter_observation() {
    let mut b = InventoryBuilder::new();
    b.add_run(runner()).unwrap();
    b.add_asset(Asset {
        id: AssetId::new("a1").unwrap(),
        kind: AssetKind::Library {
            ecosystem: "cargo".into(),
            name: "a".into(),
            version: "1".into(),
        },
        extensions: BTreeMap::new(),
    })
    .unwrap();
    b.add_evidence(observed("run", "file1")).unwrap();
    b.add_observation(Observation {
        id: ObservationId::new("obs").unwrap(),
        asset: AssetId::new("a1").unwrap(),
        evidence: EvidenceId::new("e:file1").unwrap(),
        property: "key:material".into(),
        value: "-----BEGIN PRIVATE KEY-----".into(),
    })
    .unwrap();
    assert!(matches!(
        b.finalize(InventoryLimits::default()),
        Err(InventoryError::ProhibitedMaterial)
    ));
}
