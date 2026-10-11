//! Contract tests for explicit, non-inferential cross-source correlation.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    CollectionRunId, CollectorId, Confidence, CoverageState, EvidenceKind, IdentityContext,
    InventoryLimits, ProtocolState, RelationshipKind,
    collector::{
        COLLECTOR_CONTRACT_VERSION, CollectionMode, CollectionOutcome, CollectionStatus,
        CollectorCapabilities, CollectorDescriptor, RequestedSource,
    },
    coverage::CollectionScopeId,
    pipeline::{PipelineError, PipelineInput, normalize},
    raw::{RawFactKind, RawLimits, RawObservation, RawSourceKind, RawSourceLocator},
    registry::Registry,
    scope::CollectionScope,
};
use std::collections::{BTreeMap, BTreeSet};

fn descriptor() -> CollectorDescriptor {
    CollectorDescriptor {
        contract_version: COLLECTOR_CONTRACT_VERSION,
        id: CollectorId::new("correlation-fixture").unwrap(),
        version: "1.0".into(),
        capabilities: CollectorCapabilities {
            sources: BTreeSet::from([RawSourceKind::Telemetry]),
            mode: CollectionMode::Passive,
            required_permissions: BTreeSet::new(),
            checkpoint: false,
        },
    }
}
fn event(id: &str, source: &str, fact: RawFactKind) -> RawObservation {
    let attrs = if matches!(fact, RawFactKind::AlgorithmUse { .. }) {
        BTreeMap::from([
            (
                "cryptomap:algorithm-namespace".into(),
                "tls_cipher_suite".into(),
            ),
            ("cryptomap:algorithm-kind".into(), "cipher_suite".into()),
        ])
    } else {
        BTreeMap::new()
    };
    RawObservation {
        contract_version: 1,
        event_id: id.into(),
        collector: CollectorId::new("correlation-fixture").unwrap(),
        collector_version: "1.0".into(),
        run: CollectionRunId::new("correlation-run").unwrap(),
        source: RawSourceLocator {
            kind: RawSourceKind::Telemetry,
            item: source.into(),
            offset: None,
            line: None,
            column: None,
        },
        observed_at: "2026-10-11T12:00:00Z".into(),
        fact,
        evidence_kind: EvidenceKind::Direct,
        confidence: Confidence::Confirmed,
        inference_rule: None,
        source_sha256: None,
        attributes: attrs,
    }
}
fn protocol(id: &str, state: ProtocolState) -> RawObservation {
    event(
        id,
        "stream:protocol",
        RawFactKind::Protocol {
            family: "TLS".into(),
            version: Some("1.3".into()),
            state,
        },
    )
}
fn cert(id: &str) -> RawObservation {
    event(
        id,
        "stream:certificate",
        RawFactKind::Certificate {
            fingerprint_sha256: "ae".repeat(32),
        },
    )
}
fn key(id: &str) -> RawObservation {
    event(
        id,
        "stream:key",
        RawFactKind::KeyReference {
            provider: "kms".into(),
            reference: "KeyCase-1".into(),
        },
    )
}
fn algorithm(id: &str) -> RawObservation {
    event(
        id,
        "stream:algorithm",
        RawFactKind::AlgorithmUse {
            identifier: "0x1301".into(),
            profile: None,
            operation: Some("encrypt".into()),
        },
    )
}
fn config(id: &str) -> RawObservation {
    event(
        id,
        "stream:config",
        RawFactKind::Configuration {
            property: "app:tls_profile".into(),
            value: "TLSv1.3".into(),
        },
    )
}
fn dependency(id: &str) -> RawObservation {
    event(
        id,
        "stream:dep",
        RawFactKind::Dependency {
            ecosystem: "cargo".into(),
            name: "rustls".into(),
            version: "0.23.0".into(),
        },
    )
}
fn link(mut raw: RawObservation, kind: &str, target: &str) -> RawObservation {
    raw.attributes
        .insert("cryptomap:relation-kind".into(), kind.into());
    raw.attributes
        .insert("cryptomap:relation-target-event".into(), target.into());
    raw
}
fn run(
    rows: Vec<RawObservation>,
    states: Option<BTreeMap<String, CoverageState>>,
    max_relationships: usize,
) -> Result<cryptomap::InventorySnapshot, PipelineError> {
    let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-correlation").unwrap());
    let mut requested = BTreeSet::new();
    for raw in &rows {
        requested.insert(raw.source.item.clone());
    }
    let mut sources = Vec::new();
    for item in requested {
        scope
            .grant_logical(RawSourceKind::Telemetry, &item)
            .unwrap();
        sources.push(RequestedSource {
            kind: RawSourceKind::Telemetry,
            item,
        });
    }
    let coverage = states.unwrap_or_else(|| {
        sources
            .iter()
            .map(|r| (r.item.clone(), CoverageState::InspectedObserved))
            .collect()
    });
    let complete = coverage.values().all(|s| {
        matches!(
            s,
            CoverageState::InspectedObserved | CoverageState::InspectedNoObservation
        )
    });
    let status = if complete {
        CollectionStatus::Complete
    } else {
        let succeeded = coverage.values().any(|s| {
            matches!(
                s,
                CoverageState::InspectedObserved | CoverageState::InspectedNoObservation
            )
        });
        if succeeded {
            CollectionStatus::Partial
        } else {
            CollectionStatus::Failed
        }
    };
    let outcome = CollectionOutcome {
        descriptor: descriptor(),
        run: CollectionRunId::new("correlation-run").unwrap(),
        observations: rows,
        coverage,
        diagnostics: Vec::new(),
        status,
    };
    let expected = descriptor();
    let run_id = CollectionRunId::new("correlation-run").unwrap();
    let identity = IdentityContext::new("tenant-correlation")
        .unwrap()
        .with_provider_instance("kms-instance-1")
        .unwrap();
    let mut inventory_limits = InventoryLimits::default();
    inventory_limits.relationships = max_relationships;
    normalize(
        PipelineInput {
            scope: &scope,
            identity: &identity,
            registry: &Registry::builtin(),
            expected_descriptor: &expected,
            expected_run: &run_id,
            sources: &sources,
            raw_limits: RawLimits::default(),
            inventory_limits,
            started_at: "2026-10-11T11:59:00Z",
            ended_at: "2026-10-11T12:01:00Z",
        },
        outcome,
    )
}
fn cross_source() -> Vec<RawObservation> {
    vec![
        link(
            protocol("protocol-cert", ProtocolState::Negotiated),
            "uses_certificate",
            "cert",
        ),
        link(
            protocol("protocol-key", ProtocolState::Negotiated),
            "uses_key",
            "key",
        ),
        link(
            protocol("protocol-algo", ProtocolState::Negotiated),
            "uses_algorithm",
            "algo",
        ),
        cert("cert"),
        key("key"),
        algorithm("algo"),
    ]
}

#[test]
fn explicit_cross_source_edges_have_exact_types_and_asserting_evidence() {
    let snapshot = run(cross_source(), None, 8).unwrap();
    assert_eq!(snapshot.relationships.len(), 3);
    for kind in [
        RelationshipKind::UsesCertificate,
        RelationshipKind::UsesKey,
        RelationshipKind::UsesAlgorithm,
    ] {
        let rel = snapshot
            .relationships
            .values()
            .find(|r| r.kind == kind)
            .unwrap();
        // One collector assertion supports the edge; the target's presence
        // evidence does NOT magically corroborate the asserted relationship.
        assert_eq!(rel.evidence.len(), 1);
        let evidence = &snapshot.evidence[rel.evidence.iter().next().unwrap()];
        assert!(evidence.source.contains("stream:protocol"));
    }
    assert_eq!(snapshot.assets.len(), 4);
    assert_eq!(snapshot.evidence.len(), 6);
    snapshot.verify(InventoryLimits::default()).unwrap();
}

#[test]
fn permutation_preserves_relationships_and_snapshot_digest() {
    let rows = cross_source();
    let mut reverse = rows.clone();
    reverse.reverse();
    let a = run(rows, None, 8).unwrap();
    let b = run(reverse, None, 8).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.id, b.id);
}

#[test]
fn independently_identical_certificates_merge_identity_without_inventing_an_edge() {
    let mut a = cert("cert-a");
    let mut b = cert("cert-b");
    b.source.item = "stream:other-cert".into();
    a.fact = RawFactKind::Certificate {
        fingerprint_sha256: "AE".repeat(32),
    };
    let snapshot = run(vec![a, b], None, 8).unwrap();
    assert_eq!(snapshot.assets.len(), 1);
    assert_eq!(snapshot.evidence.len(), 2);
    assert!(snapshot.relationships.is_empty());
}

#[test]
fn partial_source_still_retains_asserted_relationship_and_partial_coverage() {
    let rows = cross_source();
    let mut states: BTreeMap<String, CoverageState> = rows
        .iter()
        .map(|r| (r.source.item.clone(), CoverageState::InspectedObserved))
        .collect();
    states.insert("stream:certificate".into(), CoverageState::Partial);
    let snapshot = run(rows, Some(states), 8).unwrap();
    assert_eq!(snapshot.relationships.len(), 3);
    assert_eq!(
        snapshot.coverage["stream:certificate"],
        CoverageState::Partial
    );
}

#[test]
fn repeated_assertions_merge_relationship_identity_and_union_evidence() {
    let first = link(
        protocol("protocol-cert-1", ProtocolState::Negotiated),
        "uses_certificate",
        "cert",
    );
    let second = link(
        protocol("protocol-cert-2", ProtocolState::Negotiated),
        "uses_certificate",
        "cert",
    );
    let snap = run(vec![first, second, cert("cert")], None, 8).unwrap();
    assert_eq!(snap.relationships.len(), 1);
    assert_eq!(
        snap.relationships.values().next().unwrap().evidence.len(),
        2
    );
}

#[test]
fn configured_protocol_cannot_claim_negotiated_usage() {
    for (kind, target) in [
        ("uses_certificate", cert("target")),
        ("uses_key", key("target")),
        ("uses_algorithm", algorithm("target")),
    ] {
        let src = link(protocol("src", ProtocolState::Configured), kind, "target");
        assert!(matches!(
            run(vec![src, target], None, 8),
            Err(PipelineError::InvalidOutcome)
        ));
    }
}

#[test]
fn explicit_configuration_and_dependency_links_do_not_claim_active_use() {
    let rows = vec![
        link(
            protocol("configured", ProtocolState::Configured),
            "configured_for",
            "config",
        ),
        link(config("config"), "depends_on", "dep"),
        dependency("dep"),
    ];
    let snap = run(rows, None, 8).unwrap();
    assert_eq!(snap.relationships.len(), 2);
    assert!(
        snap.relationships
            .values()
            .any(|r| r.kind == RelationshipKind::ConfiguredFor)
    );
    assert!(
        snap.relationships
            .values()
            .any(|r| r.kind == RelationshipKind::DependsOn)
    );
    assert!(!snap.relationships.values().any(|r| matches!(
        r.kind,
        RelationshipKind::UsesAlgorithm | RelationshipKind::UsesKey
    )));
}

#[test]
fn invalid_and_inferred_relationship_claims_fail_closed() {
    let tests = [
        ("uses_certificate", "missing"),
        ("related_to", "cert"),
        ("uses_key", "cert"),
        ("uses_certificate", "self"),
    ];
    for (kind, target) in tests {
        let src = link(protocol("self", ProtocolState::Negotiated), kind, target);
        assert!(matches!(
            run(vec![src, cert("cert")], None, 8),
            Err(PipelineError::InvalidOutcome)
        ));
    }
    let mut source = link(
        protocol("inferred", ProtocolState::Negotiated),
        "uses_certificate",
        "cert",
    );
    source.evidence_kind = EvidenceKind::Inferred;
    source.inference_rule = Some("assumption:unverified".into());
    assert!(matches!(
        run(vec![source, cert("cert")], None, 8),
        Err(PipelineError::InvalidOutcome)
    ));
}

#[test]
fn orphan_hint_and_budget_overflow_fail_closed() {
    let mut incomplete = protocol("incomplete", ProtocolState::Negotiated);
    incomplete
        .attributes
        .insert("cryptomap:relation-target-event".into(), "cert".into());
    assert!(matches!(
        run(vec![incomplete, cert("cert")], None, 8),
        Err(PipelineError::InvalidOutcome)
    ));
    assert!(matches!(
        run(cross_source(), None, 0),
        Err(PipelineError::Inventory(
            cryptomap::InventoryError::LimitExceeded(_)
        ))
    ));
}
