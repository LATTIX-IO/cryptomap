//! FOSS-320: a bounded, explicitly scoped raw-to-canonical vertical slice.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    CollectionRunId, CollectorId, Confidence, CoverageState, EvidenceKind, IdentityContext,
    InventoryError, InventoryLimits,
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
        id: CollectorId::new("fixture-collector").unwrap(),
        version: "1.0".into(),
        capabilities: CollectorCapabilities {
            sources: BTreeSet::from([RawSourceKind::Telemetry]),
            mode: CollectionMode::Passive,
            required_permissions: BTreeSet::new(),
            checkpoint: false,
        },
    }
}
fn source() -> RequestedSource {
    RequestedSource {
        kind: RawSourceKind::Telemetry,
        item: "stream:test".into(),
    }
}
fn raw(event: &str, name: &str) -> RawObservation {
    RawObservation {
        contract_version: 1,
        event_id: event.into(),
        collector: CollectorId::new("fixture-collector").unwrap(),
        collector_version: "1.0".into(),
        run: CollectionRunId::new("run-a").unwrap(),
        source: RawSourceLocator {
            kind: RawSourceKind::Telemetry,
            item: "stream:test".into(),
            offset: None,
            line: None,
            column: None,
        },
        observed_at: "2026-10-11T12:00:00Z".into(),
        fact: RawFactKind::AlgorithmUse {
            identifier: name.into(),
            profile: None,
            operation: Some("encrypt".into()),
        },
        evidence_kind: EvidenceKind::Direct,
        confidence: Confidence::Confirmed,
        inference_rule: None,
        source_sha256: None,
        attributes: BTreeMap::from([
            (
                "cryptomap:algorithm-namespace".into(),
                "tls_cipher_suite".into(),
            ),
            ("cryptomap:algorithm-kind".into(), "cipher_suite".into()),
        ]),
    }
}
fn outcome(records: Vec<RawObservation>) -> CollectionOutcome {
    CollectionOutcome {
        descriptor: descriptor(),
        run: CollectionRunId::new("run-a").unwrap(),
        observations: records,
        coverage: BTreeMap::from([("stream:test".into(), CoverageState::InspectedObserved)]),
        diagnostics: Vec::new(),
        status: CollectionStatus::Complete,
    }
}
fn normalize_fixture(
    scope: &CollectionScope,
    identity: &IdentityContext,
    registry: &Registry,
    data: CollectionOutcome,
) -> Result<cryptomap::InventorySnapshot, PipelineError> {
    let expected_descriptor = descriptor();
    let expected_run = CollectionRunId::new("run-a").unwrap();
    normalize(
        PipelineInput {
            scope,
            identity,
            registry,
            expected_descriptor: &expected_descriptor,
            expected_run: &expected_run,
            sources: &[source()],
            raw_limits: RawLimits::default(),
            inventory_limits: InventoryLimits::default(),
            started_at: "2026-10-11T11:59:00Z",
            ended_at: "2026-10-11T12:01:00Z",
        },
        data,
    )
}
fn setup() -> (CollectionScope, IdentityContext, Registry) {
    let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-1").unwrap());
    scope
        .grant_logical(RawSourceKind::Telemetry, "stream:test")
        .unwrap();
    (
        scope,
        IdentityContext::new("tenant-1").unwrap(),
        Registry::builtin(),
    )
}

#[test]
fn checked_algorithm_result_creates_canonical_evidence_and_coverage() {
    let (scope, identity, registry) = setup();
    let snapshot = normalize_fixture(
        &scope,
        &identity,
        &registry,
        outcome(vec![raw("event-1", "0x1301")]),
    )
    .unwrap();
    assert_eq!(snapshot.assets.len(), 1);
    assert_eq!(snapshot.evidence.len(), 1);
    assert!(
        snapshot
            .observations
            .values()
            .any(|o| o.property == "algorithm:normalized" && o.value == "TLS_AES_128_GCM_SHA256")
    );
    assert!(
        snapshot
            .observations
            .values()
            .any(|o| o.property == "algorithm:raw-identifier" && o.value == "0x1301")
    );
    assert_eq!(
        snapshot.coverage.get("stream:test"),
        Some(&CoverageState::InspectedObserved)
    );
    snapshot.verify(InventoryLimits::default()).unwrap();
}

#[test]
fn reversed_raw_record_order_produces_identical_snapshot_digest() {
    let (scope, identity, registry) = setup();
    let first = raw("event-1", "0x1301");
    let second = raw("event-2", "0x1302");
    let a = normalize_fixture(
        &scope,
        &identity,
        &registry,
        outcome(vec![first.clone(), second.clone()]),
    )
    .unwrap();
    let b = normalize_fixture(&scope, &identity, &registry, outcome(vec![second, first])).unwrap();
    assert_eq!(a.id, b.id);
    assert_eq!(a, b);
}

#[test]
fn unknown_identifier_is_not_coerced_to_a_known_profile() {
    let (scope, identity, registry) = setup();
    let snap = normalize_fixture(
        &scope,
        &identity,
        &registry,
        outcome(vec![raw("x", "0xFFFF")]),
    )
    .unwrap();
    assert!(
        snap.observations
            .values()
            .any(|o| o.property == "algorithm:normalized" && o.value.contains("unmapped:"))
    );
    assert!(
        !snap
            .observations
            .values()
            .any(|o| o.value == "TLS_AES_128_GCM_SHA256")
    );
}

#[test]
fn unauthorized_source_and_inconsistent_coverage_fail_closed() {
    let (scope, identity, registry) = setup();
    let mut wrong_source = outcome(vec![raw("event-1", "0x1301")]);
    wrong_source.observations[0].source.item = "stream:other".into();
    assert!(matches!(
        normalize_fixture(&scope, &identity, &registry, wrong_source),
        Err(PipelineError::InvalidOutcome)
    ));
    let mut inconsistent = outcome(vec![raw("event-1", "0x1301")]);
    inconsistent
        .coverage
        .insert("stream:test".into(), CoverageState::InspectedNoObservation);
    assert!(matches!(
        normalize_fixture(&scope, &identity, &registry, inconsistent),
        Err(PipelineError::InvalidOutcome)
    ));
}

#[test]
fn conflicting_replay_and_malformed_configuration_are_rejected() {
    let (scope, identity, registry) = setup();
    let conflicting = outcome(vec![raw("duplicate", "0x1301"), raw("duplicate", "0x1302")]);
    assert!(matches!(
        normalize_fixture(&scope, &identity, &registry, conflicting),
        Err(PipelineError::Inventory(
            InventoryError::DuplicateObservation(_)
        ))
    ));
    let mut malformed = raw("event-config", "0x1301");
    malformed.fact = RawFactKind::Configuration {
        property: "unnamespaced".into(),
        value: "nonsecret".into(),
    };
    assert!(matches!(
        normalize_fixture(&scope, &identity, &registry, outcome(vec![malformed])),
        Err(PipelineError::Inventory(InventoryError::InvalidMetadata))
    ));
}

#[test]
fn identity_context_cannot_cross_an_authorized_scope() {
    let (scope, _, registry) = setup();
    let foreign = IdentityContext::new("different-tenant").unwrap();
    assert!(matches!(
        normalize_fixture(
            &scope,
            &foreign,
            &registry,
            outcome(vec![raw("one", "0x1301")])
        ),
        Err(PipelineError::InvalidOutcome)
    ));
}

#[test]
fn partial_collection_keeps_unrelated_successful_evidence() {
    let (mut scope, identity, registry) = setup();
    scope
        .grant_logical(RawSourceKind::Certificate, "store:denied")
        .unwrap();
    let mut data = outcome(vec![raw("event-1", "0x1301")]);
    data.descriptor
        .capabilities
        .sources
        .insert(RawSourceKind::Certificate);
    data.coverage
        .insert("store:denied".into(), CoverageState::Failed);
    data.status = CollectionStatus::Partial;
    let sources = vec![
        source(),
        RequestedSource {
            kind: RawSourceKind::Certificate,
            item: "store:denied".into(),
        },
    ];
    let expected_descriptor = data.descriptor.clone();
    let expected_run = CollectionRunId::new("run-a").unwrap();
    let snapshot = normalize(
        PipelineInput {
            scope: &scope,
            identity: &identity,
            registry: &registry,
            expected_descriptor: &expected_descriptor,
            expected_run: &expected_run,
            sources: &sources,
            raw_limits: RawLimits::default(),
            inventory_limits: InventoryLimits::default(),
            started_at: "2026-10-11T11:59:00Z",
            ended_at: "2026-10-11T12:01:00Z",
        },
        data,
    )
    .unwrap();
    assert_eq!(snapshot.assets.len(), 1);
    assert_eq!(snapshot.evidence.len(), 1);
    assert_eq!(
        snapshot.coverage.get("store:denied"),
        Some(&CoverageState::Failed)
    );
    assert_eq!(
        snapshot.runs.values().next().unwrap().completeness,
        cryptomap::coverage::RunCompleteness::Partial
    );
}

#[test]
fn dependency_presence_does_not_infer_algorithm_execution() {
    use cryptomap::AssetKind;
    use std::fs;
    let temp = std::env::temp_dir().join(format!(
        "cryptomap-pipeline-dependency-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp).unwrap();
    fs::write(temp.join("Cargo.lock"), b"fixture").unwrap();
    let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-1").unwrap());
    scope
        .grant_file(
            RawSourceKind::Dependency,
            "lockfile-1",
            &temp,
            "Cargo.lock",
            1024,
        )
        .unwrap();
    let mut data = outcome(vec![raw("dependency-1", "0x1301")]);
    data.descriptor.capabilities.sources = BTreeSet::from([RawSourceKind::Dependency]);
    data.observations[0].source.kind = RawSourceKind::Dependency;
    data.observations[0].source.item = "lockfile-1".into();
    data.observations[0].attributes.clear();
    data.observations[0].fact = RawFactKind::Dependency {
        ecosystem: "cargo".into(),
        name: "ring".into(),
        version: "0.17.0".into(),
    };
    data.coverage = BTreeMap::from([("lockfile-1".into(), CoverageState::InspectedObserved)]);
    let sources = [RequestedSource {
        kind: RawSourceKind::Dependency,
        item: "lockfile-1".into(),
    }];
    let identity = IdentityContext::new("tenant-1").unwrap();
    let registry = Registry::builtin();
    let expected_descriptor = data.descriptor.clone();
    let expected_run = CollectionRunId::new("run-a").unwrap();
    let snapshot = normalize(
        PipelineInput {
            scope: &scope,
            identity: &identity,
            registry: &registry,
            expected_descriptor: &expected_descriptor,
            expected_run: &expected_run,
            sources: &sources,
            raw_limits: RawLimits::default(),
            inventory_limits: InventoryLimits::default(),
            started_at: "2026-10-11T11:59:00Z",
            ended_at: "2026-10-11T12:01:00Z",
        },
        data,
    )
    .unwrap();
    assert!(
        snapshot
            .assets
            .values()
            .all(|asset| matches!(asset.kind, AssetKind::Library { .. }))
    );
    assert!(
        snapshot
            .observations
            .values()
            .all(|obs| obs.property == "dependency:presence" && obs.value == "declared")
    );
    // On Windows the capability-root directory handle prevents deletion.
    // Release it before removing the temporary fixture directory.
    drop(scope);
    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn forged_run_and_collector_provenance_are_rejected() {
    let (scope, identity, registry) = setup();
    let mut forged_run = outcome(vec![raw("event", "0x1301")]);
    forged_run.run = CollectionRunId::new("forged-run").unwrap();
    forged_run.observations[0].run = forged_run.run.clone();
    assert!(matches!(
        normalize_fixture(&scope, &identity, &registry, forged_run),
        Err(PipelineError::InvalidOutcome)
    ));

    let mut forged_collector = outcome(vec![raw("event", "0x1301")]);
    forged_collector.descriptor.id = CollectorId::new("rogue-collector").unwrap();
    forged_collector.observations[0].collector = forged_collector.descriptor.id.clone();
    assert!(matches!(
        normalize_fixture(&scope, &identity, &registry, forged_collector),
        Err(PipelineError::InvalidOutcome)
    ));
}

#[test]
fn absent_location_and_explicit_zero_remain_distinct_assets() {
    let (scope, identity, registry) = setup();
    let a = raw("no-offset", "0x1301");
    let mut b = raw("zero-offset", "0x1301");
    b.source.offset = Some(0);
    let snap = normalize_fixture(&scope, &identity, &registry, outcome(vec![a, b])).unwrap();
    assert_eq!(snap.assets.len(), 2);
}

#[test]
fn partial_source_with_observations_preserves_both_facts_and_partial_status() {
    let (scope, identity, registry) = setup();
    let mut data = outcome(vec![raw("partial-one", "0x1301")]);
    data.coverage
        .insert("stream:test".into(), CoverageState::Partial);
    data.status = CollectionStatus::Failed;
    // There are no completely inspected sources, so aggregate status is
    // Failed, while the source-specific result remains Partial.
    let snap = normalize_fixture(&scope, &identity, &registry, data).unwrap();
    assert_eq!(snap.assets.len(), 1);
    assert_eq!(snap.evidence.len(), 1);
    assert_eq!(
        snap.coverage.get("stream:test"),
        Some(&CoverageState::Partial)
    );
    assert_eq!(
        snap.runs.values().next().unwrap().completeness,
        cryptomap::coverage::RunCompleteness::Failed
    );
    snap.verify(InventoryLimits::default()).unwrap();
}

#[test]
fn failed_source_with_observations_is_rejected() {
    let (scope, identity, registry) = setup();
    let mut data = outcome(vec![raw("failed-one", "0x1301")]);
    data.coverage
        .insert("stream:test".into(), CoverageState::Failed);
    data.status = CollectionStatus::Failed;
    assert!(matches!(
        normalize_fixture(&scope, &identity, &registry, data),
        Err(PipelineError::InvalidOutcome)
    ));
}

#[test]
fn conflicting_location_encoding_does_not_collapse_sources() {
    let (scope, identity, registry) = setup();
    let mut colon = raw("source-with-colon", "0x1301");
    colon.source.item = "a:1".into();
    colon.source.offset = Some(2);
    let mut plain = raw("source-without-colon", "0x1301");
    plain.source.item = "a".into();
    plain.source.offset = Some(1);
    plain.source.line = Some(2);
    // Locations with potentially ambiguous string concatenation cannot
    // collide, even when source IDs share delimiters.
    // Test the exact tuple semantics with separately authorized sources.
    let mut mixed_scope = CollectionScope::new(CollectionScopeId::new("tenant-1").unwrap());
    mixed_scope
        .grant_logical(RawSourceKind::Telemetry, "a:1")
        .unwrap();
    mixed_scope
        .grant_logical(RawSourceKind::Telemetry, "a")
        .unwrap();
    let sources = [
        RequestedSource {
            kind: RawSourceKind::Telemetry,
            item: "a:1".into(),
        },
        RequestedSource {
            kind: RawSourceKind::Telemetry,
            item: "a".into(),
        },
    ];
    let mut data = outcome(vec![colon, plain]);
    data.coverage.clear();
    data.coverage
        .insert("a:1".into(), CoverageState::InspectedObserved);
    data.coverage
        .insert("a".into(), CoverageState::InspectedObserved);
    let expected_descriptor = descriptor();
    let expected_run = CollectionRunId::new("run-a").unwrap();
    let result = normalize(
        PipelineInput {
            scope: &mixed_scope,
            identity: &identity,
            registry: &registry,
            expected_descriptor: &expected_descriptor,
            expected_run: &expected_run,
            sources: &sources,
            raw_limits: RawLimits::default(),
            inventory_limits: InventoryLimits::default(),
            started_at: "2026-10-11T11:59:00Z",
            ended_at: "2026-10-11T12:01:00Z",
        },
        data,
    )
    .unwrap();
    assert_eq!(result.assets.len(), 2);
    drop(scope);
}

#[test]
fn certificate_fingerprint_is_validated_and_canonicalized_without_certificate_body() {
    use cryptomap::AssetKind;
    let (scope, identity, registry) = setup();
    let mut uppercase = raw("cert-upper", "unused");
    uppercase.fact = RawFactKind::Certificate {
        fingerprint_sha256: "AB".repeat(32),
    };
    uppercase.attributes.clear();
    let mut lowercase = uppercase.clone();
    lowercase.event_id = "cert-lower".into();
    lowercase.fact = RawFactKind::Certificate {
        fingerprint_sha256: "ab".repeat(32),
    };
    let snap = normalize_fixture(
        &scope,
        &identity,
        &registry,
        outcome(vec![uppercase, lowercase]),
    )
    .unwrap();
    assert_eq!(snap.assets.len(), 1);
    assert_eq!(snap.evidence.len(), 2);
    assert!(snap.assets.values().all(|asset| matches!(
        &asset.kind,
        AssetKind::Certificate {
            fingerprint_sha256,
            public_key_profile: None,
            signature_profile: None
        } if fingerprint_sha256 == &"ab".repeat(32)
    )));
    assert!(snap.observations.values().all(
        |obs| obs.property == "certificate:fingerprint-sha256" && obs.value == "ab".repeat(32)
    ));
    snap.verify(InventoryLimits::default()).unwrap();
}

#[test]
fn malformed_certificate_fingerprint_fails_before_snapshot() {
    let (scope, identity, registry) = setup();
    for bad in ["abcd", &"z".repeat(64)] {
        let mut item = raw("bad-certificate", "unused");
        item.attributes.clear();
        item.fact = RawFactKind::Certificate {
            fingerprint_sha256: bad.into(),
        };
        assert!(matches!(
            normalize_fixture(&scope, &identity, &registry, outcome(vec![item])),
            Err(PipelineError::Inventory(InventoryError::InvalidMetadata))
        ));
    }
}

#[test]
fn key_reference_requires_provider_instance_and_never_sets_algorithm() {
    use cryptomap::AssetKind;
    let (scope, identity, registry) = setup();
    let mut item = raw("key-1", "unused");
    item.attributes.clear();
    item.fact = RawFactKind::KeyReference {
        provider: "external-kms".into(),
        reference: "opaque-key-id-001".into(),
    };
    assert!(matches!(
        normalize_fixture(&scope, &identity, &registry, outcome(vec![item.clone()])),
        Err(PipelineError::Inventory(
            InventoryError::InsufficientIdentity
        ))
    ));
    let pinned = identity
        .clone()
        .with_provider_instance("kms-instance-1")
        .unwrap();
    let snap = normalize_fixture(&scope, &pinned, &registry, outcome(vec![item.clone()])).unwrap();
    assert!(snap.assets.values().all(|asset| matches!(
        &asset.kind,
        AssetKind::Key {
            algorithm: None,
            provider: Some(_),
            fingerprint: Some(_)
        }
    )));
    assert!(
        snap.observations
            .values()
            .all(|o| o.property == "key:provider-reference")
    );
    let other_instance = identity.with_provider_instance("kms-instance-2").unwrap();
    let other = normalize_fixture(&scope, &other_instance, &registry, outcome(vec![item])).unwrap();
    assert_ne!(snap.assets.keys().next(), other.assets.keys().next());
}

#[test]
fn protocol_state_and_unknown_version_remain_distinct_without_inference() {
    use cryptomap::{AssetKind, ProtocolState};
    let (scope, identity, registry) = setup();
    let mut configured = raw("configured", "unused");
    configured.attributes.clear();
    configured.fact = RawFactKind::Protocol {
        family: "TLS".into(),
        version: Some("1.3".into()),
        state: ProtocolState::Configured,
    };
    let mut negotiated = configured.clone();
    negotiated.event_id = "negotiated".into();
    negotiated.fact = RawFactKind::Protocol {
        family: "TLS".into(),
        version: Some("1.3".into()),
        state: ProtocolState::Negotiated,
    };
    let mut unknown = configured.clone();
    unknown.event_id = "version-unknown".into();
    unknown.fact = RawFactKind::Protocol {
        family: "TLS".into(),
        version: None,
        state: ProtocolState::Configured,
    };
    let snap = normalize_fixture(
        &scope,
        &identity,
        &registry,
        outcome(vec![configured, negotiated, unknown]),
    )
    .unwrap();
    assert_eq!(snap.assets.len(), 3);
    assert!(snap.assets.values().any(|a| matches!(
        a.kind,
        AssetKind::Protocol {
            state: ProtocolState::Negotiated,
            ..
        }
    )));
    assert!(snap.assets.values().any(|a| matches!(
        a.kind,
        AssetKind::Protocol {
            state: ProtocolState::Configured,
            ..
        }
    )));
    assert!(snap.assets.values().any(|a| matches!(
        &a.kind,
        AssetKind::DetailedProtocol { metadata } if
            matches!(metadata.version, cryptomap::metadata::Observed::Unknown)
    )));
    assert!(
        snap.observations
            .values()
            .any(|o| o.property == "protocol:version-availability" && o.value == "unknown")
    );
}

#[test]
fn configuration_remains_source_use_and_rejects_sensitive_property() {
    use cryptomap::AssetKind;
    let (scope, identity, registry) = setup();
    let mut configured = raw("config-1", "unused");
    configured.attributes.clear();
    configured.fact = RawFactKind::Configuration {
        property: "app:tls_min_version".into(),
        value: "TLSv1.3".into(),
    };
    let snap = normalize_fixture(
        &scope,
        &identity,
        &registry,
        outcome(vec![configured.clone()]),
    )
    .unwrap();
    assert!(
        snap.assets
            .values()
            .all(|asset| matches!(asset.kind, AssetKind::SourceUse { .. }))
    );
    assert!(
        snap.observations
            .values()
            .all(|o| o.property == "app:tls_min_version" && o.value == "TLSv1.3")
    );
    configured.fact = RawFactKind::Configuration {
        property: "app:password".into(),
        value: "unredacted-example".into(),
    };
    assert!(matches!(
        normalize_fixture(&scope, &identity, &registry, outcome(vec![configured])),
        Err(PipelineError::Inventory(InventoryError::ProhibitedMaterial))
    ));
}

#[test]
fn mixed_fact_types_permute_to_identical_canonical_snapshot() {
    use cryptomap::ProtocolState;
    let (scope, identity, registry) = setup();
    let identity = identity.with_provider_instance("kms-a").unwrap();
    let mut facts = vec![
        RawFactKind::AlgorithmUse {
            identifier: "0x1301".into(),
            profile: None,
            operation: Some("encrypt".into()),
        },
        RawFactKind::Dependency {
            ecosystem: "cargo".into(),
            name: "rustls".into(),
            version: "0.23.0".into(),
        },
        RawFactKind::Certificate {
            fingerprint_sha256: "ad".repeat(32),
        },
        RawFactKind::KeyReference {
            provider: "kms".into(),
            reference: "key-42".into(),
        },
        RawFactKind::Protocol {
            family: "TLS".into(),
            version: Some("1.3".into()),
            state: ProtocolState::Negotiated,
        },
        RawFactKind::Configuration {
            property: "app:crypto_preference".into(),
            value: "TLSv1.3".into(),
        },
    ];
    let mut records = Vec::new();
    for (index, fact) in facts.drain(..).enumerate() {
        let mut r = raw(&format!("mixed-{index}"), "0x1301");
        r.fact = fact;
        r.source.offset = Some(index as u64);
        records.push(r);
    }
    let mut reverse = records.clone();
    reverse.reverse();
    let a = normalize_fixture(&scope, &identity, &registry, outcome(records)).unwrap();
    let b = normalize_fixture(&scope, &identity, &registry, outcome(reverse)).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.assets.len(), 6);
    assert_eq!(a.evidence.len(), 6);
    a.verify(InventoryLimits::default()).unwrap();
}

#[test]
fn opaque_key_references_preserve_case_sensitive_identity() {
    let (scope, identity, registry) = setup();
    let identity = identity.with_provider_instance("kms-scope-a").unwrap();
    let mut first = raw("key-uppercase", "unused");
    first.attributes.clear();
    first.fact = RawFactKind::KeyReference {
        provider: "kms".into(),
        reference: "Key-ABC".into(),
    };
    let mut second = first.clone();
    second.event_id = "key-lowercase".into();
    second.fact = RawFactKind::KeyReference {
        provider: "kms".into(),
        reference: "key-abc".into(),
    };
    let snapshot = normalize_fixture(
        &scope, &identity, &registry, outcome(vec![first, second])
    ).unwrap();
    assert_eq!(snapshot.assets.len(), 2);
    assert!(snapshot.observations.values().any(|o| o.value == "Key-ABC"));
    assert!(snapshot.observations.values().any(|o| o.value == "key-abc"));
    snapshot.verify(InventoryLimits::default()).unwrap();
}
