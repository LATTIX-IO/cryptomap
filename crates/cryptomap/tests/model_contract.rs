//! Typed metadata, scope, conflict, query and security integration tests.
// Integration fixtures use unwrap to express required successful preconditions.
#![allow(clippy::unwrap_used)]
use cryptomap::validation::utc_seconds;
use cryptomap::*;
use std::collections::{BTreeMap, BTreeSet};

fn id(s: &str) -> AssetId {
    AssetId::new(s).unwrap()
}
fn asset(k: AssetKind, name: &str) -> Asset {
    Asset {
        id: id(name),
        kind: k,
        extensions: BTreeMap::new(),
    }
}
fn library(name: &str) -> Asset {
    asset(
        AssetKind::Library {
            ecosystem: "cargo".into(),
            name: name.into(),
            version: "1.0".into(),
        },
        name,
    )
}
fn run(idstr: &str, source: &str) -> CollectionRun {
    CollectionRun {
        id: CollectionRunId::new(idstr).unwrap(),
        collector: CollectorId::new("collector").unwrap(),
        collector_version: "1.0".into(),
        scope: CollectionScopeId::new("org-prod").unwrap(),
        requested: BTreeSet::from([source.into()]),
        started_at: "2026-10-08T00:00:00Z".into(),
        ended_at: "2026-10-08T04:00:00Z".into(),
        completeness: RunCompleteness::Partial,
    }
}
fn ev(idstr: &str, run_id: &str, time: &str, conf: Confidence) -> Evidence {
    Evidence {
        id: EvidenceId::new(idstr).unwrap(),
        collector: CollectorId::new("collector").unwrap(),
        collector_version: "1.0".into(),
        run: CollectionRunId::new(run_id).unwrap(),
        source: "unit-test".into(),
        observed_at: time.into(),
        kind: EvidenceKind::Direct,
        confidence: conf,
        source_sha256: None,
        inference_rule: None,
    }
}
fn obs(idstr: &str, ev_id: &str, value: &str) -> Observation {
    Observation {
        id: ObservationId::new(idstr).unwrap(),
        asset: id("app"),
        evidence: EvidenceId::new(ev_id).unwrap(),
        property: "protocol:negotiated".into(),
        context: None,
        value: value.into(),
    }
}
fn make(with_second: bool) -> InventorySnapshot {
    let mut b = InventoryBuilder::new();
    b.add_run(run("r1", "app")).unwrap();
    b.add_asset(library("app")).unwrap();
    b.add_evidence(ev("e1", "r1", "2026-10-08T01:00:00Z", Confidence::High))
        .unwrap();
    b.add_observation(obs("o1", "e1", "TLS1.2")).unwrap();
    if with_second {
        b.add_evidence(ev(
            "e2",
            "r1",
            "2026-10-08T01:10:00Z",
            Confidence::Confirmed,
        ))
        .unwrap();
        b.add_observation(obs("o2", "e2", "TLS1.3")).unwrap();
    }
    b.set_coverage("app", CoverageState::Partial);
    b.finalize(InventoryLimits::default()).unwrap()
}
#[test]
fn type_specific_identity_is_stable_and_scoped() {
    let a = IdentityContext::new("tenant-a").unwrap();
    let b = IdentityContext::new("tenant-b").unwrap();
    let left = AssetKind::Endpoint {
        transport: "TCP".into(),
        host: "EXAMPLE.com.".into(),
        port: 443,
        scope: "prod".into(),
    };
    let right = AssetKind::Endpoint {
        transport: "tcp".into(),
        host: "example.COM".into(),
        port: 443,
        scope: "prod".into(),
    };
    assert_eq!(
        AssetId::from_kind(&left, &a).unwrap(),
        AssetId::from_kind(&right, &a).unwrap()
    );
    assert_ne!(
        AssetId::from_kind(&left, &a).unwrap(),
        AssetId::from_kind(&right, &b).unwrap()
    );
    let x = AssetKind::AlgorithmUse {
        family: "AES".into(),
        profile: Some("GCM".into()),
        use_site: "src/a.rs:4".into(),
    };
    let y = AssetKind::AlgorithmUse {
        family: "AES".into(),
        profile: Some("GCM".into()),
        use_site: "src/b.rs:4".into(),
    };
    assert_ne!(
        AssetId::from_kind(&x, &a).unwrap(),
        AssetId::from_kind(&y, &a).unwrap()
    );
    let incomplete = AssetKind::Key {
        provider: Some("kms".into()),
        fingerprint: None,
        algorithm: None,
    };
    assert!(AssetId::from_kind(&incomplete, &a).is_err());
    let key = AssetKind::Key {
        provider: Some("kms".into()),
        fingerprint: Some("abc".into()),
        algorithm: None,
    };
    assert_ne!(
        AssetId::from_kind(
            &key,
            &a.clone().with_provider_instance("instance-1").unwrap()
        )
        .unwrap(),
        AssetId::from_kind(&key, &a.with_provider_instance("instance-2").unwrap()).unwrap()
    );
}
#[test]
fn timestamp_validation_and_timezone() {
    assert_eq!(
        utc_seconds("2026-10-08T01:00:00Z").unwrap(),
        utc_seconds("2026-10-07T21:00:00-04:00").unwrap()
    );
    for bad in [
        "2026-02-29T00:00:00Z",
        "2026-13-08T00:00:00Z",
        "2026-10-08T25:00:00Z",
        "2026-10-08T00:00:60Z",
        "2026-10-08T01:00:00",
        "2026-10-08T01:00:00+25:00",
    ] {
        assert!(utc_seconds(bad).is_err(), "{bad}");
    }
    assert!(utc_seconds("2024-02-29T00:00:00Z").is_ok());
}
#[test]
fn contexts_preserve_history_and_detect_actual_conflicts() {
    let same = make(true);
    assert_eq!(same.conflicts.len(), 1);
    assert_eq!(same.conflicts.values().next().unwrap().values.len(), 2);
    let mut b = InventoryBuilder::new();
    b.add_run(run("r1", "app")).unwrap();
    b.add_asset(library("app")).unwrap();
    b.add_evidence(ev("e1", "r1", "2026-10-08T01:00:00Z", Confidence::High))
        .unwrap();
    b.add_evidence(ev("e2", "r1", "2026-10-08T03:00:00Z", Confidence::High))
        .unwrap();
    b.add_observation(obs("o1", "e1", "TLS1.2")).unwrap();
    b.add_observation(obs("o2", "e2", "TLS1.3")).unwrap();
    assert!(
        b.finalize(InventoryLimits::default())
            .unwrap()
            .conflicts
            .is_empty()
    );
}
#[test]
fn import_detects_tampering_and_schema_mismatch() {
    let original = make(false);
    let mut modified = original.clone();
    modified
        .assets
        .get_mut(&id("app"))
        .unwrap()
        .extensions
        .insert("source:owner".into(), "infra".into());
    assert!(matches!(
        modified.verify(InventoryLimits::default()),
        Err(InventoryError::DigestMismatch)
    ));
    let json = serde_json::to_string(&original).unwrap();
    assert_eq!(
        InventorySnapshot::from_json_verified(&json, InventoryLimits::default()).unwrap(),
        original
    );
    assert!(
        InventorySnapshot::from_json_verified(
            &json,
            InventoryLimits {
                snapshot_bytes: 10,
                ..InventoryLimits::default()
            }
        )
        .is_err()
    );
    let mut wrong_version = original.clone();
    wrong_version.schema_version = 999;
    assert!(matches!(
        wrong_version.verify(InventoryLimits::default()),
        Err(InventoryError::UnsupportedSchema(999))
    ));
}
#[test]
fn changeset_detects_new_evidence_and_confidence() {
    let first = make(false);
    let second = make(true);
    let delta = first.diff(&second);
    assert!(
        delta
            .observations_added
            .contains(&ObservationId::new("o2").unwrap())
    );
    assert!(
        delta
            .evidence_added
            .contains(&EvidenceId::new("e2").unwrap())
    );
    assert_eq!(delta.conflicts_introduced.len(), 1);
    let mut altered = first.clone();
    altered
        .evidence
        .get_mut(&EvidenceId::new("e1").unwrap())
        .unwrap()
        .confidence = Confidence::Confirmed;
    assert!(
        first
            .diff(&altered)
            .confidence_changed
            .contains(&EvidenceId::new("e1").unwrap())
    );
}
#[test]
fn typed_query_and_graph_traversal() {
    let mut b = InventoryBuilder::new();
    b.add_asset(library("app")).unwrap();
    b.add_asset(library("lib")).unwrap();
    b.add_relationship(Relationship {
        id: RelationshipId::new("dep").unwrap(),
        from: id("app"),
        to: id("lib"),
        kind: RelationshipKind::DependsOn,
        evidence: BTreeSet::new(),
    })
    .unwrap();
    let snapshot = b.finalize(InventoryLimits::default()).unwrap();
    assert_eq!(snapshot.query().kind("library").ids(5).unwrap().len(), 2);
    assert_eq!(
        snapshot.query().package("cargo", "app").ids(5).unwrap(),
        vec![id("app")]
    );
    assert!(
        snapshot
            .traverse(&id("app"), Some(RelationshipKind::DependsOn), 3, 10)
            .unwrap()
            .contains(&id("lib"))
    );
    assert!(snapshot.traverse(&id("app"), None, 3, 1).is_err());
}
#[test]
fn secret_payloads_and_invalid_relationships_are_rejected() {
    let mut a = library("app");
    a.extensions.insert(
        "auth:private-key".into(),
        "-----BEGIN PRIVATE KEY-----".into(),
    );
    let mut b = InventoryBuilder::new();
    b.add_asset(a).unwrap();
    assert!(matches!(
        b.finalize(InventoryLimits::default()),
        Err(InventoryError::ProhibitedMaterial)
    ));
    let mut c = InventoryBuilder::new();
    c.add_asset(library("app")).unwrap();
    c.add_asset(library("other")).unwrap();
    c.add_relationship(Relationship {
        id: RelationshipId::new("r").unwrap(),
        from: id("app"),
        to: id("other"),
        kind: RelationshipKind::UsesKey,
        evidence: BTreeSet::new(),
    })
    .unwrap();
    assert!(matches!(
        c.finalize(InventoryLimits::default()),
        Err(InventoryError::InvalidMetadata)
    ));
}
#[test]
fn coverage_cannot_claim_complete_when_sources_failed() {
    let mut run = run("r1", "app");
    run.completeness = RunCompleteness::Complete;
    let mut b = InventoryBuilder::new();
    b.add_run(run).unwrap();
    b.add_coverage_record(CoverageRecord {
        run: CollectionRunId::new("r1").unwrap(),
        source_item: "app".into(),
        state: CoverageState::Failed,
        reason_code: Some("timeout".into()),
    });
    assert!(b.finalize(InventoryLimits::default()).is_err());
}

#[test]
fn redacted_reports_do_not_expose_sensitive_inventory_metadata() {
    let mut builder = InventoryBuilder::new();
    builder
        .add_asset(Asset {
            id: AssetId::new("secret-internal-hostname").unwrap(),
            kind: AssetKind::Endpoint {
                transport: "tcp".into(),
                host: "internal.secret.example".into(),
                port: 443,
                scope: "private-network".into(),
            },
            extensions: BTreeMap::new(),
        })
        .unwrap();
    builder.set_coverage("internal.secret.example", CoverageState::InspectedObserved);
    let snapshot = builder.finalize(InventoryLimits::default()).unwrap();
    let view = snapshot.redacted_report();
    let rendered = serde_json::to_string(&view).unwrap();
    assert_eq!(view.asset_count, 1);
    assert!(!rendered.contains("internal.secret.example"));
    assert!(!rendered.contains("private-network"));
    assert!(!rendered.contains("secret-internal-hostname"));
    assert!(!rendered.contains(&snapshot.id.to_string()));
}

#[test]
fn complete_collection_requires_a_coverage_record_for_every_requested_item() {
    let mut completed = run("complete", "file1");
    completed.completeness = RunCompleteness::Complete;
    let mut invalid = InventoryBuilder::new();
    invalid.add_run(completed.clone()).unwrap();
    assert!(matches!(
        invalid.finalize(InventoryLimits::default()),
        Err(InventoryError::InvalidMetadata)
    ));

    let mut valid = InventoryBuilder::new();
    valid.add_run(completed).unwrap();
    valid.add_coverage_record(CoverageRecord {
        run: CollectionRunId::new("complete").unwrap(),
        source_item: "file1".into(),
        state: CoverageState::InspectedNoObservation,
        reason_code: None,
    });
    assert!(valid.finalize(InventoryLimits::default()).is_ok());
}

#[test]
fn evidence_collector_must_match_declared_collection_run() {
    let mut builder = InventoryBuilder::new();
    builder.add_run(run("r1", "file1")).unwrap();
    let mut mismatched = ev("e1", "r1", "2026-10-08T01:00:00Z", Confidence::High);
    mismatched.collector = CollectorId::new("unrelated").unwrap();
    builder.add_evidence(mismatched).unwrap();
    assert!(matches!(
        builder.finalize(InventoryLimits::default()),
        Err(InventoryError::InvalidMetadata)
    ));
}

#[test]
fn multiple_configured_capabilities_and_distinct_sessions_are_not_conflicts() {
    let mut b = InventoryBuilder::new();
    b.add_run(run("r1", "app")).unwrap();
    b.add_asset(library("app")).unwrap();
    b.add_evidence(ev("e1", "r1", "2026-10-08T01:00:00Z", Confidence::High))
        .unwrap();
    b.add_evidence(ev("e2", "r1", "2026-10-08T01:01:00Z", Confidence::High))
        .unwrap();
    let mut a = obs("o1", "e1", "TLS_AES_128_GCM_SHA256");
    a.property = "protocol:configured".into();
    let mut c = obs("o2", "e2", "TLS_AES_256_GCM_SHA384");
    c.property = "protocol:configured".into();
    b.add_observation(a).unwrap();
    b.add_observation(c).unwrap();
    assert!(
        b.finalize(InventoryLimits::default())
            .unwrap()
            .conflicts
            .is_empty()
    );

    let mut b = InventoryBuilder::new();
    b.add_run(run("r1", "app")).unwrap();
    b.add_asset(library("app")).unwrap();
    b.add_evidence(ev("e1", "r1", "2026-10-08T01:00:00Z", Confidence::High))
        .unwrap();
    b.add_evidence(ev("e2", "r1", "2026-10-08T01:01:00Z", Confidence::High))
        .unwrap();
    let mut a = obs("o1", "e1", "TLS1.2");
    let mut c = obs("o2", "e2", "TLS1.3");
    a.context = Some("connection-a".into());
    c.context = Some("connection-b".into());
    b.add_observation(a).unwrap();
    b.add_observation(c).unwrap();
    assert!(
        b.finalize(InventoryLimits::default())
            .unwrap()
            .conflicts
            .is_empty()
    );
}

#[test]
fn endpoint_identity_matches_cross_platform_v2_golden_vector() {
    let context = IdentityContext::new("tenant-a").unwrap();
    let endpoint = AssetKind::Endpoint {
        transport: "TCP".into(),
        host: "EXAMPLE.com.".into(),
        port: 443,
        scope: "prod".into(),
    };
    let id = AssetId::from_kind(&endpoint, &context).unwrap();
    assert_eq!(
        id.as_str(),
        "asset:v2:85e78bf3a84092d09e219bd9d48e082aeb5d093afa28e098b66c0af76f66d0d3"
    );
}

#[test]
fn a_new_complete_scan_of_only_a_subset_cannot_confirm_removal() {
    fn snapshot(assets: &[&str], coverage: &[&str]) -> InventorySnapshot {
        let mut builder = InventoryBuilder::new();
        for name in assets {
            builder.add_asset(library(name)).unwrap();
        }
        for name in coverage {
            builder.set_coverage(*name, CoverageState::InspectedObserved);
        }
        builder.finalize(InventoryLimits::default()).unwrap()
    }
    let old = snapshot(&["a", "b"], &["file-a", "file-b"]);
    let subset = snapshot(&["a"], &["file-a"]);
    let delta = old.diff(&subset);
    assert!(delta.removed.is_empty());
    assert!(delta.tentative_removed.contains(&id("b")));

    let fully_inspected = snapshot(&["a"], &["file-a", "file-b"]);
    let delta = old.diff(&fully_inspected);
    assert!(delta.removed.contains(&id("b")));
    assert!(delta.tentative_removed.is_empty());
}

#[test]
fn duplicate_json_keys_are_rejected_before_snapshot_verification() {
    let snapshot = make(false);
    let json = serde_json::to_string(&snapshot).unwrap();
    let duplicate_header = json.replacen(
        "\"schema_version\":2",
        "\"schema_version\":2,\"schema_version\":2",
        1,
    );
    assert_ne!(duplicate_header, json);
    assert!(matches!(
        InventorySnapshot::from_json_verified(&duplicate_header, InventoryLimits::default()),
        Err(InventoryError::Encoding(_))
    ));

    let duplicate_nested = json.replacen(
        "\"extensions\":{",
        "\"extensions\":{\"source:tag\":\"safe\",\"source:tag\":\"evil\",",
        1,
    );
    assert_ne!(duplicate_nested, json);
    assert!(matches!(
        InventorySnapshot::from_json_verified(&duplicate_nested, InventoryLimits::default()),
        Err(InventoryError::Encoding(_))
    ));
}

#[test]
fn case_sensitive_source_use_sites_never_merge() {
    let context = IdentityContext::new("tenant-a").unwrap();
    let upper = AssetKind::AlgorithmUse {
        family: "AES".into(),
        profile: Some("GCM".into()),
        use_site: "src/Crypto.rs:22".into(),
    };
    let lower = AssetKind::AlgorithmUse {
        family: "aes".into(),
        profile: Some("gcm".into()),
        use_site: "src/crypto.rs:22".into(),
    };
    assert_ne!(
        AssetId::from_kind(&upper, &context).unwrap(),
        AssetId::from_kind(&lower, &context).unwrap()
    );
}

#[test]
fn certificate_reconciliation_preserves_independent_collector_provenance() {
    let context = IdentityContext::new("prod").unwrap();
    let fingerprint = "a".repeat(64);
    let cert_kind = AssetKind::Certificate {
        fingerprint_sha256: fingerprint,
        public_key_profile: Some("RSA-3072".into()),
        signature_profile: Some("SHA256-RSA".into()),
    };
    let mut builder = InventoryBuilder::new();
    let mut file_run = run("file-run", "certificate.pem");
    file_run.collector = CollectorId::new("filesystem").unwrap();
    let mut tls_run = run("tls-run", "tls://service.example:443");
    tls_run.collector = CollectorId::new("tls").unwrap();
    builder.add_run(file_run).unwrap();
    builder.add_run(tls_run).unwrap();

    let from_file = builder
        .ingest_candidate(cert_kind.clone(), &context, BTreeMap::new())
        .unwrap();
    let from_tls = builder
        .ingest_candidate(cert_kind, &context, BTreeMap::new())
        .unwrap();
    assert_eq!(from_file, from_tls);

    let mut first = ev(
        "file-evidence",
        "file-run",
        "2026-10-08T00:30:00Z",
        Confidence::High,
    );
    first.collector = CollectorId::new("filesystem").unwrap();
    first.source = "certificate.pem".into();
    let mut second = ev(
        "tls-evidence",
        "tls-run",
        "2026-10-08T00:31:00Z",
        Confidence::Confirmed,
    );
    second.collector = CollectorId::new("tls").unwrap();
    second.source = "tls://service.example:443".into();
    builder.add_evidence(first).unwrap();
    builder.add_evidence(second).unwrap();

    for (observation_id, evidence_id) in
        [("file-obs", "file-evidence"), ("tls-obs", "tls-evidence")]
    {
        builder
            .add_observation(Observation {
                id: ObservationId::new(observation_id).unwrap(),
                asset: from_file.clone(),
                evidence: EvidenceId::new(evidence_id).unwrap(),
                property: "certificate:fingerprint".into(),
                context: None,
                value: "a".repeat(64),
            })
            .unwrap();
    }
    let snapshot = builder.finalize(InventoryLimits::default()).unwrap();
    assert_eq!(snapshot.assets.len(), 1);
    assert_eq!(snapshot.observations_for(&from_file).count(), 2);
    assert_eq!(snapshot.evidence.len(), 2);
    assert_eq!(snapshot.conflicts.len(), 0);
    let json = serde_json::to_string(&snapshot).unwrap();
    assert_eq!(
        InventorySnapshot::from_json_verified(&json, InventoryLimits::default()).unwrap(),
        snapshot
    );
}

#[test]
fn incompatible_metadata_cannot_be_silently_merged_under_the_same_id() {
    let context = IdentityContext::new("prod").unwrap();
    let mut builder = InventoryBuilder::new();
    let first = AssetKind::Certificate {
        fingerprint_sha256: "a".repeat(64),
        public_key_profile: Some("RSA-3072".into()),
        signature_profile: None,
    };
    let incompatible = AssetKind::Certificate {
        fingerprint_sha256: "a".repeat(64),
        public_key_profile: Some("EC-P256".into()),
        signature_profile: None,
    };
    builder
        .ingest_candidate(first, &context, BTreeMap::new())
        .unwrap();
    assert!(
        builder
            .ingest_candidate(incompatible, &context, BTreeMap::new())
            .is_err()
    );
}

#[test]
fn matching_relationships_accumulate_independent_evidence() {
    let mut builder=InventoryBuilder::new();
    builder.add_run(run("r1","app")).unwrap();
    builder.add_asset(library("app")).unwrap();
    builder.add_asset(library("lib")).unwrap();
    builder.add_evidence(ev("first","r1","2026-10-08T01:00:00Z",Confidence::High)).unwrap();
    builder.add_evidence(ev("second","r1","2026-10-08T01:01:00Z",Confidence::Confirmed)).unwrap();
    let key=RelationshipId::from_endpoints(RelationshipKind::DependsOn,&id("app"),&id("lib")).unwrap();
    let backwards=RelationshipId::from_endpoints(RelationshipKind::DependsOn,&id("lib"),&id("app")).unwrap();
    assert_ne!(key,backwards);

    for evidence in ["first","second"] {
        builder.add_relationship(Relationship{
            id:key.clone(), from:id("app"), to:id("lib"),
            kind:RelationshipKind::DependsOn,
            evidence:BTreeSet::from([EvidenceId::new(evidence).unwrap()]),
        }).unwrap();
    }
    let snapshot=builder.finalize(InventoryLimits::default()).unwrap();
    assert_eq!(snapshot.relationships.len(),1);
    assert_eq!(snapshot.relationships[&key].evidence.len(),2);
    snapshot.verify(InventoryLimits::default()).unwrap();
}
