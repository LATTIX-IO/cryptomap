//! Multi-collector normalization, provenance isolation and deterministic reconciliation.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    AssetKind, CollectionRunId, CollectorId, Confidence, CoverageState, EvidenceKind,
    IdentityContext, InventoryError, InventoryLimits, RunCompleteness,
    batch::{BatchLimits, BatchRun, normalize_batch},
    collector::{
        COLLECTOR_CONTRACT_VERSION, CollectionMode, CollectionOutcome, CollectionStatus,
        CollectorCapabilities, CollectorDescriptor, RequestedSource,
    },
    coverage::CollectionScopeId,
    pipeline::{PipelineError, PipelineInput},
    raw::{RawFactKind, RawLimits, RawObservation, RawSourceKind, RawSourceLocator},
    registry::Registry,
    scope::CollectionScope,
};
use std::collections::{BTreeMap, BTreeSet};

struct Fixture {
    scope: CollectionScope,
    identity: IdentityContext,
    registry: Registry,
    descriptor: CollectorDescriptor,
    run: CollectionRunId,
    sources: Vec<RequestedSource>,
}
impl Fixture {
    fn new(tenant: &str, run: &str, collector: &str, sources: &[(RawSourceKind, &str)]) -> Self {
        let mut scope = CollectionScope::new(CollectionScopeId::new(tenant).unwrap());
        let mut requested = Vec::new();
        let mut supported = BTreeSet::new();
        for (kind, source) in sources {
            scope.grant_logical(kind.clone(), *source).unwrap();
            supported.insert(kind.clone());
            requested.push(RequestedSource {
                kind: kind.clone(),
                item: (*source).into(),
            });
        }
        Self {
            scope,
            identity: IdentityContext::new(tenant)
                .unwrap()
                .with_provider_instance(format!("provider:{collector}"))
                .unwrap(),
            registry: Registry::builtin(),
            descriptor: CollectorDescriptor {
                contract_version: COLLECTOR_CONTRACT_VERSION,
                id: CollectorId::new(collector).unwrap(),
                version: "1.0".into(),
                capabilities: CollectorCapabilities {
                    sources: supported,
                    mode: CollectionMode::Passive,
                    required_permissions: BTreeSet::new(),
                    checkpoint: false,
                },
            },
            run: CollectionRunId::new(run).unwrap(),
            sources: requested,
        }
    }
    fn observation(&self, event: &str, source: &str, fact: RawFactKind) -> RawObservation {
        let kind = self
            .sources
            .iter()
            .find(|s| s.item == source)
            .unwrap()
            .kind
            .clone();
        let mut attributes = BTreeMap::new();
        if matches!(fact, RawFactKind::AlgorithmUse { .. }) {
            attributes.insert(
                "cryptomap:algorithm-namespace".into(),
                "tls_cipher_suite".into(),
            );
            attributes.insert("cryptomap:algorithm-kind".into(), "cipher_suite".into());
        }
        RawObservation {
            contract_version: 1,
            event_id: event.into(),
            collector: self.descriptor.id.clone(),
            collector_version: self.descriptor.version.clone(),
            run: self.run.clone(),
            source: RawSourceLocator {
                kind,
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
            attributes,
        }
    }
    fn input<'a>(&'a self, outcome: CollectionOutcome) -> BatchRun<'a> {
        BatchRun {
            input: PipelineInput {
                scope: &self.scope,
                identity: &self.identity,
                registry: &self.registry,
                expected_descriptor: &self.descriptor,
                expected_run: &self.run,
                sources: &self.sources,
                raw_limits: RawLimits::default(),
                inventory_limits: InventoryLimits::default(),
                started_at: "2026-10-11T11:59:00Z",
                ended_at: "2026-10-11T12:01:00Z",
            },
            outcome,
        }
    }
    fn outcome(
        &self,
        observations: Vec<RawObservation>,
        coverage: BTreeMap<String, CoverageState>,
    ) -> CollectionOutcome {
        let successful = coverage
            .values()
            .filter(|s| {
                matches!(
                    s,
                    CoverageState::InspectedObserved | CoverageState::InspectedNoObservation
                )
            })
            .count();
        let status = if successful == coverage.len() {
            CollectionStatus::Complete
        } else if successful > 0 {
            CollectionStatus::Partial
        } else {
            CollectionStatus::Failed
        };
        CollectionOutcome {
            descriptor: self.descriptor.clone(),
            run: self.run.clone(),
            observations,
            coverage,
            diagnostics: Vec::new(),
            status,
        }
    }
}
fn cert() -> RawFactKind {
    RawFactKind::Certificate {
        fingerprint_sha256: "ab".repeat(32),
    }
}
fn state(item: &str, coverage: CoverageState) -> BTreeMap<String, CoverageState> {
    BTreeMap::from([(item.into(), coverage)])
}
fn fixture_pair() -> (Fixture, Fixture) {
    (
        Fixture::new(
            "tenant-a",
            "run-A",
            "collector-telemetry",
            &[(RawSourceKind::Telemetry, "shared")],
        ),
        Fixture::new(
            "tenant-a",
            "run-B",
            "collector-certificate",
            &[(RawSourceKind::Certificate, "shared")],
        ),
    )
}

#[test]
fn heterogeneous_collectors_with_same_source_name_preserve_run_coverage() {
    let (a, b) = fixture_pair();
    let result = normalize_batch(
        vec![
            a.input(a.outcome(
                vec![a.observation("same-event", "shared", cert())],
                state("shared", CoverageState::InspectedObserved),
            )),
            b.input(b.outcome(
                vec![b.observation("same-event", "shared", cert())],
                state("shared", CoverageState::InspectedObserved),
            )),
        ],
        BatchLimits::default(),
    )
    .unwrap();
    assert_eq!(result.assets.len(), 1);
    assert_eq!(result.evidence.len(), 2);
    assert_eq!(result.observations.len(), 2);
    assert_eq!(result.runs.len(), 2);
    assert_eq!(result.coverage_records.len(), 2);
    // Do not pollute legacy coverage with ephemeral run-derived keys;
    // the typed records hold the authoritative run+source tuple.
    assert!(result.coverage.is_empty());
    let distinct: BTreeSet<_> = result
        .coverage_records
        .iter()
        .map(|r| (&r.run, &r.source_item))
        .collect();
    assert_eq!(distinct.len(), 2);
    assert!(
        result
            .assets
            .values()
            .all(|asset| matches!(asset.kind, AssetKind::Certificate { .. }))
    );
    result.verify(InventoryLimits::default()).unwrap();
}

#[test]
fn permutation_of_collector_completion_order_is_digest_invariant() {
    let (a, b) = fixture_pair();
    let o1 = a.outcome(
        vec![a.observation("same-event", "shared", cert())],
        state("shared", CoverageState::InspectedObserved),
    );
    let o2 = b.outcome(
        vec![b.observation("same-event", "shared", cert())],
        state("shared", CoverageState::InspectedObserved),
    );
    let first = normalize_batch(
        vec![a.input(o1.clone()), b.input(o2.clone())],
        BatchLimits::default(),
    )
    .unwrap();
    let reversed = normalize_batch(vec![b.input(o2), a.input(o1)], BatchLimits::default()).unwrap();
    assert_eq!(first, reversed);
    assert_eq!(first.id, reversed.id);
}

#[test]
fn failed_and_partial_runs_do_not_erase_successful_assets_or_claim_complete() {
    let (good, failed) = fixture_pair();
    let partial = Fixture::new(
        "tenant-a",
        "run-C",
        "collector-partial",
        &[
            (RawSourceKind::Telemetry, "stream:observed"),
            (RawSourceKind::Telemetry, "stream:failed"),
        ],
    );
    let output = normalize_batch(
        vec![
            good.input(good.outcome(
                vec![good.observation("good", "shared", cert())],
                state("shared", CoverageState::InspectedObserved),
            )),
            failed.input(failed.outcome(vec![], state("shared", CoverageState::Failed))),
            partial.input(partial.outcome(
                vec![partial.observation(
                    "partial",
                    "stream:observed",
                    RawFactKind::Dependency {
                        ecosystem: "cargo".into(),
                        name: "rustls".into(),
                        version: "0.23".into(),
                    },
                )],
                BTreeMap::from([
                    ("stream:observed".into(), CoverageState::InspectedObserved),
                    ("stream:failed".into(), CoverageState::Failed),
                ]),
            )),
        ],
        BatchLimits::default(),
    )
    .unwrap();
    assert_eq!(output.runs.len(), 3);
    assert_eq!(output.assets.len(), 2);
    assert_eq!(output.coverage_records.len(), 4);
    assert_eq!(
        output.runs[&good.run].completeness,
        RunCompleteness::Complete
    );
    assert_eq!(
        output.runs[&failed.run].completeness,
        RunCompleteness::Failed
    );
    assert_eq!(
        output.runs[&partial.run].completeness,
        RunCompleteness::Partial
    );
    output.verify(InventoryLimits::default()).unwrap();
}

#[test]
fn duplicate_run_ids_and_cross_tenant_scope_are_rejected() {
    let (a, _) = fixture_pair();
    let duplicate = Fixture::new(
        "tenant-a",
        "run-A",
        "other-collector",
        &[(RawSourceKind::Telemetry, "shared")],
    );
    let o1 = a.outcome(
        vec![a.observation("a", "shared", cert())],
        state("shared", CoverageState::InspectedObserved),
    );
    let o2 = duplicate.outcome(
        vec![duplicate.observation("a", "shared", cert())],
        state("shared", CoverageState::InspectedObserved),
    );
    assert!(matches!(
        normalize_batch(
            vec![a.input(o1.clone()), duplicate.input(o2)],
            BatchLimits::default()
        ),
        Err(PipelineError::InvalidOutcome)
    ));
    let foreign = Fixture::new(
        "tenant-b",
        "run-B",
        "other-collector",
        &[(RawSourceKind::Telemetry, "shared")],
    );
    let foreign_outcome = foreign.outcome(
        vec![foreign.observation("a", "shared", cert())],
        state("shared", CoverageState::InspectedObserved),
    );
    assert!(matches!(
        normalize_batch(
            vec![a.input(o1), foreign.input(foreign_outcome)],
            BatchLimits::default()
        ),
        Err(PipelineError::InvalidOutcome)
    ));
}

#[test]
fn authorization_and_forged_provenance_fail_closed() {
    let (a, b) = fixture_pair();
    let mut forged = b.outcome(
        vec![b.observation("forged", "shared", cert())],
        state("shared", CoverageState::InspectedObserved),
    );
    forged.run = CollectionRunId::new("forged").unwrap();
    assert!(matches!(
        normalize_batch(
            vec![
                a.input(a.outcome(vec![], state("shared", CoverageState::Failed))),
                b.input(forged)
            ],
            BatchLimits::default()
        ),
        Err(PipelineError::InvalidOutcome)
    ));
    let mut unauthorized = a.outcome(
        vec![a.observation("event", "shared", cert())],
        state("shared", CoverageState::InspectedObserved),
    );
    unauthorized.observations[0].source.item = "not-granted".into();
    assert!(matches!(
        normalize_batch(vec![a.input(unauthorized)], BatchLimits::default()),
        Err(PipelineError::InvalidOutcome)
    ));
}

#[test]
fn aggregate_run_source_observation_and_byte_budgets_reject_before_merge() {
    let (a, b) = fixture_pair();
    let o1 = a.outcome(
        vec![a.observation("one", "shared", cert())],
        state("shared", CoverageState::InspectedObserved),
    );
    let o2 = b.outcome(
        vec![b.observation("two", "shared", cert())],
        state("shared", CoverageState::InspectedObserved),
    );
    for limits in [
        BatchLimits {
            runs: 1,
            ..BatchLimits::default()
        },
        BatchLimits {
            sources: 1,
            ..BatchLimits::default()
        },
        BatchLimits {
            observations: 1,
            ..BatchLimits::default()
        },
        BatchLimits {
            raw_bytes: 1,
            ..BatchLimits::default()
        },
    ] {
        assert!(matches!(
            normalize_batch(vec![a.input(o1.clone()), b.input(o2.clone())], limits),
            Err(PipelineError::Inventory(InventoryError::LimitExceeded(_)))
        ));
    }
    let constrained = BatchLimits {
        inventory: InventoryLimits {
            evidence: 1,
            ..InventoryLimits::default()
        },
        ..BatchLimits::default()
    };
    assert!(matches!(
        normalize_batch(vec![a.input(o1), b.input(o2)], constrained),
        Err(PipelineError::Inventory(InventoryError::LimitExceeded(_)))
    ));
}

#[test]
fn structurally_invalid_run_is_not_mislabeled_as_valid_partial_failure() {
    let (a, b) = fixture_pair();
    let valid = a.outcome(
        vec![a.observation("one", "shared", cert())],
        state("shared", CoverageState::InspectedObserved),
    );
    let invalid = b.outcome(
        vec![b.observation("other", "shared", cert())],
        state("shared", CoverageState::Failed),
    );
    assert!(matches!(
        normalize_batch(
            vec![a.input(valid), b.input(invalid)],
            BatchLimits::default()
        ),
        Err(PipelineError::InvalidOutcome)
    ));
}

#[test]
fn relinking_by_event_id_across_run_boundaries_is_not_allowed() {
    use cryptomap::ProtocolState;
    let a = Fixture::new(
        "tenant-a",
        "run-A",
        "protocol",
        &[(RawSourceKind::Telemetry, "protocol")],
    );
    let b = Fixture::new(
        "tenant-a",
        "run-B",
        "certificate",
        &[(RawSourceKind::Certificate, "certificate")],
    );
    let mut protocol = a.observation(
        "protocol",
        "protocol",
        RawFactKind::Protocol {
            family: "TLS".into(),
            version: Some("1.3".into()),
            state: ProtocolState::Negotiated,
        },
    );
    protocol
        .attributes
        .insert("cryptomap:relation-kind".into(), "uses_certificate".into());
    protocol
        .attributes
        .insert("cryptomap:relation-target-event".into(), "cert".into());
    let remote = b.observation("cert", "certificate", cert());
    assert!(matches!(
        normalize_batch(
            vec![
                a.input(a.outcome(
                    vec![protocol],
                    state("protocol", CoverageState::InspectedObserved)
                )),
                b.input(b.outcome(
                    vec![remote],
                    state("certificate", CoverageState::InspectedObserved)
                )),
            ],
            BatchLimits::default()
        ),
        Err(PipelineError::InvalidOutcome)
    ));
}

#[test]
fn independently_asserted_edges_union_evidence_across_runs_only_for_same_identity() {
    use cryptomap::{ProtocolState, RelationshipKind};
    let sources = [
        (RawSourceKind::Telemetry, "stream:tls"),
        (RawSourceKind::Certificate, "store:cert"),
    ];
    // Same collector and exact source site but different run IDs: canonical
    // protocol and certificate identities converge, run evidence does not.
    let a = Fixture::new("tenant-a", "run-A", "tls-collector", &sources);
    let b = Fixture::new("tenant-a", "run-B", "tls-collector", &sources);
    let build = |fixture: &Fixture| {
        let mut asserted = fixture.observation(
            "protocol",
            "stream:tls",
            RawFactKind::Protocol {
                family: "TLS".into(),
                version: Some("1.3".into()),
                state: ProtocolState::Negotiated,
            },
        );
        asserted
            .attributes
            .insert("cryptomap:relation-kind".into(), "uses_certificate".into());
        asserted.attributes.insert(
            "cryptomap:relation-target-event".into(),
            "certificate".into(),
        );
        fixture.outcome(
            vec![
                asserted,
                fixture.observation("certificate", "store:cert", cert()),
            ],
            BTreeMap::from([
                ("stream:tls".into(), CoverageState::InspectedObserved),
                ("store:cert".into(), CoverageState::InspectedObserved),
            ]),
        )
    };
    let out_a = build(&a);
    let out_b = build(&b);
    let merged = normalize_batch(
        vec![b.input(out_b.clone()), a.input(out_a.clone())],
        BatchLimits::default(),
    )
    .unwrap();
    assert_eq!(merged.assets.len(), 2);
    assert_eq!(merged.evidence.len(), 4);
    assert_eq!(merged.relationships.len(), 1);
    let edge = merged.relationships.values().next().unwrap();
    assert_eq!(edge.kind, RelationshipKind::UsesCertificate);
    assert_eq!(edge.evidence.len(), 2);
    assert_eq!(merged.coverage_records.len(), 4);
    merged.verify(InventoryLimits::default()).unwrap();

    let limited = BatchLimits {
        inventory: InventoryLimits {
            relationships: 0,
            ..InventoryLimits::default()
        },
        ..BatchLimits::default()
    };
    assert!(matches!(
        normalize_batch(vec![a.input(out_a), b.input(out_b)], limited),
        Err(PipelineError::Inventory(InventoryError::LimitExceeded(_)))
    ));
}

#[test]
fn matching_profile_and_certificate_without_explicit_assertion_create_no_edge() {
    use cryptomap::ProtocolState;
    let fixture = Fixture::new(
        "tenant-a",
        "run-unlinked",
        "tls-collector",
        &[
            (RawSourceKind::Telemetry, "stream:tls"),
            (RawSourceKind::Certificate, "store:cert"),
        ],
    );
    let outcome = fixture.outcome(
        vec![
            fixture.observation(
                "protocol",
                "stream:tls",
                RawFactKind::Protocol {
                    family: "TLS".into(),
                    version: Some("1.3".into()),
                    state: ProtocolState::Negotiated,
                },
            ),
            fixture.observation("certificate", "store:cert", cert()),
        ],
        BTreeMap::from([
            ("stream:tls".into(), CoverageState::InspectedObserved),
            ("store:cert".into(), CoverageState::InspectedObserved),
        ]),
    );
    let snapshot = normalize_batch(vec![fixture.input(outcome)], BatchLimits::default()).unwrap();
    assert!(snapshot.relationships.is_empty());
    snapshot.verify(InventoryLimits::default()).unwrap();
}

#[test]
fn reinspection_with_fresh_run_ids_has_stable_coverage_and_confirmed_evidence_removal() {
    let before = Fixture::new(
        "tenant-a",
        "old-run",
        "collector-telemetry",
        &[(RawSourceKind::Telemetry, "shared")],
    );
    let after = Fixture::new(
        "tenant-a",
        "new-run",
        "collector-telemetry",
        &[(RawSourceKind::Telemetry, "shared")],
    );
    let previous = normalize_batch(
        vec![before.input(before.outcome(
            vec![before.observation("event", "shared", cert())],
            state("shared", CoverageState::InspectedObserved),
        ))],
        BatchLimits::default(),
    )
    .unwrap();
    let current = normalize_batch(
        vec![after.input(after.outcome(
            vec![after.observation("event", "shared", cert())],
            state("shared", CoverageState::InspectedObserved),
        ))],
        BatchLimits::default(),
    )
    .unwrap();
    let changes = previous.diff(&current);
    assert!(changes.coverage_changed.is_empty());
    assert!(changes.evidence_tentative_removed.is_empty());
    assert!(changes.observations_tentative_removed.is_empty());
    assert_eq!(changes.evidence_removed.len(), 1);
    assert_eq!(changes.observations_removed.len(), 1);
    assert!(changes.tentative_removed.is_empty());
    assert!(previous.coverage.is_empty() && current.coverage.is_empty());
}

#[test]
fn partial_reinspection_does_not_confirm_missing_prior_evidence() {
    let before = Fixture::new(
        "tenant-a",
        "old-run",
        "collector-telemetry",
        &[(RawSourceKind::Telemetry, "shared")],
    );
    let after = Fixture::new(
        "tenant-a",
        "new-run",
        "collector-telemetry",
        &[(RawSourceKind::Telemetry, "shared")],
    );
    let old = normalize_batch(
        vec![before.input(before.outcome(
            vec![before.observation("event", "shared", cert())],
            state("shared", CoverageState::InspectedObserved),
        ))],
        BatchLimits::default(),
    )
    .unwrap();
    let new = normalize_batch(
        vec![after.input(after.outcome(vec![], state("shared", CoverageState::Failed)))],
        BatchLimits::default(),
    )
    .unwrap();
    let diff = old.diff(&new);
    assert_eq!(diff.evidence_tentative_removed.len(), 1);
    assert!(diff.evidence_removed.is_empty());
    assert_eq!(diff.tentative_removed.len(), 1);
}
