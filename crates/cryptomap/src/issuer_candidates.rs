//! B5.6 bounded issuer-*candidate* matching over authenticated B5.5 raw records.
//!
//! DN equality does not establish a signature, issuance, trust path or anchor.
//! The caller must first have validated the entire host-authorized collection
//! outcome and the same host-owned B5.5 record receipts.

use crate::{
    AssetId, Confidence, CoverageState, Evidence, EvidenceId, EvidenceKind, InventoryBuilder,
    InventoryLimits, Relationship, RelationshipId, RelationshipKind,
    certificate_identity::CertificateIdentityAuthority,
    pipeline::PipelineError,
    raw::{RawFactKind, RawLimits, RawObservation},
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const RULE: &str = "x509:issuer-candidate:v1";
const NAMESPACE: &str = "x509:identity:v1:namespace";
const SUBJECT: &str = "x509:identity:v1:subject-dn";
const ISSUER: &str = "x509:identity:v1:issuer-dn";

/// Finite upper bounds independent of the caller's general inventory budgets.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CandidateLimits {
    pub(crate) certificates: usize,
    pub(crate) fanout: usize,
    pub(crate) pair_checks: usize,
    pub(crate) edges: usize,
    pub(crate) traversal_depth: usize,
}

impl Default for CandidateLimits {
    fn default() -> Self {
        Self {
            certificates: 1024,
            fanout: 32,
            pair_checks: 8192,
            edges: 1024,
            traversal_depth: 16,
        }
    }
}

/// Inputs already authenticated and bounded by the host-owned normalizer.
pub(crate) struct CandidateInput<'a> {
    pub(crate) records: &'a BTreeMap<String, RawObservation>,
    pub(crate) assets: &'a BTreeMap<String, AssetId>,
    pub(crate) evidence: &'a BTreeMap<String, EvidenceId>,
    pub(crate) authority: &'a CertificateIdentityAuthority,
    pub(crate) raw_limits: RawLimits,
    pub(crate) inventory_limits: InventoryLimits,
    pub(crate) limits: CandidateLimits,
    pub(crate) collection_complete: bool,
    pub(crate) run: &'a crate::CollectionRunId,
}

struct Node<'a> {
    namespace: &'a str,
    subject: Option<&'a str>,
    issuer: Option<&'a str>,
    record: &'a RawObservation,
    evidence: BTreeSet<EvidenceId>,
}

fn valid_token(token: &str) -> bool {
    token.strip_prefix("hmac-sha256:v1:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

// None means a bounded search could not establish that the edge is acyclic.
// Fail closed rather than treating resource exhaustion as an absent path.
fn creates_cycle(
    graph: &BTreeMap<AssetId, BTreeSet<AssetId>>,
    child: &AssetId,
    issuer: &AssetId,
    limits: CandidateLimits,
) -> Option<bool> {
    let mut pending = vec![(issuer.clone(), 0usize)];
    let mut visited = BTreeSet::new();
    while let Some((current, depth)) = pending.pop() {
        if !visited.insert(current.clone()) {
            continue;
        }
        if visited.len() > limits.pair_checks {
            return None;
        }
        if &current == child {
            return Some(true);
        }
        if let Some(neighbors) = graph.get(&current) {
            if depth >= limits.traversal_depth && !neighbors.is_empty() {
                return None;
            }
            for neighbor in neighbors.iter().rev() {
                pending.push((neighbor.clone(), depth + 1));
            }
        }
    }
    Some(false)
}

/// Match authenticated event references from exactly one already-validated run.
///
/// The ordinary normalization path never invokes this code without a host-owned
/// authority. All inferred edges have explicit inferred evidence and preserve
/// direct provenance of both endpoints. A scoped coverage marker is separate
/// from the original source-collection coverage and cannot upgrade its state.
pub(crate) fn link_issuer_candidates(
    builder: &mut InventoryBuilder,
    input: CandidateInput<'_>,
) -> Result<(), PipelineError> {
    let CandidateInput {
        records,
        assets,
        evidence,
        authority,
        raw_limits,
        inventory_limits,
        limits,
        collection_complete,
        run,
    } = input;
    let marker = format!("{RULE}:{}", run.as_str());
    let max_records = limits.certificates.min(raw_limits.observations);
    let max_edges = limits.edges.min(inventory_limits.relationships);
    let cert_count = records
        .values()
        .filter(|raw| matches!(raw.fact, RawFactKind::Certificate { .. }))
        .count();
    if cert_count == 0 {
        builder.set_coverage(
            marker,
            if collection_complete {
                CoverageState::NotInspected
            } else {
                CoverageState::Partial
            },
        );
        return Ok(());
    }
    if cert_count > max_records {
        builder.set_coverage(marker, CoverageState::Partial);
        return Ok(());
    }

    let mut nodes: BTreeMap<AssetId, Node<'_>> = BTreeMap::new();
    let mut incomplete = false;
    for (event, raw) in records {
        if !matches!(raw.fact, RawFactKind::Certificate { .. }) {
            continue;
        }
        let subject = raw.attributes.get(SUBJECT).map(String::as_str);
        let issuer = raw.attributes.get(ISSUER).map(String::as_str);
        if subject.is_none() && issuer.is_none() {
            // Unsupported or uncollected identity is unknown, not negative.
            incomplete = true;
            continue;
        }
        if !authority.verify_record(raw) {
            return Err(PipelineError::InvalidOutcome);
        }
        let namespace = raw
            .attributes
            .get(NAMESPACE)
            .map(String::as_str)
            .ok_or(PipelineError::InvalidOutcome)?;
        if !valid_token(namespace)
            || subject.is_some_and(|token| !valid_token(token))
            || issuer.is_some_and(|token| !valid_token(token))
        {
            return Err(PipelineError::InvalidOutcome);
        }
        if subject.is_none() || issuer.is_none() {
            incomplete = true;
        }
        let asset = assets.get(event).ok_or(PipelineError::InvalidOutcome)?;
        let direct = evidence.get(event).ok_or(PipelineError::InvalidOutcome)?;
        if let Some(previous) = nodes.get_mut(asset) {
            if previous.namespace != namespace
                || previous.subject != subject
                || previous.issuer != issuer
            {
                return Err(PipelineError::InvalidOutcome);
            }
            previous.evidence.insert(direct.clone());
        } else {
            nodes.insert(
                asset.clone(),
                Node {
                    namespace,
                    subject,
                    issuer,
                    record: raw,
                    evidence: BTreeSet::from([direct.clone()]),
                },
            );
        }
    }
    if nodes.is_empty() {
        builder.set_coverage(marker, CoverageState::Partial);
        return Ok(());
    }

    let mut index: BTreeMap<(&str, &str), BTreeSet<AssetId>> = BTreeMap::new();
    for (id, node) in &nodes {
        if let Some(subject) = node.subject {
            index
                .entry((node.namespace, subject))
                .or_default()
                .insert(id.clone());
        }
    }

    let mut graph: BTreeMap<AssetId, BTreeSet<AssetId>> = BTreeMap::new();
    let mut pairs = 0usize;
    let mut edges = 0usize;
    let mut partial = incomplete || !collection_complete;
    for (child_id, child) in &nodes {
        let Some(issuer_token) = child.issuer else {
            continue;
        };
        let Some(candidates) = index.get(&(child.namespace, issuer_token)) else {
            continue;
        };
        let viable = candidates.iter().filter(|id| *id != child_id).count();
        if viable > limits.fanout {
            partial = true;
            continue;
        }
        for issuer_id in candidates {
            if child_id == issuer_id {
                // Self-issued does not imply self-signed.
                continue;
            }
            if pairs >= limits.pair_checks || edges >= max_edges {
                partial = true;
                break;
            }
            pairs += 1;
            match creates_cycle(&graph, child_id, issuer_id, limits) {
                Some(false) => {}
                Some(true) | None => {
                    partial = true;
                    continue;
                }
            }
            let issuer = nodes.get(issuer_id).ok_or(PipelineError::InvalidOutcome)?;
            let serialized = serde_json::to_vec(&(RULE, child_id, issuer_id, run))
                .map_err(|_| PipelineError::InvalidOutcome)?;
            let inferred_id =
                EvidenceId::new(format!("evidence:v1:{:x}", Sha256::digest(serialized)))?;
            let raw = child.record;
            builder.add_evidence(Evidence {
                id: inferred_id.clone(),
                collector: raw.collector.clone(),
                collector_version: raw.collector_version.clone(),
                run: raw.run.clone(),
                source: format!("{:?}:{}", raw.source.kind, raw.source.item),
                observed_at: raw.observed_at.clone(),
                kind: EvidenceKind::Inferred,
                confidence: Confidence::Low,
                source_sha256: None,
                inference_rule: Some(RULE.to_owned()),
            })?;
            let mut backing = child.evidence.clone();
            backing.extend(issuer.evidence.iter().cloned());
            backing.insert(inferred_id);
            builder.add_relationship(Relationship {
                id: RelationshipId::from_endpoints(
                    RelationshipKind::RelatedTo,
                    child_id,
                    issuer_id,
                )?,
                from: child_id.clone(),
                to: issuer_id.clone(),
                kind: RelationshipKind::RelatedTo,
                evidence: backing,
            })?;
            graph
                .entry(child_id.clone())
                .or_default()
                .insert(issuer_id.clone());
            edges += 1;
        }
    }

    builder.set_coverage(
        marker,
        if partial {
            CoverageState::Partial
        } else if edges > 0 {
            CoverageState::InspectedObserved
        } else {
            CoverageState::InspectedNoObservation
        },
    );
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{
        Asset, AssetKind, CollectionRunId, CollectionScopeId, CollectorId,
        coverage::{CollectionRun, CoverageRecord, RunCompleteness},
        raw::{RAW_CONTRACT_VERSION, RawSourceKind, RawSourceLocator},
    };

    const AT: &str = "2026-10-18T12:00:00Z";

    fn authority(tenant: &str, version: &str, key: u8) -> CertificateIdentityAuthority {
        CertificateIdentityAuthority::new(
            CollectionScopeId::new("candidate-scope").unwrap(),
            tenant,
            version,
            [key; 32],
        )
        .unwrap()
    }

    fn token(value: char) -> String {
        format!("hmac-sha256:v1:{}", value.to_string().repeat(64))
    }

    fn record(
        auth: &CertificateIdentityAuthority,
        event: &str,
        fingerprint: char,
        subject: Option<char>,
        issuer: Option<char>,
    ) -> RawObservation {
        let mut attributes = BTreeMap::new();
        if let Some(subject) = subject {
            attributes.insert(SUBJECT.into(), token(subject));
        }
        if let Some(issuer) = issuer {
            attributes.insert(ISSUER.into(), token(issuer));
        }
        let mut raw = RawObservation {
            contract_version: RAW_CONTRACT_VERSION,
            event_id: event.into(),
            collector: CollectorId::new("candidate-unit").unwrap(),
            collector_version: "1".into(),
            run: CollectionRunId::new("run-candidate").unwrap(),
            source: RawSourceLocator {
                kind: RawSourceKind::Certificate,
                item: "unit-source".into(),
                offset: None,
                line: None,
                column: None,
            },
            observed_at: AT.into(),
            fact: RawFactKind::Certificate {
                fingerprint_sha256: fingerprint.to_string().repeat(64),
            },
            evidence_kind: EvidenceKind::Direct,
            confidence: Confidence::High,
            inference_rule: None,
            source_sha256: None,
            attributes,
        };
        auth.seal_record(&mut raw).unwrap();
        raw
    }

    fn correlate(
        auth: &CertificateIdentityAuthority,
        observations: Vec<RawObservation>,
        limits: CandidateLimits,
    ) -> Result<crate::InventorySnapshot, PipelineError> {
        correlate_with_completeness(auth, observations, limits, true)
    }

    fn correlate_with_completeness(
        auth: &CertificateIdentityAuthority,
        observations: Vec<RawObservation>,
        limits: CandidateLimits,
        collection_complete: bool,
    ) -> Result<crate::InventorySnapshot, PipelineError> {
        let mut builder = InventoryBuilder::new();
        let run = CollectionRunId::new("run-candidate").unwrap();
        builder.add_run(CollectionRun {
            id: run.clone(),
            collector: CollectorId::new("candidate-unit").unwrap(),
            collector_version: "1".into(),
            scope: CollectionScopeId::new("candidate-scope").unwrap(),
            requested: BTreeSet::from(["unit-source".into()]),
            started_at: AT.into(),
            ended_at: AT.into(),
            completeness: if collection_complete {
                RunCompleteness::Complete
            } else {
                RunCompleteness::Partial
            },
        })?;
        builder.add_coverage_record(CoverageRecord {
            run: run.clone(),
            source_item: "unit-source".into(),
            state: if collection_complete {
                CoverageState::InspectedObserved
            } else {
                CoverageState::Partial
            },
            reason_code: None,
        });
        builder.set_coverage(
            "unit-source",
            if collection_complete {
                CoverageState::InspectedObserved
            } else {
                CoverageState::Partial
            },
        );
        let mut records = BTreeMap::new();
        let mut assets = BTreeMap::new();
        let mut evidences = BTreeMap::new();
        for raw in observations {
            raw.validate(&RawLimits::default())?;
            let RawFactKind::Certificate { fingerprint_sha256 } = &raw.fact else {
                panic!("certificate fixture required");
            };
            let asset = AssetId::new(format!("asset:{}", fingerprint_sha256)).unwrap();
            let direct = EvidenceId::new(format!("evidence:{}", raw.event_id)).unwrap();
            builder.add_asset(Asset {
                id: asset.clone(),
                kind: AssetKind::Certificate {
                    fingerprint_sha256: fingerprint_sha256.clone(),
                    public_key_profile: None,
                    signature_profile: None,
                },
                extensions: BTreeMap::new(),
            })?;
            builder.add_evidence(Evidence {
                id: direct.clone(),
                collector: raw.collector.clone(),
                collector_version: raw.collector_version.clone(),
                run: raw.run.clone(),
                source: "Certificate:unit-source".into(),
                observed_at: raw.observed_at.clone(),
                kind: EvidenceKind::Direct,
                confidence: Confidence::High,
                source_sha256: None,
                inference_rule: None,
            })?;
            assets.insert(raw.event_id.clone(), asset);
            evidences.insert(raw.event_id.clone(), direct);
            records.insert(raw.event_id.clone(), raw);
        }
        link_issuer_candidates(
            &mut builder,
            CandidateInput {
                records: &records,
                assets: &assets,
                evidence: &evidences,
                authority: auth,
                raw_limits: RawLimits::default(),
                inventory_limits: InventoryLimits::default(),
                limits,
                collection_complete,
                run: &run,
            },
        )?;
        Ok(builder.finalize(InventoryLimits::default())?)
    }

    fn status(snapshot: &crate::InventorySnapshot) -> CoverageState {
        snapshot.coverage["x509:issuer-candidate:v1:run-candidate"]
    }

    #[test]
    fn leaf_matches_issuer_only_as_inferred_related_to() {
        let auth = authority("tenant", "v1", 7);
        let rows = vec![
            record(&auth, "root", 'a', Some('a'), Some('a')),
            record(&auth, "leaf", 'b', Some('b'), Some('a')),
        ];
        let snapshot = correlate(&auth, rows, CandidateLimits::default()).unwrap();
        assert_eq!(snapshot.relationships.len(), 1);
        assert_eq!(status(&snapshot), CoverageState::InspectedObserved);
        let relation = snapshot.relationships.values().next().unwrap();
        assert_eq!(relation.kind, RelationshipKind::RelatedTo);
        assert!(relation.from.as_str().contains(&"b".repeat(64)));
        assert!(relation.to.as_str().contains(&"a".repeat(64)));
        assert_eq!(relation.evidence.len(), 3);
        assert_eq!(
            snapshot
                .evidence
                .values()
                .filter(|e| e.kind == EvidenceKind::Inferred)
                .count(),
            1
        );
        assert!(snapshot.evidence.values().any(|e| {
            e.kind == EvidenceKind::Inferred
                && e.inference_rule.as_deref() == Some(RULE)
                && e.confidence == Confidence::Low
        }));
        assert!(snapshot.relationships.values().all(|r| {
            r.kind != RelationshipKind::IssuedBy && r.kind != RelationshipKind::ValidatedBy
        }));
    }

    #[test]
    fn ambiguous_candidates_and_duplicate_source_evidence_are_preserved() {
        let auth = authority("tenant", "v1", 7);
        let rows = vec![
            record(&auth, "root-a", 'a', Some('a'), Some('d')),
            record(&auth, "root-b", 'c', Some('a'), Some('d')),
            record(&auth, "duplicate-root", 'a', Some('a'), Some('d')),
            record(&auth, "leaf", 'b', Some('b'), Some('a')),
        ];
        let snapshot = correlate(&auth, rows, CandidateLimits::default()).unwrap();
        assert_eq!(snapshot.relationships.len(), 2);
        let root_a = snapshot
            .relationships
            .values()
            .find(|r| r.to.as_str().contains(&"a".repeat(64)))
            .unwrap();
        assert_eq!(root_a.evidence.len(), 4);
        assert_eq!(status(&snapshot), CoverageState::InspectedObserved);
    }

    #[test]
    fn tampered_receipt_and_wrong_tenant_key_cannot_create_candidates() {
        let auth = authority("tenant-a", "v1", 7);
        let rows = vec![
            record(&auth, "issuer", 'a', Some('a'), Some('c')),
            record(&auth, "leaf", 'b', Some('b'), Some('a')),
        ];
        let wrong = authority("tenant-b", "v1", 7);
        assert!(matches!(
            correlate(&wrong, rows.clone(), CandidateLimits::default()),
            Err(PipelineError::InvalidOutcome)
        ));
        let wrong_version = authority("tenant-a", "v2", 7);
        assert!(matches!(
            correlate(&wrong_version, rows.clone(), CandidateLimits::default()),
            Err(PipelineError::InvalidOutcome)
        ));
        let mut altered = rows;
        altered[1].attributes.insert(ISSUER.into(), token('c'));
        assert!(matches!(
            correlate(&auth, altered, CandidateLimits::default()),
            Err(PipelineError::InvalidOutcome)
        ));
    }

    #[test]
    fn fanout_pair_and_edge_budgets_report_partial_not_a_false_negative() {
        let auth = authority("tenant", "v1", 7);
        let rows = vec![
            record(&auth, "issuer-a", 'a', Some('a'), Some('d')),
            record(&auth, "issuer-b", 'c', Some('a'), Some('d')),
            record(&auth, "leaf", 'b', Some('b'), Some('a')),
        ];
        let max_fanout = CandidateLimits {
            fanout: 1,
            ..CandidateLimits::default()
        };
        let partial = correlate(&auth, rows.clone(), max_fanout).unwrap();
        assert_eq!(partial.relationships.len(), 0);
        assert_eq!(status(&partial), CoverageState::Partial);
        let limited_pairs = CandidateLimits {
            pair_checks: 1,
            ..CandidateLimits::default()
        };
        let partial = correlate(&auth, rows.clone(), limited_pairs).unwrap();
        assert_eq!(partial.relationships.len(), 1);
        assert_eq!(status(&partial), CoverageState::Partial);
        let limited_edges = CandidateLimits {
            edges: 1,
            ..CandidateLimits::default()
        };
        let partial = correlate(&auth, rows, limited_edges).unwrap();
        assert_eq!(partial.relationships.len(), 1);
        assert_eq!(status(&partial), CoverageState::Partial);
    }

    #[test]
    fn cycles_and_self_issued_do_not_become_verified_issuance() {
        let auth = authority("tenant", "v1", 7);
        let rows = vec![
            record(&auth, "a", 'a', Some('a'), Some('b')),
            record(&auth, "b", 'b', Some('b'), Some('a')),
        ];
        let snapshot = correlate(&auth, rows, CandidateLimits::default()).unwrap();
        assert_eq!(snapshot.relationships.len(), 1);
        assert_eq!(status(&snapshot), CoverageState::Partial);
        assert!(snapshot.relationships.values().all(|r| r.from != r.to));
    }

    #[test]
    fn unsupported_pseudonyms_are_partial_and_cannot_be_clean_absence() {
        let auth = authority("tenant", "v1", 7);
        let rows = vec![
            record(&auth, "unknown", 'a', None, None),
            record(&auth, "leaf", 'b', Some('b'), Some('a')),
        ];
        let snapshot = correlate(&auth, rows, CandidateLimits::default()).unwrap();
        assert_eq!(snapshot.relationships.len(), 0);
        assert_eq!(status(&snapshot), CoverageState::Partial);
    }

    #[test]
    fn incomplete_collection_is_never_promoted_to_clean_candidate_coverage() {
        let auth = authority("tenant", "v1", 7);
        let rows = vec![
            record(&auth, "issuer", 'a', Some('a'), Some('c')),
            record(&auth, "leaf", 'b', Some('b'), Some('a')),
        ];
        let snapshot =
            correlate_with_completeness(&auth, rows, CandidateLimits::default(), false).unwrap();
        assert_eq!(snapshot.relationships.len(), 1);
        assert_eq!(status(&snapshot), CoverageState::Partial);
        assert_eq!(snapshot.coverage["unit-source"], CoverageState::Partial);
    }

    #[test]
    fn repeated_input_order_is_deterministic() {
        let auth = authority("tenant", "v1", 7);
        let mut rows = vec![
            record(&auth, "root", 'a', Some('a'), Some('c')),
            record(&auth, "leaf", 'b', Some('b'), Some('a')),
        ];
        let one = correlate(&auth, rows.clone(), CandidateLimits::default()).unwrap();
        rows.reverse();
        let two = correlate(&auth, rows, CandidateLimits::default()).unwrap();
        assert_eq!(one, two);
    }
}
