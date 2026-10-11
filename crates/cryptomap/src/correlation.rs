//! Explicit, evidence-linked correlation of already-authorized raw events.
//!
//! Correlation is a second pass over the SAME validated invocation. It never
//! guesses relationships from matching names, profiles, or source proximity.
//! A relationship is a collector assertion, not independently verified use.
use crate::{
    AssetId, EvidenceId, EvidenceKind, InventoryBuilder, ProtocolState, Relationship,
    RelationshipId, RelationshipKind,
    pipeline::PipelineError,
    raw::{RawFactKind, RawObservation},
};
use std::collections::{BTreeMap, BTreeSet};

const KIND_KEY: &str = "cryptomap:relation-kind";
const TARGET_KEY: &str = "cryptomap:relation-target-event";

/// Resolve an exact relation name. No fuzzy aliases are supported.
fn relation_kind(value: &str) -> Option<RelationshipKind> {
    match value {
        "uses_certificate" => Some(RelationshipKind::UsesCertificate),
        "uses_key" => Some(RelationshipKind::UsesKey),
        "uses_algorithm" => Some(RelationshipKind::UsesAlgorithm),
        "depends_on" => Some(RelationshipKind::DependsOn),
        "configured_for" => Some(RelationshipKind::ConfiguredFor),
        _ => None,
    }
}

/// Gate edges by both independently observed raw fact categories and protocol
/// state. A configuration must never be promoted to runtime algorithm use.
fn compatible(kind: RelationshipKind, source: &RawFactKind, target: &RawFactKind) -> bool {
    matches!(
        (kind, source, target),
        (
            RelationshipKind::UsesCertificate,
            RawFactKind::Protocol {
                state: ProtocolState::Negotiated,
                ..
            },
            RawFactKind::Certificate { .. },
        ) | (
            RelationshipKind::UsesKey,
            RawFactKind::Protocol {
                state: ProtocolState::Negotiated,
                ..
            },
            RawFactKind::KeyReference { .. },
        ) | (
            RelationshipKind::UsesAlgorithm,
            RawFactKind::Protocol {
                state: ProtocolState::Negotiated,
                ..
            },
            RawFactKind::AlgorithmUse { .. },
        ) | (
            RelationshipKind::DependsOn,
            RawFactKind::Configuration { .. },
            RawFactKind::Dependency { .. },
        ) | (
            RelationshipKind::ConfiguredFor,
            RawFactKind::Protocol {
                state: ProtocolState::Configured,
                ..
            },
            RawFactKind::Configuration { .. },
        )
    )
}

/// Build supported edges from exact source-event references.
///
/// Both events must have already passed the same host-pinned run, collector,
/// scope, source and coverage validation. The edge's evidence is the *asserting
/// source event only*: observing a target asset is not independent confirmation
/// of the claimed relationship. Contradictory edges remain separate assertions.
pub(crate) fn link_explicit(
    builder: &mut InventoryBuilder,
    records: &BTreeMap<String, RawObservation>,
    assets: &BTreeMap<String, AssetId>,
    evidence: &BTreeMap<String, EvidenceId>,
) -> Result<(), PipelineError> {
    for (event_id, raw) in records {
        let kind_value = raw.attributes.get(KIND_KEY);
        let target_id = raw.attributes.get(TARGET_KEY);
        let (Some(kind_value), Some(target_id)) = (kind_value, target_id) else {
            if kind_value.is_some() || target_id.is_some() {
                return Err(PipelineError::InvalidOutcome);
            }
            continue;
        };
        if target_id == event_id || raw.evidence_kind != EvidenceKind::Direct {
            return Err(PipelineError::InvalidOutcome);
        }
        let kind = relation_kind(kind_value).ok_or(PipelineError::InvalidOutcome)?;
        let target = records
            .get(target_id)
            .ok_or(PipelineError::InvalidOutcome)?;
        if !compatible(kind, &raw.fact, &target.fact) {
            return Err(PipelineError::InvalidOutcome);
        }
        let from = assets.get(event_id).ok_or(PipelineError::InvalidOutcome)?;
        let to = assets.get(target_id).ok_or(PipelineError::InvalidOutcome)?;
        let supporting = evidence
            .get(event_id)
            .ok_or(PipelineError::InvalidOutcome)?;
        builder.add_relationship(Relationship {
            id: RelationshipId::from_endpoints(kind, from, to)?,
            from: from.clone(),
            to: to.clone(),
            kind,
            evidence: BTreeSet::from([supporting.clone()]),
        })?;
    }
    Ok(())
}
