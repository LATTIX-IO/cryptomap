//! Privacy-minimized inventory summaries for reporting and external review.
//!
//! This is intentionally not a lossless CBOM or a canonical cryptomap snapshot.
use crate::{InventorySnapshot,RelationshipKind};
use serde::{Deserialize,Serialize};
use std::collections::BTreeMap;

/// Privacy-minimized summary with no source paths, hostnames, key IDs, or raw observations.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct RedactedInventoryReport {
    /// Number of canonical assets.
    pub asset_count: usize,
    /// Number of evidence records.
    pub evidence_count: usize,
    /// Number of observations.
    pub observation_count: usize,
    /// Anonymized asset summaries.
    pub assets: Vec<RedactedAssetSummary>,
    /// Anonymized relationship topology.
    pub relationships: Vec<RedactedRelation>,
    /// Counts of collection coverage states.
    pub coverage_counts: BTreeMap<String,usize>,
}
/// Report-only anonymous asset label and kind.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct RedactedAssetSummary {
    /// Report-local alias, not suitable as a durable asset reference.
    pub alias: String,
    /// Canonical kind name, with metadata omitted.
    pub kind: String,
    /// Count of observations associated with the asset.
    pub observations: usize,
}
/// A report-only relationship with anonymized endpoints.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct RedactedRelation {
    /// Report-local source alias.
    pub from: String,
    /// Report-local target alias.
    pub to: String,
    /// Non-secret relationship type.
    pub kind: String,
}
impl InventorySnapshot {
    /// Produce a report that drops observed values, source paths, IDs, and key metadata.
    ///
    /// Aliases are local to one report and must not be used for correlation
    /// between exports. The report intentionally has no SnapshotId.
    pub fn redacted_report(&self) -> RedactedInventoryReport {
        let aliases: BTreeMap<_,_>=self.assets.keys().enumerate()
            .map(|(i,k)|(k.clone(),format!("asset-{:06}",i+1))).collect();
        let assets=self.assets.values().map(|a|RedactedAssetSummary{
            alias:aliases[&a.id].clone(),
            kind:a.kind.name().into(),
            observations:self.observations.values().filter(|o|o.asset==a.id).count(),
        }).collect();
        let relationships=self.relationships.values().map(|r|RedactedRelation{
            from:aliases[&r.from].clone(),
            to:aliases[&r.to].clone(),
            kind:relation_name(r.kind).into(),
        }).collect();
        let mut coverage_counts=BTreeMap::new();
        for state in self.coverage.values(){
            *coverage_counts.entry(format!("{state:?}")).or_insert(0)+=1;
        }
        for record in &self.coverage_records{
            *coverage_counts.entry(format!("{:?}",record.state)).or_insert(0)+=1;
        }
        RedactedInventoryReport{
            asset_count:self.assets.len(),evidence_count:self.evidence.len(),
            observation_count:self.observations.len(),assets,relationships,coverage_counts,
        }
    }
}
fn relation_name(kind:RelationshipKind)->&'static str{
    match kind{
        RelationshipKind::UsesAlgorithm=>"uses-algorithm",
        RelationshipKind::UsesKey=>"uses-key",
        RelationshipKind::UsesCertificate=>"uses-certificate",
        RelationshipKind::DependsOn=>"depends-on",
        RelationshipKind::ObservedAt=>"observed-at",
        RelationshipKind::ProvidedBy=>"provided-by",
        RelationshipKind::PossibleAlias=>"possible-alias",
        RelationshipKind::RelatedTo=>"related-to",
        RelationshipKind::NegotiatedAt=>"negotiated-at",
        RelationshipKind::ConfiguredFor=>"configured-for",
        RelationshipKind::StoredIn=>"stored-in",
        RelationshipKind::IssuedBy=>"issued-by",
        RelationshipKind::ValidatedBy=>"validated-by",
        RelationshipKind::Contains=>"contains",
        RelationshipKind::ImplementsProtocol=>"implements-protocol",
    }
}
