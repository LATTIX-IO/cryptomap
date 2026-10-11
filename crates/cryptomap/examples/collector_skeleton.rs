//! Example of a third-party collector implementation.
//!
//! Run with: cargo run --example collector_skeleton
use cryptomap::{
    CollectionRunId, CollectorId, Confidence, CoverageState, EvidenceKind, InventoryError,
    collector::{
        self, COLLECTOR_CONTRACT_VERSION, CancellationToken, CollectionMode, CollectionRequest,
        CollectionSink, Collector, CollectorCapabilities, CollectorDescriptor, RequestedSource,
    },
    raw::{
        RAW_CONTRACT_VERSION, RawFactKind, RawLimits, RawObservation, RawSourceKind,
        RawSourceLocator,
    },
};
use std::collections::{BTreeMap, BTreeSet};

struct ExampleCollector;
impl Collector for ExampleCollector {
    fn descriptor(&self) -> CollectorDescriptor {
        CollectorDescriptor {
            contract_version: COLLECTOR_CONTRACT_VERSION,
            id: CollectorId::new("example-dependencies").expect("valid static ID"),
            version: "1.0".into(),
            capabilities: CollectorCapabilities {
                sources: BTreeSet::from([RawSourceKind::Dependency]),
                mode: CollectionMode::Passive,
                required_permissions: BTreeSet::new(),
                checkpoint: false,
            },
        }
    }
    fn collect(
        &self,
        req: &CollectionRequest,
        sink: &mut CollectionSink,
        _: &CancellationToken,
    ) -> Result<(), InventoryError> {
        // No actual filesystem read occurs in this mock. A real collector must
        // obtain authorization from its host BEFORE attempting any I/O.
        for source in &req.sources {
            let fact = RawObservation {
                contract_version: RAW_CONTRACT_VERSION,
                event_id: format!("fixture:{}", source.item),
                collector: self.descriptor().id,
                collector_version: "1.0".into(),
                run: req.run.clone(),
                source: RawSourceLocator {
                    kind: source.kind.clone(),
                    item: source.item.clone(),
                    offset: None,
                    line: None,
                    column: None,
                },
                observed_at: "2026-10-10T00:00:00Z".into(),
                fact: RawFactKind::Dependency {
                    ecosystem: "cargo".into(),
                    name: "openssl".into(),
                    version: "0.10".into(),
                },
                evidence_kind: EvidenceKind::Inferred,
                confidence: Confidence::Low,
                inference_rule: Some("synthetic-fixture-v1".into()),
                source_sha256: None,
                attributes: BTreeMap::new(),
            };
            sink.emit(fact)?;
            sink.cover(&source.item, CoverageState::InspectedObserved)?;
        }
        Ok(())
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let request = CollectionRequest {
        run: CollectionRunId::new("example-run")?,
        sources: vec![RequestedSource {
            kind: RawSourceKind::Dependency,
            item: "fixture/Cargo.lock".into(),
        }],
        limits: RawLimits::default(),
        options: BTreeMap::new(),
    };
    let output = collector::collect(&ExampleCollector, request, &CancellationToken::default())?;
    println!(
        "{} raw observations, status {:?}",
        output.observations.len(),
        output.status
    );
    Ok(())
}
