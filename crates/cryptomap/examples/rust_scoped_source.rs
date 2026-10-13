//! Collect one explicitly granted Rust source file into a verified inventory.
//!
//! Usage: cargo run --locked --features rust-source --example rust_scoped_source --
//!   ROOT RELATIVE-FILE RFC3339-TIME TENANT-SCOPE RUN-ID
//! This is passive syntactic evidence, not proof of algorithm execution.
use cryptomap::{
    AssetKind, CollectionRunId, IdentityContext, InventoryLimits,
    collector::{CancellationToken, Collector, RequestedSource},
    collectors::source::rust::{MAX_RUST_SOURCE_BYTES, RustSourceCollector},
    coverage::CollectionScopeId,
    orchestration::{ScopedInvocation, collect_normalized},
    pipeline::PipelineInput,
    raw::{RawLimits, RawSourceKind},
    registry::Registry,
    scope::CollectionScope,
};
use std::{error::Error, path::Path};

/// Authorize one exact Rust file; no recursion, Cargo invocation or network access.
pub fn run_source(
    root: &Path,
    relative: &Path,
    observed_at: &str,
    tenant_scope: &str,
    run_id: &str,
) -> Result<cryptomap::InventorySnapshot, Box<dyn Error>> {
    let mut scope = CollectionScope::new(CollectionScopeId::new(tenant_scope)?);
    let source_item = "source:rust-file";
    scope.grant_file(
        RawSourceKind::Source,
        source_item,
        root,
        relative,
        MAX_RUST_SOURCE_BYTES,
    )?;
    let collector = RustSourceCollector::new(&scope, observed_at);
    let expected_descriptor = collector.descriptor();
    let expected_run = CollectionRunId::new(run_id)?;
    let identity = IdentityContext::new(scope.id().as_str())?;
    let registry = Registry::builtin();
    let sources = vec![RequestedSource {
        kind: RawSourceKind::Source,
        item: source_item.into(),
    }];
    let inventory_limits = InventoryLimits::default();
    let snapshot = collect_normalized(
        ScopedInvocation {
            collector: &collector,
            input: PipelineInput {
                scope: &scope,
                identity: &identity,
                registry: &registry,
                expected_descriptor: &expected_descriptor,
                expected_run: &expected_run,
                sources: &sources,
                raw_limits: RawLimits::default(),
                inventory_limits,
                started_at: observed_at,
                ended_at: observed_at,
            },
        },
        &CancellationToken::default(),
    )?;
    snapshot.verify_for_scope(scope.id(), inventory_limits)?;
    Ok(snapshot)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let (Some(root), Some(relative), Some(at), Some(tenant), Some(run), None) = (
        args.next(),
        args.next(),
        args.next(),
        args.next(),
        args.next(),
        args.next(),
    ) else {
        return Err("usage: rust_scoped_source ROOT RELATIVE-FILE RFC3339-TIME TENANT-SCOPE RUN-ID".into());
    };
    let at = at.to_str().ok_or("timestamp must be UTF-8 RFC3339")?;
    let tenant = tenant.to_str().ok_or("tenant must be UTF-8")?;
    let run = run.to_str().ok_or("run must be UTF-8")?;
    let snapshot = run_source(Path::new(&root), Path::new(&relative), at, tenant, run)?;
    let found = snapshot
        .query_assets(|asset| matches!(asset.kind, AssetKind::SourceUse { .. }))
        .count();
    println!(
        "verified snapshot={} syntactic_call_sites={} coverage_records={}",
        snapshot.id,
        found,
        snapshot.coverage_records.len()
    );
    println!("qualified syntactic calls do not prove algorithm execution or crate resolution");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn packaged_fixture_is_verifiable_and_deterministic() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixtures/source");
        let relative = Path::new("crypto_calls.rs");
        let first = run_source(
            &root,
            relative,
            "2026-10-13T15:00:00Z",
            "example-tenant",
            "example-run",
        ).unwrap();
        let again = run_source(
            &root,
            relative,
            "2026-10-13T15:00:00Z",
            "example-tenant",
            "example-run",
        ).unwrap();
        assert_eq!(first, again);
        assert_eq!(first.evidence.len(), 4);
    }
}
