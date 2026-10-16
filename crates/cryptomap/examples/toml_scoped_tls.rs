//! Exact-file configured TLS evidence, not negotiated transport or crypto use.
//!
//! cargo run --locked --features toml-tls-config --example toml_scoped_tls --
//!   ROOT RELATIVE-TOML-FILE RFC3339-TIME TENANT-SCOPE RUN-ID
use cryptomap::{
    AssetKind, CollectionRunId, IdentityContext, InventoryLimits, ProtocolState,
    collector::{CancellationToken, Collector, RequestedSource},
    collectors::source::config_toml::{MAX_TOML_TLS_BYTES, TomlTlsConfigCollector},
    coverage::CollectionScopeId,
    orchestration::{ScopedInvocation, collect_normalized},
    pipeline::PipelineInput,
    raw::{RawLimits, RawSourceKind},
    registry::Registry,
    scope::CollectionScope,
};
use std::{error::Error, path::Path};

/// Read one exact authorized TOML profile through the scoped SDK.
pub fn run_config(
    root: &Path,
    relative: &Path,
    observed_at: &str,
    tenant: &str,
    run_name: &str,
) -> Result<cryptomap::InventorySnapshot, Box<dyn Error>> {
    let mut scope = CollectionScope::new(CollectionScopeId::new(tenant)?);
    let item = "source:toml-tls-profile";
    scope.grant_file(
        RawSourceKind::Source,
        item,
        root,
        relative,
        MAX_TOML_TLS_BYTES,
    )?;
    let collector = TomlTlsConfigCollector::new(&scope, observed_at);
    let expected_descriptor = collector.descriptor();
    let expected_run = CollectionRunId::new(run_name)?;
    let identity = IdentityContext::new(scope.id().as_str())?;
    let registry = Registry::builtin();
    let sources = vec![RequestedSource {
        kind: RawSourceKind::Source,
        item: item.into(),
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
        return Err("usage: toml_scoped_tls ROOT RELATIVE-TOML RFC3339-TIME TENANT RUN-ID".into());
    };
    let at = at.to_str().ok_or("timestamp must be UTF-8 RFC3339")?;
    let tenant = tenant.to_str().ok_or("tenant must be UTF-8")?;
    let run = run.to_str().ok_or("run must be UTF-8")?;
    let snapshot = run_config(Path::new(&root), Path::new(&relative), at, tenant, run)?;
    let configured_protocols = snapshot
        .query_assets(|asset| {
            matches!(
                asset.kind,
                AssetKind::Protocol {
                    state: ProtocolState::Configured,
                    ..
                }
            )
        })
        .count();
    println!(
        "verified snapshot={} configured_tls_versions={} evidence={} coverage={}",
        snapshot.id,
        configured_protocols,
        snapshot.evidence.len(),
        snapshot.coverage_records.len()
    );
    println!("configured capabilities do not establish negotiated TLS or executed algorithms");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn packaged_toml_fixture_round_trips_with_exact_evidence() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixtures/config");
        let first = run_config(
            &root,
            Path::new("tls.toml"),
            "2026-10-13T15:00:00Z",
            "toml-tenant",
            "toml-run",
        )
        .unwrap();
        let second = run_config(
            &root,
            Path::new("tls.toml"),
            "2026-10-13T15:00:00Z",
            "toml-tenant",
            "toml-run",
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.evidence.len(), 4);
        assert_eq!(first.coverage_records.len(), 1);
    }
}
