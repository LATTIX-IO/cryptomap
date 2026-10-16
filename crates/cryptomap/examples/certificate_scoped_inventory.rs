//! Passive exact-file public X.509 certificate evidence, not chain validation or private-key access.
//!
//! cargo run --locked --features certificate-files --example certificate_scoped_inventory --
//!   ROOT RELATIVE-CERTIFICATE-FILE RFC3339-TIME TENANT-SCOPE RUN-ID
use cryptomap::{
    AssetKind, CollectionRunId, IdentityContext, InventoryLimits,
    collector::{CancellationToken, Collector, RequestedSource},
    collectors::certificate::{MAX_CERT_FILE_BYTES, CertificateFileCollector},
    coverage::CollectionScopeId,
    orchestration::{ScopedInvocation, collect_normalized},
    pipeline::PipelineInput,
    raw::{RawLimits, RawSourceKind},
    registry::Registry,
    scope::CollectionScope,
};
use std::{error::Error, path::Path};

/// Read one exact authorized certificate profile through the scoped SDK.
pub fn run_certificate(
    root: &Path,
    relative: &Path,
    observed_at: &str,
    tenant: &str,
    run_name: &str,
) -> Result<cryptomap::InventorySnapshot, Box<dyn Error>> {
    let mut scope = CollectionScope::new(CollectionScopeId::new(tenant)?);
    let item = "certificate:public-file";
    scope.grant_file(
        RawSourceKind::Certificate,
        item,
        root,
        relative,
        MAX_CERT_FILE_BYTES,
    )?;
    let collector = CertificateFileCollector::new(&scope, observed_at);
    let expected_descriptor = collector.descriptor();
    let expected_run = CollectionRunId::new(run_name)?;
    let identity = IdentityContext::new(scope.id().as_str())?;
    let registry = Registry::builtin();
    let sources = vec![RequestedSource {
        kind: RawSourceKind::Certificate,
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
        return Err("usage: certificate_scoped_inventory ROOT RELATIVE-CERTIFICATE-FILE RFC3339-TIME TENANT RUN-ID".into());
    };
    let at = at.to_str().ok_or("timestamp must be UTF-8 RFC3339")?;
    let tenant = tenant.to_str().ok_or("tenant must be UTF-8")?;
    let run = run.to_str().ok_or("run must be UTF-8")?;
    let snapshot = run_certificate(Path::new(&root), Path::new(&relative), at, tenant, run)?;
    let public_certificates = snapshot
        .query_assets(|asset| {
            matches!(
                asset.kind,
                AssetKind::Certificate { .. }
            )
        })
        .count();
    println!(
        "verified snapshot={} public_certificates={} evidence={} coverage={}",
        snapshot.id,
        public_certificates,
        snapshot.evidence.len(),
        snapshot.coverage_records.len()
    );
    println!("public certificate bytes do not establish trust, revocation status or private key possession");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn packaged_public_rsa_fixture_round_trips_without_trust_claims() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixtures/certificate");
        let first = run_certificate(
            &root,
            Path::new("rsa.pem"),
            "2026-10-16T12:00:00Z",
            "cert-tenant",
            "cert-run",
        )
        .unwrap();
        let second = run_certificate(
            &root,
            Path::new("rsa.pem"),
            "2026-10-16T12:00:00Z",
            "cert-tenant",
            "cert-run",
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.evidence.len(), 1);
        assert_eq!(first.coverage_records.len(), 1);
        assert_eq!(
            first.query_assets(|a| matches!(a.kind, AssetKind::Certificate { .. })).count(),
            1,
        );
    }
}
