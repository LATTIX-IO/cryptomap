//! Explicit opt-in manual read-only CurrentUser/My acceptance (no private data printed).
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    CollectionRunId, CollectionScopeId,
    certificate_store_scope::{
        CertificateStoreGrant, CertificateStoreLocation, CertificateStoreTarget,
    },
    collector::{CancellationToken, CollectionRequest, RequestedSource},
    collectors::certificate_store::CertificateStoreCollector,
    raw::{RawLimits, RawSourceKind},
    scope::{CollectionScope, collect_scoped},
};
use cryptomap_windows_store::WindowsCertificateStoreBackend;
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !cfg!(windows) {
        return Err("native Windows certificate-store inspection is unavailable here".into());
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 || args[0] != "--authorize-current-user-my" {
        return Err("explicit --authorize-current-user-my and RFC3339 timestamp required".into());
    }
    let target = CertificateStoreTarget::new(CertificateStoreLocation::CurrentUser, "My")?;
    let mut scope = CollectionScope::new(CollectionScopeId::new("manual-current-user-my")?);
    scope.grant_certificate_store(
        "manual:current-user-my",
        CertificateStoreGrant::new(target, 64, 4 * 1024 * 1024)?,
    )?;
    let request = CollectionRequest {
        run: CollectionRunId::new("manual-current-user-run")?,
        sources: vec![RequestedSource {
            kind: RawSourceKind::CertificateStore,
            item: "manual:current-user-my".to_owned(),
        }],
        limits: RawLimits {
            sources: 1,
            observations: 64,
            ..RawLimits::default()
        },
        options: BTreeMap::new(),
    };
    let provider = WindowsCertificateStoreBackend;
    let collector = CertificateStoreCollector::new(&scope, &provider, &args[1]);
    let outcome = collect_scoped(&scope, &collector, request, &CancellationToken::default())?;
    println!(
        "status={:?} coverage={:?} public_certificate_facts={} diagnostic_count={}",
        outcome.status,
        outcome.coverage.get("manual:current-user-my"),
        outcome.observations.len(),
        outcome.diagnostics.len(),
    );
    Ok(())
}
