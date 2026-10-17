//! Inert B5.2 certificate-store grant, with no Windows API or other OS I/O.
//! cargo run --locked -p cryptomap --features certificate-store-grants --example certificate_store_authorization
use cryptomap::{
    CollectionRunId, CollectionScopeId,
    certificate_store_scope::{
        CertificateStoreGrant, CertificateStoreLocation, CertificateStoreTarget,
    },
    collector::{CollectionRequest, RequestedSource},
    raw::{RawLimits, RawSourceKind},
    scope::CollectionScope,
};
use std::{collections::BTreeMap, error::Error};

fn main() -> Result<(), Box<dyn Error>> {
    // A trusted host, never a collector or source file, selects this target.
    let target = CertificateStoreTarget::new(CertificateStoreLocation::CurrentUser, "My")?;
    let grant = CertificateStoreGrant::new(target, 4, 256 * 1024)?;
    let mut scope = CollectionScope::new(CollectionScopeId::new("example-tenant")?);
    scope.grant_certificate_store("example:personal-certificates", grant)?;

    let mut limits = RawLimits::default();
    limits.observations = 4;
    let req = CollectionRequest {
        run: CollectionRunId::new("example-store-run")?,
        sources: vec![RequestedSource {
            kind: RawSourceKind::CertificateStore,
            item: "example:personal-certificates".into(),
        }],
        limits,
        options: BTreeMap::new(),
    };
    scope.validate_request(&req)?;
    let permitted = scope.authorize_certificate_store("example:personal-certificates")?;
    println!(
        "Grant validated: {} (max public contexts {}, max public DER bytes {}). No store was opened.",
        permitted.target().id(),
        permitted.max_entries(),
        permitted.max_public_bytes(),
    );
    Ok(())
}
