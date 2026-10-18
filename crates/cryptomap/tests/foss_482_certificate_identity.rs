//! B5.5 exact-scope HMAC projection, parser parity, privacy and negative cases.
#![cfg(feature = "certificate-identity")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    CollectionRunId, CollectionScopeId, CoverageState,
    certificate_identity::{CertificateIdentityAuthority, IdentityError},
    certificate_store_scope::{CertificateStoreGrant, CertificateStoreLocation, CertificateStoreTarget},
    collector::{CancellationToken, CollectionRequest, RequestedSource},
    collectors::{
        certificate::{CertificateFileCollector, MAX_CERT_FILE_BYTES, parse_der, parse_der_with_identity},
        certificate_store::{CertificateStoreCollector, PublicCertificateStoreBackend, StoreProviderError},
    },
    raw::{RawLimits, RawSourceKind},
    scope::{CollectionScope, collect_scoped},
};
use std::{collections::BTreeMap, fs};
use x509_cert::{Certificate, der::{DecodePem, Encode}};
const PEM: &[u8] = include_bytes!("../examples/fixtures/certificate/rsa.pem");
const AT: &str = "2026-10-18T12:00:00Z";

struct Memory(Vec<u8>);
impl PublicCertificateStoreBackend for Memory {
    fn visit(&self, _target: CertificateStoreTarget, v: &mut dyn FnMut(&[u8]) -> Result<(), StoreProviderError>)
        -> Result<(), StoreProviderError> {
        v(&self.0)
    }
}
fn request(kind: RawSourceKind, item: &str) -> CollectionRequest {
    CollectionRequest {
        run: CollectionRunId::new("b55-run").unwrap(),
        sources: vec![RequestedSource { kind, item: item.to_owned() }],
        limits: RawLimits { observations: 4, ..RawLimits::default() },
        options: BTreeMap::new(),
    }
}
#[test]
fn keyed_file_and_store_correlate_without_changing_public_identity() {
    let dir = std::env::temp_dir().join(format!("cryptomap-b55-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("cert.pem"), PEM).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
    let _cleanup = Cleanup(dir.clone());
    let mut scope = CollectionScope::new(CollectionScopeId::new("b55-scope").unwrap());
    scope.grant_file(RawSourceKind::Certificate, "b55:file", &dir, "cert.pem", MAX_CERT_FILE_BYTES).unwrap();
    let target = CertificateStoreTarget::new(CertificateStoreLocation::CurrentUser, "My").unwrap();
    scope.grant_certificate_store("b55:store", CertificateStoreGrant::new(target, 4, 256*1024).unwrap()).unwrap();
    let der = Certificate::from_pem(PEM).unwrap().to_der().unwrap();
    let authority = CertificateIdentityAuthority::new(scope.id().clone(), "tenant-a", "v1", [7;32]).unwrap();
    let file = collect_scoped(
        &scope, &CertificateFileCollector::new(&scope, AT).with_identity(&authority).unwrap(),
        request(RawSourceKind::Certificate,"b55:file"), &CancellationToken::default(),
    ).unwrap();
    let store = collect_scoped(
        &scope, &CertificateStoreCollector::new(&scope, &Memory(der.clone()), AT).with_identity(&authority).unwrap(),
        request(RawSourceKind::CertificateStore,"b55:store"), &CancellationToken::default(),
    ).unwrap();
    assert_eq!(file.coverage["b55:file"], CoverageState::InspectedObserved);
    assert_eq!(store.coverage["b55:store"], CoverageState::InspectedObserved);
    let f = &file.observations[0];
    let s = &store.observations[0];
    assert_eq!(f.fact, s.fact);
    assert_ne!(f.event_id, s.event_id);
    for key in ["x509:identity:v1:subject-dn", "x509:identity:v1:issuer-dn", "x509:identity:v1:issuer-serial"] {
        assert_eq!(f.attributes.get(key), s.attributes.get(key));
    }
    assert_eq!(parse_der(&der).unwrap().fingerprint_sha256(), parse_der_with_identity(&der,&authority).unwrap().fingerprint_sha256());
    let baseline = collect_scoped(&scope, &CertificateFileCollector::new(&scope, AT),
        request(RawSourceKind::Certificate,"b55:file"),&CancellationToken::default()).unwrap();
    assert!(baseline.observations[0].attributes.keys().all(|k| !k.starts_with("x509:identity:")));
    let text = serde_json::to_string(&file).unwrap();
    assert!(!text.contains("-----BEGIN"));
    assert!(!text.contains("PRIVATE KEY"));
    assert!(!text.contains("\"subject\""));
    assert!(!text.contains("\"issuer\""));
    assert!(!text.contains("\"serial\""));
}
#[test]
fn authority_key_tenant_version_and_scope_are_isolated() {
    let scope = CollectionScopeId::new("b55-scope").unwrap();
    assert!(matches!(CertificateIdentityAuthority::new(scope.clone(),"t","v",[0;32]),Err(IdentityError::InvalidAuthority)));
    assert!(matches!(CertificateIdentityAuthority::new(scope.clone(),"bad/tenant","v",[1;32]),Err(IdentityError::InvalidAuthority)));
    let authority = CertificateIdentityAuthority::new(scope,"tenant","v1",[5;32]).unwrap();
    let der = Certificate::from_pem(PEM).unwrap().to_der().unwrap();
    let a = authority.project_der(&der).unwrap();
    assert_ne!(a,CertificateIdentityAuthority::new(CollectionScopeId::new("b55-scope").unwrap(),"other","v1",[5;32]).unwrap().project_der(&der).unwrap());
    assert_ne!(a,CertificateIdentityAuthority::new(CollectionScopeId::new("b55-scope").unwrap(),"tenant","v2",[5;32]).unwrap().project_der(&der).unwrap());
    assert_ne!(a,CertificateIdentityAuthority::new(CollectionScopeId::new("b55-scope").unwrap(),"tenant","v1",[6;32]).unwrap().project_der(&der).unwrap());
    assert_eq!(authority.check_scope(&CollectionScopeId::new("other").unwrap()), Err(IdentityError::ScopeMismatch));
    assert!(!format!("{authority:?}").contains("tenant"));
    assert_eq!(authority.project_der(&[0]),Err(IdentityError::InvalidCertificate));
}
