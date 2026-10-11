//! FOSS-319: capability-rooted filesystem and explicit network scope tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    CollectionRunId, CollectionScopeId, CollectorId, InventoryError,
    collector::{
        COLLECTOR_CONTRACT_VERSION, CancellationToken, CollectionMode, CollectionRequest,
        CollectionSink, Collector, CollectorCapabilities, CollectorDescriptor, RequestedSource,
    },
    filesystem_scope::{FileRoot, validate_relative},
    network_scope::{NetworkScope, NetworkTarget},
    raw::{RawLimits, RawSourceKind},
    scope::{CollectionScope, ScopeError, collect_scoped},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
static NEXT: AtomicUsize = AtomicUsize::new(1);

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let num = NEXT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("cryptomap-foss319-{}-{}", std::process::id(), num));
        fs::create_dir_all(root.join("inside")).unwrap();
        fs::write(root.join("inside").join("Cargo.lock"), b"safe-file").unwrap();
        fs::write(root.join("secret.txt"), b"outside-data").unwrap();
        Self { root }
    }
    fn dir(&self) -> PathBuf {
        self.root.join("inside")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[test]
fn explicit_file_capability_reads_only_allowed_relative_file() {
    let fixture = Fixture::new();
    let root = FileRoot::open(fixture.dir()).unwrap();
    assert!(root.authorize("Cargo.lock", 32).is_ok());
    assert_eq!(
        root.authorize("Cargo.lock", 32)
            .unwrap()
            .read_bounded()
            .unwrap(),
        b"safe-file"
    );
    assert!(matches!(
        root.authorize("Cargo.lock", 2).unwrap().read_bounded(),
        Err(ScopeError::ResourceLimit)
    ));
    assert!(root.authorize("../secret.txt", 32).is_err());
    assert!(root.authorize(fixture.root.join("secret.txt"), 32).is_err());
    assert!(root.authorize("missing.lock", 32).is_err());
    assert!(root.authorize("Cargo*.lock", 32).is_err());
    assert!(root.authorize("Cargo.lock", 0).is_err());
}

#[test]
fn validate_relative_rejects_traversal_globs_and_device_names() {
    for text in [
        "../secret",
        "sub/../../secret",
        "/etc/passwd",
        ".",
        "file?.pem",
        "file*.pem",
        "C:\\Windows\\win.ini",
        "\\\\server\\share",
    ] {
        assert!(validate_relative(Path::new(text)).is_err(), "{text}");
    }
    assert!(validate_relative(Path::new("sub/file.pem")).is_ok());
}

#[cfg(unix)]
#[test]
fn file_capability_rejects_external_and_internal_symlinks() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let dir = fixture.dir();
    symlink(fixture.root.join("secret.txt"), dir.join("outside-link")).unwrap();
    symlink(dir.join("Cargo.lock"), dir.join("inside-link")).unwrap();
    let root = FileRoot::open(&dir).unwrap();
    assert!(root.authorize("outside-link", 100).is_err());
    assert!(root.authorize("inside-link", 100).is_err());
    symlink(&dir, fixture.root.join("root-link")).unwrap();
    assert!(FileRoot::open(fixture.root.join("root-link")).is_err());
}

#[cfg(unix)]
#[test]
fn post_grant_symlink_swap_is_rejected_at_open_time() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let root = FileRoot::open(fixture.dir()).unwrap();
    let authorized = root.authorize("Cargo.lock", 1024).unwrap();
    fs::rename(
        fixture.dir().join("Cargo.lock"),
        fixture.dir().join("original.lock"),
    )
    .unwrap();
    symlink(
        fixture.root.join("secret.txt"),
        fixture.dir().join("Cargo.lock"),
    )
    .unwrap();
    assert!(matches!(
        authorized.open_read(),
        Err(ScopeError::OutOfScope) | Err(ScopeError::Io)
    ));
}

#[cfg(windows)]
#[test]
fn file_capability_rejects_windows_symlink_when_allowed_by_host() {
    use std::os::windows::fs::symlink_file;
    let fixture = Fixture::new();
    let dir = fixture.dir();
    // Windows symlink creation may require Developer Mode or elevated privileges.
    if symlink_file(fixture.root.join("secret.txt"), dir.join("link.txt")).is_ok() {
        let root = FileRoot::open(&dir).unwrap();
        assert!(root.authorize("link.txt", 100).is_err());
    }
}

#[test]
fn explicit_network_pins_and_ports_are_enforced() {
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let target = NetworkTarget::new("127.0.0.1", port, None, []).unwrap();
    let id = target.id();
    let mut scope = NetworkScope::new();
    scope.grant(target.clone()).unwrap();
    assert!(scope.grant(target).is_err());
    assert!(scope.permits(&id));
    let permitted = scope.authorize(&id).unwrap();
    assert!(matches!(
        permitted.connect(SocketAddr::new(ip, port + 1), Duration::from_millis(500)),
        Err(ScopeError::OutOfScope)
    ));
    assert!(matches!(
        permitted.connect(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), port),
            Duration::from_millis(500)
        ),
        Err(ScopeError::OutOfScope)
    ));
    assert!(
        permitted
            .connect(SocketAddr::new(ip, port), Duration::ZERO)
            .is_err()
    );
    let _client = permitted
        .connect(SocketAddr::new(ip, port), Duration::from_secs(1))
        .unwrap();
    let _accepted = listener.accept().unwrap();
}

#[test]
fn hostname_requires_caller_pinned_ip_and_rejects_ambiguous_urls() {
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert!(NetworkTarget::new("example.com", 443, None, []).is_err());
    assert!(NetworkTarget::new("https://example.com", 443, None, [ip]).is_err());
    assert!(NetworkTarget::new("example.com/redirect", 443, None, [ip]).is_err());
    assert!(NetworkTarget::new("example.com", 0, None, [ip]).is_err());
    assert!(NetworkTarget::new("example.com", 443, Some("invalid/url"), [ip]).is_err());
    assert!(
        NetworkTarget::new(
            "127.0.0.1",
            443,
            None,
            [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]
        )
        .is_err()
    );
    let target = NetworkTarget::new("API.Example.com", 443, Some("API.Example.com"), [ip]).unwrap();
    assert_eq!(target.id(), "api.example.com:443");
    assert_eq!(target.sni(), Some("api.example.com"));
    let mut scope = NetworkScope::new();
    scope.grant(target).unwrap();
    assert!(scope.authorize("another.example.com:443").is_err());
}

fn descriptor() -> CollectorDescriptor {
    CollectorDescriptor {
        contract_version: COLLECTOR_CONTRACT_VERSION,
        id: CollectorId::new("mock").unwrap(),
        version: "1".into(),
        capabilities: CollectorCapabilities {
            sources: BTreeSet::from([RawSourceKind::Dependency, RawSourceKind::TlsEndpoint]),
            mode: CollectionMode::Passive,
            required_permissions: BTreeSet::new(),
            checkpoint: false,
        },
    }
}
struct Mock;
impl Collector for Mock {
    fn descriptor(&self) -> CollectorDescriptor {
        descriptor()
    }
    fn collect(
        &self,
        _: &CollectionRequest,
        _: &mut CollectionSink,
        _: &CancellationToken,
    ) -> Result<(), InventoryError> {
        Ok(())
    }
}
fn request(kind: RawSourceKind, item: &str) -> CollectionRequest {
    CollectionRequest {
        run: CollectionRunId::new("run").unwrap(),
        sources: vec![RequestedSource {
            kind,
            item: item.into(),
        }],
        limits: RawLimits::default(),
        options: BTreeMap::new(),
    }
}
#[test]
fn scoped_collector_fails_closed_before_invoking_unapproved_source() {
    let fixture = Fixture::new();
    let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-1").unwrap());
    scope
        .grant_file(
            RawSourceKind::Dependency,
            "Cargo.lock",
            fixture.dir(),
            "Cargo.lock",
            1024,
        )
        .unwrap();
    let okay = request(RawSourceKind::Dependency, "Cargo.lock");
    assert!(collect_scoped(&scope, &Mock, okay, &CancellationToken::default()).is_ok());
    let outsider = request(RawSourceKind::Dependency, "../secret.txt");
    assert!(matches!(
        collect_scoped(&scope, &Mock, outsider, &CancellationToken::default()),
        Err(ScopeError::OutOfScope)
    ));
    let wrong_kind = request(RawSourceKind::TlsEndpoint, "Cargo.lock");
    assert!(matches!(
        scope.validate_request(&wrong_kind),
        Err(ScopeError::OutOfScope)
    ));
    assert_eq!(
        scope
            .open_file(RawSourceKind::Dependency, "Cargo.lock")
            .unwrap()
            .read_bounded()
            .unwrap(),
        b"safe-file"
    );
    assert!(
        scope
            .open_file(RawSourceKind::Dependency, "outside.txt")
            .is_err()
    );
}
#[test]
fn logical_authorizations_are_exact_and_nonexpanding() {
    let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-1").unwrap());
    scope
        .grant_logical(RawSourceKind::Certificate, "store:CurrentUser/Root")
        .unwrap();
    scope
        .grant_logical(RawSourceKind::Telemetry, "stream:approved")
        .unwrap();
    assert!(
        scope
            .grant_logical(RawSourceKind::Certificate, "store:CurrentUser/Root")
            .is_err()
    );
    assert!(
        scope
            .grant_logical(RawSourceKind::Source, "source:*")
            .is_err()
    );
    assert!(
        scope
            .validate_request(&request(
                RawSourceKind::Certificate,
                "store:CurrentUser/Root"
            ))
            .is_ok()
    );
    assert!(
        scope
            .validate_request(&request(RawSourceKind::Telemetry, "stream:other"))
            .is_err()
    );
    assert!(
        scope
            .open_file(RawSourceKind::Certificate, "store:CurrentUser/Root")
            .is_err()
    );
}
