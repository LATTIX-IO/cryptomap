//! Authorized collection-source manifest and scoped collector entrypoint.
//!
//! This is a capability API for trusted in-process collectors, not a process
//! sandbox: malicious plugin code can still call the operating system's
//! ambient APIs. Run untrusted collectors with OS process isolation.
//!
//! Files are opened only through `FileRoot`; endpoints are connected only
//! through exact target pins. Logical certificate-store and telemetry grants
//! authorize a name but do not confer native OS access privileges.
#[cfg(feature = "certificate-store-grants")]
use crate::certificate_store_scope::CertificateStoreGrant;
use crate::{
    CollectionScopeId, InventoryError,
    collector::{self, CancellationToken, CollectionOutcome, CollectionRequest, Collector},
    filesystem_scope::{AuthorizedFile, FileRoot},
    network_scope::{AuthorizedEndpoint, NetworkScope, NetworkTarget},
    raw::RawSourceKind,
    validation,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

/// Sanitized authorization error type, without untrusted path or endpoint data.
pub enum ScopeError {
    /// Invalid or ambiguous caller configuration.
    InvalidInput,
    /// Source is outside the caller-approved scope.
    OutOfScope,
    /// Caller-supplied budget exceeded.
    ResourceLimit,
    /// Scoped OS I/O failed (paths are not included in this error).
    Io,
    /// An inventory/collector validation error occurred.
    Collection(InventoryError),
}
impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => f.write_str("invalid scope input"),
            Self::OutOfScope => f.write_str("source outside granted scope"),
            Self::ResourceLimit => f.write_str("scope resource limit exceeded"),
            Self::Io => f.write_str("scoped I/O failed"),
            Self::Collection(_) => f.write_str("collector contract failed"),
        }
    }
}
// Public debug logs must not echo raw event IDs, paths or nested error
// payloads supplied by untrusted source data.
impl fmt::Debug for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl Error for ScopeError {}

struct FileGrant {
    root: FileRoot,
    relative: PathBuf,
    max_bytes: usize,
}

/// A caller-owned authorization manifest containing only explicit sources.
///
/// No globbing, recursive traversal, automatic DNS resolution, connection
/// redirection, or automatic certificate store enumeration is performed.
pub struct CollectionScope {
    id: CollectionScopeId,
    files: BTreeMap<(RawSourceKind, String), FileGrant>,
    network: NetworkScope,
    logical: BTreeSet<(RawSourceKind, String)>,
    #[cfg(feature = "certificate-store-grants")]
    certificate_stores: BTreeMap<String, CertificateStoreGrant>,
}

fn check_source_id(item: &str) -> Result<(), ScopeError> {
    if item.is_empty()
        || item.trim() != item
        || item.contains(['*', '?', '\0'])
        || item.len() > 2048
    {
        return Err(ScopeError::InvalidInput);
    }
    validation::safe_text(item, 2048).map_err(|_| ScopeError::InvalidInput)
}

impl CollectionScope {
    /// Create a unique, explicitly caller-authorized collection scope.
    pub fn new(id: CollectionScopeId) -> Self {
        Self {
            id,
            files: BTreeMap::new(),
            network: NetworkScope::new(),
            logical: BTreeSet::new(),
            #[cfg(feature = "certificate-store-grants")]
            certificate_stores: BTreeMap::new(),
        }
    }

    /// Immutable scope identity for provenance and run records.
    pub fn id(&self) -> &CollectionScopeId {
        &self.id
    }

    /// Grant exactly one relative file under a rooted OS capability.
    ///
    /// Opens a directory authority *now*, but verifies the relative file again
    /// for every subsequent access (and uses a rooted OS file handle).
    pub fn grant_file(
        &mut self,
        kind: RawSourceKind,
        item: impl Into<String>,
        root: impl AsRef<Path>,
        relative: impl AsRef<Path>,
        max_bytes: usize,
    ) -> Result<(), ScopeError> {
        if !matches!(
            kind,
            RawSourceKind::Dependency
                | RawSourceKind::Certificate
                | RawSourceKind::Source
                | RawSourceKind::Telemetry
        ) {
            return Err(ScopeError::InvalidInput);
        }
        let item = item.into();
        check_source_id(&item)?;
        let key = (kind, item);
        if self.files.contains_key(&key) || self.logical.contains(&key) {
            return Err(ScopeError::InvalidInput);
        }
        #[cfg(feature = "certificate-store-grants")]
        if key.0 == RawSourceKind::Certificate && self.certificate_stores.contains_key(&key.1) {
            return Err(ScopeError::InvalidInput);
        }
        let root = FileRoot::open(root)?;
        let relative = relative.as_ref().to_path_buf();
        root.authorize(&relative, max_bytes)?;
        self.files.insert(
            key,
            FileGrant {
                root,
                relative,
                max_bytes,
            },
        );
        Ok(())
    }

    /// Grant one explicit network target with caller-pinned destination IPs.
    pub fn grant_endpoint(&mut self, target: NetworkTarget) -> Result<(), ScopeError> {
        self.network.grant(target)
    }

    /// Grant a certificate store or in-memory telemetry stream by exact ID.
    ///
    /// The collector still needs platform authorization; this call does not
    /// open a certificate store or telemetry stream.
    pub fn grant_logical(
        &mut self,
        kind: RawSourceKind,
        item: impl Into<String>,
    ) -> Result<(), ScopeError> {
        if !matches!(kind, RawSourceKind::Certificate | RawSourceKind::Telemetry) {
            return Err(ScopeError::InvalidInput);
        }
        let item = item.into();
        check_source_id(&item)?;
        let key = (kind, item);
        if self.files.contains_key(&key) || self.logical.contains(&key) {
            return Err(ScopeError::InvalidInput);
        }
        #[cfg(feature = "certificate-store-grants")]
        if key.0 == RawSourceKind::Certificate && self.certificate_stores.contains_key(&key.1) {
            return Err(ScopeError::InvalidInput);
        }
        self.logical.insert(key);
        Ok(())
    }

    /// Grant one exact certificate store, with typed hive, name and finite budgets.
    ///
    /// No OS store is opened, enumerated or authenticated by this grant.
    #[cfg(feature = "certificate-store-grants")]
    pub fn grant_certificate_store(
        &mut self,
        item: impl Into<String>,
        grant: CertificateStoreGrant,
    ) -> Result<(), ScopeError> {
        let item = item.into();
        check_source_id(&item)?;
        grant.validate()?;
        let file_key = (RawSourceKind::Certificate, item.clone());
        if self.certificate_stores.contains_key(&item)
            || self.files.contains_key(&file_key)
            || self.logical.contains(&file_key)
        {
            return Err(ScopeError::InvalidInput);
        }
        self.certificate_stores.insert(item, grant);
        Ok(())
    }

    /// Resolve an exact named store authorization, without accessing the OS.
    ///
    /// Callers must use the host-granted source item, not an untrusted store path.
    #[cfg(feature = "certificate-store-grants")]
    pub fn authorize_certificate_store(
        &self,
        item: &str,
    ) -> Result<&CertificateStoreGrant, ScopeError> {
        self.certificate_stores
            .get(item)
            .ok_or(ScopeError::OutOfScope)
    }

    /// Verify that every collector source item is an exact granted entry.
    /// Re-run on every invocation; a collector capability declaration is not
    /// permission and `request.options` never adds sources.
    pub fn validate_request(&self, req: &CollectionRequest) -> Result<(), ScopeError> {
        if req.sources.is_empty() {
            return Err(ScopeError::InvalidInput);
        }
        for src in &req.sources {
            #[cfg(feature = "certificate-store-grants")]
            if src.kind == RawSourceKind::CertificateStore {
                let grant = self.authorize_certificate_store(&src.item)?;
                // This is an output-record limit; the independent public DER
                // byte ceiling is enforced by the future native adapter.
                if req.limits.observations > grant.max_entries() {
                    return Err(ScopeError::ResourceLimit);
                }
                continue;
            }
            let permitted = if src.kind == RawSourceKind::TlsEndpoint {
                self.network.permits(&src.item)
            } else {
                let key = (src.kind.clone(), src.item.clone());
                self.files.contains_key(&key) || self.logical.contains(&key)
            };
            if !permitted {
                return Err(ScopeError::OutOfScope);
            }
        }
        Ok(())
    }

    /// Obtain the sole approved file capability for this collector/source item.
    pub fn open_file(
        &self,
        kind: RawSourceKind,
        item: &str,
    ) -> Result<AuthorizedFile<'_>, ScopeError> {
        let grant = self
            .files
            .get(&(kind, item.to_owned()))
            .ok_or(ScopeError::OutOfScope)?;
        grant.root.authorize(&grant.relative, grant.max_bytes)
    }

    /// Obtain a capability pinned to exactly one approved TLS destination.
    pub fn open_endpoint(&self, item: &str) -> Result<AuthorizedEndpoint<'_>, ScopeError> {
        self.network.authorize(item)
    }
}

/// Check that a collector holding a scope is invoked under that exact grant.
///
/// Comparing only scope IDs is insufficient: separate objects can carry the
/// same tenant label yet authorize different files. No source is opened here.
pub(crate) fn validate_collector_binding<C: Collector + ?Sized>(
    scope: &CollectionScope,
    collector: &C,
) -> Result<(), ScopeError> {
    if !collector.matches_invocation_scope(scope) {
        return Err(ScopeError::OutOfScope);
    }
    Ok(())
}

/// Scope-validated collector entry point for trusted in-process plugins.
///
/// This checks scope before running the collector. A truly untrusted plugin
/// needs OS process isolation because it could bypass Rust APIs and perform
/// ambient I/O directly; see docs/foss-319-scope-security.md.
pub fn collect_scoped<C: Collector + ?Sized>(
    scope: &CollectionScope,
    collector: &C,
    request: CollectionRequest,
    cancel: &CancellationToken,
) -> Result<CollectionOutcome, ScopeError> {
    validate_collector_binding(scope, collector)?;
    scope.validate_request(&request)?;
    collector::collect(collector, request, cancel).map_err(ScopeError::Collection)
}

/// Run an opt-in fault-isolated collector after validating exact host grants.
///
/// This mode requires a cooperative collector whose single-source calls are
/// independent. Each source failure is reported as failed coverage rather than
/// a clean absence. The raw route validates granted scope but does not
/// independently bind collector descriptor or tenant identity. Use
/// `orchestration::collect_normalized_isolated` for host-pinned provenance.
pub fn collect_scoped_isolated<C: Collector + ?Sized>(
    scope: &CollectionScope,
    collector: &C,
    request: CollectionRequest,
    cancel: &CancellationToken,
) -> Result<CollectionOutcome, ScopeError> {
    validate_collector_binding(scope, collector)?;
    scope.validate_request(&request)?;
    collector::collect_isolated(collector, request, cancel).map_err(ScopeError::Collection)
}
