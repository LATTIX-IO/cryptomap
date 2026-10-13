//! Passive Rust AST source-call evidence without execution or symbol resolution.
//!
//! Only explicitly granted .rs files are read through CollectionScope. The
//! syntactic whitelist is intentionally small: a call path is not proof that
//! Rust resolved it to the named dependency or that the call executed.
//! No argument values, source excerpts, strings or macro payloads are emitted.
use crate::{
    Confidence, CoverageState, EvidenceKind, InventoryError,
    collector::{
        COLLECTOR_CONTRACT_VERSION, CancellationToken, CollectionMode, CollectionRequest,
        CollectionSink, Collector, CollectorCapabilities, CollectorDescriptor, CollectorDiagnostic,
        CollectorDiagnosticCode,
    },
    raw::{RAW_CONTRACT_VERSION, RawFactKind, RawObservation, RawSourceKind, RawSourceLocator},
    scope::{CollectionScope, ScopeError},
};
use proc_macro2::TokenTree;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use syn::{
    Expr, ExprCall, PathArguments,
    visit::{self, Visit},
};

/// Absolute maximum bytes parsed from any one source (even with a larger host grant).
pub const MAX_RUST_SOURCE_BYTES: usize = 32 * 1024;
const MAX_TOKENS: usize = 8_192;
const MAX_NESTING: usize = 64;
const MAX_CALLS_PER_FILE: usize = 256;
const ID: &str = "cryptomap:rust-source-calls";
const VERSION: &str = "0.1.0";

/// An exact, reviewed call path seen in source syntax.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CallSite {
    api: &'static str,
    line: u32,
    column: u32,
    offset: u64,
}

/// Only direct three-segment paths without generics are claimed.
/// Imports, aliases, method calls, generic-qualified paths and dynamic
/// dispatch intentionally do not count as evidence in this increment.
fn reviewed_call(path: &syn::Path) -> Option<&'static str> {
    if path.segments.len() != 3
        || path
            .segments
            .iter()
            .any(|part| !matches!(part.arguments, PathArguments::None))
    {
        return None;
    }
    let segments: Vec<String> = path
        .segments
        .iter()
        .map(|part| part.ident.to_string())
        .collect();
    match (
        segments[0].as_str(),
        segments[1].as_str(),
        segments[2].as_str(),
    ) {
        ("sha2", "Sha256", "digest") => Some("sha2::Sha256::digest"),
        ("sha2", "Sha512", "digest") => Some("sha2::Sha512::digest"),
        ("ring", "digest", "digest") => Some("ring::digest::digest"),
        ("rustls", "ClientConfig", "builder") => Some("rustls::ClientConfig::builder"),
        _ => None,
    }
}

#[derive(Default)]
struct CallVisitor {
    sites: Vec<CallSite>,
    overflow: bool,
}
impl<'ast> Visit<'ast> for CallVisitor {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if self.overflow {
            return;
        }
        if let Expr::Path(expr) = node.func.as_ref() {
            if expr.qself.is_none() {
                if let Some(api) = reviewed_call(&expr.path) {
                    let Some(first) = expr.path.segments.first() else {
                        self.overflow = true;
                        return;
                    };
                    let position = first.ident.span();
                    let line = position.start().line;
                    let column = position.start().column.saturating_add(1);
                    let offset = position.byte_range().start;
                    match (
                        u32::try_from(line),
                        u32::try_from(column),
                        u64::try_from(offset),
                    ) {
                        (Ok(line), Ok(column), Ok(offset)) if line > 0 && column > 0 => {
                            if self.sites.len() >= MAX_CALLS_PER_FILE {
                                self.overflow = true;
                                return;
                            }
                            self.sites.push(CallSite {
                                api,
                                line,
                                column,
                                offset,
                            });
                        }
                        _ => {
                            self.overflow = true;
                            return;
                        }
                    }
                }
            }
        }
        visit::visit_expr_call(self, node);
    }
}

/// Reject highly nested untrusted syntax before invoking a recursive AST parser.
///
/// The byte-level check is intentionally conservative: parentheses appearing
/// inside comments or literals may cause a resource-limit diagnostic rather
/// than an incorrect clean scan. The token count additionally bounds the
/// actual parsed TokenTree hierarchy.
fn syntax_budget(content: &str) -> Result<(), CollectorDiagnosticCode> {
    let mut nesting = 0_usize;
    for byte in content.bytes() {
        match byte {
            b'(' | b'[' | b'{' => {
                nesting = nesting.saturating_add(1);
                if nesting > MAX_NESTING {
                    return Err(CollectorDiagnosticCode::ResourceLimit);
                }
            }
            b')' | b']' | b'}' => nesting = nesting.saturating_sub(1),
            _ => {}
        }
    }
    let token_stream = content
        .parse::<proc_macro2::TokenStream>()
        .map_err(|_| CollectorDiagnosticCode::MalformedSource)?;
    let mut queue = vec![(token_stream, 0_usize)];
    let mut total_tokens = 0_usize;
    while let Some((stream, depth)) = queue.pop() {
        if depth > MAX_NESTING {
            return Err(CollectorDiagnosticCode::ResourceLimit);
        }
        for token in stream {
            total_tokens = total_tokens.saturating_add(1);
            if total_tokens > MAX_TOKENS {
                return Err(CollectorDiagnosticCode::ResourceLimit);
            }
            if let TokenTree::Group(group) = token {
                queue.push((group.stream(), depth.saturating_add(1)));
            }
        }
    }
    Ok(())
}

fn extract_calls(bytes: &[u8]) -> Result<Vec<CallSite>, CollectorDiagnosticCode> {
    let content =
        std::str::from_utf8(bytes).map_err(|_| CollectorDiagnosticCode::MalformedSource)?;
    syntax_budget(content)?;
    let file = syn::parse_file(content).map_err(|_| CollectorDiagnosticCode::MalformedSource)?;
    let mut visitor = CallVisitor::default();
    visitor.visit_file(&file);
    if visitor.overflow
        || visitor
            .sites
            .iter()
            .any(|site| site.offset as usize >= bytes.len())
    {
        return Err(CollectorDiagnosticCode::ResourceLimit);
    }
    visitor.sites.sort_by_key(|site| (site.offset, site.api));
    Ok(visitor.sites)
}

fn io_code(error: &ScopeError) -> CollectorDiagnosticCode {
    match error {
        ScopeError::ResourceLimit => CollectorDiagnosticCode::ResourceLimit,
        ScopeError::InvalidInput | ScopeError::OutOfScope => {
            CollectorDiagnosticCode::PermissionDenied
        }
        ScopeError::Io | ScopeError::Collection(_) => CollectorDiagnosticCode::MalformedSource,
    }
}

fn failed(
    sink: &mut CollectionSink,
    item: &str,
    code: CollectorDiagnosticCode,
    coverage: CoverageState,
) -> Result<(), InventoryError> {
    sink.diagnose(CollectorDiagnostic {
        code,
        source_item: Some(item.to_owned()),
    })?;
    sink.cover(item, coverage)
}

/// A trusted in-process Rust source collector with no implicit root, traversal,
/// network, process execution or ambient file I/O.
pub struct RustSourceCollector<'a> {
    scope: &'a CollectionScope,
    observed_at: String,
}
impl<'a> RustSourceCollector<'a> {
    /// Construct without file I/O. The host must grant every exact source item.
    pub fn new(scope: &'a CollectionScope, observed_at: impl Into<String>) -> Self {
        Self {
            scope,
            observed_at: observed_at.into(),
        }
    }
}
impl Collector for RustSourceCollector<'_> {
    fn descriptor(&self) -> CollectorDescriptor {
        CollectorDescriptor {
            contract_version: COLLECTOR_CONTRACT_VERSION,
            id: crate::CollectorId::new(ID)
                .unwrap_or_else(|_| unreachable!("constant Rust source descriptor")),
            version: VERSION.into(),
            capabilities: CollectorCapabilities {
                sources: BTreeSet::from([RawSourceKind::Source]),
                mode: CollectionMode::Passive,
                required_permissions: BTreeSet::new(),
                checkpoint: false,
            },
        }
    }

    fn collect(
        &self,
        request: &CollectionRequest,
        sink: &mut CollectionSink,
        cancel: &CancellationToken,
    ) -> Result<(), InventoryError> {
        self.scope
            .validate_request(request)
            .map_err(|_| InventoryError::InvalidMetadata)?;
        let descriptor = self.descriptor();
        for source in &request.sources {
            if cancel.is_cancelled() {
                failed(
                    sink,
                    &source.item,
                    CollectorDiagnosticCode::Cancelled,
                    CoverageState::NotInspected,
                )?;
                continue;
            }
            let file = match self.scope.open_file(RawSourceKind::Source, &source.item) {
                Ok(file) => file,
                Err(error) => {
                    failed(sink, &source.item, io_code(&error), CoverageState::Failed)?;
                    continue;
                }
            };
            // The authorized relative extension, never a user-supplied label,
            // controls this collector's supported syntax profile.
            if file.relative().extension().and_then(|ext| ext.to_str()) != Some("rs") {
                failed(
                    sink,
                    &source.item,
                    CollectorDiagnosticCode::UnsupportedSource,
                    CoverageState::Unsupported,
                )?;
                continue;
            }
            let bytes = match file.read_limited(MAX_RUST_SOURCE_BYTES) {
                Ok(bytes) => bytes,
                Err(error) => {
                    failed(sink, &source.item, io_code(&error), CoverageState::Failed)?;
                    continue;
                }
            };
            let calls = match extract_calls(&bytes) {
                Ok(calls) if calls.len() <= request.limits.observations => calls,
                Ok(_) => {
                    failed(
                        sink,
                        &source.item,
                        CollectorDiagnosticCode::ResourceLimit,
                        CoverageState::Failed,
                    )?;
                    continue;
                }
                Err(code) => {
                    failed(sink, &source.item, code, CoverageState::Failed)?;
                    continue;
                }
            };
            let digest = format!("{:x}", Sha256::digest(&bytes));
            let mut interrupted = false;
            let count = calls.len();
            for site in calls {
                if cancel.is_cancelled() {
                    interrupted = true;
                    break;
                }
                // Only approved API path names and immutable source coordinates
                // enter the event hash; no argument content or raw source text.
                let identity = serde_json::to_vec(&(
                    "cryptomap:rust-source-site:v1",
                    &source.item,
                    site.offset,
                    site.line,
                    site.column,
                    site.api,
                ))
                .map_err(|_| InventoryError::InvalidMetadata)?;
                sink.emit(RawObservation {
                    contract_version: RAW_CONTRACT_VERSION,
                    event_id: format!("rust-call:v1:{:x}", Sha256::digest(identity)),
                    collector: descriptor.id.clone(),
                    collector_version: descriptor.version.clone(),
                    run: request.run.clone(),
                    source: RawSourceLocator {
                        kind: RawSourceKind::Source,
                        item: source.item.clone(),
                        offset: Some(site.offset),
                        line: Some(site.line),
                        column: Some(site.column),
                    },
                    observed_at: self.observed_at.clone(),
                    // This maps to canonical SourceUse, not AlgorithmUse:
                    // the existing algorithm registry has no Rust API namespace
                    // and these calls do not establish runtime execution.
                    fact: RawFactKind::Configuration {
                        property: "source:qualified-crypto-api-call".into(),
                        value: site.api.into(),
                    },
                    evidence_kind: EvidenceKind::Direct,
                    confidence: Confidence::High,
                    inference_rule: None,
                    source_sha256: Some(digest.clone()),
                    attributes: BTreeMap::from([(
                        "source:evidence-semantics".into(),
                        "syntactic-call-only".into(),
                    )]),
                })?;
            }
            if interrupted {
                failed(
                    sink,
                    &source.item,
                    CollectorDiagnosticCode::Cancelled,
                    CoverageState::Partial,
                )?;
            } else {
                sink.cover(
                    &source.item,
                    if count == 0 {
                        CoverageState::InspectedNoObservation
                    } else {
                        CoverageState::InspectedObserved
                    },
                )?;
            }
        }
        Ok(())
    }
}
