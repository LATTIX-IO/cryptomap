//! FOSS-370 parser-backed source evidence: correctness, scope and security.
//! These are executable with: cargo test -p cryptomap --features rust-source
//! --test foss_370_rust_source --locked.
#![cfg(feature = "rust-source")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    AssetKind, CollectionRunId, CoverageState, EvidenceKind, IdentityContext, InventoryLimits,
    InventorySnapshot,
    collector::{
        CancellationToken, CollectionRequest, CollectionSink, CollectionStatus, Collector,
        CollectorDiagnosticCode, RequestedSource,
    },
    collectors::source::rust::{MAX_RUST_SOURCE_BYTES, RustSourceCollector},
    coverage::CollectionScopeId,
    orchestration::{ScopedInvocation, collect_normalized},
    pipeline::{PipelineError, PipelineInput},
    raw::{RawFactKind, RawLimits, RawSourceKind},
    registry::Registry,
    scope::{CollectionScope, collect_scoped},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
const OBSERVED_AT: &str = "2026-10-13T15:00:00Z";

struct Sandbox {
    root: PathBuf,
}
impl Sandbox {
    fn new() -> Self {
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("cryptomap-foss370-{}-{unique}", std::process::id()));
        fs::create_dir(&root).unwrap();
        Self { root }
    }
    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) {
        fs::write(self.root.join(name), bytes).unwrap();
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn scope_for(root: &Path, files: &[(&str, &str)]) -> CollectionScope {
    let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-rust").unwrap());
    for (item, name) in files {
        scope
            .grant_file(
                RawSourceKind::Source,
                *item,
                root,
                name,
                MAX_RUST_SOURCE_BYTES + 8192,
            )
            .unwrap();
    }
    scope
}
fn sources(items: &[&str]) -> Vec<RequestedSource> {
    items
        .iter()
        .map(|item| RequestedSource {
            kind: RawSourceKind::Source,
            item: (*item).into(),
        })
        .collect()
}
fn run_raw(
    scope: &CollectionScope,
    items: &[&str],
    limits: RawLimits,
) -> cryptomap::collector::CollectionOutcome {
    let collector = RustSourceCollector::new(scope, OBSERVED_AT);
    collect_scoped(
        scope,
        &collector,
        CollectionRequest {
            run: CollectionRunId::new("run-rust").unwrap(),
            sources: sources(items),
            limits,
            options: Default::default(),
        },
        &CancellationToken::default(),
    )
    .unwrap()
}

fn normalized(
    scope: &CollectionScope,
    items: &[&str],
    tenant: &str,
) -> Result<InventorySnapshot, PipelineError> {
    let collector = RustSourceCollector::new(scope, OBSERVED_AT);
    let descriptor = collector.descriptor();
    let run = CollectionRunId::new("run-rust").unwrap();
    let identity = IdentityContext::new(tenant).unwrap();
    let registry = Registry::builtin();
    let sources = sources(items);
    collect_normalized(
        ScopedInvocation {
            collector: &collector,
            input: PipelineInput {
                scope,
                identity: &identity,
                registry: &registry,
                expected_descriptor: &descriptor,
                expected_run: &run,
                sources: &sources,
                raw_limits: RawLimits::default(),
                inventory_limits: InventoryLimits::default(),
                started_at: OBSERVED_AT,
                ended_at: OBSERVED_AT,
            },
        },
        &CancellationToken::default(),
    )
}

#[test]
fn exact_ast_calls_emit_frozen_syntax_only_source_evidence() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixtures/source");
    let scope = scope_for(&root, &[("one", "crypto_calls.rs")]);
    let output = run_raw(&scope, &["one"], RawLimits::default());
    assert_eq!(output.status, CollectionStatus::Complete);
    assert_eq!(output.coverage["one"], CoverageState::InspectedObserved);
    assert!(output.diagnostics.is_empty());
    assert_eq!(output.observations.len(), 4);
    let expect = [
        "sha2::Sha256::digest",
        "sha2::Sha512::digest",
        "ring::digest::digest",
        "rustls::ClientConfig::builder",
    ];
    let read = fs::read(root.join("crypto_calls.rs")).unwrap();
    let digest = format!("{:x}", Sha256::digest(read));
    // The bounded sink intentionally orders records by stable hashed event ID,
    // not lexicographic source-call position. Assert syntax in source order by
    // the independently recorded byte offsets, not by arbitrary hash order.
    let mut sites: Vec<_> = output.observations.iter().collect();
    sites.sort_by_key(|record| record.source.offset);
    for (record, name) in sites.into_iter().zip(expect) {
        assert!(matches!(
            &record.fact,
            RawFactKind::Configuration { property, value }
            if property == "source:qualified-crypto-api-call" && value == name
        ));
        assert_eq!(record.source.kind, RawSourceKind::Source);
        assert_eq!(record.source.item, "one");
        assert!(record.source.line.unwrap() > 0);
        assert!(record.source.column.unwrap() > 0);
        assert!(record.source.offset.unwrap() > 0);
        assert_eq!(record.source_sha256.as_deref(), Some(digest.as_str()));
        assert_eq!(record.evidence_kind, EvidenceKind::Direct);
        assert_eq!(
            record.attributes["source:evidence-semantics"],
            "syntactic-call-only"
        );
    }
    let json = serde_json::to_string(&output).unwrap();
    assert!(!json.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(!json.contains("macro_rules"));
    let snapshot = normalized(&scope, &["one"], "tenant-rust").unwrap();
    snapshot
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    assert_eq!(snapshot.evidence.len(), 4);
    assert_eq!(
        snapshot
            .query_assets(|a| matches!(a.kind, AssetKind::SourceUse { .. }))
            .count(),
        4
    );
    assert_eq!(
        snapshot
            .query_assets(|a| matches!(a.kind, AssetKind::AlgorithmUse { .. }))
            .count(),
        0
    );
}

#[test]
fn strings_comments_imports_local_methods_and_macros_are_not_calls() {
    let sandbox = Sandbox::new();
    sandbox.write(
        "no_calls.rs",
        br###"
        use sha2::Sha256;
        fn demo() {
          let _ = "sha2::Sha256::digest(input)";
          // sha2::Sha512::digest(input);
          let _ = Sha256::digest(b"ignored"); 
          let _ = self_digest();
          let _ = fake.sha2();
          let _ = sha2::Sha256::digest!(input);
          macro_rules! hidden { () => { sha2::Sha256::digest(input) } }
        }
        "###,
    );
    let scope = scope_for(&sandbox.root, &[("one", "no_calls.rs")]);
    let output = run_raw(&scope, &["one"], RawLimits::default());
    assert_eq!(
        output.coverage["one"],
        CoverageState::InspectedNoObservation
    );
    assert!(output.observations.is_empty());
    assert_eq!(output.status, CollectionStatus::Complete);
}

#[test]
fn conditional_cfg_source_is_syntax_evidence_not_runtime_confirmation() {
    let sandbox = Sandbox::new();
    sandbox.write(
        "cfg.rs",
        b"#[cfg(any())]\nfn disabled() { let _ = sha2::Sha256::digest(b\"x\"); }\n",
    );
    let scope = scope_for(&sandbox.root, &[("one", "cfg.rs")]);
    let output = run_raw(&scope, &["one"], RawLimits::default());
    assert_eq!(output.observations.len(), 1);
    assert_eq!(output.coverage["one"], CoverageState::InspectedObserved);
}

#[test]
fn independent_file_order_preserves_canonical_snapshot_identity() {
    let sandbox = Sandbox::new();
    sandbox.write("a.rs", b"fn x() { sha2::Sha256::digest(b\"a\"); }");
    sandbox.write("b.rs", b"fn y() { sha2::Sha512::digest(b\"b\"); }");
    let scope = scope_for(&sandbox.root, &[("src:a", "a.rs"), ("src:b", "b.rs")]);
    let first = run_raw(&scope, &["src:a", "src:b"], RawLimits::default());
    let second = run_raw(&scope, &["src:b", "src:a"], RawLimits::default());
    assert_eq!(first.observations, second.observations);
    assert_eq!(first.coverage, second.coverage);
    let a = normalized(&scope, &["src:a", "src:b"], "tenant-rust").unwrap();
    let b = normalized(&scope, &["src:b", "src:a"], "tenant-rust").unwrap();
    assert_eq!(a, b);
    a.verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    let mut different = CollectionScope::new(CollectionScopeId::new("other-tenant").unwrap());
    different
        .grant_file(RawSourceKind::Source, "src:a", &sandbox.root, "a.rs", 8192)
        .unwrap();
    different
        .grant_file(RawSourceKind::Source, "src:b", &sandbox.root, "b.rs", 8192)
        .unwrap();
    let other = normalized(&different, &["src:a", "src:b"], "other-tenant").unwrap();
    assert_ne!(a.id, other.id);
    assert!(
        a.verify_for_scope(different.id(), InventoryLimits::default())
            .is_err()
    );
}

#[test]
fn malformed_utf8_and_oversized_source_are_not_clean() {
    let sandbox = Sandbox::new();
    sandbox.write("bad.rs", b"fn not_closed(");
    sandbox.write("utf8.rs", [0xff, 0xfe, 0xfd]);
    sandbox.write("large.rs", vec![b' '; MAX_RUST_SOURCE_BYTES + 1]);
    let scope = scope_for(
        &sandbox.root,
        &[
            ("bad", "bad.rs"),
            ("utf8", "utf8.rs"),
            ("large", "large.rs"),
        ],
    );
    let output = run_raw(&scope, &["bad", "utf8", "large"], RawLimits::default());
    assert_eq!(output.status, CollectionStatus::Failed);
    assert!(output.observations.is_empty());
    for item in ["bad", "utf8", "large"] {
        assert_eq!(output.coverage[item], CoverageState::Failed);
    }
    assert_eq!(output.diagnostics.len(), 3);
    assert_eq!(
        output.diagnostics[0].code,
        CollectorDiagnosticCode::MalformedSource
    );
    assert_eq!(
        output.diagnostics[1].code,
        CollectorDiagnosticCode::MalformedSource
    );
    assert_eq!(
        output.diagnostics[2].code,
        CollectorDiagnosticCode::ResourceLimit
    );
}

#[test]
fn unsupported_extension_is_explicit_unsupported_and_attempted() {
    let sandbox = Sandbox::new();
    sandbox.write("rules.json", b"fn fake() { sha2::Sha256::digest(b\"x\"); }");
    let scope = scope_for(&sandbox.root, &[("not-rs", "rules.json")]);
    let output = run_raw(&scope, &["not-rs"], RawLimits::default());
    assert_eq!(output.coverage["not-rs"], CoverageState::Unsupported);
    assert_eq!(output.status, CollectionStatus::Failed);
    assert!(output.observations.is_empty());
    assert_eq!(
        output.diagnostics[0].code,
        CollectorDiagnosticCode::UnsupportedSource
    );
}

#[test]
fn resource_limits_prevent_partial_lookalike_and_hidden_overread() {
    let sandbox = Sandbox::new();
    sandbox.write(
        "calls.rs",
        b"fn f() { sha2::Sha256::digest(b\"x\"); sha2::Sha512::digest(b\"y\"); }",
    );
    let scope = scope_for(&sandbox.root, &[("calls", "calls.rs")]);
    let limits = RawLimits {
        observations: 1,
        ..RawLimits::default()
    };
    let output = run_raw(&scope, &["calls"], limits);
    assert_eq!(output.coverage["calls"], CoverageState::Failed);
    assert!(output.observations.is_empty());
    assert_eq!(
        output.diagnostics[0].code,
        CollectorDiagnosticCode::ResourceLimit
    );
    assert!(
        scope
            .open_file(RawSourceKind::Source, "calls")
            .unwrap()
            .read_limited(8)
            .is_err()
    );
}

#[test]
fn deep_syntax_or_large_token_count_is_rejected_before_ast() {
    let sandbox = Sandbox::new();
    sandbox.write("deep.rs", format!("fn x() {{ {} }}", "(".repeat(80)));
    sandbox.write(
        "tokens.rs",
        format!("fn x() {{ {} }}", "let a=0;".repeat(2500)),
    );
    let scope = scope_for(
        &sandbox.root,
        &[("deep", "deep.rs"), ("tokens", "tokens.rs")],
    );
    let output = run_raw(&scope, &["deep", "tokens"], RawLimits::default());
    for item in ["deep", "tokens"] {
        assert_eq!(output.coverage[item], CoverageState::Failed);
    }
    assert!(output.observations.is_empty());
    assert!(
        output
            .diagnostics
            .iter()
            .all(|d| d.code == CollectorDiagnosticCode::ResourceLimit)
    );
}

#[test]
fn missing_after_grant_is_failed_not_clean() {
    let sandbox = Sandbox::new();
    sandbox.write("gone.rs", b"fn x() {}");
    let scope = scope_for(&sandbox.root, &[("gone", "gone.rs")]);
    fs::remove_file(sandbox.root.join("gone.rs")).unwrap();
    let output = run_raw(&scope, &["gone"], RawLimits::default());
    assert_eq!(output.coverage["gone"], CoverageState::Failed);
    assert_eq!(output.status, CollectionStatus::Failed);
    assert!(output.observations.is_empty());
}

#[test]
fn denied_source_or_wrong_tenant_fails_before_normalization() {
    let sandbox = Sandbox::new();
    sandbox.write("safe.rs", b"fn x() {}");
    let scope = scope_for(&sandbox.root, &[("safe", "safe.rs")]);
    let collector = RustSourceCollector::new(&scope, OBSERVED_AT);
    let request = CollectionRequest {
        run: CollectionRunId::new("run-rust").unwrap(),
        sources: sources(&["ungranted"]),
        limits: RawLimits::default(),
        options: Default::default(),
    };
    assert!(collect_scoped(&scope, &collector, request, &CancellationToken::default()).is_err());
    assert!(normalized(&scope, &["safe"], "wrong-tenant").is_err());
    assert!(normalized(&scope, &["ungranted"], "tenant-rust").is_err());
}

#[cfg(unix)]
#[test]
fn file_symlink_cannot_extend_explicit_authority() {
    use std::os::unix::fs::symlink;
    let sandbox = Sandbox::new();
    sandbox.write("outside.rs", b"fn x() {}");
    symlink(
        sandbox.root.join("outside.rs"),
        sandbox.root.join("redirect.rs"),
    )
    .unwrap();
    let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-rust").unwrap());
    assert!(
        scope
            .grant_file(
                RawSourceKind::Source,
                "link",
                &sandbox.root,
                "redirect.rs",
                8192
            )
            .is_err()
    );
}

#[test]
fn cancelled_before_collection_does_not_open_or_claim_clean() {
    let sandbox = Sandbox::new();
    sandbox.write("one.rs", b"fn x() { sha2::Sha256::digest(b\"x\"); }");
    let scope = scope_for(&sandbox.root, &[("one", "one.rs")]);
    let collector = RustSourceCollector::new(&scope, OBSERVED_AT);
    let mut sink = CollectionSink::new(
        collector.descriptor(),
        CollectionRequest {
            run: CollectionRunId::new("run-rust").unwrap(),
            sources: sources(&["one"]),
            limits: RawLimits::default(),
            options: Default::default(),
        },
    )
    .unwrap();
    let cancel = CancellationToken::default();
    cancel.cancel();
    collector
        .collect(
            &CollectionRequest {
                run: CollectionRunId::new("run-rust").unwrap(),
                sources: sources(&["one"]),
                limits: RawLimits::default(),
                options: Default::default(),
            },
            &mut sink,
            &cancel,
        )
        .unwrap();
    let output = sink.finish();
    assert_eq!(output.coverage["one"], CoverageState::NotInspected);
    assert!(output.observations.is_empty());
}

#[test]
fn long_undelimited_expression_chains_fail_before_recursive_ast_parsing() {
    let sandbox = Sandbox::new();
    sandbox.write(
        "unary.rs",
        format!("fn f() {{ let _ = {}true; }}", "!".repeat(250)),
    );
    sandbox.write(
        "binary.rs",
        format!("fn f() {{ let _ = 1{}; }}", "+1".repeat(250)),
    );
    sandbox.write(
        "field.rs",
        format!("fn f() {{ let _ = x{}; }}", ".field".repeat(250)),
    );
    sandbox.write(
        "generic.rs",
        format!("type Deep = {}u8{};", "Vec<".repeat(100), ">".repeat(100)),
    );
    let scope = scope_for(
        &sandbox.root,
        &[
            ("binary", "binary.rs"),
            ("field", "field.rs"),
            ("generic", "generic.rs"),
            ("unary", "unary.rs"),
        ],
    );
    let outcome = run_raw(
        &scope,
        &["binary", "field", "generic", "unary"],
        RawLimits::default(),
    );
    assert_eq!(outcome.status, CollectionStatus::Failed);
    assert!(outcome.observations.is_empty());
    for source in ["binary", "field", "generic", "unary"] {
        assert_eq!(outcome.coverage[source], CoverageState::Failed);
    }
    assert_eq!(outcome.diagnostics.len(), 4);
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|d| d.code == CollectorDiagnosticCode::ResourceLimit)
    );
}

#[test]
fn many_independent_short_statements_remain_supported() {
    let sandbox = Sandbox::new();
    let source = format!("fn normal() {{ {} }}", "let v = 1;".repeat(350));
    sandbox.write("many.rs", source);
    let scope = scope_for(&sandbox.root, &[("many", "many.rs")]);
    let outcome = run_raw(&scope, &["many"], RawLimits::default());
    assert_eq!(
        outcome.coverage["many"],
        CoverageState::InspectedNoObservation
    );
    assert!(outcome.diagnostics.is_empty());
    assert!(outcome.observations.is_empty());
}
