//! FOSS-371: authorized, bounded, configured-only JSON TLS evidence.
#![cfg(feature = "json-tls-config")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    AssetKind, CollectionRunId, CoverageState, EvidenceKind, IdentityContext, InventoryLimits,
    InventorySnapshot, ProtocolState,
    collector::{
        CancellationToken, CollectionRequest, CollectionSink, CollectionStatus, Collector,
        CollectorDiagnosticCode, RequestedSource,
    },
    collectors::source::config_json::{JsonTlsConfigCollector, MAX_JSON_TLS_BYTES, PROFILE},
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
const AT: &str = "2026-10-13T15:00:00Z";
const BASIC: &str = r#"{"profile":"cryptomap:tls-config:v1","tls":{"versions":["1.2","1.3"],"cipher_suites":["TLS_AES_128_GCM_SHA256","TLS_CHACHA20_POLY1305_SHA256"]}}"#;
struct Sandbox {
    root: PathBuf,
}
impl Sandbox {
    fn new() -> Self {
        let count = NEXT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("cryptomap-foss371-{}-{count}", std::process::id()));
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
fn scope_for(root: &Path, grants: &[(&str, &str)]) -> CollectionScope {
    let mut scope = CollectionScope::new(CollectionScopeId::new("json-tls-tenant").unwrap());
    for (item, relative) in grants {
        scope
            .grant_file(
                RawSourceKind::Source,
                *item,
                root,
                relative,
                MAX_JSON_TLS_BYTES + 4096,
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
fn request(items: &[&str], limits: RawLimits) -> CollectionRequest {
    CollectionRequest {
        run: CollectionRunId::new("json-run").unwrap(),
        sources: sources(items),
        limits,
        options: Default::default(),
    }
}
fn raw(
    scope: &CollectionScope,
    items: &[&str],
    limits: RawLimits,
) -> cryptomap::collector::CollectionOutcome {
    collect_scoped(
        scope,
        &JsonTlsConfigCollector::new(scope, AT),
        request(items, limits),
        &CancellationToken::default(),
    )
    .unwrap()
}
fn normalized(
    scope: &CollectionScope,
    items: &[&str],
    tenant: &str,
) -> Result<InventorySnapshot, PipelineError> {
    let collector = JsonTlsConfigCollector::new(scope, AT);
    let descriptor = collector.descriptor();
    let run = CollectionRunId::new("json-run").unwrap();
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
                started_at: AT,
                ended_at: AT,
            },
        },
        &CancellationToken::default(),
    )
}
fn single_input(payload: impl AsRef<[u8]>) -> (Sandbox, CollectionScope) {
    let sandbox = Sandbox::new();
    sandbox.write("tls.json", payload);
    let scope = scope_for(&sandbox.root, &[("tls:one", "tls.json")]);
    (sandbox, scope)
}
fn assert_failed(bytes: impl AsRef<[u8]>, expected: CollectorDiagnosticCode) {
    let (_sandbox, scope) = single_input(bytes);
    let outcome = raw(&scope, &["tls:one"], RawLimits::default());
    assert_eq!(outcome.status, CollectionStatus::Failed);
    assert_eq!(outcome.coverage["tls:one"], CoverageState::Failed);
    assert!(outcome.observations.is_empty());
    assert_eq!(outcome.diagnostics.len(), 1);
    assert_eq!(outcome.diagnostics[0].code, expected);
}
#[test]
fn exact_document_profile_emits_only_direct_configured_facts() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixtures/config");
    let scope = scope_for(&fixture, &[("one", "tls.json")]);
    let output = raw(&scope, &["one"], RawLimits::default());
    assert_eq!(output.status, CollectionStatus::Complete);
    assert_eq!(output.coverage["one"], CoverageState::InspectedObserved);
    assert_eq!(output.observations.len(), 4);
    assert!(output.diagnostics.is_empty());
    let bytes = fs::read(fixture.join("tls.json")).unwrap();
    let digest = format!("{:x}", Sha256::digest(bytes));
    let mut versions = 0;
    let mut suites = 0;
    for fact in &output.observations {
        assert_eq!(fact.source.item, "one");
        assert_eq!(fact.source.kind, RawSourceKind::Source);
        assert_eq!(fact.source.line, None);
        assert_eq!(fact.source.column, None);
        assert_eq!(fact.source.offset, None);
        assert_eq!(fact.source_sha256.as_deref(), Some(digest.as_str()));
        assert_eq!(fact.evidence_kind, EvidenceKind::Direct);
        assert_eq!(fact.attributes["source:parser-profile"], PROFILE);
        assert_eq!(
            fact.attributes["source:evidence-semantics"],
            "configured-only"
        );
        match &fact.fact {
            RawFactKind::Protocol {
                family,
                version: Some(version),
                state: ProtocolState::Configured,
            } => {
                assert_eq!(family, "TLS");
                assert!(version == "1.2" || version == "1.3");
                versions += 1;
            }
            RawFactKind::Configuration { property, value } => {
                assert_eq!(property, "tls:configured-cipher-suite");
                assert!(
                    value == "TLS_AES_128_GCM_SHA256" || value == "TLS_CHACHA20_POLY1305_SHA256"
                );
                suites += 1;
            }
            other => panic!("unexpected fact: {other:?}"),
        }
    }
    assert_eq!((versions, suites), (2, 2));
    let snap = normalized(&scope, &["one"], "json-tls-tenant").unwrap();
    snap.verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    assert_eq!(snap.evidence.len(), 4);
    assert_eq!(
        snap.query_assets(|a| matches!(
            a.kind,
            AssetKind::Protocol {
                state: ProtocolState::Configured,
                ..
            }
        ))
        .count(),
        2
    );
    assert_eq!(
        snap.query_assets(|a| matches!(
            a.kind,
            AssetKind::Protocol {
                state: ProtocolState::Negotiated,
                ..
            }
        ))
        .count(),
        0
    );
    assert_eq!(
        snap.query_assets(|a| matches!(a.kind, AssetKind::AlgorithmUse { .. }))
            .count(),
        0
    );
}
#[test]
fn profile_with_no_settings_is_clean_only_after_successful_inspection() {
    let (_box, scope) = single_input(r#"{"profile":"cryptomap:tls-config:v1","tls":{}}"#);
    let result = raw(&scope, &["tls:one"], RawLimits::default());
    assert_eq!(result.status, CollectionStatus::Complete);
    assert_eq!(
        result.coverage["tls:one"],
        CoverageState::InspectedNoObservation
    );
    assert!(result.observations.is_empty());
    assert!(result.diagnostics.is_empty());
}
#[test]
fn unknown_versioned_profile_is_explicitly_unsupported() {
    let (_box, scope) = single_input(r#"{"profile":"cryptomap:tls-config:v2","tls":{}}"#);
    let output = raw(&scope, &["tls:one"], RawLimits::default());
    assert_eq!(output.status, CollectionStatus::Failed);
    assert_eq!(output.coverage["tls:one"], CoverageState::Unsupported);
    assert_eq!(
        output.diagnostics[0].code,
        CollectorDiagnosticCode::UnsupportedSource
    );
    assert!(output.observations.is_empty());
}
#[test]
fn missing_profile_or_wrong_shape_cannot_assert_clean() {
    for bytes in [
        r#"{"tls":{}}"#,
        r#"{"profile":"cryptomap:tls-config:v1"}"#,
        r#"{"profile":5,"tls":{}}"#,
        r#"[]"#,
        r#"{"profile":"cryptomap:tls-config:v1","tls":{"versions":"1.3"}}"#,
        r#"{"profile":"cryptomap:tls-config:v1","tls":null}"#,
    ] {
        assert_failed(bytes, CollectorDiagnosticCode::MalformedSource);
    }
}
#[test]
fn secrets_unknown_fields_and_key_duplicates_are_rejected_without_leak() {
    for bytes in [
        r#"{"profile":"cryptomap:tls-config:v1","tls":{"private_key":"-----BEGIN PRIVATE KEY-----"}}"#,
        r#"{"profile":"cryptomap:tls-config:v1","tls":{"password":"do-not-echo"}}"#,
        r#"{"profile":"cryptomap:tls-config:v1","tls":{"versions":[],"versions":[]}}"#,
        r#"{"profile":"cryptomap:tls-config:v1","profile":"cryptomap:tls-config:v1","tls":{}}"#,
        r#"{"profile":"cryptomap:tls-config:v1","tls":{},"secret":"do-not-echo"}"#,
    ] {
        let (_box, scope) = single_input(bytes);
        let result = raw(&scope, &["tls:one"], RawLimits::default());
        assert_eq!(result.coverage["tls:one"], CoverageState::Failed);
        assert_eq!(
            result.diagnostics[0].code,
            CollectorDiagnosticCode::MalformedSource
        );
        assert!(result.observations.is_empty());
        let json = serde_json::to_string(&result).unwrap();
        let debug = format!("{result:?}");
        for report in [&json, &debug] {
            assert!(!report.contains("do-not-echo"));
            assert!(!report.contains("BEGIN PRIVATE KEY"));
        }
    }
}
#[test]
fn duplicate_values_unknown_settings_and_empty_names_fail() {
    for bad in [
        r#"{"profile":"cryptomap:tls-config:v1","tls":{"versions":["1.3","1.3"]}}"#,
        r#"{"profile":"cryptomap:tls-config:v1","tls":{"cipher_suites":["TLS_AES_128_GCM_SHA256","TLS_AES_128_GCM_SHA256"]}}"#,
        r#"{"profile":"cryptomap:tls-config:v1","tls":{"versions":["1.4"]}}"#,
        r#"{"profile":"cryptomap:tls-config:v1","tls":{"versions":[""]}}"#,
        r#"{"profile":"cryptomap:tls-config:v1","tls":{"cipher_suites":["TLS_NOT_REAL"]}}"#,
        r#"{"profile":"cryptomap:tls-config:v1","tls":{"versions":["TLS1.3"]}}"#,
    ] {
        assert_failed(bad, CollectorDiagnosticCode::MalformedSource);
    }
}
#[test]
fn bounded_lists_fail_without_partial_evidence() {
    let many_versions = format!(
        r#"{{"profile":"cryptomap:tls-config:v1","tls":{{"versions":[{}]}}}}"#,
        vec!["\"1.3\""; 50].join(","),
    );
    let many_suites = format!(
        r#"{{"profile":"cryptomap:tls-config:v1","tls":{{"cipher_suites":[{}]}}}}"#,
        vec!["\"TLS_AES_128_GCM_SHA256\""; 40].join(","),
    );
    assert_failed(many_versions, CollectorDiagnosticCode::MalformedSource);
    assert_failed(many_suites, CollectorDiagnosticCode::MalformedSource);
}
#[test]
fn malformed_invalid_utf8_depth_and_oversized_input_fail_closed() {
    assert_failed(b"{broken", CollectorDiagnosticCode::MalformedSource);
    assert_failed([0xff, 0xfe, 0xfd], CollectorDiagnosticCode::MalformedSource);
    assert_failed("[".repeat(140), CollectorDiagnosticCode::MalformedSource);
    let huge = format!("{}{}", BASIC, " ".repeat(MAX_JSON_TLS_BYTES + 1));
    assert_failed(huge, CollectorDiagnosticCode::ResourceLimit);
}
#[test]
fn extension_comes_from_grant_not_from_untrusted_request_item() {
    let box_ = Sandbox::new();
    box_.write("not-json.txt", BASIC);
    let scope = scope_for(&box_.root, &[("tls.json", "not-json.txt")]);
    let result = raw(&scope, &["tls.json"], RawLimits::default());
    assert_eq!(result.coverage["tls.json"], CoverageState::Unsupported);
    assert!(result.observations.is_empty());
    assert_eq!(
        result.diagnostics[0].code,
        CollectorDiagnosticCode::UnsupportedSource
    );
}
#[test]
fn raw_budget_is_checked_before_emitting_any_records_for_one_file() {
    let (_box, scope) = single_input(BASIC);
    let limits = RawLimits {
        observations: 1,
        ..RawLimits::default()
    };
    let out = raw(&scope, &["tls:one"], limits);
    assert_eq!(out.coverage["tls:one"], CoverageState::Failed);
    assert!(out.observations.is_empty());
    assert_eq!(
        out.diagnostics[0].code,
        CollectorDiagnosticCode::ResourceLimit
    );
}
#[test]
fn mixed_valid_and_invalid_sources_keep_successes_and_failed_coverage() {
    let box_ = Sandbox::new();
    box_.write("good.json", BASIC);
    box_.write("bad.json", b"{bad");
    let scope = scope_for(&box_.root, &[("good", "good.json"), ("bad", "bad.json")]);
    let result = raw(&scope, &["good", "bad"], RawLimits::default());
    assert_eq!(result.status, CollectionStatus::Partial);
    assert_eq!(result.coverage["good"], CoverageState::InspectedObserved);
    assert_eq!(result.coverage["bad"], CoverageState::Failed);
    assert_eq!(result.observations.len(), 4);
    let snapshot = normalized(&scope, &["good", "bad"], "json-tls-tenant").unwrap();
    snapshot
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    assert_eq!(snapshot.evidence.len(), 4);
}
#[test]
fn reordering_sources_preserves_raw_and_normalized_identity() {
    let box_ = Sandbox::new();
    box_.write("a.json", BASIC);
    box_.write(
        "b.json",
        r#"{"profile":"cryptomap:tls-config:v1","tls":{"versions":["1.3"]}}"#,
    );
    let scope = scope_for(&box_.root, &[("a", "a.json"), ("b", "b.json")]);
    let first = raw(&scope, &["a", "b"], RawLimits::default());
    let again = raw(&scope, &["b", "a"], RawLimits::default());
    assert_eq!(first, again);
    let left = normalized(&scope, &["a", "b"], "json-tls-tenant").unwrap();
    let right = normalized(&scope, &["b", "a"], "json-tls-tenant").unwrap();
    assert_eq!(left, right);
    assert!(normalized(&scope, &["a", "b"], "other-tenant").is_err());
}
#[test]
fn content_modification_changes_evidence_identity_without_guessing_runtime_use() {
    let box_ = Sandbox::new();
    box_.write("tls.json", BASIC);
    let scope = scope_for(&box_.root, &[("one", "tls.json")]);
    let before = raw(&scope, &["one"], RawLimits::default());
    let newer = BASIC.replace("TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_256_GCM_SHA384");
    box_.write("tls.json", newer);
    let after = raw(&scope, &["one"], RawLimits::default());
    assert_ne!(before.observations, after.observations);
    assert_eq!(before.coverage, after.coverage);
    assert_ne!(
        before.observations[0].source_sha256,
        after.observations[0].source_sha256
    );
}
#[test]
fn unauthorized_source_fails_preflight_before_any_requested_file_is_read() {
    let box_ = Sandbox::new();
    box_.write("vanished.json", BASIC);
    let scope = scope_for(&box_.root, &[("allowed", "vanished.json")]);
    fs::remove_file(box_.root.join("vanished.json")).unwrap();
    let collector = JsonTlsConfigCollector::new(&scope, AT);
    let failed = collect_scoped(
        &scope,
        &collector,
        request(&["allowed", "ungranted"], RawLimits::default()),
        &CancellationToken::default(),
    );
    assert!(failed.is_err());
    assert!(normalized(&scope, &["ungranted"], "json-tls-tenant").is_err());
    let attempted = raw(&scope, &["allowed"], RawLimits::default());
    assert_eq!(attempted.coverage["allowed"], CoverageState::Failed);
}
#[test]
fn pre_cancelled_collection_is_uninspected_not_failed_or_clean() {
    let (_box, scope) = single_input(BASIC);
    let collector = JsonTlsConfigCollector::new(&scope, AT);
    let req = request(&["tls:one"], RawLimits::default());
    let mut sink = CollectionSink::new(collector.descriptor(), req.clone()).unwrap();
    let cancel = CancellationToken::default();
    cancel.cancel();
    collector.collect(&req, &mut sink, &cancel).unwrap();
    let output = sink.finish();
    assert_eq!(output.coverage["tls:one"], CoverageState::NotInspected);
    assert!(output.observations.is_empty());
    assert_eq!(
        output.diagnostics[0].code,
        CollectorDiagnosticCode::Cancelled
    );
}
#[cfg(unix)]
#[test]
fn file_symlinks_cannot_extend_authority() {
    use std::os::unix::fs::symlink;
    let box_ = Sandbox::new();
    box_.write("real.json", BASIC);
    symlink(box_.root.join("real.json"), box_.root.join("link.json")).unwrap();
    let mut scope = CollectionScope::new(CollectionScopeId::new("json-tls-tenant").unwrap());
    assert!(
        scope
            .grant_file(RawSourceKind::Source, "link", &box_.root, "link.json", 4096)
            .is_err()
    );
}
