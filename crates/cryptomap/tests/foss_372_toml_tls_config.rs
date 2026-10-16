//! FOSS-372: authorized, bounded, configured-only TOML TLS evidence.
#![cfg(feature = "toml-tls-config")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    AssetKind, CollectionRunId, CoverageState, EvidenceKind, IdentityContext, InventoryLimits,
    InventorySnapshot, ProtocolState,
    batch::BatchLimits,
    collector::{
        CancellationToken, CollectionRequest, CollectionSink, CollectionStatus, Collector,
        CollectorDiagnosticCode, RequestedSource,
    },
    collectors::source::config_toml::{MAX_TOML_TLS_BYTES, TomlTlsConfigCollector},
    coverage::CollectionScopeId,
    orchestration::{ScopedInvocation, collect_normalized, collect_normalized_batch},
    pipeline::{PipelineError, PipelineInput},
    raw::{RawFactKind, RawLimits, RawSourceKind},
    registry::Registry,
    scope::{CollectionScope, ScopeError, collect_scoped, collect_scoped_isolated},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
const AT: &str = "2026-10-13T15:00:00Z";
const BASIC: &str = r#"profile = "cryptomap:tls-config:v1"
[tls]
versions = ["1.2", "1.3"]
cipher_suites = ["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"]
"#;
struct Sandbox {
    root: PathBuf,
}
impl Sandbox {
    fn new() -> Self {
        let root = (0..128)
            .find_map(|_| {
                let count = NEXT.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("cryptomap-foss372-{}-{count}", std::process::id()));
                match fs::create_dir(&path) {
                    Ok(()) => Some(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => panic!("cannot create isolated test directory: {error}"),
                }
            })
            .unwrap();
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
    let mut scope = CollectionScope::new(CollectionScopeId::new("toml-tls-tenant").unwrap());
    for (item, relative) in grants {
        scope
            .grant_file(
                RawSourceKind::Source,
                *item,
                root,
                relative,
                MAX_TOML_TLS_BYTES + 4096,
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
        run: CollectionRunId::new("toml-run").unwrap(),
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
        &TomlTlsConfigCollector::new(scope, AT),
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
    let collector = TomlTlsConfigCollector::new(scope, AT);
    let descriptor = collector.descriptor();
    let run = CollectionRunId::new("toml-run").unwrap();
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
    sandbox.write("tls.toml", payload);
    let scope = scope_for(&sandbox.root, &[("tls:one", "tls.toml")]);
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
fn exact_toml_profile_reports_only_configured_source_evidence() {
    let (_dir, scope) = single_input(BASIC);
    let output = raw(&scope, &["tls:one"], RawLimits::default());
    assert_eq!(output.status, CollectionStatus::Complete);
    assert_eq!(output.coverage["tls:one"], CoverageState::InspectedObserved);
    assert_eq!(output.observations.len(), 4);
    let digest = format!("{:x}", Sha256::digest(BASIC.as_bytes()));
    let mut protocols = 0;
    let mut suites = 0;
    for event in &output.observations {
        assert_eq!(event.source.item, "tls:one");
        assert_eq!(event.source.kind, RawSourceKind::Source);
        assert_eq!(event.source.line, None);
        assert_eq!(event.source.column, None);
        assert_eq!(event.source.offset, None);
        assert_eq!(event.source_sha256.as_deref(), Some(digest.as_str()));
        assert!(event.event_id.starts_with("toml-tls:v1:"));
        assert_eq!(event.evidence_kind, EvidenceKind::Direct);
        assert_eq!(
            event.attributes["source:evidence-semantics"],
            "configured-only"
        );
        match &event.fact {
            RawFactKind::Protocol { family, state, .. } => {
                assert_eq!(family, "TLS");
                assert_eq!(*state, ProtocolState::Configured);
                protocols += 1;
            }
            RawFactKind::Configuration { property, .. } => {
                assert_eq!(property, "tls:configured-cipher-suite");
                suites += 1;
            }
            other => panic!("unexpected fact kind: {other:?}"),
        }
    }
    assert_eq!((protocols, suites), (2, 2));
    let snapshot = normalized(&scope, &["tls:one"], "toml-tls-tenant").unwrap();
    snapshot
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    assert_eq!(snapshot.evidence.len(), 4);
    assert_eq!(
        snapshot
            .query_assets(|a| matches!(
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
        snapshot
            .query_assets(|a| matches!(
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
        snapshot
            .query_assets(|a| matches!(a.kind, AssetKind::AlgorithmUse { .. }))
            .count(),
        0
    );
}
#[test]
fn supported_empty_tls_table_is_inspected_no_observation() {
    let (_dir, scope) = single_input("profile = \"cryptomap:tls-config:v1\"\n[tls]\n");
    let out = raw(&scope, &["tls:one"], RawLimits::default());
    assert_eq!(out.status, CollectionStatus::Complete);
    assert_eq!(
        out.coverage["tls:one"],
        CoverageState::InspectedNoObservation
    );
    assert!(out.observations.is_empty());
    assert!(out.diagnostics.is_empty());
}
#[test]
fn equivalent_explicit_toml_table_headers_are_accepted() {
    for header in ["[tls] # authenticated policy", "['tls']", "[\"tls\"]"] {
        let valid =
            format!("profile = \"cryptomap:tls-config:v1\"\n{header}\nversions = [\"1.3\"]\n");
        let (_box, scope) = single_input(valid);
        let out = raw(&scope, &["tls:one"], RawLimits::default());
        assert_eq!(out.status, CollectionStatus::Complete, "{header}");
        assert_eq!(out.coverage["tls:one"], CoverageState::InspectedObserved);
        assert_eq!(out.observations.len(), 1);
    }
}

#[test]
fn dotted_implicit_tables_and_inline_tables_are_not_explicit_grants() {
    for bad in [
        "tls.versions = [\"1.3\"]\n",
        "tls = { versions = [\"1.3\"] }\n",
    ] {
        assert_failed(
            format!("profile = \"cryptomap:tls-config:v1\"\n{bad}"),
            CollectorDiagnosticCode::MalformedSource,
        );
    }
}

#[test]
fn unsupported_profile_is_not_reported_clean() {
    let (_dir, scope) = single_input("profile = \"cryptomap:tls-config:v2\"\n[tls]\n");
    let out = raw(&scope, &["tls:one"], RawLimits::default());
    assert_eq!(out.coverage["tls:one"], CoverageState::Unsupported);
    assert!(out.observations.is_empty());
    assert_eq!(
        out.diagnostics[0].code,
        CollectorDiagnosticCode::UnsupportedSource
    );
}
#[test]
fn missing_marker_missing_table_and_inline_table_are_malformed() {
    for bad in [
        "[tls]\nversions = [\"1.3\"]\n",
        "profile = \"cryptomap:tls-config:v1\"\n",
        "profile = \"cryptomap:tls-config:v1\"\ntls = { versions = [\"1.3\"] }\n",
        "profile = 99\n[tls]\n",
        "profile = \"cryptomap:tls-config:v1\"\n[tls]\nversions = \"1.3\"\n",
        "profile = \"cryptomap:tls-config:v1\"\n[tls]\nversions = [7]\n",
    ] {
        assert_failed(bad, CollectorDiagnosticCode::MalformedSource);
    }
}
#[test]
fn secret_bearing_fields_and_duplicate_table_keys_fail_without_leakage() {
    for bad in [
        "profile = \"cryptomap:tls-config:v1\"\n[tls]\nprivate_key = \"-----BEGIN PRIVATE KEY-----\"\n",
        "profile = \"cryptomap:tls-config:v1\"\n[tls]\npassword = \"do-not-echo\"\n",
        "profile = \"cryptomap:tls-config:v1\"\n[tls]\nversions = []\nversions = []\n",
        "profile = \"cryptomap:tls-config:v1\"\nprofile = \"cryptomap:tls-config:v1\"\n[tls]\n",
        "profile = \"cryptomap:tls-config:v1\"\nsecret = \"do-not-echo\"\n[tls]\n",
        "profile = \"cryptomap:tls-config:v1\"\n[tls]\nversions = []\n[tls]\n",
    ] {
        let (_dir, scope) = single_input(bad);
        let out = raw(&scope, &["tls:one"], RawLimits::default());
        assert_eq!(out.coverage["tls:one"], CoverageState::Failed);
        assert_eq!(
            out.diagnostics[0].code,
            CollectorDiagnosticCode::MalformedSource
        );
        assert!(out.observations.is_empty());
        for report in [serde_json::to_string(&out).unwrap(), format!("{out:?}")] {
            assert!(!report.contains("do-not-echo"));
            assert!(!report.contains("BEGIN PRIVATE KEY"));
        }
    }
}
#[test]
fn duplicate_values_unsupported_cipher_and_versions_are_malformed() {
    for bad in [
        "versions = [\"1.3\", \"1.3\"]",
        "versions = [\"1.4\"]",
        "versions = [\"\"]",
        "cipher_suites = [\"TLS_AES_128_GCM_SHA256\", \"TLS_AES_128_GCM_SHA256\"]",
        "cipher_suites = [\"TLS_NOT_REAL\"]",
        "versions = [\"TLS1.3\"]",
    ] {
        let bad = format!("profile = \"cryptomap:tls-config:v1\"\n[tls]\n{bad}\n");
        assert_failed(bad, CollectorDiagnosticCode::MalformedSource);
    }
}
#[test]
fn array_limits_and_raw_budget_prevent_partial_false_evidence() {
    let many = vec!["\"1.3\""; 50].join(", ");
    assert_failed(
        format!("profile = \"cryptomap:tls-config:v1\"\n[tls]\nversions = [{many}]\n"),
        CollectorDiagnosticCode::MalformedSource,
    );
    let (_dir, scope) = single_input(BASIC);
    let budget = RawLimits {
        observations: 1,
        ..RawLimits::default()
    };
    let out = raw(&scope, &["tls:one"], budget);
    assert_eq!(out.coverage["tls:one"], CoverageState::Failed);
    assert_eq!(
        out.diagnostics[0].code,
        CollectorDiagnosticCode::ResourceLimit
    );
    assert!(out.observations.is_empty());
}
#[test]
fn invalid_utf8_bad_syntax_and_oversized_file_fail_closed() {
    assert_failed(b"\xff\xff", CollectorDiagnosticCode::MalformedSource);
    assert_failed(
        "profile =\n[tls]\n",
        CollectorDiagnosticCode::MalformedSource,
    );
    assert_failed("[".repeat(140), CollectorDiagnosticCode::MalformedSource);
    let huge = format!("{BASIC}{}", " ".repeat(MAX_TOML_TLS_BYTES + 1));
    assert_failed(huge, CollectorDiagnosticCode::ResourceLimit);
}
#[test]
fn extension_comes_from_grant_not_untrusted_item_name() {
    let sandbox = Sandbox::new();
    sandbox.write("not-toml.txt", BASIC);
    let scope = scope_for(&sandbox.root, &[("trusted.toml", "not-toml.txt")]);
    let out = raw(&scope, &["trusted.toml"], RawLimits::default());
    assert_eq!(out.coverage["trusted.toml"], CoverageState::Unsupported);
    assert!(out.observations.is_empty());
    assert_eq!(
        out.diagnostics[0].code,
        CollectorDiagnosticCode::UnsupportedSource
    );
}
#[test]
fn mixed_valid_and_malformed_sources_keep_partial_with_explicit_failure() {
    let sandbox = Sandbox::new();
    sandbox.write("good.toml", BASIC);
    sandbox.write("bad.toml", "[tls]\nsecret = \"nope\"\n");
    let scope = scope_for(&sandbox.root, &[("good", "good.toml"), ("bad", "bad.toml")]);
    let out = raw(&scope, &["good", "bad"], RawLimits::default());
    assert_eq!(out.status, CollectionStatus::Partial);
    assert_eq!(out.coverage["good"], CoverageState::InspectedObserved);
    assert_eq!(out.coverage["bad"], CoverageState::Failed);
    assert_eq!(out.observations.len(), 4);
    let snapshot = normalized(&scope, &["good", "bad"], "toml-tls-tenant").unwrap();
    snapshot
        .verify_for_scope(scope.id(), InventoryLimits::default())
        .unwrap();
    assert_eq!(snapshot.evidence.len(), 4);
}
#[test]
fn deterministic_order_and_changed_source_digest_are_visible() {
    let sandbox = Sandbox::new();
    sandbox.write("a.toml", BASIC);
    sandbox.write(
        "b.toml",
        "profile = \"cryptomap:tls-config:v1\"\n[tls]\nversions = [\"1.3\"]\n",
    );
    let scope = scope_for(&sandbox.root, &[("a", "a.toml"), ("b", "b.toml")]);
    assert_eq!(
        raw(&scope, &["a", "b"], RawLimits::default()),
        raw(&scope, &["b", "a"], RawLimits::default())
    );
    let a = normalized(&scope, &["a", "b"], "toml-tls-tenant").unwrap();
    let b = normalized(&scope, &["b", "a"], "toml-tls-tenant").unwrap();
    assert_eq!(a, b);
    assert!(normalized(&scope, &["a", "b"], "other-tenant").is_err());
    let before = raw(&scope, &["a"], RawLimits::default());
    sandbox.write(
        "a.toml",
        BASIC.replace("TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_256_GCM_SHA384"),
    );
    let after = raw(&scope, &["a"], RawLimits::default());
    assert_ne!(before.observations, after.observations);
    assert_ne!(
        before.observations[0].source_sha256,
        after.observations[0].source_sha256
    );
}
#[test]
fn unauthorized_request_rejected_before_any_files_are_opened() {
    let sandbox = Sandbox::new();
    sandbox.write("removed.toml", BASIC);
    let scope = scope_for(&sandbox.root, &[("allowed", "removed.toml")]);
    fs::remove_file(sandbox.root.join("removed.toml")).unwrap();
    let collector = TomlTlsConfigCollector::new(&scope, AT);
    assert!(
        collect_scoped(
            &scope,
            &collector,
            request(&["allowed", "ungranted"], RawLimits::default()),
            &CancellationToken::default()
        )
        .is_err()
    );
    assert!(normalized(&scope, &["ungranted"], "toml-tls-tenant").is_err());
    assert_eq!(
        raw(&scope, &["allowed"], RawLimits::default()).coverage["allowed"],
        CoverageState::Failed
    );
}
#[test]
fn cancellation_is_uninspected_not_negative_evidence() {
    let (_dir, scope) = single_input(BASIC);
    let collector = TomlTlsConfigCollector::new(&scope, AT);
    let req = request(&["tls:one"], RawLimits::default());
    let mut sink = CollectionSink::new(collector.descriptor(), req.clone()).unwrap();
    let cancel = CancellationToken::default();
    cancel.cancel();
    collector.collect(&req, &mut sink, &cancel).unwrap();
    let out = sink.finish();
    assert_eq!(out.coverage["tls:one"], CoverageState::NotInspected);
    assert!(out.observations.is_empty());
    assert_eq!(out.diagnostics[0].code, CollectorDiagnosticCode::Cancelled);
}
#[cfg(unix)]
#[test]
fn symlink_targets_are_not_extended_into_approved_grants() {
    use std::os::unix::fs::symlink;
    let sandbox = Sandbox::new();
    sandbox.write("real.toml", BASIC);
    symlink(
        sandbox.root.join("real.toml"),
        sandbox.root.join("link.toml"),
    )
    .unwrap();
    let mut scope = CollectionScope::new(CollectionScopeId::new("toml-tls-tenant").unwrap());
    assert!(
        scope
            .grant_file(
                RawSourceKind::Source,
                "link",
                &sandbox.root,
                "link.toml",
                4096
            )
            .is_err()
    );
}
#[test]
fn collector_scope_mismatch_rejected_in_raw_isolated_normalized_and_batch() {
    let a = Sandbox::new();
    let b = Sandbox::new();
    a.write("tls.toml", BASIC);
    b.write(
        "tls.toml",
        "profile = \"cryptomap:tls-config:v1\"\n[tls]\nversions = [\"1.3\"]\n",
    );
    let scope_a = scope_for(&a.root, &[("same", "tls.toml")]);
    let scope_b = scope_for(&b.root, &[("same", "tls.toml")]);
    let collector = TomlTlsConfigCollector::new(&scope_a, AT);
    assert!(collector.matches_invocation_scope(&scope_a));
    assert!(!collector.matches_invocation_scope(&scope_b));
    let req = request(&["same"], RawLimits::default());
    let cancel = CancellationToken::default();
    assert!(matches!(
        collect_scoped(&scope_b, &collector, req.clone(), &cancel),
        Err(ScopeError::OutOfScope)
    ));
    assert!(matches!(
        collect_scoped_isolated(&scope_b, &collector, req.clone(), &cancel),
        Err(ScopeError::OutOfScope)
    ));
    let descriptor = collector.descriptor();
    let run = req.run.clone();
    let identity = IdentityContext::new("toml-tls-tenant").unwrap();
    let registry = Registry::builtin();
    let sources = sources(&["same"]);
    let inv = || ScopedInvocation {
        collector: &collector,
        input: PipelineInput {
            scope: &scope_b,
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
    };
    assert!(matches!(
        collect_normalized(inv(), &cancel),
        Err(PipelineError::Scope(ScopeError::OutOfScope))
    ));
    assert!(matches!(
        collect_normalized_batch(vec![inv()], BatchLimits::default(), &cancel),
        Err(PipelineError::Scope(ScopeError::OutOfScope))
    ));
    assert_eq!(
        collect_scoped(&scope_a, &collector, req, &cancel)
            .unwrap()
            .status,
        CollectionStatus::Complete
    );
}
