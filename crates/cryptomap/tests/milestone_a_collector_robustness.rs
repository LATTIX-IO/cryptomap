//! Deterministic, bounded release smoke for hostile Cargo/npm source bytes.
//! This is a corpus-based regression, not a coverage-guided fuzz campaign.
#![allow(clippy::unwrap_used)]

use cryptomap::{
    CollectionRunId, CoverageState,
    collector::{CancellationToken, CollectionRequest, CollectionStatus, RequestedSource},
    collectors::dependency::{
        manifest_collector::CargoManifestCollector, npm::NpmLockfileCollector,
        npm_manifest_collector::NpmManifestCollector,
    },
    coverage::CollectionScopeId,
    raw::{RawLimits, RawSourceKind},
    scope::{CollectionScope, collect_scoped},
};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

const CASES: usize = 32;
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new(filename: &str, bytes: &[u8]) -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cryptomap-a-fuzz-smoke-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::write(path.join(filename), bytes).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Confirm a known-invalid document cannot produce confirmed observations or
/// an inspected-no-observation coverage state through the public collector API.
fn assert_rejected(kind: &str, bytes: &[u8]) {
    let (filename, source) = match kind {
        "cargo" => ("Cargo.toml", "cargo:manifest"),
        "npm-manifest" => ("package.json", "npm:manifest"),
        "npm-lock" => ("package-lock.json", "npm:lock"),
        _ => panic!("unknown test collector"),
    };
    let fixture = Fixture::new(filename, bytes);
    let mut scope = CollectionScope::new(CollectionScopeId::new("tenant-a").unwrap());
    scope
        .grant_file(
            RawSourceKind::Dependency,
            source,
            &fixture.0,
            filename,
            4096,
        )
        .unwrap();
    let request = CollectionRequest {
        run: CollectionRunId::new("release-fuzz-run").unwrap(),
        sources: vec![RequestedSource {
            kind: RawSourceKind::Dependency,
            item: source.into(),
        }],
        limits: RawLimits::default(),
        options: BTreeMap::new(),
    };
    let cancelled = CancellationToken::default();
    let at = "2026-10-12T12:00:00Z";
    let result = match kind {
        "cargo" => collect_scoped(
            &scope,
            &CargoManifestCollector::new(&scope, at),
            request,
            &cancelled,
        ),
        "npm-manifest" => collect_scoped(
            &scope,
            &NpmManifestCollector::new(&scope, at),
            request,
            &cancelled,
        ),
        "npm-lock" => collect_scoped(
            &scope,
            &NpmLockfileCollector::new(&scope, at),
            request,
            &cancelled,
        ),
        _ => unreachable!(),
    }
    .unwrap();
    assert_eq!(result.status, CollectionStatus::Failed, "{kind}");
    assert_eq!(result.coverage[source], CoverageState::Failed, "{kind}");
    assert!(result.observations.is_empty(), "{kind}");
    assert!(!result.diagnostics.is_empty(), "{kind}");
}

#[test]
fn seeded_unsupported_profiles_never_report_clean_absence() {
    for i in 0..CASES {
        let cargo = format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nunknown_{i:03} = true\n[dependencies]\nring = \"=0.17.12\"\n"
        );
        assert_rejected("cargo", cargo.as_bytes());

        let manifest = r#"{"name":"app","version":"1.0.0","UNSUPPORTED":false,"dependencies":{"ring":"1.2.3"}}"#
            .replace("UNSUPPORTED", &format!("unknown_{i:03}"));
        assert_rejected("npm-manifest", manifest.as_bytes());

        let lock = r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/../ESCAPE":{"version":"1.2.3"}}}"#
            .replace("ESCAPE", &format!("escape_{i:03}"));
        assert_rejected("npm-lock", lock.as_bytes());
    }
}

#[test]
fn seeded_invalid_utf8_and_random_tail_are_fail_closed_and_bounded() {
    let mut state = 0x4F62_91AA_275C_803Du64;
    for i in 0..CASES {
        let length = 1 + ((i * 37) % 255);
        // The first byte guarantees malformed UTF-8. The tail deterministically
        // exercises varied lengths and byte distributions without dependencies,
        // network access, nondeterministic seeds or a runner time budget.
        let mut bytes = Vec::with_capacity(length);
        bytes.push(0xff);
        for _ in 1..length {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.push(state as u8);
        }
        for kind in ["cargo", "npm-manifest", "npm-lock"] {
            assert_rejected(kind, &bytes);
        }
    }
}
