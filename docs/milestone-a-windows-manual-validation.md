# Milestone A: inspectable Windows / PowerShell release acceptance

This is a **step-through operator walkthrough**, not a script that prints "Passed".
Execute each block individually in **PowerShell 7** from the checked-out
`LATTIX-IO/cryptomap` repository root. Read the outputs and record actual
values. The code exercises the shipped passive Cargo/npm collectors, the
canonical snapshot contract, and the exact local package archive.

**Prerequisites:** Git; Rustup/Cargo with **both Rust 1.99.0 (including rustfmt
and Clippy) and Rust 1.85.0** already installed; PowerShell 7; Python 3.11+
(for `tomllib`); tar; and optionally `gh` with authorized read access to this
repository. `rust-toolchain.toml` selects 1.99.0 for unqualified `cargo`
commands; Rust 1.85.0 is used *only* when explicitly selected by `+1.85.0`.
Install both toolchains deliberately before an offline validation: otherwise
Rustup will attempt an unplanned network download.
Run in an isolated development workspace, not on a production source tree.
This walkthrough performs no registry publication or credential operations.

## 1. Inspect exactly what you are testing

~~~powershell
Set-Location (git rev-parse --show-toplevel)
if ($LASTEXITCODE -ne 0) { throw 'Not in the cryptomap Git checkout' }
$head = (git rev-parse HEAD).Trim()
$branch = (git branch --show-current).Trim()
git status --short
$head
$branch
cargo --version
rustc --version
rustup run 1.85.0 rustc --version
python --version
~~~

Check that `$head` is the exact, reviewed 40-character source commit you
intend to qualify; a green check from another SHA is not sufficient. The
reference CI uses Linux and Windows and separately checks the 1.85 MSRV.
Record any uncommitted modifications; do not attribute a locally modified
build to the signed repository SHA. On main, version is
`0.1.1-alpha.1`; **publish is deliberately disabled**.

## 2. Inspect real source files before collecting

~~~powershell
$cargoRoot = (Resolve-Path 'crates/cryptomap/examples/fixtures/cargo').Path
Get-Content (Join-Path $cargoRoot 'Cargo.toml')
Get-Content (Join-Path $cargoRoot 'Cargo.lock')
Get-FileHash (Join-Path $cargoRoot 'Cargo.lock') -Algorithm SHA256

$npmRoot = (Resolve-Path 'crates/cryptomap/examples/fixtures/npm').Path
Get-Content (Join-Path $npmRoot 'package.json')
Get-Content (Join-Path $npmRoot 'package-lock.json')
Get-FileHash (Join-Path $npmRoot 'package-lock.json') -Algorithm SHA256
~~~

The Cargo fixture declares `ring = "=0.17.12"` and a lockfile package.
The npm fixture has an exact `@scope/ring` package version. These files
supply evidence of **package presence**. They do not prove that a cryptographic
algorithm was executed. Each example explicitly grants **only** its manifest
and lockfile; it does not search the rest of a repository, run package
installation scripts, or make network connections as part of collection.

## 3. Run the Cargo collector twice and compare the actual snapshot

Use a pinned demonstration timestamp, tenant identity and unique run
prefix. Two runs with *identical* input/identity/time must produce the same
verified snapshot line; changing the tenant must change it.

~~~powershell
$at = '2026-10-12T12:00:00Z'
$tenant = 'manual-cargo-tenant'
$run = 'manual-fixture-20261013'

$first = & cargo run --quiet --locked -p cryptomap --example cargo_scoped_inventory -- $cargoRoot $at $tenant $run 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { throw "Cargo collection failed: $first" }
$first

$second = & cargo run --quiet --locked -p cryptomap --example cargo_scoped_inventory -- $cargoRoot $at $tenant $run 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { throw "Cargo replay failed: $second" }
$second

$pattern = '(?m)^verified snapshot=\S+ libraries=\d+ direct_dependencies=\d+ coverage_records=\d+\s*$'
$a = [regex]::Match($first, $pattern).Value.Trim()
$b = [regex]::Match($second, $pattern).Value.Trim()
if ([string]::IsNullOrWhiteSpace($a) -or $a -ne $b) {
    throw 'Identical fixture runs did not produce the same verified snapshot counts and ID'
}
"Stable replay: $a"

$foreign = & cargo run --quiet --locked -p cryptomap --example cargo_scoped_inventory -- $cargoRoot $at 'another-tenant' $run 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { throw "Other-tenant collection failed: $foreign" }
$c = [regex]::Match($foreign, $pattern).Value.Trim()
if ([string]::IsNullOrWhiteSpace($c) -or $c -eq $a) {
    throw 'Tenant separation did not change the snapshot identity'
}
"Independent-tenant snapshot: $c"
~~~

The packaged Cargo example independently verifies the scope-bound snapshot
before printing. You should see **two coverage records** (manifest + lock).
Do not claim cross-tenant access or authentic producer identity solely from
the hash: the comparison proves deterministic serialization and namespace
separation, not a cryptographic signature.

## 4. Collect the npm fixture and verify supported dependency evidence

~~~powershell
$npmRun = 'manual-npm-fixture-20261013'
$npmOut = & cargo run --quiet --locked -p cryptomap --example npm_scoped_inventory -- $npmRoot $at 'manual-npm-tenant' $npmRun 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { throw "npm collection failed: $npmOut" }
$npmOut
if (-not [regex]::IsMatch($npmOut, $pattern)) {
    throw 'npm did not report a verified snapshot and bounded coverage'
}
~~~

This invokes the **Rust SDK**, not npm or any npm lifecycle script. The
Cargo and npm examples both report library, proven direct-dependency and
coverage counts. Read those counts and inspect the two inputs to understand
which claims are justified; a successful count is not an algorithm use,
certificate, active TLS session, policy, or CBOM finding.

## 5. Intentionally reject unsupported input — without changing Git files

Use a fresh disposable directory. These are **expected nonzero exits**:
the supported Cargo subset requires exact pins, and the npm direct
dependencies must agree with their lockfile. Do not interpret failure as
"no cryptography found".

~~~powershell
$scratch = Join-Path $env:TEMP ('cryptomap-manual-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
Copy-Item (Join-Path $cargoRoot 'Cargo.toml') (Join-Path $scratch 'Cargo.toml')
Copy-Item (Join-Path $cargoRoot 'Cargo.lock') (Join-Path $scratch 'Cargo.lock')
$original = Get-Content (Join-Path $scratch 'Cargo.toml') -Raw
$changed = $original.Replace('ring = "=0.17.12"', 'ring = "^0.17.12"')
if ($original -eq $changed) { throw 'Unsupported-profile mutation did not apply' }
Set-Content -Path (Join-Path $scratch 'Cargo.toml') -Value $changed -NoNewline -Encoding utf8
Get-Content (Join-Path $scratch 'Cargo.toml')

& cargo run --quiet --locked -p cryptomap --example cargo_scoped_inventory -- $scratch $at 'manual-negative-tenant' 'manual-negative-run'
if ($LASTEXITCODE -eq 0) { throw 'FAIL: ambiguous Cargo version range was accepted' }
"Expected rejection: Cargo exited with code $LASTEXITCODE"
~~~

For the independent npm negative test, use a new disposable directory:

~~~powershell
$npmScratch = Join-Path $env:TEMP ('cryptomap-npm-manual-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $npmScratch | Out-Null
Copy-Item (Join-Path $npmRoot 'package.json') (Join-Path $npmScratch 'package.json')
Copy-Item (Join-Path $npmRoot 'package-lock.json') (Join-Path $npmScratch 'package-lock.json')
$original = Get-Content (Join-Path $npmScratch 'package.json') -Raw
$changed = $original.Replace('"@scope/ring": "1.2.3"', '"@scope/ring": "1.2.4"')
if ($original -eq $changed) { throw 'npm version mismatch mutation did not apply' }
Set-Content -Path (Join-Path $npmScratch 'package.json') -Value $changed -NoNewline -Encoding utf8
Get-Content (Join-Path $npmScratch 'package.json')

& cargo run --quiet --locked -p cryptomap --example npm_scoped_inventory -- $npmScratch $at 'manual-npm-negative' 'manual-npm-negative-run'
if ($LASTEXITCODE -eq 0) { throw 'FAIL: npm manifest/lockfile mismatch was accepted' }
"Expected rejection: npm profile exited with code $LASTEXITCODE"
~~~

After inspecting those files and errors, remove only the two directories
whose paths are stored in `$scratch` and `$npmScratch`:

~~~powershell
Remove-Item -LiteralPath $scratch, $npmScratch -Recurse -Force
~~~

## 6. Observe individual quality, regression and MSRV gates

Run the commands **one at a time**. A successful Cargo exit and an actual
test report count constitute evidence; merely starting a test does not.

~~~powershell
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test -p cryptomap --test milestone_a_identity_golden --locked -- --nocapture
cargo test -p cryptomap --test milestone_a_snapshot_diff_golden --locked -- --nocapture
cargo test -p cryptomap --test milestone_a_collector_robustness --locked -- --nocapture
cargo test -p cryptomap --test milestone_a_inventory_scale_smoke --locked -- --nocapture
cargo test -p cryptomap --test foss_369_isolation --locked -- --nocapture
cargo test --workspace --all-targets --all-features --locked -- --nocapture
cargo +1.85.0 check --workspace --all-targets --all-features --locked
cargo +1.85.0 test --workspace --all-features --locked
~~~

After **each** invocation, inspect `$LASTEXITCODE` and the specific test
result. Windows/MSRV are useful local evidence, but they cannot substitute
for an exact-head successful GitHub Actions matrix. The frozen asset:v2 and
snapshot-v2 vectors are normative: never regenerate failed golden values
just to obtain a green build.

The source collector added after the original Milestone A freeze can also
be inspected separately using its optional feature:

~~~powershell
cargo test -p cryptomap --test foss_370_rust_source --features rust-source --locked -- --nocapture
~~~

Those results are *syntactic* Rust call-site evidence, not execution proof.

## 7. Inspect the actual crate archive and its unsigned evidence

~~~powershell
cargo package --package cryptomap --locked
cargo package --list --package cryptomap --locked

$archives = @(Get-ChildItem -File 'target/package/cryptomap-*.crate')
if ($archives.Count -ne 1) { throw 'Expected exactly one Cryptomap .crate archive' }
$archive = $archives[0].FullName
Get-FileHash -LiteralPath $archive -Algorithm SHA256

tar -tzf $archive
if ($LASTEXITCODE -ne 0) { throw 'Archive listing failed' }
$version = '0.1.1-alpha.1'
$packagedManifest = tar -xOzf $archive ("cryptomap-" + $version + "/Cargo.toml") | Out-String
if ($LASTEXITCODE -ne 0 -or $packagedManifest -notmatch '(?m)^publish = false\s*$') {
    throw 'Packaged manifest is missing the required publish=false guard'
}
$packagedManifest
~~~

Cargo's package may contain a normalized manifest. The tarball should
contain both licenses, the crate README, examples and supported fixtures;
compare against `scripts/verify-packaged-consumer.sh`. An archive digest
is a content checksum only, not proof of authentic publisher identity.

~~~powershell
python -m unittest discover -s scripts -p test_release_evidence.py -v
if ($LASTEXITCODE -ne 0) { throw 'Release evidence regression tests failed' }

New-Item -ItemType Directory -Force -Path 'target/release-evidence' | Out-Null
python scripts/release_evidence.py --archive $archive --commit $head --workspace-manifest Cargo.toml --lockfile Cargo.lock --output 'target/release-evidence/manual.json'
if ($LASTEXITCODE -ne 0) { throw 'Archive inspection failed' }
$evidence = Get-Content 'target/release-evidence/manual.json' -Raw | ConvertFrom-Json
$evidence | Select-Object schema, commit, archive, sha256, version, publish_enabled
if ($evidence.commit -ne $head -or $evidence.publish_enabled -ne $false) {
    throw 'Archive evidence differs from exact checkout or premature publish guard'
}
~~~

This local record is **unsigned**. The offline packaged-consumer script
`scripts/verify-packaged-consumer.sh` requires Bash; run it under WSL or a
CI Linux runner after reading its commands to inspect what actually runs.
It validates an extracted archive using an unrelated Cargo consumer and
separate source fixtures. A workspace test alone cannot replace that gate.

## 8. Verify *CI-produced*, signed main artifacts — never local substitutes

This step requires the GitHub CLI `gh`, read access, and an **approved main
commit** with completed Linux, Windows, Rust 1.85 and main-only signed
attestation jobs. Branch PR runs cannot sign with these privileges.

~~~powershell
gh auth status
gh run list --repo LATTIX-IO/cryptomap --workflow 'Rust CI' --branch main --limit 10
~~~

After reviewing the list and source commit, enter the exact main CI run ID
and the corresponding 40-character commit SHA. These values must match:

~~~powershell
$ciRun = Read-Host 'Successful main-push Rust CI run ID'
$approvedMainSha = Read-Host 'Reviewed exact main commit SHA'
if ($ciRun -notmatch '^[0-9]+$' -or $approvedMainSha -cnotmatch '^[0-9a-f]{40}$') {
    throw 'Expected a numeric run ID and a full lowercase 40-character commit SHA'
}
$ci = gh run view $ciRun --repo LATTIX-IO/cryptomap --json headSha,status,conclusion,event,headBranch,workflowName,workflowDatabaseId | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Unable to retrieve GitHub Actions run metadata' }
$workflow = gh api repos/LATTIX-IO/cryptomap/actions/workflows/ci.yml | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Unable to retrieve the pinned Rust CI workflow identity' }
$ci
if ($ci.headSha -cne $approvedMainSha -or $ci.status -ne 'completed' -or
    $ci.conclusion -ne 'success' -or $ci.event -ne 'push' -or
    $ci.headBranch -ne 'main' -or $ci.workflowName -ne 'Rust CI' -or
    $ci.workflowDatabaseId -ne $workflow.id -or
    $workflow.path -ne '.github/workflows/ci.yml') {
    throw 'This is not completed, successful, exact-SHA main-push Rust CI workflow evidence'
}

$ciArtifactDir = Join-Path (Get-Location).Path 'target/attested-main-artifact'
New-Item -ItemType Directory -Force -Path $ciArtifactDir | Out-Null
gh run download $ciRun --repo LATTIX-IO/cryptomap --name cryptomap-tested-crate --dir $ciArtifactDir
if ($LASTEXITCODE -ne 0) { throw 'Failed to download the CI-tested candidate' }
$ciCrates = @(Get-ChildItem -File $ciArtifactDir -Filter 'cryptomap-*.crate')
if ($ciCrates.Count -ne 1) { throw 'CI artifact count is not exactly one' }
Get-FileHash -LiteralPath $ciCrates[0].FullName -Algorithm SHA256

$attestationScope = @(
    '--repo', 'LATTIX-IO/cryptomap',
    '--signer-workflow', 'LATTIX-IO/cryptomap/.github/workflows/ci.yml',
    '--source-ref', 'refs/heads/main',
    '--source-digest', $approvedMainSha
)
gh attestation verify $ciCrates[0].FullName @attestationScope
if ($LASTEXITCODE -ne 0) { throw 'CI SLSA attestation failed source-bound verification' }
gh attestation verify $ciCrates[0].FullName @attestationScope --predicate-type https://spdx.dev/Document/v2.3
if ($LASTEXITCODE -ne 0) { throw 'CI SPDX SBOM attestation failed source-bound verification' }
~~~

Record the exact run URL, candidate checksum, verified attestations and
reviewed commit. The subject is **the downloaded CI candidate**, not the
locally created archive. The software SPDX is a dependency inventory
generated by the CI supply-chain job, **not** a cryptographic CBOM.

## 9. Separate owner-only registry gates (stop here until authorized)

A green local walk-through and signed main CI are **not** permission to
publish. The crates.io registry already has an unrelated-to-this-release
`cryptomap 0.1.0`; that version cannot be overwritten. The proposed
`0.1.1-alpha.1` is not reserved.

A designated repository/release owner must independently verify:

1. Authenticated crates.io ownership of the exact `cryptomap` namespace,
   fresh availability of the candidate version, appropriate credentials and
   absence of any existing collision.
2. A single explicitly reviewed **release PR** intentionally allowing the
   registry (`publish = ["crates-io"]`) and exact version, with no
   incidental feature or security change.
3. Full successful **new exact-SHA main-push CI**, the tested candidate bytes
   and both verified attestations, followed by an approved registry dry-run.
4. GitHub environment `cryptomap-publish` with required human reviewers,
   a deliberate manually supplied approved SHA and approved version,
   repository variable `CRYPTOMAP_RELEASE_ENABLED=true` only when authorized,
   plus scoped credentials.
5. After actual authorized publication, installation of the **registry**
   version into a new clean project, documentation/license/release inspection
   and saved artifacts, and credential rotation where applicable.

**No publication command, token, tag, release dispatch, or release-variable
change is part of this walkthrough.** Keep FOSS-363 open until authenticated
ownership, protected approval and the registry-distributed consumer check are
complete.

## Operator evidence ledger

| Evidence | Your observed result |
| --- | --- |
| Tested local Git SHA and working-tree status | Record explicitly |
| Cargo two-run digest equality and differing-tenant digest | Record the actual three snapshot lines |
| npm verified snapshot / bounded coverage | Record the output |
| Unsupported Cargo range rejected with nonzero exit | Record exit and diagnostic |
| npm manifest/lock mismatch rejected with nonzero exit | Record exit and diagnostic |
| Cargo check, Clippy, golden tests and Rust 1.85 | Record test counts and failure details |
| Local `.crate` SHA-256 and unsigned evidence JSON | Record digest and output location |
| Exact reviewed main push CI, run ID, all four jobs | Record CI URL and commit |
| Two signed attestations verified for CI artifact | Record CLI output and checked digest |
| Authenticated crates.io ownership and protected publish approval | **PENDING unless actually confirmed** |
| Post-publish registry consumer | **PENDING until an approved release** |

For unsupported inputs, negative coverage is **not** a finding that the
repository lacks cryptography. These distinctions protect the Milestone A
promise while later source, configuration and live telemetry capabilities
remain under separate milestones.
