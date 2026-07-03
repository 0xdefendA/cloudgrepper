# Release Automation + Standalone Repo — Design Spec

**Date:** 2026-07-03
**Status:** Approved (pending user review of this document)

## Purpose

Ship versioned GitHub releases with prebuilt binaries for the five mainstream targets, and
make the repository fully standalone — no dependency on the archived Python cloudgrep clone
for tests or CI.

## Context and decisions

- The upstream Python repo (`cado-security/cloudgrep`) is unmaintained (last commit ~3 years
  ago) and may disappear. Today our tests read fixtures from a sibling clone at
  `../cloudgrep` — unacceptable for CI and for anyone cloning this repo cold.
- **Decision: vendor, don't reference.** Fixtures (116KB / 16 files) and the stdlib-only
  Python oracle (`search.py`, 193 lines) move into this repo. Both projects are Apache-2.0;
  provenance is recorded.
- **Decision: hand-rolled matrix workflow** (over cargo-dist and taiki-e's action): five
  native runners need no cross-compilation, and a readable ~80-line workflow beats generated
  machinery at this scale. Migrating to cargo-dist later (for `curl | sh` installers) stays
  easy.
- **Project philosophy note:** byte-for-byte Python parity was the *porting* bar. After the
  first release, cloudgrepper evolves independently; the live-comparison scripts remain as
  dev-time aids, and strict parity is no longer a release gate.

## Part 1: Standalone repo (decoupling from ../cloudgrep)

1. **Fixtures** → `tests/data/` (copied verbatim from upstream `tests/data/`, including the
   UTF-8 torture files, `.gz`/`.zip` archives, and `yara.rule`). Add `tests/data/README.md`
   recording origin repo, commit hash, and Apache-2.0 attribution.
2. **Path updates** — the seven files referencing `../cloudgrep/tests/data` switch to
   `tests/data` (still via `env!("CARGO_MANIFEST_DIR")`): `src/decompress.rs`,
   `src/search.rs`, `src/yara.rs`, `tests/cli_behavior.rs`, `tests/emulator.rs`,
   `tests/support/mod.rs`, `scripts/bench.sh`.
3. **Oracle** → `scripts/oracle/search.py` (verbatim copy, Apache header + provenance
   comment). `scripts/gen_golden.py` imports the vendored copy; golden files remain
   regenerable with no external checkout.
4. **Live-comparison scripts** (`compare_python.sh`, `real_cloud_diff.sh`, `bench.sh`)
   resolve the Python tool from `python3 -m cloudgrep` if importable (pip install) else the
   sibling clone, and exit with a clear message if neither is available. Dev-time aids only;
   never CI.
5. Acceptance: `cargo test` passes in a cold clone with no sibling directory.

## Part 2: Release workflow (`.github/workflows/release.yml`)

**Trigger:** push of tag `v*`; plus `workflow_dispatch` for a dry-run (builds and uploads
workflow artifacts, skips creating the GitHub release).

**Build matrix — all native runners, no cross-compilation:**

| target | runner | archive |
|---|---|---|
| x86_64-unknown-linux-gnu | ubuntu-latest | tar.gz |
| aarch64-unknown-linux-gnu | ubuntu-24.04-arm | tar.gz |
| aarch64-apple-darwin | macos-latest | tar.gz |
| x86_64-apple-darwin | macos-13 | tar.gz |
| x86_64-pc-windows-msvc | windows-latest | zip |

**Per matrix job:** checkout → install stable Rust → `cargo test` (emulator tests self-skip;
proves the tagged commit passes on that OS) → `cargo build --release --target <triple>` →
package `cloudgrepper-<tag>-<triple>.{tar.gz|zip}` containing the binary + LICENSE +
README.md → emit `<archive>.sha256` → upload as a workflow artifact. All scripted steps use
`shell: bash` (works on Windows runners via git-bash).

**Release job** (needs: all matrix jobs; `permissions: contents: write`):
1. Guard: tag `vX.Y.Z` must equal the `version` in Cargo.toml — fail the release otherwise.
2. Download all artifacts; create the GitHub release via `softprops/action-gh-release` with
   the 10 files (5 archives + 5 checksums) and auto-generated release notes.

**Cargo.toml release profile:**

```toml
[profile.release]
lto = "thin"
strip = true
codegen-units = 1
```

## Part 3: CI workflow (`.github/workflows/ci.yml`)

On push and pull_request to `main`: single ubuntu-latest job — checkout, stable Rust,
`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`. (Single OS
for speed; the release matrix exercises the other platforms at tag time.)

## Release procedure (documented in README)

1. Bump `version` in Cargo.toml, commit.
2. `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. The workflow tests, builds, packages, and publishes the release.

## Testing strategy

- Part 1 is fully verified locally: `cargo test` in a temp clone without the sibling repo.
- Parts 2–3 are verified on GitHub: push the workflows on the PR branch (CI runs on the PR),
  then trigger a `workflow_dispatch` dry-run of release.yml; finally a real `v0.1.0` tag
  after merge.

## Error handling

- Any matrix job failing (test or build) fails the whole release — no partial releases.
- Version-mismatch guard fails before anything is published.
- `workflow_dispatch` dry-runs cannot publish (release step is gated on tag refs).
