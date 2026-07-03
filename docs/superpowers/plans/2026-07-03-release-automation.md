# Release Automation + Standalone Repo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the repo fully standalone (no `../cloudgrep` dependency for tests) and ship 5-target binary releases from GitHub Actions on `v*` tags.

**Architecture:** Vendor the 116KB fixture corpus and the 193-line stdlib-only Python oracle into this repo with provenance. A hand-rolled matrix release workflow builds on five native runners (no cross-compilation), packages archives + sha256, and a final job publishes the GitHub release after a tag↔Cargo.toml version guard. A minimal single-OS CI workflow runs fmt/clippy/test on every push/PR.

**Tech Stack:** GitHub Actions (actions/checkout@v4, dtolnay/rust-toolchain@stable, actions/upload-artifact@v4 + download-artifact@v4, softprops/action-gh-release@v2), bash packaging steps.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-03-release-automation-design.md`.
- After Task 1, `cargo test` MUST pass in a cold clone with no `../cloudgrep` sibling.
- Vendored content is copied VERBATIM from upstream (Apache-2.0) with provenance recorded (repo URL + commit hash). Never modify the upstream clone itself.
- Archive naming: `cloudgrepper-<tag>-<target-triple>.{tar.gz|zip}`; each with a `.sha256` sidecar.
- The five targets/runners exactly as specced: x86_64-unknown-linux-gnu/ubuntu-latest, aarch64-unknown-linux-gnu/ubuntu-24.04-arm, aarch64-apple-darwin/macos-latest, x86_64-apple-darwin/macos-15-intel, x86_64-pc-windows-msvc/windows-latest.
- `cargo fmt` + `cargo clippy --all-targets -- -D warnings` clean before every commit.
- Live-comparison scripts are dev-time aids: they must resolve python cloudgrep from pip OR the sibling clone and exit with a clear message when neither exists — but they are NEVER wired into CI.

## File Structure

```
tests/data/                      # vendored fixtures (16 files) + README.md provenance
scripts/oracle/search.py         # vendored Python oracle (verbatim + provenance header comment)
scripts/gen_golden.py            # imports vendored oracle instead of sibling repo
scripts/{compare_python,real_cloud_diff,bench}.sh  # python-cloudgrep resolution helper
.github/workflows/release.yml    # tag-triggered 5-target release
.github/workflows/ci.yml         # push/PR fmt+clippy+test
Cargo.toml                       # [profile.release] additions
README.md                        # release procedure section
src/{decompress,search,yara}.rs, tests/{cli_behavior,emulator}.rs, tests/support/mod.rs  # fixture path updates
```

---

### Task 1: Vendor fixtures + oracle; make `cargo test` standalone

**Files:**
- Create: `tests/data/` (16 fixture files), `tests/data/README.md`, `scripts/oracle/search.py`
- Modify: `src/decompress.rs`, `src/search.rs`, `src/yara.rs`, `tests/cli_behavior.rs`, `tests/emulator.rs`, `tests/support/mod.rs` (fixture paths), `scripts/gen_golden.py` (oracle import + data path)

**Interfaces:**
- Produces: fixture path convention `format!("{}/tests/data/{}", env!("CARGO_MANIFEST_DIR"), name)` used by all tests from now on; vendored oracle importable as `from search import Search` with `scripts/oracle` on sys.path.

- [ ] **Step 1: Vendor the fixtures with provenance**

```bash
cp -R ../cloudgrep/tests/data tests/data
UPSTREAM_SHA=$(git -C ../cloudgrep rev-parse HEAD)
cat > tests/data/README.md <<EOF
# Test fixtures

Copied verbatim from https://github.com/cado-security/cloudgrep
(commit ${UPSTREAM_SHA}), tests/data/. Apache-2.0, same as this project.
These files are the correctness oracle corpus for the port — do not edit them.
EOF
```

- [ ] **Step 2: Vendor the oracle**

```bash
mkdir -p scripts/oracle
{ printf '# Vendored verbatim from https://github.com/cado-security/cloudgrep\n# (cloudgrep/search.py, commit %s). Apache-2.0.\n# Used only to regenerate tests/golden/ via ../gen_golden.py.\n' "$(git -C ../cloudgrep rev-parse HEAD)"; cat ../cloudgrep/cloudgrep/search.py; } > scripts/oracle/search.py
```

- [ ] **Step 3: Update fixture paths in Rust sources**

In each of `src/decompress.rs`, `src/search.rs`, `src/yara.rs`, `tests/cli_behavior.rs`, `tests/emulator.rs`, `tests/support/mod.rs`, replace every occurrence of the string `/../cloudgrep/tests/data` with `/tests/data` (they all build paths via `env!("CARGO_MANIFEST_DIR")`). Verify none remain:

```bash
grep -rn "cloudgrep/tests/data" src/ tests/ && echo "LEFTOVERS — fix them" || echo clean
```

- [ ] **Step 4: Update gen_golden.py** — replace the sibling-repo import and DATA path:

```python
# old:
# sys.path.insert(0, os.path.join(HERE, "..", "..", "cloudgrep"))
# from cloudgrep.search import Search
# DATA = os.path.join(HERE, "..", "..", "cloudgrep", "tests", "data")
# new:
sys.path.insert(0, os.path.join(HERE, "oracle"))
from search import Search  # vendored oracle (see scripts/oracle/search.py)

DATA = os.path.join(HERE, "..", "tests", "data")
```

- [ ] **Step 5: Verify goldens regenerate identically**

```bash
python3 scripts/gen_golden.py && git diff --stat tests/golden/
```
Expected: script prints `wrote <name>` for all cases and `git diff` shows NO changes to tests/golden/ (vendored oracle + vendored fixtures reproduce the committed goldens byte-for-byte). If any golden differs, STOP — the vendoring is not verbatim.

- [ ] **Step 6: Full local suite**

Run: `cargo test` then `CLOUDGREPPER_EMULATOR=1 cargo test --test emulator` (docker stack assumed up; if not, plain `cargo test` suffices — emulator paths changed only for fixture seeding).
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A && git commit -m "feat: vendor test fixtures and python oracle; repo is standalone"
```

- [ ] **Step 8: Cold-clone proof (the acceptance criterion; needs Step 7's commit)**

```bash
CLONE_DIR=$(mktemp -d)/cloudgrepper-standalone
git clone --quiet . "$CLONE_DIR" && (cd "$CLONE_DIR" && git checkout -q cloudgrepper-impl 2>/dev/null || true; cargo test 2>&1 | tail -3)
```
Expected: `test result: ok` lines, zero failures — in a directory whose parent has NO cloudgrep clone.

---

### Task 2: Live-comparison scripts resolve python cloudgrep gracefully

**Files:**
- Modify: `scripts/compare_python.sh`, `scripts/real_cloud_diff.sh`, `scripts/bench.sh`

**Interfaces:**
- Consumes: nothing new. Produces: each script self-contained; `python3 -m cloudgrep` invocable after the resolution block or the script exits 2 with a clear message.

- [ ] **Step 1: Add the resolution block** near the top of each of the three scripts (after `set -euo pipefail` / HERE definition), replacing any `(cd ../cloudgrep && python3 -m cloudgrep ...)` invocation style with plain `python3 -m cloudgrep ...`:

```bash
# Resolve the python cloudgrep oracle: pip-installed, or a sibling clone.
if ! python3 -c "import cloudgrep" 2>/dev/null; then
  if [ -d "$HERE/../../cloudgrep" ]; then
    export PYTHONPATH="$HERE/../../cloudgrep${PYTHONPATH:+:$PYTHONPATH}"
  fi
fi
if ! python3 -c "import cloudgrep" 2>/dev/null; then
  echo "python cloudgrep not found. Either 'pip install cloudgrep' or clone" >&2
  echo "https://github.com/cado-security/cloudgrep as a sibling of this repo." >&2
  exit 2
fi
```

(`bench.sh` additionally: change its `FIXTURE=` line from `$HERE/../../cloudgrep/tests/data/apache_access.log` to `$HERE/../tests/data/apache_access.log`.)

- [ ] **Step 2: Verify both resolution paths**

```bash
bash -n scripts/compare_python.sh scripts/real_cloud_diff.sh scripts/bench.sh  # syntax
# sibling exists on this machine, so resolution must succeed silently:
grep -l "import cloudgrep" scripts/*.sh >/dev/null 2>&1 || true
PYTHONPATH= python3 -c "import sys; sys.path.insert(0, '../cloudgrep'); import cloudgrep" && echo sibling-resolvable
```
Then simulate absence: `HERE=/nonexistent bash -c 'cd /tmp && exec bash <path-to-script>'` is awkward — instead temporarily run one script with `PYTHONPATH=` from a directory without the sibling and confirm the exit-2 message. Simplest concrete check:

```bash
(cd "$(mktemp -d)" && bash /Users/jeffbryner/development/cloudgrep-port/cloudgrepper/scripts/compare_python.sh 2>&1 | head -2; echo "exit=$?")
```
Expected: usage error OR the not-found message — never a silent crash referencing ../cloudgrep. (The script argument-checks first; passing dummy args `b q` makes it reach the resolution block: expect the two-line message and exit 2 if python cloudgrep isn't importable from that cwd — note the sibling clone still resolves via $HERE, which is correct behavior, so this check mainly proves no hard failure.)

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "feat: comparison scripts resolve python cloudgrep from pip or sibling clone"
```

---

### Task 3: Release + CI workflows, release profile, README procedure

**Files:**
- Create: `.github/workflows/release.yml`, `.github/workflows/ci.yml`
- Modify: `Cargo.toml` (release profile), `README.md` (release procedure section)

**Interfaces:**
- Consumes: standalone test suite from Task 1 (workflows use a single self-checkout).
- Produces: tag `vX.Y.Z` → GitHub release with 10 assets (5 archives + 5 sha256).

- [ ] **Step 1: release profile in Cargo.toml** (append after `[dependencies]`/`[dev-dependencies]` sections):

```toml
[profile.release]
lto = "thin"
strip = true
codegen-units = 1
```

- [ ] **Step 2: `.github/workflows/release.yml`** — exact content:

```yaml
name: release

on:
  push:
    tags: ["v*"]
  workflow_dispatch: {} # dry-run: builds artifacts, skips publishing

permissions:
  contents: read

jobs:
  build:
    name: build ${{ matrix.target }}
    runs-on: ${{ matrix.runner }}
    strategy:
      fail-fast: true
      matrix:
        include:
          - { target: x86_64-unknown-linux-gnu, runner: ubuntu-latest, ext: tar.gz }
          - { target: aarch64-unknown-linux-gnu, runner: ubuntu-24.04-arm, ext: tar.gz }
          - { target: aarch64-apple-darwin, runner: macos-latest, ext: tar.gz }
          - { target: x86_64-apple-darwin, runner: macos-15-intel, ext: tar.gz }
          - { target: x86_64-pc-windows-msvc, runner: windows-latest, ext: zip }
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      - name: Test
        run: cargo test
      - name: Build
        run: cargo build --release --target ${{ matrix.target }}
      - name: Package
        shell: bash
        run: |
          NAME="cloudgrepper-${GITHUB_REF_NAME}-${{ matrix.target }}"
          mkdir "$NAME"
          BIN=cloudgrepper
          [[ "${{ matrix.target }}" == *windows* ]] && BIN=cloudgrepper.exe
          cp "target/${{ matrix.target }}/release/$BIN" "$NAME/"
          cp LICENSE README.md "$NAME/"
          if [[ "${{ matrix.ext }}" == "zip" ]]; then
            7z a "$NAME.zip" "$NAME"
          else
            tar czf "$NAME.tar.gz" "$NAME"
          fi
          if command -v sha256sum >/dev/null; then
            sha256sum "$NAME.${{ matrix.ext }}" > "$NAME.${{ matrix.ext }}.sha256"
          else
            shasum -a 256 "$NAME.${{ matrix.ext }}" > "$NAME.${{ matrix.ext }}.sha256"
          fi
      - uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.target }}
          path: |
            cloudgrepper-*.tar.gz*
            cloudgrepper-*.zip*
          if-no-files-found: error

  release:
    needs: build
    if: startsWith(github.ref, 'refs/tags/')
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - name: Verify tag matches Cargo.toml version
        shell: bash
        run: |
          CARGO_V=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
          TAG_V="${GITHUB_REF_NAME#v}"
          if [[ "$CARGO_V" != "$TAG_V" ]]; then
            echo "Tag ${GITHUB_REF_NAME} != Cargo.toml version ${CARGO_V}" >&2
            exit 1
          fi
      - uses: actions/download-artifact@v4
        with:
          path: dist
          merge-multiple: true
      - uses: softprops/action-gh-release@v2
        with:
          files: dist/*
          generate_release_notes: true
```

- [ ] **Step 3: `.github/workflows/ci.yml`** — exact content:

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - run: cargo fmt --check
      - run: cargo clippy --all-targets -- -D warnings
      - run: cargo test
```

- [ ] **Step 4: README release-procedure section** — add near the end (before the License note):

```markdown
## Releasing

1. Bump `version` in `Cargo.toml` and commit.
2. `git tag vX.Y.Z && git push origin vX.Y.Z`
3. GitHub Actions tests on all five targets, builds release binaries
   (Linux x86_64/ARM64, macOS Apple Silicon/Intel, Windows x86_64), and
   publishes them — with sha256 checksums — on the GitHub release.

A `workflow_dispatch` run of the release workflow builds all artifacts
without publishing (dry run).
```

- [ ] **Step 5: Local verification** (workflows can't run locally):

```bash
python3 -c "import yaml,sys; [yaml.safe_load(open(f)) for f in ['.github/workflows/release.yml','.github/workflows/ci.yml']]; print('yaml ok')" 2>/dev/null || ruby -ryaml -e "YAML.load_file('.github/workflows/release.yml'); YAML.load_file('.github/workflows/ci.yml'); puts 'yaml ok'" 2>/dev/null || echo "no yaml parser locally — rely on push"
cargo build --release 2>&1 | tail -1   # release profile compiles (lto/strip)
cargo test 2>&1 | grep -c "^test result: ok" # suites still green
```

- [ ] **Step 6: Commit and push — CI validates itself on the PR**

```bash
git add -A && git commit -m "feat: release workflow (5 targets), CI workflow, release profile"
git push
gh pr checks --watch || true   # watch the ci workflow run on the PR
```
Expected: the `ci` workflow appears on PR #1 and passes (fmt, clippy, test on a cold GitHub checkout — this is the true standalone proof).

**Post-merge follow-ups (not part of this plan's tasks, note in final report):** `workflow_dispatch` dry-run of release.yml only becomes invokable once the workflow exists on the default branch (GitHub limitation); after merging, run `gh workflow run release.yml` for the dry run, then tag `v0.1.0`.
```
