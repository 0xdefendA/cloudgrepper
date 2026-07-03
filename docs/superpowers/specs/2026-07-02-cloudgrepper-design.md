# cloudgrepper — Design Spec

**Date:** 2026-07-02
**Status:** Approved (pending user review of this document)

## Purpose

cloudgrepper is a faithful Rust port of [cloudgrep](https://github.com/cado-security/cloudgrep)
(Cado Security, Python, Apache-2.0, now deprecated): "grep for cloud storage." It searches log
files (optionally gzip/zip compressed) in AWS S3, Azure Blob Storage, and Google Cloud Storage,
in parallel, without indexing into a SIEM.

**The bar:** same inputs → same matches/output as the Python tool, byte-for-byte comparable
(modulo cross-file output ordering, which is nondeterministic in both). When behavior is
ambiguous, the Python source in `../cloudgrep/` is the source of truth. Quirks are preserved,
not fixed.

**Why Rust:** the original is unmaintained; Rust gives a single static binary, memory safety,
and a genuinely parallel streaming data path (the perf win is the point of the rewrite).

## Decisions made during design

| Decision | Choice |
|---|---|
| Scope | Full port, all milestones, one coherent design |
| Data path | Streaming in-memory (no temp files) |
| Concurrency | tokio + `buffer_unordered`, default 10 workers (matches Python), tuned in perf milestone |
| Yara engine | yara-x (VirusTotal's pure-Rust YARA) — no C toolchain dependency |
| Cloud testing | Local fixtures + emulators first; real-cloud validation as a later milestone |
| Extra flags | `-cd/--convert_date` and `-og/--use_og_name` exist in the real Python CLI (absent from the CLAUDE.md table) and are included |

## Architecture

Single binary crate. Modules:

```
src/
  main.rs        # entry: parse CLI, init tracing, build tokio runtime, run
  cli.rs         # clap derive struct — all 18 flags
  filters.rs     # object filters: prefix / name-contains / date-range / size
  providers/
    mod.rs       # ObjectStore trait
    s3.rs        # aws-sdk-s3 (honors --profile + default credential chain)
    azure.rs     # azure_storage_blobs (DefaultAzureCredential-equivalent)
    gcs.rs       # google-cloud-storage (GOOGLE_APPLICATION_CREDENTIALS)
  decompress.rs  # extension sniffing (.gz/.zip) -> text lines from Bytes
  search.rs      # compiled regex list, per-line matching -> match records
  logparse.rs    # log_type presets, json/jsonl/csv parsing, property traversal
  output.rs      # line vs JSON output, hide_filenames
  yara.rs        # yara-x scan of in-memory buffer (milestone 7)
```

### The ObjectStore trait

The one core abstraction. Two operations:

- `list(filters) -> stream of ObjectMeta` — key, size, last-modified; filters applied during
  listing (prefix pushed down to the provider API where supported, as Python does).
- `fetch(key) -> Bytes` — the object's contents, in memory.

Everything downstream (decompress → search → output) is provider-agnostic. This seam is also
what makes emulator testing work: each provider client accepts an endpoint override
(LocalStack/MinIO, Azurite, fake-gcs-server).

Python allows S3 + Azure + GCS in a single invocation; cloudgrepper keeps that — each configured
provider is listed and searched in the same run.

### Data flow

1. Parse CLI → load queries (`-q` comma-separated, or `-v` file of one regex per line, blank
   lines skipped) → compile each pattern once.
2. Per provider: list objects with filters applied (date range, size cap, name-contains,
   prefix). Size-0 objects and objects over `--file_size` (default 100 MB) are never fetched.
3. Bounded-concurrency stream (`buffer_unordered(10)`): fetch object into `Bytes` →
   decompress if `.gz`/`.zip` → iterate lines → regex per line → emit match records.
4. Matches stream to stdout as found (no buffering/sorting), through a locked writer so lines
   never interleave mid-line. Diagnostics go through `tracing` mirroring Python's `logging`
   levels (warnings by default, everything with `--debug`).

Memory bound: file-size cap × worker count (default 100 MB × 10 = 1 GB worst case; typical log
files keep this far lower).

## CLI (must match argparse exactly)

clap derive, with clap aliases for the multi-char short forms.

```
-b   --bucket           AWS S3 bucket
-an  --account-name     Azure account name
-cn  --container-name   Azure container name
-gb  --google-bucket    GCS bucket
-q   --query            Comma-separated list of regexes
-v   --file             File of regexes, one per line
-y   --yara             File of Yara rules
-p   --prefix           Object name prefix filter (default "")
-f   --filename         Object name contains-keyword filter
-s   --start_date       Modified-after filter (YYYY-MM-DD advertised; lenient parse)
-e   --end_date         Modified-before filter
-fs  --file_size        Skip objects larger than N bytes (default 100_000_000)
-pr  --profile          AWS profile
-d   --debug            Debug logging
-hf  --hide_filenames   Omit filenames from output
-lt  --log_type         Preset: cloudtrail | azure | waf
-lf  --log_format       Custom format: json | jsonl | csv
-lp  --log_properties   Comma-separated property path to records
-jo  --json_output      Output matches as JSON (one object per line = JSONL)
-cd  --convert_date     Normalize dates to UTC before comparing (S3 filter path)
-og  --use_og_name      Use original key name for extension detection/log labels
```

Behavioral details:

- No arguments at all → print help to stderr, exit 1 (Python does exactly this).
- Date parsing: Python uses `dateutil.parser` (very lenient). We accept the documented
  `YYYY-MM-DD` plus common ISO datetime forms via chrono; the spec of accepted formats is
  documented in the README. Unparseable date → error and exit.
- Version: cloudgrepper carries its own version; help text shape mirrors the original.

## Search semantics (mirrors `search.py`)

- Patterns use Python `re` semantics; the `regex` crate covers the practical intersection.
  Invalid pattern → error, as in Python.
- Content is decoded as UTF-8 with invalid sequences replaced (Python `errors="ignore"`
  equivalence; verified against the UTF-8 torture-test fixtures).
- Every pattern is tested against every line (search-anywhere semantics); each matching
  pattern emits its own output record.
- Default output: `{key_name}: {line}`. `-hf` drops the filename. `-jo` emits one JSON object
  per match per line — i.e. **the JSON output mode is streaming JSONL** (this matches Python,
  which `print(json.dumps(record))`s each match). Field names: `key_name`, `query`, `line`;
  yara matches use `match_rule`/`match_strings`.
- Exit code 0 even when nothing matches (only usage errors exit non-zero).

### Log parsing

- `-lt cloudtrail` → format json, properties `["Records"]`
- `-lt azure` → format json, properties `["data"]`
- `-lt waf` → format jsonl, no properties
- Any other `-lt` value → error and exit.
- Two-stage matching quirk preserved: with a log format active, a line is JSON-parsed only if
  a regex matched the raw line first; then each record extracted via the property path is
  re-tested against the pattern as serialized JSON, and matching records are output as the
  `line` field. Python's odd `jsonl` "split" behavior is replicated as-is.
- Azure special case preserved: when an account name is present, `.gz`/`.zip` contents are
  JSON-loaded whole (Azure log-export format) rather than line-iterated.

### Decompression

- Extension-based detection (`.gz`, `.zip`) on the object key. Zip archives: every non-directory
  member is searched; member text is line-iterated like any file.
- `-og/--use_og_name`: in Python this chooses between the temp-file name and the original key
  for extension detection and log labels. With no temp files, the original key is naturally
  authoritative; the flag is accepted for CLI compatibility and affects only which name appears
  in debug logs. Documented in README.

### Yara (milestone 7)

`-y` compiles a rules file with yara-x and scans each object's in-memory buffer **instead of**
regex search (Python short-circuits to yara when rules are given — preserved). Output records
use `match_rule` and `match_strings`. yara-x has very high libyara rule compatibility; any
divergence found during validation is documented.

## Error handling

- Per-object errors (download failure, corrupt gzip/zip, blob vanished) → log exception,
  count as unmatched, continue. One bad object never kills the run.
- Run-level errors (no query, invalid log type, credential/listing failure, bad regex,
  unparseable date) → error message and exit.
- S3 path logs bucket region + file count as warnings before searching, matching Python's
  egress-charge warning.

## Testing strategy (the correctness oracle)

1. **Ported unit tests.** Translate `../cloudgrep/tests/test_unit.py` to Rust `#[test]`s,
   running against the same fixture files in `../cloudgrep/tests/data/` (referenced by
   relative path — the clone is read-only oracle, nothing is copied or modified).
2. **Golden-output tests.** For each fixture × representative query/flag combination, capture
   the Python tool's output once and assert cloudgrepper produces the same line-set (sorted
   comparison across files; exact-order comparison within a single file's matches).
3. **Emulator integration tests.** docker-compose with LocalStack or MinIO (S3), Azurite
   (Azure), fake-gcs-server (GCS); seed the fixtures, run the compiled binary end-to-end,
   diff against the Python tool pointed at the same emulator. Gated behind an env flag so
   plain `cargo test` requires no Docker.
4. **Real-cloud validation (later phase).** Run both tools against real buckets and diff.
   Scheduled as milestone 9.

## Milestones

1. **Scaffold + CLI** — cargo project, git init in `cloudgrepper/`, all 18 flags, help/no-args
   behavior, Apache-2.0 license, README crediting cado-security.
2. **S3 end-to-end** — list (filters) → fetch → regex → line output, validated against emulator.
3. **Decompression** — `.gz`, `.zip`.
4. **Output modes** — `-hf`, `-jo` (JSONL).
5. **Log parsing** — `-lt` presets, then `-lf`/`-lp`.
6. **Azure + GCS** — providers vs Azurite / fake-gcs-server.
7. **Yara** — yara-x.
8. **Parallelism/perf** — tune worker count, benchmark vs Python.
9. **Real-cloud validation** — diff vs Python on real buckets.

Definition of done per milestone: same inputs → same output as Python on the oracle tests.

## Conventions

- `cargo fmt` + `cargo clippy` clean before every commit.
- Git repository lives in `cloudgrepper/` (never nested under the original repo's `.git`).
- License Apache-2.0; README credits cado-security's cloudgrep as the original.

## Suggested stack (from CLAUDE.md, confirmed)

clap (derive) · tokio + futures · regex · aws-sdk-s3 · azure_storage/azure_storage_blobs ·
google-cloud-storage · flate2 + zip · serde/serde_json · chrono · yara-x · tracing
