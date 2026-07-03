# cloudgrepper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A faithful Rust port of cloudgrep ("grep for cloud storage" — S3/Azure/GCS) producing byte-for-byte comparable output to the Python original.

**Architecture:** Single binary crate. One `ObjectStore` trait (list + fetch) per provider; a streaming in-memory pipeline (tokio `buffer_unordered`, 10 workers) fetches objects into `Bytes`, decompresses (.gz/.zip), line-matches compiled regexes, and streams match records to stdout. A `pyjson` module replicates Python's `json.dumps`/`repr` formatting so output is comparable.

**Tech Stack:** clap 4 (derive), tokio, futures, regex, aws-sdk-s3, azure_storage_blobs 0.21, google-cloud-storage 0.24 (yoshidan), flate2, zip, serde_json (preserve_order), chrono, yara-x, tracing.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-02-cloudgrepper-design.md`. Python source of truth: `../cloudgrep/` (read-only oracle — NEVER modify it).
- All 21 CLI flags must match the Python argparse CLI exactly, including multi-char short forms (`-an`, `-fs`, …) via an argv-normalization shim.
- Output must be byte-for-byte comparable to Python: lines keep their trailing `\n` when printed (Python's `print(f"{key}: {line}")` doubles newlines — preserve this), JSON output is one `json.dumps`-formatted object per line (JSONL, `", "`/`": "` separators, ensure_ascii), dict-valued lines print as Python `repr`.
- File content is decoded as UTF-8 with invalid bytes **dropped** (Python `errors="ignore"`), not replaced.
- Exit codes: no args → help on stderr, exit 1. Everything else (including "no query" and zero matches) exits 0, matching Python.
- Per-object errors: log and continue. Quirks are preserved, not fixed (csv parsing yields nothing; GCS filter ignores size; two-stage log matching).
- Fixture files: `../cloudgrep/tests/data/` referenced via `env!("CARGO_MANIFEST_DIR")` — never copied.
- Default worker count 10 (Python's `max_workers`); `CLOUDGREPPER_WORKERS` env override added in Task 15.
- `cargo fmt` + `cargo clippy --all-targets -- -D warnings` clean before every commit.
- Crate API note: cloud-SDK crates move fast. If a provider snippet fails to compile, check docs.rs for the pinned version before changing versions; do not silently upgrade majors.

## File Structure

```
cloudgrepper/
  Cargo.toml
  LICENSE                  # Apache-2.0, copied from ../cloudgrep/LICENSE
  README.md                # credits cado-security/cloudgrep
  src/
    main.rs                # argv shim, clap parse, logging init, tokio runtime, run
    cli.rs                 # Cli struct (21 flags), normalize_args, parse_comma_list, load_query_file, parse_date
    pyjson.rs              # dumps() = Python json.dumps; python_repr() = Python repr()
    filters.rs             # ObjectMeta, Filters::matches
    decompress.rs          # decode_ignore, FileKind, detect, texts, split_lines
    output.rs              # Record enum, print_match
    logparse.rs            # parse_logs, extract_log_entries
    search.rs              # SearchConfig, search_object, search_line, search_logs
    yara.rs                # yara-x compile + scan (Task 14)
    runner.rs              # RunConfig, run(): per-provider list -> buffer_unordered fetch+search
    providers/
      mod.rs               # ObjectStore trait
      s3.rs                # aws-sdk-s3
      azure.rs             # azure_storage_blobs
      gcs.rs               # google-cloud-storage
  tests/
    unit ports live in src/ #[cfg(test)] modules
    golden.rs              # golden-output tests vs Python-captured output
    cli_behavior.rs        # binary-level: no-args help, invalid log_type
    emulator.rs            # env-gated integration tests (MinIO/Azurite/fake-gcs)
  scripts/
    gen_golden.py          # runs Python Search() over fixtures, captures stdout to tests/golden/
    compare_python.sh      # emulator diff: cloudgrepper vs python cloudgrep
    real_cloud_diff.sh     # milestone 9 runbook script
  docker/docker-compose.yml # minio, azurite, fake-gcs-server
  tests/golden/*.txt        # captured Python outputs (committed)
```

---

### Task 1: Scaffold

**Files:**
- Create: `Cargo.toml`, `src/main.rs`, `LICENSE`, `README.md`, `.gitignore`

**Interfaces:**
- Produces: a building, committed crate skeleton every later task compiles against.

- [ ] **Step 1: cargo init** (the directory already exists with docs/ and .git)

```bash
cd /Users/jeffbryner/development/cloudgrep-port/cloudgrepper
cargo init --name cloudgrepper
```

- [ ] **Step 2: Write Cargo.toml**

```toml
[package]
name = "cloudgrepper"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
description = "grep for cloud storage (S3, Azure, GCS) — Rust port of cado-security/cloudgrep"

[dependencies]
anyhow = "1"
async-trait = "0.1"
bytes = "1"
chrono = "0.4"
clap = { version = "4", features = ["derive"] }
flate2 = "1"
futures = "0.3"
regex = "1"
serde = { version = "1", features = ["derive"] }
serde_json = { version = "1", features = ["preserve_order"] }
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
zip = "2"
```

(Cloud SDKs and yara-x are added in their own tasks so the build stays green.)

- [ ] **Step 3: Placeholder main** — `src/main.rs`:

```rust
fn main() {
    println!("cloudgrepper");
}
```

- [ ] **Step 4: License, README, .gitignore**

```bash
cp ../cloudgrep/LICENSE LICENSE
printf '/target\n' > .gitignore
```

`README.md`:

```markdown
# cloudgrepper

grep for cloud storage: search log files (optionally gzip/zip compressed) in AWS S3,
Azure Blob Storage, and Google Cloud Storage, in parallel, without indexing into a SIEM.

A faithful Rust port of [cloudgrep](https://github.com/cado-security/cloudgrep) by
Cado Security (Apache-2.0, now deprecated). Same CLI, same output; `-jo` emits streaming
JSONL. Credit and thanks to cado-security for the original design and test corpus.

License: Apache-2.0.
```

- [ ] **Step 5: Verify and commit**

Run: `cargo build && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: builds clean.

```bash
git add -A && git commit -m "chore: scaffold cloudgrepper crate"
```

---

### Task 2: pyjson — Python-compatible JSON and repr formatting

**Files:**
- Create: `src/pyjson.rs`
- Modify: `src/main.rs` (add `mod pyjson;`)

**Interfaces:**
- Produces:
  - `pub fn dumps(value: &serde_json::Value) -> String` — byte-identical to Python `json.dumps(value)` defaults: separators `", "` / `": "`, ensure_ascii (non-ASCII → `\uXXXX`), insertion key order (serde_json `preserve_order`).
  - `pub fn python_repr(value: &serde_json::Value) -> String` — Python `repr()`/`str()` of the equivalent dict/list: `None`/`True`/`False`, single-quoted strings (double-quoted when the string contains `'` but not `"`), `{'k': v}` spacing.
- Consumed by: output.rs (JSON output + dict line printing), search.rs (two-stage log match serializes entries with `dumps`).

- [ ] **Step 1: Write failing tests** (bottom of `src/pyjson.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dumps_matches_python_json_dumps() {
        assert_eq!(
            dumps(&json!({"a": 1, "b": [true, null, "x"]})),
            r#"{"a": 1, "b": [true, null, "x"]}"#
        );
        // ensure_ascii: non-ASCII chars are \uXXXX-escaped like Python
        assert_eq!(dumps(&json!({"msg": "héllo"})), r#"{"msg": "h\u00e9llo"}"#);
        // control chars and quotes
        assert_eq!(dumps(&json!("a\"b\\c\nd")), r#""a\"b\\c\nd""#);
        // floats keep a decimal point like Python repr
        assert_eq!(dumps(&json!(1.0)), "1.0");
        assert_eq!(dumps(&json!(42)), "42");
        // key order is insertion order (preserve_order feature)
        let v: serde_json::Value = serde_json::from_str(r#"{"z": 1, "a": 2}"#).unwrap();
        assert_eq!(dumps(&v), r#"{"z": 1, "a": 2}"#);
    }

    #[test]
    fn python_repr_matches_python_str_of_dict() {
        assert_eq!(python_repr(&json!({"a": "b"})), "{'a': 'b'}");
        assert_eq!(
            python_repr(&json!({"k": [1, true, null]})),
            "{'k': [1, True, None]}"
        );
        // string containing a single quote uses double quotes, like Python repr
        assert_eq!(python_repr(&json!("it's")), r#""it's""#);
        assert_eq!(python_repr(&json!("plain")), "'plain'");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test pyjson 2>&1 | tail -5`
Expected: compile error, functions not defined.

- [ ] **Step 3: Implement** (top of `src/pyjson.rs`)

```rust
//! Python-compatible JSON serialization (json.dumps defaults) and repr()
//! formatting. Output fidelity with the Python cloudgrep requires both.

use serde_json::Value;

pub fn dumps(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => write_number(out, n),
        Value::String(s) => write_json_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (k, val)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_json_string(out, k);
                out.push_str(": ");
                write_value(out, val);
            }
            out.push('}');
        }
    }
}

fn write_number(out: &mut String, n: &serde_json::Number) {
    if n.is_f64() {
        let f = n.as_f64().unwrap();
        let s = format!("{f}");
        out.push_str(&s);
        // Python repr always keeps a decimal point on finite floats
        if !s.contains('.') && !s.contains('e') && !s.contains("inf") && !s.contains("NaN") {
            out.push_str(".0");
        }
    } else {
        out.push_str(&n.to_string());
    }
}

fn write_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c if (c as u32) <= 0x7e => out.push(c),
            c => {
                // ensure_ascii: escape as UTF-16 code units (surrogate pairs
                // for astral chars), exactly like Python
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

pub fn python_repr(v: &Value) -> String {
    let mut out = String::new();
    write_repr(&mut out, v);
    out
}

fn write_repr(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("None"),
        Value::Bool(b) => out.push_str(if *b { "True" } else { "False" }),
        Value::Number(n) => write_number(out, n),
        Value::String(s) => write_str_repr(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_repr(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (k, val)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_str_repr(out, k);
                out.push_str(": ");
                write_repr(out, val);
            }
            out.push('}');
        }
    }
}

fn write_str_repr(out: &mut String, s: &str) {
    // Python repr: single quotes, unless the string contains ' and not "
    let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
}
```

Add `mod pyjson;` to `src/main.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test pyjson`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A && git commit -m "feat: pyjson module for Python-compatible json.dumps and repr output"
```

---

### Task 3: decompress — decode, detect, split, extract

**Files:**
- Create: `src/decompress.rs`
- Modify: `src/main.rs` (add `mod decompress;`)

**Interfaces:**
- Produces:
  - `pub fn decode_ignore(data: &[u8]) -> String` — UTF-8 decode **dropping** invalid bytes (Python `errors="ignore"`).
  - `#[derive(Clone, Copy, PartialEq, Debug)] pub enum FileKind { Plain, Gzip, Zip }`
  - `pub fn detect(name: &str) -> FileKind` — by `.gz`/`.zip` suffix.
  - `pub fn texts(data: &[u8], kind: FileKind) -> anyhow::Result<Vec<String>>` — decoded text per logical file: Plain/Gzip → 1 element; Zip → one per non-directory member.
  - `pub fn split_lines(text: &str) -> Vec<&str>` — lines **keeping** their trailing `\n` (Python file iteration semantics; a final line without `\n` is still yielded).
- Consumed by: search.rs.

- [ ] **Step 1: Write failing tests** (`#[cfg(test)]` in `src/decompress.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let p = format!(
            "{}/../cloudgrep/tests/data/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        );
        std::fs::read(p).unwrap()
    }

    #[test]
    fn decode_ignore_drops_invalid_bytes() {
        assert_eq!(decode_ignore(b"ab\xffcd"), "abcd"); // Python: b'ab\xffcd'.decode('utf-8','ignore') == 'abcd'
        assert_eq!(decode_ignore("héllo".as_bytes()), "héllo");
    }

    #[test]
    fn detect_by_extension() {
        assert_eq!(detect("logs/a.log.gz"), FileKind::Gzip);
        assert_eq!(detect("a.zip"), FileKind::Zip);
        assert_eq!(detect("a.log"), FileKind::Plain);
    }

    #[test]
    fn split_lines_keeps_newlines() {
        assert_eq!(split_lines("a\nb\nc"), vec!["a\n", "b\n", "c"]);
        assert_eq!(split_lines("a\n"), vec!["a\n"]);
        assert_eq!(split_lines(""), Vec::<&str>::new());
    }

    #[test]
    fn gzip_fixture_contains_content() {
        let t = texts(&fixture("000000.gz"), FileKind::Gzip).unwrap();
        assert_eq!(t.len(), 1);
        assert!(t[0].contains("Running on machine"));
    }

    #[test]
    fn zip_fixture_contains_content() {
        let t = texts(&fixture("000000.zip"), FileKind::Zip).unwrap();
        assert!(!t.is_empty());
        assert!(t.iter().any(|s| s.contains("Running on machine")));
    }

    #[test]
    fn all_fixtures_decode_without_panic() {
        // Port of Python test_weird_files (UTF-8 torture files included)
        let dir = format!("{}/../cloudgrep/tests/data", env!("CARGO_MANIFEST_DIR"));
        for entry in std::fs::read_dir(dir).unwrap() {
            let data = std::fs::read(entry.unwrap().path()).unwrap();
            let _ = split_lines(&decode_ignore(&data)).len();
        }
        // and 14_3.log has an exact line "SomeLine" (last line, no trailing \n)
        let text = decode_ignore(&fixture("14_3.log"));
        assert!(split_lines(&text).iter().any(|l| *l == "SomeLine"));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test decompress 2>&1 | tail -5`
Expected: compile error.

- [ ] **Step 3: Implement**

```rust
//! Transparent handling of .gz and .zip objects, plus Python-compatible
//! text decoding (errors="ignore" drops undecodable bytes).

use std::io::Read;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileKind {
    Plain,
    Gzip,
    Zip,
}

pub fn detect(name: &str) -> FileKind {
    if name.ends_with(".gz") {
        FileKind::Gzip
    } else if name.ends_with(".zip") {
        FileKind::Zip
    } else {
        FileKind::Plain
    }
}

pub fn decode_ignore(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len());
    let mut rest = data;
    loop {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                return out;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                out.push_str(std::str::from_utf8(&rest[..valid]).unwrap());
                let skip = e.error_len().unwrap_or(rest.len() - valid);
                rest = &rest[valid + skip..];
            }
        }
    }
}

pub fn split_lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (i, b) in text.bytes().enumerate() {
        if b == b'\n' {
            lines.push(&text[start..=i]);
            start = i + 1;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

pub fn texts(data: &[u8], kind: FileKind) -> anyhow::Result<Vec<String>> {
    match kind {
        FileKind::Plain => Ok(vec![decode_ignore(data)]),
        FileKind::Gzip => {
            let mut decoder = flate2::read::GzDecoder::new(data);
            let mut buf = Vec::new();
            decoder.read_to_end(&mut buf)?;
            Ok(vec![decode_ignore(&buf)])
        }
        FileKind::Zip => {
            let cursor = std::io::Cursor::new(data);
            let mut archive = zip::ZipArchive::new(cursor)?;
            let mut out = Vec::new();
            for i in 0..archive.len() {
                let mut member = archive.by_index(i)?;
                if member.is_dir() {
                    continue;
                }
                let mut buf = Vec::new();
                member.read_to_end(&mut buf)?;
                out.push(decode_ignore(&buf));
            }
            Ok(out)
        }
    }
}
```

Add `mod decompress;` to `src/main.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test decompress`
Expected: PASS (6 tests). If `14_3.log`'s "SomeLine" assertion fails, verify with `tail -1 ../cloudgrep/tests/data/14_3.log` — the Python test `test_weird_files` asserts an element equal to `"SomeLine"` exists, which requires it be the final unterminated line; adjust the expectation only to what Python's generator would actually yield.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A && git commit -m "feat: decompress module (.gz/.zip, Python-compatible decoding and line split)"
```

---

### Task 4: filters — object metadata filtering + date parsing

**Files:**
- Create: `src/filters.rs`
- Modify: `src/main.rs` (add `mod filters;`)

**Interfaces:**
- Produces:
  - `#[derive(Clone, Debug)] pub struct ObjectMeta { pub key: String, pub size: i64, pub last_modified: Option<chrono::DateTime<chrono::Utc>> }`
  - `#[derive(Clone, Debug, Default)] pub struct Filters { pub key_contains: Option<String>, pub from_date: Option<chrono::DateTime<chrono::Utc>>, pub to_date: Option<chrono::DateTime<chrono::Utc>>, pub max_size: i64, pub check_size: bool }`
  - `impl Filters { pub fn matches(&self, obj: &ObjectMeta) -> bool }` — Python `filter_object` semantics: date-window check first; when `check_size`, reject size 0 or size > max_size; reject when `key_contains` not a substring of key. GCS uses `check_size: false` (Python's `filter_object_google` has **no size check** — quirk preserved).
  - `pub fn parse_date(s: &str) -> anyhow::Result<chrono::DateTime<chrono::Utc>>` — accepts `YYYY-MM-DD` (midnight UTC) and RFC3339/`YYYY-MM-DDTHH:MM:SS` forms. (Python uses lenient `dateutil` and naive datetimes that can crash on comparison without `-cd`; we treat naive input as UTC — a documented superset, README task 10.)
- Consumed by: providers (list-time filtering), runner.

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn meta(key: &str, size: i64, y: i32) -> ObjectMeta {
        ObjectMeta {
            key: key.into(),
            size,
            last_modified: Some(Utc.with_ymd_and_hms(y, 1, 1, 0, 0, 0).unwrap()),
        }
    }

    fn window() -> Filters {
        Filters {
            key_contains: Some("example".into()),
            from_date: Some(Utc.with_ymd_and_hms(2021, 1, 1, 0, 0, 0).unwrap()),
            to_date: Some(Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap()),
            max_size: 500,
            check_size: true,
        }
    }

    #[test]
    fn size_over_limit_rejected_then_accepted() {
        // Port of test_object_not_empty_and_size_greater_than_file_size
        let obj = meta("example_file.txt", 1000, 2022);
        assert!(!window().matches(&obj));
        let mut f = window();
        f.max_size = 500_000;
        assert!(f.matches(&obj));
    }

    #[test]
    fn empty_file_rejected() {
        // Port of test_filter_object_s3_empty_file
        let mut f = window();
        f.key_contains = Some("empty".into());
        f.max_size = 10_000;
        assert!(!f.matches(&meta("empty_file.log", 0, 2023)));
    }

    #[test]
    fn out_of_date_range_rejected() {
        // Port of test_filter_object_s3_out_of_date_range
        let mut f = window();
        f.key_contains = Some("old".into());
        f.max_size = 10_000;
        assert!(!f.matches(&meta("old_file.log", 500, 2021).clone_with_date(2021)));
    }

    #[test]
    fn gcs_style_no_size_check() {
        // Port of test_returns_true_if_all_conditions_are_met: GCS blob with
        // no size still matches because filter_object_google never checks size
        let mut f = window();
        f.check_size = false;
        let obj = ObjectMeta { key: "example_file.txt".into(), size: 0, last_modified: None };
        assert!(f.matches(&obj));
    }

    #[test]
    fn key_contains_rejects_nonmatching() {
        assert!(!window().matches(&meta("not_a_thing.txt", 100, 2022)));
    }

    #[test]
    fn parse_date_forms() {
        assert_eq!(
            parse_date("2023-01-01").unwrap(),
            Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap()
        );
        assert!(parse_date("2023-01-01T10:30:00").is_ok());
        assert!(parse_date("2023-01-01T10:30:00Z").is_ok());
        assert!(parse_date("not a date").is_err());
    }
}
```

Note: `clone_with_date` above is a test-local helper — implement it inside the test module:

```rust
    impl ObjectMeta {
        fn clone_with_date(&self, y: i32) -> ObjectMeta {
            let mut o = self.clone();
            o.last_modified = Some(Utc.with_ymd_and_hms(y, 1, 1, 0, 0, 0).unwrap());
            o
        }
    }
```

Wait — the out-of-range test needs last_modified 2021 with from_date 2022. Simpler: drop the helper and build the filter window as 2022..2024 with the object dated 2021:

```rust
    #[test]
    fn out_of_date_range_rejected() {
        let f = Filters {
            key_contains: Some("old".into()),
            from_date: Some(Utc.with_ymd_and_hms(2022, 1, 1, 0, 0, 0).unwrap()),
            to_date: Some(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()),
            max_size: 10_000,
            check_size: true,
        };
        assert!(!f.matches(&meta("old_file.log", 500, 2021)));
    }
```

Use this version; do not implement `clone_with_date`.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test filters 2>&1 | tail -5`
Expected: compile error.

- [ ] **Step 3: Implement**

```rust
//! Object-listing filters, ported from cloud.py's filter_object* functions.

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};

#[derive(Clone, Debug)]
pub struct ObjectMeta {
    pub key: String,
    pub size: i64,
    pub last_modified: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default)]
pub struct Filters {
    pub key_contains: Option<String>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub max_size: i64,
    // filter_object_google never checks size — GCS sets this false
    pub check_size: bool,
}

impl Filters {
    pub fn matches(&self, obj: &ObjectMeta) -> bool {
        if let Some(lm) = obj.last_modified {
            if let Some(from) = self.from_date {
                if lm < from {
                    return false;
                }
            }
            if let Some(to) = self.to_date {
                if lm > to {
                    return false;
                }
            }
        }
        if self.check_size && (obj.size == 0 || obj.size > self.max_size) {
            return false;
        }
        if let Some(kc) = &self.key_contains {
            if !obj.key.contains(kc.as_str()) {
                return false;
            }
        }
        true
    }
}

pub fn parse_date(s: &str) -> anyhow::Result<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Ok(ndt.and_utc());
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Ok(ndt.and_utc());
    }
    if let Ok(nd) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Ok(nd.and_hms_opt(0, 0, 0).unwrap().and_utc());
    }
    anyhow::bail!("could not parse date: {s}")
}
```

Add `mod filters;` to `src/main.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test filters`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A && git commit -m "feat: object filters and date parsing (ports filter_object* semantics)"
```

---

### Task 5: cli — flags, argv shim, query loading

**Files:**
- Create: `src/cli.rs`
- Modify: `src/main.rs` (add `mod cli;`)

**Interfaces:**
- Produces:
  - `#[derive(clap::Parser, Debug)] pub struct Cli` — fields: `bucket: Option<String>`, `account_name: Option<String>`, `container_name: Option<String>`, `google_bucket: Option<String>`, `query: Option<String>`, `file: Option<String>`, `yara: Option<String>`, `prefix: String` (default `""`), `filename: Option<String>`, `start_date: Option<String>`, `end_date: Option<String>`, `file_size: i64` (default `100_000_000`), `profile: Option<String>`, `debug: bool`, `hide_filenames: bool`, `log_type: Option<String>`, `log_format: Option<String>`, `log_properties: Option<String>`, `json_output: bool`, `convert_date: bool`, `use_og_name: bool`.
  - `pub fn normalize_args<I: IntoIterator<Item = String>>(args: I) -> Vec<String>` — rewrites Python's multi-char short forms to long forms before clap sees them.
  - `pub fn parse_comma_list(s: &str) -> Vec<String>` — Python `list_of_strings`: split on `,`, trim, drop empties.
  - `pub fn load_query_file(path: &str) -> anyhow::Result<Vec<String>>` — Python `load_queries`: one per line, trimmed, blanks dropped.
- Consumed by: main.rs, runner.rs.

**Critical detail:** clap short flags are single-char only. Python argparse accepts `-an`, `-cn`, `-gb`, `-fs`, `-pr`, `-hf`, `-lt`, `-lf`, `-lp`, `-jo`, `-cd`, `-og`. The shim maps each (and its `=value` form) to the long flag. Long flag spellings must match argparse exactly: `--account-name`, `--container-name`, `--google-bucket` use hyphens; `--start_date`, `--end_date`, `--file_size`, `--hide_filenames`, `--log_type`, `--log_format`, `--log_properties`, `--json_output`, `--convert_date`, `--use_og_name` use underscores — so every underscore flag needs an explicit `long = "..."` (clap derive would kebab-case them).

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        let mut full = vec!["cloudgrepper".to_string()];
        full.extend(args.iter().map(|s| s.to_string()));
        Cli::try_parse_from(normalize_args(full)).unwrap()
    }

    #[test]
    fn short_flag_shim_maps_all_multichar_shorts() {
        let cli = parse(&[
            "-b", "buck", "-an", "acct", "-cn", "cont", "-gb", "gbuck", "-q", "foo,bar",
            "-fs", "500", "-pr", "prof", "-hf", "-lt", "cloudtrail", "-jo", "-cd", "-og",
        ]);
        assert_eq!(cli.bucket.as_deref(), Some("buck"));
        assert_eq!(cli.account_name.as_deref(), Some("acct"));
        assert_eq!(cli.container_name.as_deref(), Some("cont"));
        assert_eq!(cli.google_bucket.as_deref(), Some("gbuck"));
        assert_eq!(cli.file_size, 500);
        assert_eq!(cli.profile.as_deref(), Some("prof"));
        assert!(cli.hide_filenames && cli.json_output && cli.convert_date && cli.use_og_name);
        assert_eq!(cli.log_type.as_deref(), Some("cloudtrail"));
    }

    #[test]
    fn long_flags_use_python_spellings() {
        let cli = parse(&["--file_size", "42", "--hide_filenames", "--start_date", "2023-01-01"]);
        assert_eq!(cli.file_size, 42);
        assert!(cli.hide_filenames);
        assert_eq!(cli.start_date.as_deref(), Some("2023-01-01"));
        // kebab-case must NOT be accepted for underscore flags
        assert!(Cli::try_parse_from(["p", "--file-size", "42"]).is_err());
    }

    #[test]
    fn shim_handles_equals_form_and_defaults() {
        let cli = parse(&["-fs=99", "-b", "x"]);
        assert_eq!(cli.file_size, 99);
        let cli = parse(&["-b", "x"]);
        assert_eq!(cli.file_size, 100_000_000);
        assert_eq!(cli.prefix, "");
    }

    #[test]
    fn comma_list_matches_python_list_of_strings() {
        assert_eq!(parse_comma_list("a, b ,,c"), vec!["a", "b", "c"]);
        assert_eq!(parse_comma_list(""), Vec::<String>::new());
    }

    #[test]
    fn load_query_file_trims_and_drops_blanks() {
        // Port of test_returns_string_with_file_contents
        let p = std::env::temp_dir().join("cloudgrepper_queries_test.txt");
        std::fs::write(&p, "query1\nquery2\n\n  query3  \n").unwrap();
        assert_eq!(
            load_query_file(p.to_str().unwrap()).unwrap(),
            vec!["query1", "query2", "query3"]
        );
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test cli 2>&1 | tail -5`
Expected: compile error.

- [ ] **Step 3: Implement**

```rust
//! CLI mirroring cloudgrep's argparse interface exactly, including the
//! multi-char "short" options argparse allows but clap does not.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "cloudgrepper",
    about = "CloudGrep: grep for cloud storage (S3, Azure, Google Cloud). Rust port of cado-security/cloudgrep."
)]
pub struct Cli {
    /// AWS S3 Bucket to search (e.g. my-bucket)
    #[arg(short = 'b', long)]
    pub bucket: Option<String>,
    /// Azure Account Name to search
    #[arg(long = "account-name")]
    pub account_name: Option<String>,
    /// Azure Container Name to search
    #[arg(long = "container-name")]
    pub container_name: Option<String>,
    /// Google Cloud Bucket to search
    #[arg(long = "google-bucket")]
    pub google_bucket: Option<String>,
    /// Comma-separated list of regex patterns to search
    #[arg(short = 'q', long)]
    pub query: Option<String>,
    /// File containing queries (one per line)
    #[arg(short = 'v', long)]
    pub file: Option<String>,
    /// File containing Yara rules
    #[arg(short = 'y', long)]
    pub yara: Option<String>,
    /// Filter objects by prefix (e.g. logs/)
    #[arg(short = 'p', long, default_value = "")]
    pub prefix: String,
    /// Filter objects whose names contain a keyword (e.g. .log.gz)
    #[arg(short = 'f', long)]
    pub filename: Option<String>,
    /// Filter objects modified after this date (YYYY-MM-DD)
    #[arg(short = 's', long = "start_date")]
    pub start_date: Option<String>,
    /// Filter objects modified before this date (YYYY-MM-DD)
    #[arg(short = 'e', long = "end_date")]
    pub end_date: Option<String>,
    /// Max file size in bytes (default: 100MB)
    #[arg(long = "file_size", default_value_t = 100_000_000)]
    pub file_size: i64,
    /// AWS profile to use (e.g. default, dev, prod)
    #[arg(long)]
    pub profile: Option<String>,
    /// Enable debug logging
    #[arg(short = 'd', long)]
    pub debug: bool,
    /// Hide filenames in output
    #[arg(long = "hide_filenames")]
    pub hide_filenames: bool,
    /// Pre-defined log type (e.g. cloudtrail, azure)
    #[arg(long = "log_type")]
    pub log_type: Option<String>,
    /// Custom log format (e.g. json, csv)
    #[arg(long = "log_format")]
    pub log_format: Option<String>,
    /// Comma-separated list of log properties to extract
    #[arg(long = "log_properties")]
    pub log_properties: Option<String>,
    /// Output results in JSON format
    #[arg(long = "json_output")]
    pub json_output: bool,
    /// Convert date to ISO format (YYYY-MM-DDTHH:MM:SS)
    #[arg(long = "convert_date")]
    pub convert_date: bool,
    /// Use original key name instead of temporary name for uncompressed files
    #[arg(long = "use_og_name")]
    pub use_og_name: bool,
}

const SHORT_MAP: [(&str, &str); 12] = [
    ("-an", "--account-name"),
    ("-cn", "--container-name"),
    ("-gb", "--google-bucket"),
    ("-fs", "--file_size"),
    ("-pr", "--profile"),
    ("-hf", "--hide_filenames"),
    ("-lt", "--log_type"),
    ("-lf", "--log_format"),
    ("-lp", "--log_properties"),
    ("-jo", "--json_output"),
    ("-cd", "--convert_date"),
    ("-og", "--use_og_name"),
];

pub fn normalize_args<I: IntoIterator<Item = String>>(args: I) -> Vec<String> {
    args.into_iter()
        .map(|arg| {
            for (short, long) in SHORT_MAP {
                if arg == short {
                    return long.to_string();
                }
                if let Some(rest) = arg.strip_prefix(&format!("{short}=")) {
                    return format!("{long}={rest}");
                }
            }
            arg
        })
        .collect()
}

pub fn parse_comma_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(String::from)
        .collect()
}

pub fn load_query_file(path: &str) -> anyhow::Result<Vec<String>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}
```

Add `mod cli;` to `src/main.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test cli`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A && git commit -m "feat: CLI with argparse-compatible flags and multi-char short-option shim"
```

---

### Task 6: output — match records and print_match

**Files:**
- Create: `src/output.rs`
- Modify: `src/main.rs` (add `mod output;`)

**Interfaces:**
- Produces:
  - `pub enum Record { Match { key_name: String, query: String, line: serde_json::Value }, Yara { key_name: String, match_rule: String, match_strings: Vec<String> } }`
  - `pub fn print_match(rec: &Record, hide_filenames: bool, json_output: bool, out: &mut impl std::io::Write)` — replicates `search.py::print_match` exactly (see behavior table below).
- Consumes: `pyjson::{dumps, python_repr}` from Task 2.
- Consumed by: search.rs, yara.rs, runner.rs.

**Behavior table (from `../cloudgrep/cloudgrep/search.py` lines 17-30):**

| record | json_output | output line |
|---|---|---|
| Match, string line | true | `{"key_name": "k", "query": "q", "line": "raw line\n"}` via `pyjson::dumps` (key_name omitted if hidden) |
| Match, dict line (log entry) | true | same, `line` is the JSON object |
| Match, string line | false | `k: raw line\n` (line keeps its own `\n` → doubled newline) or just the line if hidden |
| Match, dict line | false | `k: {'a': 'b'}` — dict rendered with `pyjson::python_repr` |
| Yara | false | `k: rule_name: [$a]` — `match_strings` rendered `[$id, $id]`, identifiers unquoted |
| Yara | true | `{'key_name': 'k', 'match_rule': 'rule_name', 'match_strings': [$a]}` — **Python quirk**: `json.dumps` raises TypeError on yara objects and falls back to `print(str(output))`, so JSON mode emits Python-repr, with unquoted `$id` items. Replicate exactly. |

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn capture(rec: &Record, hide: bool, json_out: bool) -> String {
        let mut buf = Vec::new();
        print_match(rec, hide, json_out, &mut buf);
        String::from_utf8(buf).unwrap()
    }

    fn sample() -> Record {
        Record::Match {
            key_name: "file.log".into(),
            query: "hello".into(),
            line: json!("hello world\n"),
        }
    }

    #[test]
    fn line_output_keeps_trailing_newline_doubled() {
        // Python: print(f"{key}: {line}") where line ends in \n
        assert_eq!(capture(&sample(), false, false), "file.log: hello world\n\n");
        assert_eq!(capture(&sample(), true, false), "hello world\n\n");
    }

    #[test]
    fn json_output_is_python_json_dumps() {
        assert_eq!(
            capture(&sample(), false, true),
            "{\"key_name\": \"file.log\", \"query\": \"hello\", \"line\": \"hello world\\n\"}\n"
        );
        assert_eq!(
            capture(&sample(), true, true),
            "{\"query\": \"hello\", \"line\": \"hello world\\n\"}\n"
        );
    }

    #[test]
    fn dict_line_prints_python_repr() {
        let rec = Record::Match {
            key_name: "k".into(),
            query: "q".into(),
            line: json!({"eventName": "PutObject"}),
        };
        assert_eq!(capture(&rec, false, false), "k: {'eventName': 'PutObject'}\n");
    }

    #[test]
    fn yara_line_and_json_fallback() {
        let rec = Record::Yara {
            key_name: "key_name".into(),
            match_rule: "rule_name".into(),
            match_strings: vec!["$a".into()],
        };
        assert_eq!(capture(&rec, false, false), "key_name: rule_name: [$a]\n");
        // Port of test_yara expected output (json.dumps TypeError fallback)
        assert_eq!(
            capture(&rec, true, true),
            "{'match_rule': 'rule_name', 'match_strings': [$a]}\n"
        );
        assert_eq!(
            capture(&rec, false, true),
            "{'key_name': 'key_name', 'match_rule': 'rule_name', 'match_strings': [$a]}\n"
        );
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test output 2>&1 | tail -5`
Expected: compile error.

- [ ] **Step 3: Implement**

```rust
//! Match record printing, ported from search.py::print_match.

use crate::pyjson;
use serde_json::{Map, Value};
use std::io::Write;

pub enum Record {
    Match {
        key_name: String,
        query: String,
        line: Value,
    },
    Yara {
        key_name: String,
        match_rule: String,
        match_strings: Vec<String>,
    },
}

pub fn print_match(rec: &Record, hide_filenames: bool, json_output: bool, out: &mut impl Write) {
    match rec {
        Record::Match { key_name, query, line } => {
            if json_output {
                let mut map = Map::new();
                if !hide_filenames {
                    map.insert("key_name".into(), Value::String(key_name.clone()));
                }
                map.insert("query".into(), Value::String(query.clone()));
                map.insert("line".into(), line.clone());
                let _ = writeln!(out, "{}", pyjson::dumps(&Value::Object(map)));
            } else {
                let line_disp = match line {
                    Value::String(s) => s.clone(),
                    other => pyjson::python_repr(other),
                };
                if hide_filenames {
                    let _ = writeln!(out, "{line_disp}");
                } else {
                    let _ = writeln!(out, "{key_name}: {line_disp}");
                }
            }
        }
        Record::Yara { key_name, match_rule, match_strings } => {
            // Python renders yara StringMatch objects via repr: [$a, $b]
            let strings_disp = format!("[{}]", match_strings.join(", "));
            if json_output {
                // Python quirk: json.dumps raises TypeError on yara objects,
                // falls back to print(str(dict)) — repr-style output
                let mut parts = Vec::new();
                if !hide_filenames {
                    parts.push(format!("'key_name': '{key_name}'"));
                }
                parts.push(format!("'match_rule': '{match_rule}'"));
                parts.push(format!("'match_strings': {strings_disp}"));
                let _ = writeln!(out, "{{{}}}", parts.join(", "));
            } else {
                let line = format!("{match_rule}: {strings_disp}");
                if hide_filenames {
                    let _ = writeln!(out, "{line}");
                } else {
                    let _ = writeln!(out, "{key_name}: {line}");
                }
            }
        }
    }
}
```

Add `mod output;` to `src/main.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test output`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A && git commit -m "feat: output module replicating print_match line/JSON/yara semantics"
```

---

### Task 7: logparse — parse_logs and extract_log_entries

**Files:**
- Create: `src/logparse.rs`
- Modify: `src/main.rs` (add `mod logparse;`), `Cargo.toml` (add `csv = "1"`)

**Interfaces:**
- Produces:
  - `pub fn parse_logs(line: &str, log_format: &str) -> Option<serde_json::Value>` — `"json"`: parse, log error + None on failure. `"jsonl"`: Python does `line.strip().split("\n")` → array of the trimmed line's segments (strings). `"csv"`: Python `list(csv.DictReader([line]))` semantics — first row is the header, remaining rows become dicts; a single-line input therefore yields an **empty array** (quirk preserved). Unknown format: log `Unsupported log format: {fmt}` + None.
  - `pub fn extract_log_entries(parsed: serde_json::Value, log_properties: &[String]) -> Vec<serde_json::Value>` — walk properties into objects; final list → its items; null → empty; anything else → single-item vec. (Python raises AttributeError when an intermediate value is a non-dict; we stop the walk and yield nothing — documented micro-divergence to avoid a crash.)
  - `pub fn is_falsy(v: &serde_json::Value) -> bool` — Python truthiness: null/false/0/`""`/`[]`/`{}` are falsy. search.rs uses it for Python's `if not parsed: return`.
- Consumed by: search.rs.

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_format_parses_object() {
        let v = parse_logs(r#"{"Records": [{"a": 1}]}"#, "json").unwrap();
        assert_eq!(v, json!({"Records": [{"a": 1}]}));
        assert!(parse_logs("not json", "json").is_none());
    }

    #[test]
    fn jsonl_format_returns_trimmed_line_as_string_array() {
        // Python: line.strip().split("\n") — single line in, single string out
        assert_eq!(
            parse_logs("  {\"a\": 1}  \n", "jsonl").unwrap(),
            json!(["{\"a\": 1}"])
        );
    }

    #[test]
    fn csv_single_line_is_header_only_and_empty() {
        // Python quirk: DictReader consumes the sole line as the header
        assert_eq!(parse_logs("col1,col2", "csv").unwrap(), json!([]));
        // multi-line input (only reachable in tests) does produce rows
        assert_eq!(
            parse_logs("col1,col2\nval1,val2", "csv").unwrap(),
            json!([{"col1": "val1", "col2": "val2"}])
        );
    }

    #[test]
    fn unknown_format_returns_none() {
        // Port of test_search_logs_unknown_format
        assert!(parse_logs(r#"{"foo": "bar"}"#, "not_a_real_format").is_none());
    }

    #[test]
    fn extract_walks_properties() {
        let parsed = json!({"Records": [{"e": 1}, {"e": 2}]});
        assert_eq!(
            extract_log_entries(parsed, &["Records".to_string()]),
            vec![json!({"e": 1}), json!({"e": 2})]
        );
        // missing property -> empty
        assert!(extract_log_entries(json!({"a": 1}), &["nope".to_string()]).is_empty());
        // no properties + non-list -> single item
        assert_eq!(extract_log_entries(json!({"a": 1}), &[]), vec![json!({"a": 1})]);
        // top-level list ignores properties (Python only walks dicts)
        assert_eq!(
            extract_log_entries(json!([1, 2]), &["data".to_string()]),
            vec![json!(1), json!(2)]
        );
    }

    #[test]
    fn falsy_matches_python_truthiness() {
        for v in [json!(null), json!(false), json!(0), json!(""), json!([]), json!({})] {
            assert!(is_falsy(&v));
        }
        assert!(!is_falsy(&json!([1])));
        assert!(!is_falsy(&json!("x")));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test logparse 2>&1 | tail -5`
Expected: compile error.

- [ ] **Step 3: Implement**

```rust
//! Log-record extraction, ported from search.py::parse_logs and
//! extract_log_entries, quirks included.

use serde_json::Value;
use tracing::error;

pub fn parse_logs(line: &str, log_format: &str) -> Option<Value> {
    match log_format {
        "json" => match serde_json::from_str::<Value>(line) {
            Ok(v) => Some(v),
            Err(e) => {
                error!("JSON decode error in line: {line} ({e})");
                None
            }
        },
        "jsonl" => {
            let parts: Vec<Value> = line
                .trim()
                .split('\n')
                .map(|s| Value::String(s.to_string()))
                .collect();
            Some(Value::Array(parts))
        }
        "csv" => {
            // Python: list(csv.DictReader([line])) — header row + data rows
            let mut rows = Vec::new();
            let mut rdr = csv::ReaderBuilder::new()
                .has_headers(true)
                .flexible(true)
                .from_reader(line.as_bytes());
            let headers = match rdr.headers() {
                Ok(h) => h.clone(),
                Err(e) => {
                    error!("CSV parse error in line: {line} ({e})");
                    return None;
                }
            };
            for rec in rdr.records().flatten() {
                let mut obj = serde_json::Map::new();
                for (h, v) in headers.iter().zip(rec.iter()) {
                    obj.insert(h.to_string(), Value::String(v.to_string()));
                }
                rows.push(Value::Object(obj));
            }
            Some(Value::Array(rows))
        }
        other => {
            error!("Unsupported log format: {other}");
            None
        }
    }
}

pub fn extract_log_entries(parsed: Value, log_properties: &[String]) -> Vec<Value> {
    let mut current = parsed;
    if !log_properties.is_empty() && current.is_object() {
        for prop in log_properties {
            let next = if let Value::Object(map) = &current {
                map.get(prop).cloned().unwrap_or(Value::Null)
            } else {
                // Python would raise AttributeError here; we stop the walk
                Value::Null
            };
            current = next;
            if current.is_null() {
                break;
            }
        }
    }
    match current {
        Value::Array(items) => items,
        Value::Null => Vec::new(),
        other => vec![other],
    }
}

pub fn is_falsy(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}
```

Add `csv = "1"` to `[dependencies]` in Cargo.toml and `mod logparse;` to `src/main.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test logparse`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A && git commit -m "feat: logparse module (json/jsonl/csv, property extraction, Python truthiness)"
```

---

### Task 8: search — the matching engine + golden-output tests

**Files:**
- Create: `src/search.rs`, `scripts/gen_golden.py`, `tests/golden.rs`, `tests/support/mod.rs`, `tests/golden/*.txt` (generated)
- Modify: `src/main.rs` (add `mod search;`)

**Interfaces:**
- Produces:
  - `pub struct SearchConfig { pub patterns: Vec<(String, regex::Regex)>, pub hide_filenames: bool, pub json_output: bool, pub log_format: Option<String>, pub log_properties: Vec<String>, pub account_name: Option<String> }`
  - `pub fn compile_patterns(patterns: &[String]) -> anyhow::Result<Vec<(String, regex::Regex)>>` — first bad pattern is a run-level error, like Python's `re.compile` raising.
  - `pub fn search_object(cfg: &SearchConfig, key_name: &str, data: &[u8], out: &mut impl std::io::Write) -> bool` — full port of `search.py::search_file` on in-memory bytes; returns "any match" (feeds the per-file hit count).
  - `pub fn search_line(cfg: &SearchConfig, key_name: &str, line: &str, out: &mut impl std::io::Write) -> bool`
- Consumes: `decompress::{detect, texts, split_lines, FileKind}`, `logparse::{parse_logs, extract_log_entries, is_falsy}`, `output::{Record, print_match}`, `pyjson::dumps`.
- Consumed by: runner.rs, tests/golden.rs.

**⚠ Documented divergences from Python 1.0.5 (deliberate — record in spec, README, and code comments):**

1. **All matching lines are reported.** Python 1.0.5's `process_lines` is `any(search_line(...) for line in lines)` — `any()` short-circuits, so Python stops after the **first matching line per file** (a regression; it guts grep semantics). cloudgrepper searches every line, per the approved spec. Golden-comparison cases below are therefore restricted to inputs with at most one matching line (or single-line JSON files, where Python's per-record loop is not short-circuited).
2. **Decompression keys off the object key.** Python 1.0.5 detects `.gz`/`.zip` from the *temp-file name* (random, extensionless) unless `-og` is passed — i.e. S3 decompression is silently broken without `-og` (another regression; `test_gzip` passes only because tests call `search_file` with real filenames). cloudgrepper always detects from the object key — equivalent to Python run with `-og`, and to Python ≤ 1.0.4. `-og` remains accepted and only affects debug-log labels.

**Ported semantics (verify each against `../cloudgrep/cloudgrep/search.py` while implementing):**
- Per line: every pattern tested; each hit → if `log_format` is set, go two-stage (parse line, extract entries, re-match each entry's `pyjson::dumps` serialization, print matching entries); else print the raw-line record. Return whether any pattern hit.
- Azure special case: `account_name` set AND kind is Gzip/Zip → whole decompressed text is JSON-parsed; Python then iterates the parsed value as "lines" — real string entries get searched, any non-string entry raises TypeError caught as a whole-file error. Port: parse JSON; if it's an array, process **string** elements with `search_line`; on the first non-string element log `Error processing gzip file: {key_name}` (or zip) and return false. JSON parse failure → same error log, false.
- Zip: every non-directory member searched; per-member "any match" OR-ed into the file result (`matched_any`).
- Corrupt gzip/zip → log error, return false (never panic).

- [ ] **Step 1: Write failing unit tests** (`#[cfg(test)]` in `src/search.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../cloudgrep/tests/data/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        ))
        .unwrap()
    }

    fn cfg(patterns: &[&str]) -> SearchConfig {
        SearchConfig {
            patterns: compile_patterns(
                &patterns.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
            .unwrap(),
            hide_filenames: false,
            json_output: false,
            log_format: None,
            log_properties: vec![],
            account_name: None,
        }
    }

    fn run(cfg: &SearchConfig, key: &str, data: &[u8]) -> (bool, String) {
        let mut buf = Vec::new();
        let found = search_object(cfg, key, data, &mut buf);
        (found, String::from_utf8(buf).unwrap())
    }

    #[test]
    fn gzip_search_finds_match() {
        // Port of test_gzip + test_print_match
        let (found, out) = run(&cfg(&["Running on machine"]), "000000.gz", &fixture("000000.gz"));
        assert!(found);
        assert!(out.contains("Running on machine"));
    }

    #[test]
    fn zip_search_finds_match() {
        // Port of test_zip
        let (found, out) = run(&cfg(&["Running on machine"]), "000000.zip", &fixture("000000.zip"));
        assert!(found);
        assert!(out.contains("Running on machine"));
    }

    #[test]
    fn json_output_mode_emits_valid_jsonl() {
        // Port of test_json_output
        let mut c = cfg(&["Running on machine"]);
        c.json_output = true;
        let (_, out) = run(&c, "000000.gz", &fixture("000000.gz"));
        for line in out.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(v.get("query").is_some());
        }
    }

    #[test]
    fn all_matching_lines_reported_not_just_first() {
        // Deliberate divergence from Python's any() short-circuit
        let data = b"hit one\nmiss\nhit two\n";
        let (found, out) = run(&cfg(&["hit"]), "k.log", data);
        assert!(found);
        assert!(out.contains("hit one") && out.contains("hit two"));
    }

    #[test]
    fn cloudtrail_search() {
        // Port of test_search_cloudtrail
        let mut c = cfg(&["Running on machine"]);
        c.log_format = Some("json".into());
        c.log_properties = vec!["Records".into()];
        // bad json / no match: must not panic, must not match
        let (found, _) = run(&c, "bad_cloudtrail.json", &fixture("bad_cloudtrail.json"));
        assert!(!found);
        let (found, _) = run(&c, "cloudtrail.json", &fixture("cloudtrail.json"));
        assert!(!found);

        let mut c = cfg(&["SignatureVersion"]);
        c.log_format = Some("json".into());
        c.log_properties = vec!["Records".into()];
        c.json_output = true;
        let (found, out) = run(
            &c,
            "cloudtrail_singleline.json",
            &fixture("cloudtrail_singleline.json"),
        );
        assert!(found);
        assert!(out.contains("SignatureVersion"));
        let first = out.lines().next().unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(first).is_ok());
    }

    #[test]
    fn two_stage_matching_requires_raw_line_hit() {
        // A pattern present in the serialized record but NOT the raw line
        // never fires (Python quirk: raw-line regex gates JSON parsing).
        let data = br#"{"Records": [{"msg": "héllo"}]}"#; // raw line lacks "héllo"
        let mut c = cfg(&["héllo"]);
        c.log_format = Some("json".into());
        c.log_properties = vec!["Records".into()];
        let (found, out) = run(&c, "k.json", data);
        assert!(!found && out.is_empty());
    }

    #[test]
    fn compile_patterns_rejects_bad_regex() {
        assert!(compile_patterns(&["(unclosed".to_string()]).is_err());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test search 2>&1 | tail -5`
Expected: compile error.

- [ ] **Step 3: Implement**

```rust
//! The matching engine: port of search.py::search_file / search_line /
//! search_logs operating on in-memory bytes.

use crate::decompress::{self, FileKind};
use crate::logparse;
use crate::output::{print_match, Record};
use crate::pyjson;
use regex::Regex;
use serde_json::Value;
use std::io::Write;
use tracing::error;

pub struct SearchConfig {
    pub patterns: Vec<(String, Regex)>,
    pub hide_filenames: bool,
    pub json_output: bool,
    pub log_format: Option<String>,
    pub log_properties: Vec<String>,
    pub account_name: Option<String>,
}

pub fn compile_patterns(patterns: &[String]) -> anyhow::Result<Vec<(String, Regex)>> {
    patterns
        .iter()
        .map(|p| Ok((p.clone(), Regex::new(p)?)))
        .collect()
}

pub fn search_object(
    cfg: &SearchConfig,
    key_name: &str,
    data: &[u8],
    out: &mut impl Write,
) -> bool {
    let kind = decompress::detect(key_name);

    // Azure export special case: whole file is one JSON document
    if cfg.account_name.is_some() && kind != FileKind::Plain {
        return search_azure_json(cfg, key_name, data, kind, out);
    }

    let texts = match decompress::texts(data, kind) {
        Ok(t) => t,
        Err(e) => {
            let what = match kind {
                FileKind::Gzip => "gzip file",
                FileKind::Zip => "zip file",
                FileKind::Plain => "file",
            };
            error!("Error processing {what}: {key_name}: {e}");
            return false;
        }
    };
    let mut matched_any = false;
    for text in &texts {
        for line in decompress::split_lines(text) {
            // NOTE: Python 1.0.5 short-circuits after the first matching
            // line (any()); we deliberately search every line.
            if search_line(cfg, key_name, line, out) {
                matched_any = true;
            }
        }
    }
    matched_any
}

fn search_azure_json(
    cfg: &SearchConfig,
    key_name: &str,
    data: &[u8],
    kind: FileKind,
    out: &mut impl Write,
) -> bool {
    let what = if kind == FileKind::Zip { "zip file" } else { "gzip file" };
    let texts = match decompress::texts(data, kind) {
        Ok(t) => t,
        Err(e) => {
            error!("Error processing {what}: {key_name}: {e}");
            return false;
        }
    };
    let mut matched_any = false;
    for text in &texts {
        let parsed: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                error!("Error processing {what}: {key_name}: {e}");
                continue;
            }
        };
        let Value::Array(entries) = parsed else {
            error!("Error processing {what}: {key_name}: expected JSON array");
            continue;
        };
        for entry in entries {
            match entry {
                Value::String(s) => {
                    if search_line(cfg, key_name, &s, out) {
                        matched_any = true;
                    }
                }
                _ => {
                    // Python: re.search(pattern, dict) raises TypeError,
                    // aborting the whole file
                    error!("Error processing {what}: {key_name}: non-string entry");
                    return matched_any;
                }
            }
        }
    }
    matched_any
}

pub fn search_line(
    cfg: &SearchConfig,
    key_name: &str,
    line: &str,
    out: &mut impl Write,
) -> bool {
    let mut found = false;
    for (raw, re) in &cfg.patterns {
        if re.is_match(line) {
            if let Some(fmt) = &cfg.log_format {
                search_logs(cfg, key_name, line, raw, re, fmt, out);
            } else {
                print_match(
                    &Record::Match {
                        key_name: key_name.to_string(),
                        query: raw.clone(),
                        line: Value::String(line.to_string()),
                    },
                    cfg.hide_filenames,
                    cfg.json_output,
                    out,
                );
            }
            found = true;
        }
    }
    found
}

fn search_logs(
    cfg: &SearchConfig,
    key_name: &str,
    line: &str,
    raw_pattern: &str,
    re: &Regex,
    log_format: &str,
    out: &mut impl Write,
) {
    let Some(parsed) = logparse::parse_logs(line, log_format) else {
        return;
    };
    if logparse::is_falsy(&parsed) {
        return;
    }
    for entry in logparse::extract_log_entries(parsed, &cfg.log_properties) {
        let entry_str = pyjson::dumps(&entry);
        if re.is_match(&entry_str) {
            print_match(
                &Record::Match {
                    key_name: key_name.to_string(),
                    query: raw_pattern.to_string(),
                    line: entry,
                },
                cfg.hide_filenames,
                cfg.json_output,
                out,
            );
        }
    }
}
```

Add `mod search;` to `src/main.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test search`
Expected: PASS (7 tests).

- [ ] **Step 5: Write the golden generator** — `scripts/gen_golden.py`:

```python
#!/usr/bin/env python3
"""Capture Python cloudgrep Search() output over fixtures -> tests/golden/.

Uses only the Python stdlib (search.py has no third-party imports).
Golden cases are restricted to scenarios where Python 1.0.5's any()
short-circuit cannot truncate output: single-line JSON files, or files
whose first matching line is the only interesting comparison.
"""
import io
import os
import sys
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "cloudgrep"))
from cloudgrep.search import Search  # noqa: E402

DATA = os.path.join(HERE, "..", "..", "cloudgrep", "tests", "data")
OUT = os.path.join(HERE, "..", "tests", "golden")
os.makedirs(OUT, exist_ok=True)

# (golden_name, fixture, queries, hide_filenames, log_format, log_properties, json_output)
CASES = [
    ("cloudtrail_sig_json.txt", "cloudtrail_singleline.json", ["SignatureVersion"], False, "json", ["Records"], True),
    ("cloudtrail_sig_line.txt", "cloudtrail_singleline.json", ["SignatureVersion"], False, "json", ["Records"], False),
    ("cloudtrail_sig_hidden.txt", "cloudtrail_singleline.json", ["SignatureVersion"], True, "json", ["Records"], True),
    ("azure_singleline_json.txt", "azure_singleline.json", ["listKeys"], False, "json", ["data"], True),
    ("gz_first_match.txt", "000000.gz", ["Running on machine"], False, None, [], False),
    ("gz_first_match_json.txt", "000000.gz", ["Running on machine"], False, None, [], True),
    ("zip_first_match.txt", "000000.zip", ["Running on machine"], False, None, [], False),
    ("utf8_torture.txt", "UTF-8-Test.txt", ["the"], False, None, [], False),
]

for name, fixture, queries, hide, fmt, props, jo in CASES:
    buf = io.StringIO()
    with redirect_stdout(buf):
        Search().search_file(os.path.join(DATA, fixture), fixture, queries, hide, None, fmt, props, jo)
    with open(os.path.join(OUT, name), "w") as f:
        f.write(buf.getvalue())
    print(f"wrote {name}")
```

Run: `python3 scripts/gen_golden.py`
Expected: `wrote <name>` for all cases; files appear in `tests/golden/`. Inspect each golden file — non-empty except where a case legitimately produces no output.

**Caveat for `utf8_torture.txt` and the gz/zip cases:** Python emits only the first matching line. The Rust assertions for these compare Python's output as a **prefix** of ours; the single-line JSON cases compare **exact equality**.

- [ ] **Step 6: Write golden tests** — `tests/golden.rs`:

```rust
//! Byte-comparison against captured Python cloudgrep output.
//! Regenerate goldens with: python3 scripts/gen_golden.py

mod support;
use support::*;

#[test]
fn exact_equality_cases() {
    for (golden, fixture, queries, hide, fmt, props, jo) in [
        ("cloudtrail_sig_json.txt", "cloudtrail_singleline.json", "SignatureVersion", false, Some("json"), "Records", true),
        ("cloudtrail_sig_line.txt", "cloudtrail_singleline.json", "SignatureVersion", false, Some("json"), "Records", false),
        ("cloudtrail_sig_hidden.txt", "cloudtrail_singleline.json", "SignatureVersion", true, Some("json"), "Records", true),
        ("azure_singleline_json.txt", "azure_singleline.json", "listKeys", false, Some("json"), "data", true),
    ] {
        let ours = run_search(fixture, queries, hide, fmt, props, jo);
        assert_eq!(ours, golden_content(golden), "golden mismatch: {golden}");
    }
}

#[test]
fn prefix_cases_python_truncates_at_first_match() {
    for (golden, fixture, queries, jo) in [
        ("gz_first_match.txt", "000000.gz", "Running on machine", false),
        ("gz_first_match_json.txt", "000000.gz", "Running on machine", true),
        ("zip_first_match.txt", "000000.zip", "Running on machine", false),
        ("utf8_torture.txt", "UTF-8-Test.txt", "the", false),
    ] {
        let ours = run_search(fixture, queries, false, None, "", jo);
        let golden = golden_content(golden);
        assert!(
            ours.starts_with(&golden),
            "python output should be a prefix of ours for {fixture}"
        );
    }
}
```

And the shared helper — `tests/support/mod.rs` (a subdirectory module, NOT `tests/support.rs`, which cargo would compile as its own test crate):

```rust
use cloudgrepper::search::{compile_patterns, search_object, SearchConfig};

pub fn run_search(
    fixture: &str,
    query: &str,
    hide: bool,
    log_format: Option<&str>,
    log_properties: &str,
    json_output: bool,
) -> String {
    let data = std::fs::read(format!(
        "{}/../cloudgrep/tests/data/{}",
        env!("CARGO_MANIFEST_DIR"),
        fixture
    ))
    .unwrap();
    let cfg = SearchConfig {
        patterns: compile_patterns(&[query.to_string()]).unwrap(),
        hide_filenames: hide,
        json_output,
        log_format: log_format.map(String::from),
        log_properties: if log_properties.is_empty() {
            vec![]
        } else {
            vec![log_properties.to_string()]
        },
        account_name: None,
    };
    let mut buf = Vec::new();
    search_object(&cfg, fixture, &data, &mut buf);
    String::from_utf8(buf).unwrap()
}

pub fn golden_content(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/golden/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    ))
    .unwrap()
}
```

**Integration tests need the library target.** Add to `Cargo.toml`:

```toml
[lib]
name = "cloudgrepper"
path = "src/lib.rs"

[[bin]]
name = "cloudgrepper"
path = "src/main.rs"
```

Create `src/lib.rs` re-exporting the modules (`pub mod cli; pub mod decompress; pub mod filters; pub mod logparse; pub mod output; pub mod pyjson; pub mod search;`) and slim `src/main.rs` down to `use cloudgrepper::...` (drop its `mod` declarations, keep `fn main`).

- [ ] **Step 7: Run all tests**

Run: `cargo test`
Expected: PASS. If an exact-equality golden fails, diff byte-by-byte (`assert_eq!` prints both) and fix the Rust side — the golden file is the oracle, never edit it by hand.

- [ ] **Step 8: Commit** (golden files are committed — they are test assets)

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A && git commit -m "feat: search engine with golden-output tests against Python oracle"
```

---

### Task 9: providers — ObjectStore trait + S3

**Files:**
- Create: `src/providers/mod.rs`, `src/providers/s3.rs`
- Modify: `src/lib.rs` (add `pub mod providers;`), `Cargo.toml` (add AWS SDK deps)

**Interfaces:**
- Produces:
  - `#[async_trait::async_trait] pub trait ObjectStore: Send + Sync { async fn list(&self, prefix: &str, filters: &crate::filters::Filters) -> anyhow::Result<Vec<crate::filters::ObjectMeta>>; async fn fetch(&self, key: &str) -> anyhow::Result<bytes::Bytes>; fn display_url(&self, key: &str) -> String; }`
  - `pub struct S3Provider` with `pub async fn new(bucket: String, profile: Option<String>) -> anyhow::Result<S3Provider>` and `pub async fn log_region_warning(&self)` (Python warns `Bucket region: {region}. (Search from the same region to avoid egress charges.)`).
- Consumed by: runner.rs (via `Arc<dyn ObjectStore>`), tests/emulator.rs.

**Endpoint override:** the AWS SDK natively honors `AWS_ENDPOINT_URL`. When that env var is set (emulators), enable `force_path_style(true)` — MinIO/LocalStack require path-style addressing.

- [ ] **Step 1: Add dependencies** to `Cargo.toml`:

```toml
aws-config = { version = "1", features = ["behavior-version-latest"] }
aws-sdk-s3 = "1"
```

- [ ] **Step 2: Write failing test** (in `src/providers/s3.rs`; network-free — real coverage lands in Task 11's emulator tests)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn display_url_is_s3_scheme() {
        let p = S3Provider::new("mybucket".into(), None).await.unwrap();
        assert_eq!(p.display_url("a/b.log"), "s3://mybucket/a/b.log");
    }
}
```

Run: `cargo test providers 2>&1 | tail -5` — expected: compile error.

- [ ] **Step 3: Implement** — `src/providers/mod.rs`:

```rust
//! Cloud storage providers behind one trait: list object metadata
//! (filtered) and fetch object bytes.

pub mod s3;

use crate::filters::{Filters, ObjectMeta};

#[async_trait::async_trait]
pub trait ObjectStore: Send + Sync {
    async fn list(&self, prefix: &str, filters: &Filters) -> anyhow::Result<Vec<ObjectMeta>>;
    async fn fetch(&self, key: &str) -> anyhow::Result<bytes::Bytes>;
    fn display_url(&self, key: &str) -> String;
}
```

`src/providers/s3.rs`:

```rust
use crate::filters::{Filters, ObjectMeta};
use chrono::{DateTime, Utc};
use tracing::warn;

pub struct S3Provider {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl S3Provider {
    pub async fn new(bucket: String, profile: Option<String>) -> anyhow::Result<Self> {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(p) = profile {
            loader = loader.profile_name(p);
        }
        let shared = loader.load().await;
        let mut builder = aws_sdk_s3::config::Builder::from(&shared);
        if std::env::var("AWS_ENDPOINT_URL").is_ok() {
            builder = builder.force_path_style(true);
        }
        Ok(Self {
            client: aws_sdk_s3::Client::from_conf(builder.build()),
            bucket,
        })
    }

    pub async fn log_region_warning(&self) {
        let region = self
            .client
            .get_bucket_location()
            .bucket(&self.bucket)
            .send()
            .await
            .ok()
            .and_then(|r| r.location_constraint().map(|l| l.as_str().to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        warn!("Bucket region: {region}. (Search from the same region to avoid egress charges.)");
    }
}

#[async_trait::async_trait]
impl super::ObjectStore for S3Provider {
    async fn list(&self, prefix: &str, filters: &Filters) -> anyhow::Result<Vec<ObjectMeta>> {
        use futures::StreamExt;
        let mut out = Vec::new();
        let mut pages = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .into_paginator()
            .page_size(1000)
            .send();
        while let Some(page) = pages.next().await {
            for obj in page?.contents() {
                let meta = ObjectMeta {
                    key: obj.key().unwrap_or_default().to_string(),
                    size: obj.size().unwrap_or(0),
                    last_modified: obj.last_modified().and_then(|dt| {
                        DateTime::<Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
                    }),
                };
                if filters.matches(&meta) {
                    out.push(meta);
                }
            }
        }
        Ok(out)
    }

    async fn fetch(&self, key: &str) -> anyhow::Result<bytes::Bytes> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?;
        Ok(resp.body.collect().await?.into_bytes())
    }

    fn display_url(&self, key: &str) -> String {
        format!("s3://{}/{}", self.bucket, key)
    }
}
```

Add `pub mod providers;` to `src/lib.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test providers`
Expected: PASS. (`S3Provider::new` with no credentials succeeds — credentials are only resolved on first request.)

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A && git commit -m "feat: ObjectStore trait and S3 provider"
```

---

### Task 10: runner + main — end-to-end wiring

**Files:**
- Create: `src/runner.rs`, `tests/cli_behavior.rs`
- Modify: `src/lib.rs` (add `pub mod runner;`), `src/main.rs` (full rewrite below)

**Interfaces:**
- Produces:
  - `pub fn resolve_log_format(log_type: Option<&str>, log_format: Option<String>, log_properties: Vec<String>) -> Result<(Option<String>, Vec<String>), String>` — the `-lt` preset table; `Err(bad_value)` for unknown types.
  - `pub async fn run(cli: crate::cli::Cli) -> anyhow::Result<()>` — full orchestration. Returns `Ok(())` for Python's "log an error, exit 0" paths (no query, invalid log_type); returns `Err` only for genuinely fatal issues (bad regex, bad date) which main maps to exit 1 — matching Python's uncaught-traceback exits.
  - `pub const DEFAULT_WORKERS: usize = 10;`
- Consumes: everything produced by Tasks 2–9.

**Python behavior being ported (from `cloudgrep.py::search` + `__main__.py::main`):**
- Query resolution: `-q` wins over `-v`; neither → `logging.error("No query provided. Exiting.")`, exit 0.
- `-lt` values are lower-cased; `cloudtrail` → json/`Records`, `azure` → json/`data`, `waf` → jsonl/none; anything else → `Invalid log_type: {value}`, exit 0. Explicit `-lf`/`-lp` are only consulted when `-lt` is absent (Python overwrites them when log_type is set).
- S3 block logs the region warning, then `Searching {n} files in {bucket} for {queries}...` where `{queries}` renders as a Python list (`['a', 'b']` — use `pyjson::python_repr` on the array).
- Azure/GCS blocks log the same "Searching..." line at info level.
- Providers run sequentially (S3, then Azure, then GCS), each with its own bounded-concurrency download+search stream.

- [ ] **Step 1: Write failing tests**

Unit tests in `src/runner.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_type_presets() {
        assert_eq!(
            resolve_log_format(Some("cloudtrail"), None, vec![]),
            Ok((Some("json".into()), vec!["Records".into()]))
        );
        assert_eq!(
            resolve_log_format(Some("CloudTrail"), None, vec![]), // case-insensitive
            Ok((Some("json".into()), vec!["Records".into()]))
        );
        assert_eq!(
            resolve_log_format(Some("azure"), None, vec![]),
            Ok((Some("json".into()), vec!["data".into()]))
        );
        assert_eq!(
            resolve_log_format(Some("waf"), None, vec![]),
            Ok((Some("jsonl".into()), vec![]))
        );
        assert_eq!(
            resolve_log_format(Some("nope"), None, vec![]),
            Err("nope".to_string())
        );
        // no log_type: custom format/properties pass through
        assert_eq!(
            resolve_log_format(None, Some("json".into()), vec!["Records".into()]),
            Ok((Some("json".into()), vec!["Records".into()]))
        );
    }
}
```

Binary-level tests — `tests/cli_behavior.rs` (no network: all three cases exit before provider work):

```rust
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cloudgrepper"))
}

#[test]
fn no_args_prints_help_to_stderr_and_exits_1() {
    // Port of test_main_no_args_shows_help
    let out = bin().output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.to_lowercase().contains("usage"));
}

#[test]
fn invalid_log_type_logs_error_and_exits_0() {
    let out = bin().args(["-q", "x", "-lt", "bogus"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Invalid log_type: bogus"));
}

#[test]
fn no_query_logs_error_and_exits_0() {
    let out = bin().args(["-b", "some-bucket"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("No query provided. Exiting."));
}

#[test]
fn bad_regex_exits_nonzero() {
    let out = bin().args(["-q", "(unclosed", "-lt", "cloudtrail"]).output().unwrap();
    assert_ne!(out.status.code(), Some(0));
}
```

Run: `cargo test runner cli_behavior 2>&1 | tail -5` — expected: compile error.

- [ ] **Step 2: Implement runner** — `src/runner.rs`:

```rust
//! Orchestration: port of cloudgrep.py::search plus the download/search
//! fan-out from cloud.py, using a bounded-concurrency stream instead of
//! a thread pool.

use crate::cli::{load_query_file, parse_comma_list, Cli};
use crate::filters::{parse_date, Filters};
use crate::providers::{s3::S3Provider, ObjectStore};
use crate::pyjson;
use crate::search::{compile_patterns, search_object, SearchConfig};
use futures::StreamExt;
use serde_json::Value;
use std::io::Write;
use std::sync::Arc;
use tracing::{error, info, warn};

pub const DEFAULT_WORKERS: usize = 10;

pub fn resolve_log_format(
    log_type: Option<&str>,
    log_format: Option<String>,
    log_properties: Vec<String>,
) -> Result<(Option<String>, Vec<String>), String> {
    match log_type.map(|s| s.to_lowercase()).as_deref() {
        Some("cloudtrail") => Ok((Some("json".into()), vec!["Records".into()])),
        Some("azure") => Ok((Some("json".into()), vec!["data".into()])),
        Some("waf") => Ok((Some("jsonl".into()), vec![])),
        Some(other) => Err(other.to_string()),
        None => Ok((log_format, log_properties)),
    }
}

fn queries_display(queries: &[String]) -> String {
    let arr = Value::Array(queries.iter().cloned().map(Value::String).collect());
    pyjson::python_repr(&arr)
}

pub async fn run(cli: Cli) -> anyhow::Result<()> {
    // Query resolution (query beats file, like Python)
    let mut queries = cli.query.as_deref().map(parse_comma_list).unwrap_or_default();
    if queries.is_empty() {
        if let Some(file) = &cli.file {
            queries = load_query_file(file)?;
        }
    }
    if cli.yara.is_none() && queries.is_empty() {
        error!("No query provided. Exiting.");
        return Ok(());
    }

    if cli.yara.is_some() {
        // Wired in Task 14 (yara-x). Until then this is an explicit,
        // honest failure — not silent wrong behavior.
        error!("Yara scanning not yet implemented (Task 14). Exiting.");
        return Ok(());
    }

    let log_properties = cli.log_properties.as_deref().map(parse_comma_list).unwrap_or_default();
    let (log_format, log_properties) =
        match resolve_log_format(cli.log_type.as_deref(), cli.log_format.clone(), log_properties) {
            Ok(pair) => pair,
            Err(bad) => {
                error!("Invalid log_type: {bad}");
                return Ok(());
            }
        };

    let from_date = cli.start_date.as_deref().map(parse_date).transpose()?;
    let to_date = cli.end_date.as_deref().map(parse_date).transpose()?;

    let cfg = Arc::new(SearchConfig {
        patterns: compile_patterns(&queries)?,
        hide_filenames: cli.hide_filenames,
        json_output: cli.json_output,
        log_format,
        log_properties,
        account_name: cli.account_name.clone(),
    });

    let filters = Filters {
        key_contains: cli.filename.clone(),
        from_date,
        to_date,
        max_size: cli.file_size,
        check_size: true,
    };

    if let Some(bucket) = &cli.bucket {
        let provider = S3Provider::new(bucket.clone(), cli.profile.clone()).await?;
        provider.log_region_warning().await;
        let keys = provider.list(&cli.prefix, &filters).await?;
        warn!(
            "Searching {} files in {} for {}...",
            keys.len(),
            bucket,
            queries_display(&queries)
        );
        search_provider(Arc::new(provider), keys, cfg.clone(), DEFAULT_WORKERS).await;
    }

    // Azure (Task 12) and GCS (Task 13) blocks land here, mirroring the
    // S3 block with their own providers and info-level "Searching" logs.

    Ok(())
}

pub async fn search_provider(
    store: Arc<dyn ObjectStore>,
    keys: Vec<crate::filters::ObjectMeta>,
    cfg: Arc<SearchConfig>,
    workers: usize,
) -> usize {
    futures::stream::iter(keys.into_iter().map(|meta| {
        let store = store.clone();
        let cfg = cfg.clone();
        async move {
            info!("Downloading {}", store.display_url(&meta.key));
            match store.fetch(&meta.key).await {
                Ok(data) => {
                    let mut buf = Vec::new();
                    let matched = search_object(&cfg, &meta.key, &data, &mut buf);
                    let stdout = std::io::stdout();
                    let mut lock = stdout.lock();
                    let _ = lock.write_all(&buf);
                    usize::from(matched)
                }
                Err(e) => {
                    error!("Error processing {}: {e:#}", meta.key);
                    0
                }
            }
        }
    }))
    .buffer_unordered(workers)
    .fold(0, |acc, n| async move { acc + n })
    .await
}
```

- [ ] **Step 3: Rewrite main** — `src/main.rs`:

```rust
use clap::{CommandFactory, Parser};
use cloudgrepper::cli::{normalize_args, Cli};

fn init_logging(debug: bool) {
    // Python: WARNING by default, DEBUG with -d, all to stderr
    let level = if debug { "debug" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 {
        // Python: no args -> help on stderr, exit 1
        eprintln!("{}", Cli::command().render_help());
        std::process::exit(1);
    }
    let cli = Cli::parse_from(normalize_args(args));
    init_logging(cli.debug);
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    if let Err(e) = rt.block_on(cloudgrepper::runner::run(cli)) {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}
```

Add `pub mod runner;` to `src/lib.rs`.

- [ ] **Step 4: Run all tests**

Run: `cargo test`
Expected: PASS (runner unit test, 4 binary tests, and everything from Tasks 2–9).

- [ ] **Step 5: Manual smoke test**

```bash
cargo run -- -q test 2>&1 | head -3        # runs, no bucket -> no provider work, exit 0
cargo run -- 2>&1 | head -3; echo "exit=$?" # help + exit 1
```

- [ ] **Step 6: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A && git commit -m "feat: runner orchestration and main wiring (S3 end-to-end)"
```

---

### Task 11: S3 emulator integration tests (MinIO)

**Files:**
- Create: `docker/docker-compose.yml`, `tests/emulator.rs`, `scripts/compare_python.sh`

**Interfaces:**
- Consumes: the compiled binary (`CARGO_BIN_EXE_cloudgrepper`), `S3Provider` seeding via the SDK.
- Produces: env-gated end-to-end proof that list→filter→fetch→search→output works against a real S3 API.

**Gating:** every test in `tests/emulator.rs` starts with
`if std::env::var("CLOUDGREPPER_EMULATOR").is_err() { eprintln!("skipped: set CLOUDGREPPER_EMULATOR=1"); return; }`
so plain `cargo test` needs no Docker.

- [ ] **Step 1: docker-compose** — `docker/docker-compose.yml` (Azurite and fake-gcs are used by Tasks 12–13; define all three now):

```yaml
services:
  minio:
    image: minio/minio
    command: server /data
    ports: ["9000:9000"]
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
  azurite:
    image: mcr.microsoft.com/azure-storage/azurite
    ports: ["10000:10000"]
  fake-gcs:
    image: fsouza/fake-gcs-server
    command: ["-scheme", "http", "-port", "4443", "-public-host", "localhost:4443"]
    ports: ["4443:4443"]
```

Run: `docker compose -f docker/docker-compose.yml up -d` and verify `docker compose -f docker/docker-compose.yml ps` shows all three running.

- [ ] **Step 2: Write the integration test** — `tests/emulator.rs`:

```rust
//! End-to-end tests against local emulators. Gated: CLOUDGREPPER_EMULATOR=1.
//! Start emulators with: docker compose -f docker/docker-compose.yml up -d

use std::process::Command;

const MINIO: &str = "http://127.0.0.1:9000";

fn s3_env(cmd: &mut Command) -> &mut Command {
    cmd.env("AWS_ACCESS_KEY_ID", "minioadmin")
        .env("AWS_SECRET_ACCESS_KEY", "minioadmin")
        .env("AWS_ENDPOINT_URL", MINIO)
        .env("AWS_REGION", "us-east-1")
        .env("AWS_EC2_METADATA_DISABLED", "true")
}

async fn s3_client() -> aws_sdk_s3::Client {
    std::env::set_var("AWS_ACCESS_KEY_ID", "minioadmin");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "minioadmin");
    std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
    let conf = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .endpoint_url(MINIO)
        .region(aws_config::Region::new("us-east-1"))
        .load()
        .await;
    let s3conf = aws_sdk_s3::config::Builder::from(&conf)
        .force_path_style(true)
        .build();
    aws_sdk_s3::Client::from_conf(s3conf)
}

fn fixture_path(name: &str) -> String {
    format!("{}/../cloudgrep/tests/data/{}", env!("CARGO_MANIFEST_DIR"), name)
}

async fn seed(client: &aws_sdk_s3::Client, bucket: &str, objects: &[(&str, Vec<u8>)]) {
    let _ = client.create_bucket().bucket(bucket).send().await; // idempotent
    for (key, body) in objects {
        client
            .put_object()
            .bucket(bucket)
            .key(*key)
            .body(aws_sdk_s3::primitives::ByteStream::from(body.clone()))
            .send()
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn s3_end_to_end_someline() {
    // Port of test_e2e: three fixture logs, all matching "SomeLine"
    if std::env::var("CLOUDGREPPER_EMULATOR").is_err() {
        eprintln!("skipped: set CLOUDGREPPER_EMULATOR=1");
        return;
    }
    let client = s3_client().await;
    let files = ["14_3.log", "35010_7.log", "apache_access.log"];
    let objects: Vec<(&str, Vec<u8>)> = files
        .iter()
        .map(|f| (*f, std::fs::read(fixture_path(f)).unwrap()))
        .collect();
    seed(&client, "e2e-bucket", &objects).await;

    let out = s3_env(&mut Command::new(env!("CARGO_BIN_EXE_cloudgrepper")))
        .args(["-b", "e2e-bucket", "-q", "SomeLine"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for f in files {
        assert!(stdout.contains(f), "expected a match line from {f}");
    }
}

#[tokio::test]
async fn s3_filters_and_gz_decompression() {
    // Port of test_list_files_returns_pre_filtered_files + gz handling
    if std::env::var("CLOUDGREPPER_EMULATOR").is_err() {
        eprintln!("skipped: set CLOUDGREPPER_EMULATOR=1");
        return;
    }
    let client = s3_client().await;
    seed(
        &client,
        "filter-bucket",
        &[
            ("log_file1.txt", b"dummy content".to_vec()),
            ("log_file2.txt", b"dummy content".to_vec()),
            ("not_a_thing.txt", b"dummy content".to_vec()),
            ("log_empty.txt", Vec::new()),
            ("archive.log.gz", std::fs::read(fixture_path("000000.gz")).unwrap()),
        ],
    )
    .await;

    // -f log: only log_file1/log_file2 survive filtering (empty file dropped)
    let out = s3_env(&mut Command::new(env!("CARGO_BIN_EXE_cloudgrepper")))
        .args(["-b", "filter-bucket", "-q", "dummy content", "-f", "log"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("log_file1.txt") && stdout.contains("log_file2.txt"));
    assert!(!stdout.contains("not_a_thing.txt"));

    // gz object decompressed transparently (Python 1.0.5 needs -og; we don't)
    let out = s3_env(&mut Command::new(env!("CARGO_BIN_EXE_cloudgrepper")))
        .args(["-b", "filter-bucket", "-q", "Running on machine", "-f", ".gz"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("Running on machine"));
}
```

Note: `aws_config::Region` — if the import path fails, use `aws_config::meta::region::RegionProviderChain` or `aws_sdk_s3::config::Region::new("us-east-1")`; check docs.rs for the pinned version.

- [ ] **Step 3: Run**

```bash
docker compose -f docker/docker-compose.yml up -d
CLOUDGREPPER_EMULATOR=1 cargo test --test emulator -- --nocapture
```
Expected: both tests PASS. Without the env var, `cargo test` still passes (skips).

- [ ] **Step 4: Python comparison script** — `scripts/compare_python.sh`:

```bash
#!/usr/bin/env bash
# Manual aid: diff cloudgrepper vs python cloudgrep against MinIO.
# Requires: pip install boto3 (>=1.28 for AWS_ENDPOINT_URL support).
# Caveats: Python 1.0.5 prints only the first matching line per file and
# does not decompress .gz from S3 without -og, so restrict comparisons to
# plain single-match objects for exact diffs.
set -euo pipefail
BUCKET=${1:?usage: compare_python.sh <bucket> <query>}
QUERY=${2:?usage: compare_python.sh <bucket> <query>}
export AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin
export AWS_ENDPOINT_URL=http://127.0.0.1:9000 AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
HERE="$(cd "$(dirname "$0")" && pwd)"
cargo run --quiet --manifest-path "$HERE/../Cargo.toml" -- -b "$BUCKET" -q "$QUERY" | sort > /tmp/cloudgrepper.out
(cd "$HERE/../../cloudgrep" && python3 -m cloudgrep -b "$BUCKET" -q "$QUERY") | sort > /tmp/cloudgrep.out
diff /tmp/cloudgrep.out /tmp/cloudgrepper.out && echo "OUTPUT MATCHES"
```

`chmod +x scripts/compare_python.sh`. Run it once against `e2e-bucket`/`SomeLine` and record the result in the commit message (a diff caused by the two documented Python regressions is expected and fine — say which).

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A && git commit -m "test: S3 end-to-end against MinIO emulator + python comparison script"
```

---

### Task 12: Azure provider

**Files:**
- Create: `src/providers/azure.rs`
- Modify: `src/providers/mod.rs` (add `pub mod azure;`), `src/runner.rs` (Azure block), `Cargo.toml`, `tests/emulator.rs` (Azurite test)

**Interfaces:**
- Produces: `pub struct AzureProvider` with `pub fn new(account_name: &str, container_name: &str) -> anyhow::Result<AzureProvider>`, implementing `ObjectStore`. `display_url` → `azure://{account}/{container}/{key}`.
- Consumes: `ObjectStore`, `Filters` (with `check_size: true` — Python's `filter_object_azure` checks size).

**Auth:** Python uses `DefaultAzureCredential`. Port: `AZURE_STORAGE_USE_EMULATOR=1` → Azurite's well-known dev-store account (test-only branch); otherwise token credential from `azure_identity` (covers `az login`, env vars, managed identity).

- [ ] **Step 1: Add dependencies** to `Cargo.toml`:

```toml
azure_core = "0.21"
azure_identity = "0.21"
azure_storage = "0.21"
azure_storage_blobs = "0.21"
time = "0.3"
```

(These are the final releases of the unofficial-but-complete Azure SDK line; pin exactly. If any snippet below mismatches, consult docs.rs/azure_storage_blobs/0.21 — do not upgrade to the 2025 `azure_storage_blob` rewrite within this task.)

- [ ] **Step 2: Implement** — `src/providers/azure.rs`:

```rust
use crate::filters::{Filters, ObjectMeta};
use azure_storage::prelude::*;
use azure_storage_blobs::prelude::*;
use chrono::{DateTime, Utc};
use futures::StreamExt;

pub struct AzureProvider {
    container: ContainerClient,
    account: String,
    container_name: String,
}

impl AzureProvider {
    pub fn new(account_name: &str, container_name: &str) -> anyhow::Result<Self> {
        let container = if std::env::var("AZURE_STORAGE_USE_EMULATOR").is_ok() {
            // Azurite well-known devstore credentials (test-only path)
            ClientBuilder::emulator().container_client(container_name)
        } else {
            let credential = azure_identity::create_credential()?;
            let storage_credentials = StorageCredentials::token_credential(credential);
            BlobServiceClient::new(account_name, storage_credentials)
                .container_client(container_name)
        };
        Ok(Self {
            container,
            account: account_name.to_string(),
            container_name: container_name.to_string(),
        })
    }
}

fn to_chrono(t: time::OffsetDateTime) -> Option<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(t.unix_timestamp(), t.nanosecond())
}

#[async_trait::async_trait]
impl super::ObjectStore for AzureProvider {
    async fn list(&self, prefix: &str, filters: &Filters) -> anyhow::Result<Vec<ObjectMeta>> {
        let mut out = Vec::new();
        let mut pages = self
            .container
            .list_blobs()
            .prefix(prefix.to_string())
            .into_stream();
        while let Some(page) = pages.next().await {
            for blob in page?.blobs.blobs() {
                let meta = ObjectMeta {
                    key: blob.name.clone(),
                    size: blob.properties.content_length as i64,
                    last_modified: to_chrono(blob.properties.last_modified),
                };
                if filters.matches(&meta) {
                    out.push(meta);
                }
            }
        }
        Ok(out)
    }

    async fn fetch(&self, key: &str) -> anyhow::Result<bytes::Bytes> {
        let content = self.container.blob_client(key).get_content().await?;
        Ok(bytes::Bytes::from(content))
    }

    fn display_url(&self, key: &str) -> String {
        format!("azure://{}/{}/{}", self.account, self.container_name, key)
    }
}
```

- [ ] **Step 3: Wire into runner** — in `src/runner.rs`, replace the `// Azure (Task 12) and GCS (Task 13) blocks land here...` comment with:

```rust
    if let (Some(account_name), Some(container_name)) = (&cli.account_name, &cli.container_name) {
        let provider = crate::providers::azure::AzureProvider::new(account_name, container_name)?;
        let keys = provider.list(&cli.prefix, &filters).await?;
        info!(
            "Searching {} files in {}/{} for {}...",
            keys.len(),
            account_name,
            container_name,
            queries_display(&queries)
        );
        search_provider(Arc::new(provider), keys, cfg.clone(), DEFAULT_WORKERS).await;
    }

    // GCS block (Task 13) lands here.
```

- [ ] **Step 4: Azurite integration test** — append to `tests/emulator.rs`:

```rust
#[tokio::test]
async fn azure_end_to_end() {
    // Port of test_azure_search_mocked, against real Azurite
    if std::env::var("CLOUDGREPPER_EMULATOR").is_err() {
        eprintln!("skipped: set CLOUDGREPPER_EMULATOR=1");
        return;
    }
    use azure_storage_blobs::prelude::*;
    let container = ClientBuilder::emulator().container_client("azuretest");
    let _ = container.create().await; // idempotent
    container
        .blob_client("testblob.log")
        .put_block_blob("Some Azure log entry that mentions azure target")
        .await
        .unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_cloudgrepper"))
        .env("AZURE_STORAGE_USE_EMULATOR", "1")
        .args(["-an", "devstoreaccount1", "-cn", "azuretest", "-q", "azure target"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("azure target"));
    assert!(stdout.contains("testblob.log"));
}
```

Add the azure crates to `[dev-dependencies]` only if not already in `[dependencies]` (they are — no change needed).

- [ ] **Step 5: Run**

```bash
cargo test                                            # unit suite still green
CLOUDGREPPER_EMULATOR=1 cargo test --test emulator azure -- --nocapture
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A && git commit -m "feat: Azure Blob Storage provider with Azurite integration test"
```

---

### Task 13: GCS provider

**Files:**
- Create: `src/providers/gcs.rs`
- Modify: `src/providers/mod.rs` (add `pub mod gcs;`), `src/runner.rs` (GCS block), `Cargo.toml`, `tests/emulator.rs`

**Interfaces:**
- Produces: `pub struct GcsProvider` with `pub async fn new(bucket: &str) -> anyhow::Result<GcsProvider>`, implementing `ObjectStore`. `display_url` → `gs://{bucket}/{key}`.
- **Quirk:** the GCS filter uses `check_size: false` (Python's `filter_object_google` never checks size — `--file_size` does not apply to GCS).

- [ ] **Step 1: Add dependency** to `Cargo.toml`:

```toml
google-cloud-storage = "0.24"
```

(The yoshidan crate. If crates.io shows it renamed to `gcloud-storage`, pin the last `google-cloud-storage` release instead of migrating mid-task; note it in the commit message.)

- [ ] **Step 2: Implement** — `src/providers/gcs.rs`:

```rust
use crate::filters::{Filters, ObjectMeta};
use chrono::{DateTime, Utc};
use google_cloud_storage::client::{Client, ClientConfig};
use google_cloud_storage::http::objects::download::Range;
use google_cloud_storage::http::objects::get::GetObjectRequest;
use google_cloud_storage::http::objects::list::ListObjectsRequest;

pub struct GcsProvider {
    client: Client,
    bucket: String,
}

impl GcsProvider {
    pub async fn new(bucket: &str) -> anyhow::Result<Self> {
        // STORAGE_EMULATOR_HOST (fake-gcs-server) -> anonymous + endpoint
        let config = if let Ok(host) = std::env::var("STORAGE_EMULATOR_HOST") {
            let mut c = ClientConfig::default().anonymous();
            c.storage_endpoint = host;
            c
        } else {
            // honors GOOGLE_APPLICATION_CREDENTIALS / gcloud ADC
            ClientConfig::default().with_auth().await?
        };
        Ok(Self {
            client: Client::new(config),
            bucket: bucket.to_string(),
        })
    }
}

#[async_trait::async_trait]
impl super::ObjectStore for GcsProvider {
    async fn list(&self, prefix: &str, filters: &Filters) -> anyhow::Result<Vec<ObjectMeta>> {
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let resp = self
                .client
                .list_objects(&ListObjectsRequest {
                    bucket: self.bucket.clone(),
                    prefix: Some(prefix.to_string()),
                    page_token: page_token.clone(),
                    ..Default::default()
                })
                .await?;
            for obj in resp.items.unwrap_or_default() {
                let meta = ObjectMeta {
                    key: obj.name.clone(),
                    size: obj.size,
                    last_modified: obj.updated.and_then(|t| {
                        DateTime::<Utc>::from_timestamp(t.unix_timestamp(), t.nanosecond())
                    }),
                };
                if filters.matches(&meta) {
                    out.push(meta);
                }
            }
            page_token = resp.next_page_token;
            if page_token.is_none() {
                break;
            }
        }
        Ok(out)
    }

    async fn fetch(&self, key: &str) -> anyhow::Result<bytes::Bytes> {
        let data = self
            .client
            .download_object(
                &GetObjectRequest {
                    bucket: self.bucket.clone(),
                    object: key.to_string(),
                    ..Default::default()
                },
                &Range::default(),
            )
            .await?;
        Ok(bytes::Bytes::from(data))
    }

    fn display_url(&self, key: &str) -> String {
        format!("gs://{}/{}", self.bucket, key)
    }
}
```

- [ ] **Step 3: Wire into runner** — replace the `// GCS block (Task 13) lands here.` comment in `src/runner.rs` with:

```rust
    if let Some(google_bucket) = &cli.google_bucket {
        let provider = crate::providers::gcs::GcsProvider::new(google_bucket).await?;
        // Python's filter_object_google never checks size
        let gcs_filters = Filters { check_size: false, ..filters.clone() };
        let keys = provider.list(&cli.prefix, &gcs_filters).await?;
        info!(
            "Searching {} files in {} for {}...",
            keys.len(),
            google_bucket,
            queries_display(&queries)
        );
        search_provider(Arc::new(provider), keys, cfg.clone(), DEFAULT_WORKERS).await;
    }
```

- [ ] **Step 4: fake-gcs integration test** — append to `tests/emulator.rs`:

```rust
#[tokio::test]
async fn gcs_end_to_end() {
    // Port of test_google_search_mocked, against fake-gcs-server
    if std::env::var("CLOUDGREPPER_EMULATOR").is_err() {
        eprintln!("skipped: set CLOUDGREPPER_EMULATOR=1");
        return;
    }
    // Seed via fake-gcs JSON API (bucket create + object upload)
    let http = reqwest::Client::new();
    let _ = http
        .post("http://localhost:4443/storage/v1/b?project=test-project")
        .json(&serde_json::json!({"name": "gcstest"}))
        .send()
        .await
        .unwrap();
    http.post("http://localhost:4443/upload/storage/v1/b/gcstest/o?uploadType=media&name=test_gcs_file.log")
        .body("This is some fake file: google target")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_cloudgrepper"))
        .env("STORAGE_EMULATOR_HOST", "http://localhost:4443")
        .args(["-gb", "gcstest", "-q", "google target"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("google target"));
    assert!(stdout.contains("test_gcs_file.log"));
}
```

Add to `[dev-dependencies]`:

```toml
reqwest = { version = "0.12", features = ["json"] }
```

- [ ] **Step 5: Run**

```bash
cargo test
CLOUDGREPPER_EMULATOR=1 cargo test --test emulator gcs -- --nocapture
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A && git commit -m "feat: GCS provider with fake-gcs-server integration test"
```

---

### Task 14: Yara scanning (yara-x)

**Files:**
- Create: `src/yara.rs`
- Modify: `src/lib.rs` (add `pub mod yara;`), `src/runner.rs` (replace the yara bail branch), `Cargo.toml`

**Interfaces:**
- Produces:
  - `pub fn compile_rules(path: &str) -> anyhow::Result<yara_x::Rules>`
  - `pub fn scan_object(rules: &yara_x::Rules, key_name: &str, data: &[u8], hide_filenames: bool, json_output: bool, out: &mut impl std::io::Write) -> bool` — emits one `Record::Yara` per matching rule; `match_strings` is the list of matched pattern identifiers (`$a` style). Returns "any rule matched".
- Consumes: `output::{Record, print_match}`.

**Python behavior:** when `-y` is given, yara scanning **replaces** regex search entirely (`search_file` short-circuits). Output divergence is already documented in output.rs Task 6 (Python's `json.dumps` TypeError fallback is replicated; our `match_strings` holds identifiers of matched patterns rather than libyara `StringMatch` reprs — same `[$a]` rendering for the common case).

- [ ] **Step 1: Add dependency**

```toml
yara-x = "1"
```

(Pure Rust — no libyara install needed. If the current major is 2, pin `"1"` anyway for this task; check docs.rs for `Scanner`/`Compiler` API drift.)

- [ ] **Step 2: Write failing tests** (in `src/yara.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str =
        r#"rule rule_name {strings: $a = "get" nocase wide ascii condition: $a}"#;

    fn compile(src: &str) -> yara_x::Rules {
        yara_x::compile(src).unwrap()
    }

    #[test]
    fn yara_scan_matches_and_formats_like_python() {
        // Port of test_yara: hide_filenames=True, json_output=True
        let rules = compile(RULE);
        let mut buf = Vec::new();
        let matched = scan_object(&rules, "key_name", b"one\nget stuff\nthree", true, true, &mut buf);
        assert!(matched);
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "{'match_rule': 'rule_name', 'match_strings': [$a]}\n"
        );
    }

    #[test]
    fn yara_no_match_returns_false_no_output() {
        let rules = compile(RULE);
        let mut buf = Vec::new();
        assert!(!scan_object(&rules, "k", b"nothing here", false, false, &mut buf));
        assert!(buf.is_empty());
    }

    #[test]
    fn fixture_rule_matches_apache_log() {
        // yara.rule fixture: rule get { $get = "GET" nocase wide ascii }
        let path = format!(
            "{}/../cloudgrep/tests/data/yara.rule",
            env!("CARGO_MANIFEST_DIR")
        );
        let rules = compile_rules(&path).unwrap();
        let data = std::fs::read(format!(
            "{}/../cloudgrep/tests/data/apache_access.log",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let mut buf = Vec::new();
        assert!(scan_object(&rules, "apache_access.log", &data, false, false, &mut buf));
        assert!(String::from_utf8(buf).unwrap().contains("get: [$get]"));
    }
}
```

Run: `cargo test yara 2>&1 | tail -5` — expected: compile error.

- [ ] **Step 3: Implement**

```rust
//! Yara scanning via yara-x (pure-Rust YARA). Replaces regex search when
//! -y is given, matching search.py's short-circuit.

use crate::output::{print_match, Record};
use std::io::Write;

pub fn compile_rules(path: &str) -> anyhow::Result<yara_x::Rules> {
    let source = std::fs::read_to_string(path)?;
    yara_x::compile(source.as_str()).map_err(|e| anyhow::anyhow!("yara compile error: {e}"))
}

pub fn scan_object(
    rules: &yara_x::Rules,
    key_name: &str,
    data: &[u8],
    hide_filenames: bool,
    json_output: bool,
    out: &mut impl Write,
) -> bool {
    let mut scanner = yara_x::Scanner::new(rules);
    let results = match scanner.scan(data) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Error processing {key_name}: yara scan failed: {e}");
            return false;
        }
    };
    let mut matched = false;
    for rule in results.matching_rules() {
        matched = true;
        let match_strings: Vec<String> = rule
            .patterns()
            .filter(|p| p.matches().len() > 0)
            .map(|p| p.identifier().to_string())
            .collect();
        print_match(
            &Record::Yara {
                key_name: key_name.to_string(),
                match_rule: rule.identifier().to_string(),
                match_strings,
            },
            hide_filenames,
            json_output,
            out,
        );
    }
    matched
}
```

API drift notes: in some yara-x versions `patterns()` returns an iterator whose items expose `matches()` as a slice accessor — if `.len()` isn't available use `!p.matches().is_empty()` or count the iterator; if `yara_x::compile` isn't exported, use `yara_x::Compiler::new()` + `add_source()` + `build()`.

- [ ] **Step 4: Wire into runner** — in `src/runner.rs`, replace the yara bail branch:

```rust
    let yara_rules = match &cli.yara {
        Some(path) => Some(Arc::new(crate::yara::compile_rules(path)?)),
        None => None,
    };
```

(Place this before the `queries.is_empty()` check; keep Python's ordering: query check first, then yara compile — verify against `cloudgrep.py::search` lines 91-101: query check IS first, yara compile second. Keep our `cli.yara.is_none() && queries.is_empty()` guard: Python requires a query even with yara — actually check line 94: `if not query: return` runs unconditionally, so **yara without -q also exits "No query provided"**. Replicate: drop the `cli.yara.is_none() &&` clause so a missing query always exits, and require `-q`/`-v` alongside `-y` exactly like Python.)

Then thread the rules through `search_provider` by extending its signature:

```rust
pub async fn search_provider(
    store: Arc<dyn ObjectStore>,
    keys: Vec<crate::filters::ObjectMeta>,
    cfg: Arc<SearchConfig>,
    yara_rules: Option<Arc<yara_x::Rules>>,
    workers: usize,
) -> usize
```

and inside the per-object async block:

```rust
                Ok(data) => {
                    let mut buf = Vec::new();
                    let matched = match &yara_rules {
                        Some(rules) => crate::yara::scan_object(
                            rules, &meta.key, &data, cfg.hide_filenames, cfg.json_output, &mut buf,
                        ),
                        None => search_object(&cfg, &meta.key, &data, &mut buf),
                    };
                    let stdout = std::io::stdout();
                    let mut lock = stdout.lock();
                    let _ = lock.write_all(&buf);
                    usize::from(matched)
                }
```

Update the three call sites (S3/Azure/GCS blocks) to pass `yara_rules.clone()`.

- [ ] **Step 5: Run all tests**

Run: `cargo test`
Expected: PASS (yara unit tests + all prior suites; the runner change compiles everywhere).

- [ ] **Step 6: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A && git commit -m "feat: yara scanning via yara-x"
```

---

### Task 15: Parallelism & performance pass

**Files:**
- Create: `scripts/bench.sh`
- Modify: `src/runner.rs` (worker override + spawn_blocking), `README.md` (perf numbers)

**Interfaces:**
- Produces: `pub fn workers() -> usize` — `CLOUDGREPPER_WORKERS` env override, default `DEFAULT_WORKERS` (10). CPU-bound search moves to `tokio::task::spawn_blocking` so heavy regex work doesn't stall the fetch reactor.

- [ ] **Step 1: Worker override + test** (in `src/runner.rs`)

```rust
pub fn workers() -> usize {
    std::env::var("CLOUDGREPPER_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_WORKERS)
}
```

Test (append to runner's `#[cfg(test)]`; env-var tests must not run in parallel with each other — use one test):

```rust
    #[test]
    fn workers_env_override() {
        std::env::remove_var("CLOUDGREPPER_WORKERS");
        assert_eq!(workers(), DEFAULT_WORKERS);
        std::env::set_var("CLOUDGREPPER_WORKERS", "32");
        assert_eq!(workers(), 32);
        std::env::set_var("CLOUDGREPPER_WORKERS", "zero");
        assert_eq!(workers(), DEFAULT_WORKERS);
        std::env::remove_var("CLOUDGREPPER_WORKERS");
    }
```

Replace `DEFAULT_WORKERS` with `workers()` at the three `search_provider` call sites.

- [ ] **Step 2: Move search off the reactor** — in the per-object block of `search_provider`, wrap the CPU-bound part:

```rust
                Ok(data) => {
                    let cfg = cfg.clone();
                    let yara_rules = yara_rules.clone();
                    let key = meta.key.clone();
                    let (matched, buf) = tokio::task::spawn_blocking(move || {
                        let mut buf = Vec::new();
                        let matched = match &yara_rules {
                            Some(rules) => crate::yara::scan_object(
                                rules, &key, &data, cfg.hide_filenames, cfg.json_output, &mut buf,
                            ),
                            None => search_object(&cfg, &key, &data, &mut buf),
                        };
                        (matched, buf)
                    })
                    .await
                    .unwrap_or((false, Vec::new()));
                    let stdout = std::io::stdout();
                    let mut lock = stdout.lock();
                    let _ = lock.write_all(&buf);
                    usize::from(matched)
                }
```

Run: `cargo test` — everything stays green.

- [ ] **Step 3: Benchmark script** — `scripts/bench.sh`:

```bash
#!/usr/bin/env bash
# Benchmark cloudgrepper vs python cloudgrep against MinIO with N copies
# of apache_access.log. Requires: docker compose up -d, hyperfine, boto3.
set -euo pipefail
N=${1:-200}
BUCKET=bench-bucket
export AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin
export AWS_ENDPOINT_URL=http://127.0.0.1:9000 AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
HERE="$(cd "$(dirname "$0")" && pwd)"
FIXTURE="$HERE/../../cloudgrep/tests/data/apache_access.log"

python3 - "$N" "$BUCKET" "$FIXTURE" <<'PY'
import sys, boto3
n, bucket, fixture = int(sys.argv[1]), sys.argv[2], sys.argv[3]
s3 = boto3.client("s3")
try:
    s3.create_bucket(Bucket=bucket)
except Exception:
    pass
body = open(fixture, "rb").read()
for i in range(n):
    s3.put_object(Bucket=bucket, Key=f"logs/{i}.log", Body=body)
print(f"seeded {n} objects")
PY

cargo build --release --manifest-path "$HERE/../Cargo.toml"
hyperfine --warmup 1 \
  "$HERE/../target/release/cloudgrepper -b $BUCKET -q 'GET /wp-login' -p logs/" \
  "python3 -m cloudgrep -b $BUCKET -q 'GET /wp-login' -p logs/" \
  --export-markdown /tmp/cloudgrepper_bench.md
cat /tmp/cloudgrepper_bench.md
```

`chmod +x scripts/bench.sh`. Run with MinIO up; try `CLOUDGREPPER_WORKERS` at 10/32/64 and record the best setting.

- [ ] **Step 4: Record results in README** — add a `## Performance` section with the hyperfine table, the worker-count finding, and the benchmark command. State the comparison caveat (Python 1.0.5 prints first-match-only, so it does strictly less output work).

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A && git commit -m "perf: worker tuning, spawn_blocking search, benchmark script"
```

---

### Task 16: Docs + real-cloud validation runbook

**Files:**
- Create: `scripts/real_cloud_diff.sh`
- Modify: `README.md`, `docs/superpowers/specs/2026-07-02-cloudgrepper-design.md` (divergences section, if not already present)

- [ ] **Step 1: README usage + divergences.** Extend README.md with: full flag table (all 21, copied from the spec), examples for each provider, emulator test instructions (`docker compose -f docker/docker-compose.yml up -d && CLOUDGREPPER_EMULATOR=1 cargo test --test emulator`), and a **Known divergences from Python cloudgrep 1.0.5** section:
  1. all matching lines are reported (Python stops at the first matching line per file — `any()` short-circuit regression);
  2. `.gz`/`.zip` are always detected from the object key (Python 1.0.5 requires `-og` for S3 decompression — temp-file-name regression);
  3. yara `match_strings` lists matched pattern identifiers; JSON-mode yara output replicates Python's `str(dict)` fallback;
  4. naive `--start_date`/`--end_date` values are treated as UTC (Python can crash comparing naive/aware datetimes without `-cd`);
  5. `--file_size` still doesn't apply to GCS (quirk kept, documented).

- [ ] **Step 2: real_cloud_diff.sh**

```bash
#!/usr/bin/env bash
# Milestone 9: validate cloudgrepper against python cloudgrep on a REAL
# bucket you own. Usage:
#   scripts/real_cloud_diff.sh s3 <bucket> <query> [extra flags...]
#   scripts/real_cloud_diff.sh azure <account> <container> <query> [extra...]
#   scripts/real_cloud_diff.sh gcs <bucket> <query> [extra...]
# Requires: pip install cloudgrep (or run from ../cloudgrep), cargo build --release.
set -euo pipefail
MODE=${1:?mode: s3|azure|gcs}; shift
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/../target/release/cloudgrepper"
case "$MODE" in
  s3)    ARGS=(-b "$1" -q "$2"); shift 2 ;;
  azure) ARGS=(-an "$1" -cn "$2" -q "$3"); shift 3 ;;
  gcs)   ARGS=(-gb "$1" -q "$2"); shift 2 ;;
  *) echo "unknown mode $MODE" >&2; exit 2 ;;
esac
ARGS+=("$@")
"$BIN" "${ARGS[@]}" 2>/dev/null | sort > /tmp/cloudgrepper.real.out
python3 -m cloudgrep "${ARGS[@]}" 2>/dev/null | sort > /tmp/cloudgrep.real.out
echo "--- diff (python vs rust) ---"
diff /tmp/cloudgrep.real.out /tmp/cloudgrepper.real.out && echo "OUTPUT MATCHES"
echo "Expected diffs: rust reports ALL matching lines; python only the first"
echo "per file, and skips .gz decompression without -og (see README)."
```

`chmod +x scripts/real_cloud_diff.sh`.

- [ ] **Step 3: Final full check**

```bash
cargo test
cargo fmt --check && cargo clippy --all-targets -- -D warnings
docker compose -f docker/docker-compose.yml up -d && CLOUDGREPPER_EMULATOR=1 cargo test --test emulator
```
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "docs: usage, known divergences, real-cloud validation runbook"
```

Real-cloud validation itself is a manual, user-driven phase: run `real_cloud_diff.sh` against real buckets, file any unexplained diff as a bug, and record explained diffs in the README divergences section.
