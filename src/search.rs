//! The matching engine: port of search.py::search_file / search_line /
//! search_logs operating on in-memory bytes.
//!
//! # Divergences from Python cloudgrep 1.0.5 (deliberate)
//!
//! 1. **All matching lines are reported.** Python 1.0.5's `process_lines` is
//!    `any(search_line(...) for line in lines)` — `any()` short-circuits, so
//!    Python stops after the **first matching line per file** (a regression).
//!    cloudgrepper searches every line.
//!
//! 2. **Decompression keys off the object key.** Python 1.0.5 detects `.gz`/
//!    `.zip` from the temp-file name (random, extensionless) unless `-og` is
//!    passed — i.e. S3 decompression is silently broken without `-og`.
//!    cloudgrepper always detects from the object key.

use crate::decompress::{self, FileKind};
use crate::logparse;
use crate::output::{print_match, Record};
use crate::pyjson;
use regex::Regex;
use serde_json::Value;
use std::io::Write;
use tracing::error;

#[derive(Clone)]
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
    let what = if kind == FileKind::Zip {
        "zip file"
    } else {
        "gzip file"
    };
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

pub fn search_line(cfg: &SearchConfig, key_name: &str, line: &str, out: &mut impl Write) -> bool {
    let mut found = false;
    for (raw, re) in &cfg.patterns {
        if re.is_match(line) {
            if let Some(fmt) = &cfg.log_format {
                // Two-stage: raw line must match the regex (checked above),
                // then each parsed entry's serialized form must also match.
                // `found` is only set when search_logs actually prints output.
                if search_logs(cfg, key_name, line, raw, re, fmt, out) {
                    found = true;
                }
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
                found = true;
            }
        }
    }
    found
}

/// Search parsed log entries and print matching ones.
/// Returns true if at least one entry was printed.
fn search_logs(
    cfg: &SearchConfig,
    key_name: &str,
    line: &str,
    raw_pattern: &str,
    re: &Regex,
    log_format: &str,
    out: &mut impl Write,
) -> bool {
    let Some(parsed) = logparse::parse_logs(line, log_format) else {
        return false;
    };
    if logparse::is_falsy(&parsed) {
        return false;
    }
    let mut printed = false;
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
            printed = true;
        }
    }
    printed
}

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
            patterns: compile_patterns(&patterns.iter().map(|s| s.to_string()).collect::<Vec<_>>())
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
        let (found, out) = run(
            &cfg(&["Running on machine"]),
            "000000.gz",
            &fixture("000000.gz"),
        );
        assert!(found);
        assert!(out.contains("Running on machine"));
    }

    #[test]
    fn zip_search_finds_match() {
        // Port of test_zip
        let (found, out) = run(
            &cfg(&["Running on machine"]),
            "000000.zip",
            &fixture("000000.zip"),
        );
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
        // The raw line DOES contain "héllo" (UTF-8), so the first-stage
        // regex matches. But pyjson::dumps escapes non-ASCII to \uXXXX, so
        // the entry serializes to {"msg": "héllo"}, which does NOT match
        // the pattern "héllo". search_logs returns false → found = false,
        // no output.
        // (Python 1.0.5 still sets found=True here — we differ deliberately:
        // found means "output was produced", not "raw line matched".)
        let data = b"{\"Records\": [{\"msg\": \"h\xc3\xa9llo\"}]}"; // h + UTF-8(é) + llo
        let mut c = cfg(&["h\u{00e9}llo"]);
        c.log_format = Some("json".into());
        c.log_properties = vec!["Records".into()];
        let (found, out) = run(&c, "k.json", data);
        assert!(!found && out.is_empty());
    }

    #[test]
    fn compile_patterns_rejects_bad_regex() {
        assert!(compile_patterns(&["(unclosed".to_string()]).is_err());
    }

    #[test]
    fn azure_json_gz_aborts_at_non_string_entry() {
        // Build gz bytes containing JSON array with: string, dict (aborts), unreachable string
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write as IoWrite;
        let json = br#"["first azure target hit", {"not": "a string"}, "second azure target never reached"]"#;
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(json).unwrap();
        let gz_bytes = enc.finish().unwrap();

        let c = SearchConfig {
            patterns: compile_patterns(&["azure target".to_string()]).unwrap(),
            hide_filenames: false,
            json_output: false,
            log_format: None,
            log_properties: vec![],
            account_name: Some("acct".into()),
        };
        let (found, out) = run(&c, "export.json.gz", &gz_bytes);
        assert!(found, "should match before hitting the non-string entry");
        assert!(
            out.contains("first azure target hit"),
            "first match should appear"
        );
        assert!(
            !out.contains("second azure target"),
            "should abort at dict, not reach second string"
        );
    }
}
