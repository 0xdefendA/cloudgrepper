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
            .filter(|p| p.matches().next().is_some())
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

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = r#"rule rule_name {strings: $a = "get" nocase wide ascii condition: $a}"#;

    fn compile(src: &str) -> yara_x::Rules {
        yara_x::compile(src).unwrap()
    }

    #[test]
    fn yara_scan_matches_and_formats_like_python() {
        // Port of test_yara: hide_filenames=True, json_output=True
        let rules = compile(RULE);
        let mut buf = Vec::new();
        let matched = scan_object(
            &rules,
            "key_name",
            b"one\nget stuff\nthree",
            true,
            true,
            &mut buf,
        );
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
        assert!(!scan_object(
            &rules,
            "k",
            b"nothing here",
            false,
            false,
            &mut buf
        ));
        assert!(buf.is_empty());
    }

    #[test]
    fn fixture_rule_matches_apache_log() {
        // yara.rule fixture: rule get { $get = "GET" nocase wide ascii }
        let path = format!("{}/tests/data/yara.rule", env!("CARGO_MANIFEST_DIR"));
        let rules = compile_rules(&path).unwrap();
        let data = std::fs::read(format!(
            "{}/tests/data/apache_access.log",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let mut buf = Vec::new();
        assert!(scan_object(
            &rules,
            "apache_access.log",
            &data,
            false,
            false,
            &mut buf
        ));
        assert!(String::from_utf8(buf).unwrap().contains("get: [$get]"));
    }
}
