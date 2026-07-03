//! Byte-comparison against captured Python cloudgrep output.
//! Regenerate goldens with: python3 scripts/gen_golden.py

mod support;
use support::*;

#[test]
fn exact_equality_cases() {
    for (golden, fixture, queries, hide, fmt, props, jo) in [
        (
            "cloudtrail_sig_json.txt",
            "cloudtrail_singleline.json",
            "SignatureVersion",
            false,
            Some("json"),
            "Records",
            true,
        ),
        (
            "cloudtrail_sig_line.txt",
            "cloudtrail_singleline.json",
            "SignatureVersion",
            false,
            Some("json"),
            "Records",
            false,
        ),
        (
            "cloudtrail_sig_hidden.txt",
            "cloudtrail_singleline.json",
            "SignatureVersion",
            true,
            Some("json"),
            "Records",
            true,
        ),
        (
            "azure_singleline_json.txt",
            "azure_singleline.json",
            "listKeys",
            false,
            Some("json"),
            "data",
            true,
        ),
    ] {
        let ours = run_search(fixture, queries, hide, fmt, props, jo);
        assert_eq!(ours, golden_content(golden), "golden mismatch: {golden}");
    }
}

#[test]
fn prefix_cases_python_truncates_at_first_match() {
    for (golden, fixture, queries, jo) in [
        (
            "gz_first_match.txt",
            "000000.gz",
            "Running on machine",
            false,
        ),
        (
            "gz_first_match_json.txt",
            "000000.gz",
            "Running on machine",
            true,
        ),
        (
            "zip_first_match.txt",
            "000000.zip",
            "Running on machine",
            false,
        ),
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
