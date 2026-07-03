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
fn yara_without_query_logs_error_and_exits_0() {
    // Python's `if not query: return` runs unconditionally, so -y without
    // -q/-v exits "No query provided" too.
    let rule = format!(
        "{}/../cloudgrep/tests/data/yara.rule",
        env!("CARGO_MANIFEST_DIR")
    );
    let out = bin()
        .args(["-b", "some-bucket", "-y", &rule])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("No query provided. Exiting."));
}

#[test]
fn bad_regex_exits_nonzero() {
    let out = bin()
        .args(["-q", "(unclosed", "-lt", "cloudtrail"])
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
}

#[test]
fn help_documents_every_multichar_short_form() {
    // The -an/-lt style shorts are handled by an argv shim, invisible to
    // clap — their help text must advertise them so users can discover them.
    let out = bin().arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    for short in [
        "-an", "-cn", "-gb", "-fs", "-pr", "-hf", "-lt", "-lf", "-lp", "-jo", "-cd", "-og",
    ] {
        assert!(
            help.contains(&format!("[short: {short}]")),
            "help output missing short form {short}"
        );
    }
}
