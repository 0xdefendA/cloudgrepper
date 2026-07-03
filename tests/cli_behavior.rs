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
    let out = bin()
        .args(["-q", "(unclosed", "-lt", "cloudtrail"])
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
}
