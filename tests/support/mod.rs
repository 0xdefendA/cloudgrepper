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
