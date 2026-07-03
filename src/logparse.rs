//! Log-record extraction, ported from search.py::parse_logs and
//! extract_log_entries, quirks included.

use serde_json::Value;
use tracing::error;

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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
        assert_eq!(
            extract_log_entries(json!({"a": 1}), &[]),
            vec![json!({"a": 1})]
        );
        // top-level list ignores properties (Python only walks dicts)
        assert_eq!(
            extract_log_entries(json!([1, 2]), &["data".to_string()]),
            vec![json!(1), json!(2)]
        );
    }

    #[test]
    fn falsy_matches_python_truthiness() {
        for v in [
            json!(null),
            json!(false),
            json!(0),
            json!(""),
            json!([]),
            json!({}),
        ] {
            assert!(is_falsy(&v));
        }
        assert!(!is_falsy(&json!([1])));
        assert!(!is_falsy(&json!("x")));
    }
}
