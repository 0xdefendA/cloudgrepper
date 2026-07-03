//! Match record printing, ported from search.py::print_match.

use crate::pyjson;
use serde_json::{Map, Value};
use std::io::Write;

#[allow(dead_code)]
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

#[allow(dead_code)]
pub fn print_match(rec: &Record, hide_filenames: bool, json_output: bool, out: &mut impl Write) {
    match rec {
        Record::Match {
            key_name,
            query,
            line,
        } => {
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
        Record::Yara {
            key_name,
            match_rule,
            match_strings,
        } => {
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
        assert_eq!(
            capture(&sample(), false, false),
            "file.log: hello world\n\n"
        );
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
        assert_eq!(
            capture(&rec, false, false),
            "k: {'eventName': 'PutObject'}\n"
        );
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
