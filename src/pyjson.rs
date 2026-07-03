//! Python-compatible JSON serialization (json.dumps defaults) and repr()
//! formatting. Output fidelity with the Python cloudgrep requires both.

use serde_json::Value;

/// Serialize a JSON value to a Python-compatible JSON string.
/// Matches Python json.dumps() with ensure_ascii=True (non-ASCII chars are \uXXXX-escaped).
#[allow(dead_code)]
pub fn dumps(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

/// Python repr() representation for dict/list values
#[allow(dead_code)]
pub fn python_repr(v: &Value) -> String {
    let mut out = String::new();
    write_repr(&mut out, v);
    out
}

#[allow(dead_code)]
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

#[allow(dead_code)]
fn write_str_repr(out: &mut String, s: &str) {
    // Python repr: single quotes, unless the string contains ' and not "
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
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
        // The 'é' character (U+00E9) should be escaped as é by the function
        assert_eq!(
            dumps(&json!({"msg": "héllo"})),
            "{\"msg\": \"h\\u00e9llo\"}"
        );
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
