//! Python-compatible JSON serialization (json.dumps defaults) and repr()
//! formatting. Output fidelity with the Python cloudgrep requires both.
//!
//! The public functions `dumps` and `python_repr` are used by the search
//! pipeline; suppress the dead_code lint here because the functions are
//! wired in at runtime rather than called directly from `main`.
#![allow(dead_code)]

use serde_json::Value;

/// Serialize a JSON value to a Python-compatible JSON string.
/// Matches Python json.dumps() with ensure_ascii=True (non-ASCII chars are \uXXXX-escaped).
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

/// Render an f64 exactly as Python's json.dumps / repr does.
///
/// Python uses scientific notation when exponent >= 16 or < -4, and always
/// formats the exponent with a sign and at least two digits (e.g. `1e+20`,
/// `1.5e-05`).  Fixed notation otherwise, with a decimal point always present.
fn python_float_repr(f: f64) -> String {
    if f.is_nan() {
        return "NaN".to_string(); // json.dumps(float('nan'))
    }
    if f.is_infinite() {
        return if f > 0.0 {
            "Infinity".to_string()
        } else {
            "-Infinity".to_string()
        };
    }
    // Rust {:e} gives the shortest round-trip mantissa, e.g. "1.5e-5", "1e20"
    let sci = format!("{f:e}");
    let (mantissa, exp_str) = sci.split_once('e').expect("{:e} always has exponent");
    let exp: i32 = exp_str.parse().expect("exponent is integer");
    if !(-4..16).contains(&exp) {
        // Python: 'e' + sign + at-least-2-digit exponent
        let sign = if exp < 0 { '-' } else { '+' };
        format!("{mantissa}e{sign}{:02}", exp.unsigned_abs())
    } else {
        // fixed notation; Rust Display is already shortest round-trip
        let s = format!("{f}");
        if s.contains('.') {
            s
        } else {
            format!("{s}.0")
        }
    }
}

fn write_number(out: &mut String, n: &serde_json::Number) {
    if n.is_f64() {
        let f = n.as_f64().unwrap();
        out.push_str(&python_float_repr(f));
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

/// Python repr() representation for dict/list values
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
    fn float_formatting_matches_python() {
        // Verified against: python3 -c 'import json; ...' 2025-07
        // Scientific: exp >= 16
        assert_eq!(dumps(&json!(1e20_f64)), "1e+20");
        assert_eq!(dumps(&json!(1e16_f64)), "1e+16");
        // Scientific: exp < -4
        assert_eq!(dumps(&json!(1.5e-5_f64)), "1.5e-05");
        assert_eq!(dumps(&json!(1e-5_f64)), "1e-05");
        // Fixed: exp in [-4, 16)
        assert_eq!(dumps(&json!(1e15_f64)), "1000000000000000.0");
        assert_eq!(dumps(&json!(0.0001_f64)), "0.0001");
        assert_eq!(dumps(&json!(3.5_f64)), "3.5"); // simple non-PI float
        assert_eq!(dumps(&json!(1.0_f64)), "1.0");
        // -0.0: Python json.dumps(-0.0) == "-0.0"
        assert_eq!(python_float_repr(-0.0_f64), "-0.0");
        // Integers are unchanged
        assert_eq!(dumps(&json!(42)), "42");
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
