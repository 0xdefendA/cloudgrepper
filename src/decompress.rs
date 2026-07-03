//! Transparent handling of .gz and .zip objects, plus Python-compatible
//! text decoding (errors="ignore" drops undecodable bytes).
//!
//! # Consumers
//! Consumed by search.rs.

use std::io::Read;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileKind {
    Plain,
    Gzip,
    Zip,
}

pub fn detect(name: &str) -> FileKind {
    if name.ends_with(".gz") {
        FileKind::Gzip
    } else if name.ends_with(".zip") {
        FileKind::Zip
    } else {
        FileKind::Plain
    }
}

pub fn decode_ignore(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len());
    let mut rest = data;
    loop {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                return out;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                out.push_str(std::str::from_utf8(&rest[..valid]).unwrap());
                // error_len() is None when the input ends mid-sequence
                // (truncated, not invalid); Python errors="ignore" drops a
                // truncated trailing sequence too, so skip to end-of-input.
                let skip = e.error_len().unwrap_or(rest.len() - valid);
                rest = &rest[valid + skip..];
            }
        }
    }
}

/// Implement Python's universal-newline translation: \r\n → \n, then lone \r → \n.
/// Equivalent to reading with open(..., 'r') which applies newline=None (universal mode).
fn normalize_newlines(s: String) -> String {
    // Two-pass left-to-right: first collapse \r\n pairs, then remaining \r.
    s.replace("\r\n", "\n").replace('\r', "\n")
}

pub fn split_lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (i, b) in text.bytes().enumerate() {
        if b == b'\n' {
            lines.push(&text[start..=i]);
            start = i + 1;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

pub fn texts(data: &[u8], kind: FileKind) -> anyhow::Result<Vec<String>> {
    match kind {
        FileKind::Plain => Ok(vec![normalize_newlines(decode_ignore(data))]),
        FileKind::Gzip => {
            let mut decoder = flate2::read::GzDecoder::new(data);
            let mut buf = Vec::new();
            decoder.read_to_end(&mut buf)?;
            Ok(vec![normalize_newlines(decode_ignore(&buf))])
        }
        FileKind::Zip => {
            let cursor = std::io::Cursor::new(data);
            let mut archive = zip::ZipArchive::new(cursor)?;
            let mut out = Vec::new();
            for i in 0..archive.len() {
                let mut member = archive.by_index(i)?;
                if member.is_dir() {
                    continue;
                }
                let mut buf = Vec::new();
                member.read_to_end(&mut buf)?;
                out.push(normalize_newlines(decode_ignore(&buf)));
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let p = format!(
            "{}/../cloudgrep/tests/data/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        );
        std::fs::read(p).unwrap()
    }

    #[test]
    fn decode_ignore_drops_invalid_bytes() {
        assert_eq!(decode_ignore(b"ab\xffcd"), "abcd"); // Python: b'ab\xffcd'.decode('utf-8','ignore') == 'abcd'
        assert_eq!(decode_ignore("héllo".as_bytes()), "héllo");
    }

    #[test]
    fn detect_by_extension() {
        assert_eq!(detect("logs/a.log.gz"), FileKind::Gzip);
        assert_eq!(detect("a.zip"), FileKind::Zip);
        assert_eq!(detect("a.log"), FileKind::Plain);
    }

    #[test]
    fn split_lines_keeps_newlines() {
        assert_eq!(split_lines("a\nb\nc"), vec!["a\n", "b\n", "c"]);
        assert_eq!(split_lines("a\n"), vec!["a\n"]);
        assert_eq!(split_lines(""), Vec::<&str>::new());
    }

    #[test]
    fn gzip_fixture_contains_content() {
        let t = texts(&fixture("000000.gz"), FileKind::Gzip).unwrap();
        assert_eq!(t.len(), 1);
        assert!(t[0].contains("Running on machine"));
    }

    #[test]
    fn zip_fixture_contains_content() {
        let t = texts(&fixture("000000.zip"), FileKind::Zip).unwrap();
        assert!(!t.is_empty());
        assert!(t.iter().any(|s| s.contains("Running on machine")));
    }

    #[test]
    fn normalize_newlines_crlf() {
        // CRLF: texts returns normalized text, split_lines yields clean lines
        let data = b"alpha\r\nbeta\r\n";
        let t = texts(data, FileKind::Plain).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0], "alpha\nbeta\n");
        let lines = split_lines(&t[0]);
        assert_eq!(lines, vec!["alpha\n", "beta\n"]);
    }

    #[test]
    fn normalize_newlines_lone_cr() {
        let data = b"a\rb";
        let t = texts(data, FileKind::Plain).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0], "a\nb");
    }

    #[test]
    fn normalize_newlines_mixed() {
        // Input: "x\r\r\ny"
        // Pass 1: replace \r\n → \n: "x\r\ny"
        // Pass 2: replace \r → \n: "x\n\ny"
        let data = b"x\r\r\ny";
        let t = texts(data, FileKind::Plain).unwrap();
        assert_eq!(t[0], "x\n\ny");
    }

    #[test]
    fn all_fixtures_decode_without_panic() {
        // Port of Python test_weird_files (UTF-8 torture files included)
        let dir = format!("{}/../cloudgrep/tests/data", env!("CARGO_MANIFEST_DIR"));
        for entry in std::fs::read_dir(dir).unwrap() {
            let data = std::fs::read(entry.unwrap().path()).unwrap();
            let _ = split_lines(&decode_ignore(&data)).len();
        }
        // and 14_3.log has an exact line "SomeLine" (last line, no trailing \n)
        let text = decode_ignore(&fixture("14_3.log"));
        assert!(split_lines(&text).contains(&"SomeLine"));
    }
}
