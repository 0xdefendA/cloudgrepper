//! CLI mirroring cloudgrep's argparse interface exactly, including the
//! multi-char "short" options argparse allows but clap does not.

#![allow(dead_code)]

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "cloudgrepper",
    about = "CloudGrep: grep for cloud storage (S3, Azure, Google Cloud). Rust port of cado-security/cloudgrep."
)]
pub struct Cli {
    /// AWS S3 Bucket to search (e.g. my-bucket)
    #[arg(short = 'b', long)]
    pub bucket: Option<String>,
    /// Azure Account Name to search
    #[arg(long = "account-name")]
    pub account_name: Option<String>,
    /// Azure Container Name to search
    #[arg(long = "container-name")]
    pub container_name: Option<String>,
    /// Google Cloud Bucket to search
    #[arg(long = "google-bucket")]
    pub google_bucket: Option<String>,
    /// Comma-separated list of regex patterns to search
    #[arg(short = 'q', long)]
    pub query: Option<String>,
    /// File containing queries (one per line)
    #[arg(short = 'v', long)]
    pub file: Option<String>,
    /// File containing Yara rules
    #[arg(short = 'y', long)]
    pub yara: Option<String>,
    /// Filter objects by prefix (e.g. logs/)
    #[arg(short = 'p', long, default_value = "")]
    pub prefix: String,
    /// Filter objects whose names contain a keyword (e.g. .log.gz)
    #[arg(short = 'f', long)]
    pub filename: Option<String>,
    /// Filter objects modified after this date (YYYY-MM-DD)
    #[arg(short = 's', long = "start_date")]
    pub start_date: Option<String>,
    /// Filter objects modified before this date (YYYY-MM-DD)
    #[arg(short = 'e', long = "end_date")]
    pub end_date: Option<String>,
    /// Max file size in bytes (default: 100MB)
    #[arg(long = "file_size", default_value_t = 100_000_000)]
    pub file_size: i64,
    /// AWS profile to use (e.g. default, dev, prod)
    #[arg(long)]
    pub profile: Option<String>,
    /// Enable debug logging
    #[arg(short = 'd', long)]
    pub debug: bool,
    /// Hide filenames in output
    #[arg(long = "hide_filenames")]
    pub hide_filenames: bool,
    /// Pre-defined log type (e.g. cloudtrail, azure)
    #[arg(long = "log_type")]
    pub log_type: Option<String>,
    /// Custom log format (e.g. json, csv)
    #[arg(long = "log_format")]
    pub log_format: Option<String>,
    /// Comma-separated list of log properties to extract
    #[arg(long = "log_properties")]
    pub log_properties: Option<String>,
    /// Output results in JSON format
    #[arg(long = "json_output")]
    pub json_output: bool,
    /// Convert date to ISO format (YYYY-MM-DDTHH:MM:SS)
    #[arg(long = "convert_date")]
    pub convert_date: bool,
    /// Use original key name instead of temporary name for uncompressed files
    #[arg(long = "use_og_name")]
    pub use_og_name: bool,
}

const SHORT_MAP: [(&str, &str); 12] = [
    ("-an", "--account-name"),
    ("-cn", "--container-name"),
    ("-gb", "--google-bucket"),
    ("-fs", "--file_size"),
    ("-pr", "--profile"),
    ("-hf", "--hide_filenames"),
    ("-lt", "--log_type"),
    ("-lf", "--log_format"),
    ("-lp", "--log_properties"),
    ("-jo", "--json_output"),
    ("-cd", "--convert_date"),
    ("-og", "--use_og_name"),
];

pub fn normalize_args<I: IntoIterator<Item = String>>(args: I) -> Vec<String> {
    args.into_iter()
        .map(|arg| {
            for (short, long) in SHORT_MAP {
                if arg == short {
                    return long.to_string();
                }
                if let Some(rest) = arg.strip_prefix(&format!("{short}=")) {
                    return format!("{long}={rest}");
                }
            }
            arg
        })
        .collect()
}

pub fn parse_comma_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(String::from)
        .collect()
}

pub fn load_query_file(path: &str) -> anyhow::Result<Vec<String>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        let mut full = vec!["cloudgrepper".to_string()];
        full.extend(args.iter().map(|s| s.to_string()));
        Cli::try_parse_from(normalize_args(full)).unwrap()
    }

    #[test]
    fn short_flag_shim_maps_all_multichar_shorts() {
        let cli = parse(&[
            "-b",
            "buck",
            "-an",
            "acct",
            "-cn",
            "cont",
            "-gb",
            "gbuck",
            "-q",
            "foo,bar",
            "-fs",
            "500",
            "-pr",
            "prof",
            "-hf",
            "-lt",
            "cloudtrail",
            "-jo",
            "-cd",
            "-og",
        ]);
        assert_eq!(cli.bucket.as_deref(), Some("buck"));
        assert_eq!(cli.account_name.as_deref(), Some("acct"));
        assert_eq!(cli.container_name.as_deref(), Some("cont"));
        assert_eq!(cli.google_bucket.as_deref(), Some("gbuck"));
        assert_eq!(cli.file_size, 500);
        assert_eq!(cli.profile.as_deref(), Some("prof"));
        assert!(cli.hide_filenames && cli.json_output && cli.convert_date && cli.use_og_name);
        assert_eq!(cli.log_type.as_deref(), Some("cloudtrail"));
    }

    #[test]
    fn long_flags_use_python_spellings() {
        let cli = parse(&[
            "--file_size",
            "42",
            "--hide_filenames",
            "--start_date",
            "2023-01-01",
        ]);
        assert_eq!(cli.file_size, 42);
        assert!(cli.hide_filenames);
        assert_eq!(cli.start_date.as_deref(), Some("2023-01-01"));
        // kebab-case must NOT be accepted for underscore flags
        assert!(Cli::try_parse_from(["p", "--file-size", "42"]).is_err());
    }

    #[test]
    fn shim_handles_equals_form_and_defaults() {
        let cli = parse(&["-fs=99", "-b", "x"]);
        assert_eq!(cli.file_size, 99);
        let cli = parse(&["-b", "x"]);
        assert_eq!(cli.file_size, 100_000_000);
        assert_eq!(cli.prefix, "");
    }

    #[test]
    fn comma_list_matches_python_list_of_strings() {
        assert_eq!(parse_comma_list("a, b ,,c"), vec!["a", "b", "c"]);
        assert_eq!(parse_comma_list(""), Vec::<String>::new());
    }

    #[test]
    fn load_query_file_trims_and_drops_blanks() {
        // Port of test_returns_string_with_file_contents
        let p = std::env::temp_dir().join("cloudgrepper_queries_test.txt");
        std::fs::write(&p, "query1\nquery2\n\n  query3  \n").unwrap();
        assert_eq!(
            load_query_file(p.to_str().unwrap()).unwrap(),
            vec!["query1", "query2", "query3"]
        );
    }
}
