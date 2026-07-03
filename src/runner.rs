//! Orchestration: port of cloudgrep.py::search plus the download/search
//! fan-out from cloud.py, using a bounded-concurrency stream instead of
//! a thread pool.

use crate::cli::{load_query_file, parse_comma_list, Cli};
use crate::filters::{parse_date, Filters};
use crate::providers::{s3::S3Provider, ObjectStore};
use crate::pyjson;
use crate::search::{compile_patterns, search_object, SearchConfig};
use futures::StreamExt;
use serde_json::Value;
use std::io::Write;
use std::sync::Arc;
use tracing::{error, info, warn};

pub const DEFAULT_WORKERS: usize = 10;

pub fn resolve_log_format(
    log_type: Option<&str>,
    log_format: Option<String>,
    log_properties: Vec<String>,
) -> Result<(Option<String>, Vec<String>), String> {
    match log_type.map(|s| s.to_lowercase()).as_deref() {
        Some("cloudtrail") => Ok((Some("json".into()), vec!["Records".into()])),
        Some("azure") => Ok((Some("json".into()), vec!["data".into()])),
        Some("waf") => Ok((Some("jsonl".into()), vec![])),
        Some(other) => Err(other.to_string()),
        None => Ok((log_format, log_properties)),
    }
}

fn queries_display(queries: &[String]) -> String {
    let arr = Value::Array(queries.iter().cloned().map(Value::String).collect());
    pyjson::python_repr(&arr)
}

pub async fn run(cli: Cli) -> anyhow::Result<()> {
    // Query resolution (query beats file, like Python)
    let mut queries = cli
        .query
        .as_deref()
        .map(parse_comma_list)
        .unwrap_or_default();
    if queries.is_empty() {
        if let Some(file) = &cli.file {
            queries = load_query_file(file)?;
        }
    }
    if cli.yara.is_none() && queries.is_empty() {
        error!("No query provided. Exiting.");
        return Ok(());
    }

    if cli.yara.is_some() {
        // Wired in Task 14 (yara-x). Until then this is an explicit,
        // honest failure — not silent wrong behavior.
        error!("Yara scanning not yet implemented (Task 14). Exiting.");
        return Ok(());
    }

    let log_properties = cli
        .log_properties
        .as_deref()
        .map(parse_comma_list)
        .unwrap_or_default();
    let (log_format, log_properties) = match resolve_log_format(
        cli.log_type.as_deref(),
        cli.log_format.clone(),
        log_properties,
    ) {
        Ok(pair) => pair,
        Err(bad) => {
            error!("Invalid log_type: {bad}");
            return Ok(());
        }
    };

    let from_date = cli.start_date.as_deref().map(parse_date).transpose()?;
    let to_date = cli.end_date.as_deref().map(parse_date).transpose()?;

    let cfg = Arc::new(SearchConfig {
        patterns: compile_patterns(&queries)?,
        hide_filenames: cli.hide_filenames,
        json_output: cli.json_output,
        log_format,
        log_properties,
        account_name: cli.account_name.clone(),
    });

    let filters = Filters {
        key_contains: cli.filename.clone(),
        from_date,
        to_date,
        max_size: cli.file_size,
        check_size: true,
    };

    if let Some(bucket) = &cli.bucket {
        let provider = S3Provider::new(bucket.clone(), cli.profile.clone()).await?;
        provider.log_region_warning().await;
        let keys = provider.list(&cli.prefix, &filters).await?;
        warn!(
            "Searching {} files in {} for {}...",
            keys.len(),
            bucket,
            queries_display(&queries)
        );
        search_provider(Arc::new(provider), keys, cfg.clone(), DEFAULT_WORKERS).await;
    }

    // Azure (Task 12) and GCS (Task 13) blocks land here, mirroring the
    // S3 block with their own providers and info-level "Searching" logs.

    Ok(())
}

pub async fn search_provider(
    store: Arc<dyn ObjectStore>,
    keys: Vec<crate::filters::ObjectMeta>,
    cfg: Arc<SearchConfig>,
    workers: usize,
) -> usize {
    futures::stream::iter(keys.into_iter().map(|meta| {
        let store = store.clone();
        let cfg = cfg.clone();
        async move {
            info!("Downloading {}", store.display_url(&meta.key));
            match store.fetch(&meta.key).await {
                Ok(data) => {
                    let mut buf = Vec::new();
                    let matched = search_object(&cfg, &meta.key, &data, &mut buf);
                    let stdout = std::io::stdout();
                    let mut lock = stdout.lock();
                    let _ = lock.write_all(&buf);
                    usize::from(matched)
                }
                Err(e) => {
                    error!("Error processing {}: {e:#}", meta.key);
                    0
                }
            }
        }
    }))
    .buffer_unordered(workers)
    .fold(0, |acc, n| async move { acc + n })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_type_presets() {
        assert_eq!(
            resolve_log_format(Some("cloudtrail"), None, vec![]),
            Ok((Some("json".into()), vec!["Records".into()]))
        );
        assert_eq!(
            resolve_log_format(Some("CloudTrail"), None, vec![]), // case-insensitive
            Ok((Some("json".into()), vec!["Records".into()]))
        );
        assert_eq!(
            resolve_log_format(Some("azure"), None, vec![]),
            Ok((Some("json".into()), vec!["data".into()]))
        );
        assert_eq!(
            resolve_log_format(Some("waf"), None, vec![]),
            Ok((Some("jsonl".into()), vec![]))
        );
        assert_eq!(
            resolve_log_format(Some("nope"), None, vec![]),
            Err("nope".to_string())
        );
        // no log_type: custom format/properties pass through
        assert_eq!(
            resolve_log_format(None, Some("json".into()), vec!["Records".into()]),
            Ok((Some("json".into()), vec!["Records".into()]))
        );
    }
}
