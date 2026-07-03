//! S3 provider — wraps aws-sdk-s3 behind the ObjectStore trait.

use crate::filters::{Filters, ObjectMeta};
use aws_credential_types::Credentials;
use chrono::DateTime;
use std::path::Path;
use tracing::warn;

pub struct S3Provider {
    client: aws_sdk_s3::Client,
    bucket: String,
    /// Authoritative region resolved during construction (us-east-1 normalised).
    bucket_region: String,
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Map a `GetBucketLocation` `LocationConstraint` value to a region name,
/// matching boto3's normalisation rules.
///
/// - `None` or `""` → `"us-east-1"` (S3 classic / us-east-1 returns no constraint)
/// - `"EU"`         → `"eu-west-1"` (legacy alias)
/// - anything else  → the constraint string verbatim
pub fn bucket_region_from_constraint(c: Option<&str>) -> String {
    match c {
        None | Some("") => "us-east-1".to_string(),
        Some("EU") => "eu-west-1".to_string(),
        Some(r) => r.to_string(),
    }
}

/// Parse a single key from an AWS INI-style profile file.
///
/// Handles both the `[profile_name]` format (credentials file) and
/// `[profile profile_name]` format (config file).
fn parse_ini_value(path: &Path, profile_name: &str, key: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let alt_header = format!("profile {}", profile_name);
    let mut in_section = false;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim();
            in_section = section == profile_name || section == alt_header;
            continue;
        }
        if !in_section || line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Return the best-guess path to the user's home directory without importing
/// extra crates (HOME / USERPROFILE env vars).
fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
}

/// Extract **static** AWS credentials (access key + secret) from the profile
/// files, skipping any SSO / `login_session` / MFA configuration that would
/// require a live token refresh.
///
/// `credentials_file` and `config_file` default to the standard AWS paths
/// (`~/.aws/credentials` and `~/.aws/config`) when `None`.
///
/// Returns `None` when no static key pair is found for `profile_name`.
pub fn profile_static_credentials(
    profile_name: &str,
    credentials_file: Option<&Path>,
    config_file: Option<&Path>,
) -> Option<Credentials> {
    let home = home_dir()?;
    let default_creds = home.join(".aws").join("credentials");
    let default_config = home.join(".aws").join("config");

    // Search both files in order; credentials file takes precedence.
    let files: [&Path; 2] = [
        credentials_file.unwrap_or(&default_creds),
        config_file.unwrap_or(&default_config),
    ];

    let mut key_id = None;
    let mut secret = None;

    for file in &files {
        if key_id.is_none() {
            key_id = parse_ini_value(file, profile_name, "aws_access_key_id");
        }
        if secret.is_none() {
            secret = parse_ini_value(file, profile_name, "aws_secret_access_key");
        }
        if key_id.is_some() && secret.is_some() {
            break;
        }
    }

    Some(Credentials::new(
        key_id?,
        secret?,
        None,
        None,
        "profile-static",
    ))
}

/// Build an `aws_sdk_s3::Config` from an already-loaded `SdkConfig`, overriding
/// the region and preserving path-style for endpoint overrides (emulators).
fn make_s3_config(
    shared: &aws_config::SdkConfig,
    region: aws_config::Region,
) -> aws_sdk_s3::Config {
    let mut b = aws_sdk_s3::config::Builder::from(shared).region(region);
    if std::env::var("AWS_ENDPOINT_URL").is_ok() {
        b = b.force_path_style(true);
    }
    b.build()
}

// ─── provider ────────────────────────────────────────────────────────────────

impl S3Provider {
    /// Create an S3Provider, resolving credentials and bucket region so that
    /// subsequent operations never hit a redirect or a stale-token failure.
    ///
    /// Credential precedence (matches boto3 / AWS CLI):
    /// 1. Environment variables (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`)
    /// 2. Static keys in the profile's credentials/config files (skipping any
    ///    `login_session` / SSO configuration that may have an expired token)
    /// 3. Full default chain (EC2 instance profile, ECS task role, …)
    pub async fn new(bucket: String, profile: Option<String>) -> anyhow::Result<Self> {
        let profile_name = profile.as_deref().unwrap_or("default");

        // ── Step 1: build credential-aware SdkConfig ────────────────────────
        // If static keys exist in the profile files inject them explicitly so
        // aws-config never attempts to refresh the login_session / SSO token.
        // Env vars (AWS_ACCESS_KEY_ID etc.) are handled automatically by the
        // default loader and take priority over any override we inject here.
        let mut loader =
            aws_config::defaults(aws_config::BehaviorVersion::latest()).profile_name(profile_name);

        if let Some(static_creds) = profile_static_credentials(profile_name, None, None) {
            // Only inject when env vars are absent; otherwise the env-var provider
            // (which the loader still tries first) will win anyway.
            if std::env::var("AWS_ACCESS_KEY_ID").is_err() {
                loader = loader.credentials_provider(
                    aws_credential_types::provider::SharedCredentialsProvider::new(static_creds),
                );
            }
        }

        let shared = loader.load().await;

        // ── Step 2: resolve initial region from profile ──────────────────────
        let initial_region = shared
            .region()
            .cloned()
            .unwrap_or_else(|| aws_config::Region::new("us-east-1"));

        // ── Step 3: build initial client ────────────────────────────────────
        let initial_client =
            aws_sdk_s3::Client::from_conf(make_s3_config(&shared, initial_region.clone()));

        // ── Step 4: resolve bucket's actual region (region redirect) ─────────
        // With an endpoint override (MinIO / emulators), skip the redirect
        // logic — the emulator always runs in the configured region.
        let (client, bucket_region) = if std::env::var("AWS_ENDPOINT_URL").is_ok() {
            (initial_client, initial_region.as_ref().to_string())
        } else {
            let constraint = initial_client
                .get_bucket_location()
                .bucket(&bucket)
                .send()
                .await
                .ok()
                .and_then(|r| r.location_constraint().map(|l| l.as_str().to_string()));

            let detected = bucket_region_from_constraint(constraint.as_deref());

            if detected != initial_region.as_ref() {
                let new_region = aws_config::Region::new(detected.clone());
                let new_client = aws_sdk_s3::Client::from_conf(make_s3_config(&shared, new_region));
                (new_client, detected)
            } else {
                (initial_client, detected)
            }
        };

        Ok(Self {
            client,
            bucket,
            bucket_region,
        })
    }

    /// Emit a tracing warning with the bucket's region (resolved once in new()).
    pub async fn log_region_warning(&self) {
        let region = &self.bucket_region;
        warn!("Bucket region: {region}. (Search from the same region to avoid egress charges.)");
    }
}

#[async_trait::async_trait]
impl super::ObjectStore for S3Provider {
    async fn list(&self, prefix: &str, filters: &Filters) -> anyhow::Result<Vec<ObjectMeta>> {
        let mut out = Vec::new();
        let mut pages = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .into_paginator()
            .page_size(1000)
            .send();
        while let Some(page) = pages.next().await {
            for obj in page?.contents() {
                let meta = ObjectMeta {
                    key: obj.key().unwrap_or_default().to_string(),
                    size: obj.size().unwrap_or(0),
                    last_modified: obj
                        .last_modified()
                        .and_then(|dt| DateTime::from_timestamp(dt.secs(), dt.subsec_nanos())),
                };
                if filters.matches(&meta) {
                    out.push(meta);
                }
            }
        }
        Ok(out)
    }

    async fn fetch(&self, key: &str) -> anyhow::Result<bytes::Bytes> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?;
        Ok(resp.body.collect().await?.into_bytes())
    }

    fn display_url(&self, key: &str) -> String {
        format!("s3://{}/{}", self.bucket, key)
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::ObjectStore;

    // ── bucket_region_from_constraint ───────────────────────────────────────

    #[test]
    fn constraint_none_is_us_east_1() {
        assert_eq!(bucket_region_from_constraint(None), "us-east-1");
    }

    #[test]
    fn constraint_empty_string_is_us_east_1() {
        assert_eq!(bucket_region_from_constraint(Some("")), "us-east-1");
    }

    #[test]
    fn constraint_eu_maps_to_eu_west_1() {
        assert_eq!(bucket_region_from_constraint(Some("EU")), "eu-west-1");
    }

    #[test]
    fn constraint_us_west_2_passthrough() {
        assert_eq!(
            bucket_region_from_constraint(Some("us-west-2")),
            "us-west-2"
        );
    }

    // ── profile_static_credentials ──────────────────────────────────────────

    #[test]
    fn static_creds_from_credentials_file() {
        let dir = tempfile::tempdir().unwrap();
        let creds_path = dir.path().join("credentials");
        // credentials file has static keys
        std::fs::write(
            &creds_path,
            "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        )
        .unwrap();
        // config file has a login_session that should be ignored
        let config_path = dir.path().join("config");
        std::fs::write(
            &config_path,
            "[default]\nregion = us-east-1\nlogin_session = arn:aws:iam::1:user/x\n",
        )
        .unwrap();

        let creds =
            profile_static_credentials("default", Some(&creds_path), Some(&config_path)).unwrap();
        assert_eq!(creds.access_key_id(), "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(
            creds.secret_access_key(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert!(creds.session_token().is_none());
    }

    #[test]
    fn static_creds_none_when_only_login_session() {
        let dir = tempfile::tempdir().unwrap();
        let creds_path = dir.path().join("credentials");
        // credentials file has no static keys
        std::fs::write(&creds_path, "[default]\n").unwrap();
        // config file also has no static keys — only login_session
        let config_path = dir.path().join("config");
        std::fs::write(
            &config_path,
            "[default]\nregion = us-east-1\nlogin_session = arn:aws:iam::1:user/x\n",
        )
        .unwrap();

        let result = profile_static_credentials("default", Some(&creds_path), Some(&config_path));
        assert!(
            result.is_none(),
            "expected None when no static keys, got {:?}",
            result.map(|c| c.access_key_id().to_string())
        );
    }

    // ── display_url (regression) ────────────────────────────────────────────

    #[tokio::test]
    async fn display_url_is_s3_scheme() {
        let p = S3Provider::new("mybucket".into(), None).await.unwrap();
        assert_eq!(p.display_url("a/b.log"), "s3://mybucket/a/b.log");
    }
}
