//! S3 provider — wraps aws-sdk-s3 behind the ObjectStore trait.

use crate::filters::{Filters, ObjectMeta};
use chrono::DateTime;
use tracing::warn;

pub struct S3Provider {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl S3Provider {
    pub async fn new(bucket: String, profile: Option<String>) -> anyhow::Result<Self> {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(p) = profile {
            loader = loader.profile_name(p);
        }
        let shared = loader.load().await;
        let mut builder = aws_sdk_s3::config::Builder::from(&shared);
        if std::env::var("AWS_ENDPOINT_URL").is_ok() {
            builder = builder.force_path_style(true);
        }
        Ok(Self {
            client: aws_sdk_s3::Client::from_conf(builder.build()),
            bucket,
        })
    }

    pub async fn log_region_warning(&self) {
        let region = self
            .client
            .get_bucket_location()
            .bucket(&self.bucket)
            .send()
            .await
            .ok()
            .and_then(|r| r.location_constraint().map(|l| l.as_str().to_string()))
            .unwrap_or_else(|| "unknown".to_string());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::ObjectStore;

    #[tokio::test]
    async fn display_url_is_s3_scheme() {
        let p = S3Provider::new("mybucket".into(), None).await.unwrap();
        assert_eq!(p.display_url("a/b.log"), "s3://mybucket/a/b.log");
    }
}
