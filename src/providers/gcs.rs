//! Google Cloud Storage provider — port of cloud.py::search_google.
//!
//! Emulator support: set STORAGE_EMULATOR_HOST=http://localhost:4443 (no trailing slash)
//! to target fake-gcs-server. In that mode we use anonymous auth so no credentials
//! are needed.

use crate::filters::{Filters, ObjectMeta};
use chrono::{DateTime, Utc};
use google_cloud_storage::client::{Client, ClientConfig};
use google_cloud_storage::http::objects::download::Range;
use google_cloud_storage::http::objects::get::GetObjectRequest;
use google_cloud_storage::http::objects::list::ListObjectsRequest;

pub struct GcsProvider {
    client: Client,
    bucket: String,
}

impl GcsProvider {
    pub async fn new(bucket: &str) -> anyhow::Result<Self> {
        // STORAGE_EMULATOR_HOST (fake-gcs-server) -> anonymous + endpoint override
        let config = if let Ok(host) = std::env::var("STORAGE_EMULATOR_HOST") {
            let mut c = ClientConfig::default().anonymous();
            c.storage_endpoint = host;
            c
        } else {
            // honors GOOGLE_APPLICATION_CREDENTIALS / gcloud ADC
            ClientConfig::default().with_auth().await?
        };
        Ok(Self {
            client: Client::new(config),
            bucket: bucket.to_string(),
        })
    }
}

#[async_trait::async_trait]
impl super::ObjectStore for GcsProvider {
    async fn list(&self, prefix: &str, filters: &Filters) -> anyhow::Result<Vec<ObjectMeta>> {
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let resp = self
                .client
                .list_objects(&ListObjectsRequest {
                    bucket: self.bucket.clone(),
                    prefix: Some(prefix.to_string()),
                    page_token: page_token.clone(),
                    ..Default::default()
                })
                .await?;
            for obj in resp.items.unwrap_or_default() {
                let meta = ObjectMeta {
                    key: obj.name.clone(),
                    size: obj.size,
                    last_modified: obj.updated.and_then(|t| {
                        DateTime::<Utc>::from_timestamp(t.unix_timestamp(), t.nanosecond())
                    }),
                };
                if filters.matches(&meta) {
                    out.push(meta);
                }
            }
            page_token = resp.next_page_token;
            if page_token.is_none() {
                break;
            }
        }
        Ok(out)
    }

    async fn fetch(&self, key: &str) -> anyhow::Result<bytes::Bytes> {
        let data = self
            .client
            .download_object(
                &GetObjectRequest {
                    bucket: self.bucket.clone(),
                    object: key.to_string(),
                    ..Default::default()
                },
                &Range::default(),
            )
            .await?;
        Ok(bytes::Bytes::from(data))
    }

    fn display_url(&self, key: &str) -> String {
        format!("gs://{}/{}", self.bucket, key)
    }
}
