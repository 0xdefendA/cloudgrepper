use crate::filters::{Filters, ObjectMeta};
use azure_storage::prelude::*;
use azure_storage_blobs::prelude::*;
use chrono::{DateTime, Utc};
use futures::StreamExt;

pub struct AzureProvider {
    container: ContainerClient,
    account: String,
    container_name: String,
}

impl AzureProvider {
    pub fn new(account_name: &str, container_name: &str) -> anyhow::Result<Self> {
        let container = if std::env::var("AZURE_STORAGE_USE_EMULATOR").is_ok() {
            // Azurite well-known devstore credentials (test-only path)
            ClientBuilder::emulator().container_client(container_name)
        } else {
            let credential = azure_identity::create_credential()?;
            let storage_credentials = StorageCredentials::token_credential(credential);
            BlobServiceClient::new(account_name, storage_credentials)
                .container_client(container_name)
        };
        Ok(Self {
            container,
            account: account_name.to_string(),
            container_name: container_name.to_string(),
        })
    }
}

fn to_chrono(t: time::OffsetDateTime) -> Option<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(t.unix_timestamp(), t.nanosecond())
}

#[async_trait::async_trait]
impl super::ObjectStore for AzureProvider {
    async fn list(&self, prefix: &str, filters: &Filters) -> anyhow::Result<Vec<ObjectMeta>> {
        let mut out = Vec::new();
        let mut pages = self
            .container
            .list_blobs()
            .prefix(prefix.to_string())
            .into_stream();
        while let Some(page) = pages.next().await {
            for blob in page?.blobs.blobs() {
                let meta = ObjectMeta {
                    key: blob.name.clone(),
                    size: blob.properties.content_length as i64,
                    last_modified: to_chrono(blob.properties.last_modified),
                };
                if filters.matches(&meta) {
                    out.push(meta);
                }
            }
        }
        Ok(out)
    }

    async fn fetch(&self, key: &str) -> anyhow::Result<bytes::Bytes> {
        let content = self.container.blob_client(key).get_content().await?;
        Ok(bytes::Bytes::from(content))
    }

    fn display_url(&self, key: &str) -> String {
        format!("azure://{}/{}/{}", self.account, self.container_name, key)
    }
}
