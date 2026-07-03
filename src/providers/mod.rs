//! Cloud storage providers behind one trait: list object metadata
//! (filtered) and fetch object bytes.

pub mod s3;

use crate::filters::{Filters, ObjectMeta};

#[async_trait::async_trait]
pub trait ObjectStore: Send + Sync {
    async fn list(&self, prefix: &str, filters: &Filters) -> anyhow::Result<Vec<ObjectMeta>>;
    async fn fetch(&self, key: &str) -> anyhow::Result<bytes::Bytes>;
    fn display_url(&self, key: &str) -> String;
}
