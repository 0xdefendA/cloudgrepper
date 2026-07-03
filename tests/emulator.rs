//! End-to-end tests against local emulators. Gated: CLOUDGREPPER_EMULATOR=1.
//! Start emulators with: docker compose -f docker/docker-compose.yml up -d

use std::process::Command;

const MINIO: &str = "http://127.0.0.1:9000";

fn s3_env(cmd: &mut Command) -> &mut Command {
    cmd.env("AWS_ACCESS_KEY_ID", "minioadmin")
        .env("AWS_SECRET_ACCESS_KEY", "minioadmin")
        .env("AWS_ENDPOINT_URL", MINIO)
        .env("AWS_REGION", "us-east-1")
        .env("AWS_EC2_METADATA_DISABLED", "true")
}

async fn s3_client() -> aws_sdk_s3::Client {
    std::env::set_var("AWS_ACCESS_KEY_ID", "minioadmin");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "minioadmin");
    std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
    let conf = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .endpoint_url(MINIO)
        .region(aws_config::Region::new("us-east-1"))
        .load()
        .await;
    let s3conf = aws_sdk_s3::config::Builder::from(&conf)
        .force_path_style(true)
        .build();
    aws_sdk_s3::Client::from_conf(s3conf)
}

fn fixture_path(name: &str) -> String {
    format!(
        "{}/../cloudgrep/tests/data/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

async fn seed(client: &aws_sdk_s3::Client, bucket: &str, objects: &[(&str, Vec<u8>)]) {
    let _ = client.create_bucket().bucket(bucket).send().await; // idempotent
    for (key, body) in objects {
        client
            .put_object()
            .bucket(bucket)
            .key(*key)
            .body(aws_sdk_s3::primitives::ByteStream::from(body.clone()))
            .send()
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn s3_end_to_end_someline() {
    // Port of test_e2e: three fixture logs, all matching "SomeLine"
    if std::env::var("CLOUDGREPPER_EMULATOR").is_err() {
        eprintln!("skipped: set CLOUDGREPPER_EMULATOR=1");
        return;
    }
    let client = s3_client().await;
    let files = ["14_3.log", "35010_7.log", "apache_access.log"];
    let objects: Vec<(&str, Vec<u8>)> = files
        .iter()
        .map(|f| (*f, std::fs::read(fixture_path(f)).unwrap()))
        .collect();
    seed(&client, "e2e-bucket", &objects).await;

    let out = s3_env(&mut Command::new(env!("CARGO_BIN_EXE_cloudgrepper")))
        .args(["-b", "e2e-bucket", "-q", "SomeLine"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for f in files {
        assert!(stdout.contains(f), "expected a match line from {f}");
    }
}

#[tokio::test]
async fn s3_filters_and_gz_decompression() {
    // Port of test_list_files_returns_pre_filtered_files + gz handling
    if std::env::var("CLOUDGREPPER_EMULATOR").is_err() {
        eprintln!("skipped: set CLOUDGREPPER_EMULATOR=1");
        return;
    }
    let client = s3_client().await;
    seed(
        &client,
        "filter-bucket",
        &[
            ("log_file1.txt", b"dummy content".to_vec()),
            ("log_file2.txt", b"dummy content".to_vec()),
            ("not_a_thing.txt", b"dummy content".to_vec()),
            ("log_empty.txt", Vec::new()),
            (
                "archive.log.gz",
                std::fs::read(fixture_path("000000.gz")).unwrap(),
            ),
        ],
    )
    .await;

    // -f log: only log_file1/log_file2 survive filtering (empty file dropped)
    let out = s3_env(&mut Command::new(env!("CARGO_BIN_EXE_cloudgrepper")))
        .args(["-b", "filter-bucket", "-q", "dummy content", "-f", "log"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("log_file1.txt") && stdout.contains("log_file2.txt"));
    assert!(!stdout.contains("not_a_thing.txt"));
    assert!(
        !stdout.contains("log_empty.txt"),
        "empty file should be dropped by the size filter"
    );

    // gz object decompressed transparently (Python 1.0.5 needs -og; we don't)
    let out = s3_env(&mut Command::new(env!("CARGO_BIN_EXE_cloudgrepper")))
        .args([
            "-b",
            "filter-bucket",
            "-q",
            "Running on machine",
            "-f",
            ".gz",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("Running on machine"));
}

#[tokio::test]
async fn azure_end_to_end() {
    // Port of test_azure_search_mocked, against real Azurite
    if std::env::var("CLOUDGREPPER_EMULATOR").is_err() {
        eprintln!("skipped: set CLOUDGREPPER_EMULATOR=1");
        return;
    }
    use azure_storage_blobs::prelude::*;
    let container = ClientBuilder::emulator().container_client("azuretest");
    let _ = container.create().await; // idempotent
    container
        .blob_client("testblob.log")
        .put_block_blob("Some Azure log entry that mentions azure target")
        .await
        .unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_cloudgrepper"))
        .env("AZURE_STORAGE_USE_EMULATOR", "1")
        .args([
            "-an",
            "devstoreaccount1",
            "-cn",
            "azuretest",
            "-q",
            "azure target",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("azure target"));
    assert!(stdout.contains("testblob.log"));
}
