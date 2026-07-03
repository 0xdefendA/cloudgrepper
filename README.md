# cloudgrepper

grep for cloud storage: search log files (optionally gzip/zip compressed) in AWS S3,
Azure Blob Storage, and Google Cloud Storage, in parallel, without indexing into a SIEM.

A faithful Rust port of [cloudgrep](https://github.com/cado-security/cloudgrep) by
Cado Security (Apache-2.0, now deprecated). Same CLI, same output; `-jo` emits streaming
JSONL. Credit and thanks to cado-security for the original design and test corpus.

License: Apache-2.0.

## Usage

### CLI Flags

| Short | Long | Description |
|-------|------|-------------|
| `-b` | `--bucket` | AWS S3 bucket |
| `-an` | `--account-name` | Azure account name |
| `-cn` | `--container-name` | Azure container name |
| `-gb` | `--google-bucket` | GCS bucket |
| `-q` | `--query` | Comma-separated list of regexes to search for |
| `-v` | `--file` | File of regexes, one per line (blank lines skipped) |
| `-y` | `--yara` | File of Yara rules |
| `-p` | `--prefix` | Object name prefix filter (e.g., `logs/`) |
| `-f` | `--filename` | Object name contains-keyword filter |
| `-s` | `--start_date` | Objects modified after date/time (e.g., `2024-01-01`, `2024-01-01T12:00:00`) |
| `-e` | `--end_date` | Objects modified before date/time |
| `-fs` | `--file_size` | Skip objects larger than N bytes (default `100000000` / 100 MB) |
| `-pr` | `--profile` | AWS profile name (for S3) |
| `-d` | `--debug` | Enable debug logging |
| `-hf` | `--hide_filenames` | Omit filenames from output |
| `-lt` | `--log_type` | Preset log type: `cloudtrail`, `azure`, or `waf` |
| `-lf` | `--log_format` | Custom log format: `json`, `jsonl`, or `csv` |
| `-lp` | `--log_properties` | Comma-separated property path to extract records (e.g., `Records`) |
| `-jo` | `--json_output` | Output matches as JSON (JSONL format, one object per line) |
| `-cd` | `--convert_date` | Normalize dates to UTC before comparing (S3 filter) |
| `-og` | `--use_og_name` | Use original object key name for extension detection and log labels |

### AWS S3 Examples

Search all objects in a bucket:
```bash
cloudgrepper -b my-bucket -q "error"
```

Search with prefix filter and date range:
```bash
cloudgrepper -b my-bucket -q "error" -p "logs/" -s "2024-01-01" -e "2024-01-02"
```

Search CloudTrail logs and output as JSON:
```bash
cloudgrepper -b my-bucket -q "DeleteBucket" -lt cloudtrail -jo
```

Search multiple patterns:
```bash
cloudgrepper -b my-bucket -q "error,warning,failed"
```

Use a specific AWS profile:
```bash
cloudgrepper -b my-bucket -q "error" -pr myprofile
```

### Azure Storage Examples

Search a container:
```bash
cloudgrepper -an myaccount -cn mycontainer -q "error"
```

Search with date range and JSON output:
```bash
cloudgrepper -an myaccount -cn mycontainer -q "failed" -s "2024-01-01" -e "2024-01-02" -jo
```

### Google Cloud Storage Examples

Search a GCS bucket:
```bash
cloudgrepper -gb my-bucket -q "error"
```

Search with prefix filter:
```bash
cloudgrepper -gb my-bucket -q "error" -p "logs/"
```

### Query Patterns

Use regexes from a file (one per line):
```bash
cloudgrepper -b my-bucket -v patterns.txt
```

Where `patterns.txt` contains:
```
error.*failed
warning: .*
\d{3,} ms
```

### Yara Rules

Scan with Yara rules:
```bash
cloudgrepper -b my-bucket -y rules.yar
```

### Output Modes

Default output (line-by-line with filenames):
```bash
cloudgrepper -b my-bucket -q "error"
# Output: s3://bucket/logs/app.log: 2024-01-01 ERROR: Something went wrong
```

Hide filenames:
```bash
cloudgrepper -b my-bucket -q "error" -hf
# Output: 2024-01-01 ERROR: Something went wrong
```

JSON output (JSONL, one object per match):
```bash
cloudgrepper -b my-bucket -q "error" -jo
# Output: {"key_name": "s3://bucket/logs/app.log", "query": "error", "line": "2024-01-01 ERROR: ..."}
```

## Testing

### Unit and Integration Tests

Run all tests:
```bash
cargo test
```

### Emulator Tests

cloudgrepper includes end-to-end tests against local cloud emulators (LocalStack/MinIO for S3, Azurite for Azure, fake-gcs-server for GCS). These are gated behind the `CLOUDGREPPER_EMULATOR` env flag.

Start the emulators:
```bash
docker compose -f docker/docker-compose.yml up -d
```

Run emulator tests:
```bash
CLOUDGREPPER_EMULATOR=1 cargo test --test emulator
```

Note: these tests require Docker and docker-compose to be installed and running.

### Code Quality

Check formatting and lints:
```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings
```

## Performance

Benchmarked against MinIO (local docker) with 200 × `apache_access.log` objects (`-q 'GET /wp-login' -p logs/`), mean of 3 runs:

| Tool | Workers | Mean (ms) |
|------|---------|-----------|
| cloudgrepper (Rust) | 10 (default) | 228 |
| cloudgrepper (Rust) | 32 | 237 |
| cloudgrep (Python 1.0.5) | — | 808 |

**~3.5× faster than the Python tool** at the default concurrency of 10. Raising workers to 32 shows no improvement against a local MinIO server (the bottleneck shifts to the loopback NIC, not CPU); on a real S3 bucket with higher network latency more workers will help.

**Tuning:** set `CLOUDGREPPER_WORKERS=N` (env var) to override the default of 10. Values that are zero or non-numeric are silently ignored and fall back to the default.

**Caveat:** Python cloudgrep 1.0.5 prints only the first matching line per file (`break` after the first hit), so it does strictly less output work than cloudgrepper, which reports all matching lines. The advantage shown above is conservative.

**Reproduce (requires docker compose up -d and hyperfine):**

```bash
./scripts/bench.sh 200
```

## Known Divergences from Python cloudgrep 1.0.5

The following intentional divergences exist between cloudgrepper (Rust) and Python cloudgrep 1.0.5:

1. **All matching lines are reported.** Python 1.0.5's `process_lines` uses `any(...)`, which short-circuits after the first matching line per file — grep semantics are broken in 1.0.5. cloudgrepper searches every line and reports all matches, restoring correct grep behavior.

2. **`.gz`/`.zip` decompression is always enabled.** Python 1.0.5 detects `.gz`/`.zip` from the temp-file name (which is random and extensionless), so S3 objects are never decompressed unless `-og/--use_og_name` is passed. cloudgrepper always detects compression from the object key (equivalent to Python ≤ 1.0.4, or 1.0.5 with `-og`). This is a fix for a regression in Python 1.0.5.

3. **Two-stage "matched" bookkeeping with log formats.** With a log format active (e.g., `-lt cloudtrail`), when a regex matches a raw line but no extracted record re-matches, Python still counts the file as matched; cloudgrepper counts it only when a record is actually emitted. This is invisible in CLI output (Python discards per-file hit counts) but may affect API-level comparisons.

4. **Yara `match_strings` reports matched pattern identifiers.** cloudgrepper lists matched pattern identifiers from yara-x; in JSON mode, yara output replicates Python's `str(dict)` fallback for compatibility.

5. **Naive dates are treated as UTC.** When using `--start_date`/`--end_date` without timezone info, cloudgrepper treats them as UTC. Python can crash when comparing naive and aware datetimes without `-cd/--convert_date`; cloudgrepper handles this gracefully.

6. **`--file_size` does not apply to GCS.** This Python quirk is preserved: size filtering works for S3 and Azure, but not for Google Cloud Storage. This is documented here to avoid confusion during cross-provider validation.
