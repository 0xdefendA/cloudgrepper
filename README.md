# cloudgrepper

grep for cloud storage: search log files (optionally gzip/zip compressed) in AWS S3,
Azure Blob Storage, and Google Cloud Storage, in parallel, without indexing into a SIEM.

A faithful Rust port of [cloudgrep](https://github.com/cado-security/cloudgrep) by
Cado Security (Apache-2.0, now deprecated). Same CLI, same output; `-jo` emits streaming
JSONL. Credit and thanks to cado-security for the original design and test corpus.

License: Apache-2.0.

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
