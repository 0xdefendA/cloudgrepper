# cloudgrepper

grep for cloud storage: search log files (optionally gzip/zip compressed) in AWS S3,
Azure Blob Storage, and Google Cloud Storage, in parallel, without indexing into a SIEM.

A faithful Rust port of [cloudgrep](https://github.com/cado-security/cloudgrep) by
Cado Security (Apache-2.0, now deprecated). Same CLI, same output; `-jo` emits streaming
JSONL. Credit and thanks to cado-security for the original design and test corpus.

License: Apache-2.0.
