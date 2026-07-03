#!/usr/bin/env bash
# Manual aid: diff cloudgrepper vs python cloudgrep against MinIO.
# Requires: pip install boto3 (>=1.28 for AWS_ENDPOINT_URL support).
# Caveats: Python 1.0.5 prints only the first matching line per file and
# does not decompress .gz from S3 without -og, so restrict comparisons to
# plain single-match objects for exact diffs.
set -euo pipefail
BUCKET=${1:?usage: compare_python.sh <bucket> <query>}
QUERY=${2:?usage: compare_python.sh <bucket> <query>}
export AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin
export AWS_ENDPOINT_URL=http://127.0.0.1:9000 AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
HERE="$(cd "$(dirname "$0")" && pwd)"
cargo run --quiet --manifest-path "$HERE/../Cargo.toml" -- -b "$BUCKET" -q "$QUERY" | sort > /tmp/cloudgrepper.out
(cd "$HERE/../../cloudgrep" && python3 -m cloudgrep -b "$BUCKET" -q "$QUERY") | sort > /tmp/cloudgrep.out
diff /tmp/cloudgrep.out /tmp/cloudgrepper.out && echo "OUTPUT MATCHES"
