#!/usr/bin/env bash
# Benchmark cloudgrepper vs python cloudgrep against MinIO with N copies
# of apache_access.log. Requires: docker compose up -d, hyperfine, boto3.
set -euo pipefail
N=${1:-200}
BUCKET=bench-bucket
export AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin
export AWS_ENDPOINT_URL=http://127.0.0.1:9000 AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
HERE="$(cd "$(dirname "$0")" && pwd)"
FIXTURE="$HERE/../../cloudgrep/tests/data/apache_access.log"

python3 - "$N" "$BUCKET" "$FIXTURE" <<'PY'
import sys, boto3
n, bucket, fixture = int(sys.argv[1]), sys.argv[2], sys.argv[3]
s3 = boto3.client("s3")
try:
    s3.create_bucket(Bucket=bucket)
except Exception:
    pass
body = open(fixture, "rb").read()
for i in range(n):
    s3.put_object(Bucket=bucket, Key=f"logs/{i}.log", Body=body)
print(f"seeded {n} objects")
PY

cargo build --release --manifest-path "$HERE/../Cargo.toml"
hyperfine --warmup 1 \
  "$HERE/../target/release/cloudgrepper -b $BUCKET -q 'GET /wp-login' -p logs/" \
  "python3 -m cloudgrep -b $BUCKET -q 'GET /wp-login' -p logs/" \
  --export-markdown /tmp/cloudgrepper_bench.md
cat /tmp/cloudgrepper_bench.md
