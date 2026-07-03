#!/usr/bin/env bash
# Milestone 9: validate cloudgrepper against python cloudgrep on a REAL
# bucket you own. Usage:
#   scripts/real_cloud_diff.sh s3 <bucket> <query> [extra flags...]
#   scripts/real_cloud_diff.sh azure <account> <container> <query> [extra...]
#   scripts/real_cloud_diff.sh gcs <bucket> <query> [extra...]
# Requires: pip install cloudgrep (or run from ../cloudgrep), cargo build --release.
set -euo pipefail
MODE=${1:?mode: s3|azure|gcs}; shift
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/../target/release/cloudgrepper"
case "$MODE" in
  s3)    ARGS=(-b "$1" -q "$2"); shift 2 ;;
  azure) ARGS=(-an "$1" -cn "$2" -q "$3"); shift 3 ;;
  gcs)   ARGS=(-gb "$1" -q "$2"); shift 2 ;;
  *) echo "unknown mode $MODE" >&2; exit 2 ;;
esac
ARGS+=("$@")
"$BIN" "${ARGS[@]}" 2>/dev/null | sort > /tmp/cloudgrepper.real.out
python3 -m cloudgrep "${ARGS[@]}" 2>/dev/null | sort > /tmp/cloudgrep.real.out
echo "--- diff (python vs rust) ---"
diff /tmp/cloudgrep.real.out /tmp/cloudgrepper.real.out && echo "OUTPUT MATCHES"
echo "Expected diffs: rust reports ALL matching lines; python only the first"
echo "per file, and skips .gz decompression without -og (see README)."
