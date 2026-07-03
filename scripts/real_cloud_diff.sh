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

# Resolve the python cloudgrep oracle: pip-installed, or a sibling clone.
if ! python3 -c "import cloudgrep" 2>/dev/null; then
  if [ -d "$HERE/../../cloudgrep" ]; then
    export PYTHONPATH="$HERE/../../cloudgrep${PYTHONPATH:+:$PYTHONPATH}"
  fi
fi
if ! python3 -c "import cloudgrep" 2>/dev/null; then
  echo "python cloudgrep not found. Either 'pip install cloudgrep' or clone" >&2
  echo "https://github.com/cado-security/cloudgrep as a sibling of this repo." >&2
  exit 2
fi

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
