#!/usr/bin/env bash
# Export a Kohl chain spec and inject bootnode multiaddrs.
#
# All built-in chains are FCMP-only fair launch (no Dual / CLSAG era).
# Host version matrix + genesis checklist: docs/fcmp-runbook.md
#
# Usage:
#   ./scripts/make-chainspec.sh --chain kohl \
#     --bootnode /ip4/203.0.113.10/tcp/30333/p2p/12D3KooW... \
#     --output chainspecs/kohl.json
#
# Miners can then run:
#   kohl --chain chainspecs/kohl.json --validator --bootnodes ...   # bootnodes also in file
#   # or just:
#   kohl --chain chainspecs/kohl.json --validator --mining-seed ...
set -euo pipefail

KOHL_BIN="${KOHL_BIN:-./target/release/kohl}"
CHAIN="kohl"
OUTPUT=""
RAW=0
BOOTNODES=()

usage() {
  sed -n '2,14p' "$0" | sed 's/^# \?//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --chain) CHAIN="$2"; shift 2 ;;
    --output|-o) OUTPUT="$2"; shift 2 ;;
    --bootnode) BOOTNODES+=("$2"); shift 2 ;;
    --raw) RAW=1; shift ;;
    --bin) KOHL_BIN="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 1 ;;
  esac
done

if [[ ! -f "$KOHL_BIN" && ! -x "$KOHL_BIN" ]]; then
  # allow PATH lookup
  if ! command -v "$KOHL_BIN" >/dev/null 2>&1; then
    echo "error: kohl binary not found: $KOHL_BIN" >&2
    exit 1
  fi
fi

if [[ ${#BOOTNODES[@]} -eq 0 ]]; then
  echo "error: pass at least one --bootnode /ip4/.../tcp/30333/p2p/<PeerId>" >&2
  exit 1
fi

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

EXPORT_ARGS=(export-chain-spec --chain "$CHAIN" --output "$TMP")
if [[ "$RAW" -eq 1 ]]; then
  EXPORT_ARGS+=(--raw)
fi

"$KOHL_BIN" "${EXPORT_ARGS[@]}"

python3 - "$TMP" "${BOOTNODES[@]}" <<'PY'
import json, sys
path = sys.argv[1]
boots = sys.argv[2:]
with open(path) as f:
    spec = json.load(f)
spec["bootNodes"] = boots
with open(path, "w") as f:
    json.dump(spec, f, indent=2)
    f.write("\n")
print(f"bootNodes ({len(boots)}):", file=sys.stderr)
for b in boots:
    print(f"  {b}", file=sys.stderr)
print(f"id={spec.get('id')} name={spec.get('name')} chainType={spec.get('chainType')}", file=sys.stderr)
PY

if [[ -n "$OUTPUT" ]]; then
  mkdir -p "$(dirname "$OUTPUT")"
  mv "$TMP" "$OUTPUT"
  trap - EXIT
  echo "Wrote $OUTPUT"
else
  cat "$TMP"
fi
