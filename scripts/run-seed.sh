#!/usr/bin/env bash
# Foreground public seed (dev/ops convenience; prefer systemd in production).
set -euo pipefail

KOHL_BIN="${KOHL_BIN:-./target/release/kohl}"
CHAIN="${CHAIN:-kohl}"
BASE_PATH="${BASE_PATH:-./data/seed}"
KEY_FILE="${KEY_FILE:-$BASE_PATH/node-key}"
LISTEN_ADDR="${LISTEN_ADDR:-/ip4/0.0.0.0/tcp/30333}"
PUBLIC_ADDR="${PUBLIC_ADDR:-}"
MINING_SEED="${MINING_SEED:-}"
NAME="${NAME:-kohl-seed}"

if [[ -z "$PUBLIC_ADDR" ]]; then
  echo "error: set PUBLIC_ADDR to the multiaddr peers dial, e.g.:" >&2
  echo "  PUBLIC_ADDR=/ip4/203.0.113.10/tcp/30333 $0" >&2
  exit 1
fi

mkdir -p "$BASE_PATH"
if [[ ! -f "$KEY_FILE" ]]; then
  echo "Generating $KEY_FILE"
  "$KOHL_BIN" key generate-node-key --file "$KEY_FILE"
fi

ARGS=(
  --chain "$CHAIN"
  --base-path "$BASE_PATH"
  --node-key-file "$KEY_FILE"
  --name "$NAME"
  --listen-addr "$LISTEN_ADDR"
  --public-addr "$PUBLIC_ADDR"
  --rpc-cors localhost
)

if [[ -n "$MINING_SEED" ]]; then
  ARGS+=(--validator --mining-seed "$MINING_SEED")
fi

echo "Starting seed: chain=$CHAIN public=$PUBLIC_ADDR"
exec "$KOHL_BIN" "${ARGS[@]}" "$@"
