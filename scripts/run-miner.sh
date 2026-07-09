#!/usr/bin/env bash
# Foreground miner that dials a bootnode.
set -euo pipefail

KOHL_BIN="${KOHL_BIN:-./target/release/kohl}"
CHAIN="${CHAIN:-kohl}"
BASE_PATH="${BASE_PATH:-./data/miner}"
KEY_FILE="${KEY_FILE:-$BASE_PATH/node-key}"
BOOTNODE="${BOOTNODE:-}"
MINING_SEED="${MINING_SEED:-}"
NAME="${NAME:-kohl-miner}"
LISTEN_ADDR="${LISTEN_ADDR:-/ip4/0.0.0.0/tcp/30333}"
PUBLIC_ADDR="${PUBLIC_ADDR:-}"

if [[ -z "$BOOTNODE" ]]; then
  echo "error: set BOOTNODE multiaddr, e.g.:" >&2
  echo "  BOOTNODE=/ip4/203.0.113.10/tcp/30333/p2p/12D3KooW... $0" >&2
  exit 1
fi
if [[ -z "$MINING_SEED" ]]; then
  echo "error: set MINING_SEED to 64 hex chars" >&2
  exit 1
fi

mkdir -p "$BASE_PATH"
if [[ ! -f "$KEY_FILE" ]]; then
  "$KOHL_BIN" key generate-node-key --file "$KEY_FILE"
fi

ARGS=(
  --chain "$CHAIN"
  --base-path "$BASE_PATH"
  --node-key-file "$KEY_FILE"
  --name "$NAME"
  --validator
  --mining-seed "$MINING_SEED"
  --bootnodes "$BOOTNODE"
  --listen-addr "$LISTEN_ADDR"
  --rpc-cors localhost
)
if [[ -n "$PUBLIC_ADDR" ]]; then
  ARGS+=(--public-addr "$PUBLIC_ADDR")
fi

echo "Starting miner → bootnode $BOOTNODE"
exec "$KOHL_BIN" "${ARGS[@]}" "$@"
