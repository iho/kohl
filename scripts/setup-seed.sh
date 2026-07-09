#!/usr/bin/env bash
# One-time directories + stable node key for a Kohl seed or miner host.
set -euo pipefail

KOHL_BIN="${KOHL_BIN:-./target/release/kohl}"
DATA_DIR="${DATA_DIR:-/var/lib/kohl}"
KEY_FILE="${KEY_FILE:-$DATA_DIR/node-key}"

if [[ ! -x "$KOHL_BIN" && ! -f "$KOHL_BIN" ]]; then
  echo "error: kohl binary not found at $KOHL_BIN" >&2
  echo "  cargo build -p kohl-node --release" >&2
  echo "  # or: KOHL_BIN=/usr/local/bin/kohl $0" >&2
  exit 1
fi

mkdir -p "$DATA_DIR/chain"

if [[ -f "$KEY_FILE" ]]; then
  echo "node-key already exists: $KEY_FILE"
  echo "PeerId (from existing key):"
  # Substrate prints peer id on generate only; for existing keys use RPC after start
  # or re-derive with key inspect-node-key if available.
  if "$KOHL_BIN" key inspect-node-key --file "$KEY_FILE" 2>/dev/null; then
    :
  else
    echo "  (start the node and call system_localPeerId, or keep the PeerId from first generate)"
  fi
else
  echo "Generating node key → $KEY_FILE"
  # PeerId goes to stderr
  "$KOHL_BIN" key generate-node-key --file "$KEY_FILE"
  chmod 600 "$KEY_FILE"
fi

echo
echo "Next:"
echo "  1. Open TCP 30333 on the firewall"
echo "  2. Set PUBLIC_ADDR=/ip4/<your-ip>/tcp/30333 (or /dns/...)"
echo "  3. Bootnode multiaddr = PUBLIC_ADDR/p2p/<PeerId>"
echo "  4. See docs/production-bootnode.md and scripts/systemd/"
echo
echo "Example seed start:"
echo "  $KOHL_BIN --chain kohl --base-path $DATA_DIR/chain \\"
echo "    --node-key-file $KEY_FILE --validator --mining-seed <64-hex> \\"
echo "    --listen-addr /ip4/0.0.0.0/tcp/30333 \\"
echo "    --public-addr /ip4/<PUBLIC_IP>/tcp/30333"
