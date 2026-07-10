# Production bootnode / public seed — runbook

How to run a **public Kohl node** that miners and other full nodes can dial.

---

## 0. Choose the chain

| Spec | CLI | Initial difficulty | Use for |
|------|-----|--------------------|---------|
| **mainnet** | `--chain kohl` or `--chain mainnet` | `50_000_000` | Real public network |
| **kohl-ash** | `--chain kohl-ash` | `100_000` | Multi-node smoke / public testnet |
| **dev** | `--dev` | low | Single-machine only — **not** for public peers |

Miners and seeds **must use the same chain id and genesis**. Mismatched specs = different networks.

All presets are **FCMP-only** (no Dual / CLSAG spend path). Host version matrix, genesis checklist, and re-genesis policy: **[fcmp-runbook.md](fcmp-runbook.md)**.

> **Mainnet is a fair launch** (zero genesis supply). Whoever starts mining first is the start of that history. Coordinate a public “genesis moment” if you care about a shared start; the binary does not enforce a start time.

---

## 1. Server checklist

- Linux VPS with a **stable public IPv4** (IPv6 optional)
- Open **TCP 30333** (P2P) from the internet
- **Do not** open JSON-RPC (`9944`) to the world unless you put a filter in front
- Disk for chain DB (`--base-path`); SSD preferred
- For real RandomX mining on this host: build with `--features randomx` and a capable CPU
- A seed can be **non-mining** (relay only) or **mining** (`--validator` + `--mining-seed`)

---

## 2. One-time setup on the seed server

```bash
# Build (release). RandomX optional on a pure seed; required for serious mining.
cargo build -p kohl-node --release
# Mining seed machine:
# cargo build -p kohl-node --release --features randomx

mkdir -p /var/lib/kohl
# Stable PeerId — back this file up offline
./target/release/kohl key generate-node-key --file /var/lib/kohl/node-key
# stderr prints PeerId, e.g. 12D3KooW...
```

Note:

- **Public IP** (or DNS A record), e.g. `203.0.113.10` or `seed.kohl.network`
- **PeerId** from the command above

Firewall:

```bash
# example ufw
sudo ufw allow 30333/tcp
sudo ufw allow OpenSSH
sudo ufw enable
# RPC stays closed on the public interface
```

---

## 3. Start the public seed

### 3.1 Mining seed (authors blocks + relays)

```bash
PUBLIC_IP=203.0.113.10          # your real public IP or hostname resolved by peers
PEER_ID=12D3KooW...             # from generate-node-key

./target/release/kohl \
  --chain kohl \
  --base-path /var/lib/kohl/chain \
  --node-key-file /var/lib/kohl/node-key \
  --name kohl-seed-1 \
  --validator \
  --mining-seed <64-hex-wallet-seed> \
  --listen-addr /ip4/0.0.0.0/tcp/30333 \
  --public-addr /ip4/${PUBLIC_IP}/tcp/30333 \
  --rpc-port 9944 \
  --rpc-cors localhost \
  --prometheus-port 9615
```

- `--listen-addr /ip4/0.0.0.0/tcp/30333` — accept P2P from the internet  
- `--public-addr ...` — address **advertised** to peers (use the IP others can route to)  
- RPC defaults to **localhost** — miners do **not** need your RPC; they need P2P  

### 3.2 Relay-only seed (no mining)

Omit `--validator` and `--mining-seed` if you only want connectivity (still useful as a bootnode). For PoW chains, at least some nodes must mine or the chain stalls.

### 3.3 systemd unit (sketch)

```ini
# /etc/systemd/system/kohl.service
[Unit]
Description=Kohl mainnet seed
After=network-online.target
Wants=network-online.target

[Service]
User=kohl
Group=kohl
Type=simple
ExecStart=/usr/local/bin/kohl \
  --chain kohl \
  --base-path /var/lib/kohl/chain \
  --node-key-file /var/lib/kohl/node-key \
  --name kohl-seed-1 \
  --validator \
  --mining-seed /run/secrets/kohl-mining-seed-contents-or-env \
  --listen-addr /ip4/0.0.0.0/tcp/30333 \
  --public-addr /ip4/203.0.113.10/tcp/30333 \
  --rpc-cors localhost
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Prefer loading `--mining-seed` from a root-only file or secret manager, not a world-readable unit file.

---

## 4. Bootnode multiaddr (give this to miners)

Format:

```text
/ip4/<PUBLIC_IP>/tcp/30333/p2p/<PEER_ID>
```

Example:

```text
/ip4/203.0.113.10/tcp/30333/p2p/12D3KooWSupkuQsnozTSyvBbTjo2xjs2U6tsVJganuRKCq1TRCbD
```

If you use DNS that resolves to the seed:

```text
/dns/seed.kohl.network/tcp/30333/p2p/<PEER_ID>
```

Publish it on the website, Discord, README, etc.

---

## 5. How a miner connects

On each miner machine:

```bash
cargo build -p kohl-node --release --features randomx

./target/release/kohl \
  --chain kohl \
  --base-path ~/.kohl/miner1 \
  --validator \
  --mining-seed <their-64-hex-seed> \
  --bootnodes /ip4/203.0.113.10/tcp/30333/p2p/12D3KooW... \
  --listen-addr /ip4/0.0.0.0/tcp/30333 \
  --public-addr /ip4/<miner-public-ip>/tcp/30333 \
  --rpc-cors localhost
```

Notes:

- **Same** `--chain kohl` as the seed  
- `--bootnodes` is how they find the network before DHT/gossip fills in  
- Miners that are behind NAT should still set a reachable `--public-addr` if possible, or rely on dialing out to the seed  
- Multiple bootnodes: repeat `--bootnodes addr1 --bootnodes addr2`

### Verify connectivity

On the seed (RPC local):

```bash
curl -sH 'content-type: application/json' \
  -d '{"id":1,"jsonrpc":"2.0","method":"system_health","params":[]}' \
  http://127.0.0.1:9944

curl -sH 'content-type: application/json' \
  -d '{"id":1,"jsonrpc":"2.0","method":"system_peers","params":[]}' \
  http://127.0.0.1:9944
```

Expect `peers > 0` once a miner has connected. Logs should show inbound sessions and, if mining, block import / seal lines.

---

## 6. Bake bootnodes into a chain spec (recommended)

So miners can use a JSON file instead of pasting multiaddrs:

```bash
cargo build -p kohl-node --release

# PeerId of an existing key:
./target/release/kohl key inspect-node-key --file /var/lib/kohl/node-key

./scripts/make-chainspec.sh \
  --chain kohl \
  --bootnode /ip4/YOUR.IP/tcp/30333/p2p/12D3KooW... \
  --output chainspecs/kohl.json
```

Miners:

```bash
./target/release/kohl \
  --chain ./chainspecs/kohl.json \
  --validator \
  --mining-seed <64-hex>
```

See [chainspecs/README.md](../chainspecs/README.md).

---

## 7. Scripts & systemd

| Path | Purpose |
|------|---------|
| [`scripts/setup-seed.sh`](../scripts/setup-seed.sh) | Create data dir + node key |
| [`scripts/run-seed.sh`](../scripts/run-seed.sh) | Foreground public seed |
| [`scripts/run-miner.sh`](../scripts/run-miner.sh) | Foreground miner → bootnode |
| [`scripts/make-chainspec.sh`](../scripts/make-chainspec.sh) | Export JSON + inject `bootNodes` |
| [`scripts/systemd/kohl-seed.service`](../scripts/systemd/kohl-seed.service) | Production seed unit |
| [`scripts/systemd/kohl-miner.service`](../scripts/systemd/kohl-miner.service) | Production miner unit |

### systemd seed (summary)

```bash
sudo useradd --system --home /var/lib/kohl --shell /usr/sbin/nologin kohl || true
sudo mkdir -p /var/lib/kohl /etc/kohl
sudo cp target/release/kohl /usr/local/bin/kohl
sudo -u kohl KOHL_BIN=/usr/local/bin/kohl DATA_DIR=/var/lib/kohl ./scripts/setup-seed.sh
sudo cp scripts/systemd/kohl-seed.service /etc/systemd/system/
sudo cp scripts/systemd/kohl-seed.env.example /etc/kohl/seed.env
sudoedit /etc/kohl/seed.env   # PUBLIC_ADDR, MINING_SEED
sudo chmod 600 /etc/kohl/seed.env
sudo chown -R kohl:kohl /var/lib/kohl
sudo systemctl daemon-reload
sudo systemctl enable --now kohl-seed
journalctl -u kohl-seed -f
```

### Foreground (no systemd)

```bash
# Seed
PUBLIC_ADDR=/ip4/YOUR.IP/tcp/30333 \
MINING_SEED=<64-hex> \
  ./scripts/run-seed.sh

# Miner (other machine)
BOOTNODE=/ip4/YOUR.IP/tcp/30333/p2p/12D3KooW... \
MINING_SEED=<64-hex> \
  ./scripts/run-miner.sh
```

---

## 8. Security (public seed)

| Do | Don’t |
|----|--------|
| Open **30333/tcp** only for P2P | Bind unsafe RPC to `0.0.0.0` |
| Keep RPC on localhost / VPN / onion | Share `--mining-seed` or node-key |
| Use `--node-key-file` (stable PeerId) | Use `--tmp` on production (wipes state) |
| Run under a dedicated user + systemd | Run as root without need |
| Monitor disk growth of `--base-path` | Assume “mainnet” is immutable without social consensus |

Public RPC (if you must): reverse proxy, `safe` methods only, rate limits — see Substrate RPC docs. Prefer miners running their **own** full node.

---

## 9. Tor seed instead of clearnet

If the seed should not reveal a clearnet IP, use an onion bootnode instead of `/ip4/...`. See [tor-runbook.md](tor-runbook.md) (L2) and publish:

```text
/onion3/<v3>:30333/p2p/<PEER_ID>
```

Miners then need Tor-capable dial (e.g. `torsocks` + `--network-backend libp2p`).

---

## 10. Minimal “go live” sequence

1. Provision VPS, open **30333/tcp**.  
2. `./scripts/setup-seed.sh` (or `generate-node-key`) → save PeerId + key file.  
3. Start seed: `PUBLIC_ADDR=/ip4/<IP>/tcp/30333 MINING_SEED=... ./scripts/run-seed.sh`  
   or enable `kohl-seed.service`.  
4. Confirm local RPC health; confirm listen on 30333 (`ss -lntp | grep 30333`).  
5. `./scripts/make-chainspec.sh --bootnode /ip4/<IP>/tcp/30333/p2p/<PeerId> -o chainspecs/kohl.json`  
6. Publish multiaddr + optional chainspec.  
7. Second machine: `BOOTNODE=... MINING_SEED=... ./scripts/run-miner.sh` (same chain).  
8. Confirm `system_peers` ≥ 1 and blocks advance while mining.

---

## Related

| Doc | Contents |
|-----|----------|
| [README.md](../README.md) | Build, dev chain, Dandelion++ |
| [tor-runbook.md](tor-runbook.md) | Tor outbound / onion |
| [chainspecs/README.md](../chainspecs/README.md) | Distributing JSON specs |
| [BLUEPRINT.md](../BLUEPRINT.md) | Tokenomics, consensus |
