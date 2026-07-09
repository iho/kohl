# Kohl over Tor — runbook

**Audience:** operators who already run a Kohl node and want network-layer privacy  
**Last verified against:** `polkadot-stable2606` / kohl node CLI (no native `--proxy-server`)  
**Companion:** Dandelion++ (stem/fluff) is always on in the node; Tor is defence in depth.

---

## 0. Why Tor still matters

| Layer | What it hides | What it does **not** hide |
|-------|----------------|---------------------------|
| **RingCT** | sender / receiver / amount on chain | your IP when you submit or peer |
| **Dandelion++** | first-hop origin correlation on the peer graph | long-term peer identity, clearnet listeners |
| **Tor** | IP of your node (and optionally wallet) from peers & observers | bad opsec, compromised remote RPC, malware |

If you mine or submit transfers on clearnet, any peer (or ISP) can still log *that your IP talked to the p2p port*. Tor moves that traffic into the onion network.

> **Honest limits.** Tor does not make you anonymous by magic. Timing correlation, wallet reuse across clearnet/Tor, RPC left open on `0.0.0.0`, and mixing “identity” traffic with node traffic all leak. This runbook is operational hygiene, not a guarantee.

---

## 1. Threat model (pick a level)

| Level | Goal | Effort |
|-------|------|--------|
| **L1 — Outbound only** | Your node dials peers via Tor; you do **not** accept inbound onion traffic | Low |
| **L2 — Full onion node** | Inbound P2P (and optionally RPC) via Tor hidden services; no public TCP if you choose | Medium |
| **L3 — Wallet over Tor** | Wallet only talks to *your* node over an onion RPC (or SOCKS to localhost) | Low–medium |

Most solo operators want **L1 + L3**. Public bootnodes / seed operators want **L2**.

---

## 2. Prerequisites

### 2.1 Install Tor

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install -y tor

# macOS (Homebrew)
brew install tor
# or use the Tor Browser only for SOCKS — a system `tor` daemon is better for nodes
```

Default SOCKS is usually **`127.0.0.1:9050`**. Control port (optional) **`9051`**.

Check:

```bash
curl -sS --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# expect "IsTor": true
```

### 2.2 Build Kohl

```bash
cargo build -p kohl-node --release
# binary: ./target/release/kohl
```

### 2.3 CLI notes (important)

- There is **no** `--proxy-server` flag on current Kohl / Substrate (`polkadot-stable2606`). Older docs that mention it are obsolete.
- Default network backend is **`litep2p`**. For maximum multiaddr compatibility when advertising onion addresses, prefer **`--network-backend libp2p`** until you have tested onion dials on litep2p in your environment.
- P2P listen defaults are typically TCP on ports derived from the chain (often **30333**). Always set `--listen-addr` explicitly when pairing with Tor.
- RPC defaults to **localhost** — keep it that way unless you know what you are doing.

Useful flags:

| Flag | Purpose |
|------|---------|
| `--listen-addr <multiaddr>` | Where the node binds (local TCP for Tor to forward into) |
| `--public-addr <multiaddr>` | Address you **advertise** to peers (onion multiaddr) |
| `--bootnodes <multiaddr>` | Peers to dial (can be onion multiaddrs if transport allows) |
| `--rpc-port` / `--rpc-cors` | Wallet JSON-RPC (keep local or onion-only) |
| `--node-key-file` | Stable PeerId across restarts |
| `--network-backend libp2p` | Prefer for onion experiments |
| `--validator` | Author blocks / mine |
| `--mining-seed <64-hex>` | Persistent coinbase address |

---

## 3. Level 1 — Outbound via Tor (`torsocks`)

**Use when:** you only need dial-out privacy (connect to clearnet or onion peers without publishing an onion service).

### 3.1 Run the node under torsocks

```bash
# Install torsocks if needed (Debian: apt install torsocks)
torsocks ./target/release/kohl \
  --chain kohl-ash \
  --validator \
  --tmp \
  --mining-seed <64-hex> \
  --listen-addr /ip4/127.0.0.1/tcp/30333 \
  --rpc-port 9944 \
  --network-backend libp2p
```

What this does:

- All TCP from the process goes through Tor SOCKS (DNS too, with `--socks5-hostname` semantics via torsocks).
- Binding to **`127.0.0.1`** means you are **not** accepting clearnet inbound. Other nodes cannot dial you unless you set up L2.

### 3.2 Verify egress is Tor

While the node runs:

```bash
# From another shell — confirm Tor works
curl -sS --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

# Optional: watch Tor log for circuits
sudo journalctl -u tor -f   # systemd
# or: tail -f /usr/local/var/log/tor.log  (Homebrew paths vary)
```

In Kohl logs you should eventually see peer connections (if bootnodes / DHT peers exist). On a quiet testnet with no peers, “no peers” is expected — that is not a Tor failure.

### 3.3 Caveats (L1)

- `torsocks` can break UDP; Substrate p2p is TCP-oriented so this is usually fine.
- Some platforms’ `torsocks` are flaky with multi-threaded runtimes. If the node fails to dial, use L2’s SOCKS-isolation approach (network namespace / `IsolateDestAddr`) or run Tor as a transparent proxy (advanced).
- You still need **bootnodes** that are reachable from Tor (clearnet TCP via Tor exit, or onion).

---

## 4. Level 2 — Onion service for P2P (and optional RPC)

**Use when:** you want peers to dial *you* without learning your IP.

### 4.1 Tor hidden service config

Edit Tor config (`/etc/tor/torrc` or Homebrew’s `torrc`):

```torrc
## SOCKS for local tools / wallets
SocksPort 9050

## P2P onion → local Kohl listen port
HiddenServiceDir /var/lib/tor/kohl-p2p/
HiddenServicePort 30333 127.0.0.1:30333

## Optional: separate RPC onion (wallet only; never share publicly if unlocked)
# HiddenServiceDir /var/lib/tor/kohl-rpc/
# HiddenServicePort 9944 127.0.0.1:9944
```

Restart Tor and read the hostname:

```bash
sudo cat /var/lib/tor/kohl-p2p/hostname
# e.g. abcdef...xyz.onion
```

macOS Homebrew example paths:

```bash
# brew services start tor
cat "$(brew --prefix)/var/lib/tor/kohl-p2p/hostname"  # if you set HiddenServiceDir there
```

### 4.2 Stable PeerId

```bash
mkdir -p ~/.kohl
# Generate once; back this file up offline
./target/release/kohl key generate-node-key --file ~/.kohl/node-key
```

Note the printed **PeerId** (or run the node once and read logs / `system_localPeerId` RPC).

### 4.3 Start Kohl bound only to localhost

```bash
ONION=$(sudo cat /var/lib/tor/kohl-p2p/hostname)   # no trailing newline issues: tr -d '\n'
PEER_ID="<your-peer-id>"

./target/release/kohl \
  --chain kohl-ash \
  --validator \
  --base-path ~/.kohl/chain \
  --node-key-file ~/.kohl/node-key \
  --listen-addr /ip4/127.0.0.1/tcp/30333 \
  --public-addr "/onion3/${ONION%.onion}:30333" \
  --rpc-port 9944 \
  --rpc-cors localhost \
  --network-backend libp2p \
  --mining-seed <64-hex>
```

Multiaddr forms (pick what your stack accepts):

```text
/onion3/<56-char-v3-without-.onion>:<port>
/onion3/<56-char-v3-without-.onion>:<port>/p2p/<PeerId>
```

Use **`--public-addr`** so other nodes learn the onion address. The `.onion` suffix is **not** part of the multiaddr hash field — multiaddr uses the 56-character v3 name without `.onion`.

Example:

```text
hostname:  abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion
multiaddr: /onion3/abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv:30333/p2p/12D3KooW...
```

### 4.4 Bootnode string to give others

```text
/onion3/<v3>:<port>/p2p/<PeerId>
```

Peers run:

```bash
./target/release/kohl ... \
  --bootnodes "/onion3/<v3>:30333/p2p/<PeerId>" \
  --network-backend libp2p
```

They still need **a way to dial onion** (their own Tor + working onion transport, or torsocks, or a SOCKS-aware stack).

### 4.5 Optional RPC onion

If you enabled `kohl-rpc` hidden service:

```bash
# Wallet host only reaches RPC via Tor SOCKS → onion:9944
# Never expose author_* / unsafe RPCs on a public onion without auth.
```

Keep RPC methods restricted; treat an onion RPC like a password-less private URL — anyone who learns the `.onion` can call it.

---

## 5. Level 3 — Wallet / RPC over Tor

### 5.1 Wallet on the same machine as the node

Simplest: RPC on `127.0.0.1:9944`, wallet uses `http://127.0.0.1:9944`. No Tor needed for the last hop (node already Tor-isolated).

### 5.2 Wallet on another host

1. Node exposes RPC only on localhost + RPC onion (L2).
2. Wallet uses Tor SOCKS:

```bash
# Example with curl; point your wallet HTTP client at the same SOCKS proxy
curl --socks5-hostname 127.0.0.1:9050 \
  -H 'content-type: application/json' \
  -d '{"id":1,"jsonrpc":"2.0","method":"system_health","params":[]}' \
  http://<rpc-onion-host>.onion:9944
```

Prefer a remote full node **you** control. A third-party public RPC undoes much of your network privacy regardless of Tor.

### 5.3 Opsec for wallets

- Do not open the same wallet on clearnet RPC and Tor RPC in a way that links identities.
- Do not paste onion addresses into clearnet browsers that bypass Tor.
- Prefer one machine role: “node” vs “daily browsing”.

---

## 6. Suggested profiles

### 6.1 Solo miner (quiet)

```bash
# Tor daemon running with SocksPort 9050
torsocks ./target/release/kohl \
  --chain kohl-ash \
  --validator \
  --base-path ~/.kohl/chain \
  --node-key-file ~/.kohl/node-key \
  --listen-addr /ip4/127.0.0.1/tcp/30333 \
  --rpc-port 9944 \
  --network-backend libp2p \
  --mining-seed <64-hex>
```

### 6.2 Reachable onion seed / peer

Tor `HiddenServicePort 30333 127.0.0.1:30333` +:

```bash
./target/release/kohl \
  --chain kohl-ash \
  --base-path ~/.kohl/seed \
  --node-key-file ~/.kohl/node-key \
  --listen-addr /ip4/127.0.0.1/tcp/30333 \
  --public-addr "/onion3/<v3>:30333" \
  --rpc-port 9944 \
  --network-backend libp2p
```

Publish only the `/onion3/.../p2p/...` multiaddr, never your clearnet IP.

### 6.3 Dev smoke (no Tor)

```bash
./target/release/kohl --dev --validator --tmp --mining-seed <64-hex>
```

Use this for local crypto/mining tests only.

---

## 7. Verification checklist

- [ ] `curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip` → `IsTor: true`
- [ ] Kohl `--listen-addr` is `127.0.0.1` (or another non-routable bind) when using onion
- [ ] Tor `HiddenServicePort` target matches Kohl listen host:port
- [ ] `hostname` file exists; multiaddr uses 56-char v3 **without** `.onion`
- [ ] PeerId stable via `--node-key-file`
- [ ] RPC not on `0.0.0.0` unless intentional and filtered
- [ ] Wallet path does not mix clearnet third-party RPC with “private” use
- [ ] Logs show Dandelion++ enabled (`kohl::dandelion`) — independent of Tor

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| No peers | Empty network / wrong bootnodes | Use known onion or clearnet bootnodes; confirm chain id |
| Onion peers never connect | Backend/transport cannot dial onion | Try `--network-backend libp2p`; ensure client uses Tor |
| Hidden service “not found” | Tor not restarted / wrong dir perms | `HiddenServiceDir` owned by tor user; restart tor |
| RPC works locally, not via onion | Wrong `HiddenServicePort` or RPC bind | RPC must listen on the address Tor targets (`127.0.0.1:9944`) |
| torsocks crashes / hangs | TLS or multi-thread issues | Prefer onion HS + direct local bind; or OS-level Tor routing |
| “Connection refused” to 30333 | Kohl not listening yet / wrong port | Match `--listen-addr` port to `HiddenServicePort` |

---

## 9. What we deliberately do **not** recommend

- Exposing full RPC (especially `author_*`) on a public clearnet interface “because Tor is hard”.
- Sharing one onion between unrelated wallets and a public explorer.
- Believing Dandelion++ alone replaces Tor (or vice versa).
- Documenting a fake `--proxy-server` flag — **it is not available** on current Kohl builds.

---

## 10. Related docs

| Doc | Contents |
|-----|----------|
| [README.md](../README.md) | Quick start, Dandelion++ summary |
| [BLUEPRINT.md](../BLUEPRINT.md) | Architecture & privacy limitations |
| [GLOSSARY.md](../GLOSSARY.md) | Terms (Dandelion++, stealth, CLSAG, …) |
| `node/src/dandelion/` | Stem/fluff implementation |

---

## 11. Minimal copy-paste (L2 skeleton)

```bash
# 1) torrc
# HiddenServiceDir /var/lib/tor/kohl-p2p/
# HiddenServicePort 30333 127.0.0.1:30333
# SocksPort 9050
# then: sudo systemctl restart tor

ONION=$(sudo cat /var/lib/tor/kohl-p2p/hostname | tr -d '\n' | sed 's/\.onion$//')

./target/release/kohl \
  --chain kohl-ash \
  --validator \
  --base-path ~/.kohl/chain \
  --node-key-file ~/.kohl/node-key \
  --listen-addr /ip4/127.0.0.1/tcp/30333 \
  --public-addr "/onion3/${ONION}:30333" \
  --rpc-port 9944 \
  --network-backend libp2p \
  --mining-seed <64-hex>
```

When you have a PeerId, publish:

```text
/onion3/${ONION}:30333/p2p/<PeerId>
```
