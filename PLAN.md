# pairmesh — PLAN.md (`pms` + `pmc` on top of tailcat)

## 0. Goal (one paragraph)

Expose anything on a private machine to the internet via a public VM with great UX and sane security. Two tiny CLIs: `pms` (server, runs on VM, always embeds its own DERP relay + Caddy edge) and `pmc` (client, runs on laptop, imports `tailcat` lib). Pair once with a single-use code, then daily use is `pmc 3000 --as next` → `https://next.pairmesh.com`. Own code stays small: crypto/NAT-traversal = tailcat, TLS/wildcard/H1+H2+H3 = Caddy, relay = embedded derper. We only write pairing, bridge (Caddy ↔ tailcat), keepalive/reconnect, CLI/config, installer/systemd.

Non-goals: multi-tenant, dashboard, custom mux/crypto, QUIC termination by hand, SOCKS5/LB/plugins (frp sprawl).

## 1. Architecture

```
browser --TCP 80/443 + UDP 443--> pms (VM, linux only, runs as root for :443)
  TCP :443 = Caddy layer4 SNI split (caddy-l4 module, no custom TLS parsing):
    derp.<domain>  → derper 127.0.0.1:443 (own LE cert, see Certs below)
    everything else → Caddy https 127.0.0.1:24443
  TCP :80 = Caddy: /.well-known/acme-challenge/* for derp.<domain> →
    derper 127.0.0.1:18080 (answers its own HTTP-01); rest → 404.
  UDP :3478 = standalone STUN reflector (pms, on tailscale's stunserver
    pkg). derper's own STUN would sit on loopback with our -a — useless
    for NAT discovery. This public one enables direct P2P; without it
    everything still works, relayed via DERP.
  bridge 127.0.0.1:13xxx = tailcat.Client → pmc
                                          --tailcat (WG + PSK + magicsock, DERP rendezvous, direct UDP upgrade)-->
                                   pmc (laptop: `tailcat serve` + expose registry) --> localhost:3000/5432/...
```

* `pms` manages 3 things in one binary: `derper` subprocess, Caddy
  subprocess (our build WITH `github.com/mholt/caddy-l4`, generated
  Caddyfile), and bridge loop (`tailcat.Client` → forwards Caddy and
  public ports dial).
* Platforms: server `pms`+caddy+derper = linux amd64/arm64 only.
  Client `pmc` = linux+darwin (amd64/arm64), pure Go, no caddy dep.
* Why a split is needed at all (blocks release otherwise): derper must terminate its own TLS on 443 and is documented proxy-incompatible (`tailscale/cmd/derper/README.md:37-39`); Caddy also needs 443. `reverse_proxy` to derper is **not viable**. Fix is Caddy's own layer4 SNI route (frp pattern, zero custom parsing). Alternative of derper on :8443+manual+custom-derpmap is rejected: odd-port egress filtering breaks DERP fallback where 443 passes. Two-public-IP setup remains a possible future escape hatch, not the default.
* Certs: derper issues and rotates its own LE cert (`--certmode=letsencrypt`,
  `-a 127.0.0.1:443` so TLS is on). HTTP-01 reaches it because Caddy
  proxies `/.well-known/acme-challenge/*` for derp.<domain> to derper's
  localhost mux — plain HTTP routes by Host, so no SNI problem and no
  issuer fight. No file syncing, no derper restarts. Never run two issuers
  for one name. Self-signed/`sha256-raw` derper nodes are dev-only —
  production needs the publicly-trusted hostname.
* `pmc` wraps `tailcat.Server` (`OnTCP`/`OnUDP`) + persistent `~/.config/pmc/` keys + expose table. No inbound ports, no root, userspace only.
* Multi-client, closed group (updated): any number of `pmc` devices pair to one `pms`. After pairing, every paired device can reach every other paired device's served ports — full mesh, zero per-peer config. `pms` is the trusted introducer + directory (`name → {pubkey, fullAddr, online}`); data goes P2P (direct UDP when possible, own-derper relay otherwise). Public web edge (Caddy) is one use of the mesh; device-to-device (`pmc ssh <name>`) is the other. No tenant isolation — one trust domain per `pms`.
* Default DERP is **never** used in prod: `pms init` bakes the embedded DERP hostname into full (self-contained) tokens (`--full-address` form, no client map fetch). Public `tailcat.dev` map only as dev fallback with loud warning. Pin tailcat lib + derper build to the same upstream rev and upgrade together (`--verify-clients` needs same-rev tailscaled; we skip it — tailcat `--allow` is the gate).
* tailcat is wrapped behind our `bridge` interface (no direct imports outside `internal/bridge`). Upstream promises no API/CLI/wire stability (`tailcat.go:29-33`); pin `go.mod`, expect gVisor/Tailscale bumps to break reflect hacks. Build with upstream release tags (`build-tags.txt`, `-tags "$(cat build-tags.txt)" -ldflags "-s -w"`).

## 2. CLI / UX spec (final names)

Both installed as 3-letter commands. `pairmesh` is repo name only. `pmc` with no args = help. Every command prints the next command. Same flag names as config keys.

```
# VM
pms init --domain pairmesh.com --email you@mail.com
pms pair            # prints: pmc pair <single-use-code>  (10 min TTL, burned on use)
pms devices         # paired devices + presence + exposes
pms unpair <name>   # revoke (allowlist refresh ≤30s)
pms lock|unlock     # close/open enrollment
pms status          # domain + daemon health
pms run             # daemon (systemd runs this; logs via journalctl -u pms)

# laptop
pmc pair <code>     # once, no args — auto-named (hostname + short id), prints: paired as `kabir-tp-a1b2`
pmc 3000 --as next  # → https://next.pairmesh.com → localhost:3000 (shorthand for expose)
pmc expose 5432 --tcp 5432  # → <domain>:5432 → localhost:5432 (raw TCP)
pmc expose 53 --udp 53      # raw UDP (DNS/game/WG/H3-origin)
pmc serve ssh       # serve this box's sshd to the mesh (key auth, no public port)
pmc unserve ssh     # stop serving sshd
pmc ssh <name>      # dial a paired device by name, no token — e.g. pmc ssh kabir-tp-a1b2
pmc devices         # paired devices + online + direct/relay
pmc list            # exposes + healthy/direct-vs-relay
pmc status          # tunnel, last handshake, reconnect count
pmc rename <name>   # optional rename (unique LDH, collision-checked)
pmc unexpose next
pmc up -d / pmc down                # daemon from config file
```

Rules: `pmc 3000` with no `--as` auto-names (`p3000.<domain>` or `next` collision-checked). Errors prescribe fixes (`UDP 443 blocked → H3 off, H2 ok`, `*.domain not pointing here → set A record`). `status` always shows `direct|relay` + RTT.

## 3. Auth (one-time pairing) + auto-mesh

* `pms pair` generates 256-bit random `pair-<base62>` + expiry (10 min) + single-use flag in `/var/lib/pms/pair.db` (0600). Prints `pmc pair <code>`. Pairing takes **no arguments** — the client never passes a name. The code is the sole gate: share over a private channel only.
* `pmc pair <code>`: client derives the DERP host from the pairing URL and builds a persistent serving keypair + PSK (stable `tc...` address, fixed region so it stays valid), presents the code to `POST /_pms/pair` over TLS. Server verifies (constant-time), validates the pubkey parses, and upserts by pubkey: first pair auto-assigns a name (`sanitized-hostname + 4-hex`, collision-checked, e.g. `kabir-tp-a1b2`); re-pairing the same key keeps the name and rotates token + address (old bearer dies, no orphan entries). Returns `{name, token, derp_host, domain}`. Client prints `paired as <name> — rename anytime: pmc rename <name>` (`POST /_pms/rename`, conflict → 409). Rename is optional, never blocking.
* Mesh policy: **allow-all within the trust domain**. Every serving `pmc` sets `AllowedClients` = all directory pubkeys, refreshed on change (poll `pms` every 30 s, restart only on diff, disk-cached across outages; `pms` pushes on pair/unpair via revision). Any paired device dials any other by name (`pmc ssh <name>` = auth'd directory lookup → lib dial, one refresh-and-retry per connection on dial failure; tokens never shown). TOFU pin per peer (changed key aborts; unattended stdin aborts — never auto-trust on EOF). `pms devices` / `pms unpair <name>` manage membership; `pms lock` closes enrollment (mint + verify refuse).
* Key discipline (footgun): upstream silently reuses saved `default`/`client-default` keys when present. `pms`/`pmc` always pass explicit keys and log `ephemeral|saved:<name>` at startup. PSK stays on (never `--psk=false`; false is v0.5-compat only and drops PQ + DERP-operator protection).
* Rate-limit pairing endpoint 5/min/IP (`x/time/rate`), identical error strings + jitter, no oracle. Brute-force test required.
* Rotation: `pms pair --rotate` re-keys server, invalidates old tokens; `pms unpair <name>` removes one device and pushes a fresh allowlist to the rest; `pms lock`/`pms unlock` closes/opens enrollment.

## 4. Forwarding semantics (what "route anything" means)

* Web (`pmc 3000 --as next`): Caddy terminates H1+H2+H3 at edge (UDP 443 open = H3 free, `Alt-Svc` automatic), `reverse_proxy 127.0.0.1:13xxx`, injects `X-Forwarded-For/Proto/Host`, preserves `Host`, passes `Upgrade: websocket` (WSS free). Tunnel leg is H1 over tailcat TCP. Origin stays H1 — no user change.
* Custom domains (`pmc expose 3773 --host t3.example.com`): any hostname whose DNS points at us; same site template, LE HTTP-01 like the rest (proven live). First claimant wins a host; conflicts log loudly.
* Wildcard (`*.example.com`): NOT yet — LE forbids HTTP-01 for wildcards, so it needs DNS-01: provider API credentials + caddy rebuilt with the matching `caddy-dns/<provider>` plugin + a `tls { dns … }` render change. Per-host certs (current) cover the same ground with ~30–60 s issuance each and 50/week/domain budget; wildcard becomes worth it past dozens of hosts or for instant subdomains.
* TCP (`--tcp`): `pms` binds the public port directly (`:<pub> → tailcat (device, local)`); reconcile prunes on removal and recreates failed listeners each tick. Carries TLS/SNI/SSH/H2 — opaque bytes. First claimant wins a port; conflicts log loudly.
* UDP (`--udp`): `pms` binds `:<pub>/udp` directly; bridge uses the **lib directly** (`DialUDPPort`/`OnUDP` + `ProxyPacketConns`) — the `tailcat forward` CLI is **TCP-only** (`cmd/tailcat/forward.go`), so no CLI wrapping for UDP. `ConnPacketConn` = connected, boundaries preserved; constraints inherited: payload ≤ `MaxUDPPayload` 1232 B (1280−40−8; larger = dropped, no fragmentation), server idle close after `DefaultUDPIdleTimeout` 2 m, client reaps quiet flows at 90 s (re-dial on next datagram; transport NAT keepalives are magicsock's job, not ours). H3-origin passthrough (UDP 443 → origin) supported; edge H3 termination (above) is the default for web.
* TCP specifics: `OnTCP`/`OnTCPForward`/`OnUDP`/`OnUDPForward` must be set before `Start` (nil = RST/drop); `DrainTCP` on both ends before exit or FIN is lost (CLI uses 5 s); `ProxyConns` half-close aware. Netstack is userspace gVisor — expect lower throughput than kernel; DERP fallback is rate-limited with no SLA (direct path is the fast path; `DiscoPing.Endpoint != ""` = direct).
* Unknown Host/SNI → 404/close, no default backend. No regex routing: exact > longest `*.example.com` (single-label) only.

## 5. Reliability / durability

* Reconnect: daemon heartbeats every 30 s (presence + exposes), allowlist refreshes every 30 s (restart serving only on diff; disk cache bridges `pms` outages), reconcile heals dead listeners every 15 s, DERP backoff is tailcat-internal. `pmc status` shows daemon state; `DiscoPing` reports direct-vs-relay.
* Timeouts: 10 s dial/handshake deadline everywhere (pairing, tailcat dials, splitter peek, SNI backend dial); 15 s control-plane HTTP client; 3 s `pms status`; 90 s quiet-UDP reap; 5 s admin ReadHeaderTimeout.
* Shutdown: `SIGINT/SIGTERM` → cancel (listeners close, forwards drop) → 15 s admin drain → close tailcat → Caddy/derper SIGINT. Tracked conns close so stop never hangs on idle keepalives.
* Supervisor: systemd units (`Restart=always`; pms needs root for :443, pmc runs as user), loopback-only health (`127.0.0.1:18923/healthz`), `slog`-style plain logs, secret-free (pubkey prefixes + names only).

## 6. Security (sensitive-workload bar)

* TLS 1.3 only at edge (Caddy) + WireGuard E2E inside; `X25519`, no cipher tuning (Go/Caddy defaults). Never `InsecureSkipVerify`. Secrets from file 0600 or env, never URL/query/logs.
* No public metrics/debug. Pairing endpoint via Caddy with rate-limit; bridge admin on loopback.
* Privilege drop after bind (systemd `DynamicUser=nobody`), `TAILCAT_PEER_KEY` propagated for audit, SFTP/`exec` services **off** — only `serve <ports>` + `forward`.
* Threat model doc + `SECURITY.md`: DERP operator sees pubkeys/metadata (not payload with PSK); token leak = dial capability until rotation + allowlist refresh; DNS TXT = public by definition. Pairing code is the crown jewel (single-use, 10-min TTL, 5/min/IP rate-limit) — anyone holding a live code joins the full mesh, so `pms lock` after enrolling your devices.
* Tests gate release: pairing brute-force, token-reuse, stale-allowlist (unpaired device must fail within refresh window), unknown-host probe, kill-9 + reconnect storm, 24 h soak (direct + forced-relay).

## 7. Config (both file + flags/env)

```yaml
# /etc/pms/config.yaml (server) — flags override, $PMS_* env overrides flags for secrets
domain: pairmesh.com
email: you@mail.com
derp_addr: :443
derp_stun: :3478
caddy_http: :80
caddy_https: :443
data_base: 13000
allowed_clients:            # set by pairing (N devices, allow-all mesh)
  - name: kabir-tp-a1b2
    pubkey: nodekey:...
enrollment_open: true       # pms lock flips to false
```

```yaml
# ~/.config/pmc/config.yaml (client)
server: derp.pairmesh.com
domain: pairmesh.com
exposes:
  - local: 3000
    as: next        # → next.pairmesh.com (web)
  - local: 5432
    tcp: 5432
```

## 8. Repo layout (one module, two mains)

```
go.mod (go 1.27, deps: tailcat, caddy/v2, x/time/rate, yaml.v3 only)
cmd/pms/main.go        cmd/pmc/main.go
internal/pair/        # one-time codes, constant-time verify, TTL, burn
internal/directory/   # name→{pubkey,addr,online}, allowlist push, unpair/lock
internal/bridge/      # tailcat client↔127.0.0.1 TCP+UDP forwards, ProxyPacketConns, MTU/idle handling
internal/edge/        # embedded derper mgmt + Caddyfile gen + admin reload
internal/health/      # loopback health, ping/direct-vs-relay
internal/config/      # file+flags+env merge
deploy/install.sh     # curl installer: -s -- server|client, arch detect, systemd units
deploy/pms.service    deploy/pmc.service
deploy/Caddyfile.tmpl
PLAN.md  README.md  SECURITY.md
```

## 9. Build order (small PRs, each e2e-tested)

1. `pair` (no-arg) + auto-name + embedded derper + `pmc 3000 --as` TCP web path (Caddy H1/H2) + `status`.
2. Caddy H3 (UDP 443) + WSS passthrough test + wildcard test.
3. Raw `--tcp`/`--udp` exposes + 1232 B + idle-timeout + keepalive tests.
4. P2P mesh: directory + auto-allow refresh + `pmc serve ssh` / `pmc ssh <name>` / `pmc devices` + unpair/lock.
5. Reconnect/backoff/DERP-fallback + systemd + installer + docs.
6. Hardening gate: brute-force, token-reuse, stale-allowlist, unknown-host, soak. No release without green.

## 10. Risks / open choices (updated after upstream audit 2026-09-09
and live test 2026-09-10)

Live-test lessons (each shipped unnoticed until real traffic):
* Bridge needs its own stable dial identity, advertised via
  `/_pms/directory` as `server_pubkey` and allowlisted by every device.
  Without it, public traffic 502s while P2P keeps working (asymmetric
  failure — the hardest kind to notice).
* Every mesh member must use OUR derpmap (`/_pms/derpmap.json`), never the
  public default: a sender homed on a foreign relay can never reach a peer
  homed on ours (relays only forward within meshed infra). Symptom is
  identical to the above (dials retry forever, relay idle).
* Caddy `route` + bare `handle` siblings reorder with 404 first — pair API
  used `handle /_pms/*` + bare `respond` (order verified via `caddy adapt`).
* derper cannot share :443 with layer4 in one netns (EADDRINUSE): plaintext
  derper behind l4tls termination instead. Verified live, incl. probe 200.
* pms singleton via pid-file LOCK (not pid existence): stale volume files
  bricked restarts; a parent-written pid once refused its own child.
* Forwards pin their tailcat address at creation: on rotation (re-pair,
  region move) the old closure dials the dead address forever while Caddy
  correctly alerts on the retired SNI — reconcile now recreates on addr
  mismatch (found live via Caddy debug SNI logging).
* `pms init` writes domain+email only; defaults stay in code (a stale
  full-config file once hid a fixed port default through a whole cycle).
* tailcat API/wire unstable: contained by `bridge`-interface wrap + version pin (lib + derper same rev). `forward` CLI gap closed by using lib for UDP.
* Mesh/HA: explicitly v1-out. Single derper node; two one-node regions (not one meshed multi-node region) if HA is ever needed. No `--verify-clients` (needs colocated tailscaled); `--allow` + PSK is the gate.
* `pmc forward` UDP via CLI may lag lib — bridge uses lib directly (`DialUDP`/`OnUDPForward`), CLI is thin wrapper.
* Wildcard needs one DNS step (`A *.domain → VM IP`); without it, `--as` falls back to explicit `--host` + clear error.
* Upstream quirks, kept: `AllowProxy` field is dead (ignore); WASM demo is DERP-only (no WebRTC direct) — native Go unaffected; tailcat wire format strips RegionID/Code/Name (restored as index+1 on parse): our region 900 shows as `derp-1` in magicsock logs with an empty code. Harmless label quirk (node HostName/ports survive; routing is by node key) — verified live via 1 ms hairpin latency + working relay. Do not "fix" home selection on this log line's account; verify with traffic, not labels.
* UDP :443 needs its own layer4 server in network-prefix syntax (`udp/:443`); `:443/udp` adapts cleanly but fails at runtime ("unknown network") — adapt success ≠ runtime success. QUIC needs no SNI split (derper never speaks it): blind-proxy to Caddy's auto H3 listener. H3 end-to-end proven live 2026-09-10 (real handshake, HTTP/3.0 200 with content).
