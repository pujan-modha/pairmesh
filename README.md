# pairmesh — `pms` + `pmc` on tailcat

[![CI](https://github.com/pujan-modha/pairmesh/actions/workflows/ci.yml/badge.svg)](https://github.com/pujan-modha/pairmesh/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/pujan-modha/pairmesh)](https://github.com/pujan-modha/pairmesh/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.27-blue.svg)](go.mod)

Expose anything behind NAT to the internet with two 3-letter commands.
Pair once, then publish. See [PLAN.md](PLAN.md) for architecture.

## Quickstart

VM (public IP):

```bash
curl -fsSL https://get.pairmesh.com | sh -s -- server
pms init --domain pairmesh.com --email you@mail.com
# DNS: A pairmesh.com, *.pairmesh.com, derp.pairmesh.com → VM IP
# needs (installed by the script): pms + caddy (our build WITH caddy-l4)
#   + derper binaries, TCP 80/443 + UDP 443/3478 open
systemctl enable --now pms
pms pair     # → pmc pair <code>
```

Laptop (behind NAT, no ports, no root):

```bash
curl -fsSL https://get.pairmesh.com | sh -s -- client
pmc pair <code>            # once — auto-named, e.g. kabir-tp-a1b2
pmc 3000 --as next         # → https://next.pairmesh.com (H1+H2+H3 via Caddy)
pmc serve ssh              # serve sshd to paired devices (no public port)
pmc up -d                  # daemon holds the tunnel + heartbeat (required!)
pmc ssh <name>             # office ↔ home, names not tokens
```

## Commands

`pms`: `init pair devices unpair lock|unlock status run`
`pmc`: `pair | 3000 --as next | expose --tcp/--udp | serve/unserve ssh | ssh <name> | devices list status rename unexpose | up [-d] down`

Flags work anywhere: `pmc 3000 --as next --config X` ≡ any order.
Config files: `/etc/pms/config.yaml`, `~/.config/pmc/config.yaml` (0600).
`pmc`: flags override file, env overrides secrets. `pms`: file plus
`$PMS_DATA_DIR`. `pms init` writes domain+email only — all other defaults
live in code so upgrades apply; if you hand-set a default key, it pins.
Renaming the domain later means re-pairing every device (clients pin the
server URL at pair time).

## How it works

- **Pipe**: tailcat lib (WireGuard + magicsock NAT traversal + own DERP
  relay). `pms` hosts derper; `pmc` imports tailcat. Our code is only
  pairing, directory, bridge, CLI.
- **Edge**: Caddy (our build with `caddy-l4`; stock Caddy lacks the layer4
  app) owns public :443 via an SNI split (`derp.<domain>` → derper, rest
  → its own HTTPS on localhost) and terminates H1+H2+H3 + wildcard certs.
  derper gets its own LE cert over proxied HTTP-01. Zero hand-rolled TLS
  parsing in our code.
- **Mesh**: `pms` is the trusted directory (`name → pubkey/addr/online`).
  Devices auto-allow all paired peers, TOFU-pinned. `pms lock` closes
  enrollment; `pms unpair` revokes (allowlist refresh ≤30s + on-dial).
- **Limits inherited**: UDP datagrams ≤1232 B, 2-min server idle close
  (client reaps quiet flows at 90 s), DERP relay fallback when UDP blocked.

## Build

```bash
go build -o pms ./cmd/pms          # server: linux amd64/arm64
go build -o pmc ./cmd/pmc          # client: linux+darwin amd64/arm64
GOOS=darwin GOARCH=arm64 go build -o pmc-darwin-arm64 ./cmd/pmc
go test ./...
```

Release binaries (what install.sh fetches):

| artifact | platforms | source |
|---|---|---|
| `pms` | linux amd64/arm64 | `go build ./cmd/pms` |
| `pmc` | linux+darwin amd64/arm64 | `go build ./cmd/pmc` |
| `caddy` | linux amd64/arm64 | `xcaddy build --with github.com/mholt/caddy-l4@v0.1.2` (caddy v2.11.4, verified: our rendered Caddyfile `adapt`s clean) |
| `derper` | linux amd64/arm64 | `go build tailscale.com/cmd/derper` (same rev as tailcat's dep) |

Pinned: `tailcat v0.6.0` (see `go.mod`). Upstream promises no API
stability — tailcat is imported only by `internal/bridge`.

## Security

See [SECURITY.md](SECURITY.md). TL;DR: pairing code is the crown jewel
(single-use, 10 min, 5/min/IP); `tc...` addresses are bearer secrets;
never publish `no-auth` services; run your own derper (default public
relays are rate-limited, no SLA).
