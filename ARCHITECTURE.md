# pairmesh architecture (plain words)

pairmesh is a **pair-to-peer mesh**: your machines find each other by
*name* (not IP address), prove who they are with keys (not accounts),
and move bytes over encrypted pipes. One pairing step joins a device to
two things at once: the private mesh (talk to each other) and the public
edge (the internet talks to you).

```
laptop ──tunnel──▶  VM (pms)  ◀──tunnel── office
                       │
                   internet
```

## The three upstream projects (we use them, we don't change them)

**Important up front: pairmesh forks, patches, and modifies none of
these.** It uses them as a Go library (tailcat) and as managed
subprocesses (derper, Caddy), pinned to exact versions in `go.mod` and
`deploy/Dockerfile`. Upgrading one means changing a version string, not
reconciling a fork.

### 1. tailcat — the encrypted pipe (Go library)

`github.com/tailscale/tailcat` v0.6.0 — "Tailscale without Tailscale": the
WireGuard + NAT-traversal + relay data plane with no accounts and no
control plane. One side serves an address (`tc…`), the other dials it;
everything between them is WireGuard-encrypted, hole-punched to direct
UDP when NAT allows, relayed when not. No root, no TUN device, no OS
network changes — TCP terminates inside the process.

What it gives us: crypto, NAT traversal, multiplexed streams, UDP flows.
What it does *not* give us: names, pairing, allowlists that update
themselves, HTTP routing, certificates, daemons, CLIs worth using.

### 2. derper — the meeting point (binary we run)

Tailscale's DERP relay server (`tailscale.com/cmd/derper`, same rev as
tailcat's dependency). Two machines that can't see each other directly
both dial out to it; it introduces them and relays bytes only when
hole-punching fails. It understands nothing about our services, ports,
or domains — it's a lobby, not a receptionist. We run our own so no
third party ever sees even metadata, and we run a tiny standalone STUN
reflector next to it (derper's own STUN would sit on loopback) so direct
paths actually form.

### 3. Caddy (with caddy-l4) — the public front door (binary we run)

Caddy v2.11.4 + `caddy-l4` v0.1.2, built via `xcaddy`. It owns public
`:443` through a layer-4 SNI split (`derp.*` → derper after TLS
termination, everything else → its own HTTPS), terminates HTTP/1+2+3
with automatic Let's Encrypt certs (TLS 1.3 only), and reverse-proxies
named hosts to local bridge ports. We generate its Caddyfile; a golden
test keeps the checked-in template byte-identical to the renderer.

## What pairmesh adds (~2–3k lines of our own)

Everything above moves bytes. None of it knows *who is allowed to talk
to whom*. That's the whole product:

- **Pairing** (`pms pair` → `pmc pair <code>`): single-use 10-minute
  codes. The server verifies in constant time, auto-names the device,
  and records its WireGuard identity. Re-pairing the same key keeps the
  name and rotates the credential.
- **Directory** (`internal/directory`): the trusted introducer —
  `name → {pubkey, address, exposes, online}`. Closed group: paired
  devices can reach each other, nobody else exists.
- **Bridge** (`internal/bridge`): the *only* package importing tailcat.
  Dials serving devices on the server side, forwards localhost ports on
  the client side. If we ever swap transports, this directory is the
  entire blast radius.
- **Edge management** (`internal/edge`): renders Caddyfiles, supervises
  the `caddy`/`derper` subprocesses, runs STUN. Caddy + derper would
  otherwise each need hand-holding; `pms run` parents them.
- **Mesh policy**: allow-all within the trust domain. Every serving box
  allowlists all directory keys (refreshed every 30 s, cached across
  outages); peers TOFU-pin each other and abort — including on EOF —
  at the slightest identity change.
- **CLI/UX** (`pms`, `pmc`): pairing, exposing (`3000 --as shop`,
  `--host`, `--tcp`, `--udp`), `serve ssh`, `ssh [user@]name`, daemon
  lifecycle with file locks (never pid-existence checks), systemd units,
  installer, health on loopback only.

## How the four flows move bytes

- **Public web** (`pmc 3000 --as shop` → `https://shop.domain`):
  browser → Caddy (`:443`, H1/H2/H3, LE cert) → `127.0.0.1:13xxx` →
  bridge dials the device's tailcat address → device forwards to
  `localhost:3000`. Origin stays plain HTTP; the edge does the fancy.
- **Raw TCP/UDP** (`--tcp 5432`, `--udp 53`): `pms` binds the public
  port directly; same tunnel underneath; datagrams preserved, ≤1232 B.
- **Mesh SSH** (`pmc ssh [user@]office`): directory lookup → TOFU check
  → tailcat dial (direct P2P when possible, our DERP relay if not) →
  stock `ssh` over a localhost forward. `pms` is not in the data path.
- **Pairing**: one HTTPS POST with a burned-after-reading code; from
  then on, bearer tokens that rotate on heartbeat.

## What we deliberately don't do

No virtual network (no IPs, TUN, routes, DNS surgery — names, not
addresses). No accounts, SSO, orgs, or per-app policies (one trust
domain per `pms`; need more, run two). No dashboard, metrics endpoint,
or multi-server mesh yet (see PLAN.md §10). No HA: one VM, backups
are the operator's job, documented in README.
