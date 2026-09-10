# SECURITY.md

## Trust model

One trust domain per `pms`. Any paired device can reach any other's served
ports. If that sentence scares you, run two `pms` hosts.

- **Pairing code** = full membership. 192-bit random, single-use, 10-minute
  TTL, SHA-256 at rest, constant-time verify, identical error for
  unknown/expired/used/locked (no oracle), 5/min/IP rate-limit. Share over a
  private channel. Close enrollment when done: `pms lock`.
- **Device tokens** = bearer auth to directory/heartbeat (SHA-256 at rest,
  0600 files). Rotated automatically every hour on heartbeat, old token
  surviving a 5-minute grace window (crash between receive and store).
  Rotate immediately anytime via re-pairing; revoke via `pms unpair`.
- **`tc...` addresses** contain the WireGuard PSK — bearer dial capability.
  Never logged, never in DNS. DNS TXT is public by definition; our CLIs
  never accept DNS names for secret servers.
- **DERP operator** (even your own hoster) sees node pubkeys + traffic
  metadata, not payload (PSK + WireGuard). Default public relays are
  best-effort/rate-limited; production runs its own derper subprocess.
- **Peer keys** are TOFU-pinned (`known_peers`); a changed pubkey aborts
  with a loud warning — confirm out-of-band before clearing. Unattended
  stdin (pipes, cron) never auto-trusts: EOF aborts the connection.
- **No `no-auth-ssh` / `exec` / `files` services**: only `serve <ports>` +
  key-authed `ssh` to system sshd. Public web has no default backend
  (unknown Host/SNI → 404/close). Health/metrics bind loopback only.
- **TLS**: 1.3 only at edge (Caddy renders `protocols tls1.3` on every
  public HTTPS site; asserted in render tests), PSK always on inside
  (never `--psk=false`).

## Hardening gate (release checklist)

- [x] pairing brute-force + token reuse + expired-code rejection (unit)
- [x] stale-allowlist: unlisted identity refused (hermetic test)
- [ ] unknown-Host/SNI probe → 404/close, nothing leaked (needs staging)
- [ ] kill -9 + reconnect storm (needs staging)
- [ ] 24 h soak, direct + forced-relay paths (needs staging)
- [x] `go vet`, unit + hermetic tunnel tests green

## Reporting

Do not open a public issue. Use GitHub's [private vulnerability
reporting](https://github.com/pujan-modha/pairmesh/security/advisories/new)
instead. Do not post live pairing codes, tokens, or `tc...` addresses
anywhere.
