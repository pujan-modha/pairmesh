# Contributing to pairmesh

Thanks for stopping by. Small, focused project — contributions that keep it
that way are welcome.

## Setup

Requires Go 1.27+.

```bash
go build ./...        # pms + pmc
go vet ./...
go test ./...         # includes hermetic tunnel tests (no network needed)
```

## Ground rules

- **Minimal core.** New flags, modes, and dependencies need a strong reason.
  Prefer deleting code to adding it.
- **No custom crypto, muxing, or TLS parsing.** WireGuard/tailcat and Caddy
  own those layers; we glue.
- **Tests for behavior changes.** Unit tests for logic, hermetic tests in
  `internal/bridge` for tunnel paths. Live infrastructure stays out of CI.
- **Docs match code.** `README.md`, `PLAN.md`, and `deploy/Caddyfile.tmpl`
  (byte-checked against the renderer by test) must stay truthful.
- **Secrets never touch git.** Pairing codes, tokens, keys, `*.db` files —
  the `.gitignore` blocks the common cases; stay alert anyway.

## Security issues

Do **not** open a public issue. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) instead.
See [SECURITY.md](SECURITY.md) for the threat model.
