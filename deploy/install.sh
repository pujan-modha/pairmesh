#!/bin/sh
# pairmesh installer.
#   server (linux only, amd64/arm64): pms + caddy(with l4) + derper
#     curl -fsSL https://get.pairmesh.com | sh -s -- server
#   client (linux + mac): pmc
#     curl -fsSL https://get.pairmesh.com | sh -s -- client
set -eu

ROLE="${1:-}"
VERSION="${PAIRMESH_VERSION:-latest}"
BASE="${PAIRMESH_BASE:-https://github.com/pujan-modha/pairmesh/releases/download}"
BINDIR="${BINDIR:-/usr/local/bin}"

case "$ROLE" in
  server) BINS="pms caddy derper" ;;
  client) BINS="pmc" ;;
  *) echo "usage: sh install.sh -- server|client" >&2; exit 2 ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"

case "$ROLE" in
  server)
    case "$OS" in
      linux) ;;
      *) echo "server role is linux-only (client supports linux + mac)" >&2; exit 1 ;;
    esac
    ;;
esac

for BIN in $BINS; do
  URL="$BASE/$VERSION/${BIN}-${OS}-${ARCH}.tar.gz"
  TMP="$(mktemp -d)"
  echo "installing $BIN ($OS/$ARCH) from $URL"
  curl -fsSL "$URL" | tar -xz -C "$TMP"
  install -m 0755 "$TMP/$BIN" "$BINDIR/$BIN"
  rm -rf "$TMP"
done
echo "installed: $BINS → $BINDIR"
if [ "$ROLE" = "server" ]; then
  echo "next: pms init --domain <domain> --email <you@mail>"
else
  echo "next: pmc pair <code>   (get the code from: pms pair)"
fi
