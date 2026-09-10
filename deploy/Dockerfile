# pairmesh server image: pms + caddy(with l4) + derper.
# Server is linux-only (amd64/arm64). Build:
#   docker build -t pairmesh-pms -f deploy/Dockerfile .
#   docker buildx build --platform linux/amd64,linux/arm64 -t pairmesh-pms -f deploy/Dockerfile .
ARG GO_VERSION=1.27

# ---- pms + derper (pinned via go.mod) ----
FROM golang:${GO_VERSION}-bookworm AS gobuild
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
ARG TARGETARCH
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w" -o /out/pms ./cmd/pms \
 && CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w" -o /out/derper tailscale.com/cmd/derper

# ---- caddy with the layer4 module (pinned) ----
FROM golang:${GO_VERSION}-bookworm AS caddybuild
ARG TARGETARCH
RUN GOBIN=/usr/local/bin go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
# GOARCH is inherited by the `go build` xcaddy shells out to (multi-arch safe).
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} xcaddy build --with github.com/mholt/caddy-l4@v0.1.2 --output /out/caddy

# ---- runtime ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists
# Caddy storage (certs, ACME accounts) MUST live on the volume: fresh storage
# per recreate forces mass re-issuance (rate limits) and — worse — leaves the
# pair site without TLS at boot, which breaks the bridge's DERP-map fetch
# window and strands it on a foreign relay (observed live).
ENV XDG_DATA_HOME=/var/lib/pms
COPY --from=gobuild /out/pms /out/derper /usr/local/bin/
COPY --from=caddybuild /out/caddy /usr/local/bin/
VOLUME ["/var/lib/pms", "/etc/pms"]
EXPOSE 80/tcp 443/tcp 443/udp 3478/udp
ENTRYPOINT ["pms", "run", "--config", "/etc/pms/config.yaml"]
