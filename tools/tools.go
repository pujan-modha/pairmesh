//go:build tools

// Package tools pins build-only dependencies: release binaries that are
// main packages (unimportable by our code) whose full dependency graph
// must stay in go.mod/go.sum so `go build <pkg>` and Docker work.
// Keep the rev identical to tailcat's tailscale.com dependency.
package tools

import (
	_ "tailscale.com/cmd/derper"
)
