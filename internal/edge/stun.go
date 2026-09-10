package edge

import (
	"context"
	"log"

	"tailscale.com/net/stunserver"
)

// ServeSTUN runs a standalone STUN reflector on addr (e.g. :3478) until it
// fails. derper binds its own STUN to -a's host — loopback in our layout,
// useless for remote NAT discovery — so this public one is what makes
// direct P2P paths possible. Without it everything still works, relayed.
// Callers run it in a goroutine; ctx only selects which failures are worth
// logging. The process lifetime bounds the socket.
func ServeSTUN(ctx context.Context, addr string) {
	ss := stunserver.New(ctx)
	if err := ss.ListenAndServe(addr); err != nil {
		select {
		case <-ctx.Done():
		default:
			log.Printf("edge: stun %s: %v (direct paths degraded to relay)", addr, err)
		}
	}
}
