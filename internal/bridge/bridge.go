// Package bridge wraps the tailcat library behind a narrow interface.
// This is the only package that imports tailcat (upstream promises no API
// stability), so a future transport swap touches one directory.
package bridge

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"

	"github.com/pujan-modha/pairmesh/internal/keys"
)

// Tunables (PLAN §5).
const (
	// UDPReadTimeout bounds quiet client-side flows. Server kills idle flows
	// at 2 min; we reap earlier so a dead relay never wedges a flow table
	// entry, at the cost of a re-dial on the next datagram past the window.
	// (Transport NAT keepalives are magicsock's job, not ours.)
	UDPReadTimeout = 90 * time.Second
	DialTimeout    = 10 * time.Second
)

// Tunnel dials into serving peers. One tailcat.Client is cached per peer
// address; Dial* re-handshakes lazily through DERP with NAT upgrade.
type Tunnel struct {
	mu         sync.Mutex
	clients    map[string]*tailcat.Client
	clientKey  key.NodePrivate // persistent dial identity (allowlisted by peers)
	hasKey     bool
	derpMapURL string // custom DERP map; empty = upstream public default
	logf       func(string, ...any)
}

// New returns a tunnel. logf nil → discard.
func New(logf func(string, ...any)) *Tunnel {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Tunnel{clients: map[string]*tailcat.Client{}, logf: logf}
}

// WithClientKey pins the dial identity (stable allowlisting). Must be
// called before first use.
func (t *Tunnel) WithClientKey(k key.NodePrivate) *Tunnel {
	t.clientKey = k
	t.hasKey = true
	return t
}

// WithDERPMapURL pins dials to our relay map (see pms derpMap). Without
// it, magicsock may home on a foreign public relay that cannot reach peers
// homed on ours — dials hang forever with a healthy-looking relay.
func (t *Tunnel) WithDERPMapURL(url string) *Tunnel {
	t.derpMapURL = url
	return t
}

// ClientFor returns the cached client for a full tailcat address.
func (t *Tunnel) ClientFor(addr tailcat.Addr) *tailcat.Client {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.clients[string(addr)]; ok {
		return c
	}
	c := tailcat.NewClient(addr)
	if t.hasKey {
		c.Key = t.clientKey
	}
	if t.derpMapURL != "" {
		c.DERPMapURL = t.derpMapURL
	}
	c.Logf = t.logf
	t.clients[string(addr)] = c
	return c
}

// DialTCP opens a TCP stream to port on the peer, with handshake deadline.
func (t *Tunnel) DialTCP(ctx context.Context, addr tailcat.Addr, port uint16) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()
	return t.ClientFor(addr).DialTCPPort(ctx, port)
}

// DialUDP opens a connected UDP flow to port on the peer.
func (t *Tunnel) DialUDP(ctx context.Context, addr tailcat.Addr, port uint16) (tailcat.ConnPacketConn, error) {
	ctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()
	return t.ClientFor(addr).DialUDPPort(ctx, port)
}

// Path reports whether the peer is reachable directly (vs DERP relay).
func (t *Tunnel) Path(ctx context.Context, addr tailcat.Addr) (direct bool, via string, err error) {
	ctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()
	res, err := t.ClientFor(addr).DiscoPing(ctx)
	if err != nil {
		return false, "", err
	}
	if res.Endpoint != "" {
		return true, res.Endpoint, nil
	}
	return false, fmt.Sprintf("derp-%d", res.DERPRegionID), nil
}

// Close shuts all cached clients.
func (t *Tunnel) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for a, c := range t.clients {
		c.Close()
		delete(t.clients, a)
	}
}

// ForwardTCP serves listenAddr locally; each inbound conn is spliced to
// (addr, port) on the peer. Runs until ctx done.
func (t *Tunnel) ForwardTCP(ctx context.Context, listenAddr string, addr tailcat.Addr, port uint16) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	// NOTE: per-connection dial failures below use t.logf; the accept
	// loop below uses it too — no global logger, tests stay quiet.
	for {
		down, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				t.logf("bridge: accept: %v", err)
				// Brief pause: transient errors (EMFILE, ENFILE)
				// must not spin the loop at 100% CPU.
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(50 * time.Millisecond):
				}
				continue
			}
		}
		go func(down net.Conn) {
			defer down.Close()
			up, err := t.DialTCP(ctx, addr, port)
			if err != nil {
				t.logf("bridge: dial port %d: %v", port, err)
				return
			}
			defer up.Close()
			tailcat.ProxyConns(down, up)
		}(down)
	}
}

// ForwardUDP serves a local UDP socket; each source gets a connected tailcat
// UDP flow to (addr, port). Datagrams over MaxUDPPayload are dropped
// (no-fragmentation rule for the 1280-byte tunnel MTU). Runs until ctx done.
func (t *Tunnel) ForwardUDP(ctx context.Context, listenAddr string, addr tailcat.Addr, port uint16) error {
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return err
	}
	defer pc.Close()
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	var mu sync.Mutex
	type flow struct {
		up  tailcat.ConnPacketConn
		gen uint64 // deleted only by its own reaper (see below)
	}
	flows := map[string]flow{}
	var nextGen uint64
	buf := make([]byte, tailcat.MaxUDPPayload)
	for {
		n, remote, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				for _, f := range flows {
					f.up.Close()
				}
				return nil
			default:
				t.logf("bridge: udp read: %v", err)
				continue
			}
		}
		if n > tailcat.MaxUDPPayload {
			continue
		}
		mu.Lock()
		f, ok := flows[remote.String()]
		mu.Unlock()
		if !ok {
			// Dial outside the lock: a 10 s handshake must never stall
			// other flows' setup/teardown.
			up, err := t.DialUDP(ctx, addr, port)
			if err != nil {
				t.logf("bridge: udp dial: %v", err)
				continue
			}
			mu.Lock()
			if dup, taken := flows[remote.String()]; taken {
				// Lost the race: another datagram built this flow
				// while we dialed. Keep the first, drop ours.
				mu.Unlock()
				up.Close()
				f = dup
			} else {
				nextGen++
				f = flow{up: up, gen: nextGen}
				flows[remote.String()] = f
				mu.Unlock()
				go func(up tailcat.ConnPacketConn, remote net.Addr, gen uint64) {
					defer func() {
						up.Close()
						mu.Lock()
						if cur, ok := flows[remote.String()]; ok && cur.gen == gen {
							delete(flows, remote.String())
						}
						mu.Unlock()
					}()
					rbuf := make([]byte, tailcat.MaxUDPPayload)
					for {
						_ = up.SetReadDeadline(time.Now().Add(UDPReadTimeout))
						m, err := up.Read(rbuf)
						if err != nil {
							return // idle timeout or closed
						}
						if _, err := pc.WriteTo(rbuf[:m], remote); err != nil {
							return
						}
					}
				}(up, remote, f.gen)
			}
		}
		if _, err := f.up.Write(buf[:n]); err != nil {
			t.logf("bridge: udp write: %v", err)
		}
	}
}

// ServeConfig describes one serving pmc box.
type ServeConfig struct {
	// TCP maps served tailcat port → local forward target host:port.
	TCP map[uint16]string
	// UDP maps served tailcat port → local forward target host:port.
	UDP map[uint16]string
	// Allow lists nodekey:... identities. Empty = deny all (never allow-all).
	Allow []string
}

// Serve starts a tailcat server forwarding to localhost. The tailcat address
// is stable across restarts for stable keys+region. To refresh the allowlist,
// Close the server and Serve again (race-free; dialers redial with backoff).
func Serve(srv *tailcat.Server, cfg ServeConfig) error {
	for _, a := range cfg.Allow {
		pub, err := keys.ParsePub(a)
		if err != nil {
			return err
		}
		srv.AddAllowedClient(pub)
	}
	srv.OnTCP = func(port uint16) func(net.Conn) {
		target, ok := cfg.TCP[port]
		if !ok {
			return nil // RST: port not served
		}
		return func(c net.Conn) {
			defer c.Close()
			up, err := net.DialTimeout("tcp", target, DialTimeout)
			if err != nil {
				return
			}
			defer up.Close()
			tailcat.ProxyConns(c, up)
		}
	}
	srv.OnUDP = func(port uint16) func(tailcat.ConnPacketConn) {
		target, ok := cfg.UDP[port]
		if !ok {
			return nil
		}
		return func(c tailcat.ConnPacketConn) {
			defer c.Close()
			up, err := net.Dial("udp", target)
			if err != nil {
				return
			}
			defer up.Close()
			// *net.UDPConn implements ConnPacketConn (compile-checked
			// below); connected UDP preserves datagram boundaries.
			if pcc, ok := up.(tailcat.ConnPacketConn); ok {
				tailcat.ProxyPacketConns(c, pcc)
				return
			}
			up.Close()
		}
	}
	return srv.Start()
}

// udpConnPacketConn is a compile-time guarantee that the Serve UDP branch's
// type assertion can never fail at runtime.
var _ tailcat.ConnPacketConn = (*net.UDPConn)(nil)
