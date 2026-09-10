// Hermetic tailcat data-path tests: in-process DERP (same recipe as
// upstream TS_DEBUG_TAILCAT_LOCAL_DERP), real WireGuard + NAT stack,
// no internet. Proves bridge.Serve/Dial/Forward carry TCP + UDP.
package bridge

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// localDERP starts an in-process DERP + STUN on loopback and returns a
// region clients/servers embed directly (no DERP map fetch, no network).
// InsecureForTests skips TLS verification for the httptest cert.
func localDERP(t *testing.T) *tailcfg.DERPRegion {
	t.Helper()
	logf := logger.WithPrefix(func(f string, a ...any) { t.Logf(f, a...) }, "[dev-derp] ")
	d := derpserver.New(key.NewNode(), logf)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewUnstartedServer(derpserver.Handler(d))
	hs.Listener = ln
	hs.Config.ErrorLog = logger.StdLogger(logf)
	hs.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	hs.StartTLS()
	t.Cleanup(hs.Close)

	uln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { uln.Close() })
	go func() {
		var buf [1500]byte
		for {
			n, src, err := uln.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				return
			}
			txid, err := stun.ParseBindingRequest(buf[:n])
			if err != nil {
				continue
			}
			uln.WriteToUDPAddrPort(stun.Response(txid, src), src)
		}
	}()
	return &tailcfg.DERPRegion{
		RegionID: 1, RegionCode: "D",
		Nodes: []*tailcfg.DERPNode{{
			Name: "t1", RegionID: 1, HostName: "T",
			IPv4: "127.0.0.1", IPv6: "none",
			STUNPort:         uln.LocalAddr().(*net.UDPAddr).Port,
			DERPPort:         hs.Listener.Addr().(*net.TCPAddr).Port,
			InsecureForTests: true,
		}},
	}
}

// testServer starts a tailcat server on reg serving TCPPort→echo and
// UDPPort→echo, allowlisting dialKey. Returns its full address.
func testServer(t *testing.T, reg *tailcfg.DERPRegion, dialKey key.NodePublic, tcpPort, udpPort uint16) tailcat.Addr {
	t.Helper()
	pk := tailcat.NewPrivateKey()
	srv := &tailcat.Server{
		Key: pk.Private, PresharedKey: pk.Public.PresharedKey, Region: reg,
		Logf: func(f string, a ...any) { t.Logf("[srv] "+f, a...) },
	}
	srv.AddAllowedClient(dialKey)
	srv.OnTCP = func(port uint16) func(net.Conn) {
		if port != tcpPort {
			return nil
		}
		return func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 64<<10)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if _, err := c.Write(buf[:n]); err != nil {
					return
				}
			}
		}
	}
	srv.OnUDP = func(port uint16) func(tailcat.ConnPacketConn) {
		if port != udpPort {
			return nil
		}
		return func(c tailcat.ConnPacketConn) {
			defer c.Close()
			buf := make([]byte, tailcat.MaxUDPPayload)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if _, err := c.Write(buf[:n]); err != nil {
					return
				}
			}
		}
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("server start: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv.TailcatAddr()
}

func testClient(t *testing.T) (*Tunnel, key.NodePrivate) {
	t.Helper()
	ck := key.NewNode()
	tun := New(func(f string, a ...any) { t.Logf("[cli] "+f, a...) })
	tun.WithClientKey(ck)
	t.Cleanup(tun.Close)
	return tun, ck
}

func TestTCPEchoLocalDERP(t *testing.T) {
	if testing.Short() {
		t.Skip("skip live tunnel in -short")
	}
	reg := localDERP(t)
	tun, ck := testClient(t)
	addr := testServer(t, reg, ck.Public(), 4001, 4002)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, err := tun.DialTCP(ctx, addr, 4001)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	msg := []byte("hello hermetic tunnel")
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
	// Path report must work; direct expected on loopback but relay is
	// valid behavior — log, don't hard-fail (see PLAN §4).
	if direct, via, err := tun.Path(ctx, addr); err != nil {
		t.Fatalf("path: %v", err)
	} else {
		t.Logf("path: direct=%v via=%s", direct, via)
	}
}

func TestUDPEchoLocalDERP(t *testing.T) {
	if testing.Short() {
		t.Skip("skip live tunnel in -short")
	}
	reg := localDERP(t)
	tun, ck := testClient(t)
	addr := testServer(t, reg, ck.Public(), 4001, 4002)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pc, err := tun.DialUDP(ctx, addr, 4002)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer pc.Close()
	msg := []byte("hello hermetic datagram")
	if len(msg) > tailcat.MaxUDPPayload {
		t.Fatal("fixture exceeds MaxUDPPayload")
	}
	if _, err := pc.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(20 * time.Second))
	buf := make([]byte, tailcat.MaxUDPPayload)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf[:n], msg)
	}
}

func TestServeHelperAllowlist(t *testing.T) {
	if testing.Short() {
		t.Skip("skip live tunnel in -short")
	}
	reg := localDERP(t)
	// Local echo target behind bridge.Serve.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				fmt.Fprint(c, "served")
			}(c)
		}
	}()
	target := ln.Addr().String()

	allowedTun, allowedCK := testClient(t)
	_ = allowedTun
	deniedTun, _ := testClient(t)

	pk := tailcat.NewPrivateKey()
	srv := &tailcat.Server{
		Key: pk.Private, PresharedKey: pk.Public.PresharedKey, Region: reg,
		Logf: func(f string, a ...any) { t.Logf("[srv] "+f, a...) },
	}
	if err := Serve(srv, ServeConfig{
		TCP: map[uint16]string{5001: target}, Allow: []string{keyToText(t, allowedCK.Public())},
	}); err != nil {
		t.Fatalf("serve: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	addr := srv.TailcatAddr()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, err := allowedTun.DialTCP(ctx, addr, 5001)
	if err != nil {
		t.Fatalf("allowed dial: %v", err)
	}
	got, err := io.ReadAll(io.LimitReader(c, 64))
	c.Close()
	if err != nil || string(got) != "served" {
		t.Fatalf("allowed read = %q, %v", got, err)
	}

	// Unlisted identity must not reach the service.
	dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer dcancel()
	if dc, err := deniedTun.DialTCP(dctx, addr, 5001); err == nil {
		dc.Close()
		t.Fatal("denied client reached the service")
	} else {
		t.Logf("denied correctly: %v", err)
	}
}

func keyToText(t *testing.T, k key.NodePublic) string {
	t.Helper()
	b, err := k.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestServeHelperUDP exercises bridge.Serve's UDP branch end to end:
// local UDP echo target → Serve UDP map → client dial → round trip.
// (Covers the *net.UDPConn assertion + ProxyPacketConns wiring that the
// raw echo test above bypasses.)
func TestServeHelperUDP(t *testing.T) {
	if testing.Short() {
		t.Skip("skip live tunnel in -short")
	}
	reg := localDERP(t)
	// Local UDP echo target.
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		buf := make([]byte, tailcat.MaxUDPPayload)
		for {
			n, addr, err := target.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := target.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()

	allowedTun, allowedCK := testClient(t)
	pk := tailcat.NewPrivateKey()
	srv := &tailcat.Server{
		Key: pk.Private, PresharedKey: pk.Public.PresharedKey, Region: reg,
		Logf: func(f string, a ...any) { t.Logf("[srv] "+f, a...) },
	}
	if err := Serve(srv, ServeConfig{
		UDP:   map[uint16]string{5002: target.LocalAddr().String()},
		Allow: []string{keyToText(t, allowedCK.Public())},
	}); err != nil {
		t.Fatalf("serve: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	addr := srv.TailcatAddr()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pc, err := allowedTun.DialUDP(ctx, addr, 5002)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer pc.Close()
	msg := []byte("via-serve-udp")
	if _, err := pc.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(20 * time.Second))
	buf := make([]byte, tailcat.MaxUDPPayload)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf[:n], msg)
	}
}
