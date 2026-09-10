// Command pms runs on the VM: owns derper + Caddy (with layer4 SNI split) + bridge.
//
//	Usage:
//	  pms init --domain pairmesh.com --email you@mail.com
//	  pms pair            # prints: pmc pair <code>
//	  pms devices         # paired devices
//	  pms unpair <name>   # revoke
//	  pms lock|unlock     # close/open enrollment
//	  pms status
//	  pms run             # daemon (systemd)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"github.com/pujan-modha/pairmesh/internal/bridge"
	"github.com/pujan-modha/pairmesh/internal/config"
	"github.com/pujan-modha/pairmesh/internal/directory"
	"github.com/pujan-modha/pairmesh/internal/edge"
	"github.com/pujan-modha/pairmesh/internal/health"
	"github.com/pujan-modha/pairmesh/internal/keys"
	"github.com/pujan-modha/pairmesh/internal/pair"
	"github.com/pujan-modha/pairmesh/internal/pid"
	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "pair":
		err = cmdPair(args)
	case "devices":
		err = cmdDevices(args)
	case "unpair":
		err = cmdUnpair(args)
	case "lock":
		err = cmdLock(args, true)
	case "unlock":
		err = cmdLock(args, false)
	case "status":
		err = cmdStatus(args)
	case "run":
		err = cmdRun(args)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "pms: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "pms: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`pms — pairmesh server (runs on the VM)

  pms init --domain pairmesh.com --email you@mail.com
  pms pair                  print a single-use pairing code (10 min)
  pms devices               list paired devices
  pms unpair <name>         revoke a device
  pms lock|unlock           close/open enrollment
  pms status                domain + daemon health
  pms run                   daemon (systemd runs this)

Config: /etc/pms/config.yaml (plus $PMS_DATA_DIR override).`)
}

func loadPMSConfig(path string) config.PMSConfig {
	cfg := config.DefaultPMS()
	_ = config.LoadYAML(path, &cfg)
	if v := config.EnvOr("PMS_DATA_DIR", ""); v != "" {
		cfg.DataDir = v
	}
	return cfg
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	domain := fs.String("domain", "", "public domain (required)")
	email := fs.String("email", "", "ACME email (required)")
	cfgPath := fs.String("config", "/etc/pms/config.yaml", "config path")
	_ = fs.Parse(args)
	if *domain == "" || *email == "" {
		return fmt.Errorf("init: --domain and --email are required\n  e.g. pms init --domain pairmesh.com --email you@mail.com")
	}
	// Write a MINIMAL file (domain + email only): every other default lives
	// in code so upgrades pick up new defaults instead of running pinned
	// to whatever was default at init time (a stale derper_addr once hid
	// a fixed port conflict through an entire test cycle).
	cfg := config.PMSConfig{Domain: *domain, Email: *email}
	dataDir := config.EnvOr("PMS_DATA_DIR", config.DefaultPMS().DataDir)
	if err := config.SaveYAML(*cfgPath, &cfg); err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("init: data dir %s: %w (run as root or set PMS_DATA_DIR)", dataDir, err)
	}
	fmt.Printf("wrote %s\n", *cfgPath)
	fmt.Println("next:")
	fmt.Println("  1. point DNS at this VM:  A <domain> / A *.<domain> / A derp.<domain>")
	fmt.Println("  2. install caddy + derper binaries on PATH, open TCP 80/443 + UDP 443/3478")
	fmt.Println("  3. pms run   (or enable the systemd unit)")
	fmt.Println("  4. pms pair  (link your first device)")
	return nil
}

func cmdPair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/pms/config.yaml", "config path")
	_ = fs.Parse(args)
	cfg := loadPMSConfig(*cfgPath)
	st := pair.New(pair.DefaultPath(cfg.DataDir))
	code, err := st.Mint(time.Now())
	if err != nil {
		return err
	}
	fmt.Println("run ONCE on the new device (single-use, expires in 10 min):")
	fmt.Printf("  pmc pair %s\n", code)
	return nil
}

func cmdDevices(args []string) error {
	fs := flag.NewFlagSet("devices", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/pms/config.yaml", "config path")
	_ = fs.Parse(args)
	cfg := loadPMSConfig(*cfgPath)
	devs, err := directory.New(directory.DefaultPath(cfg.DataDir)).ListErr()
	if err != nil {
		return fmt.Errorf("devices: %w", err)
	}
	for _, d := range devs {
		st := "offline"
		if d.Online && time.Since(d.LastSeen) < 2*time.Minute {
			st = "online"
		}
		fmt.Printf("%-24s %-7s exposes=%s last=%s\n", d.Name, st, strings.Join(d.Exposes, ","), d.LastSeen.Format(time.RFC3339))
	}
	return nil
}

func cmdUnpair(args []string) error {
	fs := flag.NewFlagSet("unpair", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/pms/config.yaml", "config path")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: pms unpair <name>")
	}
	cfg := loadPMSConfig(*cfgPath)
	if !directory.New(directory.DefaultPath(cfg.DataDir)).Remove(fs.Arg(0)) {
		return fmt.Errorf("no such device %q", fs.Arg(0))
	}
	fmt.Printf("revoked %q (remaining devices refresh allowlists within ~30s)\n", fs.Arg(0))
	return nil
}

func cmdLock(args []string, lock bool) error {
	fs := flag.NewFlagSet("lock", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/pms/config.yaml", "config path")
	_ = fs.Parse(args)
	cfg := loadPMSConfig(*cfgPath)
	if err := pair.New(pair.DefaultPath(cfg.DataDir)).SetLocked(lock); err != nil && !(lock == false && os.IsNotExist(err)) {
		return err
	}
	if lock {
		fmt.Println("enrollment closed (pms pair now refuses; unlock to re-open)")
	} else {
		fmt.Println("enrollment open")
	}
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/pms/config.yaml", "config path")
	_ = fs.Parse(args)
	cfg := loadPMSConfig(*cfgPath)
	fmt.Printf("domain: %s\n", cfg.Domain)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + cfg.AdminAddr + "/healthz")
	if err != nil {
		fmt.Println("daemon: not running (pms run)")
		return nil
	}
	defer resp.Body.Close()
	var st health.Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return err
	}
	fmt.Printf("daemon: healthy=%v %s (devices=%d rev=%d)\n", st.Healthy, st.Detail, st.Devices, st.Revision)
	return nil
}

// server wires admin API + edge + bridge reconcile.
type server struct {
	cfg config.PMSConfig
	dir *directory.Directory
	pst *pair.Store
	tun *bridge.Tunnel
	// srvKey is this server's stable tailcat dial identity. The bridge
	// presents it when dialing devices, so every device allowlist must
	// contain it (served via /_pms/directory as server_pubkey). Without
	// this, devices reject the bridge's meows and all public traffic 502s
	// while device-to-device keeps working — exactly the failure that
	// shipped unnoticed until the first live test.
	srvPub string
}

// cmdRun is the daemon: admin API, Caddy (layer4 :443 split + HTTPS), derper, bridge loop.
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/pms/config.yaml", "config path")
	_ = fs.Parse(args)
	cfg := loadPMSConfig(*cfgPath)
	if err := validateConfig(cfg); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Single daemon per data dir: the lock (not the file) arbitrates, so a
	// stale pid file from a dead container can never wedge startup, and a
	// second `run` refuses instead of shadowing the first one's port.
	lock, err := pid.Acquire(pidPath(cfg.DataDir), os.Getpid(), "pms")
	if err != nil {
		return err
	}
	defer lock.Close()

	s := &server{
		cfg: cfg,
		dir: directory.New(directory.DefaultPath(cfg.DataDir)),
		pst: pair.New(pair.DefaultPath(cfg.DataDir)),
		tun: bridge.New(log.Printf),
	}
	defer s.tun.Close()

	derpHost := "derp." + cfg.Domain
	// All dials use our map over the public https origin — never the public
	// default (a sender homed on a foreign relay can never reach a peer
	// homed on ours). Plain-http loopback was tried: tailcat silently
	// falls back to the default map on fetch trouble, stranding the bridge
	// on a foreign relay with zero errors. https works here because no
	// dial can exist before a device pairs, and pairing already proves
	// this origin serves valid TLS.
	s.tun.WithDERPMapURL("https://pair." + cfg.Domain + "/_pms/derpmap.json")
	log.Printf("pms: derp map %s", "https://pair."+cfg.Domain+"/_pms/derpmap.json")
	// Stable server dial identity (persisted; PSK/region unused — the
	// bridge only dials, never serves).
	srvID, err := keys.LoadOrCreate(cfg.DataDir, derpHost)
	if err != nil {
		return fmt.Errorf("server identity: %w", err)
	}
	srvKey, err := srvID.ClientKey()
	if err != nil {
		return fmt.Errorf("server identity: %w", err)
	}
	s.tun.WithClientKey(srvKey)
	s.srvPub = srvID.NodePub
	log.Printf("pms: bridge identity %s", shortKey(s.srvPub))
	derp := &edge.Derper{
		Bin: dflt(cfg.DerperBin, "derper"), Hostname: derpHost,
		Addr: cfg.DerperAddr, STUNPort: cfg.DerperSTUNPort,
		HTTPPort: cfg.DerperHTTPPort,
		KeyFile:  filepath.Join(cfg.DataDir, "derper.key"),
	}
	caddy := &edge.Caddy{
		Bin: dflt(cfg.CaddyBin, "caddy"), AdminAPI: "127.0.0.1:2019",
		HTTPSAddr: cfg.CaddyHTTPSAddr, Derper: cfg.DerperAddr,
		FilePath: filepath.Join(cfg.DataDir, "Caddyfile"),
	}

	// Best-effort edge boot: missing binaries must not kill pairing/bridge.
	tryBoot := func(name string, fn func() error) {
		if err := fn(); err != nil {
			log.Printf("pms: edge %s unavailable: %v (pairing + bridge still run)", name, err)
		}
	}
	tryBoot("derper", func() error { return derp.Start(ctx) })
	tryBoot("caddy", func() error {
		if err := caddy.Render(cfg.Domain, cfg.Email, cfg.AdminAddr, nil); err != nil {
			return err
		}
		return caddy.Start(ctx)
	})
	defer derp.Stop()
	defer caddy.Stop()
	// Public STUN for NAT discovery (derper's own STUN sits on loopback
	// with our -a; without this, clients fall back to DERP relay).
	if cfg.DerperSTUNPort > 0 {
		go edge.ServeSTUN(ctx, fmt.Sprintf(":%d", cfg.DerperSTUNPort))
	} else {
		log.Printf("pms: STUN disabled (derp_stun<=0); clients use relay only")
	}

	admin := &http.Server{
		Addr:              cfg.AdminAddr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	// The admin API is the control plane (pairing, directory, heartbeat):
	// a daemon that can't bind it is worse than useless (clients would
	// silently talk to whatever IS on that port), so this is fatal.
	adminLn, err := net.Listen("tcp", cfg.AdminAddr)
	if err != nil {
		return fmt.Errorf("admin %s: %w (another pms running?)", cfg.AdminAddr, err)
	}
	go func() {
		if err := admin.Serve(adminLn); err != nil && err != http.ErrServerClosed {
			log.Printf("pms: admin %s: %v", cfg.AdminAddr, err)
		}
	}()

	// Gate the bridge on our DERP map being fetchable: a dial made while
	// the map is unreachable falls back to the public default map and the
	// bridge homes on a foreign relay (silent blackhole, cached up to an
	// hour). No dial can usefully precede this — and without Caddy serving
	// TLS there is no inbound product anyway.
	mapURL := "https://pair." + cfg.Domain + "/_pms/derpmap.json"
	if err := waitForDERPMap(ctx, mapURL, 4*time.Minute); err != nil {
		log.Printf("pms: %v", err)
	}
	go s.reconcileLoop(ctx, cfg, caddy)

	<-ctx.Done()
	shut, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = admin.Shutdown(shut)
	return nil
}

// waitForDERPMap polls url until it returns 200 with a parseable map.
func waitForDERPMap(ctx context.Context, url string, timeout time.Duration) error {
	client := &http.Client{Timeout: 15 * time.Second}
	deadline := time.Now().Add(timeout)
	for {
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		if resp, err := client.Do(req); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			if resp.StatusCode == 200 && json.Valid(body) {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("derp map %s not ready after %s", url, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func dflt(v, fb string) string {
	if v != "" {
		return v
	}
	return fb
}

// shortKey logs a pubkey prefix (never the secret-bearing whole).
func shortKey(k string) string {
	if len(k) > 19 {
		return k[:19] + "…"
	}
	return k
}

// pidPath tracks the running daemon for refuse-if-running.
func pidPath(dataDir string) string { return dataDir + "/pms.pid" }

// validateConfig fails fast on operator error instead of degrading obscurely
// mid-run (dead challenges, unbindable listeners, unwritable state).
func validateConfig(cfg config.PMSConfig) error {
	if cfg.Domain == "" {
		return fmt.Errorf("run: no domain configured — pms init first")
	}
	if strings.ContainsAny(cfg.Domain, ":/") {
		return fmt.Errorf("run: domain %q must be a bare hostname", cfg.Domain)
	}
	if !strings.Contains(cfg.Email, "@") {
		return fmt.Errorf("run: bad ACME email %q — pms init --email", cfg.Email)
	}
	for name, addr := range map[string]string{
		"admin_addr": cfg.AdminAddr, "caddy_https_addr": cfg.CaddyHTTPSAddr,
		"derper_addr": cfg.DerperAddr,
	} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("run: bad %s %q", name, addr)
		}
	}
	if cfg.DerperHTTPPort != -1 && (cfg.DerperHTTPPort <= 0 || cfg.DerperHTTPPort > 65535) {
		return fmt.Errorf("run: bad derp_http_port %d (-1 disables)", cfg.DerperHTTPPort)
	}
	if cfg.DataBasePort <= 0 || cfg.DataBasePort > 60000 {
		return fmt.Errorf("run: bad data_base %d", cfg.DataBasePort)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("run: data dir %s: %w", cfg.DataDir, err)
	}
	return nil
}

// routes: pairing (rate-limited) + token-authed directory/heartbeat/rename
// + the public DERP map (relay metadata, intentionally unauthenticated —
// like any DERP map, it names the relay, not the mesh).
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	pl := newPairLimiter()
	mux.HandleFunc("/_pms/derpmap.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(derpMap("derp." + s.cfg.Domain))
	})
	mux.HandleFunc("/_pms/pair", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !pl.allow(ip) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		var req struct {
			Code     string `json:"code"`
			PubKey   string `json:"pubkey"`
			FullAddr string `json:"full_addr"`
			Hostname string `json:"hostname"`
		}
		if json.Unmarshal(body, &req) != nil || req.Code == "" || req.PubKey == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if _, err := keys.ParsePub(req.PubKey); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// Identical error for unknown/expired/used/locked: no oracle.
		// Outcomes are audit-logged (IP + result only, never secrets).
		if err := s.pst.Verify(req.Code, time.Now()); err != nil {
			time.Sleep(200 * time.Millisecond)
			log.Printf("pms: pairing denied for %s", ip)
			http.Error(w, "invalid or expired pairing code", http.StatusUnauthorized)
			return
		}
		name, token, err := s.dir.Add(config.AutoName(req.Hostname), req.PubKey, req.FullAddr)
		if err != nil {
			http.Error(w, "pairing failed", http.StatusInternalServerError)
			return
		}
		log.Printf("pms: paired %q for %s", name, ip)
		json.NewEncoder(w).Encode(map[string]string{
			"name": name, "token": token,
			"derp_host": "derp." + s.cfg.Domain, "domain": s.cfg.Domain,
		})
	})
	authed := func(next func(http.ResponseWriter, *http.Request, directory.Device)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			name := r.Header.Get("X-Device")
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			dev, ok := s.dir.AuthToken(name, tok)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r, dev)
		}
	}
	mux.HandleFunc("/_pms/directory", authed(func(w http.ResponseWriter, r *http.Request, _ directory.Device) {
		json.NewEncoder(w).Encode(map[string]any{
			"revision": s.dir.Revision(), "devices": s.dir.List(),
			"server_pubkey": s.srvPub,
		})
	}))
	mux.HandleFunc("/_pms/heartbeat", authed(func(w http.ResponseWriter, r *http.Request, dev directory.Device) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		var req struct {
			FullAddr string    `json:"full_addr"`
			Exposes  *[]string `json:"exposes"` // nil = absent, keep old
			Online   *bool     `json:"online"`  // nil = true (legacy daemons)
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// Empty address is legitimate (tunnel down, heartbeat alive);
		// non-empty must parse as a tailcat address or the old one stands.
		addr := req.FullAddr
		if addr != "" {
			if _, err := tailcat.ParseAddr(tailcat.Addr(addr)); err != nil {
				log.Printf("pms: bad full_addr from %q, keeping old", dev.Name)
				addr = dev.FullAddr
			}
		}
		online := req.Online == nil || *req.Online
		_ = s.dir.Heartbeat(dev.Name, addr, online)
		if req.Exposes != nil {
			_ = s.dir.SetExposes(dev.Name, *req.Exposes)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("/_pms/rename", authed(func(w http.ResponseWriter, r *http.Request, dev directory.Device) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
		var req struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(body, &req) != nil || !config.ValidName(req.Name) {
			http.Error(w, "bad name (lowercase, digits, hyphens)", http.StatusBadRequest)
			return
		}
		switch err := s.dir.Rename(dev.Name, req.Name); err {
		case nil:
			json.NewEncoder(w).Encode(map[string]string{"name": req.Name})
		case directory.ErrExists:
			http.Error(w, "name taken", http.StatusConflict)
		default:
			http.Error(w, "rename failed", http.StatusInternalServerError)
		}
	}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(health.Status{Role: "pms", Healthy: true, Devices: len(s.dir.List()), Revision: s.dir.Revision()})
	})
	return mux
}

// derpMap is the single-region map every mesh member must use INSTEAD of
// the public default. A sender homed on a foreign relay (e.g. a public
// one from the default map) can never reach a peer homed on ours — relays
// only forward within meshed infrastructure, and ours meshes with nothing.
// This misrouting shipped unnoticed once (tunnel dialed forever while the
// relay sat idle); the map constraint is load-bearing, not cosmetic.
//
// OmitDefaultRegions is the teeth: without it the custom regions MERGE
// with the public defaults and netcheck happily homes on a foreign relay
// again (observed live: home derp-1 despite our map being fetched fine).
func derpMap(derpHost string) *tailcfg.DERPMap {
	return &tailcfg.DERPMap{
		OmitDefaultRegions: true,
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			900: {
				RegionID: 900, RegionCode: "pms", RegionName: "pairmesh",
				Nodes: []*tailcfg.DERPNode{{
					Name: "900a", RegionID: 900, HostName: derpHost,
					DERPPort: 443, STUNPort: 3478,
				}},
			},
		},
	}
}

// The map itself is handler-shared state; unsynchronized access is a data
// race under concurrent pairing attempts.
// pairLimiter is a mutex-guarded 5/min-per-IP limiter set.
// The map itself is handler-shared state; unsynchronized access is a data
// race under concurrent pairing attempts.
type pairLimiter struct {
	mu sync.Mutex
	m  map[string]*rate.Limiter
}

func newPairLimiter() *pairLimiter { return &pairLimiter{m: map[string]*rate.Limiter{}} }

// allow: 5/min per IP.
func (p *pairLimiter) allow(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	l, ok := p.m[ip]
	if !ok {
		if len(p.m) > 4096 {
			return false
		}
		l = rate.NewLimiter(rate.Every(12*time.Second), 5)
		p.m[ip] = l
	}
	return l.Allow()
}

// reconcileLoop keeps bridge forwards + Caddyfile in sync with the
// directory. Web expose web:<as>:<local> on device D → 127.0.0.1:<base+n> →
// (D addr, local); Caddy <as>.<domain> → that port. Raw tcp:<pub>:<local> /
// udp:<pub>:<local> bind the public port directly (pms owns the edge).
// ssh on D → localhost forward for operator use (no public port).
func (s *server) reconcileLoop(ctx context.Context, cfg config.PMSConfig, caddy *edge.Caddy) {
	var mu sync.Mutex
	forwards := map[string]context.CancelFunc{}
	fwdAddr := map[string]string{} // forward key → tailcat addr it dials
	ensure := func(key, listen, addr string, port uint16, udp bool) {
		mu.Lock()
		if _, ok := forwards[key]; ok {
			if fwdAddr[key] == addr {
				mu.Unlock()
				return
			}
			// Address rotated under a live forward (re-pair, region
			// move): the old closure would dial the dead address
			// forever — Caddy correctly alerts on the retired SNI
			// while the directory shows the new one. Recreate.
			log.Printf("pms: forward %s address changed, recreating", key)
			forwards[key]()
			delete(forwards, key)
		}
		fctx, cancel := context.WithCancel(ctx)
		forwards[key] = cancel
		fwdAddr[key] = addr
		mu.Unlock()
		go func() {
			var err error
			if udp {
				err = s.tun.ForwardUDP(fctx, listen, tailcat.Addr(addr), port)
			} else {
				err = s.tun.ForwardTCP(fctx, listen, tailcat.Addr(addr), port)
			}
			// Drop the key so the next tick recreates a failed listener
			// (port conflict resolved, daemon back, …). Keep fwdAddr: a
			// changed address is detected via mismatch above.
			mu.Lock()
			delete(forwards, key)
			mu.Unlock()
			if err != nil {
				log.Printf("pms: forward %s (%s): %v", key, listen, err)
			}
		}()
	}
	prune := func(live map[string]bool) {
		mu.Lock()
		defer mu.Unlock()
		for key, cancel := range forwards {
			if !live[key] {
				cancel()
				delete(forwards, key)
				delete(fwdAddr, key)
			}
		}
	}
	var lastExposes string
	reconcile := func() {
		devs, err := s.dir.ListErr()
		if err != nil {
			// Transient store error: keep last-known forwards + Caddyfile,
			// never fail open to an empty edge.
			log.Printf("pms: directory read: %v (keeping last-known edge)", err)
			return
		}
		live := map[string]bool{}
		claim := map[string]string{} // shared edge name → owning device
		// take claims a shared name (public port, web host); first claimant
		// (pairing order) wins, losers log loudly instead of breaking the
		// edge with duplicates.
		take := func(what, name, owner string) bool {
			if o, ok := claim[what+"/"+name]; ok {
				if o != owner {
					log.Printf("pms: %s %q already claimed by %s (skipping %s)", what, name, o, owner)
				}
				return false
			}
			claim[what+"/"+name] = owner
			return true
		}
		var exposes []edge.Expose
		n := 0
		for _, dev := range devs {
			if dev.FullAddr == "" {
				continue
			}
			for _, spec := range dev.Exposes {
				kind, a, b := splitSpec(spec)
				switch kind {
				case "web":
					local, err := parsePort(b)
					if err != nil {
						log.Printf("pms: bad expose %q on %s: %v", spec, dev.Name, err)
						continue
					}
					if !config.ValidName(a) {
						log.Printf("pms: bad expose name %q on %s", spec, dev.Name)
						continue
					}
					host := a + "." + cfg.Domain
					if !take("host", host, dev.Name) {
						continue
					}
					listen := fmt.Sprintf("127.0.0.1:%d", cfg.DataBasePort+n)
					key := fmt.Sprintf("web/%s/%s", dev.Name, a)
					live[key] = true
					ensure(key, listen, dev.FullAddr, local, false)
					exposes = append(exposes, edge.Expose{Host: host, To: listen})
					n++
				case "webhost":
					// Full custom hostname (e.g. t3.oci.pujan.space): DNS
					// must point at us; LE HTTP-01 flows like any site.
					host := strings.ToLower(a)
					local, err := parsePort(b)
					if err != nil || !config.ValidHost(host) {
						log.Printf("pms: bad expose %q on %s", spec, dev.Name)
						continue
					}
					if !take("host", host, dev.Name) {
						continue
					}
					listen := fmt.Sprintf("127.0.0.1:%d", cfg.DataBasePort+n)
					key := fmt.Sprintf("webhost/%s/%s", dev.Name, host)
					live[key] = true
					ensure(key, listen, dev.FullAddr, local, false)
					exposes = append(exposes, edge.Expose{Host: host, To: listen})
					n++
				case "tcp", "udp":
					pub, err1 := parsePort(a)
					local, err2 := parsePort(b)
					if err1 != nil || err2 != nil {
						log.Printf("pms: bad expose %q on %s", spec, dev.Name)
						continue
					}
					if !take(kind+"-port", fmt.Sprint(pub), dev.Name) {
						continue
					}
					listen := fmt.Sprintf(":%d", pub) // public edge port
					key := fmt.Sprintf("pub-%s/%d", kind, pub)
					live[key] = true
					ensure(key, listen, dev.FullAddr, local, kind == "udp")
					n++
				case "ssh":
					listen := fmt.Sprintf("127.0.0.1:%d", cfg.DataBasePort+n)
					key := fmt.Sprintf("ssh/%s", dev.Name)
					live[key] = true
					ensure(key, listen, dev.FullAddr, 22, false)
					n++
				default:
					log.Printf("pms: unknown expose %q on %s", spec, dev.Name)
				}
			}
		}
		prune(live)
		sig := exposesSig(exposes)
		if sig == lastExposes {
			return // forwards healed/pruned above; edge config unchanged
		}
		lastExposes = sig
		if err := caddy.Render(cfg.Domain, cfg.Email, cfg.AdminAddr, exposes); err != nil {
			log.Printf("pms: render caddyfile: %v", err)
			return
		}
		if err := caddy.Reload(); err != nil {
			log.Printf("pms: %v (edge runs previous config)", err)
			return
		}
	}
	reconcile() // immediate first pass, not after the first 15 s tick
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			// Every tick heals dead listeners (ensure) and prunes
			// removed devices; Caddy re-renders only on expose change.
			reconcile()
		}
	}
}

// exposesSig fingerprints the rendered edge so identical ticks skip reload.
func exposesSig(ex []edge.Expose) string {
	var b strings.Builder
	for _, e := range ex {
		b.WriteString(e.Host)
		b.WriteByte(0)
		b.WriteString(e.To)
		b.WriteByte(0)
	}
	return b.String()
}

func splitSpec(spec string) (kind, a, b string) {
	parts := strings.SplitN(spec, ":", 3)
	for len(parts) < 3 {
		parts = append(parts, "")
	}
	return parts[0], parts[1], parts[2]
}

// parsePort strictly parses a TCP/UDP port (Sscanf is unchecked by design).
func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 || n > 65535 {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return uint16(n), nil
}
