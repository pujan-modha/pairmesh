// Command pmc runs on private machines: pair once, then expose/serve/ssh.
//
//	Usage:
//	  pmc pair <code> [--server https://pair.<domain>]
//	  pmc 3000 --as next        expose localhost:3000 as https://next.<domain>
//	  pmc expose 5432 --tcp     expose raw TCP
//	  pmc serve ssh             serve this box's sshd (127.0.0.1:22) to the mesh
//	  pmc ssh [user@]<name> [-- cmd]  open SSH to a paired device (no tokens)
//	  pmc devices | pmc list | pmc status
//	  pmc rename <name> | pmc unexpose <as> | pmc up [-d] | pmc down
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"

	"github.com/pujan-modha/pairmesh/internal/bridge"
	"github.com/pujan-modha/pairmesh/internal/config"
	"github.com/pujan-modha/pairmesh/internal/keys"
	"github.com/pujan-modha/pairmesh/internal/pid"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	// --config anywhere: extract it, find the command as the first
	// non-flag token, pass everything (plus --config first) to it.
	rest := os.Args[1:]
	cfgVal, tmp := pullFlag(rest, "config")
	rest = tmp
	cmd := ""
	cargs := []string{}
	for i, a := range rest {
		if cmd == "" && !strings.HasPrefix(a, "-") {
			cmd, cargs = a, rest[i+1:]
			break
		}
	}
	if cmd == "" {
		usage()
		os.Exit(2)
	}
	if cfgVal != "" {
		cargs = append([]string{"--config", cfgVal}, cargs...)
	}
	args := cargs
	// Bare `pmc 3000` shorthand.
	if port, err := strconv.Atoi(cmd); err == nil {
		if err := cmdExpose(append([]string{strconv.Itoa(port)}, args...)); err != nil {
			fatal(err)
		}
		return
	}
	var err error
	switch cmd {
	case "pair":
		err = cmdPair(args)
	case "expose":
		err = cmdExpose(args)
	case "serve":
		err = cmdServe(args)
	case "unserve":
		err = cmdUnserve(args)
	case "ssh":
		err = cmdSSH(args)
	case "forward":
		err = cmdForward(args)
	case "unforward":
		err = cmdUnforward(args)
	case "forwards":
		err = cmdForwards(args)
	case "devices":
		err = cmdDevices(args)
	case "list":
		err = cmdList(args)
	case "status":
		err = cmdStatus(args)
	case "rename":
		err = cmdRename(args)
	case "unexpose":
		err = cmdUnexpose(args)
	case "up":
		err = cmdUp(args)
	case "down":
		err = cmdDown(args)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "pmc: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "pmc: %v\n", err)
	os.Exit(1)
}

func usage() {
	fmt.Println(`pmc — pairmesh client (runs on private machines)

  pmc pair <code>             link this device (once, no args besides code)
  pmc 3000 --as next          expose localhost:3000 as https://next.<domain>
  pmc expose 5432 --tcp       expose raw TCP  :5432
  pmc expose 53 --udp         expose raw UDP  :53
  pmc serve ssh               serve this box's sshd to paired devices
  pmc unserve ssh             stop serving sshd
  pmc ssh [user@]<name> [-- cmd]  SSH into a paired device (names, not tokens)
  pmc forward <name>:<port> [local]  localhost forward for plain-TCP tools
  pmc forward <name>:<port> --persist  keep it via daemon (see pmc forwards)
  pmc unforward <name:port|local>      drop a persistent forward
  pmc forwards                    show persistent forwards + live state
  pmc devices                 paired devices + presence
  pmc list                    this device's exposes
  pmc status                  tunnel + daemon health
  pmc rename <name>           request a new device name
  pmc unexpose <as>           drop an expose
  pmc up [-d] | pmc down      daemonize / stop (reads config file)

Config: ~/.config/pmc/config.yaml (flags override; token via file/env only).`)
}

func cfgPath(fs *flag.FlagSet) *string {
	return fs.String("config", defaultCfgPath(), "config path")
}

// hoist pulls --names (value or = form) from anywhere in args to the front,
// so positional-first invocations like `pmc 3000 --as next` parse correctly.
func hoist(args []string, names ...string) []string {
	var front []string
	for _, n := range names {
		if v, rest := pullFlag(args, n); v != "" {
			front = append(front, "--"+n, v)
			args = rest
		}
	}
	return append(front, args...)
}
func pullFlag(args []string, name string) (string, []string) {
	var val string
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--"+name && i+1 < len(args) {
			val = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(a, "--"+name+"=") {
			val = strings.TrimPrefix(a, "--"+name+"=")
			continue
		}
		rest = append(rest, a)
	}
	return val, rest
}

func defaultCfgPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "pmc", "config.yaml")
}

func loadPMC(path string) config.PMCConfig {
	cfg := config.DefaultPMC()
	_ = config.LoadYAML(path, &cfg)
	if v := os.Getenv("PMC_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	if v := os.Getenv("PMC_TOKEN"); v != "" {
		cfg.Token = v
	}
	if v := os.Getenv("PMC_SERVER"); v != "" {
		cfg.Server = v
	}
	return cfg
}

func savePMC(path string, cfg *config.PMCConfig) error {
	return config.SaveYAML(path, cfg)
}

// --- pair ---

func cmdPair(args []string) error {
	args = hoist(args, "server", "config")
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	cp := cfgPath(fs)
	server := fs.String("server", "", "pairing URL (default https://pair.<domain>)")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: pmc pair <code>")
	}
	code := fs.Arg(0)
	cfg := loadPMC(*cp)
	url := *server
	if url == "" {
		if cfg.Server == "" {
			return fmt.Errorf("no server known — pass --server (e.g. pmc pair <code> --server https://pair.<domain>)")
		}
		url = cfg.Server
	}
	url = strings.TrimSuffix(url, "/")
	// Identity first, bound to the real DERP host up front (derived from the
	// pairing URL), so we have a stable pubkey to send and a killed pair
	// never leaves a placeholder-region identity behind.
	id, err := keys.LoadOrCreate(cfg.DataDir, guessDerpHost(url))
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	reqBody, _ := json.Marshal(map[string]string{
		"code": code, "pubkey": id.NodePub, "hostname": host,
	})
	resp, err := apiClient.Post(url+"/_pms/pair", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("pair: %w (is the code fresh and the server reachable?)", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pair: server refused (code invalid, expired, used, or enrollment closed)")
	}
	var out struct {
		Name     string `json:"name"`
		Token    string `json:"token"`
		DerpHost string `json:"derp_host"`
		Domain   string `json:"domain"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	// Rebind identity to the real DERP host (node key preserved).
	if _, err := keys.LoadOrCreate(cfg.DataDir, out.DerpHost); err != nil {
		return err
	}
	cfg.Device, cfg.Token, cfg.Domain = out.Name, out.Token, out.Domain
	cfg.Server = url // the base URL that worked (stored for devices/heartbeat)
	if err := savePMC(*cp, &cfg); err != nil {
		return err
	}
	fmt.Printf("paired as %q\n", out.Name)
	ensureDaemon(*cp, cfg) // pair takes effect immediately, no `up` step
	return nil
}

// --- expose ---

func cmdExpose(args []string) error {
	args = hoist(args, "config", "as", "host", "tcp", "udp")
	fs := flag.NewFlagSet("expose", flag.ExitOnError)
	cp := cfgPath(fs)
	as := fs.String("as", "", "public name → https://<as>.<domain>")
	host := fs.String("host", "", "full custom hostname → local (DNS must point here)")
	tcp := fs.Int("tcp", -1, "public TCP port")
	udp := fs.Int("udp", -1, "public UDP port")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: pmc expose <local-port> [--as name] [--host name] [--tcp port] [--udp port]")
	}
	local, err := strconv.Atoi(fs.Arg(0))
	if err != nil || local <= 0 || local > 65535 {
		return fmt.Errorf("bad local port %q", fs.Arg(0))
	}
	for _, p := range []struct {
		name string
		v    int
	}{{"tcp", *tcp}, {"udp", *udp}} {
		if p.v != -1 && (p.v <= 0 || p.v > 65535) {
			return fmt.Errorf("bad --%s port %d", p.name, p.v)
		}
	}
	if *tcp == -1 {
		*tcp = 0
	}
	if *udp == -1 {
		*udp = 0
	}
	cfg := loadPMC(*cp)
	modes := 0
	if *as != "" {
		modes++
	}
	if *host != "" {
		modes++
	}
	if *tcp != 0 {
		modes++
	}
	if *udp != 0 {
		modes++
	}
	if modes == 0 {
		// Bare `pmc 3000` = web expose, auto-named p<port>.
		*as = fmt.Sprintf("p%d", local)
		modes = 1
	}
	if modes > 1 {
		return fmt.Errorf("one mode per expose: --as xor --host xor --tcp xor --udp")
	}
	if *as != "" && !config.ValidName(*as) {
		return fmt.Errorf("bad name %q (lowercase letters, digits, hyphens)", *as)
	}
	if *host != "" {
		*host = strings.ToLower(strings.TrimSpace(*host))
		if !config.ValidHost(*host) {
			return fmt.Errorf("bad hostname %q", *host)
		}
	}
	// Replace same-local entries.
	kept := cfg.Exposes[:0]
	for _, e := range cfg.Exposes {
		if e.Local != local {
			kept = append(kept, e)
		}
	}
	kept = append(kept, config.Expose{Local: local, As: *as, Host: *host, TCP: *tcp, UDP: *udp})
	cfg.Exposes = kept
	if err := savePMC(*cp, &cfg); err != nil {
		return err
	}
	switch {
	case *as != "":
		fmt.Printf("exposed https://%s.%s → localhost:%d\n", *as, cfg.Domain, local)
	case *host != "":
		fmt.Printf("exposed https://%s → localhost:%d (DNS must point here)\n", *host, local)
	case *tcp != 0:
		fmt.Printf("exposed :%d → localhost:%d\n", *tcp, local)
	default:
		fmt.Printf("exposed udp :%d → localhost:%d\n", *udp, local)
	}
	ensureDaemon(*cp, cfg) // live within a minute, no `up` step
	return nil
}

func cmdUnexpose(args []string) error {
	args = hoist(args, "config")
	fs := flag.NewFlagSet("unexpose", flag.ExitOnError)
	cp := cfgPath(fs)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: pmc unexpose <as|port>")
	}
	cfg := loadPMC(*cp)
	key := fs.Arg(0)
	kept := cfg.Exposes[:0]
	for _, e := range cfg.Exposes {
		if e.As != key && strconv.Itoa(e.Local) != key {
			kept = append(kept, e)
		}
	}
	cfg.Exposes = kept
	if err := savePMC(*cp, &cfg); err != nil {
		return err
	}
	pokeDaemon(cfg)
	fmt.Printf("removed %q\n", key)
	return nil
}

// --- serve ssh ---

func cmdServe(args []string) error {
	args = hoist(args, "config")
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cp := cfgPath(fs)
	_ = fs.Parse(args)
	if fs.NArg() != 1 || fs.Arg(0) != "ssh" {
		return fmt.Errorf("usage: pmc serve ssh")
	}
	if c, err := net.DialTimeout("tcp", "127.0.0.1:22", 2*time.Second); err != nil {
		return fmt.Errorf("no sshd on 127.0.0.1:22 (%v) — start your system SSH server first", err)
	} else {
		c.Close()
	}
	cfg := loadPMC(*cp)
	cfg.ServeSSH = true
	if err := savePMC(*cp, &cfg); err != nil {
		return err
	}
	fmt.Println("sshd will be served to paired devices (key auth; no public port).")
	ensureDaemon(*cp, cfg)
	return nil
}

func cmdUnserve(args []string) error {
	args = hoist(args, "config")
	fs := flag.NewFlagSet("unserve", flag.ExitOnError)
	cp := cfgPath(fs)
	_ = fs.Parse(args)
	if fs.NArg() != 1 || fs.Arg(0) != "ssh" {
		return fmt.Errorf("usage: pmc unserve ssh")
	}
	cfg := loadPMC(*cp)
	cfg.ServeSSH = false
	if err := savePMC(*cp, &cfg); err != nil {
		return err
	}
	pokeDaemon(cfg)
	fmt.Println("sshd no longer served.")
	return nil
}

// --- ssh ---

func cmdSSH(args []string) error {
	// Split off optional `-- cmd`.
	var cmdArgs []string
	for i, a := range args {
		if a == "--" {
			cmdArgs, args = args[i+1:], args[:i]
			break
		}
	}
	fs := flag.NewFlagSet("ssh", flag.ExitOnError)
	cp := cfgPath(fs)
	args = hoist(args, "config")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: pmc ssh [user@]<name> [-- cmd]")
	}
	// Optional login user (`pmc ssh pujan@office`): the device identity
	// (TOFU pin) stays on <name>; the user only picks the far-end login.
	login, name := "", fs.Arg(0)
	if i := strings.LastIndex(name, "@"); i >= 0 {
		login, name = name[:i], name[i+1:]
	}
	if login != "" && !validLogin(login) {
		return fmt.Errorf("bad login user %q", login)
	}
	if name == "" {
		return fmt.Errorf("usage: pmc ssh [user@]<name> [-- cmd]")
	}
	cfg := loadPMC(*cp)
	if cfg.Device == "" || cfg.Token == "" {
		return fmt.Errorf("not paired — pmc pair <code> first")
	}
	peer, err := directoryLookup(cfg, name)
	if err != nil {
		return err
	}
	if err := trustCheck(cfg, peer); err != nil {
		return err
	}
	tun, err := newPeerTunnel(cfg)
	if err != nil {
		return err
	}
	dialer := newPeerDialer(tun, cfg, peer)
	defer dialer.tun.Close()
	// Local forward → peer:22, then stock ssh with per-name host alias.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		for {
			down, err := ln.Accept()
			if err != nil {
				return
			}
			go func(down net.Conn) {
				defer down.Close()
				up, err := dialer.dial(22)
				if err != nil {
					return
				}
				defer up.Close()
				tailcat.ProxyConns(down, up)
			}(down)
		}
	}()
	sshArgs := []string{
		"-p", portOf(ln.Addr().String()),
		// Per-name alias (stable known_hosts) + accept-new (TOFU at the SSH
		// layer too; changed keys still fail loudly — consistent with the
		// tailcat-level pin checked above).
		"-o", "HostKeyAlias=" + name, "-o", "StrictHostKeyChecking=accept-new",
		sshTarget(login),
	}
	sshArgs = append(sshArgs, cmdArgs...)
	ssh := exec.Command("ssh", sshArgs...)
	ssh.Stdin, ssh.Stdout, ssh.Stderr = os.Stdin, os.Stdout, os.Stderr
	return ssh.Run()
}

// sshTarget renders the stock-ssh destination for an optional login user.
func sshTarget(login string) string {
	if login == "" {
		return "127.0.0.1"
	}
	return login + "@127.0.0.1"
}

// peerDialer dials one peer's TCP ports through the mesh: directory lookup
// once, TOFU check once, then per-connection dials with one refresh-and-
// retry on stale addresses (peer re-paired, daemon restarted). The tunnel
// is caller-owned (shared daemon tunnel or per-command one); close is the
// tunnel owner's job, not the dialer's.
type peerDialer struct {
	tun  *bridge.Tunnel
	ctx  context.Context
	cfg  config.PMCConfig
	name string
	mu   sync.Mutex
	cur  peerInfo
}

func newPeerDialer(tun *bridge.Tunnel, cfg config.PMCConfig, peer peerInfo) *peerDialer {
	return &peerDialer{
		tun: tun,
		ctx: context.Background(),
		cfg: cfg, name: peer.Name, cur: peer,
	}
}

// newPeerTunnel builds a keyed tunnel for dialing out (client role).
func newPeerTunnel(cfg config.PMCConfig) (*bridge.Tunnel, error) {
	tun := bridge.New(nil)
	ck, err := clientKey(cfg)
	if err != nil {
		tun.Close()
		return nil, err
	}
	tun.WithClientKey(ck)
	tun.WithDERPMapURL(apiBase(cfg) + "/_pms/derpmap.json")
	return tun, nil
}

func (d *peerDialer) refresh() {
	if p, err := directoryLookup(d.cfg, d.name); err == nil && p.FullAddr != "" {
		d.mu.Lock()
		d.cur = p
		d.mu.Unlock()
	}
}

func (d *peerDialer) dial(port uint16) (net.Conn, error) {
	d.mu.Lock()
	addr := d.cur.FullAddr
	d.mu.Unlock()
	ctx, cancel := context.WithTimeout(d.ctx, bridge.DialTimeout)
	defer cancel()
	if up, err := d.tun.DialTCP(ctx, tailcat.Addr(addr), port); err == nil {
		return up, nil
	}
	d.refresh()
	d.mu.Lock()
	addr = d.cur.FullAddr
	d.mu.Unlock()
	ctx2, cancel2 := context.WithTimeout(d.ctx, bridge.DialTimeout)
	defer cancel2()
	return d.tun.DialTCP(ctx2, tailcat.Addr(addr), port)
}

// parseForwardTarget splits "<name>:<port>" (device names never contain
// colons, so the last one separates).
func parseForwardTarget(s string) (name string, port uint16, err error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, fmt.Errorf("want <name>:<port>, got %q", s)
	}
	n, perr := strconv.Atoi(s[i+1:])
	if perr != nil || n <= 0 || n > 65535 {
		return "", 0, fmt.Errorf("bad port in %q", s)
	}
	if s[:i] == "" {
		return "", 0, fmt.Errorf("want <name>:<port>, got %q", s)
	}
	return s[:i], uint16(n), nil
}

// pickLocalPort binds 127.0.0.1:want, or the next free port above it,
// and reports loudly which one won. Loopback has no names, so stable,
// announced ports are the entire UX. Privileged ports (<1024) need root:
// non-root callers skip straight past them instead of burning the scan
// budget one EACCES at a time.
func pickLocalPort(want int) (int, error) {
	try := func(p int) (int, bool) {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			return 0, false
		}
		ln.Close()
		return p, true
	}
	if p, ok := try(want); ok {
		return p, nil // exact wish (works as root, or free)
	}
	start := want + 1
	if start < 1024 {
		start = 1024
	}
	for p := start; p <= 65535 && p-start <= 1000; p++ {
		if q, ok := try(p); ok {
			return q, nil
		}
	}
	return 0, fmt.Errorf("no free loopback port near %d", want)
}

// cmdForward exposes a peer's TCP port on local loopback for tools that
// speak plain SSH/TCP but not the mesh: VS Code Remote, Ansible, Termius,
// database GUIs, rsync, scp. Foreground runs until Ctrl-C; --persist hands
// the mapping to the daemon instead (survives restarts, see pmc forwards).
func cmdForward(args []string) error {
	// --persist is boolean: strip it before hoist (which assumes
	// --flag value pairs and would swallow the next positional).
	var persist bool
	kept := args[:0]
	for _, a := range args {
		if a == "--persist" {
			persist = true
			continue
		}
		kept = append(kept, a)
	}
	args = hoist(kept, "config")
	fs := flag.NewFlagSet("forward", flag.ExitOnError)
	cp := cfgPath(fs)
	_ = fs.Parse(args)
	if fs.NArg() < 1 || fs.NArg() > 2 {
		return fmt.Errorf("usage: pmc forward <name>:<port> [local-port] [--persist]")
	}
	name, port, err := parseForwardTarget(fs.Arg(0))
	if err != nil {
		return err
	}
	want := int(port)
	if fs.NArg() == 2 {
		want, err = strconv.Atoi(fs.Arg(1))
		if err != nil || want <= 0 || want > 65535 {
			return fmt.Errorf("bad local port %q", fs.Arg(1))
		}
	}
	cfg := loadPMC(*cp)
	if cfg.Device == "" || cfg.Token == "" {
		return fmt.Errorf("not paired — pmc pair <code> first")
	}
	peer, err := directoryLookup(cfg, name)
	if err != nil {
		return err
	}
	if err := trustCheck(cfg, peer); err != nil {
		return err
	}
	local, err := pickLocalPort(want)
	if err != nil {
		return err
	}
	if local != want {
		fmt.Printf("port %d busy, using %d instead\n", want, local)
	}
	if persist {
		kept := cfg.Forwards[:0]
		for _, f := range cfg.Forwards {
			if f.To != fs.Arg(0) {
				kept = append(kept, f)
			}
		}
		cfg.Forwards = append(kept, config.Forward{To: fs.Arg(0), Local: local})
		if err := savePMC(*cp, &cfg); err != nil {
			return err
		}
		fmt.Printf("persistent: 127.0.0.1:%d → %s (daemon holds it)\n", local, fs.Arg(0))
		ensureDaemon(*cp, cfg)
		return nil
	}
	tun, err := newPeerTunnel(cfg)
	if err != nil {
		return err
	}
	dialer := newPeerDialer(tun, cfg, peer)
	defer dialer.tun.Close()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", local))
	if err != nil {
		return fmt.Errorf("forward: listen: %w (taken in the meantime?)", err)
	}
	defer ln.Close()
	fmt.Printf("forwarding 127.0.0.1:%d → %s:%d  (Ctrl-C to stop)\n", local, name, port)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		down, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		go func(down net.Conn) {
			defer down.Close()
			up, err := dialer.dial(port)
			if err != nil {
				return
			}
			defer up.Close()
			tailcat.ProxyConns(down, up)
		}(down)
	}
}

// validLogin accepts POSIX-ish login names; stock ssh re-validates anyway.
func validLogin(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' && i > 0 || c == '_' || c == '-' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

func portOf(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

// fwdState is one daemon-held forward for `pmc forwards` (loopback file,
// not an API — same machine only).
type fwdState struct {
	To    string `json:"to"`
	Local int    `json:"local"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func fwdStatePath(cfg config.PMCConfig) string {
	return filepath.Join(cfg.DataDir, "forwards.json")
}

func cmdUnforward(args []string) error {
	args = hoist(args, "config")
	fs := flag.NewFlagSet("unforward", flag.ExitOnError)
	cp := cfgPath(fs)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: pmc unforward <name:port|local-port>")
	}
	cfg := loadPMC(*cp)
	key := fs.Arg(0)
	kept := cfg.Forwards[:0]
	for _, f := range cfg.Forwards {
		if f.To != key && strconv.Itoa(f.Local) != key {
			kept = append(kept, f)
		}
	}
	cfg.Forwards = kept
	if err := savePMC(*cp, &cfg); err != nil {
		return err
	}
	pokeDaemon(cfg)
	fmt.Printf("removed %q (daemon drops it within half a minute)\n", key)
	return nil
}

func cmdForwards(args []string) error {
	args = hoist(args, "config")
	fs := flag.NewFlagSet("forwards", flag.ExitOnError)
	cp := cfgPath(fs)
	_ = fs.Parse(args)
	cfg := loadPMC(*cp)
	if len(cfg.Forwards) == 0 {
		fmt.Println("no persistent forwards (pmc forward <name>:<port> --persist)")
		return nil
	}
	live := map[string]fwdState{}
	if b, err := os.ReadFile(fwdStatePath(cfg)); err == nil {
		var states []fwdState
		if json.Unmarshal(b, &states) == nil {
			for _, st := range states {
				live[st.To] = st
			}
		}
	}
	for _, f := range cfg.Forwards {
		st := "starting"
		if s, ok := live[f.To]; ok {
			if s.OK {
				st = "live"
			} else {
				st = "error: " + s.Error
			}
		} else if !isDaemonUp(cfg) {
			st = "daemon down"
		}
		fmt.Printf("127.0.0.1:%-6d → %-16s %s\n", f.Local, f.To, st)
	}
	return nil
}

// --- devices / list / status ---

func cmdDevices(args []string) error {
	args = hoist(args, "config")
	fs := flag.NewFlagSet("devices", flag.ExitOnError)
	cp := cfgPath(fs)
	_ = fs.Parse(args)
	cfg := loadPMC(*cp)
	devs, _, err := directoryFetch(cfg)
	if err != nil {
		return err
	}
	for _, d := range devs {
		st := "offline"
		if d.Online && time.Since(d.LastSeen) < 2*time.Minute {
			st = "online"
		}
		mark := ""
		if d.Name == cfg.Device {
			mark = " (this device)"
		}
		if len(d.SSHUsers) > 0 {
			mark += fmt.Sprintf(" [ssh: %s]", strings.Join(d.SSHUsers, ", "))
		}
		fmt.Printf("%-24s %-7s%s\n", d.Name, st, mark)
	}
	return nil
}

func cmdList(args []string) error {
	args = hoist(args, "config")
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	cp := cfgPath(fs)
	_ = fs.Parse(args)
	cfg := loadPMC(*cp)
	for _, e := range cfg.Exposes {
		switch {
		case e.As != "":
			fmt.Printf("web  https://%s.%s → localhost:%d\n", e.As, cfg.Domain, e.Local)
		case e.Host != "":
			fmt.Printf("web  https://%s → localhost:%d\n", e.Host, e.Local)
		case e.TCP != 0:
			fmt.Printf("tcp  :%d → localhost:%d\n", e.TCP, e.Local)
		case e.UDP != 0:
			fmt.Printf("udp  :%d → localhost:%d\n", e.UDP, e.Local)
		}
	}
	if cfg.ServeSSH {
		fmt.Println("ssh  (served to paired devices)")
	}
	return nil
}

func cmdStatus(args []string) error {
	args = hoist(args, "config")
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cp := cfgPath(fs)
	_ = fs.Parse(args)
	cfg := loadPMC(*cp)
	fmt.Printf("device: %s  server: %s\n", cfg.Device, cfg.Server)
	if isDaemonUp(cfg) {
		fmt.Println("daemon: running")
	} else {
		fmt.Println("daemon: stopped (pmc up)")
	}
	return nil
}

func cmdRename(args []string) error {
	args = hoist(args, "config")
	fs := flag.NewFlagSet("rename", flag.ExitOnError)
	cp := cfgPath(fs)
	_ = fs.Parse(args)
	if fs.NArg() != 1 || !config.ValidName(fs.Arg(0)) {
		return fmt.Errorf("usage: pmc rename <name>  (lowercase, digits, hyphens)")
	}
	cfg := loadPMC(*cp)
	if cfg.Device == "" || cfg.Token == "" {
		return fmt.Errorf("not paired — pmc pair <code> first")
	}
	body, _ := json.Marshal(map[string]string{"name": fs.Arg(0)})
	req, _ := http.NewRequest("POST", apiBase(cfg)+"/_pms/rename", bytes.NewReader(body))
	req.Header.Set("X-Device", cfg.Device)
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := apiClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var out struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return err
		}
		cfg.Device = out.Name
		if err := savePMC(*cp, &cfg); err != nil {
			return err
		}
		pokeDaemon(cfg)
		fmt.Printf("renamed to %q\n", out.Name)
		return nil
	case http.StatusConflict:
		return fmt.Errorf("name %q is taken", fs.Arg(0))
	default:
		return fmt.Errorf("rename refused (re-pair?)")
	}
}

// --- up / down ---

func pidPath(cfg config.PMCConfig) string { return cfg.DataDir + "/pmc.pid" }

func isDaemonUp(cfg config.PMCConfig) bool {
	return pid.Live(pid.Read(pidPath(cfg)), "pmc")
}

func pokeDaemon(cfg config.PMCConfig) {
	// Best-effort SIGHUP: daemon re-reads config + refreshes heartbeat.
	if p := pid.Read(pidPath(cfg)); pid.Live(p, "pmc") {
		if proc, err := os.FindProcess(p); err == nil {
			_ = proc.Signal(syscall.SIGHUP)
		}
	}
}

func cmdUp(args []string) error {
	args = hoist(args, "config")
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	cp := cfgPath(fs)
	daemon := fs.Bool("d", false, "detach")
	_ = fs.Parse(args)
	cfg := loadPMC(*cp)
	if cfg.Device == "" || cfg.Token == "" {
		return fmt.Errorf("not paired — pmc pair <code> first")
	}
	if *daemon {
		return startDetached(*cp, cfg)
	}
	// Foreground daemon (and the detached child above): singleton via file
	// lock, not pid existence. The lock dies with the process, so crashes
	// can't wedge startup — and a parent-written pid can never read as
	// "already running" to its own child.
	lock, err := pid.Acquire(pidPath(cfg), os.Getpid(), "pmc")
	if err != nil {
		return err
	}
	defer lock.Close()
	runDaemon(*cp)
	return nil
}

// startDetached launches the daemon in the background (log file, never the
// void: a silent daemon is undiagnosable).
func startDetached(cfgPath string, cfg config.PMCConfig) error {
	// Advisory pre-check so a duplicate fails HERE with a clear error
	// instead of spawning a child that immediately refuses in the log
	// file. (The child re-checks under its own lock — this is just UX,
	// the lock is the arbiter.)
	if p := pid.Read(pidPath(cfg)); pid.Live(p, "pmc") && pid.Busy(pidPath(cfg)) {
		return fmt.Errorf("daemon already running (pid %d) — pmc down first", p)
	}
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	logPath := filepath.Join(cfg.DataDir, "pmc.log")
	cmd := exec.Command(bin, "up", "--config", cfgPath)
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin = nil
	// Open here so a bad data dir fails loudly in the parent.
	lf, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("daemon log %s: %w", logPath, err)
	}
	defer lf.Close()
	cmd.Stdout, cmd.Stderr = lf, lf
	if err := cmd.Start(); err != nil {
		return err
	}
	fmt.Printf("daemon starting (log %s; verify with: pmc status)\n", logPath)
	return nil
}

// ensureDaemon starts the daemon if it isn't running. Called after
// pair/expose/serve so those commands take effect without a separate
// `pmc up` step — daily use never touches up/down/status.
func ensureDaemon(cfgPath string, cfg config.PMCConfig) {
	if isDaemonUp(cfg) {
		pokeDaemon(cfg)
		return
	}
	if err := startDetached(cfgPath, cfg); err != nil {
		fmt.Printf("note: daemon did not start (%v) — run `pmc up -d` to retry\n", err)
		return
	}
	fmt.Println("daemon started in the background (takes effect within a minute)")
}

func cmdDown(args []string) error {
	args = hoist(args, "config")
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	cp := cfgPath(fs)
	_ = fs.Parse(args)
	cfg := loadPMC(*cp)
	p := pid.Read(pidPath(cfg))
	if !pid.Live(p, "pmc") {
		fmt.Println("daemon not running")
		return nil
	}
	if proc, err := os.FindProcess(p); err == nil {
		_ = proc.Signal(syscall.SIGTERM)
	}
	markOffline(*cp)
	fmt.Println("daemon stopped")
	return nil
}

// --- daemon ---

func runDaemon(cfgPath string) {
	cfg := loadPMC(cfgPath)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	id, err := keys.LoadOrCreate(cfg.DataDir, derpHostOf(cfg))
	if err != nil {
		log.Printf("pmc: keys: %v", err)
		return
	}
	tun := bridge.New(log.Printf)
	if ck, err := id.ClientKey(); err == nil {
		tun.WithClientKey(ck)
	}
	// Our relay map, never the public default (a foreign home relay cannot
	// reach peers homed on ours — dials would hang with a live relay).
	tun.WithDERPMapURL(apiBase(cfg) + "/_pms/derpmap.json")
	defer tun.Close()

	var srv *tailcat.Server
	restartServing := func(allow []string) {
		if srv != nil {
			srv.Close()
			srv = nil
		}
		// Reload identity every restart (not just at boot): the node key
		// is stable but the region follows cfg.Server, so a domain move
		// converges on SIGHUP instead of stranding the server on a dead
		// DERP hostname (observed live: TLS errors to nowhere).
		nid, err := keys.LoadOrCreate(cfg.DataDir, derpHostOf(cfg))
		if err != nil {
			log.Printf("pmc: keys: %v", err)
			return
		}
		id = nid
		s, err := id.Server(log.Printf)
		if err != nil {
			log.Printf("pmc: server build: %v", err)
			return
		}
		s.DERPMapURL = apiBase(cfg) + "/_pms/derpmap.json"
		tcp := map[uint16]string{}
		for _, e := range cfg.Exposes {
			if e.UDP != 0 {
				continue // udp-only entries serve no TCP (least privilege)
			}
			tcp[uint16(e.Local)] = fmt.Sprintf("127.0.0.1:%d", e.Local)
		}
		if cfg.ServeSSH {
			tcp[22] = "127.0.0.1:22"
		}
		udp := map[uint16]string{}
		for _, e := range cfg.Exposes {
			if e.UDP != 0 {
				udp[uint16(e.Local)] = fmt.Sprintf("127.0.0.1:%d", e.Local)
			}
		}
		addr := ""
		if err := bridge.Serve(s, bridge.ServeConfig{TCP: tcp, UDP: udp, Allow: allow}); err != nil {
			log.Printf("pmc: serve: %v (heartbeat continues; tunnel comes up when DERP is reachable)", err)
		} else {
			srv = s
			addr = string(s.TailcatAddr())
		}
		heartbeat(cfgPath, cfg, addr)
		if srv != nil {
			log.Printf("pmc: serving as %q (allow %d peers)", cfg.Device, len(allow))
		}
	}

	// Allowlist with disk cache: a failed fetch keeps serving the last-known
	// set instead of failing closed to deny-all on a network blip.
	allow, _ := fetchAllowlist(cfg)
	allow = cachedAllow(cfg, allow)
	restartServing(allow)
	fwd := newFwdSync(ctx, tun, cfgPath)
	fwd.sync()
	hb := time.NewTicker(30 * time.Second)
	allowTick := time.NewTicker(30 * time.Second)
	defer hb.Stop()
	defer allowTick.Stop()
	lastSig := serveSignature(allow, cfg)
	for {
		select {
		case <-ctx.Done():
			markOffline(cfgPath)
			if srv != nil {
				srv.Close()
			}
			return
		case <-hup:
			cfg = loadPMC(cfgPath)
			allow, _ := fetchAllowlist(cfg)
			allow = cachedAllow(cfg, allow)
			lastSig = serveSignature(allow, cfg)
			restartServing(allow)
			fwd.sync()
		case <-hb.C:
			cfg = loadPMC(cfgPath)
			addr := ""
			if srv != nil {
				addr = string(srv.TailcatAddr())
			}
			heartbeat(cfgPath, cfg, addr)
		case <-allowTick.C:
			cfg = loadPMC(cfgPath)
			// Restart serving only when membership/exposes actually
			// changed — restarts flap the tailcat server otherwise.
			fresh, err := fetchAllowlist(cfg)
			if err != nil {
				continue // keep serving cached set; retry next tick
			}
			fresh = cachedAllow(cfg, fresh)
			if sig := serveSignature(fresh, cfg); sig != lastSig {
				lastSig = sig
				allow = fresh
				restartServing(allow)
			}
			fwd.sync()
		}
	}
}

// fwdSync holds the daemon's persistent forward listeners (`pmc forward
// --persist`), mirroring the config with prune + recreate semantics.
type fwdSync struct {
	ctx  context.Context
	tun  *bridge.Tunnel
	path string // config path (reloaded every sync)

	mu     sync.Mutex
	cancel map[string]context.CancelFunc // forward.To → stop
	pins   map[string]string             // forward.To → pinned peer pubkey
}

func newFwdSync(ctx context.Context, tun *bridge.Tunnel, cfgPath string) *fwdSync {
	return &fwdSync{
		ctx: ctx, tun: tun, path: cfgPath,
		cancel: map[string]context.CancelFunc{},
		pins:   map[string]string{},
	}
}

// pinnedChanged records the peer key on first sight; later mismatch errors.
func (f *fwdSync) pinnedChanged(to, pubkey string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if prev, ok := f.pins[to]; ok {
		return prev != pubkey
	}
	f.pins[to] = pubkey
	return false
}

// ensure runs one forward listener, recreating on failure (dropped key).
func (f *fwdSync) ensure(to string, local int, peer peerInfo, port uint16) {
	f.mu.Lock()
	if _, ok := f.cancel[to]; ok {
		f.mu.Unlock()
		return
	}
	fctx, cancel := context.WithCancel(f.ctx)
	f.cancel[to] = cancel
	f.mu.Unlock()
	go func() {
		defer func() {
			f.mu.Lock()
			delete(f.cancel, to)
			f.mu.Unlock()
		}()
		// Shared daemon tunnel (keyed at daemon start; node identity is
		// stable across rebinds, so no per-forward client needed).
		// Config reloaded fresh: a re-pair mid-run must not dial stale.
		dialer := newPeerDialer(f.tun, loadPMC(f.path), peer)
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", local))
		if err != nil {
			log.Printf("pmc: forward %s: listen: %v", to, err)
			return
		}
		defer ln.Close()
		go func() {
			<-fctx.Done()
			ln.Close()
		}()
		for {
			down, err := ln.Accept()
			if err != nil {
				select {
				case <-fctx.Done():
					return
				default:
					continue
				}
			}
			go func(down net.Conn) {
				defer down.Close()
				up, err := dialer.dial(port)
				if err != nil {
					return
				}
				defer up.Close()
				tailcat.ProxyConns(down, up)
			}(down)
		}
	}()
}

// prune stops listeners no longer configured.
func (f *fwdSync) prune(live map[string]bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for to, cancel := range f.cancel {
		if !live[to] {
			cancel()
			delete(f.cancel, to)
			delete(f.pins, to)
		}
	}
}

// sync reconciles listeners with the current config and writes
// forwards.json (read by `pmc forwards`). Directory fetch failures keep
// last-known listeners; TOFU pins are checked headlessly — a changed peer
// key errors loudly instead of following it.
func (f *fwdSync) sync() {
	cfg := loadPMC(f.path)
	if cfg.Device == "" {
		return // unpaired; nothing to hold
	}
	devs, _, err := directoryFetch(cfg)
	if err != nil {
		return // keep last-known; retry next tick
	}
	byName := map[string]peerInfo{}
	for _, d := range devs {
		byName[d.Name] = peerInfo{Name: d.Name, PubKey: d.PubKey, FullAddr: d.FullAddr}
	}
	live := map[string]bool{}
	var states []fwdState
	for _, fw := range cfg.Forwards {
		live[fw.To] = true
		st := fwdState{To: fw.To, Local: fw.Local, OK: true}
		name, port, err := parseForwardTarget(fw.To)
		peer, ok := byName[name]
		switch {
		case err != nil:
			st.OK, st.Error = false, err.Error()
		case !ok || peer.FullAddr == "":
			st.OK, st.Error = false, "peer unknown or offline"
		case f.pinnedChanged(fw.To, peer.PubKey):
			st.OK, st.Error = false, "peer identity changed — re-run pmc forward to re-pin"
		default:
			f.ensure(fw.To, fw.Local, peer, port)
		}
		states = append(states, st)
	}
	f.prune(live)
	if b, err := json.Marshal(states); err == nil {
		_ = os.WriteFile(fwdStatePath(cfg), b, 0o600)
	}
}

// serveSignature covers everything restartServing consumes, so the allow
// ticker can skip no-op restarts.
func serveSignature(allow []string, cfg config.PMCConfig) string {
	return fmt.Sprintf("allow=%s exposes=%v ssh=%v",
		strings.Join(allow, ","), exposeSpecs(cfg), cfg.ServeSSH)
}

// cachedAllow persists the last good allowlist; nil fetch results reuse it.
// The server is the source of truth — the cache only bridges outages.
func cachedAllow(cfg config.PMCConfig, fresh []string) []string {
	path := filepath.Join(cfg.DataDir, "allowlist.json")
	if fresh != nil {
		if b, err := json.Marshal(fresh); err == nil {
			_ = os.WriteFile(path, b, 0o600)
		}
		return fresh
	}
	var cached []string
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &cached)
	}
	return cached
}

// --- server API helpers ---

func apiBase(cfg config.PMCConfig) string { return strings.TrimSuffix(cfg.Server, "/") }

func directoryFetch(cfg config.PMCConfig) (devs []struct {
	Name     string    `json:"name"`
	PubKey   string    `json:"pubkey"`
	FullAddr string    `json:"full_addr"`
	Online   bool      `json:"online"`
	LastSeen time.Time `json:"last_seen"`
	SSHUsers []string  `json:"ssh_users"`
}, rev uint64, err error) {
	req, _ := http.NewRequest("GET", apiBase(cfg)+"/_pms/directory", nil)
	req.Header.Set("X-Device", cfg.Device)
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("directory: server refused (re-pair?)")
	}
	var out struct {
		Revision uint64 `json:"revision"`
		Devices  []struct {
			Name     string    `json:"name"`
			PubKey   string    `json:"pubkey"`
			FullAddr string    `json:"full_addr"`
			Online   bool      `json:"online"`
			LastSeen time.Time `json:"last_seen"`
			SSHUsers []string  `json:"ssh_users"`
		} `json:"devices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, 0, err
	}
	return out.Devices, out.Revision, nil
}

type peerInfo struct {
	Name     string
	PubKey   string
	FullAddr string
}

func directoryLookup(cfg config.PMCConfig, name string) (peerInfo, error) {
	req, _ := http.NewRequest("GET", apiBase(cfg)+"/_pms/directory", nil)
	req.Header.Set("X-Device", cfg.Device)
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := apiClient.Do(req)
	if err != nil {
		return peerInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return peerInfo{}, fmt.Errorf("directory: server refused (re-pair?)")
	}
	var out struct {
		Devices []struct {
			Name     string `json:"name"`
			PubKey   string `json:"pubkey"`
			FullAddr string `json:"full_addr"`
		} `json:"devices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return peerInfo{}, err
	}
	for _, d := range out.Devices {
		if d.Name == name {
			if d.FullAddr == "" {
				return peerInfo{}, fmt.Errorf("%q is offline (no address)", name)
			}
			return peerInfo{Name: d.Name, PubKey: d.PubKey, FullAddr: d.FullAddr}, nil
		}
	}
	return peerInfo{}, fmt.Errorf("no such device %q (pmc devices)", name)
}

// trustCheck implements TOFU: pin peer pubkey on first use, warn on change.
func trustCheck(cfg config.PMCConfig, p peerInfo) error {
	path := filepath.Join(cfg.DataDir, "known_peers")
	known := map[string]string{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &known)
	}
	if prev, ok := known[p.Name]; ok {
		if prev != p.PubKey {
			return fmt.Errorf("SECURITY: %q identity changed (possible impersonation) — confirm out-of-band, then delete %s", p.Name, path)
		}
		return nil
	}
	known[p.Name] = p.PubKey
	b, _ := json.Marshal(known)
	_ = os.WriteFile(path, b, 0o600)
	// Fail closed on EOF/pipes: only an explicit TTY answer trusts.
	// (fmt.Scanln would accept on EOF since ans stays "".)
	fmt.Printf("trust %q [%s]? [Y/n] ", p.Name, shortKey(p.PubKey))
	br := bufio.NewReader(os.Stdin)
	line, err := br.ReadString('\n')
	if err != nil {
		delete(known, p.Name)
		b, _ := json.Marshal(known)
		_ = os.WriteFile(path, b, 0o600)
		return fmt.Errorf("aborted (no confirmation)")
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	if ans != "" && ans != "y" && ans != "yes" {
		delete(known, p.Name)
		b, _ := json.Marshal(known)
		_ = os.WriteFile(path, b, 0o600)
		return fmt.Errorf("aborted")
	}
	return nil
}

func shortKey(k string) string {
	if len(k) > 19 {
		return k[:19] + "…"
	}
	return k
}

// apiClient bounds every control-plane call. A blackholed server must fail
// fast (pairing, directory, heartbeat) — never hang a CLI or the daemon.
var apiClient = &http.Client{Timeout: 15 * time.Second}

func fetchAllowlist(cfg config.PMCConfig) ([]string, error) {
	req, _ := http.NewRequest("GET", apiBase(cfg)+"/_pms/directory", nil)
	req.Header.Set("X-Device", cfg.Device)
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory: server refused (re-pair?)")
	}
	var out struct {
		Devices []struct {
			PubKey string `json:"pubkey"`
		} `json:"devices"`
		ServerPubKey string `json:"server_pubkey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	var allow []string
	for _, d := range out.Devices {
		allow = append(allow, d.PubKey)
	}
	// The server's bridge dials us for public traffic — without its key
	// in our allowlist every public byte 502s while P2P keeps working.
	if out.ServerPubKey != "" {
		allow = append(allow, out.ServerPubKey)
	}
	return allow, nil
}

func heartbeat(path string, cfg config.PMCConfig, fullAddr string) {
	postPresence(path, cfg, fullAddr, true)
}

// markOffline tells the directory this device is going away (best effort;
// the server also ages presence via LastSeen).
func markOffline(path string) {
	cfg := loadPMC(path)
	if cfg.Device == "" || cfg.Token == "" {
		return
	}
	postPresence(path, cfg, "", false)
}

func postPresence(path string, cfg config.PMCConfig, fullAddr string, online bool) {
	specs := exposeSpecs(cfg)
	body, _ := json.Marshal(map[string]any{
		"full_addr": fullAddr, "exposes": specs, "online": online,
		"ssh_user": servingUser(cfg),
	})
	req, _ := http.NewRequest("POST", apiBase(cfg)+"/_pms/heartbeat", bytes.NewReader(body))
	req.Header.Set("X-Device", cfg.Device)
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := apiClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	// Rotation: a 200 carries the replacement bearer — persist before next
	// use. Absent (204) means keep the current one.
	if resp.StatusCode == http.StatusOK {
		var out struct {
			Token string `json:"token"`
		}
		if json.NewDecoder(resp.Body).Decode(&out) == nil && out.Token != "" {
			cfg.Token = out.Token
			_ = savePMC(path, &cfg)
		}
	}
}

func exposeSpecs(cfg config.PMCConfig) []string {
	out := []string{} // non-nil: explicit empty clears server-side exposes
	for _, e := range cfg.Exposes {
		switch {
		case e.As != "":
			out = append(out, fmt.Sprintf("web:%s:%d", e.As, e.Local))
		case e.Host != "":
			out = append(out, fmt.Sprintf("webhost:%s:%d", e.Host, e.Local))
		case e.TCP != 0:
			out = append(out, fmt.Sprintf("tcp:%d:%d", e.TCP, e.Local))
		case e.UDP != 0:
			out = append(out, fmt.Sprintf("udp:%d:%d", e.UDP, e.Local))
		}
	}
	if cfg.ServeSSH {
		out = append(out, "ssh")
	}
	return out
}

// servingUser reports the local login serving sshd, or "" when not serving.
// Discovery hint only (shown in `pmc devices`); dialing still defaults to
// your own login like stock ssh — pass user@ to choose.
func servingUser(cfg config.PMCConfig) string {
	if !cfg.ServeSSH {
		return ""
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}

func clientKey(cfg config.PMCConfig) (key.NodePrivate, error) {
	id, err := keys.LoadOrCreate(cfg.DataDir, derpHostOf(cfg))
	if err != nil {
		return key.NodePrivate{}, err
	}
	return id.ClientKey()
}

// guessDerpHost derives the DERP host from a pairing URL without pairing:
// https://pair.example.com → derp.example.com (dev IP URLs pass through).
// Proper URL parsing (brackets, ports, userinfo) beats string surgery.
func guessDerpHost(serverURL string) string {
	if u, err := url.Parse(serverURL); err == nil && u.Hostname() != "" {
		if hn, ok := strings.CutPrefix(u.Hostname(), "pair."); ok {
			return "derp." + hn
		}
		return u.Hostname()
	}
	// Unparseable input: best-effort fallback so the failure surfaces as a
	// dial error, not a panic or empty region.
	u := strings.TrimPrefix(strings.TrimPrefix(serverURL, "https://"), "http://")
	if h, _, err := net.SplitHostPort(u); err == nil {
		u = h
	}
	return u
}

func derpHostOf(cfg config.PMCConfig) string { return guessDerpHost(cfg.Server) }
