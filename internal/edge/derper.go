package edge

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
)

// Derper manages a `derper` subprocess.
//
// Derper manages a `derper` subprocess in PLAINTEXT mode behind Caddy's
// layer4 TLS termination (`tls` handler on the derp SNI route).
//
// Why: derper only speaks TLS itself on port 443 or in manual mode, but
// :443 is owned by Caddy's layer4 split in the same netns — a second TLS
// listener there fails with EADDRINUSE (found live, not in review). TLS
// termination at Caddy + raw-byte proxy to a plaintext derper is
// protocol-clean (DERP is HTTP-upgrade based; Caddy holds a public LE
// cert for the name) and drops all cert syncing: derper needs no ACME,
// no files, no restarts. E2E payload security stays WireGuard+PSK inside.
type Derper struct {
	Bin      string // derper binary
	Hostname string // derp.<domain> (display/consistency; TLS is Caddy's job)
	Addr     string // localhost plaintext, e.g. 127.0.0.1:18443
	STUNPort int    // passed through: derper binds STUN on -a's host (loopback
	// here), so pms runs a separate public STUN (see edge.ServeSTUN).
	HTTPPort int    // -1 disables (Caddy owns :80; derper needs no ACME)
	KeyFile  string // /var/lib/pms/derper.key (0600, auto-created by derper)

	mu  sync.Mutex
	cmd *exec.Cmd
}

// Args builds the derper command line (flags pinned to audited upstream).
func (d *Derper) Args() []string {
	return []string{
		"-a", d.Addr,
		"--hostname", d.Hostname,
		"-c", d.KeyFile,
		"--http-port", fmt.Sprint(d.HTTPPort),
		"--stun-port", fmt.Sprint(d.STUNPort),
	}
}

// Start launches derper (restart-safe).
func (d *Derper) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopLocked()
	cmd := exec.CommandContext(ctx, d.Bin, d.Args()...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("edge: start derper: %w (is %q installed?)", err, d.Bin)
	}
	d.cmd = cmd
	return nil
}

// Stop terminates the subprocess.
func (d *Derper) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopLocked()
}

func (d *Derper) stopLocked() {
	if d.cmd != nil && d.cmd.Process != nil {
		_ = d.cmd.Process.Signal(os.Interrupt)
		_, _ = d.cmd.Process.Wait()
		d.cmd = nil
	}
}
