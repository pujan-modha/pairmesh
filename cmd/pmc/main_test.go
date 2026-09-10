package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/pujan-modha/pairmesh/internal/config"
)

func TestGuessDerpHost(t *testing.T) {
	for url, want := range map[string]string{
		"https://pair.example.com":      "derp.example.com",
		"https://pair.example.com:8443": "derp.example.com",
		"https://example.com":           "example.com",
		"http://127.0.0.1:18923":        "127.0.0.1",
		"http://[::1]:18923":            "::1",
		"https://user@pair.example.com": "derp.example.com",
	} {
		if got := guessDerpHost(url); got != want {
			t.Errorf("guessDerpHost(%q) = %q, want %q", url, got, want)
		}
	}
}

// withStdin swaps os.Stdin for the duration of fn.
func withStdin(t *testing.T, input string, fn func() error) error {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	if input != "" {
		if _, err := w.WriteString(input); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	return fn()
}

func testCfg(dir string) config.PMCConfig {
	return config.PMCConfig{DataDir: dir}
}

// EOF (pipes, scripts, cron) must NOT trust: fail closed.
func TestTrustCheckEOFAborts(t *testing.T) {
	dir := t.TempDir()
	cfg := testCfg(dir)
	p := peerInfo{Name: "office", PubKey: "nodekey:aaa", FullAddr: "tcAAA"}
	if err := withStdin(t, "", func() error { return trustCheck(cfg, p) }); err == nil {
		t.Fatal("EOF accepted trust; must abort")
	}
	if b, err := os.ReadFile(filepath.Join(dir, "known_peers")); err == nil {
		var known map[string]string
		_ = json.Unmarshal(b, &known)
		if _, ok := known["office"]; ok {
			t.Fatal("unconfirmed peer was pinned")
		}
	}
}

// Explicit yes pins.
func TestTrustCheckYesPins(t *testing.T) {
	dir := t.TempDir()
	cfg := testCfg(dir)
	p := peerInfo{Name: "office", PubKey: "nodekey:aaa", FullAddr: "tcAAA"}
	if err := withStdin(t, "y\n", func() error { return trustCheck(cfg, p) }); err != nil {
		t.Fatalf("explicit yes refused: %v", err)
	}
	// Second sighting of the same key passes silently.
	if err := withStdin(t, "", func() error { return trustCheck(cfg, p) }); err != nil {
		t.Fatalf("known key re-prompted/failed: %v", err)
	}
	// Changed key aborts loudly even with yes on stdin.
	p.PubKey = "nodekey:evil"
	if err := withStdin(t, "y\n", func() error { return trustCheck(cfg, p) }); err == nil {
		t.Fatal("changed identity accepted")
	}
}

func TestSSHLoginParsing(t *testing.T) {
	if got := sshTarget(""); got != "127.0.0.1" {
		t.Fatalf("no login: %q", got)
	}
	if got := sshTarget("pujan"); got != "pujan@127.0.0.1" {
		t.Fatalf("login: %q", got)
	}
	for _, ok := range []string{"pujan", "root", "a1", "_svc", "user-name", "u.name"} {
		if !validLogin(ok) {
			t.Errorf("validLogin(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "1abc", "has space", "a/b", "a@b", "x" + string(rune(0))} {
		if validLogin(bad) {
			t.Errorf("validLogin(%q) = true", bad)
		}
	}
}

func TestParseForwardTarget(t *testing.T) {
	name, port, err := parseForwardTarget("office:22")
	if err != nil || name != "office" || port != 22 {
		t.Fatalf("got %q %d %v", name, port, err)
	}
	if _, _, err := parseForwardTarget("office"); err == nil {
		t.Fatal("missing port accepted")
	}
	if _, _, err := parseForwardTarget(":22"); err == nil {
		t.Fatal("missing name accepted")
	}
	for _, bad := range []string{"office:0", "office:99999", "office:abc", "office:-1"} {
		if _, _, err := parseForwardTarget(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPickLocalPort(t *testing.T) {
	// Occupy a port, then demand it: must skip, not fail or steal.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	want := ln.Addr().(*net.TCPAddr).Port
	got, err := pickLocalPort(want)
	if err != nil {
		t.Fatalf("no free port near taken %d: %v", want, err)
	}
	if got == want {
		t.Fatalf("returned taken port %d", want)
	}
	if got <= 1024 {
		t.Fatalf("returned privileged port %d as non-root-safe choice", got)
	}
	// Free port returns itself.
	ln.Close()
	if got2, err := pickLocalPort(want); err != nil || got2 != want {
		t.Fatalf("free port %d → got %d, %v", want, got2, err)
	}
}
