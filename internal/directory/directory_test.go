package directory

import (
	"strings"
	"testing"
)

func TestAddUniqueNames(t *testing.T) {
	d := New(t.TempDir() + "/dir.db")
	n1, tok1, err := d.Add("laptop", "nodekey:aaa", "tcAAA")
	if err != nil {
		t.Fatal(err)
	}
	if n1 != "laptop" {
		t.Fatalf("first name = %q, want laptop", n1)
	}
	n2, _, err := d.Add("laptop", "nodekey:bbb", "tcBBB")
	if err != nil {
		t.Fatal(err)
	}
	if n2 == "laptop" || !strings.HasPrefix(n2, "laptop-") {
		t.Fatalf("second name = %q, want laptop-xxxx", n2)
	}
	if _, ok := d.AuthToken(n1, tok1); !ok {
		t.Fatal("token auth failed")
	}
	if _, ok := d.AuthToken(n1, "pmc-bogus"); ok {
		t.Fatal("bogus token accepted")
	}
	if got := len(d.PubKeys()); got != 2 {
		t.Fatalf("pubkeys = %d, want 2", got)
	}
}

func TestRenameRemove(t *testing.T) {
	d := New(t.TempDir() + "/dir.db")
	if _, _, err := d.Add("office", "nodekey:aaa", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Add("home", "nodekey:bbb", ""); err != nil {
		t.Fatal(err)
	}
	if err := d.Rename("office", "home"); err != ErrExists {
		t.Fatalf("rename collision err = %v, want ErrExists", err)
	}
	if err := d.Rename("office", "Bad_Name!"); err != ErrBadName {
		t.Fatalf("rename bad err = %v, want ErrBadName", err)
	}
	if err := d.Rename("office", "hq"); err != nil {
		t.Fatal(err)
	}
	if !d.Remove("hq") {
		t.Fatal("remove failed")
	}
	if d.Remove("hq") {
		t.Fatal("double remove succeeded")
	}
}

func TestHeartbeat(t *testing.T) {
	d := New(t.TempDir() + "/dir.db")
	name, _, err := d.Add("box", "nodekey:aaa", "tc1")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Heartbeat(name, "tc2", true); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, dev := range d.List() {
		if dev.Name == name {
			found = true
			if dev.FullAddr != "tc2" || !dev.Online {
				t.Fatalf("heartbeat not applied: %+v", dev)
			}
		}
	}
	if !found {
		t.Fatal("device missing after heartbeat")
	}
}

// Re-pairing the same key keeps the name, rotates the token, updates the
// address, and creates no second entry.
func TestRepair(t *testing.T) {
	d := New(t.TempDir() + "/dir.db")
	n1, tok1, err := d.Add("laptop", "nodekey:aaa", "tcAAA")
	if err != nil {
		t.Fatal(err)
	}
	n2, tok2, err := d.Add("laptop", "nodekey:aaa", "tcNEW")
	if err != nil {
		t.Fatal(err)
	}
	if n2 != n1 {
		t.Fatalf("re-pair renamed %q → %q, want stable name", n1, n2)
	}
	if tok2 == tok1 {
		t.Fatal("re-pair did not rotate the token")
	}
	if _, ok := d.AuthToken(n1, tok1); ok {
		t.Fatal("old token still valid after re-pair")
	}
	if _, ok := d.AuthToken(n1, tok2); !ok {
		t.Fatal("new token rejected")
	}
	if devs := d.List(); len(devs) != 1 || devs[0].FullAddr != "tcNEW" {
		t.Fatalf("re-pair orphaned entries: %+v", devs)
	}
}

// Rotation: fresh tokens are not due; rotated ones work alongside the old
// inside grace, and alone after it. List never leaks token material.
func TestRotateToken(t *testing.T) {
	d := New(t.TempDir() + "/dir.db")
	name, tok1, err := d.Add("box", "nodekey:aaa", "tc1")
	if err != nil {
		t.Fatal(err)
	}
	if d.TokenDue(name) {
		t.Fatal("fresh token due")
	}
	tok2, err := d.RotateToken(name)
	if err != nil {
		t.Fatal(err)
	}
	if tok2 == tok1 {
		t.Fatal("rotation kept the token")
	}
	if _, ok := d.AuthToken(name, tok2); !ok {
		t.Fatal("rotated token rejected")
	}
	if _, ok := d.AuthToken(name, tok1); !ok {
		t.Fatal("old token dead inside grace window")
	}
	for _, dev := range d.List() {
		if len(dev.TokenHash) != 0 || len(dev.PrevTokenHash) != 0 {
			t.Fatal("List leaks token hashes")
		}
	}
	if _, err := d.RotateToken("nope"); err != ErrNotFound {
		t.Fatalf("rotate unknown err = %v", err)
	}
}

// SetSSHUsers replaces (never appends): unserve clears the hint.
func TestSetSSHUsers(t *testing.T) {
	d := New(t.TempDir() + "/dir.db")
	name, _, err := d.Add("box", "nodekey:aaa", "tc1")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetSSHUsers(name, []string{"bob"}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetSSHUsers(name, []string{}); err != nil {
		t.Fatal(err)
	}
	for _, dev := range d.List() {
		if dev.Name == name && len(dev.SSHUsers) != 0 {
			t.Fatalf("stale ssh users: %+v", dev)
		}
	}
	if err := d.SetSSHUsers("nope", []string{"x"}); err != ErrNotFound {
		t.Fatalf("unknown err = %v", err)
	}
}
