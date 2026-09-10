package keys

import (
	"encoding/json"
	"os"
	"testing"
)

// Identity must be stable across restarts (stable keys = stable address)
// and rebind regions without rotating the node key.
func TestIdentityRoundTrip(t *testing.T) {
	dir := t.TempDir()
	id1, err := LoadOrCreate(dir, "derp.one.test")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := LoadOrCreate(dir, "derp.one.test")
	if err != nil {
		t.Fatal(err)
	}
	if id1.NodePub != id2.NodePub || id1.PSK != id2.PSK || id1.NodePriv != id2.NodePriv {
		t.Fatal("identity not stable across loads")
	}
	if _, err := id2.Server(t.Logf); err != nil {
		t.Fatalf("server build: %v", err)
	}
	if _, err := id2.ClientKey(); err != nil {
		t.Fatalf("client key: %v", err)
	}
}

func TestRebindKeepsNodeKey(t *testing.T) {
	dir := t.TempDir()
	before, err := LoadOrCreate(dir, "derp.one.test")
	if err != nil {
		t.Fatal(err)
	}
	after, err := LoadOrCreate(dir, "derp.two.test")
	if err != nil {
		t.Fatal(err)
	}
	if before.NodePub != after.NodePub {
		t.Fatal("rebind rotated the node key (address identity changed)")
	}
	if after.DERPHost != "derp.two.test" {
		t.Fatalf("rebind did not stick: %q", after.DERPHost)
	}
}

func TestParsePub(t *testing.T) {
	id, err := LoadOrCreate(t.TempDir(), "derp.one.test")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePub(id.NodePub)
	if err != nil {
		t.Fatal(err)
	}
	if pub.IsZero() {
		t.Fatal("zero pubkey")
	}
	if _, err := ParsePub("bogus"); err == nil {
		t.Fatal("bogus pubkey accepted")
	}
}

// A hand-edited (or corrupt) stored pubkey must never desync the allowlist
// identity from the actual tunnel key: load re-derives it.
func TestPubSelfHeal(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreate(dir, "derp.one.test")
	if err != nil {
		t.Fatal(err)
	}
	id.NodePub = "nodekey:0000000000000000000000000000000000000000000000000000000000000000"
	b, _ := json.Marshal(id)
	if err := os.WriteFile(DefaultPath(dir), b, 0o600); err != nil {
		t.Fatal(err)
	}
	fixed, err := LoadOrCreate(dir, "derp.one.test")
	if err != nil {
		t.Fatal(err)
	}
	if fixed.NodePub == "nodekey:0000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatal("stale pubkey survived load")
	}
	ck, err := fixed.ClientKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ck.Public().MarshalText()
	if fixed.NodePub != string(pub) {
		t.Fatal("pubkey not re-derived from private key")
	}
}

// An identity without a DERP host must fail loudly at serve time, not
// bootstrap a garbage region.
func TestEmptyHostRefused(t *testing.T) {
	id, err := LoadOrCreate(t.TempDir(), "derp.one.test")
	if err != nil {
		t.Fatal(err)
	}
	id.DERPHost = ""
	if _, err := id.Server(t.Logf); err == nil {
		t.Fatal("serving without DERP host accepted")
	}
}
