// Package keys persists tailcat node identities 0600.
// One identity per device: stable node key + PSK + DERP region, so the
// full tailcat address survives restarts. Explicit keys always — upstream
// silently reuses saved `default` keys, which we refuse to rely on.
package keys

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Identity is a persisted serving identity.
type Identity struct {
	NodePriv string `json:"node_priv"` // text-encoded key.NodePrivate
	PSK      string `json:"psk"`       // text-encoded tailcat.PresharedKey
	DERPHost string `json:"derp_host"`
	NodePub  string `json:"node_pub"` // nodekey:... (allowlist identity)
}

// DefaultPath returns the identity file path under dir.
func DefaultPath(dir string) string { return filepath.Join(dir, "identity.json") }

// userRegion builds the single custom region (900-999 is reserved for
// end-user DERP nodes) pointing at our own derper. Ports are explicit:
// clients reach DERP on public 443 (via Caddy's layer4 split) and STUN on
// 3478 (via pms's standalone reflector).
func userRegion(derpHost string) *tailcfg.DERPRegion {
	return &tailcfg.DERPRegion{
		RegionID:   900,
		RegionCode: "pms",
		RegionName: "pairmesh",
		Nodes: []*tailcfg.DERPNode{
			{
				Name: "900a", RegionID: 900, HostName: derpHost,
				DERPPort: 443, STUNPort: 3478,
			},
		},
	}
}

// LoadOrCreate loads dir/identity.json or creates a fresh identity bound to
// derpHost. If the stored DERP host differs, the region is re-bound (new
// address) while the node key is kept.
func LoadOrCreate(dir, derpHost string) (*Identity, error) {
	path := DefaultPath(dir)
	if b, err := os.ReadFile(path); err == nil {
		var id Identity
		if err := json.Unmarshal(b, &id); err != nil {
			return nil, err
		}
		var priv key.NodePrivate
		if err := priv.UnmarshalText([]byte(id.NodePriv)); err != nil {
			return nil, err
		}
		var psk tailcat.PresharedKey
		if err := psk.UnmarshalText([]byte(id.PSK)); err != nil {
			return nil, err
		}
		// NodePub is redundant (derived from NodePriv): recompute so a
		// hand-edited file can never desync the allowlist identity from
		// the actual tunnel key.
		if pub, err := priv.Public().MarshalText(); err != nil {
			return nil, err
		} else {
			id.NodePub = string(pub)
		}
		if id.DERPHost != derpHost {
			id.DERPHost = derpHost
			if err := save(path, &id); err != nil {
				return nil, err
			}
		}
		return &id, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	pk := tailcat.NewPrivateKey()
	privText, err := pk.Private.MarshalText()
	if err != nil {
		return nil, err
	}
	pskText, err := pk.Public.PresharedKey.MarshalText()
	if err != nil {
		return nil, err
	}
	pubText, err := pk.Private.Public().MarshalText()
	if err != nil {
		return nil, err
	}
	id := &Identity{
		NodePriv: string(privText), PSK: string(pskText),
		DERPHost: derpHost, NodePub: string(pubText),
	}
	if err := save(path, id); err != nil {
		return nil, err
	}
	return id, nil
}

func save(path string, id *Identity) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(id)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Server builds a tailcat.Server from the identity. Handlers and allowlist
// must be set by the caller before Start.
func (id *Identity) Server(logf func(string, ...any)) (*tailcat.Server, error) {
	var priv key.NodePrivate
	if err := priv.UnmarshalText([]byte(id.NodePriv)); err != nil {
		return nil, err
	}
	var psk tailcat.PresharedKey
	if err := psk.UnmarshalText([]byte(id.PSK)); err != nil {
		return nil, err
	}
	if psk.IsZero() {
		return nil, errors.New("keys: zero preshared key (refuse to serve without PSK)")
	}
	if id.DERPHost == "" {
		return nil, errors.New("keys: no DERP host (re-pair this device?)")
	}
	return &tailcat.Server{
		Key:          priv,
		PresharedKey: psk,
		Region:       userRegion(id.DERPHost),
		Logf:         logf,
	}, nil
}

// ClientKey returns the persistent client identity for allowlisting.
func (id *Identity) ClientKey() (key.NodePrivate, error) {
	var priv key.NodePrivate
	if err := priv.UnmarshalText([]byte(id.NodePriv)); err != nil {
		return priv, err
	}
	return priv, nil
}

// ParsePub parses a nodekey:... text (allowlist entries).
func ParsePub(text string) (key.NodePublic, error) {
	var pub key.NodePublic
	if err := pub.UnmarshalText([]byte(text)); err != nil {
		return pub, err
	}
	return pub, nil
}
