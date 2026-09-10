// Package directory is the trusted introducer: name → device record.
// One trust domain per pms. Membership changes push a fresh allowlist.
package directory

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pujan-modha/pairmesh/internal/config"
)

// Device is one paired pmc box.
type Device struct {
	Name      string   `json:"name"`
	PubKey    string   `json:"pubkey"` // nodekey:... (allowlist identity)
	FullAddr  string   `json:"full_addr,omitempty"`
	Exposes   []string `json:"exposes,omitempty"`    // compact specs: web:<as>:<local> tcp:<pub>:<local> udp:<pub>:<local> ssh
	TokenHash []byte   `json:"token_hash,omitempty"` // sha256(device bearer token)
	// Previous token during the rotation grace window (crash between
	// receiving and storing the new one must not lock the device out).
	PrevTokenHash []byte    `json:"prev_token_hash,omitempty"`
	PrevExpiry    time.Time `json:"prev_expiry,omitempty"`
	TokenIssuedAt time.Time `json:"token_issued_at,omitempty"`
	Online        bool      `json:"online"`
	LastSeen      time.Time `json:"last_seen"`
}

// Rotation policy: bearer tokens live TokenTTL, then the next heartbeat
// swaps them. The old one stays valid for GracePeriod so a client that
// crashes between receiving and persisting the new token isn't orphaned.
const (
	TokenTTL    = time.Hour
	GracePeriod = 5 * time.Minute
)

type storeFile struct {
	Devices []Device `json:"devices"`
}

var (
	ErrExists   = errors.New("device name already taken")
	ErrNotFound = errors.New("device not found")
	ErrBadName  = errors.New("invalid device name")
)

// Directory persists devices 0600. Goroutine-safe.
type Directory struct {
	mu   sync.Mutex
	path string
	rev  uint64 // allowlist revision, bumped on every membership change
}

// New creates a directory backed at path.
func New(path string) *Directory { return &Directory{path: path} }

// DefaultPath returns the store path under dataDir.
func DefaultPath(dataDir string) string { return filepath.Join(dataDir, "directory.db") }

// validName is config.ValidName (single LDH rule shared with CLI).
func validName(s string) bool { return config.ValidName(s) }

// MintToken creates a device bearer token (stored as hash only).
func MintToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "pmc-" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashOf(v string) []byte { return sha256Sum(v) }

// Add registers a device with a unique name. stem is sanitized already;
// a 4-hex suffix disambiguates collisions. Returns final name + raw token.
//
// Re-pairing the same key refreshes in place (same name, new token and
// address) instead of orphaning a stale entry — physical devices re-pair,
// abandon nothing.
func (d *Directory) Add(stem, pubkey, fullAddr string) (name, token string, err error) {
	if stem == "" {
		stem = "device"
	}
	token, err = MintToken()
	if err != nil {
		return "", "", err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.loadLocked()
	if err != nil {
		return "", "", err
	}
	taken := map[string]bool{}
	for i, dev := range st.Devices {
		taken[dev.Name] = true
		if dev.PubKey == pubkey {
			// Re-pair: same key, same name — rotate token + address so
			// the old bearer dies with the old pairing.
			st.Devices[i].FullAddr = fullAddr
			st.Devices[i].TokenHash = hashOf(token)
			st.Devices[i].TokenIssuedAt = time.Now()
			st.Devices[i].PrevTokenHash = nil
			st.Devices[i].PrevExpiry = time.Time{}
			st.Devices[i].Online = true
			st.Devices[i].LastSeen = time.Now()
			d.rev++
			if err := d.saveLocked(st); err != nil {
				return "", "", err
			}
			return dev.Name, token, nil
		}
	}
	name = stem
	if taken[name] || !validName(name) {
		name = ""
		for range 5000 {
			suffix := make([]byte, 3) // 3 bytes → exactly 4 base64 chars
			if _, err := rand.Read(suffix); err != nil {
				return "", "", err
			}
			cand := stem + "-" + base64.RawURLEncoding.EncodeToString(suffix)
			if !taken[cand] && validName(cand) {
				name = cand
				break
			}
		}
		if name == "" {
			return "", "", ErrExists
		}
	}
	st.Devices = append(st.Devices, Device{
		Name: name, PubKey: pubkey, FullAddr: fullAddr,
		TokenHash: hashOf(token), TokenIssuedAt: time.Now(),
		Online: true, LastSeen: time.Now(),
	})
	d.rev++
	if err := d.saveLocked(st); err != nil {
		return "", "", err
	}
	return name, token, nil
}

// Rename changes a device name (unique LDH).
func (d *Directory) Rename(old, newName string) error {
	if !validName(newName) {
		return ErrBadName
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.loadLocked()
	if err != nil {
		return err
	}
	idx := -1
	for i, dev := range st.Devices {
		if dev.Name == newName {
			return ErrExists
		}
		if dev.Name == old {
			idx = i
		}
	}
	if idx < 0 {
		return ErrNotFound
	}
	st.Devices[idx].Name = newName
	d.rev++
	return d.saveLocked(st)
}

// Remove deletes a device (revoke). Returns true if present.
func (d *Directory) Remove(name string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.loadLocked()
	if err != nil {
		return false
	}
	kept := st.Devices[:0]
	found := false
	for _, dev := range st.Devices {
		if dev.Name == name {
			found = true
			continue
		}
		kept = append(kept, dev)
	}
	if !found {
		return false
	}
	st.Devices = kept
	d.rev++
	_ = d.saveLocked(st)
	return true
}

// SetExposes replaces the device's expose specs.
func (d *Directory) SetExposes(name string, ex []string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.loadLocked()
	if err != nil {
		return err
	}
	for i, dev := range st.Devices {
		if dev.Name == name {
			st.Devices[i].Exposes = append([]string(nil), ex...)
			return d.saveLocked(st)
		}
	}
	return ErrNotFound
}

// Heartbeat marks online + refreshes address. Token-authenticated by caller.
func (d *Directory) Heartbeat(name, fullAddr string, online bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.loadLocked()
	if err != nil {
		return err
	}
	for i, dev := range st.Devices {
		if dev.Name == name {
			st.Devices[i].Online = online
			st.Devices[i].LastSeen = time.Now()
			if fullAddr != "" {
				st.Devices[i].FullAddr = fullAddr
			}
			return d.saveLocked(st)
		}
	}
	return ErrNotFound
}

// AuthToken constant-time checks a device bearer token: current, or the
// previous one inside its grace window (rotation crash-safety). Returns
// the device on success. Scrubbed copies only ever leave via List.
func (d *Directory) AuthToken(name, token string) (Device, bool) {
	h := hashOf(token)
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.loadLocked()
	if err != nil {
		return Device{}, false
	}
	for _, dev := range st.Devices {
		if dev.Name != name {
			continue
		}
		if len(dev.TokenHash) == len(h) &&
			subtle.ConstantTimeCompare(dev.TokenHash, h) == 1 {
			return scrub(dev), true
		}
		if now.Before(dev.PrevExpiry) && len(dev.PrevTokenHash) == len(h) &&
			subtle.ConstantTimeCompare(dev.PrevTokenHash, h) == 1 {
			return scrub(dev), true
		}
	}
	return Device{}, false
}

// RotateToken swaps in a fresh bearer token, keeping the old one valid for
// GracePeriod. Returns the raw new token (shown once, stored hashed).
func (d *Directory) RotateToken(name string) (string, error) {
	token, err := MintToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.loadLocked()
	if err != nil {
		return "", err
	}
	for i, dev := range st.Devices {
		if dev.Name == name {
			st.Devices[i].PrevTokenHash = dev.TokenHash
			st.Devices[i].PrevExpiry = now.Add(GracePeriod)
			st.Devices[i].TokenHash = hashOf(token)
			st.Devices[i].TokenIssuedAt = now
			if err := d.saveLocked(st); err != nil {
				return "", err
			}
			return token, nil
		}
	}
	return "", ErrNotFound
}

// TokenDue reports whether name's token is older than TokenTTL (rotate on
// next heartbeat). Unknown devices report false — AuthToken gates anyway.
func (d *Directory) TokenDue(name string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.loadLocked()
	if err != nil {
		return false
	}
	for _, dev := range st.Devices {
		if dev.Name == name {
			return time.Since(dev.TokenIssuedAt) > TokenTTL
		}
	}
	return false
}

// scrub removes all token material before a Device crosses a trust
// boundary (logs, API responses, Status output).
func scrub(dev Device) Device {
	dev.TokenHash = nil
	dev.PrevTokenHash = nil
	return dev
}

// List returns all devices (no token hashes — scrubbed for status output).
// Load errors yield nil (use ListErr when the distinction matters).
func (d *Directory) List() []Device {
	devs, _ := d.ListErr()
	return devs
}

// ListErr returns all devices, scrubbed, distinguishing store errors from
// empty. Reconcile paths must use this: on error keep the last-known edge,
// never fail open to an empty one.
func (d *Directory) ListErr() ([]Device, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.loadLocked()
	if err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(st.Devices))
	for _, dev := range st.Devices {
		out = append(out, scrub(dev))
	}
	return out, nil
}

// PubKeys returns allowlist identities in stable order.
func (d *Directory) PubKeys() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.loadLocked()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(st.Devices))
	for _, dev := range st.Devices {
		out = append(out, dev.PubKey)
	}
	return out
}

// Revision is the allowlist version for refresh polling.
func (d *Directory) Revision() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.rev
}

func (d *Directory) loadLocked() (storeFile, error) {
	var st storeFile
	b, err := os.ReadFile(d.path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, err
	}
	return st, nil
}

func (d *Directory) saveLocked(st storeFile) error {
	if err := os.MkdirAll(filepath.Dir(d.path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return os.WriteFile(d.path, b, 0o600)
}
