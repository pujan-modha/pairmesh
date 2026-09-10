// Package pair implements single-use, expiring pairing codes.
// The code is the sole gate into the mesh: share over a private channel.
// Verification is constant-time; codes burn on first successful use.
package pair

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
)

// TTL is the pairing-code lifetime. Rotation interval for re-pair.
const TTL = 10 * time.Minute

// Code is a single-use pairing code. Only the hash is stored — the value
// itself exists transiently at Mint (returned) and Verify (compared).
type Code struct {
	Hash      []byte    `json:"hash"` // sha256(value), never the value itself
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

type storeFile struct {
	Codes []Code `json:"codes"`
}

// Store persists codes 0600. All methods are goroutine-safe.
type Store struct {
	mu   sync.Mutex
	path string
}

func hashOf(v string) []byte { return sha256Sum(v) }

// New creates a store backed at path (created lazily 0600).
func New(path string) *Store { return &Store{path: path} }

// DefaultPath returns the store path under dataDir.
func DefaultPath(dataDir string) string { return filepath.Join(dataDir, "pair.db") }

// Mint creates a fresh single-use code, pruning expired/burned ones.
// Refuses while enrollment is locked (minting unusable codes helps no one).
func (s *Store) Mint(now time.Time) (string, error) {
	if locked, _ := s.Locked(); locked {
		return "", ErrLocked
	}
	raw := make([]byte, 24) // 192-bit entropy
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	val := "pair-" + base64.RawURLEncoding.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return "", err
	}
	kept := st.Codes[:0]
	for _, c := range st.Codes {
		if !c.Used && c.ExpiresAt.After(now) {
			kept = append(kept, c)
		}
	}
	st.Codes = append(kept, Code{Hash: hashOf(val), ExpiresAt: now.Add(TTL)})
	if err := s.saveLocked(st); err != nil {
		return "", err
	}
	return val, nil
}

var (
	// ErrInvalid is returned for unknown, expired, or already-used codes.
	// The message is intentionally identical in all cases (no oracle).
	ErrInvalid = errors.New("invalid or expired pairing code")
	// ErrLocked is returned when enrollment is closed via lock file.
	ErrLocked = errors.New("enrollment closed")
)

// Verify burns and accepts val, or returns ErrInvalid. Constant-time compare.
func (s *Store) Verify(val string, now time.Time) error {
	if locked, _ := s.Locked(); locked {
		return ErrLocked
	}
	h := hashOf(val)
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return err
	}
	for i, c := range st.Codes {
		if len(c.Hash) != len(h) {
			continue
		}
		if subtle.ConstantTimeCompare(c.Hash, h) == 1 {
			if c.Used || !c.ExpiresAt.After(now) {
				return ErrInvalid
			}
			st.Codes[i].Used = true
			// Burn failure fails CLOSED: a code we accepted but couldn't
			// record would stay redeemable (disk full/RO must not mint
			// multi-use codes).
			if err := s.saveLocked(st); err != nil {
				return err
			}
			return nil
		}
	}
	return ErrInvalid
}

// Count returns live (unused, unexpired) codes — for status, not secrets.
func (s *Store) Count(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range st.Codes {
		if !c.Used && c.ExpiresAt.After(now) {
			n++
		}
	}
	return n
}

// lockPath is the enrollment-closed sentinel.
func (s *Store) lockPath() string { return filepath.Join(filepath.Dir(s.path), "enrollment.lock") }

// SetLocked opens/closes enrollment.
func (s *Store) SetLocked(locked bool) error {
	if !locked {
		return os.Remove(s.lockPath())
	}
	return os.WriteFile(s.lockPath(), []byte("locked\n"), 0o600)
}

// Locked reports enrollment state.
func (s *Store) Locked() (bool, error) {
	_, err := os.Stat(s.lockPath())
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (s *Store) loadLocked() (storeFile, error) {
	var st storeFile
	b, err := os.ReadFile(s.path)
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

func (s *Store) saveLocked(st storeFile) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}
