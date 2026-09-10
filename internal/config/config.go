// Package config merges file + flags + env for pms/pmc.
// Precedence: flags > env > file > defaults. Secrets only from file/env.
package config

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// PMSConfig is the server configuration. Deliberately few knobs: ports 80
// and 443 are fixed (LE and the layer4 split mandate them).
type PMSConfig struct {
	Domain         string `yaml:"domain,omitempty"`
	Email          string `yaml:"email,omitempty"`
	AdminAddr      string `yaml:"admin_addr,omitempty"`
	CaddyHTTPSAddr string `yaml:"caddy_https_addr,omitempty"`
	DerperAddr     string `yaml:"derper_addr,omitempty"`
	DerperSTUNPort int    `yaml:"derp_stun,omitempty"`
	DerperHTTPPort int    `yaml:"derp_http_port,omitempty"`
	CaddyBin       string `yaml:"caddy_bin,omitempty"`
	DerperBin      string `yaml:"derper_bin,omitempty"`
	DataDir        string `yaml:"data_dir,omitempty"`
	DataBasePort   int    `yaml:"data_base,omitempty"`
}

// DefaultPMS returns hardened loopback-first defaults.
func DefaultPMS() PMSConfig {
	return PMSConfig{
		AdminAddr:      "127.0.0.1:18923",
		CaddyHTTPSAddr: "127.0.0.1:24443",
		DerperAddr:     "127.0.0.1:18443",
		DerperSTUNPort: 3478,
		DerperHTTPPort: -1,
		CaddyBin:       "caddy",
		DerperBin:      "derper",
		DataDir:        "/var/lib/pms",
		DataBasePort:   13000,
	}
}

// PMCConfig is the client configuration.
type PMCConfig struct {
	Server   string    `yaml:"server"` // derp host for pairing/control (https)
	Domain   string    `yaml:"domain"`
	Device   string    `yaml:"device"` // auto-assigned at pair
	Token    string    `yaml:"token"`  // device bearer token (file/env only)
	DataDir  string    `yaml:"data_dir"`
	Exposes  []Expose  `yaml:"exposes"`
	Forwards []Forward `yaml:"forwards"`
	ServeSSH bool      `yaml:"serve_ssh"`
}

// Expose maps one local service.
type Expose struct {
	Local int    `yaml:"local"`
	As    string `yaml:"as,omitempty"`   // web name → <as>.<domain>
	Host  string `yaml:"host,omitempty"` // full custom hostname → local
	TCP   int    `yaml:"tcp,omitempty"`  // public TCP port
	UDP   int    `yaml:"udp,omitempty"`  // public UDP port
}

// Forward maps a peer's TCP port onto local loopback, held by the daemon.
// Local is the resolved stable port (auto-picked free at --persist time).
type Forward struct {
	To    string `yaml:"to"`    // "<name>:<port>" on the peer
	Local int    `yaml:"local"` // 127.0.0.1 port locally
}

// DefaultPMC returns client defaults.
func DefaultPMC() PMCConfig {
	home, _ := os.UserHomeDir()
	return PMCConfig{
		DataDir: filepath.Join(home, ".config", "pmc"),
	}
}

// LoadYAML loads file if present, else returns zero value (no error).
func LoadYAML(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return yaml.Unmarshal(b, v)
}

// SaveYAML writes 0600 (secret-bearing files).
func SaveYAML(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// ValidName reports whether s is a valid device/expose name (LDH, ≤63).
func ValidName(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for i, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' && i > 0
		if !ok {
			return false
		}
	}
	return !strings.HasSuffix(s, "-")
}

// AutoName sanitizes a hostname into a valid name stem.
func AutoName(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	var b strings.Builder
	prevDash := true // avoid leading dash
	for _, c := range host {
		switch {
		case c >= 'a' && c <= 'z' || c >= '0' && c <= '9':
			b.WriteRune(c)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		s = "device"
	}
	// Truncate on a rune boundary: splitting a multibyte rune would leave
	// invalid bytes that fail ValidName and poison collision retries.
	if r := []rune(s); len(r) > 48 {
		s = string(r[:48])
	}
	return strings.TrimRight(s, "-")
}

// ValidHost reports whether s is a usable public hostname: lowercase LDH
// labels separated by dots, no scheme/port/path, total ≤253.
func ValidHost(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !ValidName(label) {
			return false
		}
	}
	return true
}

// EnvOr returns env value or fallback. Secrets must use this path, never flags.
func EnvOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
