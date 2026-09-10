package main

import (
	"strings"
	"testing"

	"github.com/pujan-modha/pairmesh/internal/config"
)

func validTestConfig(dir string) config.PMSConfig {
	cfg := config.DefaultPMS()
	cfg.Domain = "example.test"
	cfg.Email = "a@b.c"
	cfg.DataDir = dir
	return cfg
}

func TestValidateConfig(t *testing.T) {
	if err := validateConfig(validTestConfig(t.TempDir())); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]func(*config.PMSConfig){
		"empty domain":   func(c *config.PMSConfig) { c.Domain = "" },
		"domain URL":     func(c *config.PMSConfig) { c.Domain = "https://x.test" },
		"bad email":      func(c *config.PMSConfig) { c.Email = "not-an-email" },
		"bad admin":      func(c *config.PMSConfig) { c.AdminAddr = "nope" },
		"bad https":      func(c *config.PMSConfig) { c.CaddyHTTPSAddr = "nope" },
		"bad derper":     func(c *config.PMSConfig) { c.DerperAddr = "nope" },
		"bad http port":  func(c *config.PMSConfig) { c.DerperHTTPPort = 0 },
		"bad base port":  func(c *config.PMSConfig) { c.DataBasePort = -1 },
		"unwritable dir": func(c *config.PMSConfig) { c.DataDir = "/proc/nope/pms" },
	}
	for name, mutate := range cases {
		cfg := validTestConfig(t.TempDir())
		mutate(&cfg)
		if err := validateConfig(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestShouldManageService(t *testing.T) {
	if !shouldManageService(true, true, false) {
		t.Error("root+systemd+bare metal should manage")
	}
	for name, tc := range map[string][3]bool{
		"non-root":   {false, true, false},
		"no systemd": {true, false, false},
		"container":  {true, true, true},
		"nothing":    {false, false, true},
	} {
		if shouldManageService(tc[0], tc[1], tc[2]) {
			t.Errorf("%s: should not manage", name)
		}
	}
}

func TestUnitTemplateRenders(t *testing.T) {
	if unitTemplate == "" {
		t.Fatal("embedded unit empty")
	}
	// The template must keep its /usr/local placeholders: init renders
	// the real binary + config paths per machine at install time.
	for _, want := range []string{"/usr/local/bin/pms", "--config /etc/pms/config.yaml"} {
		if !strings.Contains(unitTemplate, want) {
			t.Errorf("unit template lost placeholder %q", want)
		}
	}
}
