package edge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The layer4 SNI split replaces our old hand-rolled TLS parser: derp host
// goes to derper, everything else to Caddy's own HTTPS listener.
func TestRenderLayer4Split(t *testing.T) {
	c := &Caddy{
		Bin: "caddy", AdminAPI: "127.0.0.1:2019",
		HTTPSAddr: "127.0.0.1:24443", Derper: "127.0.0.1:18443",
		FilePath: filepath.Join(t.TempDir(), "Caddyfile"),
	}
	err := c.Render("example.com", "a@b.c", "127.0.0.1:18923", []Expose{
		{Host: "next.example.com", To: "127.0.0.1:13000"},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(c.FilePath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"layer4",
		"@derp tls sni derp.example.com",
		"\t\t\t\ttls\n",
		"proxy tcp/127.0.0.1:18443",
		"proxy tcp/127.0.0.1:24443",
		"https://pair.example.com:24443",
		"https://derp.example.com:24443",
		"https://next.example.com:24443",
		"reverse_proxy 127.0.0.1:13000",
		"protocols tls1.3",
		"X-Forwarded-For",
		":80",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Caddyfile missing %q\n---\n%s", want, s)
		}
	}
	for _, gone := range []string{
		"acme-challenge",
		"18080",
	} {
		if strings.Contains(s, gone) {
			t.Errorf("Caddyfile still contains %q (derper needs no ACME now)", gone)
		}
	}
	// Every public HTTPS site pins TLS 1.3 (SECURITY.md stakes this claim):
	// pair + derp-automation dummy + each expose.
	if n := strings.Count(s, "protocols tls1.3"); n != 3 {
		t.Errorf("want TLS1.3 block on all 3 https sites, got %d", n)
	}
	for _, line := range strings.Split(s, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "https://") && !strings.Contains(trim, ":24443") {
			t.Errorf("site binds unexpected port: %q", line)
		}
	}
	// Every site that isn't a pure reverse_proxy needs an explicit 404
	// fallback (pair API, derp challenges, :80 catch-all): no silent 200s.
	if n := strings.Count(s, `respond "not found" 404`); n < 3 {
		t.Errorf("want >=3 explicit 404 fallbacks, got %d", n)
	}
}

// deploy/Caddyfile.tmpl is the human-readable copy of the reference render;
// fail loudly on drift instead of letting docs and code diverge.
func TestTemplateMatchesRender(t *testing.T) {
	c := &Caddy{
		Bin: "caddy", AdminAPI: "127.0.0.1:2019",
		HTTPSAddr: "127.0.0.1:24443", Derper: "127.0.0.1:18443",
		FilePath: filepath.Join(t.TempDir(), "Caddyfile"),
	}
	if err := c.Render("example.com", "you@mail.com", "127.0.0.1:18923", []Expose{
		{Host: "next.example.com", To: "127.0.0.1:13000"},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(c.FilePath)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../deploy/Caddyfile.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("deploy/Caddyfile.tmpl drifted from Render output\n--- render ---\n%s", got)
	}
}
