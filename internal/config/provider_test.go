package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vvpn/internal/core"
)

func boolRef(v bool) *bool { return &v }

// chainConfig is a stored configuration that uses both of mihomo's new blocks:
// a node dialed through another one, and a group fed by a proxy provider.
func chainConfig() Config {
	cfg := Default()
	cfg.Core.ID = "mihomo"
	cfg.Core.Profile = &core.Profile{
		Log:      "info",
		Inbounds: []core.Inbound{{Type: core.InboundMixed, Tag: "mixed-in", Listen: "127.0.0.1", Port: 4102}},
		Nodes: []core.Node{
			{Name: "front", Type: core.TypeSS, Server: "1.2.3.4", Port: 8388, Method: "aes-256-gcm", Password: "pw", DialerProxy: "landing"},
			{Name: "landing", Type: core.TypeSS, Server: "5.6.7.8", Port: 8388, Method: "aes-256-gcm", Password: "pw"},
		},
		Groups: []core.Group{{
			Name:    "PROXY",
			Type:    core.GroupSelect,
			Members: []string{"front", "landing"},
			Use:     []string{"airport"},
		}},
		Providers: []core.Provider{{
			Name: "airport", URL: "https://example.com/sub.yaml", Interval: 3600,
			HealthCheck: &core.ProviderHealthCheck{
				Enable:   boolRef(true),
				URL:      "http://www.gstatic.com/generate_204",
				Interval: 300,
			},
		}},
		Final: "PROXY",
		Rules: []core.Rule{{Kind: core.RuleFinal, Value: "", Action: "PROXY"}},
	}
	return cfg
}

// The chain and the provider list have to survive a save/load cycle: a chain
// that only lives in memory would be gone the next time the client starts.
func TestConfigRoundTripsChainAndProviders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := chainConfig()
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	for _, want := range []string{`"dialer-proxy"`, `"providers"`, `"use"`, `"health_check"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("stored config.json is missing %s\n%s", want, raw)
		}
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Core.Profile == nil {
		t.Fatal("the profile did not survive the round trip")
	}
	if got := loaded.Core.Profile.Nodes[0].DialerProxy; got != "landing" {
		t.Errorf("dialer-proxy = %q, want landing", got)
	}
	if got := loaded.Core.Profile.Nodes[1].DialerProxy; got != "" {
		t.Errorf("the landing node gained a chain: %q", got)
	}
	if got := strings.Join(loaded.Core.Profile.Groups[0].Use, ","); got != "airport" {
		t.Errorf("group.use = %q", got)
	}
	if len(loaded.Core.Profile.Providers) != 1 {
		t.Fatalf("providers = %+v", loaded.Core.Profile.Providers)
	}
	pr := loaded.Core.Profile.Providers[0]
	if pr.Name != "airport" || pr.URL != "https://example.com/sub.yaml" || pr.Interval != 3600 {
		t.Errorf("provider = %+v", pr)
	}
	if pr.ProviderType() != core.ProviderHTTP {
		t.Errorf("provider type = %q, want http by default", pr.ProviderType())
	}
	if pr.HealthCheck == nil || pr.HealthCheck.Enable == nil || !*pr.HealthCheck.Enable {
		t.Fatalf("health-check = %+v", pr.HealthCheck)
	}
	if pr.HealthCheck.Interval != 300 {
		t.Errorf("health-check interval = %d", pr.HealthCheck.Interval)
	}
	// The accessor the console layer reads has to see the same list.
	if got := loaded.Providers(); len(got) != 1 || got[0].Name != "airport" {
		t.Errorf("Providers() = %+v", got)
	}
}

// A configuration written before the feature existed keeps loading, and an
// unconfigured client must not report a provider list it never had.
func TestConfigProvidersAreOptional(t *testing.T) {
	cfg := Default()
	if got := cfg.Providers(); got != nil {
		t.Errorf("a default config reports providers: %+v", got)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the default config must stay valid: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.json")
	body := `{"inbound":{"socks5_addr":"127.0.0.1:2891","http_addr":"127.0.0.1:2890"}}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	legacy, err := Load(path)
	if err != nil {
		t.Fatalf("load legacy: %v", err)
	}
	if legacy.Core.Profile != nil && len(legacy.Core.Profile.Providers) != 0 {
		t.Errorf("a legacy config gained providers: %+v", legacy.Core.Profile.Providers)
	}
}

// Normalize is what the loader runs on every start: the padded strings a user
// or a hand-edited config.json can leave behind have to be cleaned there, or
// the validator would reject a name that only looks different.
func TestConfigNormalizeTrimsProfileChainFields(t *testing.T) {
	cfg := chainConfig()
	cfg.Core.Profile.Nodes[0].DialerProxy = "  landing  "
	cfg.Core.Profile.Groups[0].Use = []string{" airport ", "   "}
	cfg.Core.Profile.Providers[0].Name = " airport "
	cfg.Core.Profile.Providers[0].URL = " https://example.com/sub.yaml "
	cfg.Core.Profile.Providers[0].HealthCheck.URL = "  http://www.gstatic.com/generate_204 "
	cfg.Normalize()

	if got := cfg.Core.Profile.Nodes[0].DialerProxy; got != "landing" {
		t.Errorf("dialer-proxy = %q, want landing", got)
	}
	if got := strings.Join(cfg.Core.Profile.Groups[0].Use, ","); got != "airport" {
		t.Errorf("use = %q, want airport (the blank entry is dropped)", got)
	}
	if got := cfg.Core.Profile.Providers[0].Name; got != "airport" {
		t.Errorf("provider name = %q", got)
	}
	if got := cfg.Core.Profile.Providers[0].URL; got != "https://example.com/sub.yaml" {
		t.Errorf("provider url = %q", got)
	}
	if got := cfg.Core.Profile.Providers[0].HealthCheck.URL; got != "http://www.gstatic.com/generate_204" {
		t.Errorf("health-check url = %q", got)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the normalized config must validate: %v", err)
	}
}

// The cycle check has to be reachable from the configuration layer, which is
// where the app decides whether the file it just read can be used.
func TestConfigValidateRejectsDialerProxyCycle(t *testing.T) {
	cfg := chainConfig()
	cfg.Core.Profile.Nodes[1].DialerProxy = "front"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() accepted a dialer-proxy cycle")
	}
	if !strings.Contains(err.Error(), "dialer-proxy cycle") {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "front -> landing -> front") {
		t.Errorf("the error must name every node on the ring: %v", err)
	}

	// A provider name that also names an outbound is refused for the same
	// reason: the generated document would be ambiguous.
	collide := chainConfig()
	collide.Core.Profile.Providers[0].Name = "front"
	err = collide.Validate()
	if err == nil || !strings.Contains(err.Error(), "collides") {
		t.Errorf("a provider colliding with a node must be refused, got %v", err)
	}

	// And a group that uses a provider nobody declared.
	missing := chainConfig()
	missing.Core.Profile.Groups[0].Use = []string{"ghost"}
	err = missing.Validate()
	if err == nil || !strings.Contains(err.Error(), "unknown proxy provider") {
		t.Errorf("an unknown provider reference must be refused, got %v", err)
	}
}
