package config

import (
	"os"
	"path/filepath"
	"testing"

	"vvpn/internal/core"
	"vvpn/internal/rules"
)

func TestDefaultIsValid(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default().Validate() = %v", err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := Default()
	cfg.Outbound.Type = "socks5"
	cfg.Outbound.Socks5 = &Socks5{Addr: "127.0.0.1:1080", Username: "u", Password: "p"}
	cfg.Rules = append([]rules.Rule{{Kind: rules.KindDomain, Value: "blocked.example", Action: string(rules.ActionReject)}}, cfg.Rules...)
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Outbound.Type != "socks5" || loaded.Outbound.Socks5 == nil || loaded.Outbound.Socks5.Addr != "127.0.0.1:1080" {
		t.Fatalf("outbound round-trip mismatch: %+v", loaded.Outbound)
	}
	if len(loaded.Rules) != len(cfg.Rules) || loaded.Rules[0].Kind != rules.KindDomain {
		t.Fatalf("rules round-trip mismatch: %+v", loaded.Rules)
	}
}

func TestLoadOrCreateWritesDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "config.json")
	if _, err := LoadOrCreate(path); err == nil {
		t.Fatal("LoadOrCreate into a missing directory should fail, not invent one")
	}

	path = filepath.Join(dir, "config.json")
	cfg, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if cfg.Inbound.SOCKS5Addr == "" {
		t.Fatalf("created config missing defaults: %+v", cfg)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("config file not written: %v", err)
	}
}

func TestValidateRejectsBadConfig(t *testing.T) {
	cases := map[string]func(*Config){
		"no inbound":     func(c *Config) { c.Inbound = Inbound{} },
		"bad outbound":   func(c *Config) { c.Outbound.Type = "wireguard" },
		"socks5 missing": func(c *Config) { c.Outbound.Type = "socks5"; c.Outbound.Socks5 = nil },
		"bad rule": func(c *Config) {
			c.Rules = []rules.Rule{{Kind: "nope", Value: "x", Action: "direct"}}
		},
	}
	for name, mutate := range cases {
		cfg := Default()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: Validate() succeeded, want error", name)
		}
	}
}

// A profile whose final outbound disappeared (groups edited, subscription
// removed) used to stop the client from starting at all. Normalize now repairs
// it so the user can fix things from the UI instead.
func TestNormalizeHealsDanglingProfileReferences(t *testing.T) {
	cfg := Default()
	cfg.Core.Profile = &core.Profile{
		Inbounds: []core.Inbound{{Type: core.InboundMixed, Tag: "in", Listen: "127.0.0.1", Port: 7890}},
		Nodes:    []core.Node{{Name: "n1", Type: core.TypeSS, Server: "1.2.3.4", Port: 8388, Method: "aes-256-gcm", Password: "pw"}},
		// No groups at all, but the profile still points at one.
		Final: "PROXY",
		Rules: []core.Rule{{Kind: core.RuleDomainSuffix, Value: "cn", Action: "PROXY"}},
	}
	cfg.Normalize()

	if cfg.Core.Profile.Final == "PROXY" {
		t.Errorf("a dangling final outbound should be repointed, still %q", cfg.Core.Profile.Final)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the healed configuration must be valid: %v", err)
	}
	if cfg.Core.Profile.Rules[0].Action == "PROXY" {
		t.Errorf("a rule targeting a vanished group should be repointed, still %q", cfg.Core.Profile.Rules[0].Action)
	}
}

func TestNormalizeKeepsValidProfileUntouched(t *testing.T) {
	cfg := Default()
	cfg.Core.Profile = &core.Profile{
		Inbounds: []core.Inbound{{Type: core.InboundMixed, Tag: "in", Listen: "127.0.0.1", Port: 7890}},
		Nodes:    []core.Node{{Name: "n1", Type: core.TypeSS, Server: "1.2.3.4", Port: 8388, Method: "aes-256-gcm", Password: "pw"}},
		Groups:   []core.Group{{Name: "PROXY", Type: core.GroupSelect, Members: []string{"n1"}}},
		Final:    "PROXY",
		Rules: []core.Rule{
			{Kind: core.RuleDomainSuffix, Value: "cn", Action: core.ActionDirect},
			{Kind: core.RuleFinal, Value: "", Action: "PROXY"},
		},
	}
	cfg.Normalize()

	if cfg.Core.Profile.Final != "PROXY" {
		t.Errorf("a valid final was changed: %q", cfg.Core.Profile.Final)
	}
	if cfg.Core.Profile.Rules[0].Action != core.ActionDirect {
		t.Errorf("a valid rule action was changed: %q", cfg.Core.Profile.Rules[0].Action)
	}
	if len(cfg.Core.Profile.Groups) != 1 {
		t.Errorf("groups were modified: %+v", cfg.Core.Profile.Groups)
	}
}

func TestCorePortDefaultsAndValidates(t *testing.T) {
	cfg := Default()
	if cfg.Core.Port != 2899 {
		t.Fatalf("default core port = %d, want 2899", cfg.Core.Port)
	}
	cfg.Core.Port = 0
	cfg.Normalize()
	if cfg.Core.Port != 2899 {
		t.Fatalf("normalized core port = %d, want 2899", cfg.Core.Port)
	}
	cfg.Core.Port = 70000
	if err := cfg.Validate(); err == nil {
		t.Fatalf("Validate accepted an out-of-range core port")
	}
	cfg.Core.Port = 2890
	if err := cfg.Validate(); err == nil {
		t.Fatalf("Validate accepted a core port that collides with the http inbound")
	}
	cfg.Core.Port = 2899
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate rejected a usable core port: %v", err)
	}
}

// A configuration written before syan-clash had its own ports must be moved onto
// them: staying on 7890/7891/9090 would put the client straight back into a
// fight with every other proxy client on the machine.
func TestLegacyPortsMigrateToOwnedPorts(t *testing.T) {
	cfg := Config{
		Inbound: Inbound{SOCKS5Addr: "127.0.0.1:7891", HTTPAddr: "127.0.0.1:7890"},
		API:     API{Addr: "127.0.0.1:9090"},
		Core: Core{
			Port: 7899,
			Profile: &core.Profile{
				ClashAPI: "127.0.0.1:9090",
				Inbounds: []core.Inbound{{Type: core.InboundMixed, Tag: "mixed-in", Listen: "127.0.0.1", Port: 7890}},
			},
		},
	}
	cfg.Normalize()

	if cfg.Inbound.HTTPAddr != "127.0.0.1:2890" {
		t.Errorf("http addr = %s, want the client's own port", cfg.Inbound.HTTPAddr)
	}
	if cfg.Inbound.SOCKS5Addr != "127.0.0.1:2891" {
		t.Errorf("socks addr = %s, want the client's own port", cfg.Inbound.SOCKS5Addr)
	}
	if cfg.API.Addr != "127.0.0.1:3090" {
		t.Errorf("api addr = %s, want the client's own port", cfg.API.Addr)
	}
	if cfg.Core.Port != 2899 {
		t.Errorf("core port = %d, want 2899", cfg.Core.Port)
	}
	if cfg.Core.Profile.ClashAPI != core.DefaultClashAPI {
		t.Errorf("profile controller = %s, want %s", cfg.Core.Profile.ClashAPI, core.DefaultClashAPI)
	}
	if port := cfg.Core.Profile.Inbounds[0].Port; port != 2890 {
		t.Errorf("profile inbound port = %d, want 2890", port)
	}
}

// A port the user picked is theirs; normalising must leave it alone.
func TestCustomPortsSurviveNormalize(t *testing.T) {
	cfg := Config{
		Inbound: Inbound{HTTPAddr: "127.0.0.1:18080", SOCKS5Addr: "127.0.0.1:18081"},
		API:     API{Addr: "127.0.0.1:18082"},
		Core:    Core{Port: 18083},
	}
	cfg.Normalize()

	if cfg.Inbound.HTTPAddr != "127.0.0.1:18080" || cfg.Inbound.SOCKS5Addr != "127.0.0.1:18081" {
		t.Errorf("custom inbounds were rewritten: %s / %s", cfg.Inbound.HTTPAddr, cfg.Inbound.SOCKS5Addr)
	}
	if cfg.API.Addr != "127.0.0.1:18082" || cfg.Core.Port != 18083 {
		t.Errorf("custom api/core were rewritten: %s / %d", cfg.API.Addr, cfg.Core.Port)
	}
}

// The migration has to reach the file, not just memory: a settings page or a
// backup that still shows 7890 while the client listens on 2890 is a bug the
// user would have to debug by hand.
func TestLoadOrCreatePersistsMigratedPorts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw := `{
  "inbound": {"socks5_addr": "127.0.0.1:7891", "http_addr": "127.0.0.1:7890"},
  "api": {"addr": "127.0.0.1:9090"},
  "core": {"id": "mihomo", "port": 7899}
}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	cfg, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if cfg.Inbound.HTTPAddr != "127.0.0.1:2890" {
		t.Errorf("in-memory http addr = %s", cfg.Inbound.HTTPAddr)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Inbound.HTTPAddr != "127.0.0.1:2890" || reloaded.API.Addr != "127.0.0.1:3090" {
		t.Errorf("the migration was not written back: %s / %s", reloaded.Inbound.HTTPAddr, reloaded.API.Addr)
	}
	if reloaded.Core.Port != 2899 {
		t.Errorf("core port on disk = %d, want 2899", reloaded.Core.Port)
	}
}

// The system proxy bypass list is optional: a configuration written before it
// existed must keep loading, and must keep meaning "use the built-in default"
// rather than pinning a copy of it here.
func TestSysProxyBypassDefaultsAndCleans(t *testing.T) {
	if got := (SysProxy{}).BypassString(); got != "" {
		t.Fatalf("unconfigured bypass = %q, want empty", got)
	}
	got := (SysProxy{Bypass: []string{" <local> ", "", "   ", "*.corp.example.com"}}).BypassString()
	if want := "<local>;*.corp.example.com"; got != want {
		t.Fatalf("bypass = %q, want %q", got, want)
	}
}

func TestSysProxyBypassSurvivesSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := Default()
	cfg.Normalize()
	cfg.SysProxy.Bypass = []string{"<local>", "*.corp.example.com"}
	if err := Save(path, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	back, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := back.SysProxy.BypassString(); got != "<local>;*.corp.example.com" {
		t.Fatalf("reloaded bypass = %q", got)
	}

	// A file that predates the field: no sysproxy block at all.
	legacy := filepath.Join(dir, "legacy.json")
	body := `{"inbound":{"socks5_addr":"127.0.0.1:2891","http_addr":"127.0.0.1:2890"}}`
	if err := os.WriteFile(legacy, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	old, err := Load(legacy)
	if err != nil {
		t.Fatalf("load legacy: %v", err)
	}
	if got := old.SysProxy.BypassString(); got != "" {
		t.Fatalf("legacy config bypass = %q, want empty", got)
	}
}
