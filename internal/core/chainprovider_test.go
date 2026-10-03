package core

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"vvpn/internal/yamlmin"
)

// chainProviderProfile is the smallest profile that exercises both blanks this
// feature fills: a node dialed through another outbound, and a proxy group fed
// by named proxy providers.
func chainProviderProfile() Profile {
	return Profile{
		Log:      "info",
		Inbounds: []Inbound{{Type: InboundMixed, Tag: "mixed-in", Listen: "127.0.0.1", Port: 4101}},
		Nodes: []Node{
			{Name: "front", Type: TypeSS, Server: "1.2.3.4", Port: 8388, Method: "aes-256-gcm", Password: "pw", DialerProxy: "landing"},
			{Name: "landing", Type: TypeSS, Server: "5.6.7.8", Port: 8388, Method: "aes-256-gcm", Password: "pw"},
		},
		Groups: []Group{{
			Name:    "PROXY",
			Type:    GroupSelect,
			Members: []string{"front", "landing"},
			Use:     []string{"airport", "backup"},
		}},
		// Declared out of order on purpose: the generated document is sorted by
		// provider name so two runs diff cleanly.
		Providers: []Provider{
			{Name: "backup", Type: ProviderFile, Path: "providers/backup.yaml"},
			{Name: "airport", URL: "https://example.com/sub.yaml", Interval: 3600,
				HealthCheck: &ProviderHealthCheck{
					Enable:   boolRef(true),
					URL:      "http://www.gstatic.com/generate_204",
					Interval: 300,
				}},
		},
		Final: "PROXY",
		Rules: []Rule{{Kind: RuleFinal, Value: "", Action: "PROXY"}},
	}
}

func boolRef(v bool) *bool { return &v }

// lacks asserts a fragment the emitter must never write.
func lacks(t *testing.T, text, fragment, why string) {
	t.Helper()
	if strings.Contains(text, fragment) {
		t.Errorf("emitted document must not contain %q (%s)\n%s", fragment, why, text)
	}
}

// section returns the part of text between start and end, end excluded.
func section(t *testing.T, text, start, end string) string {
	t.Helper()
	i := strings.Index(text, start)
	if i < 0 {
		t.Fatalf("emitted document has no %q\n%s", start, text)
	}
	rest := text[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		t.Fatalf("emitted document has no %q after %q\n%s", end, start, text)
	}
	return rest[:j]
}

func parseYAMLMap(t *testing.T, text string) yamlmin.Map {
	t.Helper()
	doc, err := yamlmin.ParseString(text)
	if err != nil {
		t.Fatalf("parse emitted YAML: %v\n%s", err, text)
	}
	m, ok := yamlmin.AsMap(doc)
	if !ok {
		t.Fatalf("emitted document is not a mapping:\n%s", text)
	}
	return m
}

func mapValue(t *testing.T, m yamlmin.Map, key string) any {
	t.Helper()
	v, ok := m.Get(key)
	if !ok {
		t.Fatalf("key %q is missing from the emitted document", key)
	}
	return v
}

func getString(t *testing.T, m yamlmin.Map, key string) string {
	t.Helper()
	return yamlmin.AsString(mapValue(t, m, key))
}

// The whole point of the feature: the chain is written on the node that needs
// it, the providers are declared once, and the group reaches into them.
func TestMihomoEmitsDialerProxyProvidersAndUse(t *testing.T) {
	raw, err := Render("mihomo", chainProviderProfile())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	text := string(raw)

	// The provider block: sorted by name, and only the keys that were set.
	got := section(t, text, "proxy-providers:\n", "proxy-groups:\n")
	want := "" +
		"  airport:\n" +
		"    type: http\n" +
		"    url: https://example.com/sub.yaml\n" +
		"    interval: 3600\n" +
		"    health-check:\n" +
		"      enable: true\n" +
		"      url: http://www.gstatic.com/generate_204\n" +
		"      interval: 300\n" +
		"  backup:\n" +
		"    type: file\n" +
		"    path: providers/backup.yaml\n"
	if got != want {
		t.Errorf("proxy-providers block =\n%s\nwant\n%s", got, want)
	}
	if strings.Index(text, "proxy-providers:") > strings.Index(text, "proxy-groups:") {
		t.Errorf("proxy-providers must be written before the groups that use it:\n%s", text)
	}

	// The chain lives on the node that asked for it and nowhere else.
	proxies := section(t, text, "proxies:\n", "proxy-providers:\n")
	if strings.Count(proxies, "dialer-proxy") != 1 {
		t.Errorf("exactly one node should carry dialer-proxy:\n%s", proxies)
	}
	if !strings.Contains(proxies, "    dialer-proxy: landing\n") {
		t.Errorf("the front node lost its chain:\n%s", proxies)
	}
	front := strings.Index(proxies, "  - name: front\n")
	landing := strings.Index(proxies, "  - name: landing\n")
	chain := strings.Index(proxies, "    dialer-proxy: landing\n")
	if front < 0 || landing < 0 || chain < front || chain > landing {
		t.Errorf("dialer-proxy is not inside the front node entry:\n%s", proxies)
	}

	// The group keeps its members and gains the provider list.
	group := section(t, text, "proxy-groups:\n", "rules:\n")
	wantGroup := "" +
		"  - name: PROXY\n" +
		"    type: select\n" +
		"    proxies:\n" +
		"      - front\n" +
		"      - landing\n" +
		"    use:\n" +
		"      - airport\n" +
		"      - backup\n"
	if group != wantGroup {
		t.Errorf("proxy-groups block =\n%s\nwant\n%s", group, wantGroup)
	}

	// No empty value may reach the document: mihomo reads an empty string as a
	// name it has to resolve, not as "unset".
	for _, bad := range []string{`: ""`, ": null", "use: []", "health-check: {}"} {
		lacks(t, text, bad, "an unset key must be left out entirely")
	}
	lacks(t, text, "interval: 0", "0 means mihomo's own default")
}

// A profile that never touched the feature must emit exactly the document it
// emitted before: no empty chain key, no empty provider block.
func TestMihomoOmitsChainKeysWhenUnset(t *testing.T) {
	raw, err := Render("mihomo", sampleProfile())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	text := string(raw)
	for _, bad := range []string{"dialer-proxy", "proxy-providers", "use:", "health-check"} {
		lacks(t, text, bad, "the profile has no chain and no providers")
	}
}

// The emitted text has to survive the project's own YAML reader as well: the
// importer and the emitters share one subset, and a chain that only exists as
// text is not a chain.
func TestMihomoDocumentParsesBack(t *testing.T) {
	raw, err := Render("mihomo", chainProviderProfile())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	m := parseYAMLMap(t, string(raw))

	proxies, ok := yamlmin.AsSeq(mapValue(t, m, "proxies"))
	if !ok || len(proxies) != 2 {
		t.Fatalf("proxies = %#v", mapValue(t, m, "proxies"))
	}
	front, _ := yamlmin.AsMap(proxies[0])
	if got := getString(t, front, "dialer-proxy"); got != "landing" {
		t.Errorf("front.dialer-proxy = %q, want landing", got)
	}
	landing, _ := yamlmin.AsMap(proxies[1])
	if _, present := landing.Get("dialer-proxy"); present {
		t.Error("the landing node must not carry a dialer-proxy key at all")
	}

	providers, ok := yamlmin.AsMap(mapValue(t, m, "proxy-providers"))
	if !ok {
		t.Fatalf("proxy-providers is not a mapping: %#v", mapValue(t, m, "proxy-providers"))
	}
	names := make([]string, 0, len(providers))
	for _, e := range providers {
		names = append(names, e.K)
	}
	if strings.Join(names, ",") != "airport,backup" {
		t.Errorf("provider order = %v, want [airport backup]", names)
	}
	airport, _ := yamlmin.AsMap(mapValue(t, providers, "airport"))
	if got := getString(t, airport, "type"); got != "http" {
		t.Errorf("airport.type = %q, want http (an unset type means http)", got)
	}
	if got := yamlmin.AsInt(mapValue(t, airport, "interval")); got != 3600 {
		t.Errorf("airport.interval = %d, want 3600", got)
	}
	hc, ok := yamlmin.AsMap(mapValue(t, airport, "health-check"))
	if !ok {
		t.Fatalf("airport has no health-check block")
	}
	if !yamlmin.AsBool(mapValue(t, hc, "enable")) {
		t.Error("health-check.enable was not emitted as true")
	}
	backup, _ := yamlmin.AsMap(mapValue(t, providers, "backup"))
	if got := getString(t, backup, "path"); got != "providers/backup.yaml" {
		t.Errorf("backup.path = %q", got)
	}
	if _, present := backup.Get("interval"); present {
		t.Error("an unset interval must not be written: mihomo has its own default")
	}
	if _, present := backup.Get("health-check"); present {
		t.Error("an unset health-check must not be written")
	}

	groups, ok := yamlmin.AsSeq(mapValue(t, m, "proxy-groups"))
	if !ok || len(groups) != 1 {
		t.Fatalf("proxy-groups = %#v", mapValue(t, m, "proxy-groups"))
	}
	g0, _ := yamlmin.AsMap(groups[0])
	if got := strings.Join(yamlmin.AsStrings(mapValue(t, g0, "use")), ","); got != "airport,backup" {
		t.Errorf("group.use = %q, want airport,backup", got)
	}
}

// A dialer-proxy that leads back to its own start would make the core dial
// itself; the cycle has to be refused here, naming every node on the ring.
func TestProfileRejectsDialerProxyCycles(t *testing.T) {
	base := func() Profile {
		return Profile{
			Inbounds: []Inbound{{Type: InboundMixed, Tag: "in", Listen: "127.0.0.1", Port: 4101}},
			Nodes: []Node{
				{Name: "n1", Type: TypeSS, Server: "1.1.1.1", Port: 8388, Method: "aes-256-gcm", Password: "pw"},
				{Name: "n2", Type: TypeSS, Server: "2.2.2.2", Port: 8388, Method: "aes-256-gcm", Password: "pw"},
			},
			Groups: []Group{{Name: "PROXY", Type: GroupSelect, Members: []string{"n1", "n2"}}},
			Final:  "PROXY",
		}
	}

	oneWay := base()
	oneWay.Nodes[0].DialerProxy = "n2"
	if err := oneWay.Validate(); err != nil {
		t.Fatalf("a one-way chain is the point of the feature, got %v", err)
	}
	viaGroup := base()
	viaGroup.Groups = append(viaGroup.Groups, Group{Name: "LANDING", Type: GroupSelect, Members: []string{"n2"}})
	viaGroup.Nodes[0].DialerProxy = "LANDING"
	if err := viaGroup.Validate(); err != nil {
		t.Fatalf("dialing through a group that does not contain the node is fine, got %v", err)
	}

	cases := []struct {
		name  string
		want  string
		apply func(*Profile)
	}{
		{"self reference", "n1 -> n1", func(p *Profile) {
			p.Nodes[0].DialerProxy = "n1"
		}},
		{"two nodes pointing at each other", "n1 -> n2 -> n1", func(p *Profile) {
			p.Nodes[0].DialerProxy = "n2"
			p.Nodes[1].DialerProxy = "n1"
		}},
		{"a group that contains the node itself", "n1 -> n1", func(p *Profile) {
			p.Nodes[0].DialerProxy = "PROXY"
		}},
		{"a group standing between the two nodes", "n1 -> n2 -> n1", func(p *Profile) {
			p.Groups = append(p.Groups, Group{Name: "CHAIN", Type: GroupSelect, Members: []string{"n2"}})
			p.Nodes[0].DialerProxy = "CHAIN"
			p.Nodes[1].DialerProxy = "n1"
		}},
	}
	for _, c := range cases {
		p := base()
		c.apply(&p)
		err := p.Validate()
		if err == nil {
			t.Errorf("%s: Validate() accepted a dialer-proxy cycle", c.name)
			continue
		}
		if !strings.Contains(err.Error(), "dialer-proxy cycle") {
			t.Errorf("%s: unexpected error %v", c.name, err)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not name the ring %q", c.name, err, c.want)
		}
	}

	p := base()
	p.Nodes[0].DialerProxy = "ghost"
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "unknown outbound") {
		t.Errorf("a chain to a name that does not exist must be refused, got %v", err)
	}
	if err != nil && !strings.Contains(err.Error(), "ghost") {
		t.Errorf("the error should quote the unknown name, got %v", err)
	}
}

func TestProfileRejectsProviderProblems(t *testing.T) {
	cases := []struct {
		name  string
		want  string
		apply func(*Profile)
	}{
		{"duplicate name", "duplicate proxy provider", func(p *Profile) {
			p.Providers = append(p.Providers, Provider{Name: "Airport", URL: "https://example.com/other.yaml"})
		}},
		{"collides with a node", "collides", func(p *Profile) {
			p.Providers[0].Name = "front"
		}},
		{"collides with a group", "collides", func(p *Profile) {
			p.Providers[0].Name = "PROXY"
		}},
		{"use names a provider that does not exist", "unknown proxy provider", func(p *Profile) {
			p.Groups[0].Use = []string{"ghost"}
		}},
		{"http provider without a url", "needs a url", func(p *Profile) {
			p.Providers[1].URL = ""
		}},
		{"file provider without a path", "needs a path", func(p *Profile) {
			p.Providers[0].Path = ""
		}},
		{"unknown type", "unknown type", func(p *Profile) {
			p.Providers[1].Type = "rsync"
		}},
		{"negative interval", "negative interval", func(p *Profile) {
			p.Providers[1].Interval = -1
		}},
		{"negative health-check interval", "negative health-check interval", func(p *Profile) {
			p.Providers[1].HealthCheck.Interval = -1
		}},
		{"nameless provider", "no name", func(p *Profile) {
			p.Providers[0].Name = "   "
		}},
	}
	for _, c := range cases {
		p := chainProviderProfile()
		c.apply(&p)
		err := p.Validate()
		if err == nil {
			t.Errorf("%s: Validate() succeeded, want an error", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.want)
		}
	}
}

// Normalize is the only place the padded strings a user or an import can leave
// behind are cleaned, and it must not touch anything that was already there.
func TestProfileNormalizeTrimsChainAndProviderFields(t *testing.T) {
	p := chainProviderProfile()
	p.Nodes[0].DialerProxy = "  landing  "
	p.Groups[0].Use = []string{" airport ", "", "   ", "backup"}
	p.Providers[0].Name = " backup "
	p.Providers[0].Path = " providers/backup.yaml "
	p.Providers[1].Type = " HTTP "
	p.Providers[1].URL = " https://example.com/sub.yaml "
	p.Providers[1].HealthCheck.URL = "  http://www.gstatic.com/generate_204 "
	p.Normalize()

	if p.Nodes[0].DialerProxy != "landing" {
		t.Errorf("dialer-proxy = %q, want landing", p.Nodes[0].DialerProxy)
	}
	if got := strings.Join(p.Groups[0].Use, ","); got != "airport,backup" {
		t.Errorf("use = %q, want airport,backup (empty entries dropped)", got)
	}
	if p.Providers[0].Name != "backup" || p.Providers[0].Path != "providers/backup.yaml" {
		t.Errorf("file provider = %+v", p.Providers[0])
	}
	if p.Providers[1].Type != "http" || p.Providers[1].URL != "https://example.com/sub.yaml" {
		t.Errorf("http provider = %+v", p.Providers[1])
	}
	if p.Providers[1].HealthCheck.URL != "http://www.gstatic.com/generate_204" {
		t.Errorf("health-check url = %q", p.Providers[1].HealthCheck.URL)
	}
	// A field Normalize has no business touching keeps its value.
	if p.Nodes[0].Server != "1.2.3.4" || p.Nodes[0].Name != "front" {
		t.Errorf("Normalize rewrote a node it should not have: %+v", p.Nodes[0])
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("the normalized profile must still validate: %v", err)
	}

	// An all-blank use list collapses to nothing, so no empty "use" key is
	// written for a group that never named a provider.
	blank := chainProviderProfile()
	blank.Groups[0].Use = []string{"  ", ""}
	blank.Normalize()
	if blank.Groups[0].Use != nil {
		t.Errorf("an all-blank use list = %#v, want nil", blank.Groups[0].Use)
	}
	raw, err := Render("mihomo", blank)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	lacks(t, string(raw), "use:", "the group names no provider")
}

// The chain and the provider list are mihomo's blocks. The other emitters have
// no equivalent, but they must keep producing their own documents instead of
// tripping over fields that are not theirs.
func TestOtherCoresIgnoreChainAndProviderFields(t *testing.T) {
	p := chainProviderProfile()
	singbox, warnings, err := EmitSingBoxWithWarnings(p)
	if err != nil {
		t.Fatalf("EmitSingBoxWithWarnings: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	raw, err := json.Marshal(singbox)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leaked := range []string{"dialer-proxy", "proxy-providers", "health-check"} {
		if strings.Contains(string(raw), leaked) {
			t.Errorf("the sing-box document leaked %q:\n%s", leaked, raw)
		}
	}
	if _, err := EmitXray(p); err != nil {
		t.Fatalf("EmitXray: %v", err)
	}
}

// TestMihomoAcceptsTheGeneratedDocument is the only check that is not this
// package talking to itself: the client's own mihomo binary parses the
// document this feature produces. It runs -t, which validates and exits, so the
// core never listens on a port and the isolated data directory keeps its cache
// out of the shipped cores/mihomo folder.
func TestMihomoAcceptsTheGeneratedDocument(t *testing.T) {
	root := filepath.Join("..", "..")
	bin := filepath.Join(root, "cores", "mihomo", "mihomo.exe")
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("the mihomo core is not installed in this checkout: %v", err)
	}
	dir, err := filepath.Abs(filepath.Join(root, "lab", "tmp", "p41-core-verify"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}

	// The file provider points at a real payload, so the parser has a list to
	// load without a network round trip. Paths are relative on purpose: mihomo
	// resolves them against the -d directory.
	listPath := filepath.Join(dir, "local-list.yaml")
	list := "proxies:\n" +
		"  - name: provider-node\n" +
		"    type: ss\n" +
		"    server: 9.9.9.9\n" +
		"    port: 8388\n" +
		"    cipher: aes-256-gcm\n" +
		"    password: pw\n"
	if err := os.WriteFile(listPath, []byte(list), 0o644); err != nil {
		t.Fatalf("write %s: %v", listPath, err)
	}

	p := chainProviderProfile()
	p.Providers = []Provider{
		{Name: "local-list", Type: ProviderFile, Path: "local-list.yaml"},
		{Name: "remote-list", URL: "https://example.com/sub.yaml", Path: "remote-list.yaml",
			Interval: 3600, HealthCheck: &ProviderHealthCheck{
				Enable:   boolRef(true),
				URL:      "http://www.gstatic.com/generate_204",
				Interval: 300,
			}},
	}
	p.Groups[0].Use = []string{"local-list", "remote-list"}
	raw, err := Render("mihomo", p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, raw, 0o644); err != nil {
		t.Fatalf("write %s: %v", cfgPath, err)
	}

	cmd := exec.Command(bin, "-t", "-d", dir, "-f", cfgPath)
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		t.Fatalf("mihomo rejected %s: %v\n%s", cfgPath, err, text)
	}
	t.Logf("mihomo -t accepted %s: %s", cfgPath, text)
}
