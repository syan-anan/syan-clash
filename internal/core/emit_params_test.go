package core

import (
	"strings"
	"testing"
)

// tunProfile is the shape the TUN switch writes: one mixed listener plus a
// tunnel whose inbound-level values are the ones the client has always used.
func tunProfile() Profile {
	p := sampleProfile()
	p.Inbounds = append(p.Inbounds, Inbound{
		Type: InboundTun, Tag: "tun-in", Stack: "mixed",
		AutoRoute: true, StrictRoute: true, MTU: 9000, Device: "syan-clash0",
	})
	return p
}

// wantTunBlock is the tunnel document this client shipped before the tuning
// fields existed, character for character: key order, two-space indentation and
// the hard-coded values. It is the contract this work must not move - a
// configuration written before the feature has to keep producing this text.
const wantTunBlock = `tun:
  enable: true
  stack: gvisor
  device: syan-clash0
  auto-route: true
  auto-detect-interface: true
  strict-route: false
  dns-hijack:
    - any:53
    - tcp://any:53
  mtu: 9000
`

func TestMihomoTunnelBlockIsUnchangedWhenNothingIsConfigured(t *testing.T) {
	raw, err := Render("mihomo", tunProfile())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, wantTunBlock) {
		t.Fatalf("the default tunnel block changed:\n%s", text)
	}
	// The sniffer block must not appear at all: mihomo's own default is off, and
	// writing one would change the document of every existing installation.
	if strings.Contains(text, "sniffer") {
		t.Errorf("an unset sniffer must not write a sniffer block:\n%s", text)
	}
}

func TestMihomoTunnelAndSnifferFollowTheProfile(t *testing.T) {
	yes, no := true, false
	p := tunProfile()
	p.Sniff = &yes
	p.TunMTU = 1400
	p.TunStrictRoute = &yes
	p.TunDNSHijack = &no
	p.TunAutoRoute = &no
	raw, err := Render("mihomo", p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	text := string(raw)
	for _, want := range []string{
		"sniffer:\n",
		"  enable: true\n",
		"override-destination: false",
		"TLS:",
		"QUIC:",
		"mtu: 1400",
		"strict-route: true",
		"auto-route: false",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("configured mihomo document is missing %q\n%s", want, text)
		}
	}
	if strings.Contains(text, "dns-hijack") || strings.Contains(text, "any:53") {
		t.Errorf("dns-hijack was turned off but is still written:\n%s", text)
	}

	// Turning the sniffer off is a value, not an omission: the document has to
	// say so, otherwise "off" and "never configured" look identical in the file.
	p.Sniff = &no
	raw, err = Render("mihomo", p)
	if err != nil {
		t.Fatalf("Render(off): %v", err)
	}
	text = string(raw)
	if !strings.Contains(text, "sniffer:\n  enable: false\n") {
		t.Errorf("an explicitly disabled sniffer must be written as false:\n%s", text)
	}
	if strings.Contains(text, "TLS:") {
		t.Errorf("a disabled sniffer must not carry sniff rules:\n%s", text)
	}
}

func TestMihomoLogLevelIsNormalised(t *testing.T) {
	p := tunProfile()
	p.Log = "  WARNING  "
	raw, err := Render("mihomo", p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(string(raw), "log-level: warn\n") {
		t.Errorf("a padded/aliased level must land on mihomo's spelling:\n%s", string(raw))
	}
	p.Log = "nonsense"
	raw, err = Render("mihomo", p)
	if err != nil {
		t.Fatalf("Render(bad): %v", err)
	}
	if !strings.Contains(string(raw), "log-level: info\n") {
		t.Errorf("an unknown level must fall back to info:\n%s", string(raw))
	}
}

func TestXraySniffingFollowsTheSwitch(t *testing.T) {
	raw, err := Render("xray", sampleProfile())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "\"enabled\": true") || !strings.Contains(text, "\"destOverride\"") {
		t.Fatalf("Xray must keep sniffing by default:\n%s", text)
	}

	no := false
	p := sampleProfile()
	p.Sniff = &no
	raw, err = Render("xray", p)
	if err != nil {
		t.Fatalf("Render(off): %v", err)
	}
	text = string(raw)
	if !strings.Contains(text, "\"enabled\": false") {
		t.Errorf("switching the sniffer off must reach the Xray document:\n%s", text)
	}
	if strings.Contains(text, "destOverride") {
		t.Errorf("a disabled sniffer must not keep destOverride:\n%s", text)
	}
}

func TestXrayLogLevelUsesXraySpelling(t *testing.T) {
	p := sampleProfile()
	p.Log = "warn"
	raw, err := Render("xray", p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(string(raw), "\"loglevel\": \"warning\"") {
		t.Errorf("warn must become warning for Xray:\n%s", string(raw))
	}
	p.Log = "silent"
	raw, err = Render("xray", p)
	if err != nil {
		t.Fatalf("Render(silent): %v", err)
	}
	if !strings.Contains(string(raw), "\"loglevel\": \"none\"") {
		t.Errorf("silent must become none for Xray:\n%s", string(raw))
	}
}

func TestSingBoxSniffIsOnlyWrittenWhenChosen(t *testing.T) {
	raw, err := Render("sing-box", sampleProfile())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(string(raw), "\"sniff\"") {
		t.Errorf("an unset sniffer must leave the sing-box document alone:\n%s", string(raw))
	}
	yes := true
	p := sampleProfile()
	p.Sniff = &yes
	raw, err = Render("sing-box", p)
	if err != nil {
		t.Fatalf("Render(on): %v", err)
	}
	if !strings.Contains(string(raw), "\"sniff\": true") {
		t.Errorf("the sniffer choice must reach the sing-box document:\n%s", string(raw))
	}
}

func TestSingBoxTunnelFollowsTheProfileOverrides(t *testing.T) {
	no := false
	p := tunProfile()
	p.TunMTU = 1400
	p.TunAutoRoute = &no
	raw, err := Render("sing-box", p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	text := string(raw)
	for _, want := range []string{"\"mtu\": 1400", "\"auto_route\": false"} {
		if !strings.Contains(text, want) {
			t.Errorf("configured sing-box tunnel is missing %s\n%s", want, text)
		}
	}
}
