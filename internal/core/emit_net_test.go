package core

import (
	"strings"
	"testing"
)

// The network switches must reach the generated mihomo config; otherwise the
// UI toggles would silently do nothing.
func TestMihomoHonoursNetworkToggles(t *testing.T) {
	p := sampleProfile()
	p.AllowLAN = true
	p.IPv6 = true
	doc, err := EmitMihomo(p)
	if err != nil {
		t.Fatalf("EmitMihomo: %v", err)
	}
	text := yamlEmit(doc)
	for _, want := range []string{"ipv6: true\n", "allow-lan: true\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("mihomo config is missing %q\n%s", want, text)
		}
	}
}

// The defaults stay conservative: both switches off.
func TestMihomoNetworkTogglesDefaultOff(t *testing.T) {
	doc, err := EmitMihomo(sampleProfile())
	if err != nil {
		t.Fatalf("EmitMihomo: %v", err)
	}
	text := yamlEmit(doc)
	for _, want := range []string{"ipv6: false\n", "allow-lan: false\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("mihomo config is missing %q\n%s", want, text)
		}
	}
}
