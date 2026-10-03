package core

import (
	"strings"
	"testing"
)

// NormalizeTunStack is the single gate between a stored preference and a core's
// configuration, so it is pinned here: exactly two stacks may ever come out, and
// "mixed" - the stack measured dead on Windows - may never be one of them.
func TestNormalizeTunStackOnlyEverReturnsARunnableStack(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", TunStackGvisor},
		{"gvisor", TunStackGvisor},
		{"system", TunStackSystem},
		{"  System  ", TunStackSystem},
		{"SYSTEM", TunStackSystem},
		{"mixed", TunStackGvisor},
		{"bogus", TunStackGvisor},
	}
	for _, c := range cases {
		if got := NormalizeTunStack(c.in); got != c.want {
			t.Errorf("NormalizeTunStack(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The system stack has to survive the trip into mihomo's YAML, otherwise the
// selector in the 网络参数 card would look like it saved and then do nothing.
func TestEmitMihomoKeepsTheSystemStack(t *testing.T) {
	p := sampleProfile()
	p.Inbounds = append(p.Inbounds, Inbound{
		Type: InboundTun, Tag: "tun-in", Stack: TunStackSystem, AutoRoute: true, Device: "syan-clash0",
	})
	raw, err := Render("mihomo", p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(string(raw), "stack: system") {
		t.Errorf("the chosen system stack was not emitted\n%s", string(raw))
	}
}
