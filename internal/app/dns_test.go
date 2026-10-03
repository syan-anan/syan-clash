package app

import (
	"strings"
	"testing"

	"vvpn/internal/core"
)

// The console can send whatever the user typed, including a blob pasted out of
// a README. These are the shapes that have to survive that.
func TestNormalizeDNSSplitsAndDeduplicates(t *testing.T) {
	got, err := NormalizeDNS(core.DNS{
		Enabled:  true,
		Servers:  []string{"223.5.5.5, 119.29.29.29\n1.1.1.1", "223.5.5.5", "", "https://dns.google/dns-query; tls://8.8.8.8:853"},
		Strategy: "prefer_ipv4",
	}, false)
	if err != nil {
		t.Fatalf("NormalizeDNS: %v", err)
	}
	want := []string{"223.5.5.5", "119.29.29.29", "1.1.1.1", "https://dns.google/dns-query", "tls://8.8.8.8:853"}
	if len(got.Servers) != len(want) {
		t.Fatalf("servers = %v, want %v", got.Servers, want)
	}
	for i := range want {
		if got.Servers[i] != want[i] {
			t.Fatalf("servers = %v, want %v", got.Servers, want)
		}
	}
	if got.Final != "" {
		t.Fatalf("NormalizeDNS must not invent a final resolver tag, got %q", got.Final)
	}
}

func TestNormalizeDNSRefusesSystemResolverUnderTun(t *testing.T) {
	_, err := NormalizeDNS(core.DNS{
		Enabled: true,
		Servers: []string{"local", "https://223.5.5.5/dns-query"},
	}, true)
	if err == nil {
		t.Fatal("a system resolver under a tunnel has to be refused")
	}
	if !strings.Contains(err.Error(), "系统解析器") || !strings.Contains(err.Error(), "local") {
		t.Fatalf("the error must name the offending entry, got %q", err)
	}
}

func TestNormalizeDNSAllowsSystemResolverWithoutTun(t *testing.T) {
	got, err := NormalizeDNS(core.DNS{Enabled: true, Servers: []string{"local", "system"}}, false)
	if err != nil {
		t.Fatalf("without a tunnel a system resolver is merely redundant: %v", err)
	}
	// "local" and "system" are the same delegation, so only one survives.
	if len(got.Servers) != 2 {
		t.Fatalf("servers = %v, want both entries kept as written", got.Servers)
	}
}

func TestNormalizeDNSRejectsUnusableBlocks(t *testing.T) {
	cases := map[string]core.DNS{
		"enabled without servers": {Enabled: true},
		"unknown strategy":        {Enabled: true, Servers: []string{"1.1.1.1"}, Strategy: "fastest"},
		"bad fake-ip range":       {Enabled: true, Servers: []string{"1.1.1.1"}, FakeIPRange: "198.18.0.0"},
		"whitespace inside entry": {Enabled: true, Servers: []string{"1.1.1.1 8.8.8.8 x"}},
	}
	for name, in := range cases {
		if _, err := NormalizeDNS(in, false); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestNormalizeDNSAcceptsDisabledEmptyBlock(t *testing.T) {
	got, err := NormalizeDNS(core.DNS{Enabled: false}, false)
	if err != nil {
		t.Fatalf("a switched-off resolver block has nothing to validate: %v", err)
	}
	if got.Enabled || len(got.Servers) != 0 {
		t.Fatalf("unexpected block %+v", got)
	}
}

func TestNormalizeDNSKeepsFakeIPRangeWhenValid(t *testing.T) {
	got, err := NormalizeDNS(core.DNS{
		Enabled:     true,
		Servers:     []string{"1.1.1.1"},
		FakeIP:      true,
		FakeIPRange: " 198.19.0.0/16 ",
	}, false)
	if err != nil {
		t.Fatalf("NormalizeDNS: %v", err)
	}
	if got.FakeIPRange != "198.19.0.0/16" {
		t.Fatalf("fake-ip range = %q, want the trimmed value", got.FakeIPRange)
	}
	if !got.FakeIP {
		t.Fatal("the fake-ip switch was dropped")
	}
}
