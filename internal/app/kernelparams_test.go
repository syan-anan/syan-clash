package app

import (
	"context"
	"strings"
	"testing"

	"vvpn/internal/config"
	"vvpn/internal/core"
)

// A fresh client must report the values the cores have always been handed, and
// must report that the user has not touched them yet: "unset" is not the same
// as "set to the default" for the sniffer, and the console says so.
func TestKernelParamsDefaultsMatchTheShippedBehaviour(t *testing.T) {
	a := newTestApp(t)
	got := a.KernelParams()
	if got.LogLevel != "info" {
		t.Errorf("log level = %q, want info", got.LogLevel)
	}
	if len(got.Levels) == 0 {
		t.Error("the level list the console renders came back empty")
	}
	if !got.Sniff || got.SniffSet {
		t.Errorf("sniff = %v set = %v, want an effective true that was never configured", got.Sniff, got.SniffSet)
	}
	if got.TunMTU != core.TunMTUDefault || got.TunMTUSet {
		t.Errorf("tun mtu = %d set = %v, want %d and unset", got.TunMTU, got.TunMTUSet, core.TunMTUDefault)
	}
	if got.TunStrictRoute {
		t.Error("strict-route must default to off: that is the only value this client ships")
	}
	if !got.TunDNSHijack {
		t.Error("dns-hijack must default to on")
	}
	if got.TunAutoRoute {
		t.Error("auto-route must follow the (absent) tunnel inbound, which is off")
	}
	if got.TunEnabled {
		t.Error("a fresh profile has no tunnel inbound")
	}
	if got.MTUMin != core.TunMTUMin || got.MTUMax != core.TunMTUMax {
		t.Errorf("mtu bounds = %d..%d, want %d..%d", got.MTUMin, got.MTUMax, core.TunMTUMin, core.TunMTUMax)
	}
}

func TestKernelParamsRoundTripThroughTheConfigurationFile(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	level := "DEBUG"
	yes, no := true, false
	mtu := 1400
	out, err := a.SetKernelParams(ctx, KernelParamsPatch{
		LogLevel:       &level,
		Sniff:          &no,
		TunMTU:         &mtu,
		TunStrictRoute: &yes,
		TunDNSHijack:   &no,
		TunAutoRoute:   &yes,
	})
	if err != nil {
		t.Fatalf("SetKernelParams: %v", err)
	}
	if out.LogLevel != "debug" {
		t.Errorf("log level = %q, want the normalised debug", out.LogLevel)
	}
	if out.Sniff || !out.SniffSet {
		t.Errorf("sniff = %v set = %v, want an explicit false", out.Sniff, out.SniffSet)
	}
	if out.TunMTU != 1400 || !out.TunMTUSet {
		t.Errorf("tun mtu = %d set = %v, want 1400 and set", out.TunMTU, out.TunMTUSet)
	}
	if !out.TunStrictRoute || out.TunDNSHijack || !out.TunAutoRoute {
		t.Errorf("tunnel switches did not stick: strict=%v hijack=%v auto=%v",
			out.TunStrictRoute, out.TunDNSHijack, out.TunAutoRoute)
	}

	cfg, err := config.Load(a.ConfigPath())
	if err != nil {
		t.Fatalf("reload the configuration from disk: %v", err)
	}
	p := cfg.Core.Profile
	if p == nil {
		t.Fatal("the profile disappeared from the configuration file")
	}
	if p.Log != "debug" {
		t.Errorf("stored log level = %q", p.Log)
	}
	if p.Sniff == nil || *p.Sniff {
		t.Error("the sniffer choice was not stored as an explicit false")
	}
	if p.TunMTU != 1400 {
		t.Errorf("stored tun mtu = %d", p.TunMTU)
	}
	if p.TunStrictRoute == nil || !*p.TunStrictRoute {
		t.Error("strict-route was not stored")
	}
	if p.TunDNSHijack == nil || *p.TunDNSHijack {
		t.Error("dns-hijack was not stored as an explicit false")
	}
	if p.TunAutoRoute == nil || !*p.TunAutoRoute {
		t.Error("auto-route was not stored")
	}
}

// Values the core would refuse have to come back as an error with the value in
// it, not as a configuration that makes the core fail to start.
func TestKernelParamsRejectUnusableValues(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	before := a.KernelParams()

	badLevel := "chatty"
	if _, err := a.SetKernelParams(ctx, KernelParamsPatch{LogLevel: &badLevel}); err == nil {
		t.Error("an unknown log level was accepted")
	} else if !strings.Contains(err.Error(), "chatty") {
		t.Errorf("the error does not name the offending level: %v", err)
	}
	for _, mtu := range []int{100, 70000} {
		bad := mtu
		if _, err := a.SetKernelParams(ctx, KernelParamsPatch{TunMTU: &bad}); err == nil {
			t.Errorf("MTU %d was accepted", mtu)
		}
	}
	after := a.KernelParams()
	// KernelParams carries a slice, so it cannot be compared with ==; compare
	// the fields that matter one by one.
	if after.LogLevel != before.LogLevel || after.Sniff != before.Sniff ||
		after.SniffSet != before.SniffSet || after.TunMTU != before.TunMTU ||
		after.TunMTUSet != before.TunMTUSet || after.TunAutoRoute != before.TunAutoRoute ||
		after.TunStrictRoute != before.TunStrictRoute || after.TunDNSHijack != before.TunDNSHijack {
		t.Errorf("a rejected request still changed the stored values:\nbefore %+v\nafter  %+v", before, after)
	}
}

// The stored values have to reach a core's configuration, which is the only
// thing that makes the page useful.
func TestKernelParamsReachTheGeneratedCoreConfig(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	profile := a.Profile()
	profile.Inbounds = append(profile.Inbounds, core.Inbound{
		Type: core.InboundTun, Tag: "tun-in", Stack: core.TunStackGvisor,
		AutoRoute: true, MTU: 9000, Device: "syan-clash0",
	})
	if err := a.SetProfile(ctx, profile); err != nil {
		t.Fatalf("SetProfile: %v", err)
	}

	// Nothing configured yet: the tunnel document is the one that always shipped.
	raw, err := core.Render("mihomo", a.Profile())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(string(raw), "mtu: 9000") || strings.Contains(string(raw), "sniffer") {
		t.Fatalf("the default document changed:\n%s", string(raw))
	}

	yes, no := true, false
	mtu := 1380
	if _, err := a.SetKernelParams(ctx, KernelParamsPatch{
		LogLevel:       strPtr("warn"),
		Sniff:          &yes,
		TunMTU:         &mtu,
		TunStrictRoute: &yes,
		TunDNSHijack:   &no,
	}); err != nil {
		t.Fatalf("SetKernelParams: %v", err)
	}
	raw, err = core.Render("mihomo", a.Profile())
	if err != nil {
		t.Fatalf("Render(configured): %v", err)
	}
	text := string(raw)
	for _, want := range []string{
		"log-level: warn",
		"sniffer:",
		"mtu: 1380",
		"strict-route: true",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the generated document is missing %q\n%s", want, text)
		}
	}
	if strings.Contains(text, "dns-hijack") {
		t.Errorf("dns-hijack was turned off but is still written:\n%s", text)
	}

	// 0 means "stop overriding": the inbound's own 9000 comes back.
	zero := 0
	if _, err := a.SetKernelParams(ctx, KernelParamsPatch{TunMTU: &zero}); err != nil {
		t.Fatalf("SetKernelParams(zero): %v", err)
	}
	out := a.KernelParams()
	if out.TunMTUSet || out.TunMTU != 9000 {
		t.Errorf("clearing the override left mtu = %d set = %v", out.TunMTU, out.TunMTUSet)
	}
}

func strPtr(s string) *string { return &s }
