package app

import (
	"testing"

	"vvpn/internal/core"
)

func TestUpsertProxyProviderReplacesInPlace(t *testing.T) {
	p := providerTestProfile()
	first := core.Provider{Name: "airport", Type: core.ProviderHTTP, URL: "https://a/sub"}
	var err error
	p, err = upsertProxyProvider(p, first)
	if err != nil {
		t.Fatalf("upsertProxyProvider: %v", err)
	}
	second := core.Provider{Name: "AIRPORT", Type: core.ProviderHTTP, URL: "https://b/sub"}
	p, err = upsertProxyProvider(p, second)
	if err != nil {
		t.Fatalf("upsertProxyProvider (replace): %v", err)
	}
	if len(p.Providers) != 1 {
		t.Fatalf("replacing produced %d providers, want 1: %+v", len(p.Providers), p.Providers)
	}
	// The replacement wins outright: the profile now describes exactly what was
	// last submitted, including the name's casing.
	if p.Providers[0].URL != "https://b/sub" || p.Providers[0].Name != "AIRPORT" {
		t.Errorf("the replacement did not take: %+v", p.Providers[0])
	}
}

func TestUpsertProxyProviderKeepsOtherProvidersInOrder(t *testing.T) {
	p := providerTestProfile()
	var err error
	for _, name := range []string{"a", "b", "c"} {
		p, err = upsertProxyProvider(p, core.Provider{Name: name, Type: core.ProviderHTTP, URL: "https://" + name})
		if err != nil {
			t.Fatalf("upsertProxyProvider(%s): %v", name, err)
		}
	}
	p, err = upsertProxyProvider(p, core.Provider{Name: "b", Type: core.ProviderFile, Path: "/x.yaml"})
	if err != nil {
		t.Fatalf("upsertProxyProvider(replace b): %v", err)
	}
	got := make([]string, 0, len(p.Providers))
	for _, pr := range p.Providers {
		got = append(got, pr.Name)
	}
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("providers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("providers = %v, want %v (order must survive an in-place edit)", got, want)
		}
	}
	if p.Providers[1].ProviderType() != core.ProviderFile || p.Providers[1].Path != "/x.yaml" {
		t.Errorf("the in-place edit did not switch the vehicle: %+v", p.Providers[1])
	}
}

func TestUpsertProxyProviderRejectsInvalidDefinition(t *testing.T) {
	p := providerTestProfile()
	if _, err := upsertProxyProvider(p, core.Provider{Name: "x", Type: core.ProviderHTTP}); err == nil {
		t.Error("an http provider with no url was accepted")
	}
	if _, err := upsertProxyProvider(p, core.Provider{Name: "x", Type: core.ProviderFile}); err == nil {
		t.Error("a file provider with no path was accepted")
	}
	if _, err := upsertProxyProvider(p, core.Provider{Name: "  ", Type: core.ProviderHTTP, URL: "https://a"}); err == nil {
		t.Error("a provider with a blank name was accepted")
	}
	if _, err := upsertProxyProvider(p, core.Provider{Name: "x", Type: core.ProviderInline}); err == nil {
		t.Error("an inline proxy provider was accepted; a proxy list has to be fetchable")
	}
}

// A group that reaches a provider through "use" must lose that reference in the
// same step as the provider itself. Leaving it behind makes the whole profile
// invalid, and an invalid profile is one the core refuses to start with.
func TestRemoveProxyProviderUnhooksEveryGroupThatUsedIt(t *testing.T) {
	p := providerTestProfile()
	var err error
	p, err = upsertProxyProvider(p, core.Provider{Name: "airport", Type: core.ProviderHTTP, URL: "https://a"})
	if err != nil {
		t.Fatalf("upsertProxyProvider: %v", err)
	}
	p.Groups = []core.Group{
		{Name: "PROXY", Type: core.GroupSelect, Members: []string{"n1"}, Use: []string{"airport"}},
		{Name: "MIXED", Type: core.GroupSelect, Members: []string{"n1"}, Use: []string{"airport"}},
	}
	p.Final = "PROXY"
	if err := p.Validate(); err != nil {
		t.Fatalf("the profile should be valid before the removal: %v", err)
	}

	p, dropped, err := removeProxyProvider(p, "airport")
	if err != nil {
		t.Fatalf("removeProxyProvider: %v", err)
	}
	if dropped != 2 {
		t.Errorf("dropped = %d, want 2 (one reference in each group)", dropped)
	}
	if len(p.Providers) != 0 {
		t.Errorf("the provider survived: %+v", p.Providers)
	}
	for i, g := range p.Groups {
		if len(g.Use) != 0 {
			t.Errorf("group #%d still uses %v", i+1, g.Use)
		}
		if len(g.Members) != 1 || g.Members[0] != "n1" {
			t.Errorf("group #%d lost its hand-picked members: %+v", i+1, g.Members)
		}
	}
	if err := p.Validate(); err != nil {
		t.Errorf("the profile must stay valid after the removal: %v", err)
	}
}

func TestRemoveProxyProviderKeepsTheRemainingUses(t *testing.T) {
	p := providerTestProfile()
	var err error
	for _, name := range []string{"a", "b"} {
		p, err = upsertProxyProvider(p, core.Provider{Name: name, Type: core.ProviderHTTP, URL: "https://" + name})
		if err != nil {
			t.Fatalf("upsertProxyProvider(%s): %v", name, err)
		}
	}
	p.Groups = []core.Group{{Name: "PROXY", Type: core.GroupSelect, Members: []string{"n1"}, Use: []string{"a", "b"}}}
	p.Final = "PROXY"
	if err := p.Validate(); err != nil {
		t.Fatalf("the profile should be valid before the removal: %v", err)
	}
	p, dropped, err := removeProxyProvider(p, "a")
	if err != nil {
		t.Fatalf("removeProxyProvider: %v", err)
	}
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1", dropped)
	}
	if len(p.Groups[0].Use) != 1 || p.Groups[0].Use[0] != "b" {
		t.Errorf("the surviving reference was lost: %+v", p.Groups[0].Use)
	}
	if err := p.Validate(); err != nil {
		t.Errorf("the profile must stay valid: %v", err)
	}
}
func TestRemoveProxyProviderRejectsUnknownName(t *testing.T) {
	p := providerTestProfile()
	if _, _, err := removeProxyProvider(p, "ghost"); err == nil {
		t.Error("removing a provider that does not exist was accepted")
	}
	if _, _, err := removeProxyProvider(p, "   "); err == nil {
		t.Error("removing a provider with a blank name was accepted")
	}
}

// The pure halves must not touch the caller's slices: the console holds a
// profile it read a moment ago and re-renders from it when a save is refused.
func TestProxyProviderEditsDoNotMutateTheInput(t *testing.T) {
	p := providerTestProfile()
	p.Providers = []core.Provider{{Name: "airport", Type: core.ProviderHTTP, URL: "https://a"}}
	p.Groups = []core.Group{{Name: "PROXY", Type: core.GroupSelect, Members: []string{"n1"}, Use: []string{"airport"}}}
	p.Final = "PROXY"
	beforeGroups := len(p.Groups[0].Use)

	if _, err := upsertProxyProvider(p, core.Provider{Name: "airport", Type: core.ProviderHTTP, URL: "https://b"}); err != nil {
		t.Fatalf("upsertProxyProvider: %v", err)
	}
	if p.Providers[0].URL != "https://a" {
		t.Errorf("upsertProxyProvider mutated the input profile: %+v", p.Providers[0])
	}
	if _, _, err := removeProxyProvider(p, "airport"); err != nil {
		t.Fatalf("removeProxyProvider: %v", err)
	}
	if len(p.Providers) != 1 || len(p.Groups[0].Use) != beforeGroups {
		t.Errorf("removeProxyProvider mutated the input profile: providers=%+v use=%+v", p.Providers, p.Groups[0].Use)
	}
}
