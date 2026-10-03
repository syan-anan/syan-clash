package app

import (
	"context"
	"testing"

	"vvpn/internal/core"
)

// An inline set is the one case the client can measure exactly: it is holding
// the payload. A set the core was supposed to fetch cannot be measured without
// a running core, and that has to come back as an explicit "unknown" rather
// than a confident zero - an unreachable core and an empty set are different
// things, and only one of them is a problem.
func TestRuleProviderStatsCountsInlineSetsLocally(t *testing.T) {
	a := newTestApp(t)
	profile := a.Profile()
	profile.RuleProviders = []core.RuleProvider{
		{
			Name: "ads", Type: core.ProviderInline, Behavior: core.ProviderBehaviorDomain,
			Payload: []string{"a.example", "b.example", "c.example"},
		},
		{
			Name: "remote", Type: core.ProviderHTTP, Behavior: core.ProviderBehaviorClassical,
			URL: "https://example.com/rules.yaml",
		},
	}
	// Nothing references the sets, which the profile allows on purpose: a
	// provider nothing uses is still declared.
	if err := a.SetProfile(context.Background(), profile); err != nil {
		t.Fatalf("SetProfile: %v", err)
	}

	stats := a.RuleProviderStats(context.Background())
	if len(stats) != 2 {
		t.Fatalf("stats has %d entries, want 2: %+v", len(stats), stats)
	}
	if got := stats["ads"]; got.RuleCount != 3 || got.Source != "inline" {
		t.Errorf("inline set = %+v; want 3 entries from the inline source", got)
	}
	if got := stats["remote"]; got.Source != "unknown" {
		t.Errorf("unmeasured set = %+v; want an explicit unknown", got)
	}
}

func TestRuleProviderStatsIsEmptyWithoutSets(t *testing.T) {
	a := newTestApp(t)
	if stats := a.RuleProviderStats(context.Background()); len(stats) != 0 {
		t.Errorf("a profile with no rule sets produced %+v", stats)
	}
}

// mihomo writes nanosecond precision with a numeric offset. The browser's Date
// cannot parse that, and the page would show "Invalid Date" instead of the
// refresh time, so the client normalises it on the way out.
func TestNormaliseStampTurnsMihomoTimestampsIntoRFC3339(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"2026-10-03T04:12:33.123456789+08:00", "2026-10-02T20:12:33Z"},
		{"2026-10-03T04:12:33+08:00", "2026-10-02T20:12:33Z"},
		{"2026-10-03T04:12:33Z", "2026-10-03T04:12:33Z"},
		{"", ""},
		{"   ", ""},
		{"not a time", "not a time"},
	}
	for _, c := range cases {
		if got := normaliseStamp(c.in); got != c.want {
			t.Errorf("normaliseStamp(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
