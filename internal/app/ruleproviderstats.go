package app

import (
	"context"
	"strings"
	"time"

	"vvpn/internal/clashapi"
	"vvpn/internal/core"
)

// RuleProviderStat is what the console can say about one rule set: how many
// entries it carries and when it was last refreshed. The count comes from the
// core for anything the core fetched itself; an inline set never leaves the
// client, so its count is computed here.
type RuleProviderStat struct {
	RuleCount int    `json:"rule_count"`
	UpdatedAt string `json:"updated_at,omitempty"`
	// Source says where the numbers came from, so the page can be honest about
	// a set it could not measure instead of showing a confident zero.
	Source string `json:"source"`
}

// RuleProviderStats reports the state of every configured rule set, keyed by
// the name the profile uses.
//
// It never fails. A console that cannot reach the core still has to show the
// list, and a rule set that has not been fetched yet is a normal state rather
// than an error: those entries come back with Source "unknown" and the page
// says so.
func (a *App) RuleProviderStats(ctx context.Context) map[string]RuleProviderStat {
	profile := a.Profile()
	out := make(map[string]RuleProviderStat, len(profile.RuleProviders))
	if len(profile.RuleProviders) == 0 {
		return out
	}

	// Best effort: no core running, a core that does not implement the
	// endpoint, or a core still fetching its sets all land here, and all of
	// them mean "the client cannot measure this one right now".
	var fromCore map[string]clashapi.RuleProviderStatus
	if client, err := a.CoreClient(""); err == nil {
		if got, err := client.RuleProviders(ctx); err == nil {
			fromCore = got
		}
	}

	for _, rp := range profile.RuleProviders {
		name := strings.TrimSpace(rp.Name)
		if name == "" {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(rp.Type), core.ProviderInline) {
			// An inline set is the one case the client knows exactly: it is
			// holding the payload.
			out[name] = RuleProviderStat{RuleCount: len(rp.Payload), Source: "inline"}
			continue
		}
		if got, ok := fromCore[name]; ok {
			out[name] = RuleProviderStat{
				RuleCount: got.RuleCount,
				UpdatedAt: normaliseStamp(got.UpdatedAt),
				Source:    "core",
			}
			continue
		}
		out[name] = RuleProviderStat{Source: "unknown"}
	}
	return out
}

// normaliseStamp turns the timestamp a core reports into RFC3339. mihomo writes
// nanosecond precision with a numeric offset, which the browser's Date cannot
// parse; the page then shows "Invalid Date" instead of the refresh time.
func normaliseStamp(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999999-07:00"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return raw
}
