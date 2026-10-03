package app

import (
	"context"
	"fmt"
	"strings"

	"vvpn/internal/core"
)

// RuleProviders returns the profile's rule sets, in profile order.
func (a *App) RuleProviders() []core.RuleProvider {
	return a.Profile().RuleProviders
}

// UpsertRuleProvider adds a rule set, or replaces the one with the same name,
// and applies the profile. Replacing rather than appending is what lets the UI
// edit a provider in place: a rule that references it keeps working.
func (a *App) UpsertRuleProvider(ctx context.Context, rp core.RuleProvider) error {
	profile, err := upsertRuleProvider(a.Profile(), rp)
	if err != nil {
		return err
	}
	return a.SetProfile(ctx, profile)
}

// RemoveRuleProvider deletes a rule set together with every rule that named it.
// The two have to go in one step: a rule pointing at a provider that no longer
// exists makes the whole profile invalid, which would leave the core unable to
// start at all. It returns how many rules went with it.
func (a *App) RemoveRuleProvider(ctx context.Context, name string) (int, error) {
	profile, removed, err := removeRuleProvider(a.Profile(), name)
	if err != nil {
		return 0, err
	}
	if err := a.SetProfile(ctx, profile); err != nil {
		return 0, err
	}
	return removed, nil
}

// upsertRuleProvider is the pure half of UpsertRuleProvider, so the profile
// edit can be tested without an App.
func upsertRuleProvider(profile core.Profile, rp core.RuleProvider) (core.Profile, error) {
	rp.Name = strings.TrimSpace(rp.Name)
	if err := rp.Validate(); err != nil {
		return profile, err
	}
	replaced := false
	providers := make([]core.RuleProvider, 0, len(profile.RuleProviders)+1)
	for _, existing := range profile.RuleProviders {
		if strings.EqualFold(strings.TrimSpace(existing.Name), rp.Name) {
			providers = append(providers, rp)
			replaced = true
			continue
		}
		providers = append(providers, existing)
	}
	if !replaced {
		providers = append(providers, rp)
	}
	profile.RuleProviders = providers
	return profile, nil
}

// removeRuleProvider is the pure half of RemoveRuleProvider.
func removeRuleProvider(profile core.Profile, name string) (core.Profile, int, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return profile, 0, fmt.Errorf("规则集名不能为空")
	}
	found := false
	providers := make([]core.RuleProvider, 0, len(profile.RuleProviders))
	for _, rp := range profile.RuleProviders {
		if strings.EqualFold(strings.TrimSpace(rp.Name), name) {
			found = true
			continue
		}
		providers = append(providers, rp)
	}
	if !found {
		return profile, 0, fmt.Errorf("规则集 %q 不存在", name)
	}
	removed := 0
	rules := make([]core.Rule, 0, len(profile.Rules))
	for _, r := range profile.Rules {
		if r.Kind == core.RuleProviderRef && strings.EqualFold(strings.TrimSpace(r.Value), name) {
			removed++
			continue
		}
		rules = append(rules, r)
	}
	profile.RuleProviders = providers
	profile.Rules = rules
	return profile, removed, nil
}
