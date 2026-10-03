package app

import (
	"context"
	"fmt"
	"strings"

	"vvpn/internal/core"
)

// ProxyProviders returns the profile's proxy lists, in profile order.
func (a *App) ProxyProviders() []core.Provider {
	return a.Profile().Providers
}

// UpsertProxyProvider adds a proxy list, or replaces the one with the same name,
// and applies the profile. Replacing rather than appending is what lets the UI
// edit a list in place: the groups that already reach it keep working.
func (a *App) UpsertProxyProvider(ctx context.Context, pr core.Provider) error {
	profile, err := upsertProxyProvider(a.Profile(), pr)
	if err != nil {
		return err
	}
	return a.SetProfile(ctx, profile)
}

// RemoveProxyProvider deletes a proxy list together with every group reference
// to it. The two have to go in one step: a group whose "use" names a list that
// no longer exists makes the whole profile invalid, which would leave the core
// unable to start at all. It returns how many group references went with it.
func (a *App) RemoveProxyProvider(ctx context.Context, name string) (int, error) {
	profile, dropped, err := removeProxyProvider(a.Profile(), name)
	if err != nil {
		return 0, err
	}
	if err := a.SetProfile(ctx, profile); err != nil {
		return 0, err
	}
	return dropped, nil
}

// upsertProxyProvider is the pure half of UpsertProxyProvider, so the profile
// edit can be tested without an App. It deliberately does not check the name
// against the outbound names: Profile.Validate already refuses a collision, and
// keeping that rule in one place means the console sees the same wording the
// core would use.
func upsertProxyProvider(profile core.Profile, pr core.Provider) (core.Profile, error) {
	pr.Name = strings.TrimSpace(pr.Name)
	if err := pr.Validate(); err != nil {
		return profile, err
	}
	replaced := false
	providers := make([]core.Provider, 0, len(profile.Providers)+1)
	for _, existing := range profile.Providers {
		if strings.EqualFold(strings.TrimSpace(existing.Name), pr.Name) {
			providers = append(providers, pr)
			replaced = true
			continue
		}
		providers = append(providers, existing)
	}
	if !replaced {
		providers = append(providers, pr)
	}
	profile.Providers = providers
	return profile, nil
}

// removeProxyProvider is the pure half of RemoveProxyProvider. A group that
// named the list in "use" loses that entry and keeps its hand-picked members;
// a group that reaches the list by nothing else is left exactly as it was, so
// the edit can never turn a working group into an invalid one.
func removeProxyProvider(profile core.Profile, name string) (core.Profile, int, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return profile, 0, fmt.Errorf("代理集合名不能为空")
	}
	found := false
	providers := make([]core.Provider, 0, len(profile.Providers))
	for _, pr := range profile.Providers {
		if strings.EqualFold(strings.TrimSpace(pr.Name), name) {
			found = true
			continue
		}
		providers = append(providers, pr)
	}
	if !found {
		return profile, 0, fmt.Errorf("代理集合 %q 不存在", name)
	}
	dropped := 0
	groups := make([]core.Group, len(profile.Groups))
	copy(groups, profile.Groups)
	for i := range groups {
		if len(groups[i].Use) == 0 {
			continue
		}
		keep := make([]string, 0, len(groups[i].Use))
		for _, u := range groups[i].Use {
			if strings.EqualFold(strings.TrimSpace(u), name) {
				dropped++
				continue
			}
			keep = append(keep, u)
		}
		if len(keep) == 0 {
			// Writing an empty "use" would put an empty list in the generated
			// document; nil leaves the key out entirely.
			groups[i].Use = nil
			continue
		}
		groups[i].Use = keep
	}
	profile.Providers = providers
	profile.Groups = groups
	return profile, dropped, nil
}
