package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"vvpn/internal/core"
	"vvpn/internal/subscription"
)

// Subscription is one saved subscription source, so the user does not have to
// paste the link again on every start.
type Subscription struct {
	Name      string             `json:"name"`
	URL       string             `json:"url"`
	AddedAt   time.Time          `json:"added_at"`
	UpdatedAt time.Time          `json:"updated_at,omitempty"`
	Nodes     int                `json:"nodes"`
	Auto      bool               `json:"auto"`
	LastError string             `json:"last_error,omitempty"`
	Info      *subscription.Info `json:"info,omitempty"`
	// NodeNames records the servers this subscription contributed so the
	// ownership map can be rebuilt after a restart (see rebuildNodeSources).
	NodeNames []string `json:"node_names,omitempty"`
	// UserAgent overrides the User-Agent used to fetch this subscription.
	// Airports fingerprint that header and answer unknown agents with decoy
	// node lists, so being able to match what the provider expects matters.
	// Empty means "use the client default" (subscriptionUserAgent).
	UserAgent string `json:"user_agent,omitempty"`
	// IntervalOverrideHours forces how often the automatic refresh runs,
	// overriding both the provider's profile-update-interval header and the
	// built-in default. Zero means "follow the provider".
	IntervalOverrideHours int64 `json:"interval_override_hours,omitempty"`
}

// AddSubscription stores a subscription source and imports it.
func (a *App) AddSubscription(ctx context.Context, name, url string) (Subscription, error) {
	url = strings.TrimSpace(url)
	if url == "" {
		return Subscription{}, fmt.Errorf("订阅链接不能为空")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = subscriptionNameFromURL(url)
	}

	a.mu.Lock()
	for _, s := range a.subs {
		if s.URL == url {
			a.mu.Unlock()
			return Subscription{}, fmt.Errorf("订阅 %q 已经存在", s.Name)
		}
	}
	a.mu.Unlock()

	result, err := a.ImportSubscriptionAs(ctx, name, url)
	sub := Subscription{Name: name, URL: url, AddedAt: time.Now(), Auto: true}
	if err != nil {
		sub.LastError = err.Error()
	} else {
		sub.Nodes = result.Nodes
		sub.UpdatedAt = time.Now()
		sub.Info = result.Info
	}
	sub.NodeNames = namesOfImported(sub.NodeNames, result.Names)

	a.mu.Lock()
	a.subs = append(a.subs, sub)
	a.mu.Unlock()
	if err := a.saveSubs(); err != nil {
		return sub, err
	}
	if err != nil {
		return sub, fmt.Errorf("订阅已保存，但导入失败：%w", err)
	}
	a.log.Infof("订阅 %s 已导入 %d 个节点", name, result.Nodes)
	return sub, nil
}

// RemoveSubscription deletes a saved subscription.
func (a *App) RemoveSubscription(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	a.mu.Lock()
	kept := make([]Subscription, 0, len(a.subs))
	found := false
	for _, s := range a.subs {
		if s.Name == name {
			found = true
			continue
		}
		kept = append(kept, s)
	}
	a.subs = kept
	a.mu.Unlock()
	if !found {
		return fmt.Errorf("订阅 %q 不存在", name)
	}
	if err := a.saveSubs(); err != nil {
		return err
	}
	// The subscription's servers must go with it: leaving them behind would
	// silently keep routing to a provider the user just removed. Hand-added
	// nodes belong to no subscription and are untouched.
	profile := a.Profile()
	profile.Nodes = dropNodesFrom(name, profile.Nodes)
	profile.Groups = mergeGroups(profile.Groups, profile.Nodes)
	forgetNodes(name)
	// Airport rules routinely target the airport's own selector, and the final
	// outbound points at its group too. Both would now name an outbound that
	// just vanished, which profile validation rejects outright - so rebind
	// them to "follow the final outbound" instead of failing the removal.
	profile = rebindStaleTargets(profile)
	if len(profile.Groups) == 0 {
		profile.Final = ""
	}
	return a.SetProfile(ctx, profile)
}

// rebindStaleTargets clears rule actions and the final outbound that point at
// an outbound which no longer exists (for example after its subscription was
// removed). An empty action means "follow the final outbound", which keeps the
// rule list intact without dangling references that fail validation.
func rebindStaleTargets(p core.Profile) core.Profile {
	valid := make(map[string]bool, len(p.Nodes)+len(p.Groups))
	for _, n := range p.Nodes {
		valid[n.Name] = true
	}
	for _, g := range p.Groups {
		valid[g.Name] = true
	}
	for i := range p.Rules {
		if !targetExists(p.Rules[i].Action, valid) {
			p.Rules[i].Action = ""
		}
	}
	if !targetExists(p.Final, valid) {
		p.Final = ""
	}
	return p
}

// targetExists reports whether a rule target is a reserved action or a
// concrete outbound that still exists.
func targetExists(action string, valid map[string]bool) bool {
	switch action {
	case "", core.ActionDirect, core.ActionReject, core.ActionProxy:
		return true
	}
	return valid[action]
}

// Subscriptions lists the saved subscriptions.
func (a *App) Subscriptions() []Subscription {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Subscription, len(a.subs))
	copy(out, a.subs)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// UpdateSubscription re-imports one saved subscription.
func (a *App) UpdateSubscription(ctx context.Context, name string) (Subscription, error) {
	a.mu.Lock()
	var target Subscription
	found := false
	for _, s := range a.subs {
		if s.Name == name {
			target = s
			found = true
			break
		}
	}
	a.mu.Unlock()
	if !found {
		return Subscription{}, fmt.Errorf("订阅 %q 不存在", name)
	}

	result, err := a.ImportSubscriptionAs(ctx, target.Name, target.URL)
	now := time.Now()
	a.mu.Lock()
	for i := range a.subs {
		if a.subs[i].Name != name {
			continue
		}
		if err != nil {
			// A refresh cut short by shutdown is not a subscription failure:
			// recording it would leave a permanent "失败" in the console for
			// something that was the user closing the app.
			if !errors.Is(err, context.Canceled) {
				a.subs[i].LastError = err.Error()
			}
		} else {
			a.subs[i].LastError = ""
			a.subs[i].UpdatedAt = now
			a.subs[i].Nodes = result.Nodes
			a.subs[i].Info = result.Info
			a.subs[i].NodeNames = namesOfImported(a.subs[i].NodeNames, result.Names)
		}
		target = a.subs[i]
		break
	}
	a.mu.Unlock()
	if saveErr := a.saveSubs(); saveErr != nil && err == nil {
		err = saveErr
	}
	return target, err
}

// UpdateAllSubscriptions refreshes every saved subscription; failures are
// reported per subscription rather than aborting the sweep.
func (a *App) UpdateAllSubscriptions(ctx context.Context) ([]Subscription, error) {
	var updated []Subscription
	var failures []string
	for _, s := range a.Subscriptions() {
		res, err := a.UpdateSubscription(ctx, s.Name)
		updated = append(updated, res)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", s.Name, err))
		}
	}
	if len(failures) > 0 {
		return updated, fmt.Errorf("%d 个订阅更新失败：%s", len(failures), strings.Join(failures, "; "))
	}
	return updated, nil
}

// defaultAutoInterval is how often an automatic subscription is refreshed when
// the provider does not say. Providers that do say send
// profile-update-interval, which ParseUpdateInterval already reads.
const defaultAutoInterval = 12 * time.Hour

// autoInterval is how often one subscription wants to be refreshed. An explicit
// choice beats the provider's own header: the operator may know that the
// provider only publishes on a different schedule than it advertises, and an
// interval they set is a promise the console then keeps.
func autoInterval(s Subscription) time.Duration {
	if s.IntervalOverrideHours > 0 {
		return time.Duration(s.IntervalOverrideHours) * time.Hour
	}
	if s.Info != nil && s.Info.UpdateEvery > 0 {
		return time.Duration(s.Info.UpdateEvery) * time.Hour
	}
	return defaultAutoInterval
}

// AutoInterval is how often a subscription wants to be refreshed. It is
// exported so the console can show the interval next to the switch.
func AutoInterval(s Subscription) time.Duration { return autoInterval(s) }

// maxIntervalOverrideHours bounds the override the console may store: a month.
const maxIntervalOverrideHours = 24 * 30

// subscriptionUserAgent returns the User-Agent saved for a subscription. An
// empty result means "use the client default".
func (a *App) subscriptionUserAgent(name string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.subs {
		if s.Name == name {
			return s.UserAgent
		}
	}
	return ""
}

// SetSubscriptionOptions stores the per-subscription fetch options: the
// User-Agent to present and a refresh interval that overrides the provider's
// own header. A zero interval means "follow the provider". Neither value is
// applied by this call — the console follows up with a refresh, so the operator
// sees the new agent take effect immediately instead of at the next sweep.
func (a *App) SetSubscriptionOptions(name, userAgent string, intervalHours int64) (Subscription, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Subscription{}, fmt.Errorf("订阅名称不能为空")
	}
	userAgent = strings.TrimSpace(userAgent)
	if strings.ContainsAny(userAgent, "\r\n") {
		return Subscription{}, fmt.Errorf("User-Agent 不能包含换行")
	}
	if len(userAgent) > 256 {
		return Subscription{}, fmt.Errorf("User-Agent 太长（最多 256 字符）")
	}
	if intervalHours < 0 || intervalHours > maxIntervalOverrideHours {
		return Subscription{}, fmt.Errorf("更新间隔必须在 0 到 %d 小时之间", maxIntervalOverrideHours)
	}

	a.mu.Lock()
	var out Subscription
	found := false
	for i := range a.subs {
		if a.subs[i].Name == name {
			a.subs[i].UserAgent = userAgent
			a.subs[i].IntervalOverrideHours = intervalHours
			out = a.subs[i]
			found = true
			break
		}
	}
	a.mu.Unlock()
	if !found {
		return Subscription{}, fmt.Errorf("订阅 %q 不存在", name)
	}
	if err := a.saveSubs(); err != nil {
		return out, err
	}
	return out, nil
}

// NextUpdate is when a subscription is next due, zero when it is not
// automatic. The console shows this so "自动更新" is a promise the user can see
// being kept rather than a switch with no visible effect.
func (s Subscription) NextUpdate() time.Time {
	if !s.Auto {
		return time.Time{}
	}
	base := s.UpdatedAt
	if base.IsZero() {
		base = s.AddedAt
	}
	if base.IsZero() {
		return time.Time{}
	}
	return base.Add(autoInterval(s))
}

// SetSubscriptionAuto turns the scheduled refresh of one subscription on or off
// and persists the choice.
func (a *App) SetSubscriptionAuto(name string, auto bool) (Subscription, error) {
	a.mu.Lock()
	var out Subscription
	found := false
	for i := range a.subs {
		if a.subs[i].Name == name {
			a.subs[i].Auto = auto
			out = a.subs[i]
			found = true
			break
		}
	}
	a.mu.Unlock()
	if !found {
		return Subscription{}, fmt.Errorf("订阅 %q 不存在", name)
	}
	if err := a.saveSubs(); err != nil {
		return Subscription{}, err
	}
	return out, nil
}

// ErrSubscriptionStored marks an edit that was saved but whose follow-up import
// failed. The caller reports the failure without claiming the edit was lost,
// which is the difference between "nothing happened" and "retry the refresh".
var ErrSubscriptionStored = errors.New("订阅已保存，但重新导入失败")

// subscriptionByName returns one saved subscription by name.
func (a *App) subscriptionByName(name string) (Subscription, error) {
	for _, s := range a.Subscriptions() {
		if s.Name == name {
			return s, nil
		}
	}
	return Subscription{}, fmt.Errorf("订阅 %q 不存在", name)
}

// EditSubscription renames a saved subscription and/or points it at a new link.
// Both fields are optional: an empty newName keeps the current name and an empty
// url keeps the current link, so the console can send only what the user
// changed. A link change re-imports straight away, because a subscription whose
// URL changed but whose nodes are still the old provider's is worse than no
// edit at all.
func (a *App) EditSubscription(ctx context.Context, name, newName, url string) (Subscription, error) {
	name = strings.TrimSpace(name)
	newName = strings.TrimSpace(newName)
	url = strings.TrimSpace(url)
	if name == "" {
		return Subscription{}, fmt.Errorf("订阅名称不能为空")
	}

	current, err := a.subscriptionByName(name)
	if err != nil {
		return Subscription{}, err
	}
	if newName == "" {
		newName = current.Name
	}
	if url == "" {
		url = current.URL
	}

	renamed := newName != current.Name
	relinked := url != current.URL
	if !renamed && !relinked {
		return current, nil
	}
	if renamed {
		for _, s := range a.Subscriptions() {
			if s.Name == newName {
				return Subscription{}, fmt.Errorf("订阅 %q 已经存在", newName)
			}
		}
	}
	if relinked {
		for _, s := range a.Subscriptions() {
			if s.URL == url && s.Name != current.Name {
				return Subscription{}, fmt.Errorf("这条订阅链接已经属于 %q", s.Name)
			}
		}
	}

	// The name is written first, and the ownership map follows it, so the
	// re-import below already sees the nodes as belonging to the new name.
	a.mu.Lock()
	for i := range a.subs {
		if a.subs[i].Name != name {
			continue
		}
		a.subs[i].Name = newName
		a.subs[i].URL = url
		break
	}
	a.mu.Unlock()
	if renamed {
		renameNodeOwner(name, newName)
	}
	if err := a.saveSubs(); err != nil {
		return Subscription{}, err
	}
	if !relinked {
		a.log.Infof("订阅 %s 已改名为 %s", name, newName)
		return a.subscriptionByName(newName)
	}

	result, importErr := a.ImportSubscriptionAs(ctx, newName, url)
	now := time.Now()
	a.mu.Lock()
	for i := range a.subs {
		if a.subs[i].Name != newName {
			continue
		}
		if importErr != nil {
			// A refresh cut short by shutdown is not a subscription failure.
			if !errors.Is(importErr, context.Canceled) {
				a.subs[i].LastError = importErr.Error()
			}
		} else {
			a.subs[i].LastError = ""
			a.subs[i].UpdatedAt = now
			a.subs[i].Nodes = result.Nodes
			a.subs[i].Info = result.Info
			a.subs[i].NodeNames = namesOfImported(a.subs[i].NodeNames, result.Names)
		}
		break
	}
	a.mu.Unlock()
	if saveErr := a.saveSubs(); saveErr != nil && importErr == nil {
		importErr = saveErr
	}
	sub, _ := a.subscriptionByName(newName)
	if importErr != nil {
		return sub, fmt.Errorf("%w：%v", ErrSubscriptionStored, importErr)
	}
	a.log.Infof("订阅 %s 已改为 %s 并重新导入 %d 个节点", name, newName, result.Nodes)
	return sub, nil
}

// RefreshDueSubscriptions updates the automatic subscriptions whose interval
// has elapsed. It returns how many were refreshed.
func (a *App) RefreshDueSubscriptions(ctx context.Context) int {
	now := time.Now()
	var due []string
	for _, s := range a.Subscriptions() {
		if !s.Auto {
			continue
		}
		if next := s.NextUpdate(); !next.IsZero() && !now.Before(next) {
			due = append(due, s.Name)
		}
	}
	for _, name := range due {
		if _, err := a.UpdateSubscription(ctx, name); err != nil {
			a.log.Warnf("自动更新订阅 %s：%v", name, err)
		}
	}
	return len(due)
}

// StartSubscriptionScheduler checks for due subscriptions on a short tick; the
// per-subscription interval decides what actually gets refreshed, so a provider
// asking for an hourly refresh is not made to wait for a daily sweep.
func (a *App) StartSubscriptionScheduler(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 30 * time.Minute
	}
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n := a.RefreshDueSubscriptions(ctx); n > 0 {
					a.log.Infof("自动更新订阅：%d 个", n)
				}
			}
		}
	}()
}

// subscriptionNameFromURL derives a readable default name from a link.
func subscriptionNameFromURL(raw string) string {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://"), "/")
	if i := strings.IndexAny(trimmed, "?#"); i >= 0 {
		trimmed = trimmed[:i]
	}
	parts := strings.Split(trimmed, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if p := strings.TrimSpace(parts[i]); p != "" {
			return p
		}
	}
	return "subscription"
}
