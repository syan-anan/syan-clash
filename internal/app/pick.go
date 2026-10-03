package app

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// PickResult is the outcome of an automatic best-node selection.
type PickResult struct {
	Group    string         `json:"group"`
	Selected string         `json:"selected"`
	Delays   map[string]int `json:"delays"`
	Failed   []string       `json:"failed,omitempty"`
	Skipped  bool           `json:"skipped,omitempty"`
}

// PickFastestMember measures every member of a group and switches the group to
// the one with the lowest latency. It is the "auto select best node" action:
// the core's own url-test does this on a timer, but a user-triggered run is
// useful right after importing a subscription.
//
// testURL should point at something reachable in the current environment; when
// empty the core's default is used.
func (a *App) PickFastestMember(ctx context.Context, coreID, group, testURL string, timeoutMS int) (PickResult, error) {
	client, err := a.CoreClient(coreID)
	if err != nil {
		return PickResult{}, err
	}
	table, err := client.Proxies(ctx)
	if err != nil {
		return PickResult{}, err
	}
	proxy, ok := table[group]
	if !ok {
		return PickResult{}, fmt.Errorf("代理组 %q 不存在", group)
	}
	if len(proxy.All) == 0 {
		return PickResult{}, fmt.Errorf("代理组 %q 没有成员", group)
	}

	result := PickResult{Group: group, Delays: map[string]int{}}
	best := ""
	bestDelay := 0
	for _, member := range proxy.All {
		name := member
		if entry, ok := table[member]; ok && len(entry.All) > 0 {
			// A nested group: measure its currently selected member instead of
			// the group itself, which the API reports separately.
			if entry.Now != "" {
				name = entry.Now
			}
		}
		delays, err := client.Delay(ctx, name, testURL, timeoutMS)
		if err != nil {
			result.Failed = append(result.Failed, member)
			continue
		}
		delay, ok := delays[name]
		if !ok || delay <= 0 {
			result.Failed = append(result.Failed, member)
			continue
		}
		result.Delays[member] = delay
		if best == "" || delay < bestDelay {
			best = member
			bestDelay = delay
		}
	}
	if best == "" {
		return result, fmt.Errorf("代理组 %q 里没有可用节点（%d 个成员全部超时）", group, len(proxy.All))
	}
	if best == proxy.Now {
		result.Selected = best
		result.Skipped = true
		return result, nil
	}
	if err := client.Select(ctx, group, best); err != nil {
		return result, err
	}
	result.Selected = best
	return result, nil
}

// SortedDelays returns the measured latencies from fastest to slowest, which is
// what the UI shows after a sweep.
func (r PickResult) SortedDelays() []struct {
	Name  string
	Delay int
} {
	out := make([]struct {
		Name  string
		Delay int
	}, 0, len(r.Delays))
	for name, delay := range r.Delays {
		out = append(out, struct {
			Name  string
			Delay int
		}{name, delay})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Delay < out[j].Delay })
	return out
}

// SweepGroup is PickFastestMember with a sane default timeout, exposed for the
// "全部测速" button.
func (a *App) SweepGroup(ctx context.Context, coreID, group, testURL string) (PickResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	return a.PickFastestMember(ctx, coreID, group, testURL, 5000)
}
