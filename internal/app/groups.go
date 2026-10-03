package app

import (
	"context"
	"fmt"
	"strings"

	"vvpn/internal/core"
)

// GroupView is one proxy group as the UI sees it.
type GroupView struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Members []string `json:"members"`
	// Use names the proxy providers whose live nodes join this group. The
	// core merges them with Members, so a group can carry hand-picked nodes
	// and a provider-fed list at the same time.
	Use      []string `json:"use,omitempty"`
	TestURL  string   `json:"test_url,omitempty"`
	Interval int      `json:"interval,omitempty"`
	// Builtin marks a group this client generates itself (PROXY / AUTO / 其他).
	// An import re-creates those, so editing them is pointless and deleting
	// them is refused - the user wants their own groups, not a trap.
	Builtin bool `json:"builtin"`
}

// GroupEdit is the payload of one edit. Empty fields keep the current value,
// so the UI only has to send what the user actually changed.
type GroupEdit struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Members []string `json:"members"`
	// Use is nil when the caller did not mention it, which leaves the
	// current list alone; an empty but non-nil slice unhooks every
	// provider, which is how the console detaches the last one.
	Use      []string `json:"use"`
	TestURL  string   `json:"test_url"`
	Interval int      `json:"interval"`
}

// builtinGroupNames are the group names syan-clash creates on its own.
var builtinGroupNames = map[string]bool{"PROXY": true, "AUTO": true, "其他": true}

// coreBuiltins are the outbound names a core understands without a node. A
// proxy group may NOT list them: the neutral profile only accepts nodes and
// other groups as members, so a rule is the way to send traffic to DIRECT or
// REJECT. They are listed here only to explain that in the error message.
var coreBuiltins = map[string]bool{
	"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true,
	"GLOBAL": true, "COMPATIBLE": true, "PROXY": true,
}

// IsBuiltinGroup reports whether a group name is one the client generates.
func IsBuiltinGroup(name string) bool { return builtinGroupNames[name] }

// validGroupType reports whether a group type is one the cores accept.
func validGroupType(t string) bool {
	switch t {
	case core.GroupSelect, core.GroupURLTest, core.GroupFallback:
		return true
	}
	return false
}

// GroupViews lists the profile's groups.
func (a *App) GroupViews() []GroupView {
	profile := a.Profile()
	out := make([]GroupView, 0, len(profile.Groups))
	for _, g := range profile.Groups {
		out = append(out, GroupView{
			Name:     g.Name,
			Type:     g.Type,
			Members:  append([]string{}, g.Members...),
			Use:      append([]string{}, g.Use...),
			TestURL:  g.URL,
			Interval: g.Interval,
			Builtin:  IsBuiltinGroup(g.Name),
		})
	}
	return out
}

// checkGroupMembers rejects members that are neither a node, another group nor
// a core built-in: a typo there would make the whole profile invalid, and the
// user would only find out when the core refused to start.
func (a *App) checkGroupMembers(profile core.Profile, g core.Group) error {
	names := map[string]bool{}
	for _, n := range profile.Nodes {
		names[n.Name] = true
	}
	for _, other := range profile.Groups {
		if other.Name != g.Name {
			names[other.Name] = true
		}
	}
	for _, m := range g.Members {
		if names[m] {
			continue
		}
		if coreBuiltins[strings.ToUpper(m)] {
			return fmt.Errorf("组 %q 不能把 %s 当成员：想让流量直连或拒绝，写一条规则指向它", g.Name, m)
		}
		return fmt.Errorf("组 %q 的成员 %q 既不是节点也不是已存在的组", g.Name, m)
	}
	return nil
}

// checkGroupUse rejects a use that names a proxy provider the profile does
// not have. The core refuses to start on one, so the console says so first
// instead of letting the save fail somewhere further down.
func (a *App) checkGroupUse(profile core.Profile, g core.Group) error {
	if len(g.Use) == 0 {
		return nil
	}
	known := map[string]bool{}
	for _, pr := range profile.Providers {
		known[strings.ToLower(strings.TrimSpace(pr.Name))] = true
	}
	for _, u := range g.Use {
		if !known[strings.ToLower(strings.TrimSpace(u))] {
			return fmt.Errorf("组 %q 引用了不存在的代理集合 %q", g.Name, u)
		}
	}
	return nil
}

// SetGroup edits the group at index. The group is replaced in place so the
// list order (which is also the UI order and the fallback order) is preserved.
func (a *App) SetGroup(ctx context.Context, index int, e GroupEdit) error {
	profile := a.Profile()
	if index < 0 || index >= len(profile.Groups) {
		return fmt.Errorf("代理组序号 %d 不存在（共 %d 个）", index, len(profile.Groups))
	}
	g := profile.Groups[index]
	if t := strings.TrimSpace(e.Type); t != "" {
		if !validGroupType(t) {
			return fmt.Errorf("未知的组类型 %q（select / url-test / fallback）", t)
		}
		g.Type = t
	}
	if e.Members != nil {
		g.Members = normaliseMembers(e.Members)
	}
	if e.Use != nil {
		g.Use = normaliseMembers(e.Use)
	}
	if e.TestURL != "" {
		g.URL = strings.TrimSpace(e.TestURL)
	}
	if e.Interval > 0 {
		g.Interval = e.Interval
	}
	if name := strings.TrimSpace(e.Name); name != "" && name != g.Name {
		for _, other := range profile.Groups {
			if other.Name == name {
				return fmt.Errorf("已经有叫 %q 的组了", name)
			}
		}
		// Rules and the fallback may point at the group, so the rename has to
		// travel with them or the profile would end up referencing nothing.
		old := g.Name
		for i := range profile.Rules {
			if profile.Rules[i].Action == old {
				profile.Rules[i].Action = name
			}
		}
		if profile.Final == old {
			profile.Final = name
		}
		g.Name = name
	}
	if len(g.Members) == 0 {
		return fmt.Errorf("组 %q 至少要有一个成员", g.Name)
	}
	if err := a.checkGroupMembers(profile, g); err != nil {
		return err
	}
	if err := a.checkGroupUse(profile, g); err != nil {
		return err
	}
	profile.Groups[index] = g
	return a.SetProfile(ctx, profile)
}

// AddGroup appends a new group. With no members given it starts as a selector
// over every node, which is what "new group" means to a user in every other
// client.
func (a *App) AddGroup(ctx context.Context, e GroupEdit) error {
	profile := a.Profile()
	name := strings.TrimSpace(e.Name)
	if name == "" {
		return fmt.Errorf("组名不能为空")
	}
	if builtinGroupNames[name] {
		return fmt.Errorf("%q 是客户端自动生成的组名，换一个", name)
	}
	for _, g := range profile.Groups {
		if g.Name == name {
			return fmt.Errorf("已经有叫 %q 的组了", name)
		}
	}
	kind := strings.TrimSpace(e.Type)
	if kind == "" {
		kind = core.GroupSelect
	}
	if !validGroupType(kind) {
		return fmt.Errorf("未知的组类型 %q（select / url-test / fallback）", kind)
	}
	members := normaliseMembers(e.Members)
	if len(members) == 0 {
		for _, n := range profile.Nodes {
			members = append(members, n.Name)
		}
		if len(members) == 0 {
			return fmt.Errorf("还没有节点，先导入订阅再建组")
		}
	}
	g := core.Group{Name: name, Type: kind, Members: members, Use: normaliseMembers(e.Use), URL: strings.TrimSpace(e.TestURL), Interval: e.Interval}
	if g.URL == "" && (kind == core.GroupURLTest || kind == core.GroupFallback) {
		g.URL = "http://www.gstatic.com/generate_204"
	}
	if err := a.checkGroupMembers(profile, g); err != nil {
		return err
	}
	if err := a.checkGroupUse(profile, g); err != nil {
		return err
	}
	profile.Groups = append(profile.Groups, g)
	if profile.Final == "" {
		profile.Final = g.Name
	}
	return a.SetProfile(ctx, profile)
}

// RemoveGroup deletes a group and every reference to it.
func (a *App) RemoveGroup(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("组名不能为空")
	}
	profile := a.Profile()
	if len(profile.Groups) <= 1 {
		return fmt.Errorf("至少要保留一个代理组：删掉最后一个，内核就没有出口了")
	}
	index := -1
	for i, g := range profile.Groups {
		if g.Name == name {
			index = i
			break
		}
	}
	if index < 0 {
		return fmt.Errorf("组 %q 不存在", name)
	}
	groups := make([]core.Group, 0, len(profile.Groups)-1)
	groups = append(groups, profile.Groups[:index]...)
	groups = append(groups, profile.Groups[index+1:]...)
	for i := range groups {
		members := make([]string, 0, len(groups[i].Members))
		for _, m := range groups[i].Members {
			if m != name {
				members = append(members, m)
			}
		}
		groups[i].Members = members
	}
	profile.Groups = groups
	if profile.Final == name {
		profile.Final = profile.Groups[0].Name
	}
	for i := range profile.Rules {
		if profile.Rules[i].Action == name {
			profile.Rules[i].Action = profile.Final
		}
	}
	return a.SetProfile(ctx, profile)
}

// normaliseMembers trims, drops blanks and removes duplicates while keeping the
// user's order (the order is the group's priority order).
func normaliseMembers(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, m := range in {
		m = strings.TrimSpace(m)
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}
