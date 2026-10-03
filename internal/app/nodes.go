package app

import (
	"context"
	"fmt"
	"strings"

	"vvpn/internal/core"
)

// AddNode adds a manually configured node to the profile and, when the core is
// running, restarts it so the node becomes usable immediately.
func (a *App) AddNode(ctx context.Context, node core.Node) error {
	if err := node.Validate(); err != nil {
		return err
	}
	profile := a.Profile()
	for _, existing := range profile.Nodes {
		if existing.Name == node.Name {
			return fmt.Errorf("节点名 %q 已存在", node.Name)
		}
	}
	profile.Nodes = append(profile.Nodes, node)
	profile.Groups = attachNode(profile.Groups, node.Name)
	if profile.Final == "" && len(profile.Groups) > 0 {
		profile.Final = profile.Groups[0].Name
	}
	return a.SetProfile(ctx, profile)
}

// RemoveNode deletes a node and every group reference to it.
func (a *App) RemoveNode(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("节点名不能为空")
	}
	profile := a.Profile()
	kept := make([]core.Node, 0, len(profile.Nodes))
	found := false
	for _, n := range profile.Nodes {
		if n.Name == name {
			found = true
			continue
		}
		kept = append(kept, n)
	}
	if !found {
		return fmt.Errorf("节点 %q 不存在", name)
	}
	profile.Nodes = kept
	profile.Groups = detachNode(profile.Groups, name)
	if len(profile.Groups) == 0 {
		profile.Final = ""
	}
	return a.SetProfile(ctx, profile)
}

// attachNode puts a new node into the conventional groups: every automatic
// (url-test / fallback) group, plus the first selector.
func attachNode(groups []core.Group, name string) []core.Group {
	if len(groups) == 0 {
		return DefaultGroups([]core.Node{{Name: name}})
	}
	added := false
	out := make([]core.Group, 0, len(groups))
	for _, g := range groups {
		if g.Type != core.GroupSelect || !added {
			g.Members = append(g.Members, name)
			if g.Type == core.GroupSelect {
				added = true
			}
		}
		out = append(out, g)
	}
	return out
}

// detachNode removes a node from every group, dropping groups that end up
// empty so the profile stays valid.
func detachNode(groups []core.Group, name string) []core.Group {
	out := make([]core.Group, 0, len(groups))
	for _, g := range groups {
		members := make([]string, 0, len(g.Members))
		for _, m := range g.Members {
			if m != name {
				members = append(members, m)
			}
		}
		g.Members = members
		if len(g.Members) == 0 {
			continue
		}
		out = append(out, g)
	}
	return out
}

// AddRule inserts a rule at the given position (negative or past the end
// appends, and it never lands after the catch-all rule) and applies the
// profile.
func (a *App) AddRule(ctx context.Context, rule core.Rule, index int) error {
	if err := rule.Validate(); err != nil {
		return err
	}
	profile := a.Profile()
	// Adding a rule that already exists would make the rule list grow without
	// effect and confuse the "preset applied" counters.
	for _, existing := range profile.Rules {
		if strings.EqualFold(strings.TrimSpace(existing.Kind), strings.TrimSpace(rule.Kind)) &&
			strings.EqualFold(strings.TrimSpace(existing.Value), strings.TrimSpace(rule.Value)) &&
			strings.EqualFold(strings.TrimSpace(existing.Action), strings.TrimSpace(rule.Action)) {
			return fmt.Errorf("同样的规则已经存在（%s %s → %s）", rule.Kind, rule.Value, rule.Action)
		}
	}
	// A new rule must never land after the catch-all: that would silently make
	// it dead.
	insert := index
	if insert < 0 || insert > len(profile.Rules) {
		insert = len(profile.Rules)
	}
	if insert > 0 && profile.Rules[insert-1].Kind == core.RuleFinal {
		insert--
	}
	rules := make([]core.Rule, 0, len(profile.Rules)+1)
	rules = append(rules, profile.Rules[:insert]...)
	rules = append(rules, rule)
	rules = append(rules, profile.Rules[insert:]...)
	profile.Rules = rules
	return a.SetProfile(ctx, profile)
}

// RemoveRule deletes one rule by position.
func (a *App) RemoveRule(ctx context.Context, index int) error {
	profile := a.Profile()
	if index < 0 || index >= len(profile.Rules) {
		return fmt.Errorf("规则序号 %d 不存在（共 %d 条）", index, len(profile.Rules))
	}
	rules := make([]core.Rule, 0, len(profile.Rules)-1)
	rules = append(rules, profile.Rules[:index]...)
	rules = append(rules, profile.Rules[index+1:]...)
	profile.Rules = rules
	return a.SetProfile(ctx, profile)
}
