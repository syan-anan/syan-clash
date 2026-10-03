package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"vvpn/internal/config"
	"vvpn/internal/core"
)

// NodeFilterResult reports what a filter run did, which is what the UI shows
// after the user presses 应用.
type NodeFilterResult struct {
	Kept    int      `json:"nodes"`
	Dropped int      `json:"dropped"`
	Renamed int      `json:"renamed"`
	Names   []string `json:"names,omitempty"`
}

// infoNodeMarkers identify the pseudo-nodes airports insert into the node list
// to display plan information (remaining traffic, expiry, official site,
// telegram group). They are not servers, they cannot be dialled, and clicking
// one in another client only ever shows an error - which is exactly why
// CleanInfo exists. The markers are matched case-insensitively against the
// final part of the name.
var infoNodeMarkers = []string{
	// Plan / account cards.
	"剩余流量", "距离下次", "下次重置", "流量重置", "套餐到期", "到期时间",
	"过期时间", "剩余时间", "官网", "订阅地址", "订阅链接", "客服", "群组",
	"telegram", "t.me/", "http://", "https://", "www.",
	// Client placeholders. The subscription this client was built against
	// ships four of them ("若无HY节点-更换客户端即可", "安卓-clashmeta客户端",
	// "电脑-clashverge客户端", "ios-小火箭Shadowrocket客户端"). "客户端" alone is
	// the user's own wording for this class, and no real server is ever named
	// after the program that dials it, so the bare marker is kept.
	//
	// The bare protocol names "clash" and "v2ray" are deliberately NOT markers:
	// an airport can legitimately sell "香港Clash专线" / "香港V2Ray专线" as a
	// server, and dropping a working node is worse than leaving one placeholder
	// behind. The client names below are unambiguous.
	"客户端", "更换客户端", "clashmeta", "clash verge", "clashverge", "clashx",
	"v2rayng", "shadowrocket", "小火箭", "surge", "quantumult", "stash",
	"passwall", "openclash", "sing-box", "singbox", "nekoray", "mihomo",
	"hiddify", "karing", "flclash", "surfboard", "圈x",
	// "ipv6免流-请自行修改host" and its cousins. "免流" on its own is deliberately
	// NOT a marker: airports sell real 免流 nodes.
	"修改host", "hosts文件", "请自行", "自行修改",
}

// isInfoNode reports whether a node name looks like an airport information
// card rather than a server.
func isInfoNode(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range infoNodeMarkers {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}

// matchAny reports whether name contains any of the (case-insensitive)
// patterns. Blank patterns are ignored so a stray comma in the UI cannot
// swallow the whole list.
func matchAny(patterns []string, name string) bool {
	lower := strings.ToLower(name)
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// applyRename rewrites one name. An invalid regular expression is ignored
// instead of failing the whole filter: the UI validates the rules too, but a
// configuration edited by hand must not lock the user out of their nodes.
func applyRename(name string, r config.RenameRule) string {
	if r.From == "" {
		return name
	}
	if !r.Regex {
		return strings.ReplaceAll(name, r.From, r.To)
	}
	re, err := regexp.Compile(r.From)
	if err != nil {
		return name
	}
	return re.ReplaceAllString(name, r.To)
}

// applyNodeFilter runs the whole pipeline over a node list and reports which
// names changed. It is deliberately pure: the same input always produces the
// same output, which is what makes re-applying a filter idempotent when it is
// recomputed from the pre-filter baseline.
func applyNodeFilter(nodes []core.Node, f config.NodeFilter) ([]core.Node, map[string]string, int) {
	rename := map[string]string{}
	kept := make([]core.Node, 0, len(nodes))
	used := map[string]int{}
	dropped := 0
	for _, n := range nodes {
		original := n.Name
		if f.CleanInfoEnabled() && isInfoNode(original) {
			dropped++
			continue
		}
		if matchAny(f.Exclude, original) {
			dropped++
			continue
		}
		if len(f.Include) > 0 && !matchAny(f.Include, original) {
			dropped++
			continue
		}
		name := original
		if f.Prefix != "" {
			name = f.Prefix + name
		}
		if f.Suffix != "" {
			name = name + f.Suffix
		}
		for _, r := range f.Rename {
			name = applyRename(name, r)
		}
		name = strings.TrimSpace(name)
		if name == "" {
			name = original
		}
		// Two different servers must never collapse onto one name: the profile
		// rejects duplicate outbound names outright, which would fail the whole
		// import instead of one rename.
		used[name]++
		if used[name] > 1 {
			name = fmt.Sprintf("%s %d", name, used[name])
		}
		if name != original {
			rename[original] = name
		}
		n.Name = name
		kept = append(kept, n)
	}
	return kept, rename, dropped
}

// mapName follows one rename hop.
func mapName(name string, rename map[string]string) string {
	if mapped, ok := rename[name]; ok {
		return mapped
	}
	return name
}

// retarget walks a name back to the spelling it had in the baseline and then
// forward to the spelling the current filter gives it:
//
//	current --(undo)--> original --(rename)--> new
//
// Groups and rules are not part of the baseline, because the user edits them;
// the undo hop is what lets the filter be changed or cleared later without
// stranding every group member on a node name that no longer exists.
func retarget(name string, undo, rename map[string]string) string {
	if original, ok := undo[name]; ok {
		name = original
	}
	return mapName(name, rename)
}

// inverseRename flips an original->current rename map into current->original,
// which is exactly the hop needed to read the live profile back in terms of
// the baseline.
func inverseRename(rename map[string]string) map[string]string {
	if len(rename) == 0 {
		return nil
	}
	out := make(map[string]string, len(rename))
	for original, current := range rename {
		out[current] = original
	}
	return out
}

// rebindGroups follows node renames inside every group's member list. Members
// that lost their node are left to mergeGroups, which drops them and re-adds
// the orphans in one place.
func rebindGroups(groups []core.Group, undo, rename map[string]string) []core.Group {
	if len(undo) == 0 && len(rename) == 0 {
		return groups
	}
	out := make([]core.Group, len(groups))
	copy(out, groups)
	for i := range out {
		members := make([]string, len(out[i].Members))
		for j, m := range out[i].Members {
			members[j] = retarget(m, undo, rename)
		}
		out[i].Members = members
	}
	return out
}

// rebindRules follows node renames in a rule's action, which may name a node
// directly (most rules point at a group, but "this domain goes to this server"
// is a legitimate setup).
func rebindRules(in []core.Rule, undo, rename map[string]string) []core.Rule {
	if len(undo) == 0 && len(rename) == 0 {
		return in
	}
	out := make([]core.Rule, len(in))
	copy(out, in)
	for i := range out {
		out[i].Action = retarget(out[i].Action, undo, rename)
	}
	return out
}

// groupExists reports whether a profile has a group with this name.
func groupExists(groups []core.Group, name string) bool {
	for _, g := range groups {
		if g.Name == name {
			return true
		}
	}
	return false
}

// nodeBasePath is the pre-filter snapshot of everything the subscriptions
// delivered. The filter is always recomputed from it, so pressing 应用 twice
// cannot apply a rename twice.
func (a *App) nodeBasePath() string {
	return filepath.Join(filepath.Dir(a.cfgPath), "nodes-base.json")
}

// nodeBaseFile is the baseline plus the rename map that is currently in force.
// Nodes are recomputed from the baseline on every run; the rename map is what
// lets the profile's groups and rules - which the user edits and the baseline
// therefore must not overwrite - be walked back to their original spelling
// before the next filter is applied.
type nodeBaseFile struct {
	Nodes   []core.Node       `json:"nodes"`
	Renamed map[string]string `json:"renamed,omitempty"`
}

// saveNodeBase writes the pre-filter node list and the rename map that is now
// in force, atomically.
func (a *App) saveNodeBase(nodes []core.Node, renamed map[string]string) error {
	raw, err := json.MarshalIndent(nodeBaseFile{Nodes: nodes, Renamed: renamed}, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	path := a.nodeBasePath()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nodes-base-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// loadNodeBase reads the pre-filter snapshot. A missing file is not an error:
// it only means the filter has never been applied on this install. Files
// written before the rename map existed hold a bare node array; those read as
// "nothing renamed yet", which is exactly what they mean.
func (a *App) loadNodeBase() (nodeBaseFile, bool, error) {
	raw, err := os.ReadFile(a.nodeBasePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nodeBaseFile{}, false, nil
		}
		return nodeBaseFile{}, false, err
	}
	var file nodeBaseFile
	if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &file.Nodes); err != nil {
			return nodeBaseFile{}, false, fmt.Errorf("%s: %w", a.nodeBasePath(), err)
		}
	} else if err := json.Unmarshal(raw, &file); err != nil {
		return nodeBaseFile{}, false, fmt.Errorf("%s: %w", a.nodeBasePath(), err)
	}
	if len(file.Nodes) == 0 {
		return nodeBaseFile{}, false, nil
	}
	return file, true, nil
}

// HealInfoNodes re-runs the stored filter when the live node list still holds
// the airport's own information rows. Cleaning is on by default, so a profile
// imported by an older build - or imported while cleaning was switched off and
// then switched back on - would otherwise keep those rows until the next
// subscription refresh. It reports whether it changed anything.
//
// Re-running is safe by construction: the result is a function of
// (pre-filter baseline, filter), never of the previous result, so this can run
// on every start and does nothing once the list is clean.
func (a *App) HealInfoNodes(ctx context.Context) bool {
	cfg := a.Config()
	if !cfg.NodeFilter.CleanInfoEnabled() {
		return false
	}
	dirty := 0
	for _, n := range a.Profile().Nodes {
		if isInfoNode(n.Name) {
			dirty++
		}
	}
	if dirty == 0 {
		return false
	}
	res, err := a.ApplyNodeFilter(ctx, cfg.NodeFilter)
	if err != nil {
		a.log.Warnf("启动清理机场信息节点失败：%v", err)
		return false
	}
	a.log.Infof("启动清理：丢掉 %d 个机场信息节点，剩 %d 个", res.Dropped, res.Kept)
	return true
}

// NodeFilter returns the stored filter.
func (a *App) NodeFilter() config.NodeFilter { return a.Config().NodeFilter }

// ApplyNodeFilter stores a filter and immediately recomputes the node list from
// the pre-filter snapshot, then applies the result to the running core.
//
// The snapshot is what makes this safe to press repeatedly: the result is
// always a function of (subscription nodes, filter), never of the previous
// result.
func (a *App) ApplyNodeFilter(ctx context.Context, f config.NodeFilter) (NodeFilterResult, error) {
	base, ok, err := a.loadNodeBase()
	if err != nil {
		return NodeFilterResult{}, err
	}
	if !ok {
		// First run on this install: today's node list is the baseline, and it
		// is written out below so the next run recomputes from it.
		base = nodeBaseFile{Nodes: a.Profile().Nodes}
	}
	if len(base.Nodes) == 0 {
		return NodeFilterResult{}, fmt.Errorf("还没有节点，先导入订阅再设置过滤")
	}
	kept, rename, dropped := applyNodeFilter(base.Nodes, f)
	if len(kept) == 0 {
		return NodeFilterResult{}, fmt.Errorf("过滤后一个节点都不剩，已放弃这次修改（至少保留一个节点）")
	}
	// Groups, rules and the fallback are edited by the user, so they are taken
	// from the live profile - but the renames the previous run applied have to
	// be undone first, or clearing the filter would leave every member pointing
	// at a name that no longer exists.
	undo := inverseRename(base.Renamed)
	profile := a.Profile()
	profile.Nodes = kept
	profile.Groups = rebindGroups(profile.Groups, undo, rename)
	profile.Rules = rebindRules(profile.Rules, undo, rename)
	profile.Final = retarget(profile.Final, undo, rename)
	profile.Groups = mergeGroups(profile.Groups, profile.Nodes)
	if !groupExists(profile.Groups, profile.Final) {
		profile.Final = ""
		if len(profile.Groups) > 0 {
			profile.Final = profile.Groups[0].Name
		}
	}
	if err := profile.Validate(); err != nil {
		return NodeFilterResult{}, fmt.Errorf("过滤结果不可用：%w", err)
	}
	if err := a.saveNodeBase(base.Nodes, rename); err != nil {
		a.log.Warnf("保存节点基线失败：%v", err)
	}
	cfg := a.Config()
	cfg.NodeFilter = f
	cfg.Core.Profile = &profile
	if err := a.Reload(cfg); err != nil {
		return NodeFilterResult{}, err
	}
	if err := a.restartRunningCore(ctx, profile); err != nil {
		return NodeFilterResult{Kept: len(kept), Dropped: dropped, Renamed: len(rename)}, err
	}
	names := make([]string, 0, len(kept))
	for _, n := range kept {
		names = append(names, n.Name)
	}
	return NodeFilterResult{Kept: len(kept), Dropped: dropped, Renamed: len(rename), Names: names}, nil
}
