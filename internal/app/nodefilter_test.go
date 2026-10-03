package app

import (
	"context"
	"strings"
	"testing"

	"vvpn/internal/config"
	"vvpn/internal/core"
)

func TestApplyNodeFilterPure(t *testing.T) {
	nodes := []core.Node{
		{Name: "剩余流量：294.93 GB"},
		{Name: "距离下次重置剩余：29 天"},
		{Name: "香港 01"},
		{Name: "香港 02 - IEPL"},
		{Name: "美国 01"},
		{Name: "官网 https://example.com"},
	}
	// CleanInfo is left unset on purpose: cleaning is the default.
	f := config.NodeFilter{
		Exclude: []string{"iepl"},
		Prefix:  "S-",
		Rename:  []config.RenameRule{{From: "香港", To: "HK"}},
	}
	kept, rename, dropped := applyNodeFilter(nodes, f)
	// three information cards plus the excluded IEPL node
	if dropped != 4 {
		t.Fatalf("dropped = %d, want 4", dropped)
	}
	got := make([]string, 0, len(kept))
	for _, n := range kept {
		got = append(got, n.Name)
	}
	want := []string{"S-HK 01", "S-美国 01"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("names = %v, want %v", got, want)
	}
	if rename["香港 01"] != "S-HK 01" {
		t.Fatalf("rename map = %v, want 香港 01 -> S-HK 01", rename)
	}
}

// The eight rows the subscription this client was built against actually
// ships. They are the reason cleaning is on by default: seven of them are not
// servers at all, and the eighth is a note telling the user to change client.
func TestInfoNodeMarkersCoverTheRealSubscription(t *testing.T) {
	want := []string{
		"剩余流量：294.93 GB",
		"距离下次重置剩余：22 天",
		"套餐到期：2027-03-22",
		"若无HY节点-更换客户端即可",
		"安卓-clashmeta客户端",
		"电脑-clashverge客户端",
		"ios-小火箭Shadowrocket客户端",
		"ipv6免流-请自行修改host",
	}
	for _, name := range want {
		if !isInfoNode(name) {
			t.Errorf("isInfoNode(%q) = false, want true", name)
		}
	}
	// Real nodes must survive. The last two are the near misses: "免流" alone is
	// deliberately not a marker (airports sell real 免流 nodes), and a name that
	// merely mentions a client is not a placeholder row.
	keep := []string{
		"🇺🇸美国🚀1pro", "🇺🇸美国🚀神速HY02-推荐", "🇯🇵日本东京🚀1", "香港 01 - IEPL",
		"🇸🇬新加坡IPv6免流01", "🇭🇰香港Clash专线", "🇭🇰香港V2Ray专线",
	}
	for _, name := range keep {
		if isInfoNode(name) {
			t.Errorf("isInfoNode(%q) = true, want false", name)
		}
	}
}

// Cleaning must be the default: an all-zero filter (what every config on disk
// looks like today) has to drop the information rows, and IsZero has to agree,
// or the import path would skip the filter entirely.
func TestCleanInfoDefaultsOn(t *testing.T) {
	var f config.NodeFilter
	if !f.CleanInfoEnabled() {
		t.Fatal("an unset CleanInfo must mean on")
	}
	if f.IsZero() {
		t.Fatal("a default filter is not a no-op: it cleans the information rows")
	}
	nodes := []core.Node{
		{Name: "剩余流量：294.93 GB"},
		{Name: "安卓-clashmeta客户端"},
		{Name: "香港 01"},
	}
	kept, _, dropped := applyNodeFilter(nodes, f)
	if dropped != 2 || len(kept) != 1 || kept[0].Name != "香港 01" {
		t.Fatalf("default filter kept=%d dropped=%d, want 1/2", len(kept), dropped)
	}
}

func TestCleanInfoCanBeTurnedOff(t *testing.T) {
	off := false
	f := config.NodeFilter{CleanInfo: &off}
	if f.CleanInfoEnabled() {
		t.Fatal("an explicit false must mean off")
	}
	if !f.IsZero() {
		t.Fatal("an explicit off with nothing else set is a no-op")
	}
	nodes := []core.Node{{Name: "剩余流量：294.93 GB"}, {Name: "香港 01"}}
	kept, _, dropped := applyNodeFilter(nodes, f)
	if dropped != 0 || len(kept) != 2 {
		t.Fatalf("opting out kept=%d dropped=%d, want 2/0", len(kept), dropped)
	}
}

// A profile imported by an older build still carries the information rows. The
// startup heal has to drop them, walk the groups along, and then be a no-op on
// the next start.
func TestHealInfoNodes(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	cfg := a.Config()
	profile := a.Profile()
	profile.Nodes = append(profile.Nodes,
		core.Node{Name: "剩余流量：294.93 GB", Type: core.TypeSocks5, Server: "127.0.0.1", Port: 1090},
		core.Node{Name: "安卓-clashmeta客户端", Type: core.TypeSocks5, Server: "127.0.0.1", Port: 1091},
	)
	profile.Groups = mergeGroups(profile.Groups, profile.Nodes)
	cfg.Core.Profile = &profile
	if err := a.Reload(cfg); err != nil {
		t.Fatalf("reload with the dirty list: %v", err)
	}
	if !a.HealInfoNodes(ctx) {
		t.Fatal("heal reported nothing to do on a dirty list")
	}
	for _, n := range a.Profile().Nodes {
		if isInfoNode(n.Name) {
			t.Fatalf("an information row survived the heal: %q", n.Name)
		}
	}
	if len(a.Profile().Nodes) != 3 {
		t.Fatalf("nodes = %d, want the 3 real ones", len(a.Profile().Nodes))
	}
	for _, g := range a.Profile().Groups {
		for _, m := range g.Members {
			if isInfoNode(m) {
				t.Fatalf("group %q still lists the information row %q", g.Name, m)
			}
		}
	}
	if err := a.Profile().Validate(); err != nil {
		t.Fatalf("profile invalid after the heal: %v", err)
	}
	if a.HealInfoNodes(ctx) {
		t.Fatal("a clean list must make the heal a no-op")
	}
}

// Opting out through the public path must keep the rows, and the stored filter
// must round-trip the pointer.
func TestApplyNodeFilterKeepsInfoWhenTurnedOff(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	cfg := a.Config()
	profile := a.Profile()
	profile.Nodes = append(profile.Nodes,
		core.Node{Name: "套餐到期：2027-03-22", Type: core.TypeSocks5, Server: "127.0.0.1", Port: 1092},
	)
	profile.Groups = mergeGroups(profile.Groups, profile.Nodes)
	cfg.Core.Profile = &profile
	if err := a.Reload(cfg); err != nil {
		t.Fatalf("reload: %v", err)
	}
	off := false
	res, err := a.ApplyNodeFilter(ctx, config.NodeFilter{CleanInfo: &off})
	if err != nil {
		t.Fatalf("apply with cleaning off: %v", err)
	}
	if res.Dropped != 0 || res.Kept != 4 {
		t.Fatalf("kept=%d dropped=%d, want 4/0", res.Kept, res.Dropped)
	}
	if got := a.NodeFilter(); got.CleanInfoEnabled() {
		t.Fatalf("the opt-out did not persist: %+v", got)
	}
	if a.HealInfoNodes(ctx) {
		t.Fatal("the heal must not run while cleaning is switched off")
	}
}

func TestApplyNodeFilterDedupesRenames(t *testing.T) {
	nodes := []core.Node{{Name: "香港 01"}, {Name: "香港 01 备用"}, {Name: "美国 01"}}
	f := config.NodeFilter{
		Include: []string{"香港"},
		Rename: []config.RenameRule{
			{From: " 备用", To: ""},
			{From: "香港 01", To: "同一台"},
		},
	}
	kept, _, dropped := applyNodeFilter(nodes, f)
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	if len(kept) != 2 {
		t.Fatalf("kept = %d, want 2", len(kept))
	}
	if kept[0].Name != "同一台" || kept[1].Name != "同一台 2" {
		t.Fatalf("names = %q / %q, want 同一台 / 同一台 2", kept[0].Name, kept[1].Name)
	}
}

func TestApplyRenameBadRegexIsIgnored(t *testing.T) {
	if got := applyRename("a(b", config.RenameRule{From: "a(", To: "x", Regex: true}); got != "a(b" {
		t.Fatalf("bad regex changed the name to %q, want it untouched", got)
	}
	if got := applyRename("香港 01", config.RenameRule{From: "(\\d+)", To: "#$1", Regex: true}); got != "香港 #01" {
		t.Fatalf("regex rename = %q, want 香港 #01", got)
	}
}

func TestApplyNodeFilterIsIdempotent(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	f := config.NodeFilter{Prefix: "P-", Exclude: []string{"IEPL"}}

	first, err := a.ApplyNodeFilter(ctx, f)
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if first.Kept != 2 || first.Dropped != 1 {
		t.Fatalf("first apply kept=%d dropped=%d, want 2/1", first.Kept, first.Dropped)
	}
	second, err := a.ApplyNodeFilter(ctx, f)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if second.Kept != 2 || second.Dropped != 1 {
		t.Fatalf("second apply kept=%d dropped=%d, want 2/1", second.Kept, second.Dropped)
	}
	for _, n := range a.Profile().Nodes {
		if strings.Count(n.Name, "P-") != 1 {
			t.Fatalf("node %q was renamed twice", n.Name)
		}
	}
	if err := a.Profile().Validate(); err != nil {
		t.Fatalf("profile invalid after filtering: %v", err)
	}
	if _, ok, err := a.loadNodeBase(); err != nil || !ok {
		t.Fatalf("pre-filter baseline missing (ok=%v err=%v)", ok, err)
	}
	if got := a.NodeFilter(); got.Prefix != "P-" || len(got.Exclude) != 1 {
		t.Fatalf("filter was not stored: %+v", got)
	}
}

// Clearing the filter has to put the original node names back *and* walk the
// groups back with them. The first cut of this code only rebound names for the
// renames of the current run, so clearing the filter left every group member
// pointing at a node that no longer existed and the profile stopped loading.
func TestApplyNodeFilterClearsBackToBaseline(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	if _, err := a.ApplyNodeFilter(ctx, config.NodeFilter{Prefix: "E2E-"}); err != nil {
		t.Fatalf("apply prefix: %v", err)
	}
	renamed := a.Profile().Groups[0].Members
	for _, m := range renamed {
		if !strings.HasPrefix(m, "E2E-") {
			t.Fatalf("member %q was not renamed with the nodes: %v", m, renamed)
		}
	}

	back, err := a.ApplyNodeFilter(ctx, config.NodeFilter{})
	if err != nil {
		t.Fatalf("clear filter: %v", err)
	}
	if back.Kept != 3 || back.Dropped != 0 || back.Renamed != 0 {
		t.Fatalf("clearing kept=%d dropped=%d renamed=%d, want 3/0/0", back.Kept, back.Dropped, back.Renamed)
	}
	names := map[string]bool{}
	for _, n := range a.Profile().Nodes {
		names[n.Name] = true
	}
	if !names["香港 01"] || !names["美国 01"] {
		t.Fatalf("the original node names did not come back: %v", names)
	}
	for _, m := range a.Profile().Groups[0].Members {
		if !names[m] {
			t.Fatalf("group member %q matches no node after clearing: %v", m, a.Profile().Groups[0].Members)
		}
	}
	if err := a.Profile().Validate(); err != nil {
		t.Fatalf("profile invalid after clearing the filter: %v", err)
	}
	// The map must not survive the clear, or the next filter would undo
	// renames that are no longer there.
	if base, ok, err := a.loadNodeBase(); err != nil || !ok || len(base.Renamed) != 0 {
		t.Fatalf("baseline rename map should be empty after clearing (ok=%v err=%v map=%v)", ok, err, base.Renamed)
	}
}
