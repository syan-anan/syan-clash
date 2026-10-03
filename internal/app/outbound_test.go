package app

import (
	"testing"

	"vvpn/internal/clashapi"
)

func proxyTable(entries ...clashapi.Proxy) map[string]clashapi.Proxy {
	table := make(map[string]clashapi.Proxy, len(entries))
	for _, p := range entries {
		table[p.Name] = p
	}
	return table
}

func selector(name, now string, all ...string) clashapi.Proxy {
	return clashapi.Proxy{Name: name, Type: "Selector", Now: now, All: all}
}

func urlTest(name, now string, all ...string) clashapi.Proxy {
	return clashapi.Proxy{Name: name, Type: "URLTest", Now: now, All: all}
}

func node(name string) clashapi.Proxy {
	return clashapi.Proxy{Name: name, Type: "Trojan"}
}

// airportTable mirrors the shape that produced the bug: a selector that points
// at the airport's url-test group, a GLOBAL selector that came back from
// cache.db as DIRECT, a fallback group parked on an information row, and the
// information rows themselves sitting in the list as if they were servers.
func airportTable() map[string]clashapi.Proxy {
	const (
		main     = "示例机场"
		auto     = "自动选择"
		fallback = "故障转移"
		fast     = "🇹🇼台湾🚀家宽AI奈飞"
		us       = "🇺🇸美国🚀1pro"
		info     = "剩余流量：294.93 GB"
	)
	return proxyTable(
		clashapi.Proxy{Name: "DIRECT", Type: "Direct"},
		clashapi.Proxy{Name: "REJECT", Type: "Reject"},
		clashapi.Proxy{Name: "GLOBAL", Type: "Selector", Now: "DIRECT", All: []string{"DIRECT", "REJECT", info, auto, main, fallback, fast, us}},
		selector(main, auto, info, auto, fallback, fast, us),
		urlTest(auto, fast, info, fast, us),
		clashapi.Proxy{Name: fallback, Type: "Fallback", Now: info, All: []string{info, fast, us}},
		node(fast),
		node(us),
		clashapi.Proxy{Name: info, Type: "Trojan"},
	)
}

func TestResolveNodeNameFollowsTheSelectionChain(t *testing.T) {
	table := airportTable()
	cases := []struct {
		name  string
		start string
		want  string
	}{
		{"fallback group -> url-test group -> node", "示例机场", "🇹🇼台湾🚀家宽AI奈飞"},
		{"a direct selection is not a node", "GLOBAL", ""},
		{"a missing start resolves to nothing", "不存在的分组", ""},
		{"a bare node is itself", "🇺🇸美国🚀1pro", "🇺🇸美国🚀1pro"},
		{"an information row is not a node", "剩余流量：294.93 GB", ""},
	}
	for _, tc := range cases {
		if got := resolveNodeName(tc.start, table); got != tc.want {
			t.Errorf("%s: resolveNodeName(%q) = %q, want %q", tc.name, tc.start, got, tc.want)
		}
	}
}

func TestResolveNodeNameSurvivesACycle(t *testing.T) {
	table := proxyTable(
		selector("A", "B", "B"),
		selector("B", "A", "A"),
	)
	if got := resolveNodeName("A", table); got != "" {
		t.Fatalf("a cycle resolved to %q, want empty", got)
	}
}

// TestRepairTargetsOnlyTouchesUndialableSelections is the regression for the
// GLOBAL -> DIRECT selection mihomo restores from cache.db.
func TestRepairTargetsOnlyTouchesUndialableSelections(t *testing.T) {
	got := repairTargets(airportTable())
	if len(got) != 2 {
		t.Fatalf("repairs = %+v, want exactly two (GLOBAL and the fallback group)", got)
	}
	if got[0].Group != "GLOBAL" || got[0].Pick != "自动选择" {
		t.Errorf("first repair = %+v, want GLOBAL -> 自动选择 (a group beats a bare node)", got[0])
	}
	if got[1].Group != "故障转移" || got[1].Pick != "🇹🇼台湾🚀家宽AI奈飞" {
		t.Errorf("second repair = %+v, want the fallback group off the information row", got[1])
	}
}

func TestRepairTargetsLeavesARealSelectionAlone(t *testing.T) {
	table := proxyTable(
		selector("示例机场", "🇺🇸美国🚀1pro", "🇺🇸美国🚀1pro", "剩余流量：1 GB"),
		node("🇺🇸美国🚀1pro"),
		clashapi.Proxy{Name: "剩余流量：1 GB", Type: "Trojan"},
	)
	if got := repairTargets(table); len(got) != 0 {
		t.Fatalf("a group the user already pointed at a node was rewritten: %+v", got)
	}
}

func TestRepairTargetsSkipsGroupsWithNothingToPick(t *testing.T) {
	table := proxyTable(
		clashapi.Proxy{Name: "DIRECT", Type: "Direct"},
		clashapi.Proxy{Name: "REJECT", Type: "Reject"},
		selector("GLOBAL", "DIRECT", "DIRECT", "REJECT"),
	)
	if got := repairTargets(table); len(got) != 0 {
		t.Fatalf("repairs = %+v, want none: there is no node to point at", got)
	}
}

func TestRealMemberRejectsBuiltinsAndInformationRows(t *testing.T) {
	table := airportTable()
	if realMember("DIRECT", table) {
		t.Error("DIRECT counted as a dialable member")
	}
	if realMember("REJECT", table) {
		t.Error("REJECT counted as a dialable member")
	}
	if realMember("剩余流量：294.93 GB", table) {
		t.Error("an airport information row counted as a dialable member")
	}
	if realMember("GLOBAL", table) {
		t.Error("a group counted as a dialable member")
	}
	if !realMember("🇺🇸美国🚀1pro", table) {
		t.Error("a real node was rejected")
	}
}

// TestRepairThenResolveNamesTheNode is the ordering the watcher depends on: the
// repair has to land on the same snapshot the name is resolved from, otherwise a
// repaired chain still reads as "not a node" and the console keeps answering
// "core:mihomo" while traffic is already leaving through a server.
func TestRepairThenResolveNamesTheNode(t *testing.T) {
	table := airportTable()
	if got := resolveNodeName("GLOBAL", table); got != "" {
		t.Fatalf("the poisoned table already resolved to %q, the fixture is wrong", got)
	}
	for _, r := range repairTargets(table) {
		p := table[r.Group]
		p.Now = r.Pick
		table[r.Group] = p
	}
	if got := resolveNodeName("GLOBAL", table); got != "🇹🇼台湾🚀家宽AI奈飞" {
		t.Fatalf("after repair GLOBAL resolved to %q, want the url-test winner", got)
	}
}
