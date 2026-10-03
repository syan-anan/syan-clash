package app

import (
	"context"
	"testing"

	"vvpn/internal/core"
)

func TestGroupViewsAndEdit(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	views := a.GroupViews()
	if len(views) != 1 || views[0].Name != "PROXY" || !views[0].Builtin {
		t.Fatalf("initial groups = %+v", views)
	}
	if err := a.AddGroup(ctx, GroupEdit{Name: "流媒体", Type: core.GroupURLTest}); err != nil {
		t.Fatalf("AddGroup: %v", err)
	}
	views = a.GroupViews()
	if len(views) != 2 {
		t.Fatalf("groups after add = %d, want 2", len(views))
	}
	target := views[1]
	if target.Name != "流媒体" || target.Type != core.GroupURLTest {
		t.Fatalf("added group = %+v", target)
	}
	if target.TestURL == "" {
		t.Fatalf("url-test group got no default test url: %+v", target)
	}
	if len(target.Members) != 3 {
		t.Fatalf("added group members = %v, want every node", target.Members)
	}

	if err := a.SetGroup(ctx, 1, GroupEdit{Members: []string{"并不存在的节点"}}); err == nil {
		t.Fatal("a member that is not a node was accepted")
	}
	if err := a.SetGroup(ctx, 1, GroupEdit{Members: []string{"香港 01", "美国 01"}}); err != nil {
		t.Fatalf("SetGroup: %v", err)
	}
	if got := a.GroupViews()[1].Members; len(got) != 2 || got[1] != "美国 01" {
		t.Fatalf("members = %v, want [香港 01 美国 01]", got)
	}
	// DIRECT is not a node: the profile refuses it, so the API has to refuse it
	// first with a message that says what to do instead.
	if err := a.SetGroup(ctx, 1, GroupEdit{Members: []string{"DIRECT"}}); err == nil {
		t.Fatal("DIRECT was accepted as a group member")
	}

	// The fallback and the rules follow a group rename: otherwise a rename
	// would leave the profile pointing at a group that no longer exists.
	profile := a.Profile()
	profile.Final = "流媒体"
	if err := a.SetProfile(ctx, profile); err != nil {
		t.Fatalf("SetProfile: %v", err)
	}
	if err := a.SetGroup(ctx, 1, GroupEdit{Name: "流媒体2"}); err != nil {
		t.Fatalf("rename group: %v", err)
	}
	if got := a.Profile().Final; got != "流媒体2" {
		t.Fatalf("final = %q, want 流媒体2", got)
	}

	if err := a.RemoveGroup(ctx, "PROXY"); err != nil {
		t.Fatalf("RemoveGroup: %v", err)
	}
	if err := a.RemoveGroup(ctx, "流媒体2"); err == nil {
		t.Fatal("the last group was deleted; the core would have no outbound")
	}
}

func TestAddGroupValidation(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	if err := a.AddGroup(ctx, GroupEdit{Name: "PROXY"}); err == nil {
		t.Fatal("a generated group name was accepted")
	}
	if err := a.AddGroup(ctx, GroupEdit{Name: "x", Type: "turbo"}); err == nil {
		t.Fatal("an unknown group type was accepted")
	}
	if err := a.AddGroup(ctx, GroupEdit{}); err == nil {
		t.Fatal("an empty group name was accepted")
	}
	if err := a.SetGroup(ctx, 9, GroupEdit{}); err == nil {
		t.Fatal("an out-of-range index was accepted")
	}
}
