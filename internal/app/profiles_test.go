package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vvpn/internal/core"
)

func TestValidProfileName(t *testing.T) {
	for _, bad := range []string{"", "   ", "_system", ".hidden", "a/b", "a\\b", "a:b", strings.Repeat("x", maxProfileName+1)} {
		if _, err := validProfileName(bad); err == nil {
			t.Fatalf("name %q was accepted", bad)
		}
	}
	got, err := validProfileName("  日常  ")
	if err != nil || got != "日常" {
		t.Fatalf("validProfileName(日常) = %q, %v", got, err)
	}
}

func TestProfilesLifecycle(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	if err := a.SaveProfile("日常"); err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}
	list, err := a.ListProfiles()
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("profiles = %+v, want one", list)
	}
	if list[0].Name != "日常" || !list[0].Active || list[0].Nodes != 3 {
		t.Fatalf("profile entry = %+v", list[0])
	}

	// Change the running configuration, then switch back.
	profile := a.Profile()
	profile.Nodes = profile.Nodes[:1]
	profile.Groups = []core.Group{{Name: "PROXY", Type: core.GroupSelect, Members: []string{profile.Nodes[0].Name}}}
	profile.Final = "PROXY"
	if err := a.SetProfile(ctx, profile); err != nil {
		t.Fatalf("SetProfile: %v", err)
	}
	if got := len(a.Profile().Nodes); got != 1 {
		t.Fatalf("nodes after edit = %d, want 1", got)
	}
	if err := a.LoadProfile(ctx, "日常"); err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	if got := len(a.Profile().Nodes); got != 3 {
		t.Fatalf("nodes after load = %d, want 3", got)
	}
	lastUsed := filepath.Join(a.profilesDir(), lastUsedProfile+".json")
	if _, err := os.Stat(lastUsed); err != nil {
		t.Fatalf("the pre-switch configuration was not kept as _last-used: %v", err)
	}
	if _, ok, err := a.loadNodeBase(); err != nil || !ok {
		t.Fatalf("node baseline did not follow the profile (ok=%v err=%v)", ok, err)
	}

	if err := a.RenameProfile("日常", "回家"); err != nil {
		t.Fatalf("RenameProfile: %v", err)
	}
	list, _ = a.ListProfiles()
	if len(list) != 1 || list[0].Name != "回家" || !list[0].Active {
		t.Fatalf("after rename: %+v", list)
	}
	if err := a.DeleteProfile("回家"); err != nil {
		t.Fatalf("DeleteProfile: %v", err)
	}
	if list, _ = a.ListProfiles(); len(list) != 0 {
		t.Fatalf("after delete: %+v", list)
	}
	if err := a.LoadProfile(ctx, "并不存在"); err == nil {
		t.Fatal("loading a missing profile succeeded")
	}
}
