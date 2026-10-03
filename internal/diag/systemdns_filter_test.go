package diag

import "testing"

func TestMergeResolversSplitsAndDedupes(t *testing.T) {
	got := mergeResolvers([]string{"8.8.8.8, 8.8.4.4"}, []ifaceResolvers{
		{GUID: "{aaa}", Values: []string{"202.207.48.23 202.207.48.24", "8.8.8.8"}},
	}, nil)
	want := []string{"8.8.8.8", "8.8.4.4", "202.207.48.23", "202.207.48.24"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestMergeResolversDropsAdaptersThatAreNotConnected(t *testing.T) {
	up := map[string]bool{"AAA": true}
	got := mergeResolvers(nil, []ifaceResolvers{
		{GUID: "{aaa}", Values: []string{"10.0.0.1"}},
		{GUID: "{bbb}", Values: []string{"192.168.47.120"}},
	}, up)
	if len(got) != 1 || got[0] != "10.0.0.1" {
		t.Fatalf("a disconnected adapter's resolver survived: %v", got)
	}
}

func TestMergeResolversShowsEverythingWhenStateIsUnknown(t *testing.T) {
	got := mergeResolvers(nil, []ifaceResolvers{
		{GUID: "{aaa}", Values: []string{"10.0.0.1"}},
		{GUID: "{bbb}", Values: []string{"192.168.47.120"}},
	}, nil)
	if len(got) != 2 {
		t.Fatalf("an unreadable adapter state must not hide resolvers: %v", got)
	}
}

func TestNormalizeGUIDIgnoresBracesAndCase(t *testing.T) {
	if normalizeGUID(" {AaBb} ") != "AABB" {
		t.Fatalf("normalizeGUID = %q", normalizeGUID(" {AaBb} "))
	}
}
