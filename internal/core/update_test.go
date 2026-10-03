package core

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.14.2", "1.14.2", 0},
		{"v1.14.2", "1.14.2", 0},
		{"1.14.3", "1.14.2", 1},
		{"1.15.0", "1.14.9", 1},
		{"1.9.0", "1.10.0", -1},
		{"26.3.27", "26.2.0", 1},
		{"1.19.31", "1.19.4", 1},
		{"2.0.0-beta.1", "1.9.9", 1},
		{"1.0.0", "1.0", 0},
		{"1.0.1", "1.0", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestGitHubRepo(t *testing.T) {
	cases := map[string]string{
		"https://github.com/SagerNet/sing-box": "SagerNet/sing-box",
		"https://github.com/MetaCubeX/mihomo/": "MetaCubeX/mihomo",
		"https://github.com/XTLS/Xray-core":    "XTLS/Xray-core",
	}
	for in, want := range cases {
		if got := githubRepo(in); got != want {
			t.Errorf("githubRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDownloadCandidatesOrder(t *testing.T) {
	canonical := "https://github.com/owner/repo/releases/download/v1/x.zip"

	// Without a user mirror the canonical URL comes first.
	got := DownloadCandidates(canonical, "")
	if got[0] != canonical {
		t.Errorf("first candidate = %q, want the canonical URL", got[0])
	}
	if len(got) != 1+len(DefaultMirrors) {
		t.Errorf("candidates = %d, want %d", len(got), 1+len(DefaultMirrors))
	}

	// With a user mirror it is tried first, and a missing trailing slash is
	// handled.
	got = DownloadCandidates(canonical, "https://my-mirror.example")
	want := "https://my-mirror.example/" + canonical
	if got[0] != want {
		t.Errorf("first candidate = %q, want %q", got[0], want)
	}
	if got[1] != canonical {
		t.Errorf("second candidate = %q, want the canonical URL", got[1])
	}
}

func TestJoinMirror(t *testing.T) {
	target := "https://github.com/a/b"
	if got := JoinMirror("", target); got != target {
		t.Errorf("JoinMirror(empty) = %q", got)
	}
	if got := JoinMirror("https://m/", target); got != "https://m/"+target {
		t.Errorf("JoinMirror = %q", got)
	}
	if got := JoinMirror("  https://m  ", target); got != "https://m/"+target {
		t.Errorf("JoinMirror should trim and add a slash, got %q", got)
	}
}

func TestCatalogHasEmittersForEveryEntry(t *testing.T) {
	for _, spec := range CatalogEntries() {
		if spec.Emitter == "" {
			t.Errorf("core %s has no emitter", spec.ID)
		}
		if spec.DownloadURL == "" {
			t.Errorf("core %s has no pinned download URL", spec.ID)
		}
		if _, ok := assetMatchers[spec.ID]; !ok {
			t.Errorf("core %s has no asset matcher, in-app update would not know which file to fetch", spec.ID)
		}
	}
}
