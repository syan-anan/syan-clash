package control

import "testing"

// The update source is a free-text field a user types into, so the classifier
// is the part that decides whether anything is fetched at all. These cases are
// the shapes people actually paste.
func TestClassifyUpdateSource(t *testing.T) {
	cases := []struct {
		in   string
		kind string
		arg  string
	}{
		{"", "", ""},
		{"   ", "", ""},
		{"owner/repo", "github", "owner/repo"},
		{"owner/repo/", "github", "owner/repo"},
		{"https://github.com/owner/repo", "github", "owner/repo"},
		{"https://github.com/owner/repo/", "github", "owner/repo"},
		{"https://github.com/owner/repo.git", "github", "owner/repo"},
		{"https://example.com/syan-clash/update.json", "manifest", "https://example.com/syan-clash/update.json"},
		{"http://127.0.0.1:8080/update.json", "manifest", "http://127.0.0.1:8080/update.json"},
		{"ftp://example.com/x.json", "invalid", "ftp://example.com/x.json"},
		{"just-a-word", "invalid", "just-a-word"},
		{"too/many/parts", "invalid", "too/many/parts"},
	}
	for _, c := range cases {
		kind, arg := classifyUpdateSource(c.in)
		if kind != c.kind || arg != c.arg {
			t.Errorf("classifyUpdateSource(%q) = (%q, %q), want (%q, %q)", c.in, kind, arg, c.kind, c.arg)
		}
	}
}

// The asset picker must never hand the user a Linux tarball or a CPU-level
// build when a plain Windows exe is in the same release.
func TestPickWindowsAsset(t *testing.T) {
	assets := []githubAsset{
		{Name: "syan-clash-0.2.0-linux-amd64.tar.gz", BrowserDownloadURL: "linux"},
		{Name: "syan-clash-windows-amd64-v3-0.2.0.exe", BrowserDownloadURL: "v3"},
		{Name: "syan-clash-windows-amd64-0.2.0.exe", BrowserDownloadURL: "plain-win"},
		{Name: "syan-clash-0.2.0.exe", BrowserDownloadURL: "plain"},
	}
	if got := pickWindowsAsset(assets); got != "plain" {
		t.Errorf("pickWindowsAsset = %q, want %q", got, "plain")
	}
	if got := pickWindowsAsset(nil); got != "" {
		t.Errorf("pickWindowsAsset(nil) = %q, want empty", got)
	}
	onlyLinux := []githubAsset{{Name: "syan-clash-linux.tar.gz", BrowserDownloadURL: "linux"}}
	if got := pickWindowsAsset(onlyLinux); got != "" {
		t.Errorf("pickWindowsAsset(linux only) = %q, want empty", got)
	}
	winOnly := []githubAsset{
		{Name: "other-windows.exe", BrowserDownloadURL: "other"},
		{Name: "syan-clash-windows.exe", BrowserDownloadURL: "ours"},
	}
	if got := pickWindowsAsset(winOnly); got != "ours" {
		t.Errorf("pickWindowsAsset = %q, want %q", got, "ours")
	}
}

// A changelog pasted into a release body is multi-line; the notice is one line.
func TestFirstLine(t *testing.T) {
	if got := firstLine("first line\nsecond line"); got != "first line" {
		t.Errorf("firstLine = %q", got)
	}
	if got := firstLine("  \r\n  "); got != "" {
		t.Errorf("firstLine(blank) = %q", got)
	}
	if got := firstLine("only"); got != "only" {
		t.Errorf("firstLine(only) = %q", got)
	}
}
