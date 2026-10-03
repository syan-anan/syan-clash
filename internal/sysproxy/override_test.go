package sysproxy

import "testing"

// The bypass list is the one part of the system proxy the user can break by
// typing: an empty ProxyOverride is not "bypass nothing", it is "no bypass list
// at all", so the fallback has to be exact.
func TestBypassOrDefault(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", DefaultBypass},
		{"   ", DefaultBypass},
		{"\t", DefaultBypass},
		{"<local>", "<local>"},
		{"<local>;*.corp.example.com", "<local>;*.corp.example.com"},
		{" 10.0.0.0/8 ", "10.0.0.0/8"},
	}
	for _, c := range cases {
		if got := BypassOrDefault(c.in); got != c.want {
			t.Errorf("BypassOrDefault(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A configuration that never named a bypass list must keep writing exactly the
// value older builds hard-coded, otherwise "unchanged install" stops being
// true the moment this feature ships.
func TestDefaultBypassIsTheHistoricalValue(t *testing.T) {
	if DefaultBypass != "<local>" {
		t.Fatalf("DefaultBypass = %q, want %q", DefaultBypass, "<local>")
	}
}
