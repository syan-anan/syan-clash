package subscription

import (
	"testing"
	"time"
)

func TestParseUserInfoVariants(t *testing.T) {
	cases := []struct {
		header string
		want   Info
	}{
		{
			"upload=1024; download=2048; total=107374182400; expire=1893456000",
			Info{Upload: 1024, Download: 2048, Total: 107374182400, Expire: 1893456000},
		},
		{
			"upload=0,download=0,total=0,expire=0",
			Info{},
		},
		{
			" upload = 5 ; download = 10 ; total = 100 ; expire = 1893456000 ",
			Info{Upload: 5, Download: 10, Total: 100, Expire: 1893456000},
		},
		{
			"download=1; total=notanumber; expire=1893456000",
			Info{Download: 1, Expire: 1893456000},
		},
		{"", Info{}},
	}
	for _, c := range cases {
		if got := ParseUserInfo(c.header); got != c.want {
			t.Errorf("ParseUserInfo(%q) = %+v, want %+v", c.header, got, c.want)
		}
	}
}

func TestInfoDerivedValues(t *testing.T) {
	info := Info{Upload: 100, Download: 200, Total: 1000, Expire: 1893456000}
	if got := info.Used(); got != 300 {
		t.Errorf("Used() = %d, want 300", got)
	}
	if got := info.Remaining(); got != 700 {
		t.Errorf("Remaining() = %d, want 700", got)
	}
	if got := info.Remaining(); got < 0 {
		t.Error("Remaining() should be positive for a known quota")
	}

	unlimited := Info{Upload: 1, Download: 2, Total: 0}
	if got := unlimited.Remaining(); got != -1 {
		t.Errorf("Remaining() for unlimited = %d, want -1", got)
	}

	if got := info.ExpiresAt(); got.Year() != 2030 {
		t.Errorf("ExpiresAt() = %v (year %d), want 2030", got, got.Year())
	}
	empty := Info{}
	if got := empty.ExpiresAt(); !got.IsZero() {
		t.Errorf("ExpiresAt() for no expiry = %v, want the zero time", got)
	}

	// The expiry must be a real timestamp, not a rounded one.
	exp := time.Unix(1893456000, 0)
	if !info.ExpiresAt().Equal(exp) {
		t.Errorf("ExpiresAt() = %v, want %v", info.ExpiresAt(), exp)
	}
}

func TestParseUpdateInterval(t *testing.T) {
	if got := ParseUpdateInterval("24"); got != 24 {
		t.Errorf("ParseUpdateInterval(24) = %d", got)
	}
	if got := ParseUpdateInterval("0"); got != 0 {
		t.Errorf("ParseUpdateInterval(0) = %d, want 0", got)
	}
	if got := ParseUpdateInterval(""); got != 0 {
		t.Errorf("ParseUpdateInterval(empty) = %d, want 0", got)
	}
	if got := ParseUpdateInterval("-3"); got != 0 {
		t.Errorf("ParseUpdateInterval(-3) = %d, want 0", got)
	}
	if got := ParseUpdateInterval("abc"); got != 0 {
		t.Errorf("ParseUpdateInterval(abc) = %d, want 0", got)
	}
}

func TestFilenameFromDisposition(t *testing.T) {
	cases := map[string]string{
		`attachment; filename=mysub.yaml`:                                      "mysub",
		`attachment; filename="My Airport.yml"`:                                "My Airport",
		`inline; filename=plain.txt`:                                           "plain",
		`attachment; filename*=UTF-8''encoded.txt`:                             "encoded",
		`attachment; filename*=UTF-8''%E9%A6%99%E6%B8%AF`:                      "香港",
		`attachment; filename=plain.yaml; filename*=UTF-8''%E4%BC%98%E5%85%88`: "优先",
		"": "",
	}
	for in, want := range cases {
		if got := FilenameFromDisposition(in); got != want {
			t.Errorf("FilenameFromDisposition(%q) = %q, want %q", in, got, want)
		}
	}
}
