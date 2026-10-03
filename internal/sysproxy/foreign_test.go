package sysproxy

import "testing"

// foreignEntry is what decides whether the client is allowed to take the system
// proxy without asking. Getting it wrong in either direction is expensive: a
// false positive nags the user about a proxy that is already ours, a false
// negative silently cuts off whatever program had the setting.
func TestForeignEntry(t *testing.T) {
	cases := []struct {
		name    string
		server  string
		own     []string
		want    string
		foreign bool
	}{
		{
			name:   "our own http and socks entry",
			server: "http=127.0.0.1:2890;https=127.0.0.1:2890;socks=127.0.0.1:2891",
			own:    []string{"127.0.0.1:2890", "127.0.0.1:2891"},
		},
		{
			name:    "another local client on 6468",
			server:  "http=127.0.0.1:6468",
			own:     []string{"127.0.0.1:2890", "127.0.0.1:2891"},
			want:    "http=127.0.0.1:6468",
			foreign: true,
		},
		{
			name:    "a corporate proxy is not ours either",
			server:  "http=proxy.corp.example:8080",
			own:     []string{"127.0.0.1:2890"},
			want:    "http=proxy.corp.example:8080",
			foreign: true,
		},
		{
			name:    "one of ours plus one of theirs",
			server:  "http=127.0.0.1:2890;socks=127.0.0.1:6468",
			own:     []string{"127.0.0.1:2890"},
			want:    "socks=127.0.0.1:6468",
			foreign: true,
		},
		{
			name:   "a bare address with no scheme key still counts as ours",
			server: "127.0.0.1:2890",
			own:    []string{"127.0.0.1:2890"},
		},
		{
			name:   "empty entries are skipped",
			server: ";  ;http=127.0.0.1:2890;",
			own:    []string{"127.0.0.1:2890"},
		},
		{
			name:    "an empty proxy string is never foreign",
			server:  "",
			own:     []string{"127.0.0.1:2890"},
			foreign: false,
		},
		{
			name:   "whitespace around our address does not make it foreign",
			server: " http = 127.0.0.1:2890 ",
			own:    []string{"127.0.0.1:2890"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, foreign := foreignEntry(tc.server, tc.own...)
			if foreign != tc.foreign {
				t.Fatalf("foreign = %v, want %v (entry %q)", foreign, tc.foreign, got)
			}
			if got != tc.want {
				t.Fatalf("entry = %q, want %q", got, tc.want)
			}
		})
	}
}

// ourAddrsFrom / oursOnly decide how the client gives the setting back when it
// is switched off. Getting oursOnly wrong turns "switch my proxy off" into
// "switch the other program's proxy off", which is the exact damage the
// takeover prompt promised not to do.
func TestOurAddrsFrom(t *testing.T) {
	got := ourAddrsFrom("http=127.0.0.1:2890;https=127.0.0.1:2890;socks=127.0.0.1:2891")
	want := []string{"127.0.0.1:2890", "127.0.0.1:2890", "127.0.0.1:2891"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if n := len(ourAddrsFrom("")); n != 0 {
		t.Fatalf("empty string yielded %d addresses", n)
	}
}

func TestOursOnly(t *testing.T) {
	ours := ourAddrsFrom("http=127.0.0.1:2890;https=127.0.0.1:2890;socks=127.0.0.1:2891")
	cases := []struct {
		name      string
		published string
		want      bool
	}{
		{"the published string we wrote ourselves", "http=127.0.0.1:2890;https=127.0.0.1:2890;socks=127.0.0.1:2891", true},
		{"an empty snapshot means the machine had no proxy", "", true},
		{"another program on 6468 is not ours", "http=127.0.0.1:6468", false},
		{"a corporate proxy is not ours", "http=proxy.corp.example:8080", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := oursOnly(tc.published, ours...); got != tc.want {
				t.Fatalf("oursOnly(%q) = %v, want %v", tc.published, got, tc.want)
			}
		})
	}
}
