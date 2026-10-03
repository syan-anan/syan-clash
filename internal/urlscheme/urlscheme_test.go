package urlscheme

import (
	"errors"
	"strings"
	"testing"
)

// The links other clients emit, and what each one has to turn into.
func TestParseAcceptsTheLinksThisFamilyEmits(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want Action
	}{
		{
			name: "plain install-config",
			raw:  "clash://install-config?url=https%3A%2F%2Fdy11.example.com%2Fapi%2Fv1%2Fclient%2Fsubscribe%3Ftoken%3Dabc",
			want: Action{
				Kind: ActionInstallConfig,
				URL:  "https://dy11.example.com/api/v1/client/subscribe?token=abc",
			},
		},
		{
			name: "with a name",
			raw:  "clash://install-config?url=https://example.com/sub.yaml&name=%E7%A4%BA%E4%BE%8B%E6%9C%BA%E5%9C%BA",
			want: Action{Kind: ActionInstallConfig, URL: "https://example.com/sub.yaml", Name: "示例机场"},
		},
		{
			name: "trailing slash after the action",
			raw:  "clash://install-config/?url=http://127.0.0.1:8080/sub.yaml",
			want: Action{Kind: ActionInstallConfig, URL: "http://127.0.0.1:8080/sub.yaml"},
		},
		{
			name: "action in the path",
			raw:  "clash:///install-config?url=https://example.com/s",
			want: Action{Kind: ActionInstallConfig, URL: "https://example.com/s"},
		},
		{
			name: "surrounding whitespace is trimmed",
			raw:  "  clash://install-config?url=https://example.com/s\n",
			want: Action{Kind: ActionInstallConfig, URL: "https://example.com/s"},
		},
		{
			name: "the name is trimmed",
			raw:  "clash://install-config?url=https://example.com/s&name=%20%20abc%20",
			want: Action{Kind: ActionInstallConfig, URL: "https://example.com/s", Name: "abc"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse(c.raw)
			if err != nil {
				t.Fatalf("Parse(%q) failed: %v", c.raw, err)
			}
			if got.Kind != c.want.Kind || got.URL != c.want.URL || got.Name != c.want.Name {
				t.Errorf("Parse(%q) = %+v, want kind=%q url=%q name=%q",
					c.raw, got, c.want.Kind, c.want.URL, c.want.Name)
			}
			if got.Raw != strings.TrimSpace(c.raw) {
				t.Errorf("Raw = %q, want the link as received", got.Raw)
			}
		})
	}
}

// Everything that must be refused, and the reason the user will see.
func TestParseRefusesWhatItCannotActOn(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "", "空"},
		{"another scheme", "https://example.com/x", "不是 clash://"},
		{"no action", "clash://", "不认识的 clash:// 动作"},
		{"unknown action", "clash://open-config?url=https://example.com/s", "不认识的 clash:// 动作"},
		{"missing url", "clash://install-config?name=abc", "缺少 url 参数"},
		{"blank url", "clash://install-config?url=%20%20", "缺少 url 参数"},
		// A link is data from outside; it must not be able to point the
		// importer at a local file, a UNC path or a second scheme.
		{"file url", "clash://install-config?url=file%3A%2F%2F%2FC%3A%2Fsecret.yaml", "必须是 http:// 或 https://"},
		{"unc path", "clash://install-config?url=%5C%5Cserver%5Cshare%5Csub.yaml", "必须是 http:// 或 https://"},
		{"bare host", "clash://install-config?url=https%3A%2F%2F", "必须是 http:// 或 https://"},
		{"over long name", "clash://install-config?url=https://example.com/s&name=" + strings.Repeat("a", 129), "订阅名过长"},
		{"over long link", "clash://install-config?url=https://example.com/s&x=" + strings.Repeat("a", maxURLLength), "过长"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(c.raw)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded, want an error mentioning %q", c.raw, c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("Parse(%q) error %q does not mention %q", c.raw, err, c.want)
			}
		})
	}
}

func TestIsSubscriptionURL(t *testing.T) {
	yes := []string{
		"https://example.com/sub",
		"http://127.0.0.1:8080/sub.yaml?token=1",
	}
	for _, s := range yes {
		if !IsSubscriptionURL(s) {
			t.Errorf("IsSubscriptionURL(%q) = false, want true", s)
		}
	}
	no := []string{
		"",
		"file:///C:/sub.yaml",
		"ftp://example.com/sub",
		"clash://install-config?url=https://example.com/s",
		"https://",
		"https://example.com/a b",
		"https://example.com/a\nb",
		"proxies:\n  - name: x",
	}
	for _, s := range no {
		if IsSubscriptionURL(s) {
			t.Errorf("IsSubscriptionURL(%q) = true, want false", s)
		}
	}
}

// A clash:// link pasted into the import box has to behave like the address
// inside it; anything else is passed through untouched so the box keeps
// accepting plain text and plain URLs.
func TestResolveSubscriptionURL(t *testing.T) {
	got, ok := ResolveSubscriptionURL("clash://install-config?url=https%3A%2F%2Fexample.com%2Fsub")
	if !ok || got != "https://example.com/sub" {
		t.Errorf("ResolveSubscriptionURL = (%q, %v), want (https://example.com/sub, true)", got, ok)
	}
	for _, raw := range []string{
		"https://example.com/sub",
		"proxies:\n  - name: x",
		"clash://open-config?url=https://example.com/sub",
		"clash://install-config?url=file%3A%2F%2F%2FC%3A%2Fx",
	} {
		got, ok := ResolveSubscriptionURL(raw)
		if ok || got != raw {
			t.Errorf("ResolveSubscriptionURL(%q) = (%q, %v), want the input back and false", raw, got, ok)
		}
	}
}

func TestCommandQuotesTheExecutable(t *testing.T) {
	got := Command(`C:\Apps\syan-clash\syan-clash.exe`)
	if got != `"C:\Apps\syan-clash\syan-clash.exe" "%1"` {
		t.Errorf("Command = %q", got)
	}
}

func TestOwnerOfHandlesBothShapes(t *testing.T) {
	cases := map[string]string{
		`"H:\VPN\FlyClash\FlyClash.exe" "%1"`: "H:\\VPN\\FlyClash\\FlyClash.exe",
		`C:\app\client.exe %1`:                `C:\app\client.exe`,
		`"C:\with space\app.exe"`:             `C:\with space\app.exe`,
		``:                                    "",
	}
	for in, want := range cases {
		if got := ownerOf(in); got != want {
			t.Errorf("ownerOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// isOurs compares executable names, so a moved client still owns its own
// registration while another program's name never matches.
func TestIsOursComparesNames(t *testing.T) {
	if isOurs(`D:\elsewhere\syan-clash.exe`) != true {
		t.Error("a syan-clash.exe registration in another folder must count as ours")
	}
	if isOurs(`H:\VPN\FlyClash\FlyClash.exe`) {
		t.Error("FlyClash must never count as ours")
	}
	if isOurs("") {
		t.Error("an empty owner must not count as ours")
	}
}

func TestErrForeignOwnerIsRecognisable(t *testing.T) {
	_, err := Parse("clash://")
	if errors.Is(err, ErrForeignOwner) {
		t.Fatal("a parse error must not look like a foreign owner")
	}
}
