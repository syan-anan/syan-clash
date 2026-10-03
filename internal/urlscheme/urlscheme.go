// Package urlscheme turns the clash:// links this family of clients hands
// around into something the client can act on, and (on Windows) registers the
// client as the program the shell starts for them.
//
// The registration is deliberately conservative. clash:// is already owned by
// other clients on many machines - FlyClash registers it, Clash Verge
// registers it - and taking it over silently would break whichever client the
// user actually uses. Register therefore refuses to write over a registration
// that belongs to somebody else, and reports the owner so the console can say
// who has it. The switch is off unless the user turns it on.
package urlscheme

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// Scheme is the URL scheme this client handles.
const Scheme = "clash"

// ExeName is the file name this client ships as. Ownership of a registration
// is decided by name, not by full path, so a client that was moved to another
// folder still recognises its own entry.
const ExeName = "syan-clash.exe"

// Action kinds. Only the shape every client in this family agrees on is
// implemented; anything else is reported as unsupported rather than guessed
// at, because guessing wrong means importing a config the user did not ask
// for.
const (
	// ActionInstallConfig is
	// clash://install-config?url=<subscription>&name=<optional>.
	ActionInstallConfig = "install-config"
)

// maxURLLength bounds what a link may carry. A subscription address is a few
// hundred bytes; anything past this is not a link a person pasted.
const maxURLLength = 4096

// ErrForeignOwner reports a registration that belongs to another program. The
// client never overwrites one: that link belongs to the user's other client
// until they say otherwise.
var ErrForeignOwner = errors.New("clash:// 已经被另一个程序注册")

// Action is a parsed clash:// link.
type Action struct {
	Kind string // ActionInstallConfig
	URL  string // the subscription address to import
	Name string // optional subscription name
	Raw  string // the link as received
}

// Registration is the state of one scheme in the current user's registry.
type Registration struct {
	Scheme     string `json:"scheme"`
	Key        string `json:"key"`
	Command    string `json:"command"`
	Registered bool   `json:"registered"`
	Ours       bool   `json:"ours"`
	Owner      string `json:"owner"`
	Foreign    bool   `json:"foreign"`
}

// KeyPath is the per-user registry key a scheme lives under.
func KeyPath(scheme string) string { return `Software\Classes\` + scheme }

// Command renders the shell command Windows runs for a link: the executable
// in quotes, then the link. The quotes matter - a path with a space is the
// normal case, and an unquoted one would be read as two arguments.
func Command(exePath string) string {
	return `"` + exePath + `" "%1"`
}

// Parse reads a clash:// link. It accepts the shape this family emits:
//
//	clash://install-config?url=https%3A%2F%2Fexample.com%2Fsub&name=My%20Airport
//
// The host carries the action and the query carries its arguments. A trailing
// slash after the action is tolerated because some clients add one.
func Parse(raw string) (Action, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return Action{}, fmt.Errorf("clash:// 链接是空的")
	}
	if len(text) > maxURLLength {
		return Action{}, fmt.Errorf("clash:// 链接过长（%d 字节，上限 %d）", len(text), maxURLLength)
	}
	u, err := url.Parse(text)
	if err != nil {
		return Action{}, fmt.Errorf("clash:// 链接解析失败：%w", err)
	}
	if !strings.EqualFold(u.Scheme, Scheme) {
		return Action{}, fmt.Errorf("不是 clash:// 链接（scheme=%q）", u.Scheme)
	}
	kind := strings.Trim(strings.ToLower(u.Host), "/")
	if kind == "" {
		kind = strings.Trim(strings.ToLower(u.Path), "/")
	}
	if kind != ActionInstallConfig {
		return Action{}, fmt.Errorf("不认识的 clash:// 动作 %q（只支持 %s）", kind, ActionInstallConfig)
	}
	q := u.Query()
	target := strings.TrimSpace(q.Get("url"))
	if target == "" {
		return Action{}, fmt.Errorf("clash://%s 缺少 url 参数", kind)
	}
	if !IsSubscriptionURL(target) {
		return Action{}, fmt.Errorf("clash:// 里的订阅地址必须是 http:// 或 https://（收到 %s）", truncate(target, 80))
	}
	name := strings.TrimSpace(q.Get("name"))
	if len([]rune(name)) > 128 {
		return Action{}, fmt.Errorf("clash:// 里的订阅名过长（%d 字，上限 128）", len([]rune(name)))
	}
	return Action{Kind: kind, URL: target, Name: name, Raw: text}, nil
}

// IsSubscriptionURL reports whether s is a plain http(s) subscription address.
// The check is deliberately narrow: an import must never be talked into
// reading a local file, a UNC path or another scheme by a link somebody
// pasted.
func IsSubscriptionURL(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" || strings.ContainsAny(t, "\n\r\t ") {
		return false
	}
	u, err := url.Parse(t)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// ResolveSubscriptionURL unwraps a pasted payload: a clash:// link becomes the
// subscription address it carries, anything else is handed back unchanged.
// The import box accepts both, so a link copied out of a chat works exactly
// like the address inside it.
func ResolveSubscriptionURL(payload string) (string, bool) {
	text := strings.TrimSpace(payload)
	if !strings.HasPrefix(strings.ToLower(text), Scheme+"://") {
		return payload, false
	}
	action, err := Parse(text)
	if err != nil {
		return payload, false
	}
	return action.URL, true
}

// ownerOf extracts the program from a registered shell command.
func ownerOf(command string) string {
	c := strings.TrimSpace(command)
	if strings.HasPrefix(c, `"`) {
		if i := strings.Index(c[1:], `"`); i >= 0 {
			return c[1 : 1+i]
		}
	}
	if i := strings.IndexAny(c, " \t"); i > 0 {
		return c[:i]
	}
	return c
}

// isOurs reports whether a registered command belongs to this client.
func isOurs(owner string) bool {
	name := strings.TrimSpace(owner)
	if name == "" {
		return false
	}
	return strings.EqualFold(filepath.Base(name), ExeName)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
