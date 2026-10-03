package app

import (
	"context"
	"fmt"
	"os"
	"strings"

	"vvpn/internal/config"
	"vvpn/internal/urlscheme"
)

// The clash:// link handler (P2-6). Two halves that are deliberately
// independent: acting on a link works on every platform and needs no
// registration at all - the console, the clipboard import and a manually
// passed argument all go through the same code - while owning the scheme is a
// per-user registry switch that stays off until the user turns it on and is
// refused outright when another client already holds it.

// URLSchemeStatus is what the console shows about the clash:// link: whether
// the user asked for this client to own it, whether the machine actually has a
// registration, and - when somebody else owns it - who does.
type URLSchemeStatus struct {
	Scheme     string `json:"scheme"`
	Key        string `json:"key"`
	Enabled    bool   `json:"enabled"`
	Registered bool   `json:"registered"`
	Ours       bool   `json:"ours"`
	Foreign    bool   `json:"foreign"`
	Owner      string `json:"owner"`
	Command    string `json:"command"`
	Exe        string `json:"exe"`
	Hint       string `json:"hint"`
}

// URLSchemeStatus reads the switch and the registry.
func (a *App) URLSchemeStatus() URLSchemeStatus {
	a.mu.Lock()
	enabled := a.cfg.App.URLSchemeEnabled()
	a.mu.Unlock()

	cur := urlscheme.Current(urlscheme.Scheme)
	st := URLSchemeStatus{
		Scheme:     urlscheme.Scheme,
		Key:        urlscheme.KeyPath(urlscheme.Scheme),
		Enabled:    enabled,
		Registered: cur.Registered,
		Ours:       cur.Ours,
		Foreign:    cur.Foreign,
		Owner:      cur.Owner,
		Command:    cur.Command,
	}
	if exe, err := os.Executable(); err == nil {
		st.Exe = exe
	}
	st.Hint = urlSchemeHint(st)
	return st
}

func urlSchemeHint(st URLSchemeStatus) string {
	switch {
	case st.Foreign:
		return fmt.Sprintf("clash:// 已经被 %s 占用，本客户端不抢别人的注册", st.Owner)
	case st.Enabled && st.Ours:
		return "已注册：点 clash:// 链接会交给本客户端导入订阅"
	case st.Enabled:
		return "已开启，但注册还没有生效"
	default:
		return "未开启：本客户端不接管 clash:// 链接（粘贴链接导入仍然可用）"
	}
}

// SetURLScheme turns the clash:// registration on or off and remembers the
// choice. The registry is written first: a switch that claims "on" while the
// machine disagrees would be a lie the user cannot debug, and a foreign owner
// has to fail the whole call rather than be recorded as a success.
func (a *App) SetURLScheme(enabled bool) (URLSchemeStatus, error) {
	exe, err := os.Executable()
	if err != nil {
		return a.URLSchemeStatus(), err
	}
	if enabled {
		if _, err := urlscheme.Register(urlscheme.Scheme, exe); err != nil {
			return a.URLSchemeStatus(), err
		}
	} else if err := urlscheme.Unregister(urlscheme.Scheme); err != nil {
		return a.URLSchemeStatus(), err
	}
	if err := a.setURLSchemeEnabled(enabled); err != nil {
		return a.URLSchemeStatus(), err
	}
	return a.URLSchemeStatus(), nil
}

// setURLSchemeEnabled persists the switch. Like the other desktop preferences
// it writes the file first and only then updates memory, so a failed write
// leaves the running client consistent with what is on disk, and it never goes
// through Reload: the switch changes no listener.
func (a *App) setURLSchemeEnabled(on bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cfg.App.URLScheme != nil && *a.cfg.App.URLScheme == on {
		return nil
	}
	next := a.cfg
	v := on
	next.App.URLScheme = &v
	if err := config.Save(a.cfgPath, next); err != nil {
		return err
	}
	a.cfg = next
	return nil
}

// ApplyURLScheme registers the scheme at startup when the user turned it on. A
// machine where somebody else owns clash:// is not worth blocking a start
// over: the error is returned, the caller logs it, and the client keeps going.
func (a *App) ApplyURLScheme() (URLSchemeStatus, error) {
	st := a.URLSchemeStatus()
	if !st.Enabled {
		return st, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return st, err
	}
	if _, err := urlscheme.Register(urlscheme.Scheme, exe); err != nil {
		return a.URLSchemeStatus(), err
	}
	return a.URLSchemeStatus(), nil
}

// HandleURLScheme acts on a clash:// link. It is the single entry point for
// every way a link can arrive - the shell, a second launch forwarding to the
// running instance, the console's own "打开链接" button - so they cannot drift
// apart.
func (a *App) HandleURLScheme(ctx context.Context, raw string) (map[string]any, error) {
	action, err := urlscheme.Parse(raw)
	if err != nil {
		return nil, err
	}
	switch action.Kind {
	case urlscheme.ActionInstallConfig:
		return a.installConfigFromLink(ctx, action)
	}
	return nil, fmt.Errorf("不认识的 clash:// 动作 %q", action.Kind)
}

// installConfigFromLink imports the subscription a link points at. A link that
// arrives twice refreshes the subscription it already has instead of failing
// with "already exists" - which is what a user clicking the same link again
// means by clicking it.
func (a *App) installConfigFromLink(ctx context.Context, action urlscheme.Action) (map[string]any, error) {
	out := map[string]any{
		"action": action.Kind,
		"url":    action.URL,
	}
	if existing, ok := existingSubscriptionFor(a.Subscriptions(), action.URL); ok {
		sub, err := a.UpdateSubscription(ctx, existing.Name)
		if err != nil {
			return nil, err
		}
		out["name"] = sub.Name
		out["nodes"] = sub.Nodes
		out["updated"] = true
		return out, nil
	}
	sub, err := a.AddSubscription(ctx, action.Name, action.URL)
	if err != nil {
		return nil, err
	}
	out["name"] = sub.Name
	out["nodes"] = sub.Nodes
	out["updated"] = false
	return out, nil
}

// existingSubscriptionFor finds the saved subscription that already carries
// url. The comparison ignores surrounding whitespace: a subscription that was
// saved by hand can carry it.
func existingSubscriptionFor(subs []Subscription, url string) (Subscription, bool) {
	target := strings.TrimSpace(url)
	for _, s := range subs {
		if strings.TrimSpace(s.URL) == target {
			return s, true
		}
	}
	return Subscription{}, false
}
