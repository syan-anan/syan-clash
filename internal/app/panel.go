package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vvpn/internal/panel"
)

// PanelSession is the persisted 小白-panel login state.
type PanelSession struct {
	BaseURL string    `json:"base_url,omitempty"`
	Email   string    `json:"email,omitempty"`
	Token   string    `json:"token,omitempty"`
	LoginAt time.Time `json:"login_at,omitempty"`

	// RememberPassword is the user's explicit opt-in. The password is written
	// to panel.json **only** while this is true; with it off the file keeps the
	// token and nothing else, which is what the client has always done. Turning
	// the switch off erases a password that was stored before.
	RememberPassword bool `json:"remember_password,omitempty"`
	// Password is stored only when RememberPassword is on. It is never echoed
	// back to the console - PanelState reports whether one is saved, not what
	// it is - and it is only ever used to log in again.
	Password string `json:"password,omitempty"`
}

// PanelState is the UI-facing login summary (never exposes the token).
type PanelState struct {
	LoggedIn         bool   `json:"logged_in"`
	Email            string `json:"email,omitempty"`
	BaseURL          string `json:"base_url"`
	RememberPassword bool   `json:"remember_password"`
	PasswordSaved    bool   `json:"password_saved"`
}

func (a *App) panelPath() string {
	return filepath.Join(filepath.Dir(a.cfgPath), "panel.json")
}

// loadPanel restores the saved session, if any.
func (a *App) loadPanel() error {
	raw, err := os.ReadFile(a.panelPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var sess PanelSession
	if err := json.Unmarshal(raw, &sess); err != nil {
		return fmt.Errorf("%s: %w", a.panelPath(), err)
	}
	a.mu.Lock()
	a.panelSess = sess
	a.mu.Unlock()
	return nil
}

// savePanel writes the session atomically.
func (a *App) savePanel() error {
	a.mu.Lock()
	sess := a.panelSess
	a.mu.Unlock()

	raw, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	path := a.panelPath()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".panel-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// panelClient builds a client from the current session. An empty session still
// yields a usable client: the login endpoint needs no token.
func (a *App) panelClient() *panel.Client {
	a.mu.Lock()
	sess := a.panelSess
	a.mu.Unlock()
	c := panel.New(sess.BaseURL)
	c.SetToken(sess.Token)
	return c
}

// PanelClient exposes the raw API client; the console uses it for public calls
// such as the welcome banner on the 小白 page.
func (a *App) PanelClient() *panel.Client { return a.panelClient() }

// panelSession returns a copy of the current session.
func (a *App) panelSession() PanelSession {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.panelSess
}

// PanelState summarises the login state for the console.
func (a *App) PanelState() PanelState {
	sess := a.panelSession()
	base := sess.BaseURL
	if strings.TrimSpace(base) == "" {
		base = panel.DefaultBaseURL
	}
	return PanelState{
		LoggedIn:         strings.TrimSpace(sess.Token) != "",
		Email:            sess.Email,
		BaseURL:          base,
		RememberPassword: sess.RememberPassword,
		PasswordSaved:    strings.TrimSpace(sess.Password) != "",
	}
}

// PanelLogin authenticates against the panel and persists the session.
//
// An empty password means "use the one the user asked me to remember": the
// console then only has to send the email, which is the whole point of the
// remember switch.
func (a *App) PanelLogin(ctx context.Context, email, password string, remember bool) (panel.UserInfo, error) {
	email = strings.TrimSpace(email)
	if password == "" {
		if sess := a.panelSession(); sess.RememberPassword && strings.TrimSpace(sess.Password) != "" {
			password = sess.Password
			if email == "" {
				email = sess.Email
			}
		}
	}
	if email == "" || password == "" {
		return panel.UserInfo{}, &panel.InvalidInputError{Msg: "请填写邮箱和密码"}
	}
	c := a.panelClient()
	res, err := c.Login(ctx, email, password)
	if err != nil {
		return panel.UserInfo{}, err
	}
	info, err := c.UserInfo(ctx)
	if err != nil {
		return panel.UserInfo{}, err
	}
	a.mu.Lock()
	keep := ""
	if remember {
		keep = password
	}
	a.panelSess = PanelSession{
		BaseURL:          c.BaseURL(),
		Email:            email,
		Token:            res.Token,
		LoginAt:          time.Now(),
		RememberPassword: remember,
		Password:         keep,
	}
	a.mu.Unlock()
	if err := a.savePanel(); err != nil {
		return info, err
	}
	a.log.Infof("小白账号 %s 登录成功（记住密码：%v）", email, remember)
	return info, nil
}

// PanelLogout forgets the login token. The panel address and, when the user
// asked for it, the remembered password survive: logging out and back in must
// not cost the user their panel address or a retyped password.
func (a *App) PanelLogout() error {
	a.mu.Lock()
	email := a.panelSess.Email
	keep := a.panelSess
	keep.Token = ""
	keep.LoginAt = time.Time{}
	if !keep.RememberPassword {
		keep.Password = ""
	}
	a.panelSess = keep
	a.mu.Unlock()
	if err := a.savePanel(); err != nil {
		return err
	}
	if email != "" {
		a.log.Infof("小白账号 %s 已退出登录", email)
	}
	return nil
}

// PanelSetRememberPassword turns the "记住密码" switch on or off. Turning it off
// erases a stored password immediately - a switch that leaves the secret on
// disk would be a lie.
func (a *App) PanelSetRememberPassword(on bool) error {
	a.mu.Lock()
	a.panelSess.RememberPassword = on
	if !on {
		a.panelSess.Password = ""
	}
	a.mu.Unlock()
	return a.savePanel()
}

// PanelUserInfo fetches account details for the logged-in session.
func (a *App) PanelUserInfo(ctx context.Context) (panel.UserInfo, error) {
	return a.panelClient().UserInfo(ctx)
}

// PanelSubscribe fetches subscription details (traffic, plan, subscribe URL).
func (a *App) PanelSubscribe(ctx context.Context) (panel.Subscribe, error) {
	return a.panelClient().Subscribe(ctx)
}

// PanelSetBase points the panel client at another deployment and persists the
// choice. The vendor hides its API behind a rotating hostname, so the address
// has to be editable at runtime instead of compiled in. Reachability is proven
// with the public config call before anything is written; because a token is
// only valid for the deployment that issued it, the stored session is cleared
// and the user logs in again.
func (a *App) PanelSetBase(ctx context.Context, raw string) (panel.CommConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return panel.CommConfig{}, &panel.InvalidInputError{Msg: "请填写小白面板地址"}
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return panel.CommConfig{}, &panel.InvalidInputError{Msg: "面板地址需要是 http(s)://主机/路径 的形式"}
	}
	c := panel.New(raw)
	cfg, err := c.CommConfig(ctx)
	if err != nil {
		return panel.CommConfig{}, err
	}
	a.mu.Lock()
	a.panelSess = PanelSession{BaseURL: c.BaseURL()}
	a.mu.Unlock()
	if err := a.savePanel(); err != nil {
		return cfg, err
	}
	a.log.Infof("小白面板地址已切换为 %s", c.BaseURL())
	return cfg, nil
}

// PanelNotices fetches the panel announcements. Best effort by design: a
// deployment that does not serve the route answers with an error, and the page
// keeps the card hidden.
func (a *App) PanelNotices(ctx context.Context) ([]panel.Notice, error) {
	return a.panelClient().Notices(ctx)
}

// PanelImport fetches the panel's subscribe URL and imports it as a saved
// subscription, so the nodes become usable by the normal subscription flow.
func (a *App) PanelImport(ctx context.Context) (ImportResult, Subscription, error) {
	sub, err := a.PanelSubscribe(ctx)
	if err != nil {
		return ImportResult{}, Subscription{}, err
	}
	url := strings.TrimSpace(sub.SubscribeURL)
	if url == "" {
		return ImportResult{}, Subscription{}, fmt.Errorf("小白面板没有返回订阅地址")
	}
	name := "小白订阅"
	if sub.Plan != nil && strings.TrimSpace(sub.Plan.Name) != "" {
		name = "小白 · " + strings.TrimSpace(sub.Plan.Name)
	}
	// Re-importing the same URL refreshes the existing entry instead of
	// duplicating it.
	for _, s := range a.Subscriptions() {
		if s.URL == url {
			updated, err := a.UpdateSubscription(ctx, s.Name)
			if err != nil {
				return ImportResult{}, updated, err
			}
			result, ierr := a.ImportSubscriptionAs(ctx, updated.Name, updated.URL)
			if ierr != nil {
				return ImportResult{}, updated, ierr
			}
			return result, updated, nil
		}
	}
	saved, err := a.AddSubscription(ctx, name, url)
	if err != nil {
		// AddSubscription returns the stored subscription alongside the fetch
		// error, so the caller can still surface what was saved.
		return ImportResult{}, saved, err
	}
	return ImportResult{Nodes: saved.Nodes, Info: saved.Info, Source: "url"}, saved, nil
}
