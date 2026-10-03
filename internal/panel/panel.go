// Package panel talks to the "小白" (V2Board) provider panel: it wraps the
// captured HTTP API (login, user info, subscription info, public config) that
// powers the console's 小白 page.
//
// The wire format was reverse-engineered from the vendor client; the envelope
// is {"status","message","data","error"} and auth uses a bearer token returned
// by /passport/auth/login.
package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultBaseURL is deliberately empty: no provider ships with the client.
//
// A 小白 panel lives at a per-deployment hostname whose path carries a secret
// prefix, so baking one in would hand every user somebody else's deployment.
// The address is a per-user setting instead - the console asks for it on the
// 小白 page and stores it in the panel session.
const DefaultBaseURL = ""

// DefaultUserAgent mirrors the vendor client; the panel accepts other agents
// but keeping it identical avoids tripping any heuristics.
const DefaultUserAgent = "tencent/1.39.3 (Windows; Windows 10 Pro) apppbfdocj9ai3"

// Error is a structured failure returned by the panel.
type Error struct {
	Code    int    // HTTP status
	Message string // server-provided message when available
}

func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("小白面板返回 HTTP %d", e.Code)
	}
	return e.Message
}

// IsAuth tells whether the failure looks like an expired/invalid session.
func (e *Error) IsAuth() bool {
	return e.Code == http.StatusUnauthorized || e.Code == http.StatusForbidden
}

// InvalidInputError marks a caller-fixable input problem (empty credentials, a
// malformed panel address). Nothing was sent to the panel, so the console can
// answer 400 instead of blaming the upstream with a 502.
type InvalidInputError struct {
	Msg string
}

func (e *InvalidInputError) Error() string { return e.Msg }

// Client is a stateless-ish panel API client. A non-empty token switches the
// authenticated endpoints on.
type Client struct {
	baseURL string
	token   string
	ua      string
	http    *http.Client
}

// New builds a client for baseURL (empty means DefaultBaseURL).
func New(baseURL string) *Client {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		ua:      DefaultUserAgent,
		http: &http.Client{
			Timeout: 20 * time.Second,
			// Panel requests never go through a proxy: the user may have the
			// system proxy pointed at this very app.
			Transport: &http.Transport{
				Proxy: nil,
				// The panel is behind Cloudflare; keep connections warm.
				MaxIdleConns:        8,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// BaseURL returns the configured base URL.
func (c *Client) BaseURL() string { return c.baseURL }

// Token returns the current bearer token.
func (c *Client) Token() string { return c.token }

// SetToken replaces the bearer token.
func (c *Client) SetToken(token string) { c.token = strings.TrimSpace(token) }

// SetBaseURL points the client at another deployment. The panel hides behind a
// rotating hostname, so this must be changeable without a rebuild; an empty
// value restores the shipped default.
func (c *Client) SetBaseURL(raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		c.baseURL = DefaultBaseURL
		return
	}
	c.baseURL = strings.TrimRight(raw, "/")
}

// SetUserAgent overrides the default user agent (empty string restores it).
func (c *Client) SetUserAgent(ua string) {
	if strings.TrimSpace(ua) == "" {
		c.ua = DefaultUserAgent
		return
	}
	c.ua = ua
}

// envelope is the provider's universal response wrapper.
type envelope struct {
	Status  string          `json:"status"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
	Error   any             `json:"error"`
}

func (c *Client) do(ctx context.Context, method, path string, payload, out any, auth bool) error {
	if c.baseURL == "" {
		return &InvalidInputError{Msg: "请填写小白面板地址"}
	}
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("panel: encode request: %w", err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("panel: build request: %w", err)
	}
	req.Header.Set("user-agent", c.ua)
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/json")
	if auth {
		if c.token == "" {
			return &Error{Code: http.StatusUnauthorized, Message: "尚未登录小白账号"}
		}
		req.Header.Set("authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("panel: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("panel: read response: %w", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return &Error{Code: resp.StatusCode, Message: fmt.Sprintf("小白面板返回了无法解析的内容（HTTP %d）", resp.StatusCode)}
	}
	if resp.StatusCode != http.StatusOK || (env.Status != "" && env.Status != "success") {
		msg := strings.TrimSpace(env.Message)
		if msg == "" {
			msg = fmt.Sprintf("小白面板请求失败（HTTP %d）", resp.StatusCode)
		}
		return &Error{Code: resp.StatusCode, Message: msg}
	}
	if out != nil && len(env.Data) > 0 && string(env.Data) != "null" {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("panel: decode data: %w", err)
		}
	}
	return nil
}

// LoginResult is what /passport/auth/login returns on success.
//
// The panel hands out two different strings and they are not interchangeable:
// "token" is the subscription token - the one that shows up in the subscribe
// URL - while "auth_data" carries the credential the API actually
// authenticates with. Sending the subscribe token as the bearer is what made
// every follow-up call answer HTTP 403 {"status":"fail","message":"未登录或登
// 陆已过期"}: the request was fine and the credential was simply the wrong one.
type LoginResult struct {
	Token    string `json:"token"`
	AuthData string `json:"auth_data"`
	IsAdmin  bool   `json:"is_admin"`
}

// bearerToken picks the string the API authenticates with out of a login
// answer: auth_data first (the panel already prefixes it with "Bearer ", which
// this strips because the client adds its own), then the plain token as a
// fallback for forks that only send one field.
func bearerToken(res LoginResult) string {
	if v := strings.TrimSpace(res.AuthData); v != "" {
		if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
			v = strings.TrimSpace(v[7:])
		}
		if v != "" {
			return v
		}
	}
	return strings.TrimSpace(res.Token)
}

// Login performs email+password authentication and returns the bearer token.
// The token is also stored on the client for follow-up calls.
func (c *Client) Login(ctx context.Context, email, password string) (LoginResult, error) {
	payload := map[string]string{"email": strings.TrimSpace(email), "password": password}
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodPost, "/passport/auth/login", payload, &raw, false); err != nil {
		return LoginResult{}, err
	}
	var res LoginResult
	if err := json.Unmarshal(raw, &res); err == nil {
		if tok := bearerToken(res); tok != "" {
			res.Token = tok
			c.SetToken(tok)
			return res, nil
		}
	}
	// Some forks nest the token under auth_data or return a bare string.
	var nested struct {
		AuthData struct {
			Token string `json:"token"`
		} `json:"auth_data"`
	}
	if err := json.Unmarshal(raw, &nested); err == nil && nested.AuthData.Token != "" {
		res.Token = nested.AuthData.Token
		c.SetToken(res.Token)
		return res, nil
	}
	var bare string
	if err := json.Unmarshal(raw, &bare); err == nil && strings.TrimSpace(bare) != "" {
		res.Token = strings.TrimSpace(bare)
		c.SetToken(res.Token)
		return res, nil
	}
	return LoginResult{}, fmt.Errorf("小白面板没有返回登录凭据")
}

// UserInfo mirrors GET /user/info.
type UserInfo struct {
	Email             string `json:"email"`
	TransferEnable    int64  `json:"transfer_enable"`
	LastLoginAt       int64  `json:"last_login_at"`
	CreatedAt         int64  `json:"created_at"`
	Banned            bool   `json:"banned"`
	RemindExpire      bool   `json:"remind_expire"`
	RemindTraffic     bool   `json:"remind_traffic"`
	ExpiredAt         int64  `json:"expired_at"`
	Balance           int64  `json:"balance"`
	CommissionBalance int64  `json:"commission_balance"`
	PlanID            any    `json:"plan_id"`
	Discount          any    `json:"discount"`
	CommissionRate    any    `json:"commission_rate"`
	TelegramID        any    `json:"telegram_id"`
	UUID              string `json:"uuid"`
	AvatarURL         string `json:"avatar_url"`
	DeviceLimit       any    `json:"device_limit"`
}

// UserInfo fetches the account summary for the logged-in token.
func (c *Client) UserInfo(ctx context.Context) (UserInfo, error) {
	var out UserInfo
	if err := c.do(ctx, http.MethodGet, "/user/info", nil, &out, true); err != nil {
		return UserInfo{}, err
	}
	return out, nil
}

// Plan is the package attached to a subscription.
type Plan struct {
	ID             int64          `json:"id"`
	GroupID        int64          `json:"group_id"`
	TransferEnable int64          `json:"transfer_enable"` // GB
	Name           string         `json:"name"`
	SpeedLimit     any            `json:"speed_limit"`
	DeviceLimit    any            `json:"device_limit"`
	Content        string         `json:"content"`
	Prices         map[string]any `json:"prices"`
}

// Subscribe mirrors GET /user/getSubscribe.
type Subscribe struct {
	PlanID         int64  `json:"plan_id"`
	Token          string `json:"token"`
	ExpiredAt      int64  `json:"expired_at"`
	U              int64  `json:"u"` // bytes uploaded
	D              int64  `json:"d"` // bytes downloaded
	TransferEnable int64  `json:"transfer_enable"`
	Email          string `json:"email"`
	UUID           string `json:"uuid"`
	DeviceLimit    any    `json:"device_limit"`
	SpeedLimit     any    `json:"speed_limit"`
	NextResetAt    int64  `json:"next_reset_at"`
	SubscribeURL   string `json:"subscribe_url"`
	Plan           *Plan  `json:"plan"`
	ResetDay       int64  `json:"reset_day"`
}

// Used returns uploaded+downloaded bytes.
func (s Subscribe) Used() int64 { return s.U + s.D }

// Subscribe fetches subscription details, including the subscribe URL that the
// caller can import as a node source.
func (c *Client) Subscribe(ctx context.Context) (Subscribe, error) {
	var out Subscribe
	if err := c.do(ctx, http.MethodGet, "/user/getSubscribe", nil, &out, true); err != nil {
		return Subscribe{}, err
	}
	return out, nil
}

// CommConfig mirrors the public GET /guest/comm/config endpoint.
type CommConfig struct {
	TosURL               string   `json:"tos_url"`
	IsEmailVerify        int      `json:"is_email_verify"`
	IsInviteForce        int      `json:"is_invite_force"`
	EmailWhitelistSuffix []string `json:"email_whitelist_suffix"`
	IsCaptcha            int      `json:"is_captcha"`
	CaptchaType          string   `json:"captcha_type"`
	RecaptchaSiteKey     string   `json:"recaptcha_site_key"`
	AppDescription       string   `json:"app_description"`
	AppURL               string   `json:"app_url"`
	Logo                 string   `json:"logo"`
	IsRecaptcha          int      `json:"is_recaptcha"`
}

// CommConfig fetches the public panel configuration.
func (c *Client) CommConfig(ctx context.Context) (CommConfig, error) {
	var out CommConfig
	if err := c.do(ctx, http.MethodGet, "/guest/comm/config", nil, &out, false); err != nil {
		return CommConfig{}, err
	}
	return out, nil
}

// Notice is one panel announcement. The vendor client shows these as a banner
// with a detail dialog, so the console renders the same fields.
type Notice struct {
	ID        int64  `json:"id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// Notices fetches the panel announcements. Two wire shapes exist across the
// V2Board family (a paginator on /user/notice/fetch, a bare array on the
// SSPanel-style /user/announcement), so both are tried and both envelopes are
// accepted: a deployment that serves neither simply has no announcements, and
// the caller hides the card.
func (c *Client) Notices(ctx context.Context) ([]Notice, error) {
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/user/notice/fetch?current=1", nil, &raw, true); err != nil {
		var first error = err
		if err2 := c.do(ctx, http.MethodGet, "/user/announcement?json=1", nil, &raw, true); err2 != nil {
			return nil, first
		}
	}
	return decodeNotices(raw)
}

// decodeNotices accepts [..] and {"data":[..]} and nothing else.
func decodeNotices(raw json.RawMessage) ([]Notice, error) {
	var list []Notice
	if err := json.Unmarshal(raw, &list); err == nil {
		return cleanNotices(list), nil
	}
	var page struct {
		Data []Notice `json:"data"`
	}
	if err := json.Unmarshal(raw, &page); err == nil && page.Data != nil {
		return cleanNotices(page.Data), nil
	}
	return nil, fmt.Errorf("小白面板公告格式无法解析")
}

// cleanNotices drops entries without a title and trims the ones kept.
func cleanNotices(in []Notice) []Notice {
	out := make([]Notice, 0, len(in))
	for _, n := range in {
		n.Title = strings.TrimSpace(n.Title)
		n.Content = strings.TrimSpace(n.Content)
		if n.Title == "" && n.Content == "" {
			continue
		}
		out = append(out, n)
	}
	return out
}
