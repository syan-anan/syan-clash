package panel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Fixtures below are trimmed copies of real responses captured from the
// provider panel (2026-09-30), so the tests pin the exact wire format.

const userInfoJSON = `{"status":"success","message":"操作成功","data":{"email":"user@example.com","transfer_enable":322122547200,"last_login_at":1790576781,"created_at":1734365018,"banned":false,"remind_expire":true,"remind_traffic":false,"expired_at":1805723587,"balance":3283,"commission_balance":0,"plan_id":8,"discount":null,"commission_rate":null,"telegram_id":null,"uuid":"00000000-0000-4000-8000-000000000000","avatar_url":"https://cdn.v2ex.com/gravatar/6eb7bc18698fa40792c73af43441c6bf?s=64&d=identicon"},"error":null}`

const subscribeJSON = `{"status":"success","message":"操作成功","data":{"plan_id":8,"token":"0123456789abcdef0123456789abcdef","expired_at":1805723587,"u":119028927,"d":5242824019,"transfer_enable":322122547200,"email":"user@example.com","uuid":"00000000-0000-4000-8000-000000000000","device_limit":null,"speed_limit":null,"next_reset_at":1792677187,"plan":{"id":8,"group_id":3,"transfer_enable":300,"name":"示例套餐","prices":{"yearly":69,"two_yearly":99,"half_yearly":39,"three_yearly":128,"reset_traffic":4},"sell":1,"show":true,"sort":3,"renew":true,"content":"<p>300G/月</p>","tags":null,"reset_traffic_method":1,"capacity_limit":null,"created_at":1709404551,"updated_at":1779993307},"subscribe_url":"https://panel.example.com/aaaaaaaaaaaa/bbbbbbbbbbbb/0123456789abcdef0123456789abcdef","reset_day":23},"error":null}`

const commConfigJSON = `{"status":"success","message":"操作成功","data":{"tos_url":null,"is_email_verify":0,"is_invite_force":0,"email_whitelist_suffix":["qq.com","gmail.com"],"is_captcha":0,"captcha_type":"recaptcha","recaptcha_site_key":"6LcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","recaptcha_v3_site_key":null,"recaptcha_v3_score_threshold":0.5,"turnstile_site_key":null,"app_description":"示例描述","app_url":"https://example.com","logo":null,"is_recaptcha":0},"error":null}`

const loginOKJSON = `{"status":"success","message":"操作成功","data":{"token":"zzzz0000zzzz0000zzzz0000zzzz0000zzzz0000zzzz0000zzzz0000","is_admin":false},"error":null}`

const loginFailJSON = `{"status":"fail","message":"邮箱或密码错误","data":null,"error":null}`

func newTestServer(t *testing.T) (*httptest.Server, *http.Request) {
	t.Helper()
	var last *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last = r.Clone(context.Background())
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/passport/auth/login":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			_ = r.ParseForm()
			if strings.Contains(readBody(r), "wrong") {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(loginFailJSON))
				return
			}
			_, _ = w.Write([]byte(loginOKJSON))
		case r.URL.Path == "/user/info":
			if r.Header.Get("Authorization") != "Bearer zzzz0000zzzz0000zzzz0000zzzz0000zzzz0000zzzz0000zzzz0000" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"status":"fail","message":"Unauthenticated.","data":null,"error":null}`))
				return
			}
			_, _ = w.Write([]byte(userInfoJSON))
		case r.URL.Path == "/user/getSubscribe":
			_, _ = w.Write([]byte(subscribeJSON))
		case r.URL.Path == "/guest/comm/config":
			_, _ = w.Write([]byte(commConfigJSON))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	_ = last
	return srv, nil
}

func readBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	b := make([]byte, 4096)
	n, _ := r.Body.Read(b)
	return string(b[:n])
}

// The live panel answers with both a subscribe token and an auth_data bearer,
// and only the second one authenticates. Sending the first one as the bearer is
// what made every follow-up call answer 403 "未登录或登陆已过期" on the real
// machine, so the shape is pinned here with the values replaced.
func TestLoginUsesAuthDataAsBearer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/passport/auth/login" {
			t.Errorf("unexpected path %s", r.URL.Path)
			return
		}
		_, _ = io.WriteString(w, `{"status":"success","message":"操作成功","data":{"token":"subscribe-token","auth_data":"Bearer api-bearer","is_admin":false},"error":null}`)
	}))
	defer srv.Close()

	c := New(srv.URL)
	res, err := c.Login(context.Background(), "someone@example.com", "pw")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if res.Token != "api-bearer" {
		t.Errorf("Token = %q, want the auth_data bearer", res.Token)
	}
	if c.Token() != "api-bearer" {
		t.Errorf("the client kept %q, want the auth_data bearer", c.Token())
	}
	if res.AuthData == "" {
		t.Error("AuthData should still be reported to the caller")
	}
}

// A fork that sends only the plain token keeps working: auth_data wins when it
// is there, and the token is the fallback when it is not.
func TestBearerTokenFallsBackToThePlainToken(t *testing.T) {
	if got := bearerToken(LoginResult{Token: "only-token"}); got != "only-token" {
		t.Errorf("bearerToken = %q, want the plain token", got)
	}
	if got := bearerToken(LoginResult{Token: "t", AuthData: "Bearer b"}); got != "b" {
		t.Errorf("bearerToken = %q, want b", got)
	}
	if got := bearerToken(LoginResult{Token: "t", AuthData: "raw-bearer"}); got != "raw-bearer" {
		t.Errorf("bearerToken = %q, want the raw auth_data", got)
	}
	if got := bearerToken(LoginResult{}); got != "" {
		t.Errorf("bearerToken of an empty answer = %q", got)
	}
}

func TestLoginStoresToken(t *testing.T) {
	srv, _ := newTestServer(t)
	c := New(srv.URL)
	res, err := c.Login(context.Background(), "user@example.com", "hunter2")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if res.Token != "zzzz0000zzzz0000zzzz0000zzzz0000zzzz0000zzzz0000zzzz0000" {
		t.Fatalf("unexpected token %q", res.Token)
	}
	if c.Token() != res.Token {
		t.Fatal("login result was not stored on the client")
	}
}

func TestLoginFailureSurfacesMessage(t *testing.T) {
	srv, _ := newTestServer(t)
	c := New(srv.URL)
	_, err := c.Login(context.Background(), "nobody@example.com", "wrong")
	if err == nil {
		t.Fatal("expected an error")
	}
	var pe *Error
	if !errors.As(err, &pe) {
		t.Fatalf("expected *panel.Error, got %T", err)
	}
	if pe.Message != "邮箱或密码错误" {
		t.Fatalf("unexpected message %q", pe.Message)
	}
}

func TestUserInfoRoundTrip(t *testing.T) {
	srv, _ := newTestServer(t)
	c := New(srv.URL)
	c.SetToken("zzzz0000zzzz0000zzzz0000zzzz0000zzzz0000zzzz0000zzzz0000")
	info, err := c.UserInfo(context.Background())
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if info.Email != "user@example.com" || info.TransferEnable != 322122547200 {
		t.Fatalf("unexpected user info: %+v", info)
	}
	if info.UUID != "00000000-0000-4000-8000-000000000000" {
		t.Fatalf("uuid mismatch: %q", info.UUID)
	}
}

func TestUserInfoRequiresToken(t *testing.T) {
	srv, _ := newTestServer(t)
	c := New(srv.URL)
	_, err := c.UserInfo(context.Background())
	var pe *Error
	if !errors.As(err, &pe) || !pe.IsAuth() {
		t.Fatalf("expected auth error, got %v", err)
	}
}

func TestSubscribeRoundTrip(t *testing.T) {
	srv, _ := newTestServer(t)
	c := New(srv.URL)
	c.SetToken("x")
	sub, err := c.Subscribe(context.Background())
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if sub.SubscribeURL != "https://panel.example.com/aaaaaaaaaaaa/bbbbbbbbbbbb/0123456789abcdef0123456789abcdef" {
		t.Fatalf("subscribe url mismatch: %q", sub.SubscribeURL)
	}
	if sub.Plan == nil || sub.Plan.Name != "示例套餐" || sub.Plan.TransferEnable != 300 {
		t.Fatalf("plan mismatch: %+v", sub.Plan)
	}
	if sub.Used() != 119028927+5242824019 {
		t.Fatalf("Used() = %d", sub.Used())
	}
	if sub.ResetDay != 23 {
		t.Fatalf("reset day = %d", sub.ResetDay)
	}
}

func TestCommConfigNoAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	c := New(srv.URL)
	cfg, err := c.CommConfig(context.Background())
	if err != nil {
		t.Fatalf("CommConfig: %v", err)
	}
	if cfg.AppURL != "https://example.com" || cfg.IsCaptcha != 0 {
		t.Fatalf("unexpected comm config: %+v", cfg)
	}
	if len(cfg.EmailWhitelistSuffix) != 2 {
		t.Fatalf("whitelist mismatch: %v", cfg.EmailWhitelistSuffix)
	}
}

func TestSetBaseURL(t *testing.T) {
	c := New("")
	if c.BaseURL() != "" {
		t.Fatalf("no panel ships with the client, want an empty base, got %q", c.BaseURL())
	}
	c.SetBaseURL("https://example.test/api/")
	if c.BaseURL() != "https://example.test/api" {
		t.Fatalf("trailing slash should be trimmed, got %q", c.BaseURL())
	}
	c.SetBaseURL("")
	if c.BaseURL() != "" {
		t.Fatalf("clearing should leave the base empty, got %q", c.BaseURL())
	}
}

// noticesServer serves the two announcement shapes and can be told to 404 the
// V2Board route so the fallback path is exercised.
func noticesServer(t *testing.T, paginator bool, breakFetch bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user/notice/fetch":
			if breakFetch {
				http.NotFound(w, r)
				return
			}
			if paginator {
				_, _ = w.Write([]byte(`{"status":"success","data":{"data":[{"id":2,"title":"线路维护","content":"今晚 2 点维护","created_at":1790000000},{"id":1,"title":"旧的","content":"","created_at":1780000000}],"total":2,"current_page":1,"last_page":1},"error":null}`))
				return
			}
			_, _ = w.Write([]byte(`{"status":"success","data":[{"id":3,"title":"裸数组","content":"ok","created_at":1791000000}],"error":null}`))
		case "/user/announcement":
			_, _ = w.Write([]byte(`{"status":"success","data":[{"id":9,"title":"SSPanel 形态","content":"fallback","created_at":1792000000}],"error":null}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestNoticesParsesPaginator(t *testing.T) {
	srv := noticesServer(t, true, false)
	c := New(srv.URL)
	c.SetToken("t")
	list, err := c.Notices(context.Background())
	if err != nil {
		t.Fatalf("Notices: %v", err)
	}
	if len(list) != 2 || list[0].Title != "线路维护" || list[0].CreatedAt != 1790000000 {
		t.Fatalf("unexpected notices: %+v", list)
	}
}

func TestNoticesParsesBareArray(t *testing.T) {
	srv := noticesServer(t, false, false)
	c := New(srv.URL)
	c.SetToken("t")
	list, err := c.Notices(context.Background())
	if err != nil {
		t.Fatalf("Notices: %v", err)
	}
	if len(list) != 1 || list[0].Title != "裸数组" {
		t.Fatalf("unexpected notices: %+v", list)
	}
}

func TestNoticesFallsBackToSSPanelRoute(t *testing.T) {
	srv := noticesServer(t, true, true)
	c := New(srv.URL)
	c.SetToken("t")
	list, err := c.Notices(context.Background())
	if err != nil {
		t.Fatalf("Notices fallback: %v", err)
	}
	if len(list) != 1 || list[0].Title != "SSPanel 形态" {
		t.Fatalf("unexpected fallback notices: %+v", list)
	}
}

func TestDecodeNoticesRejectsUnknownShape(t *testing.T) {
	if _, err := decodeNotices([]byte(`{"unexpected":true}`)); err == nil {
		t.Fatal("expected an error for an unknown envelope")
	}
	if list, err := decodeNotices([]byte(`[]`)); err != nil || len(list) != 0 {
		t.Fatalf("empty array should decode to an empty list, got %+v %v", list, err)
	}
}

// A client with no panel address must fail locally: without this guard the
// request would be built against a relative URL and surface as a confusing
// transport error instead of "fill in the panel address".
func TestRequestsWithoutAPanelAddressAreRejectedLocally(t *testing.T) {
	c := New("")
	_, err := c.Login(context.Background(), "user@example.com", "hunter2")
	var ie *InvalidInputError
	if !errors.As(err, &ie) {
		t.Fatalf("Login with no panel address error = %v, want InvalidInputError", err)
	}
}
