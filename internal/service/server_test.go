package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testToken = "s3cret-token"

func newTestServer(shutdown func()) *Server {
	s := NewServer("127.0.0.1:0", testToken, "0.0.0-test", nil)
	s.Shutdown = shutdown
	return s
}

// do 发一个来自回环地址的请求；token 为空表示不带鉴权头。
func do(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.RemoteAddr = "127.0.0.1:5555"
	if token != "" {
		req.Header.Set(tokenHeader, token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestStatusRouteRequiresToken(t *testing.T) {
	s := newTestServer(nil)
	defer s.Runner.StopAll()
	h := s.Handler()

	if rec := do(h, "GET", "/svc/status", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("不带令牌的状态码 = %d，想要 401", rec.Code)
	}
	if rec := do(h, "GET", "/svc/status", "wrong", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("错误令牌的状态码 = %d，想要 401", rec.Code)
	}
	rec := do(h, "GET", "/svc/status", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("正确令牌的状态码 = %d，想要 200（body=%s）", rec.Code, rec.Body.String())
	}
	var body struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析响应失败：%v", err)
	}
	if !body.OK {
		t.Fatalf("ok 字段 = false，body=%s", rec.Body.String())
	}
}

func TestNonLoopbackIsRejected(t *testing.T) {
	s := newTestServer(nil)
	defer s.Runner.StopAll()

	req := httptest.NewRequest("GET", "/svc/status", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	// 令牌正确也不能放行：来源不是本机就不该看见这条通道。
	req.Header.Set(tokenHeader, testToken)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("非回环来源的状态码 = %d，想要 403（body=%s）", rec.Code, rec.Body.String())
	}
}

func TestCoreStartRejectsRelativeExe(t *testing.T) {
	s := newTestServer(nil)
	defer s.Runner.StopAll()
	body := `{"id":"x","exe":"cmd.exe"}`
	rec := do(s.Handler(), "POST", "/svc/core/start", testToken, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("相对路径的状态码 = %d，想要 400（body=%s）", rec.Code, rec.Body.String())
	}
}

func TestCoreStartRejectsMissingFile(t *testing.T) {
	s := newTestServer(nil)
	defer s.Runner.StopAll()
	missing := filepath.Join(t.TempDir(), "nope", "core.exe")
	body := fmt.Sprintf(`{"id":"x","exe":%q}`, missing)
	rec := do(s.Handler(), "POST", "/svc/core/start", testToken, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("不存在的 exe 状态码 = %d，想要 400（body=%s）", rec.Code, rec.Body.String())
	}
}

func TestCoreStartBadJSONIsBadRequest(t *testing.T) {
	s := newTestServer(nil)
	defer s.Runner.StopAll()
	h := s.Handler()
	if rec := do(h, "POST", "/svc/core/start", testToken, "{not json"); rec.Code != http.StatusBadRequest {
		t.Fatalf("坏 JSON 的状态码 = %d，想要 400", rec.Code)
	}
	if rec := do(h, "POST", "/svc/core/start", testToken, `{"id":"","exe":"cmd.exe"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("缺 id 的状态码 = %d，想要 400", rec.Code)
	}
}

// TestCoreStartConflictIs409 走完整路由：真的起一个子进程，再起第二次。
func TestCoreStartConflictIs409(t *testing.T) {
	s := newTestServer(nil)
	defer s.Runner.StopAll()
	t.Setenv(childEnv, "1")
	body := fmt.Sprintf(`{"id":"mihomo","exe":%q}`, testBinary(t))
	h := s.Handler()

	if rec := do(h, "POST", "/svc/core/start", testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("首次启动的状态码 = %d，想要 200（body=%s）", rec.Code, rec.Body.String())
	}
	if rec := do(h, "POST", "/svc/core/start", testToken, body); rec.Code != http.StatusConflict {
		t.Fatalf("重复启动的状态码 = %d，想要 409（body=%s）", rec.Code, rec.Body.String())
	}
}

func TestCoreStopIsIdempotent(t *testing.T) {
	s := newTestServer(nil)
	defer s.Runner.StopAll()
	rec := do(s.Handler(), "POST", "/svc/core/stop", testToken, `{"id":"nope"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("停止未知 id 的状态码 = %d，想要 200（body=%s）", rec.Code, rec.Body.String())
	}
}

func TestProcsRouteReturnsArray(t *testing.T) {
	s := newTestServer(nil)
	defer s.Runner.StopAll()
	rec := do(s.Handler(), "GET", "/svc/procs", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("procs 的状态码 = %d，想要 200", rec.Code)
	}
	var body struct {
		Procs []Proc `json:"procs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析响应失败：%v", err)
	}
	if body.Procs == nil {
		t.Fatalf("procs 应当是空数组而不是 null，body=%s", rec.Body.String())
	}
}

func TestShutdownRouteCallsCallback(t *testing.T) {
	called := make(chan struct{}, 1)
	s := newTestServer(func() { called <- struct{}{} })
	defer s.Runner.StopAll()

	rec := do(s.Handler(), "POST", "/svc/shutdown", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("shutdown 的状态码 = %d，想要 200（body=%s）", rec.Code, rec.Body.String())
	}
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown 回调没有被调用")
	}
}

func TestServeRejectsNonLoopbackAddr(t *testing.T) {
	s := NewServer("0.0.0.0:0", testToken, "0.0.0-test", nil)
	if err := s.Serve(context.Background()); err == nil {
		t.Fatal("监听 0.0.0.0 应当被拒绝")
	}
}
