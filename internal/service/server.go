package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// tokenHeader 是客户端和特权服务之间的共享密钥头。
const tokenHeader = "X-Syan-Token"

// maxBodyBytes 限制请求体：这条通道只传启动参数，几 KB 足够，
// 免得一个畸形请求把特权进程的内存吃满。
const maxBodyBytes = 1 << 20

// Server 是装成 Windows 服务后跑在 LocalSystem 下的特权助手。
type Server struct {
	Addr     string
	Token    string
	Version  string
	Logf     func(string, ...any)
	Runner   *Runner
	Shutdown func()
}

// NewServer 组装一个服务实例；logf 允许为 nil。
func NewServer(addr, token, version string, logf func(string, ...any)) *Server {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Server{
		Addr:    addr,
		Token:   token,
		Version: version,
		Logf:    logf,
		Runner:  NewRunner(logf),
	}
}

// Handler 返回全部路由。两道校验装在 mux 外面，连 404 都要先过鉴权，
// 免得未授权的人靠状态码差异探测这条通道上有哪些路径。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /svc/status", s.handleStatus)
	mux.HandleFunc("GET /svc/procs", s.handleProcs)
	mux.HandleFunc("POST /svc/core/start", s.handleCoreStart)
	mux.HandleFunc("POST /svc/core/stop", s.handleCoreStop)
	mux.HandleFunc("POST /svc/shutdown", s.handleShutdown)
	return s.guard(mux)
}

// Serve 在 Addr 上监听并服务，直到 ctx 取消。
//
// 地址必须先过回环校验再监听：这条通道能拉起任意绝对路径的可执行文件，
// 一旦监听到局域网地址就等于把整台机器交出去。
func (s *Server) Serve(ctx context.Context) error {
	if err := checkLoopbackAddr(s.Addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("监听 %s 失败：%w", s.Addr, err)
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	s.log("特权服务已监听 %s（version=%s）", ln.Addr().String(), s.Version)

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		<-errCh
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// guard 做两道校验：来源必须是本机回环，令牌（若配置了）必须匹配。
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackRemote(r.RemoteAddr) {
			s.log("拒绝非回环请求：remote=%s path=%s", r.RemoteAddr, r.URL.Path)
			s.writeError(w, http.StatusForbidden, "只接受本机回环地址的请求")
			return
		}
		if s.Token != "" && r.Header.Get(tokenHeader) != s.Token {
			s.writeError(w, http.StatusUnauthorized, "令牌不正确")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isLoopbackRemote 只看 IP 字面量。这里不接受主机名：RemoteAddr 由内核给出，
// 出现非 IP 说明请求不是从本机 TCP 栈上来的，宁可拒绝。
func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

// checkLoopbackAddr 保证监听地址写死了回环，而不是 0.0.0.0 或某个网卡地址。
func checkLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("服务地址 %q 无法解析：%w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("服务地址必须是回环地址，收到 %q", addr)
	}
	return nil
}

// log 统一兜住 Logf 为 nil 的情况：Server 允许被直接构造，
// 少一个 nil 判断就会在错误路径上 panic。
func (s *Server) log(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log("写响应失败：%v", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, code int, msg string) {
	s.writeJSON(w, code, map[string]string{"error": msg})
}

// decodeJSON 读一个 JSON 对象；请求体不是合法 JSON 时返回错误，
// 调用方统一映射成 400。
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(v)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"version": s.Version,
		"pid":     os.Getpid(),
		"addr":    s.Addr,
		"procs":   s.Runner.List(),
	})
}

func (s *Server) handleProcs(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{"procs": s.Runner.List()})
}

type startRequest struct {
	ID   string   `json:"id"`
	Exe  string   `json:"exe"`
	Args []string `json:"args"`
	Dir  string   `json:"dir"`
}

func (s *Server) handleCoreStart(w http.ResponseWriter, r *http.Request) {
	var body startRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeError(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	id := strings.TrimSpace(body.ID)
	exe := strings.TrimSpace(body.Exe)
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "缺少 id")
		return
	}
	if exe == "" {
		s.writeError(w, http.StatusBadRequest, "缺少 exe")
		return
	}
	// 服务以 LocalSystem 身份运行。放行相对路径就等于把 PATH 查找权交给调用方，
	// 这条通道会变成任意命令执行入口，所以只接受存在的绝对路径文件。
	if !filepath.IsAbs(exe) {
		s.writeError(w, http.StatusBadRequest, "exe 必须是绝对路径")
		return
	}
	if info, err := os.Stat(exe); err != nil || info.IsDir() {
		s.writeError(w, http.StatusBadRequest, "exe 不存在或不是普通文件")
		return
	}
	proc, err := s.Runner.Start(id, exe, body.Args, body.Dir)
	if err != nil {
		if errors.Is(err, ErrRunning) {
			s.writeError(w, http.StatusConflict, err.Error())
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"proc": proc})
}

type stopRequest struct {
	ID string `json:"id"`
}

func (s *Server) handleCoreStop(w http.ResponseWriter, r *http.Request) {
	var body stopRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeError(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	id := strings.TrimSpace(body.ID)
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "缺少 id")
		return
	}
	if err := s.Runner.Stop(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"stopped": true})
}

// handleShutdown 先把响应写出去，再在后台通知宿主退出。
// 同步调用会死锁：宿主的 Shutdown 要等当前请求结束，而当前请求正卡在里面。
func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	if s.Shutdown != nil {
		go s.Shutdown()
	}
}
