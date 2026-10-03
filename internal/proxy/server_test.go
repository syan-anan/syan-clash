package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vvpn/internal/config"
	"vvpn/internal/logbus"
	"vvpn/internal/rules"
)

// newTestServer starts a proxy core on ephemeral ports in front of an origin
// server, with SOCKS5/HTTP inbound authentication enabled.
func newTestServer(t *testing.T, rs []rules.Rule) (*Server, string, string) {
	t.Helper()
	cfg := config.Default()
	cfg.Inbound.SOCKS5Addr = "127.0.0.1:0"
	cfg.Inbound.HTTPAddr = "127.0.0.1:0"
	cfg.Inbound.Username = "labuser"
	cfg.Inbound.Password = "labpass"
	cfg.Outbound.Type = "direct"
	cfg.Outbound.IdleTimeout = 5000
	cfg.Rules = rs
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config.Validate: %v", err)
	}
	engine, err := rules.New(cfg.Rules)
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	srv, err := New(cfg, logbus.New(64, logbus.LevelError), engine)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	addrs := srv.Addrs()
	if len(addrs) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(addrs))
	}
	return srv, addrs[0].String(), addrs[1].String()
}

func newOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin:%s", r.URL.Path)
	}))
	t.Cleanup(origin.Close)
	return origin
}

func originHostPort(t *testing.T, origin *httptest.Server) string {
	t.Helper()
	_, _, err := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	if err != nil {
		t.Fatalf("split origin URL %q: %v", origin.URL, err)
	}
	return strings.TrimPrefix(origin.URL, "http://")
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func dialProxy(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn
}

func TestHTTPInboundPlainRequestWithAuth(t *testing.T) {
	origin := newOrigin(t)
	_, _, httpAddr := newTestServer(t, []rules.Rule{{Kind: rules.KindFinal, Value: "", Action: string(rules.ActionProxy)}})
	conn := dialProxy(t, httpAddr)

	target := strings.TrimPrefix(origin.URL, "http://")
	req := fmt.Sprintf("GET %s/plain HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\nConnection: close\r\n\r\n",
		origin.URL, target, basicAuth("labuser", "labpass"))
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", resp.StatusCode, body)
	}
	if string(body) != "origin:/plain" {
		t.Fatalf("body = %q, want %q", body, "origin:/plain")
	}
}

func TestHTTPInboundRequiresAuth(t *testing.T) {
	origin := newOrigin(t)
	_, _, httpAddr := newTestServer(t, []rules.Rule{{Kind: rules.KindFinal, Value: "", Action: string(rules.ActionProxy)}})
	conn := dialProxy(t, httpAddr)

	req := fmt.Sprintf("GET %s/noauth HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		origin.URL, strings.TrimPrefix(origin.URL, "http://"))
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
}

func TestSOCKS5InboundThroughOwnClient(t *testing.T) {
	origin := newOrigin(t)
	target := originHostPort(t, origin)
	_, socksAddr, _ := newTestServer(t, []rules.Rule{{Kind: rules.KindFinal, Value: "", Action: string(rules.ActionProxy)}})

	client := &Socks5Out{Addr: socksAddr, Username: "labuser", Password: "labpass", Timeout: 5 * time.Second}
	conn, err := client.Dial(context.Background(), "tcp", target)
	if err != nil {
		t.Fatalf("socks5 dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	req := fmt.Sprintf("GET /via-socks HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "origin:/via-socks" {
		t.Fatalf("got status %d body %q", resp.StatusCode, body)
	}
}

func TestSOCKS5InboundRejectsBadPassword(t *testing.T) {
	origin := newOrigin(t)
	target := originHostPort(t, origin)
	_, socksAddr, _ := newTestServer(t, []rules.Rule{{Kind: rules.KindFinal, Value: "", Action: string(rules.ActionProxy)}})

	client := &Socks5Out{Addr: socksAddr, Username: "labuser", Password: "wrong", Timeout: 5 * time.Second}
	if _, err := client.Dial(context.Background(), "tcp", target); err == nil {
		t.Fatal("dial with a wrong password succeeded, want failure")
	}
}

func TestRejectRuleBlocksConnection(t *testing.T) {
	origin := newOrigin(t)
	target := originHostPort(t, origin)
	_, _, httpAddr := newTestServer(t, []rules.Rule{
		{Kind: rules.KindDomainSuffix, Value: "127.0.0.1", Action: string(rules.ActionReject)},
		{Kind: rules.KindFinal, Value: "", Action: string(rules.ActionProxy)},
	})
	conn := dialProxy(t, httpAddr)

	req := fmt.Sprintf("GET http://%s/blocked HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\nConnection: close\r\n\r\n",
		target, target, basicAuth("labuser", "labpass"))
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestConnectTunnelToOrigin(t *testing.T) {
	origin := newOrigin(t)
	target := originHostPort(t, origin)
	_, _, httpAddr := newTestServer(t, []rules.Rule{{Kind: rules.KindFinal, Value: "", Action: string(rules.ActionProxy)}})
	conn := dialProxy(t, httpAddr)

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
		target, target, basicAuth("labuser", "labpass"))
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}
	if _, err := io.WriteString(conn, "GET /tunnel HTTP/1.1\r\nHost: "+target+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write tunneled request: %v", err)
	}
	tunneled, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read tunneled response: %v", err)
	}
	defer tunneled.Body.Close()
	body, _ := io.ReadAll(tunneled.Body)
	if string(body) != "origin:/tunnel" {
		t.Fatalf("body = %q, want %q", body, "origin:/tunnel")
	}
}

func TestRegistryTracksConnections(t *testing.T) {
	origin := newOrigin(t)
	srv, _, httpAddr := newTestServer(t, []rules.Rule{{Kind: rules.KindFinal, Value: "", Action: string(rules.ActionProxy)}})
	conn := dialProxy(t, httpAddr)

	req := fmt.Sprintf("GET %s/counted HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\nConnection: close\r\n\r\n",
		origin.URL, strings.TrimPrefix(origin.URL, "http://"), basicAuth("labuser", "labpass"))
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, total := srv.Registry().Counts(); total > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("registry never recorded the connection")
		}
		time.Sleep(20 * time.Millisecond)
	}
	snap := srv.Registry().Snapshot()
	if len(snap) == 0 {
		t.Fatal("snapshot is empty")
	}
	last := snap[0]
	if last.Up == 0 || last.Down == 0 {
		t.Fatalf("byte counters not recorded: %+v", last)
	}
	if last.Action != string(rules.ActionProxy) {
		t.Fatalf("action = %q, want proxy", last.Action)
	}
}

// A client that puts the same address in socks5_addr and http_addr means one
// mixed port. Binding the same socket twice is EADDRINUSE on the second try,
// which used to abort the whole client - what the user sees is a process that
// flashes a window and disappears.
func TestMixedInboundServesBothProtocolsOnOnePort(t *testing.T) {
	origin := newOrigin(t)
	target := originHostPort(t, origin)

	// A real port, so "the same address twice" means what it means in a
	// config file: two identical strings, not two ephemeral ports.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	cfg := config.Default()
	cfg.Inbound.SOCKS5Addr = addr
	cfg.Inbound.HTTPAddr = addr
	cfg.Inbound.Username = ""
	cfg.Inbound.Password = ""
	cfg.Outbound.Type = "direct"
	cfg.Outbound.IdleTimeout = 5000
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config.Validate: %v", err)
	}
	engine, err := rules.New([]rules.Rule{{Kind: rules.KindFinal, Value: "", Action: string(rules.ActionProxy)}})
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	srv, err := New(cfg, logbus.New(64, logbus.LevelError), engine)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	if got := len(srv.Addrs()); got != 1 {
		t.Fatalf("a mixed inbound must bind exactly one listener, got %d", got)
	}
	if got := srv.Bound("mixed"); got != addr {
		t.Fatalf("Bound(mixed) = %q, want %q", got, addr)
	}

	conn := dialProxy(t, addr)
	req := fmt.Sprintf("GET %s/mixed-http HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", origin.URL, target)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "origin:/mixed-http" {
		t.Fatalf("http through the mixed port: status %d body %q", resp.StatusCode, body)
	}

	client := &Socks5Out{Addr: addr, Timeout: 5 * time.Second}
	sc, err := client.Dial(context.Background(), "tcp", target)
	if err != nil {
		t.Fatalf("socks5 dial through the mixed port: %v", err)
	}
	defer sc.Close()
	_ = sc.SetDeadline(time.Now().Add(10 * time.Second))
	sreq := fmt.Sprintf("GET /mixed-socks HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	if _, err := io.WriteString(sc, sreq); err != nil {
		t.Fatalf("write socks request: %v", err)
	}
	sresp, err := http.ReadResponse(bufio.NewReader(sc), nil)
	if err != nil {
		t.Fatalf("read socks response: %v", err)
	}
	sbody, _ := io.ReadAll(sresp.Body)
	_ = sresp.Body.Close()
	if sresp.StatusCode != http.StatusOK || string(sbody) != "origin:/mixed-socks" {
		t.Fatalf("socks through the mixed port: status %d body %q", sresp.StatusCode, sbody)
	}

	// CONNECT through the shared port is the path that depends on the
	// half-close surviving the protocol-sniffing wrapper: once the origin
	// closes, the client has to see EOF instead of sitting on the idle
	// timeout waiting for a stream that ended.
	tconn := dialProxy(t, addr)
	if _, err := io.WriteString(tconn, fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	tbr := bufio.NewReader(tconn)
	statusLine, err := tbr.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status line: %v", err)
	}
	if !strings.Contains(statusLine, " 200") {
		t.Fatalf("CONNECT status line = %q, want 200", strings.TrimSpace(statusLine))
	}
	for {
		line, err := tbr.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	if _, err := io.WriteString(tconn, fmt.Sprintf("GET /mixed-connect HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)); err != nil {
		t.Fatalf("write tunneled request: %v", err)
	}
	tresp, err := http.ReadResponse(tbr, nil)
	if err != nil {
		t.Fatalf("read tunneled response: %v", err)
	}
	tbody, _ := io.ReadAll(tresp.Body)
	_ = tresp.Body.Close()
	if tresp.StatusCode != http.StatusOK || string(tbody) != "origin:/mixed-connect" {
		t.Fatalf("through the tunnel: status %d body %q", tresp.StatusCode, tbody)
	}
	_ = tconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := tbr.ReadByte(); err == nil {
		t.Fatal("expected EOF after the origin closed, got another byte")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("no EOF after the origin closed: the half-close did not survive the mixed wrapper")
	}
}

// A busy inbound port must not be fatal: the listener slides to the next free
// one and the client keeps running instead of exiting on startup.
func TestInboundPortSlidesWhenBusy(t *testing.T) {
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold a port: %v", err)
	}
	defer hold.Close()
	addr := hold.Addr().String()

	cfg := config.Default()
	cfg.Inbound.SOCKS5Addr = addr
	cfg.Inbound.HTTPAddr = ""
	cfg.Outbound.Type = "direct"
	engine, err := rules.New(nil)
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	srv, err := New(cfg, logbus.New(64, logbus.LevelError), engine)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start must slide instead of failing: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	if got := srv.Bound("socks5"); got == addr || got == "" {
		t.Fatalf("Bound(socks5) = %q, want a different free port", got)
	}
}
