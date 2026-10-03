package proxy

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"vvpn/internal/config"
	"vvpn/internal/logbus"
	"vvpn/internal/rules"
)

// fakeSocks5 is the smallest upstream that proves the point of SetUpstream:
// it answers the SOCKS5 handshake, records the destination it was asked for and
// pipes the stream to it. Nothing here inspects the payload, because the test
// only has to show that the connection was handed over at all.
func fakeSocks5(t *testing.T) (string, *atomic.Value) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var seen atomic.Value
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeSocks5(conn, &seen)
		}
	}()
	return ln.Addr().String(), &seen
}

func serveFakeSocks5(c net.Conn, seen *atomic.Value) {
	defer c.Close()
	br := bufio.NewReader(c)
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(br, greeting); err != nil {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	host := ""
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(pb[0])<<8|int(pb[1])))
	seen.Store(target)
	up, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// socksEchoOrigin listens on loopback and answers a fixed word, so a completed
// round trip through the entry point proves the whole path works.
func socksEchoOrigin(t *testing.T) (string, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 4)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				_, _ = c.Write([]byte("pong"))
			}(c)
		}
	}()
	return ln.Addr().String(), "pong"
}

// newUpstreamServer starts a proxy core with no authentication whose only rule
// sends everything to the "proxy" action.
func newUpstreamServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	cfg := config.Default()
	cfg.Inbound.SOCKS5Addr = "127.0.0.1:0"
	cfg.Inbound.HTTPAddr = "127.0.0.1:0"
	cfg.Outbound.Type = "direct"
	cfg.Outbound.IdleTimeout = 5000
	cfg.Rules = []rules.Rule{{Kind: rules.KindFinal, Value: "", Action: string(rules.ActionProxy)}}
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
	socks, httpAddr := srv.Bound("socks5"), srv.Bound("http")
	if socks == "" || httpAddr == "" {
		t.Fatalf("expected two inbounds, got socks=%q http=%q", socks, httpAddr)
	}
	return srv, socks, httpAddr
}

// socks5Dial performs the client half of a SOCKS5 CONNECT through the entry
// point under test.
func socks5Dial(t *testing.T, entry, target string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", entry)
	if err != nil {
		t.Fatalf("dial entry %s: %v", entry, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("socks greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("socks greeting reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("socks greeting reply = %v, want version 5 method 0", reply)
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("target %q: %v", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("target port %q: %v", portStr, err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("target %q is not an IPv4 address", host)
	}
	req := append([]byte{0x05, 0x01, 0x00, 0x01}, ip...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatalf("socks connect: %v", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatalf("socks connect reply: %v", err)
	}
	if head[1] != 0x00 {
		t.Fatalf("socks connect refused: rep=%d", head[1])
	}
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		_, _ = io.ReadFull(c, b)
	case 0x03:
		l := make([]byte, 1)
		_, _ = io.ReadFull(c, l)
		b := make([]byte, int(l[0]))
		_, _ = io.ReadFull(c, b)
	case 0x04:
		b := make([]byte, 16)
		_, _ = io.ReadFull(c, b)
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		t.Fatalf("socks bound address: %v", err)
	}
	return c
}

func roundTrip(t *testing.T, c net.Conn) string {
	t.Helper()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read through tunnel: %v", err)
	}
	return string(buf)
}

// TestSetUpstreamTakesOverProxyTraffic is the regression for the bug that made
// the client's own ports useless: with a core running, "proxy" traffic left
// from the local machine instead of through the node.
func TestSetUpstreamTakesOverProxyTraffic(t *testing.T) {
	upstream, seen := fakeSocks5(t)
	origin, want := socksEchoOrigin(t)
	srv, socksAddr, _ := newUpstreamServer(t)

	if got := srv.Upstream(); got != "" {
		t.Fatalf("upstream before SetUpstream = %q, want empty", got)
	}
	if got := srv.OutboundName(); got != "direct" {
		t.Fatalf("outbound before SetUpstream = %q, want direct", got)
	}

	srv.SetUpstream(upstream)
	if got := srv.Upstream(); got != upstream {
		t.Fatalf("upstream = %q, want %q", got, upstream)
	}
	if got, wantName := srv.OutboundName(), "socks5://"+upstream; got != wantName {
		t.Fatalf("outbound after SetUpstream = %q, want %q", got, wantName)
	}

	if got := roundTrip(t, socks5Dial(t, socksAddr, origin)); got != want {
		t.Fatalf("payload through the entry point = %q, want %q", got, want)
	}
	if got, _ := seen.Load().(string); got != origin {
		t.Fatalf("upstream was asked for %q, want %q", got, origin)
	}
}

// TestSetUpstreamEmptyRestoresConfiguredOutbound covers the other half: when
// the core stops, traffic must fall back to the configured outbound instead of
// dialling a port nothing listens on.
func TestSetUpstreamEmptyRestoresConfiguredOutbound(t *testing.T) {
	upstream, seen := fakeSocks5(t)
	origin, want := socksEchoOrigin(t)
	srv, socksAddr, _ := newUpstreamServer(t)

	srv.SetUpstream(upstream)
	srv.SetUpstream("")
	if got := srv.Upstream(); got != "" {
		t.Fatalf("upstream after reset = %q, want empty", got)
	}
	if got := srv.OutboundName(); got != "direct" {
		t.Fatalf("outbound after reset = %q, want direct", got)
	}

	if got := roundTrip(t, socks5Dial(t, socksAddr, origin)); got != want {
		t.Fatalf("payload after reset = %q, want %q", got, want)
	}
	if got, _ := seen.Load().(string); got != "" {
		t.Fatalf("the upstream was used after the reset: %q", got)
	}
}

// TestSetUpstreamIgnoresWhitespaceAndRepeats keeps the status poll honest: it
// calls SetUpstream on every tick, so a repeat must be a no-op and a padded
// address must not be treated as a different upstream.
func TestSetUpstreamIgnoresWhitespaceAndRepeats(t *testing.T) {
	srv, _, _ := newUpstreamServer(t)
	srv.SetUpstream("  127.0.0.1:2900  ")
	if got := srv.Upstream(); got != "127.0.0.1:2900" {
		t.Fatalf("upstream = %q, want the trimmed address", got)
	}
	srv.SetUpstream("127.0.0.1:2900")
	if got := srv.Upstream(); got != "127.0.0.1:2900" {
		t.Fatalf("upstream after a repeat = %q, want the same address", got)
	}
	srv.SetUpstream("127.0.0.1:2901")
	if got := srv.Upstream(); got != "127.0.0.1:2901" {
		t.Fatalf("upstream after a change = %q, want the new address", got)
	}
}
