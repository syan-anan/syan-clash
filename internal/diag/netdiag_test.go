package diag

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests cover the pieces that can be driven without the public
// internet: the local listeners stand in for the remote ends, and the ICMP
// tests are skipped when the system refuses the probe outright.

func TestEnsureDNSServer(t *testing.T) {
	cases := map[string]string{
		"":             "8.8.8.8:53",
		"8.8.8.8":      "8.8.8.8:53",
		"1.1.1.1:5353": "1.1.1.1:5353",
		"dns.google":   "dns.google:53",
	}
	for in, want := range cases {
		if got := ensureDNSServer(in); got != want {
			t.Errorf("ensureDNSServer(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDohTypeNames(t *testing.T) {
	cases := map[int]string{1: "A", 28: "AAAA", 16: "TXT", 5: "CNAME", 2: "NS", 15: "MX"}
	for n, want := range cases {
		if got := dohTypeName(n); got != want {
			t.Errorf("dohTypeName(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestIPFromUint32(t *testing.T) {
	a := netip.MustParseAddr("203.0.113.9").As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	if got := ipFromUint32(v); got.String() != "203.0.113.9" {
		t.Errorf("ipFromUint32 = %s, want 203.0.113.9", got)
	}
}

func TestLocalMTUSane(t *testing.T) {
	if got := localMTU(); got < 576 || got > 65535 {
		t.Errorf("localMTU() = %d, out of range", got)
	}
}

func TestTCPPingLocalListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	p := New(Options{Now: time.Now})
	res, err := p.TCPPing(context.Background(), "127.0.0.1", port, ViaDirect, 3000)
	if err != nil {
		t.Fatalf("TCPPing: %v", err)
	}
	if !res.OK {
		t.Fatalf("TCPPing did not connect: stage=%s err=%s", res.Stage, res.Error)
	}
	if res.Resolved != "127.0.0.1" {
		t.Errorf("resolved = %q", res.Resolved)
	}
}

func TestTCPPingRefusedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	p := New(Options{Now: time.Now})
	res, err := p.TCPPing(context.Background(), "127.0.0.1", port, ViaDirect, 2000)
	if err != nil {
		t.Fatalf("TCPPing: %v", err)
	}
	if res.OK {
		t.Errorf("expected a refused connection")
	}
	if res.Stage != "connect" {
		t.Errorf("stage = %q, want connect", res.Stage)
	}
}

func TestTLSInspectLocal(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	p := New(Options{Now: time.Now})
	res, err := p.TLSInspect(context.Background(), host, port, ViaDirect, nil)
	if err != nil {
		t.Fatalf("TLSInspect: %v", err)
	}
	if !res.OK {
		t.Fatalf("handshake failed: stage=%s err=%s", res.Stage, res.Error)
	}
	if len(res.Certs) == 0 {
		t.Errorf("no certificates returned")
	}
	if res.TLSVersion == "" {
		t.Errorf("missing TLS version")
	}
	if res.ChainOK {
		t.Errorf("a self-signed certificate must not verify")
	}
}

func TestICMPLoopback(t *testing.T) {
	rep, err := icmpProbe(netip.MustParseAddr("127.0.0.1"), 64, 32, false, time.Second)
	if errors.Is(err, errICMPUnavailable) {
		t.Skip("the system refuses ICMP probes here")
	}
	if err != nil {
		t.Fatalf("icmpProbe: %v", err)
	}
	if rep.From.String() != "127.0.0.1" {
		t.Errorf("answered by %s, want 127.0.0.1", rep.From)
	}
	if !rep.Final {
		t.Errorf("a loopback answer is the final hop")
	}
}

func TestProbeMTULoopback(t *testing.T) {
	p := New(Options{Now: time.Now})
	res, err := p.ProbeMTU(context.Background(), "127.0.0.1", 1200, 1500, 1000)
	if err != nil {
		t.Fatalf("ProbeMTU: %v", err)
	}
	if res.Error == "icmp_unavailable" {
		t.Skip("the system refuses ICMP probes here")
	}
	if !res.OK {
		t.Fatalf("loopback should carry the full payload: %+v", res)
	}
	if res.PathMTU != res.PayloadMax+28 {
		t.Errorf("path_mtu = %d, payload_max = %d", res.PathMTU, res.PayloadMax)
	}
}

func TestTraceLoopback(t *testing.T) {
	p := New(Options{Now: time.Now})
	job, err := p.StartTrace(TraceRequest{Host: "127.0.0.1", MaxHops: 3, TimeoutMS: 1000, Queries: 1})
	if err != nil {
		t.Fatalf("StartTrace: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		state, msg := job.State()
		if msg == "icmp_unavailable" {
			t.Skip("the system refuses ICMP probes here")
		}
		if state != JobRunning {
			hops, _ := job.Status()["hops"].([]TraceHop)
			if len(hops) == 0 {
				t.Fatalf("no hops recorded: %+v", job.Status())
			}
			if hops[0].TTL != 1 {
				t.Errorf("first hop ttl = %d, want 1", hops[0].TTL)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the trace did not finish")
}
