package diag

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Via names the path a probe takes out of the machine.
type Via string

const (
	// ViaProxy sends the probe through the client's own mixed port, so the
	// answer describes the node the user is actually routing through.
	ViaProxy Via = "proxy"
	// ViaDirect bypasses the proxy: the control column for every comparison.
	ViaDirect Via = "direct"
)

// ParseVia accepts what a query string or a JSON body may carry and falls back
// to proxy, which is the interesting answer for every panel that shows it.
func ParseVia(s string) Via {
	if strings.EqualFold(strings.TrimSpace(s), string(ViaDirect)) {
		return ViaDirect
	}
	return ViaProxy
}

// SanitizeVia is ParseVia for values that must stay exactly as written.
func SanitizeVia(s string) Via { return ParseVia(s) }

// dialer opens TCP connections for one probe path. A probe that goes through
// the client is opened with an HTTP CONNECT to the mixed port, which covers
// HTTP, HTTPS and bare TLS on any port with one protocol implementation.
type dialer struct {
	via          Via
	proxyAddr    func() string
	fallbackAddr func() string
	timeout      time.Duration
	userAgent    string
}

// used reports which endpoint the connection actually went through, so the
// answer can say where it came from instead of implying a node that was down.
func (d *dialer) used() string { return describeVia(d.via, d.proxyAddr(), d.fallbackAddr()) }

func describeVia(via Via, proxy, fallback string) string {
	if via == ViaDirect {
		return "direct"
	}
	return "proxy://" + proxy + " (fallback " + fallback + ")"
}

// dial opens one TCP connection for this path.
func (d *dialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("diag: unsupported network %q", network)
	}
	nd := &net.Dialer{Timeout: d.timeout}
	if d.via == ViaDirect {
		return nd.DialContext(ctx, "tcp", addr)
	}
	// The kernel's mixed port is tried first; when the kernel is not running
	// the client's own mixed port still gives a usable answer, and the caller
	// sees which one answered in via_used.
	var lastErr error
	for _, endpoint := range []string{d.proxyAddr(), d.fallbackAddr()} {
		if endpoint == "" {
			continue
		}
		conn, err := nd.DialContext(ctx, "tcp", endpoint)
		if err != nil {
			lastErr = fmt.Errorf("connect %s: %w", endpoint, err)
			continue
		}
		tunnel, err := d.handshake(ctx, conn, addr)
		if err != nil {
			_ = conn.Close()
			lastErr = fmt.Errorf("connect %s: %w", endpoint, err)
			continue
		}
		return tunnel, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("diag: no proxy endpoint configured")
	}
	return nil, lastErr
}

// handshake performs the CONNECT exchange. The reader is kept on the returned
// connection: the proxy may have buffered the first bytes of the tunnel
// payload in the same read as the status line, and dropping them would break
// TLS in a way that looks like a bad certificate.
func (d *dialer) handshake(ctx context.Context, conn net.Conn, addr string) (net.Conn, error) {
	deadline := time.Now().Add(d.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	var req strings.Builder
	req.WriteString("CONNECT " + addr + " HTTP/1.1\r\n")
	req.WriteString("Host: " + addr + "\r\n")
	req.WriteString("Proxy-Connection: keep-alive\r\n")
	if d.userAgent != "" {
		req.WriteString("User-Agent: " + d.userAgent + "\r\n")
	}
	req.WriteString("\r\n")
	if _, err := conn.Write([]byte(req.String())); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CONNECT %s: %s", addr, resp.Status)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return &tunnelConn{Conn: conn, br: br}, nil
}

// tunnelConn is a connection whose reads may start with bytes the CONNECT
// handshake already pulled off the socket.
type tunnelConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *tunnelConn) Read(b []byte) (int, error) { return c.br.Read(b) }
