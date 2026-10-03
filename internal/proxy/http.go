package proxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vvpn/internal/netutil"
)

var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func stripHopByHop(h http.Header) {
	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
}

// handleHTTP serves the HTTP proxy inbound: CONNECT for tunnels and
// absolute-form requests for plain HTTP.
//
// Plain HTTP is deliberately answered one request per client connection with
// "Connection: close". That keeps the framing trivially correct; upstream
// connection pooling and full keep-alive are the next optimization step.
func (s *Server) handleHTTP(c net.Conn, src string) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(deadlineFromIdle(s.idleTimeout))

	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	// Authenticate before stripping hop-by-hop headers: Proxy-Authorization
	// is itself a hop-by-hop header and must survive the credential check.
	if !s.httpAuthOK(req) {
		writeHTTPError(c, http.StatusProxyAuthRequired, "proxy authentication required")
		return
	}
	stripHopByHop(req.Header)

	if req.Method == http.MethodConnect {
		_ = c.SetReadDeadline(deadlineFromIdle(0))
		host, port, err := splitHostPort(req.Host, 443)
		if err != nil {
			writeHTTPError(c, http.StatusBadRequest, "bad CONNECT target")
			return
		}
		s.proxyStream(c, br, src, host, port, protoHTTP)
		return
	}

	if req.URL == nil || req.URL.Host == "" {
		writeHTTPError(c, http.StatusBadRequest, "absolute-form request URI required")
		return
	}
	host := req.URL.Hostname()
	var port uint16
	if p := req.URL.Port(); p != "" {
		v, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			writeHTTPError(c, http.StatusBadRequest, "bad port")
			return
		}
		port = uint16(v)
	} else {
		port = netutil.DefaultPortForScheme(req.URL.Scheme)
	}

	sess, ctx := s.reg.Add(context.Background(), ConnInfo{
		Source: src,
		Host:   host,
		Target: netutil.JoinHostPort(host, port),
	})
	defer sess.Close()

	upstream, rr := s.dial(ctx, host, port)
	sess.setRoute(rr)
	if upstream == nil {
		writeHTTPError(c, httpStatusForError(rr.Err), rr.Err.Error())
		return
	}
	defer func() { _ = upstream.Close() }()
	sess.attach(c)
	sess.attach(upstream)

	uc := &countingConn{Conn: upstream, read: &sess.down, write: &sess.up}
	cc := &countingConn{Conn: c, read: &sess.up, write: &sess.down}

	req.RequestURI = ""
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.Close = true
	req.Header.Set("Connection", "close")
	if err := req.Write(uc); err != nil {
		writeHTTPError(c, http.StatusBadGateway, err.Error())
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(uc), req)
	if err != nil {
		writeHTTPError(c, http.StatusBadGateway, err.Error())
		return
	}
	defer func() { _ = resp.Body.Close() }()

	stripHopByHop(resp.Header)
	resp.Close = true
	resp.Header.Set("Connection", "close")
	_ = resp.Write(cc)
}

func (s *Server) httpAuthOK(req *http.Request) bool {
	if s.cfg.Inbound.Username == "" && s.cfg.Inbound.Password == "" {
		return true
	}
	const prefix = "basic "
	raw := req.Header.Get("Proxy-Authorization")
	if len(raw) <= len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw[len(prefix):]))
	if err != nil {
		return false
	}
	user, pass, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(user), []byte(s.cfg.Inbound.Username)) == 1 &&
		subtle.ConstantTimeCompare([]byte(pass), []byte(s.cfg.Inbound.Password)) == 1
}

func deadlineFromIdle(idle time.Duration) time.Time {
	if idle <= 0 {
		return time.Time{}
	}
	return time.Now().Add(idle)
}
