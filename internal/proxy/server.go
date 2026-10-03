package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vvpn/internal/config"
	"vvpn/internal/logbus"
	"vvpn/internal/netutil"
	"vvpn/internal/rules"
)

// ErrRejected is returned when a rule action is "reject".
var ErrRejected = errors.New("connection rejected by rule")

// ruleResult is the routing decision plus the outbound that will serve it.
type ruleResult struct {
	Action   rules.Action
	Rule     string
	Outbound string
	Err      error
}

// Server owns the inbound listeners, the routing engine and the outbound.
type Server struct {
	cfg    config.Config
	log    *logbus.Bus
	engine *rules.Engine
	direct *Direct
	out    Outbound
	// upstream, when set, is the SOCKS5 address "proxy" traffic is handed to
	// instead of out: the mixed port of the core the client is running. It is what
	// makes the client's own entry point (inbound.http_addr / socks5_addr) carry
	// traffic through a node instead of straight out of the local machine.
	upstream *Socks5Out
	reg      *Registry

	connectTimeout time.Duration
	idleTimeout    time.Duration
	dnsTimeout     time.Duration

	mu        sync.Mutex
	listeners []net.Listener
	bound     map[string]string
	wg        sync.WaitGroup
	closing   atomic.Bool
}

// New builds a server from a validated configuration.
func New(cfg config.Config, log *logbus.Bus, engine *rules.Engine) (*Server, error) {
	timeout := time.Duration(cfg.Outbound.ConnectTimeout) * time.Millisecond
	var out Outbound
	switch cfg.Outbound.Type {
	case "direct":
		out = &Direct{Timeout: timeout}
	case "socks5":
		out = &Socks5Out{
			Addr:     cfg.Outbound.Socks5.Addr,
			Username: cfg.Outbound.Socks5.Username,
			Password: cfg.Outbound.Socks5.Password,
			Timeout:  timeout,
		}
	default:
		return nil, fmt.Errorf("proxy: unsupported outbound type %q", cfg.Outbound.Type)
	}
	return &Server{
		cfg:            cfg,
		log:            log,
		engine:         engine,
		direct:         &Direct{Timeout: timeout},
		out:            out,
		reg:            NewRegistry(log),
		bound:          map[string]string{},
		connectTimeout: timeout,
		idleTimeout:    time.Duration(cfg.Outbound.IdleTimeout) * time.Millisecond,
		dnsTimeout:     5 * time.Second,
	}, nil
}

// Registry exposes the live connection table.
func (s *Server) Registry() *Registry { return s.reg }

// Addrs returns the bound listener addresses in start order (mixed, or
// socks5 then http).
// It is mainly useful when an inbound was configured with port 0.
func (s *Server) Addrs() []net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]net.Addr, 0, len(s.listeners))
	for _, ln := range s.listeners {
		out = append(out, ln.Addr())
	}
	return out
}

// Engine exposes the routing engine.
func (s *Server) Engine() *rules.Engine { return s.engine }

// SetUpstream routes "proxy" traffic through a SOCKS5 upstream - the mixed
// port of the core the client is running - instead of the configured
// outbound. The client's entry point and the core keep their own ports, so
// starting or stopping a core never has to hand a listener over; only the
// destination of "proxy" traffic changes.
//
// An empty address restores the configured outbound. Called with the address
// already in force it is a no-op, which is what lets the status poll call it
// on every tick.
func (s *Server) SetUpstream(addr string) {
	addr = strings.TrimSpace(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	if addr == "" {
		s.upstream = nil
		return
	}
	if s.upstream != nil && s.upstream.Addr == addr {
		return
	}
	s.upstream = &Socks5Out{Addr: addr, Timeout: s.connectTimeout}
}

// Upstream is the SOCKS5 address "proxy" traffic is currently handed to, or
// "" when the configured outbound is in use.
func (s *Server) Upstream() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.upstream == nil {
		return ""
	}
	return s.upstream.Addr
}

// outbound is the destination of "proxy" traffic right now.
func (s *Server) outbound() Outbound {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.upstream != nil {
		return s.upstream
	}
	return s.out
}

// OutboundName is the human readable upstream identifier. It follows the
// live upstream, so the console names the core the traffic actually uses.
func (s *Server) OutboundName() string { return s.outbound().Name() }

// Start binds every configured inbound address.
//
// Two addresses that land on the same socket are one mixed port, not two
// listeners: that is the Clash spelling of "one port for both protocols".
// Binding the same socket twice fails with EADDRINUSE on the second try, which
// used to abort the whole client - what the user sees is a process that
// flashes a window and disappears.
func (s *Server) Start() error {
	type inbound struct {
		name string
		addr string
		fn   func(net.Conn, string)
	}
	var inbounds []inbound
	socksAddr := strings.TrimSpace(s.cfg.Inbound.SOCKS5Addr)
	httpAddr := strings.TrimSpace(s.cfg.Inbound.HTTPAddr)
	switch {
	case socksAddr == "" && httpAddr == "":
		return errors.New("proxy: no inbound configured")
	case socksAddr != "" && httpAddr != "" && s.sameSocket(socksAddr, httpAddr):
		inbounds = append(inbounds, inbound{"mixed", socksAddr, s.handleMixed})
	default:
		if socksAddr != "" {
			inbounds = append(inbounds, inbound{"socks5", socksAddr, s.handleSOCKS5})
		}
		if httpAddr != "" {
			inbounds = append(inbounds, inbound{"http", httpAddr, s.handleHTTP})
		}
	}

	for _, in := range inbounds {
		addr := in.addr
		if !s.cfg.Inbound.AllowLAN {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				_ = s.Close()
				return fmt.Errorf("proxy: %s inbound: %w", in.name, err)
			}
			if !netutil.IsLoopback(host) {
				s.log.Warnf("%s inbound %s is not loopback and allow_lan is false; binding 127.0.0.1:%s instead", in.name, addr, port)
				addr = net.JoinHostPort("127.0.0.1", port)
			}
		}
		ln, bound, err := s.listenSlide(addr, in.name)
		if err != nil {
			_ = s.Close()
			return fmt.Errorf("proxy: listen %s (%s): %w", addr, in.name, err)
		}
		s.mu.Lock()
		s.listeners = append(s.listeners, ln)
		s.bound[in.name] = bound
		s.mu.Unlock()
		s.log.Infof("%s inbound listening on %s", in.name, bound)

		handler := in.fn
		name := in.name
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.acceptLoop(ln, name, handler)
		}()
	}
	return nil
}

// Bound reports the address a listener actually got, keyed by inbound name
// ("mixed", "socks5" or "http"). It is how the rest of the client learns
// about a port that had to slide instead of handing out an address nothing
// listens on.
func (s *Server) Bound(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bound[name]
}

// listenSlideWindow is how far a busy inbound port may walk before the client
// gives up and reports the failure.
const listenSlideWindow = 10

// listenSlide binds addr and, when the port is already taken, walks forward
// through a small window of neighbours. A client that refuses to start because
// an unrelated program owns the port looks exactly like a client that flashes
// a window and dies; sliding keeps it usable, and the warning names the port
// it ended up on.
func (s *Server) listenSlide(addr, name string) (net.Listener, string, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		ln, err2 := net.Listen("tcp", addr)
		return ln, addr, err2
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		ln, err2 := net.Listen("tcp", addr)
		return ln, addr, err2
	}
	if port == 0 {
		// Port 0 asks the kernel for a free port: there is nothing to slide
		// away from, and the caller needs the port it actually got.
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, addr, err
		}
		return ln, ln.Addr().String(), nil
	}
	var firstErr error
	for i := 0; i < listenSlideWindow; i++ {
		if port+i > 65535 {
			break
		}
		cand := net.JoinHostPort(host, strconv.Itoa(port+i))
		ln, err := net.Listen("tcp", cand)
		if err == nil {
			if i > 0 {
				s.log.Warnf("%s 入站端口 %s 被占用，已改用 %s", name, addr, cand)
			}
			return ln, cand, nil
		}
		if i == 0 {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("no free port in range")
	}
	return nil, addr, firstErr
}

// sameSocket reports whether two configured listen addresses would end up on
// the same socket once the allow_lan rewrite has run.
func (s *Server) sameSocket(a, b string) bool {
	ha, pa, ea := net.SplitHostPort(a)
	hb, pb, eb := net.SplitHostPort(b)
	if ea != nil || eb != nil {
		return a == b
	}
	if pa == "0" || pb == "0" {
		// Port 0 asks the kernel for a free port, so two of them are two
		// sockets by definition.
		return false
	}
	if pa != pb {
		return false
	}
	if s.cfg.Inbound.AllowLAN {
		return ha == hb
	}
	// Both are rewritten to loopback below, so the port alone decides.
	return true
}

// handleMixed serves one listener as both SOCKS5 and HTTP, which is what a
// client means when socks5_addr and http_addr carry the same address. The
// first byte decides: SOCKS5 opens with its version, an HTTP request line
// opens with an ASCII method.
func (s *Server) handleMixed(c net.Conn, src string) {
	_ = c.SetReadDeadline(time.Now().Add(s.connectTimeout))
	var head [1]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		_ = c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	replay := &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(head[:]), c)}
	if head[0] == socksVer5 {
		s.handleSOCKS5(replay, src)
		return
	}
	s.handleHTTP(replay, src)
}

// prefixConn puts a byte that was read for protocol sniffing back in front of
// the stream, so the handler that receives the connection still sees it from
// its first byte.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite and CloseRead pass the TCP half-close through. The embedded
// net.Conn interface does not carry them, and without these a CONNECT tunnel
// opened on a mixed port would never hand the client a clean end of stream:
// pipe() half-closes the destination when the source reaches EOF, and that
// half-close is what tells the browser the response is over.
func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *prefixConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func (s *Server) acceptLoop(ln net.Listener, name string, handler func(net.Conn, string)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.closing.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warnf("%s inbound accept: %v", name, err)
			continue
		}
		if !s.cfg.Inbound.AllowLAN && !netutil.IsLoopbackAddr(conn.RemoteAddr()) {
			s.log.Warnf("%s inbound refused non-loopback client %s (allow_lan is false)", name, conn.RemoteAddr())
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			handler(conn, conn.RemoteAddr().String())
		}()
	}
}

// Close stops the listeners and kills live sessions. It is idempotent.
func (s *Server) Close() error {
	if s.closing.Swap(true) {
		return nil
	}
	s.mu.Lock()
	listeners := s.listeners
	s.listeners = nil
	s.mu.Unlock()
	for _, ln := range listeners {
		_ = ln.Close()
	}
	s.reg.CloseAll()
	s.wg.Wait()
	return nil
}

// route resolves the effective action for a destination.
func (s *Server) route(ctx context.Context, host string, port uint16) rules.Result {
	ip, _ := netip.ParseAddr(host)
	res := s.engine.Match(host, ip, port)
	if !res.NeedResolve {
		return res
	}
	rctx, cancel := context.WithTimeout(ctx, s.dnsTimeout)
	defer cancel()
	resolved, err := netutil.ResolveHost(rctx, host)
	if err != nil {
		s.log.Debugf("resolve %s failed (%v); falling back to proxy", host, err)
		return rules.Result{Action: rules.ActionProxy, Rule: "dns-failed -> proxy", Index: -1}
	}
	return s.engine.Match(host, resolved, port)
}

// dial applies the routing decision and opens the outbound stream.
func (s *Server) dial(ctx context.Context, host string, port uint16) (net.Conn, ruleResult) {
	res := s.route(ctx, host, port)
	rr := ruleResult{Action: res.Action, Rule: res.Rule}
	switch res.Action {
	case rules.ActionReject:
		rr.Outbound = "reject"
		rr.Err = ErrRejected
		return nil, rr
	case rules.ActionDirect:
		rr.Outbound = s.direct.Name()
		conn, err := s.dialWith(ctx, s.direct, host, port)
		rr.Err = err
		return conn, rr
	default:
		out := s.outbound()
		rr.Outbound = out.Name()
		conn, err := s.dialWith(ctx, out, host, port)
		rr.Err = err
		return conn, rr
	}
}

func (s *Server) dialWith(ctx context.Context, out Outbound, host string, port uint16) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, s.connectTimeout)
	defer cancel()
	return out.Dial(dctx, "tcp", netutil.JoinHostPort(host, port))
}

// pipe copies src into dst until EOF or the idle deadline expires, then
// half-closes dst so the peer observes a clean end of stream.
func pipe(dst, src net.Conn, idle time.Duration) {
	buf := make([]byte, 32*1024)
	for {
		if idle > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idle))
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// relay joins a client and an upstream socket, counting bytes in both
// directions, and returns once both directions have finished.
func (s *Server) relay(sess *Session, client, upstream net.Conn) {
	c := &countingConn{Conn: client, read: &sess.up, write: &sess.down}
	u := &countingConn{Conn: upstream, read: &sess.down, write: &sess.up}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pipe(u, c, s.idleTimeout)
	}()
	go func() {
		defer wg.Done()
		pipe(c, u, s.idleTimeout)
	}()
	wg.Wait()
}

// drainBuffered forwards bytes the protocol reader already pulled off the
// socket before the handshake finished.
func drainBuffered(br *bufio.Reader, dst net.Conn) error {
	if br.Buffered() == 0 {
		return nil
	}
	buf := make([]byte, br.Buffered())
	if _, err := io.ReadFull(br, buf); err != nil {
		return err
	}
	_, err := dst.Write(buf)
	return err
}

// splitHostPort is a tolerant net.SplitHostPort for proxy targets that may
// omit the port, in which case fallback is used.
func splitHostPort(target string, fallback uint16) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		var addrErr *net.AddrError
		if errors.As(err, &addrErr) && strings.Contains(addrErr.Err, "missing port") {
			return strings.Trim(target, "[]"), fallback, nil
		}
		return "", 0, err
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("bad port %q", portStr)
	}
	return host, uint16(p), nil
}
