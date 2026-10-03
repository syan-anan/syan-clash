package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// Outbound is anything the router can send "proxy" traffic to.
type Outbound interface {
	// Name is the identifier shown in the UI and logs.
	Name() string
	// Dial opens a stream to addr ("host:port"). Only TCP is supported; UDP
	// is rejected by every implementation.
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
}

// Direct sends traffic out of the local machine.
type Direct struct {
	Timeout time.Duration
}

// Name implements Outbound.
func (d *Direct) Name() string { return "direct" }

// Dial implements Outbound.
func (d *Direct) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("direct: unsupported network %q", network)
	}
	nd := net.Dialer{Timeout: d.Timeout}
	return nd.DialContext(ctx, network, addr)
}

// Socks5Out forwards traffic to an upstream SOCKS5 proxy (RFC 1928 / 1929).
type Socks5Out struct {
	Addr     string
	Username string
	Password string
	Timeout  time.Duration
}

// Name implements Outbound.
func (s *Socks5Out) Name() string { return "socks5://" + s.Addr }

// Dial implements Outbound.
func (s *Socks5Out) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("socks5 outbound: unsupported network %q", network)
	}
	nd := net.Dialer{Timeout: s.Timeout}
	conn, err := nd.DialContext(ctx, "tcp", s.Addr)
	if err != nil {
		return nil, fmt.Errorf("socks5 outbound: dial %s: %w", s.Addr, err)
	}
	if err := s.handshake(conn, addr); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Time{})
	}
	return conn, nil
}

func (s *Socks5Out) handshake(conn net.Conn, addr string) error {
	budget := s.Timeout
	if budget <= 0 {
		budget = 10 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(budget))

	methods := []byte{0x00}
	if s.Username != "" || s.Password != "" {
		methods = []byte{0x00, 0x02}
	}
	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("socks5 outbound: greeting: %w", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("socks5 outbound: greeting reply: %w", err)
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("socks5 outbound: unexpected version %d", reply[0])
	}
	switch reply[1] {
	case 0x00:
	case 0x02:
		if err := s.auth(conn); err != nil {
			return err
		}
	case 0xFF:
		return errors.New("socks5 outbound: no acceptable authentication method")
	default:
		return fmt.Errorf("socks5 outbound: server chose unsupported method %#x", reply[1])
	}

	req, err := buildSocks5Request(addr)
	if err != nil {
		return err
	}
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 outbound: request: %w", err)
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5 outbound: request reply: %w", err)
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5 outbound: %s", socks5ReplyText(resp[1]))
	}
	var skip int
	switch resp[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return fmt.Errorf("socks5 outbound: bound address: %w", err)
		}
		skip = int(l[0])
	default:
		return fmt.Errorf("socks5 outbound: unknown address type %#x", resp[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(skip+2)); err != nil {
		return fmt.Errorf("socks5 outbound: bound address: %w", err)
	}
	return nil
}

func (s *Socks5Out) auth(conn net.Conn) error {
	if len(s.Username) > 255 || len(s.Password) > 255 {
		return errors.New("socks5 outbound: username/password longer than 255 bytes")
	}
	buf := []byte{0x01, byte(len(s.Username))}
	buf = append(buf, s.Username...)
	buf = append(buf, byte(len(s.Password)))
	buf = append(buf, s.Password...)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("socks5 outbound: auth write: %w", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("socks5 outbound: auth reply: %w", err)
	}
	if reply[1] != 0x00 {
		return errors.New("socks5 outbound: authentication rejected")
	}
	return nil
}

func buildSocks5Request(addr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("socks5 outbound: %q is not host:port", addr)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("socks5 outbound: bad port %q", portStr)
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			b := ip.As4()
			req = append(req, 0x01)
			req = append(req, b[:]...)
		} else {
			b := ip.As16()
			req = append(req, 0x04)
			req = append(req, b[:]...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("socks5 outbound: hostname %q longer than 255 bytes", host)
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	return req, nil
}

func socks5ReplyText(code byte) string {
	switch code {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown SOCKS5 reply code %#x", code)
	}
}
