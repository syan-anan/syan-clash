package proxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"vvpn/internal/netutil"
	"vvpn/internal/rules"
)

const (
	socksVer5 = 0x05

	socksAuthNone         = 0x00
	socksAuthUserPass     = 0x02
	socksAuthNoAcceptable = 0xFF

	socksCmdConnect = 0x01

	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04

	socksRepSucceeded      = 0x00
	socksRepGeneralFailure = 0x01
	socksRepNotAllowed     = 0x02
	socksRepHostUnreach    = 0x04
	socksRepConnRefused    = 0x05
	socksRepCmdNotSupport  = 0x07
	socksRepAtypNotSupport = 0x08
)

func (s *Server) handleSOCKS5(c net.Conn, src string) {
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(s.connectTimeout))
	br := bufio.NewReader(c)

	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	if head[0] != socksVer5 {
		s.log.Debugf("socks5 %s: unsupported version %d", src, head[0])
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	wantAuth := s.cfg.Inbound.Username != "" || s.cfg.Inbound.Password != ""
	chosen := byte(socksAuthNoAcceptable)
	for _, m := range methods {
		if wantAuth && m == socksAuthUserPass {
			chosen = socksAuthUserPass
			break
		}
		if !wantAuth && m == socksAuthNone {
			chosen = socksAuthNone
			break
		}
	}
	if _, err := c.Write([]byte{socksVer5, chosen}); err != nil {
		return
	}
	if chosen == socksAuthNoAcceptable {
		s.log.Warnf("socks5 %s: no acceptable authentication method", src)
		return
	}
	if chosen == socksAuthUserPass && !s.socksUserPass(br, c, src) {
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	if req[0] != socksVer5 || req[2] != 0x00 {
		return
	}
	cmd, atyp := req[1], req[3]

	host, err := readSocksAddr(br, atyp)
	if err != nil {
		s.log.Debugf("socks5 %s: %v", src, err)
		s.writeSocksReply(c, socksRepAtypNotSupport)
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)

	if cmd != socksCmdConnect {
		s.log.Debugf("socks5 %s: command %#x not supported (CONNECT only)", src, cmd)
		s.writeSocksReply(c, socksRepCmdNotSupport)
		return
	}

	_ = c.SetReadDeadline(time.Time{})
	s.proxyStream(c, br, src, host, port, protoSOCKS5)
}

func (s *Server) socksUserPass(br *bufio.Reader, c net.Conn, src string) bool {
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return false
	}
	if head[0] != 0x01 {
		return false
	}
	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, user); err != nil {
		return false
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(br, plen); err != nil {
		return false
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(br, pass); err != nil {
		return false
	}
	ok := subtle.ConstantTimeCompare(user, []byte(s.cfg.Inbound.Username)) == 1 &&
		subtle.ConstantTimeCompare(pass, []byte(s.cfg.Inbound.Password)) == 1
	if ok {
		_, _ = c.Write([]byte{0x01, 0x00})
		return true
	}
	_, _ = c.Write([]byte{0x01, 0x01})
	s.log.Warnf("socks5 %s: authentication failed", src)
	return false
}

func readSocksAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case socksAtypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return netip.AddrFrom4([4]byte(b)).String(), nil
	case socksAtypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return netip.AddrFrom16([16]byte(b)).Unmap().String(), nil
	case socksAtypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		if len(b) == 0 {
			return "", errors.New("empty domain name")
		}
		return string(b), nil
	default:
		return "", fmt.Errorf("unsupported address type %#x", atyp)
	}
}

func (s *Server) writeSocksReply(c net.Conn, rep byte) {
	_, _ = c.Write([]byte{socksVer5, rep, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
}

const (
	protoSOCKS5 = "socks5"
	protoHTTP   = "http"
)

// proxyStream dials the destination, reports the outcome to the client in the
// protocol's own words, then relays bytes until either side closes.
func (s *Server) proxyStream(client net.Conn, br *bufio.Reader, src, host string, port uint16, proto string) {
	sess, ctx := s.reg.Add(context.Background(), ConnInfo{
		Source: src,
		Host:   host,
		Target: netutil.JoinHostPort(host, port),
		Action: string(rules.ActionProxy),
	})
	defer sess.Close()

	upstream, rr := s.dial(ctx, host, port)
	sess.setRoute(rr)
	if upstream == nil {
		if proto == protoSOCKS5 {
			s.writeSocksReply(client, socksRepForError(rr.Err))
		} else {
			writeHTTPError(client, httpStatusForError(rr.Err), rr.Err.Error())
		}
		return
	}
	defer func() { _ = upstream.Close() }()

	sess.attach(client)
	sess.attach(upstream)

	if proto == protoSOCKS5 {
		s.writeSocksReply(client, socksRepSucceeded)
	} else {
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
	}
	if err := drainBuffered(br, upstream); err != nil {
		return
	}
	s.relay(sess, client, upstream)
}

func socksRepForError(err error) byte {
	switch {
	case err == nil:
		return socksRepSucceeded
	case errors.Is(err, ErrRejected):
		return socksRepNotAllowed
	case errors.Is(err, syscall.ECONNREFUSED):
		return socksRepConnRefused
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return socksRepHostUnreach
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return socksRepHostUnreach
	}
	return socksRepGeneralFailure
}

func httpStatusForError(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrRejected):
		return http.StatusForbidden
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

func writeHTTPError(w io.Writer, status int, msg string) {
	body := msg + "\n"
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
}
