package diag

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"vvpn/internal/core"
)

// The DNS panel: where does a name lookup actually go, and can anybody watch it
// happen? Both halves of the answer are measured, not assumed.
//
//   - What the operating system is configured to use. Those resolvers are the
//     ones every program that ignores the proxy keeps asking, and they are what
//     a tunnel either captures (dns-hijack) or leaves alone.
//   - What the client's own resolver block points at, asked for real so the
//     panel shows an answer and a round trip instead of a configuration dump.

// The three verdicts the panel colours a row with.
const (
	riskOK   = "ok"
	riskWarn = "warn"
	riskLeak = "leak"
)

// dnsCanary is a name asked of every resolver, plus who the answer is supposed
// to belong to. The owner is the check that does not depend on a list: a
// resolver that answers "www.google.com" with an address registered to
// somebody else is being intercepted, whatever address it picked.
type dnsCanary struct {
	Name  string
	Type  string
	Owner []string
}

// dnsCanaries are the names asked of every resolver. A public name that has to
// resolve everywhere is the point: an empty answer says more about the resolver
// than about the name.
var dnsCanaries = []dnsCanary{
	{Name: "www.google.com", Type: "A", Owner: []string{"google"}},
	{Name: "www.youtube.com", Type: "A", Owner: []string{"google"}},
}

// poisonedAnswers are the addresses the GFW is documented to answer with when
// it injects a response. Seeing one is proof that something on the path is
// rewriting DNS, whatever the resolver claims to be.
var poisonedAnswers = map[string]bool{
	"4.36.66.178": true, "8.7.198.45": true, "37.61.54.158": true,
	"46.82.174.68": true, "59.24.3.173": true, "64.33.88.161": true,
	"64.33.99.47": true, "64.66.163.251": true, "65.104.202.252": true,
	"65.160.219.113": true, "66.45.252.237": true, "72.14.205.99": true,
	"72.14.205.104": true, "77.4.7.92": true, "78.16.49.15": true,
	"92.242.140.21": true, "93.46.8.89": true, "118.5.49.6": true,
	"120.19.4.50": true, "128.121.126.139": true, "159.106.121.75": true,
	"169.132.13.103": true, "192.67.198.6": true, "202.106.1.2": true,
	"203.161.230.171": true, "203.98.7.65": true, "207.12.88.98": true,
	"208.56.31.43": true, "209.145.54.50": true, "209.220.30.174": true,
	"209.36.73.33": true, "211.94.66.147": true, "213.169.251.35": true,
	"216.221.188.182": true, "216.234.179.13": true, "243.185.187.39": true,
	"249.129.46.48": true, "253.157.14.165": true,
	// Measured on 2026-10-01: every external resolver asked for
	// www.google.com over plain UDP/53 answered with this address, which is
	// not Google's. It is the injection signature on this line.
	"185.45.5.35": true,
}

// DNSLeakEntry is one resolver's row in the panel.
type DNSLeakEntry struct {
	Server     string      `json:"server"`
	Kind       string      `json:"kind"`
	Transport  string      `json:"transport"`
	RTTMS      int64       `json:"rtt_ms"`
	Answers    []DNSAnswer `json:"answers"`
	Poisoned   bool        `json:"poisoned"`
	IP         string      `json:"ip,omitempty"`
	Country    string      `json:"country,omitempty"`
	ASN        string      `json:"asn,omitempty"`
	Org        string      `json:"org,omitempty"`
	SameAsExit bool        `json:"same_as_exit"`
	Risk       string      `json:"risk"`
	// Canary is the name that was asked; Hijack* describe the answer that gave
	// the interception away, so the panel can name the owner it really has.
	Canary    string `json:"canary,omitempty"`
	HijackIP  string `json:"hijack_ip,omitempty"`
	HijackASN string `json:"hijack_asn,omitempty"`
	HijackOrg string `json:"hijack_org,omitempty"`
	Note      string `json:"note,omitempty"`
	Error     string `json:"error,omitempty"`
}

// DNSLeakReport is the whole panel.
type DNSLeakReport struct {
	Via         string         `json:"via"`
	Tun         bool           `json:"tun"`
	ExitIP      string         `json:"exit_ip,omitempty"`
	ExitCountry string         `json:"exit_country,omitempty"`
	ExitASN     string         `json:"exit_asn,omitempty"`
	SystemDNS   []string       `json:"system_dns"`
	Entries     []DNSLeakEntry `json:"entries"`
	Leaks       int            `json:"leaks"`
	Warnings    int            `json:"warnings"`
	Verdict     string         `json:"verdict"`
	VerdictKind string         `json:"verdict_kind"`
	ElapsedMS   int64          `json:"elapsed_ms"`
	TS          int64          `json:"ts"`
	Cached      bool           `json:"cached,omitempty"`
	Errors      []string       `json:"errors,omitempty"`
}

// dnsTarget is one resolver entry turned into something that can be asked.
type dnsTarget struct {
	Entry     string
	Kind      string
	Transport string
	Host      string
	Port      string
	URL       string
}

// queryable reports whether this entry can be asked directly.
func (t dnsTarget) queryable() bool {
	switch t.Transport {
	case "udp", "tcp", "tls", "https":
		return true
	}
	return false
}

// addr is the host:port the stream transports dial.
func (t dnsTarget) addr() string {
	if t.Host == "" {
		return ""
	}
	if t.Port == "" {
		return t.Host
	}
	return net.JoinHostPort(t.Host, t.Port)
}

// dnsRow pairs a row being filled in with the resolver it asks.
type dnsRow struct {
	entry  *DNSLeakEntry
	target dnsTarget
	canary dnsCanary
}

// parseDNSTarget classifies one resolver entry and works out how to reach it.
func parseDNSTarget(entry string) dnsTarget {
	s := strings.TrimSpace(entry)
	t := dnsTarget{Entry: s}
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "https://"), strings.HasPrefix(lower, "h3://"):
		t.Kind, t.Transport, t.URL = "doh", "https", s
		if u, err := url.Parse(s); err == nil {
			t.Host = u.Hostname()
			t.Port = u.Port()
			if t.Port == "" {
				t.Port = "443"
			}
		}
		return t
	case strings.HasPrefix(lower, "tls://"), strings.HasPrefix(lower, "dot://"):
		t.Kind, t.Transport = "dot", "tls"
		t.Host, t.Port = splitHostPortDefault(s[strings.Index(s, "://")+3:], "853")
		return t
	case strings.HasPrefix(lower, "quic://"):
		t.Kind, t.Transport = "doq", "quic"
		t.Host, t.Port = splitHostPortDefault(s[strings.Index(s, "://")+3:], "853")
		return t
	case strings.HasPrefix(lower, "dhcp://"):
		t.Kind, t.Transport = "dhcp", "dhcp"
		return t
	}
	if core.IsSystemResolver(s) {
		t.Kind, t.Transport = "system", "system"
		return t
	}
	t.Kind, t.Transport = "plain", "udp"
	t.Host, t.Port = splitHostPortDefault(s, "53")
	return t
}

// splitHostPortDefault splits host[:port], filling in the transport's default.
// A bare IPv6 address without brackets is treated as a host.
func splitHostPortDefault(raw, defPort string) (string, string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", defPort
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		return host, port
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return strings.Trim(s, "[]"), defPort
	}
	if strings.Count(s, ":") > 1 {
		// Bare IPv6 literal: the colons belong to the address.
		return s, defPort
	}
	return s, defPort
}

// ProbeDNSLeak answers the panel's question. servers is the resolver block the
// caller wants inspected; an empty list means only the operating system's own
// resolvers are reported. tun tells the assessment whether a tunnel is already
// capturing port 53.
func (p *Prober) ProbeDNSLeak(ctx context.Context, via Via, servers []string, tun, refresh bool) (DNSLeakReport, error) {
	servers = cleanResolverList(servers)
	key := cacheKey("dnsleak", string(via), boolKey(tun), strings.Join(servers, ","), p.proxyAddr())
	if !refresh {
		if hit, stored, ok := p.cache.get(key); ok {
			if rep, isRep := hit.(DNSLeakReport); isRep {
				rep.Cached = true
				rep.TS = stored.Unix()
				return rep, nil
			}
		}
	}

	start := p.nowTime()
	rep := DNSLeakReport{
		Via:       p.ViaUsed(via),
		Tun:       tun,
		SystemDNS: []string{},
		Entries:   []DNSLeakEntry{},
		TS:        start.Unix(),
	}

	systemDNS := SystemResolvers()
	rep.SystemDNS = systemDNS

	// The exit address is what a resolver is compared against: a resolver on
	// the same address as the exit belongs to the exit operator, and swapping
	// the exit without swapping the resolver is the classic half-done setup.
	if v, _, err := p.CheckIP(ctx, via, false); err == nil {
		rep.ExitIP, rep.ExitCountry, rep.ExitASN = v.IP, v.Country, v.ASN
	} else {
		rep.Errors = append(rep.Errors, "出口 IP 未取到："+err.Error())
	}

	// Build the row list: the machine's resolvers first (they are the ones a
	// tunnel either captures or does not), then the client's own block.
	var rows []dnsRow
	seen := map[string]bool{}
	add := func(entry DNSLeakEntry, t dnsTarget) {
		k := strings.ToLower(entry.Server)
		if k == "" || seen[k] {
			return
		}
		seen[k] = true
		rows = append(rows, dnsRow{entry: &entry, target: t})
	}
	for _, s := range systemDNS {
		t := parseDNSTarget(s)
		// A system resolver is a plain address in practice; "dhcp://auto" is
		// the only shape that names nothing to dial, and it stays unmeasured.
		if t.Kind != "plain" {
			t.Kind = "plain"
			if t.Host == "" {
				t.Transport = "system"
			} else {
				t.Transport = "udp"
			}
		}
		add(DNSLeakEntry{Server: s, Kind: "system", Transport: t.Transport, Answers: []DNSAnswer{}}, t)
	}
	for _, s := range servers {
		t := parseDNSTarget(s)
		add(DNSLeakEntry{Server: s, Kind: t.Kind, Transport: t.Transport, Answers: []DNSAnswer{}}, t)
	}
	if len(rows) == 0 {
		rep.VerdictKind, rep.Verdict = riskWarn, "没有读到任何解析器：系统里没有配置，客户端也没有指定"
		rep.ElapsedMS = p.nowTime().Sub(start).Milliseconds()
		return rep, nil
	}
	if len(rows) > 8 {
		rows = rows[:8]
		rep.Errors = append(rep.Errors, "解析器多于 8 个，只实测了前 8 个")
	}

	// Ask every resolver the same two names, four at a time.
	timeout := p.timeout()
	if timeout > 6*time.Second {
		timeout = 6 * time.Second
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		gate = make(chan struct{}, 4)
	)
	for i := range rows {
		r := &rows[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			gate <- struct{}{}
			defer func() { <-gate }()
			if !r.target.queryable() {
				mu.Lock()
				r.entry.Note = "未实测（" + r.target.Transport + "）"
				mu.Unlock()
				return
			}
			var (
				answers   []DNSAnswer
				transport string
				err       error
				rtt       int64
			)
			var canary dnsCanary
			for _, c := range dnsCanaries {
				begin := p.nowTime()
				answers, transport, err = p.exchangeDNS(ctx, r.target, c.Name, c.Type, timeout)
				rtt = p.nowTime().Sub(begin).Milliseconds()
				if err == nil && len(answers) > 0 {
					canary = c
					break
				}
			}
			mu.Lock()
			defer mu.Unlock()
			r.canary = canary
			r.entry.Canary = canary.Name
			r.entry.Transport = transport
			r.entry.RTTMS = rtt
			r.entry.Answers = answers
			if err != nil {
				r.entry.Error = err.Error()
				return
			}
			for _, a := range answers {
				if a.Type == "A" && poisonedAnswers[a.Value] {
					r.entry.Poisoned = true
					break
				}
			}
		}()
	}
	wg.Wait()

	for i := range rows {
		rows[i].entry.IP = resolverIP(rows[i].target)
	}

	// One batched lookup covers both halves: where each resolver sits, and who
	// owns each address a resolver answered with. The second half is the check
	// that needs no list of known-bad addresses: an answer to "www.google.com"
	// that belongs to somebody else is an interception, whichever address was
	// picked to hide it.
	var probeIPs []string
	for i := range rows {
		if ip := rows[i].entry.IP; ip != "" && !isPrivateAddr(ip) {
			probeIPs = append(probeIPs, ip)
		}
		for _, a := range rows[i].entry.Answers {
			if a.Type == "A" && !isPrivateAddr(a.Value) {
				probeIPs = append(probeIPs, a.Value)
			}
		}
	}
	geo, notes := p.lookupGeo(ctx, via, dedupeStrings(probeIPs))
	rep.Errors = append(rep.Errors, notes...)
	for i := range rows {
		e := rows[i].entry
		if g, ok := geo[e.IP]; ok {
			e.Country, e.ASN, e.Org = g.Country, g.ASN, g.Org
		}
		// The ownership check runs even on a row the address list already
		// flagged: naming the owner the answer really has is what turns "a
		// known-bad address" into "somebody on the path is answering for
		// Google", and that needs the lookup either way.
		if len(e.Answers) == 0 || len(rows[i].canary.Owner) == 0 {
			continue
		}
		for _, a := range e.Answers {
			if a.Type != "A" {
				continue
			}
			g, ok := geo[a.Value]
			if !ok || g.ASN == "" {
				continue
			}
			if !ownedBy(g, rows[i].canary.Owner) {
				e.Poisoned = true
				e.HijackIP, e.HijackASN, e.HijackOrg = a.Value, g.ASN, g.Org
				break
			}
		}
	}

	rep.Entries = make([]DNSLeakEntry, 0, len(rows))
	for i := range rows {
		e := rows[i].entry
		assessDNS(e, tun, rep.ExitIP)
		switch e.Risk {
		case riskLeak:
			rep.Leaks++
		case riskWarn:
			rep.Warnings++
		}
		rep.Entries = append(rep.Entries, *e)
	}
	switch {
	case rep.Leaks > 0:
		rep.VerdictKind = riskLeak
		rep.Verdict = fmt.Sprintf("发现 %d 处泄漏风险：明文解析器，或解析结果已被污染", rep.Leaks)
	case rep.Warnings > 0:
		rep.VerdictKind = riskWarn
		rep.Verdict = fmt.Sprintf("%d 个解析器没有加密，但查询仍走在本机链路上", rep.Warnings)
	default:
		rep.VerdictKind = riskOK
		rep.Verdict = "所有解析器要么加密，要么已被隧道接管"
	}
	sort.Strings(rep.Errors)
	rep.ElapsedMS = p.nowTime().Sub(start).Milliseconds()
	p.cache.put(key, rep)
	return rep, nil
}

// assessDNS turns the measured facts into the row's verdict and the sentence
// that explains it. Order matters: evidence of tampering outranks everything.
func assessDNS(e *DNSLeakEntry, tun bool, exitIP string) {
	prefix := e.Note
	e.Note = ""
	e.SameAsExit = e.IP != "" && exitIP != "" && e.IP == exitIP
	switch {
	case e.Poisoned:
		e.Risk = riskLeak
		if e.HijackIP != "" {
			e.Note = "解析 " + e.Canary + " 得到 " + e.HijackIP + "，它属于 " +
				firstString(e.HijackASN, "未知 ASN") + " " + firstString(e.HijackOrg, "未知机构") +
				"：链路上有东西在伪造应答"
		} else {
			e.Note = "解析结果命中已知污染地址：链路上有东西在伪造应答"
		}
	case e.Kind == "system" || e.Kind == "dhcp":
		if tun {
			e.Risk = riskOK
			e.Note = "TUN 已接管 53 端口，发往它的查询会被 dns-hijack 收回内核解析器"
		} else {
			e.Risk = riskLeak
			e.Note = "系统解析器，明文 UDP/53，不经代理：不遵守系统代理的程序会把域名直接送出去"
		}
	case e.Kind == "plain":
		switch {
		case isPrivateAddr(e.IP) && !tun:
			e.Risk = riskLeak
			e.Note = "局域网内的解析器，明文查询走本机链路，运营商或路由器都能看到"
		case tun:
			e.Risk = riskWarn
			e.Note = "明文 UDP/53，但已被隧道接管；解析器仍能看到查询内容"
		default:
			e.Risk = riskWarn
			e.Note = "明文 UDP/53，未加密；查询经内核出口发出，解析器能看到你查过什么"
		}
	case e.Kind == "doh", e.Kind == "dot":
		e.Risk = riskOK
		e.Note = "加密解析，链路上看不到查询内容"
	case e.Kind == "doq":
		e.Risk = riskWarn
		e.Note = "DoQ（QUIC 上的 DNS）：加密，但本客户端暂不做实测"
	default:
		e.Risk = riskWarn
		e.Note = "未识别的解析器类型"
	}
	if e.Error != "" && e.Risk == riskOK {
		e.Risk = riskWarn
	}
	if e.SameAsExit {
		if e.Risk == riskOK {
			e.Risk = riskWarn
		}
		e.Note += "；解析器与出口是同一个地址（" + exitIP + "）"
	}
	if prefix != "" {
		e.Note = prefix + "；" + e.Note
	}
}

// resolverIP is the resolver's own address, when the entry names one.
func resolverIP(t dnsTarget) string {
	host := strings.Trim(t.Host, "[]")
	if host == "" {
		return ""
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return ""
	}
	return host
}

// isPrivateAddr reports whether an address cannot be reached from the internet.
func isPrivateAddr(host string) bool {
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

// exchangeDNS asks one resolver one question and reports which transport
// actually answered.
func (p *Prober) exchangeDNS(ctx context.Context, t dnsTarget, name, qtype string, timeout time.Duration) ([]DNSAnswer, string, error) {
	id := uint16(p.nowTime().UnixNano() & 0xffff)
	msg, err := dnsQueryMessage(name, qtype, id)
	if err != nil {
		return nil, t.Transport, err
	}
	switch t.Transport {
	case "https":
		raw, err := p.dnsOverDoH(ctx, t.URL, msg)
		if err != nil {
			return nil, "https", err
		}
		answers, derr := decodeDNSAnswers(raw, qtype)
		return answers, "https", derr
	case "tls":
		raw, err := dnsOverTLS(ctx, t.addr(), t.Host, msg, timeout)
		if err != nil {
			return nil, "tls", err
		}
		answers, derr := decodeDNSAnswers(raw, qtype)
		return answers, "tls", derr
	default:
		raw, err := dnsOverUDP(ctx, t.addr(), msg, timeout)
		if err == nil {
			answers, derr := decodeDNSAnswers(raw, qtype)
			if derr == nil {
				return answers, "udp", nil
			}
			err = derr
		}
		// A truncated answer or a UDP black hole is normal on hostile
		// networks; TCP is a second attempt at the same question, not a
		// different one.
		raw, terr := dnsOverTCP(ctx, t.addr(), msg, timeout)
		if terr != nil {
			return nil, "udp", err
		}
		answers, derr := decodeDNSAnswers(raw, qtype)
		if derr != nil {
			return nil, "tcp", derr
		}
		return answers, "tcp", nil
	}
}

// decodeDNSAnswers turns a response message into the panel's answer list.
func decodeDNSAnswers(raw []byte, qtype string) ([]DNSAnswer, error) {
	rep, err := parseDNSReply(raw)
	if err != nil {
		return nil, err
	}
	if rep.RCode != 0 {
		return nil, fmt.Errorf("解析器返回 %s", dnsRCodeName(rep.RCode))
	}
	out := make([]DNSAnswer, 0, len(rep.Answers))
	for _, a := range rep.Answers {
		switch a.Type {
		case dnsTypeA, dnsTypeAAAA, dnsTypeCNAME, dnsTypeTXT, dnsTypePTR:
			out = append(out, DNSAnswer{Type: dohTypeName(a.Type), Value: a.Data, TTL: int(a.TTL)})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("解析器返回了空应答（%s）", strings.ToUpper(qtype))
	}
	return out, nil
}

// dnsOverUDP sends one query over a datagram socket. Stray datagrams from an
// earlier socket are skipped rather than read as the answer.
func dnsOverUDP(ctx context.Context, addr string, msg []byte, timeout time.Duration) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	want := binary.BigEndian.Uint16(msg[:2])
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 2 && binary.BigEndian.Uint16(buf[:2]) == want {
			return buf[:n], nil
		}
	}
}

// dnsOverTCP sends one query over a length-prefixed stream.
func dnsOverTCP(ctx context.Context, addr string, msg []byte, timeout time.Duration) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return dnsOverStream(conn, msg, timeout)
}

// dnsOverTLS does the same over an encrypted stream, which is what a tls://
// resolver entry means.
func dnsOverTLS(ctx context.Context, addr, serverName string, msg []byte, timeout time.Duration) ([]byte, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if host := strings.Trim(serverName, "[]"); host != "" {
		if _, err := netip.ParseAddr(host); err != nil {
			cfg.ServerName = host
		}
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return dnsOverStream(conn, msg, timeout)
}

// dnsOverStream writes the two-byte length prefix RFC 1035 requires on a
// stream transport and reads the framed answer back.
func dnsOverStream(conn net.Conn, msg []byte, timeout time.Duration) ([]byte, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	frame := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(frame, uint16(len(msg)))
	copy(frame[2:], msg)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n <= 0 {
		return nil, fmt.Errorf("DNS 响应长度为 0")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// dnsOverDoH posts the query to an RFC 8484 endpoint.
func (p *Prober) dnsOverDoH(ctx context.Context, rawURL string, msg []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, body, err := p.do(ctx, ViaDirect, req, clientOpts{})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &statusError{URL: rawURL, Code: resp.StatusCode}
	}
	return body, nil
}

// geoInfo is one address's owner, as the batch endpoint reports it.
type geoInfo struct {
	Country string
	ASN     string
	Org     string
}

// ownedBy reports whether an address belongs to one of the expected owners. The
// match is on the organisation text rather than on a fixed ASN list, because a
// large provider announces from several autonomous systems and a stale list
// would turn a clean answer into a false alarm.
func ownedBy(g geoInfo, owners []string) bool {
	haystack := strings.ToLower(g.Org + " " + g.ASN)
	for _, owner := range owners {
		if owner != "" && strings.Contains(haystack, strings.ToLower(owner)) {
			return true
		}
	}
	return false
}

// lookupGeo asks one endpoint about several addresses in a single request. A
// failure comes back as a note: knowing where an address sits is useful, and
// the static answer list keeps working without it.
func (p *Prober) lookupGeo(ctx context.Context, via Via, ips []string) (map[string]geoInfo, []string) {
	out := map[string]geoInfo{}
	if len(ips) == 0 {
		return out, nil
	}
	if len(ips) > 20 {
		ips = ips[:20]
	}
	query := make([]map[string]string, 0, len(ips))
	for _, ip := range ips {
		query = append(query, map[string]string{
			"query":  ip,
			"fields": "status,country,countryCode,as,asname,isp,org,query",
		})
	}
	payload, err := json.Marshal(query)
	if err != nil {
		return out, nil
	}
	req, err := http.NewRequest(http.MethodPost, urlResolverGeoBatch, bytes.NewReader(payload))
	if err != nil {
		return out, nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, body, err := p.do(ctx, via, req, clientOpts{})
	if err != nil {
		return out, []string{"地址归属查询失败：" + err.Error()}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return out, []string{"地址归属查询返回 HTTP " + itoa(resp.StatusCode)}
	}
	var parsed []struct {
		Status      string `json:"status"`
		Query       string `json:"query"`
		CountryCode string `json:"countryCode"`
		ISP         string `json:"isp"`
		Org         string `json:"org"`
		AS          string `json:"as"`
		ASName      string `json:"asname"`
	}
	if err := decodeJSON(body, &parsed); err != nil {
		return out, []string{"地址归属查询无法解析：" + err.Error()}
	}
	for _, item := range parsed {
		if !strings.EqualFold(item.Status, "success") || item.Query == "" {
			continue
		}
		out[item.Query] = geoInfo{
			Country: strings.ToUpper(item.CountryCode),
			ASN:     item.AS,
			Org:     firstString(item.Org, item.ASName, item.ISP),
		}
	}
	return out, nil
}

// dedupeStrings keeps the first occurrence of every value.
func dedupeStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// urlResolverGeoBatch is the one endpoint that answers about several addresses
// in a single request, which keeps the panel to one outbound call.
const urlResolverGeoBatch = "http://ip-api.com/batch"

// cleanResolverList trims and de-duplicates a resolver list.
func cleanResolverList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		key := strings.ToLower(s)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}

// boolKey keeps the cache key stable across the two tunnel states.
func boolKey(v bool) string {
	if v {
		return "tun"
	}
	return "notun"
}
