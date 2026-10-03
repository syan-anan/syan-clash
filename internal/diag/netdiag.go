package diag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The network toolbox: DNS, TCP, TLS, MTU and traceroute. Everything here runs
// in-process - the ICMP calls go straight to iphlpapi and nothing spawns a
// command line, which is the one promise this client makes about its own
// behaviour.

// --- DNS ---

// DNSAnswer is one record.
type DNSAnswer struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl,omitempty"`
}

// DNSResult is one resolution attempt: the question, where it was asked and
// what came back.
type DNSResult struct {
	Name    string      `json:"name"`
	Type    string      `json:"type"`
	Server  string      `json:"server"`
	Via     string      `json:"via"`
	RTTMS   int64       `json:"rtt_ms"`
	Answers []DNSAnswer `json:"answers"`
	Error   string      `json:"error,omitempty"`
}

// ResolveDNS answers one query. A direct query goes over UDP first (TCP only
// as the fallback for a truncated answer); through the proxy a UDP datagram
// cannot traverse an HTTP CONNECT tunnel, so the query goes to DoH over the
// same path instead and says so.
func (p *Prober) ResolveDNS(ctx context.Context, name, qtype, server string, via Via) (DNSResult, error) {
	name = strings.TrimSpace(name)
	qtype = strings.ToUpper(strings.TrimSpace(qtype))
	if qtype == "" {
		qtype = "A"
	}
	res := DNSResult{Name: name, Type: qtype, Answers: []DNSAnswer{}}
	if name == "" {
		return res, fmt.Errorf("name is required")
	}
	if via == ViaProxy {
		res.Server = "dns.google"
		res.Via = "doh"
		start := p.nowTime()
		answers, err := p.dohQuery(ctx, name, qtype, via)
		res.RTTMS = p.nowTime().Sub(start).Milliseconds()
		res.Answers = answers
		if err != nil {
			res.Error = err.Error()
		}
		return res, nil
	}
	server = ensureDNSServer(server)
	res.Server = server
	start := p.nowTime()
	answers, err := lookupWith(ctx, lookupResolver(server, "udp", p.timeout()), name, qtype)
	if err == nil {
		res.Via = "udp"
		res.RTTMS = p.nowTime().Sub(start).Milliseconds()
		res.Answers = answers
		return res, nil
	}
	start = p.nowTime()
	answers, err2 := lookupWith(ctx, lookupResolver(server, "tcp", p.timeout()), name, qtype)
	res.RTTMS = p.nowTime().Sub(start).Milliseconds()
	if err2 == nil {
		res.Via = "tcp"
		res.Answers = answers
		return res, nil
	}
	res.Via = "udp"
	res.Error = err.Error()
	return res, nil
}

// lookupResolver builds a Go resolver that always asks the given server over
// the given transport.
func lookupResolver(server, network string, timeout time.Duration) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			nd := net.Dialer{Timeout: timeout}
			return nd.DialContext(ctx, network, server)
		},
	}
}

// lookupWith runs one typed lookup against a resolver.
func lookupWith(ctx context.Context, r *net.Resolver, name, qtype string) ([]DNSAnswer, error) {
	switch qtype {
	case "A", "AAAA":
		network := "ip4"
		if qtype == "AAAA" {
			network = "ip6"
		}
		ips, err := r.LookupNetIP(ctx, network, name)
		if err != nil {
			return nil, err
		}
		out := make([]DNSAnswer, 0, len(ips))
		for _, ip := range ips {
			out = append(out, DNSAnswer{Type: qtype, Value: ip.String()})
		}
		return out, nil
	case "TXT":
		txts, err := r.LookupTXT(ctx, name)
		if err != nil {
			return nil, err
		}
		out := make([]DNSAnswer, 0, len(txts))
		for _, t := range txts {
			out = append(out, DNSAnswer{Type: "TXT", Value: t})
		}
		return out, nil
	case "CNAME":
		cname, err := r.LookupCNAME(ctx, name)
		if err != nil {
			return nil, err
		}
		return []DNSAnswer{{Type: "CNAME", Value: strings.TrimSuffix(cname, ".")}}, nil
	case "NS":
		nss, err := r.LookupNS(ctx, name)
		if err != nil {
			return nil, err
		}
		out := make([]DNSAnswer, 0, len(nss))
		for _, ns := range nss {
			out = append(out, DNSAnswer{Type: "NS", Value: strings.TrimSuffix(ns.Host, ".")})
		}
		return out, nil
	case "MX":
		mxs, err := r.LookupMX(ctx, name)
		if err != nil {
			return nil, err
		}
		out := make([]DNSAnswer, 0, len(mxs))
		for _, mx := range mxs {
			out = append(out, DNSAnswer{Type: "MX", Value: itoa(int(mx.Pref)) + " " + strings.TrimSuffix(mx.Host, ".")})
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported record type %q", qtype)
	}
}

// dohResponse is the dns.google JSON shape.
type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
	Comment string `json:"Comment"`
}

// dohQuery asks dns.google through the chosen path.
func (p *Prober) dohQuery(ctx context.Context, name, qtype string, via Via) ([]DNSAnswer, error) {
	u := "https://dns.google/resolve?name=" + url.QueryEscape(name) + "&type=" + url.QueryEscape(qtype)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, body, err := p.do(ctx, via, req, clientOpts{})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &statusError{URL: u, Code: resp.StatusCode}
	}
	var dr dohResponse
	if err := decodeJSON(body, &dr); err != nil {
		return nil, err
	}
	if dr.Status != 0 {
		return nil, fmt.Errorf("%s", firstString(dr.Comment, "dns status "+itoa(dr.Status)))
	}
	out := make([]DNSAnswer, 0, len(dr.Answer))
	for _, a := range dr.Answer {
		v := a.Data
		switch a.Type {
		case 16:
			v = strings.Trim(v, "\"")
		case 2, 5:
			v = strings.TrimSuffix(v, ".")
		}
		out = append(out, DNSAnswer{Type: dohTypeName(a.Type), Value: v, TTL: a.TTL})
	}
	return out, nil
}

// ensureDNSServer fills in the port and the default server.
func ensureDNSServer(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "8.8.8.8:53"
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		return net.JoinHostPort(s, "53")
	}
	return s
}

// dohTypeName maps the numeric record type back to its name.
func dohTypeName(t int) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	}
	return itoa(t)
}

// --- TCP ---

// TCPResult is one connect attempt.
type TCPResult struct {
	OK        bool   `json:"ok"`
	ConnectMS int64  `json:"connect_ms"`
	Resolved  string `json:"resolved"`
	ViaUsed   string `json:"via_used"`
	Stage     string `json:"stage,omitempty"`
	Error     string `json:"error,omitempty"`
}

// TCPPing opens and closes one connection, reporting how long the path took.
func (p *Prober) TCPPing(ctx context.Context, host string, port int, via Via, timeoutMS int) (TCPResult, error) {
	host = strings.TrimSpace(host)
	res := TCPResult{ViaUsed: p.ViaUsed(via)}
	if host == "" {
		return res, fmt.Errorf("host is required")
	}
	if port <= 0 || port > 65535 {
		port = 443
	}
	timeout := clampTimeoutMS(timeoutMS, p.timeout())
	dst, err := resolveIPv4(ctx, host)
	if err != nil {
		res.Stage = "resolve"
		res.Error = err.Error()
		return res, nil
	}
	res.Resolved = dst.String()
	d := &dialer{via: via, proxyAddr: p.proxyAddr, fallbackAddr: p.fallbackAddr, timeout: timeout, userAgent: UAProbe}
	start := p.nowTime()
	conn, err := d.dial(ctx, "tcp", net.JoinHostPort(dst.String(), itoa(port)))
	if err != nil {
		res.Stage = "connect"
		res.Error = err.Error()
		return res, nil
	}
	_ = conn.Close()
	res.OK = true
	res.ConnectMS = p.nowTime().Sub(start).Milliseconds()
	return res, nil
}

// --- TLS ---

// TLSCertInfo is one certificate of the chain.
type TLSCertInfo struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	DaysLeft  int      `json:"days_left"`
	DNSNames  []string `json:"dns_names,omitempty"`
	Serial    string   `json:"serial"`
}

// TLSResult describes the handshake and the chain the server presented.
type TLSResult struct {
	OK         bool          `json:"ok"`
	TLSVersion string        `json:"tls_version"`
	Cipher     string        `json:"cipher"`
	ALPN       string        `json:"alpn"`
	ChainOK    bool          `json:"chain_ok"`
	Certs      []TLSCertInfo `json:"certs"`
	Stage      string        `json:"stage,omitempty"`
	Error      string        `json:"error,omitempty"`
}

// TLSInspect performs the handshake, then verifies the chain by hand so the
// panel can show a bad certificate instead of only a failed handshake.
func (p *Prober) TLSInspect(ctx context.Context, host string, port int, via Via, alpn []string) (TLSResult, error) {
	host = strings.TrimSpace(host)
	res := TLSResult{Certs: []TLSCertInfo{}}
	if host == "" {
		return res, fmt.Errorf("host is required")
	}
	if port <= 0 || port > 65535 {
		port = 443
	}
	if len(alpn) == 0 {
		alpn = []string{"h2", "http/1.1"}
	}
	d := &dialer{via: via, proxyAddr: p.proxyAddr, fallbackAddr: p.fallbackAddr, timeout: p.timeout(), userAgent: UAProbe}
	raw, err := d.dial(ctx, "tcp", net.JoinHostPort(host, itoa(port)))
	if err != nil {
		res.Stage = "connect"
		res.Error = err.Error()
		return res, nil
	}
	defer func() { _ = raw.Close() }()
	tconn := tls.Client(raw, &tls.Config{ServerName: host, NextProtos: alpn, InsecureSkipVerify: true})
	hsCtx, cancel := context.WithTimeout(ctx, p.timeout()+2*time.Second)
	defer cancel()
	if err := tconn.HandshakeContext(hsCtx); err != nil {
		res.Stage = "handshake"
		res.Error = err.Error()
		return res, nil
	}
	st := tconn.ConnectionState()
	res.OK = true
	res.TLSVersion = tlsVersionName(st.Version)
	res.Cipher = tls.CipherSuiteName(st.CipherSuite)
	res.ALPN = st.NegotiatedProtocol
	for _, cert := range st.PeerCertificates {
		res.Certs = append(res.Certs, certInfo(cert, p.nowTime()))
	}
	if len(st.PeerCertificates) > 0 {
		opts := x509.VerifyOptions{}
		if _, perr := netip.ParseAddr(host); perr != nil {
			opts.DNSName = host
		}
		if _, verr := st.PeerCertificates[0].Verify(opts); verr == nil {
			res.ChainOK = true
		}
	}
	return res, nil
}

// certInfo flattens one certificate for the table.
func certInfo(cert *x509.Certificate, now time.Time) TLSCertInfo {
	if cert == nil {
		return TLSCertInfo{}
	}
	return TLSCertInfo{
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore.Format(time.RFC3339),
		NotAfter:  cert.NotAfter.Format(time.RFC3339),
		DaysLeft:  int(cert.NotAfter.Sub(now).Hours() / 24),
		DNSNames:  cert.DNSNames,
		Serial:    strings.ToUpper(cert.SerialNumber.Text(16)),
	}
}

// tlsVersionName names a version the way the panel shows it.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	}
	return "0x" + strings.ToUpper(itoa(int(v)))
}

// --- MTU ---

// MTUProbe is one bisect step.
type MTUProbe struct {
	Payload int   `json:"payload"`
	OK      bool  `json:"ok"`
	MS      int64 `json:"ms,omitempty"`
}

// MTUResult is the bisect outcome: the largest payload that made it through,
// and what that says about the path (payload + 28 bytes of IP/ICMP headers).
type MTUResult struct {
	OK         bool       `json:"ok"`
	PayloadMax int        `json:"payload_max"`
	PathMTU    int        `json:"path_mtu"`
	LocalMTU   int        `json:"local_mtu"`
	Probes     []MTUProbe `json:"probes"`
	Error      string     `json:"error,omitempty"`
}

// ProbeMTU finds the largest DF packet the path carries. min and max are total
// packet sizes; the payload is size minus the 20-byte IP and 8-byte ICMP
// headers.
func (p *Prober) ProbeMTU(ctx context.Context, host string, min, max, timeoutMS int) (MTUResult, error) {
	res := MTUResult{LocalMTU: localMTU(), Probes: []MTUProbe{}}
	host = strings.TrimSpace(host)
	if host == "" {
		return res, fmt.Errorf("host is required")
	}
	if min <= 0 || max <= 0 || min > max {
		min, max = 1200, 1500
	}
	if max > 1500 {
		max = 1500
	}
	if min < 576 {
		min = 576
	}
	dst, err := resolveIPv4(ctx, host)
	if err != nil {
		res.Error = err.Error()
		return res, nil
	}
	timeout := clampTimeoutMS(timeoutMS, p.timeout())

	unavailable := false
	try := func(payload int) bool {
		start := p.nowTime()
		_, perr := icmpProbe(dst, 64, payload, true, timeout)
		res.Probes = append(res.Probes, MTUProbe{Payload: payload, OK: perr == nil, MS: p.nowTime().Sub(start).Milliseconds()})
		if errors.Is(perr, errICMPUnavailable) {
			unavailable = true
		}
		return perr == nil
	}

	lo, hi := min-28, max-28
	if lo < 0 {
		lo = 0
	}
	best := -1
	if try(hi) {
		best = hi
	} else if !unavailable {
		for lo <= hi {
			mid := lo + (hi-lo)/2
			if try(mid) {
				best = mid
				lo = mid + 1
			} else {
				hi = mid - 1
			}
			if unavailable {
				break
			}
		}
	}
	if unavailable {
		res.Error = "icmp_unavailable"
		return res, nil
	}
	if best < 0 {
		res.Error = "路径不支持 DF 探测（可能被中间设备丢弃）"
		return res, nil
	}
	res.OK = true
	res.PayloadMax = best
	res.PathMTU = best + 28
	return res, nil
}

// --- traceroute ---

// TraceHop is one TTL step. An empty RTT list means every probe for this hop
// timed out.
type TraceHop struct {
	TTL     int       `json:"ttl"`
	IP      string    `json:"ip,omitempty"`
	RTTMS   []float64 `json:"rtt_ms"`
	Timeout bool      `json:"timeout,omitempty"`
}

// TraceRequest is one traceroute run.
type TraceRequest struct {
	Host      string
	MaxHops   int
	TimeoutMS int
	Queries   int
}

// traceRun is the shared state a polling UI renders while the walk continues.
type traceRun struct {
	mu      sync.Mutex
	host    string
	max     int
	hops    []TraceHop
	failMsg string
}

func (r *traceRun) add(hop TraceHop) {
	r.mu.Lock()
	r.hops = append(r.hops, hop)
	r.mu.Unlock()
}

func (r *traceRun) fail(msg string) {
	r.mu.Lock()
	r.failMsg = msg
	r.mu.Unlock()
}

func (r *traceRun) snapshot() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	hops := make([]TraceHop, len(r.hops))
	copy(hops, r.hops)
	return map[string]any{
		"host":     r.host,
		"max_hops": r.max,
		"hops":     hops,
		"done":     len(hops),
	}
}

// StartTrace launches a traceroute and returns immediately. The walk reports
// one hop at a time through the job snapshot.
func (p *Prober) StartTrace(req TraceRequest) (*Job, error) {
	host := strings.TrimSpace(req.Host)
	if host == "" {
		return nil, fmt.Errorf("host is required")
	}
	dst, err := resolveIPv4(context.Background(), host)
	if err != nil {
		return nil, err
	}
	maxHops := req.MaxHops
	if maxHops <= 0 {
		maxHops = 30
	}
	if maxHops > 64 {
		maxHops = 64
	}
	queries := req.Queries
	if queries <= 0 {
		queries = 2
	}
	if queries > 5 {
		queries = 5
	}
	timeout := clampTimeoutMS(req.TimeoutMS, 1000*time.Millisecond)

	run := &traceRun{host: host, max: maxHops, hops: []TraceHop{}}
	job, ctx, err := p.jobs.Begin("trace", run.snapshot)
	if err != nil {
		return nil, err
	}
	go func() {
		defer func() {
			run.mu.Lock()
			failMsg := run.failMsg
			run.mu.Unlock()
			state := JobDone
			if failMsg != "" {
				state = JobFailed
			} else if ctx.Err() != nil {
				state = JobCanceled
			}
			p.jobs.Finish(job, state, failMsg)
		}()
		run.walk(ctx, dst, maxHops, timeout, queries)
	}()
	return job, nil
}

// walk sends one echo per hop until the destination answers.
func (r *traceRun) walk(ctx context.Context, dst netip.Addr, maxHops int, timeout time.Duration, queries int) {
	for ttl := 1; ttl <= maxHops; ttl++ {
		if ctx.Err() != nil {
			return
		}
		hop := TraceHop{TTL: ttl, RTTMS: []float64{}}
		final := false
		for q := 0; q < queries; q++ {
			if ctx.Err() != nil {
				return
			}
			rep, err := icmpProbe(dst, ttl, 32, false, timeout)
			if errors.Is(err, errICMPUnavailable) {
				r.fail("icmp_unavailable")
				return
			}
			if err != nil {
				continue
			}
			if hop.IP == "" {
				hop.IP = rep.From.String()
			}
			hop.RTTMS = append(hop.RTTMS, float64(rep.RTT.Microseconds())/1000)
			if rep.Final {
				final = true
			}
		}
		if len(hop.RTTMS) == 0 {
			hop.Timeout = true
		}
		r.add(hop)
		if final {
			return
		}
	}
}

// --- ICMP ---

// icmpReply is the answer to one echo request.
type icmpReply struct {
	// From is the address that answered: the destination or a router.
	From netip.Addr
	// RTT is the measured round trip.
	RTT time.Duration
	// Final marks an answer from the destination itself.
	Final bool
}

// The ICMP sentinels. errICMPUnavailable is what the UI shows when the system
// refuses the probe outright; errICMPTimeout is a probe nobody answered.
var (
	errICMPUnavailable = errors.New("icmp_unavailable")
	errICMPTimeout     = errors.New("timeout")
)

// --- shared helpers ---

// resolveIPv4 turns a host into one IPv4 address. ICMP in this client is v4.
func resolveIPv4(ctx context.Context, host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is4() {
			return addr, nil
		}
		return netip.Addr{}, fmt.Errorf("%s is not an IPv4 address", host)
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("no IPv4 address for %s", host)
	}
	return ips[0], nil
}

// clampTimeoutMS applies the shipped bounds to a caller-provided timeout.
func clampTimeoutMS(ms int, fallback time.Duration) time.Duration {
	if ms <= 0 {
		return fallback
	}
	if ms < 500 {
		ms = 500
	}
	if ms > 60000 {
		ms = 60000
	}
	return time.Duration(ms) * time.Millisecond
}

// localMTU is the smallest MTU among the up, non-loopback interfaces, which is
// the safe assumption when the outgoing interface cannot be determined.
func localMTU() int {
	ifas, err := net.Interfaces()
	if err != nil {
		return 1500
	}
	best := 0
	for _, ifa := range ifas {
		if ifa.Flags&net.FlagUp == 0 || ifa.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifa.MTU <= 0 {
			continue
		}
		if best == 0 || ifa.MTU < best {
			best = ifa.MTU
		}
	}
	if best == 0 {
		return 1500
	}
	return best
}

// ipFromUint32 rebuilds an address from the network-order DWORD the ICMP API
// reports.
func ipFromUint32(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
