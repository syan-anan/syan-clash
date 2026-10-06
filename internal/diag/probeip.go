package diag

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// IPFlags are the booleans the public sources expose about an address. They are
// kept apart from the computed class so the panel can show the raw evidence
// next to the conclusion drawn from it.
type IPFlags struct {
	Proxy   bool `json:"proxy"`
	Hosting bool `json:"hosting"`
	Mobile  bool `json:"mobile"`
	Warp    bool `json:"warp"`
}

// IPReport is the answer to "what does the internet think this exit is?".
type IPReport struct {
	ViaUsed     string    `json:"via_used"`
	IP          string    `json:"ip"`
	Country     string    `json:"country,omitempty"`
	CountryName string    `json:"country_name,omitempty"`
	City        string    `json:"city,omitempty"`
	ASN         string    `json:"asn,omitempty"`
	Org         string    `json:"org,omitempty"`
	ISP         string    `json:"isp,omitempty"`
	PTR         string    `json:"ptr,omitempty"`
	Colo        string    `json:"colo,omitempty"`
	Class       string    `json:"class"`
	ClassLabel  string    `json:"class_label"`
	Native      bool      `json:"native"`
	Risk        int       `json:"risk"`
	RiskLabel   string    `json:"risk_label"`
	Flags       IPFlags   `json:"flags"`
	Sources     []string  `json:"sources"`
	Errors      []string  `json:"errors"`
	ElapsedMS   int64     `json:"elapsed_ms"`
	TS          int64     `json:"ts"`
	Cached      bool      `json:"cached"`
	Direct      *IPReport `json:"direct,omitempty"`
}

// The exit-class vocabulary. It is small on purpose: a panel that says
// "住宅 / 移动 / 机房 / 代理 / 未知" is actionable, a twelve-way taxonomy is not.
const (
	ClassResidential = "residential"
	ClassMobile      = "mobile"
	ClassHosting     = "hosting"
	ClassProxy       = "proxy"
	ClassUnknown     = "unknown"
)

var classLabels = map[string]string{
	ClassResidential: "住宅 IP",
	ClassMobile:      "移动网络",
	ClassHosting:     "机房 IP",
	ClassProxy:       "代理 · VPN",
	ClassUnknown:     "未知",
}

// datacenterWords identify the organisations that rent out servers. Matching
// one is the strongest offline signal that an address is not a home
// connection, and it keeps working when the online sources are unreachable.
var datacenterWords = []string{
	"amazon", "aws", "google", "microsoft", "azure", "digitalocean", "vultr",
	"linode", "akamai", "ovh", "hetzner", "oracle", "cloudflare", "alibaba",
	"tencent", "leaseweb", "choopa", "m247", "datacamp", "colocrossing",
	"contabo", "scaleway", "upcloud", "kamatera", "hostinger", "cloudsigma",
	"quadranet", "psychz", "gcore", "zenlayer", "cogent", "gige", "sharktech",
}

// The public endpoints the panel asks. Several are used because each one is
// wrong about something: one knows the flags, another knows the ASN, a third is
// simply the fastest. The panel merges them and records which one answered.
const (
	urlCloudflareTrace = "https://www.cloudflare.com/cdn-cgi/trace"
	urlIPWhoIs         = "https://ipwho.is/"
	urlIPSb            = "https://api.ip.sb/geoip"
	urlIPApi           = "http://ip-api.com/json/?fields=status,country,countryCode,city,isp,org,as,asname,mobile,proxy,hosting,query&lang=zh-CN"
)

// CheckIP runs the purity probe and reports where it went. refresh skips a
// cached answer, which is what the 重新检测 button asks for.
func (p *Prober) CheckIP(ctx context.Context, via Via, refresh bool) (IPReport, bool, error) {
	key := cacheKey("ip", string(via), p.proxyAddr())
	if !refresh {
		if hit, stored, ok := p.cache.get(key); ok {
			if rep, isRep := hit.(IPReport); isRep {
				rep.Cached = true
				rep.Direct = nil
				rep.TS = stored.Unix()
				return rep, true, nil
			}
		}
	}
	rep, err := p.IPReport(ctx, via)
	if rep.IP == "" && err != nil {
		return rep, false, err
	}
	rep.Cached = false
	p.cache.put(key, rep)
	return rep, false, err
}

// IPReport asks every source about the current exit and merges the answers. A
// source that fails is recorded and skipped: one endpoint being down must not
// blank the panel.
func (p *Prober) IPReport(ctx context.Context, via Via) (IPReport, error) {
	start := p.nowTime()
	rep := IPReport{
		ViaUsed: p.ViaUsed(via),
		Class:   ClassUnknown,
		Sources: []string{},
		Errors:  []string{},
		TS:      start.Unix(),
	}

	ctx, cancel := context.WithTimeout(ctx, p.timeout()+5*time.Second)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup
	note := func(source string) {
		mu.Lock()
		rep.Sources = append(rep.Sources, source)
		mu.Unlock()
	}
	fail := func(source string, err error) {
		mu.Lock()
		rep.Errors = append(rep.Errors, source+": "+err.Error())
		mu.Unlock()
	}

	wg.Add(4)
	go func() {
		defer wg.Done()
		text, err := p.getText(ctx, via, urlCloudflareTrace, UAProbe)
		if err != nil {
			fail("cloudflare", err)
			return
		}
		fields := parseTrace(text)
		mu.Lock()
		rep.IP = firstString(rep.IP, fields["ip"])
		rep.Colo = firstString(rep.Colo, fields["colo"])
		if fields["warp"] == "on" {
			rep.Flags.Warp = true
		}
		if loc := fields["loc"]; loc != "" && rep.Country == "" {
			rep.Country = strings.ToUpper(loc)
		}
		mu.Unlock()
		note("cloudflare.com/cdn-cgi/trace")
	}()
	go func() {
		defer wg.Done()
		var out struct {
			IP      string `json:"ip"`
			Success bool   `json:"success"`
			Country string `json:"country"`
			Code    string `json:"country_code"`
			City    string `json:"city"`
			Conn    struct {
				ASN    int    `json:"asn"`
				Org    string `json:"org"`
				ISP    string `json:"isp"`
				Domain string `json:"domain"`
			} `json:"connection"`
		}
		if err := p.getJSON(ctx, via, urlIPWhoIs, &out); err != nil {
			fail("ipwho.is", err)
			return
		}
		mu.Lock()
		rep.IP = firstString(rep.IP, out.IP)
		rep.Country = firstString(strings.ToUpper(out.Code), rep.Country)
		rep.CountryName = firstString(rep.CountryName, out.Country)
		if out.Conn.ASN > 0 {
			rep.ASN = firstString(rep.ASN, "AS"+itoa(out.Conn.ASN))
		}
		rep.Org = firstString(rep.Org, out.Conn.Org, out.Conn.Domain)
		rep.ISP = firstString(rep.ISP, out.Conn.ISP)
		mu.Unlock()
		note("ipwho.is")
	}()
	go func() {
		defer wg.Done()
		var out struct {
			IP      string `json:"ip"`
			Country string `json:"country_code"`
			ASN     int    `json:"asn"`
			Org     string `json:"asn_organization"`
			ISP     string `json:"isp"`
		}
		if err := p.getJSON(ctx, via, urlIPSb, &out); err != nil {
			fail("api.ip.sb", err)
			return
		}
		mu.Lock()
		rep.IP = firstString(rep.IP, out.IP)
		rep.Country = firstString(strings.ToUpper(out.Country), rep.Country)
		if out.ASN > 0 {
			rep.ASN = firstString(rep.ASN, "AS"+itoa(out.ASN))
		}
		rep.Org = firstString(rep.Org, out.Org)
		rep.ISP = firstString(rep.ISP, out.ISP)
		mu.Unlock()
		note("api.ip.sb/geoip")
	}()
	go func() {
		defer wg.Done()
		var out struct {
			Status      string `json:"status"`
			Query       string `json:"query"`
			Country     string `json:"country"`
			CountryCode string `json:"countryCode"`
			City        string `json:"city"`
			ISP         string `json:"isp"`
			Org         string `json:"org"`
			AS          string `json:"as"`
			ASName      string `json:"asname"`
			Mobile      bool   `json:"mobile"`
			Proxy       bool   `json:"proxy"`
			Hosting     bool   `json:"hosting"`
		}
		if err := p.getJSON(ctx, via, urlIPApi, &out); err != nil {
			fail("ip-api.com", err)
			return
		}
		if !strings.EqualFold(out.Status, "success") {
			fail("ip-api.com", &sourceError{Msg: "status=" + out.Status})
			return
		}
		mu.Lock()
		rep.IP = firstString(rep.IP, out.Query)
		rep.Country = firstString(strings.ToUpper(out.CountryCode), rep.Country)
		// ip-api is the only source that can answer in Chinese (lang=zh-CN),
		// so its place names win outright instead of racing the English ones.
		if out.Country != "" {
			rep.CountryName = out.Country
		}
		if out.City != "" {
			rep.City = out.City
		}
		rep.ISP = firstString(rep.ISP, out.ISP)
		rep.Org = firstString(rep.Org, out.Org, out.ASName)
		if rep.ASN == "" && strings.HasPrefix(strings.ToUpper(out.AS), "AS") {
			rep.ASN = out.AS
		}
		rep.Flags.Proxy = rep.Flags.Proxy || out.Proxy
		rep.Flags.Hosting = rep.Flags.Hosting || out.Hosting
		rep.Flags.Mobile = rep.Flags.Mobile || out.Mobile
		mu.Unlock()
		note("ip-api.com/json")
	}()
	wg.Wait()

	if rep.IP != "" {
		if ptr, err := p.lookupPTR(ctx, via, rep.IP); err == nil && ptr != "" {
			rep.PTR = ptr
			note("dns.google PTR")
		}
	}

	classify(&rep)
	rep.ElapsedMS = p.nowTime().Sub(start).Milliseconds()
	sort.Strings(rep.Sources)
	sort.Strings(rep.Errors)
	if rep.IP == "" {
		if len(rep.Errors) > 0 {
			return rep, &sourceError{Msg: "所有 IP 源都失败了：" + strings.Join(rep.Errors, "；")}
		}
		return rep, &sourceError{Msg: "没有拿到出口 IP"}
	}
	return rep, nil
}

// sourceError marks a probe that failed for a reason worth showing verbatim.
type sourceError struct{ Msg string }

func (e *sourceError) Error() string { return e.Msg }

// parseTrace turns the Cloudflare trace body into a field map.
func parseTrace(body string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// lookupPTR resolves the reverse name through DoH, which works through the
// proxy while plain DNS would not: UDP cannot cross an HTTP CONNECT tunnel.
func (p *Prober) lookupPTR(ctx context.Context, via Via, ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", &sourceError{Msg: "not an IP: " + ip}
	}
	rev, err := reverseName(parsed)
	if err != nil {
		return "", err
	}
	url := "https://dns.google/resolve?name=" + rev + "&type=PTR"
	var out struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := p.getJSON(ctx, via, url, &out); err != nil {
		return "", err
	}
	for _, a := range out.Answer {
		if a.Type == 12 && a.Data != "" {
			return strings.TrimSuffix(a.Data, "."), nil
		}
	}
	return "", nil
}

// reverseName builds the in-addr.arpa / ip6.arpa name for an address.
func reverseName(ip net.IP) (string, error) {
	const hex = "0123456789abcdef"
	if v4 := ip.To4(); v4 != nil {
		return itoa(int(v4[3])) + "." + itoa(int(v4[2])) + "." + itoa(int(v4[1])) + "." + itoa(int(v4[0])) + ".in-addr.arpa", nil
	}
	v6 := ip.To16()
	if v6 == nil {
		return "", &sourceError{Msg: "not an IP"}
	}
	var b strings.Builder
	for i := len(v6) - 1; i >= 0; i-- {
		b.WriteByte(hex[v6[i]>>4])
		b.WriteByte('.')
		b.WriteByte(hex[v6[i]&0x0f])
		b.WriteByte('.')
	}
	b.WriteString("ip6.arpa")
	return b.String(), nil
}

// classify fills in the class, the native flag and the risk score from the
// evidence gathered above. The order matters: a proxy flag outranks a hosting
// flag, because a rented server that also announces itself as a VPN is a VPN.
func classify(rep *IPReport) {
	haystack := strings.ToLower(strings.Join([]string{rep.Org, rep.ISP, rep.ASN, rep.PTR}, " "))
	datacenter := false
	for _, word := range datacenterWords {
		if strings.Contains(haystack, word) {
			datacenter = true
			break
		}
	}
	switch {
	case rep.Flags.Proxy || rep.Flags.Warp:
		rep.Class = ClassProxy
	case rep.Flags.Hosting || datacenter:
		rep.Class = ClassHosting
	case rep.Flags.Mobile:
		rep.Class = ClassMobile
	case rep.IP != "":
		rep.Class = ClassResidential
	default:
		rep.Class = ClassUnknown
	}
	rep.ClassLabel = classLabels[rep.Class]
	rep.Native = (rep.Class == ClassResidential || rep.Class == ClassMobile) &&
		!rep.Flags.Proxy && !rep.Flags.Hosting && !rep.Flags.Warp

	risk := 10
	switch rep.Class {
	case ClassHosting:
		risk += 40
	case ClassProxy:
		risk += 35
	case ClassUnknown:
		risk = 50
	}
	if rep.Flags.Warp {
		risk += 10
	}
	if datacenter && rep.Class != ClassHosting {
		risk += 15
	}
	if rep.PTR != "" && datacenter {
		risk += 15
	}
	if risk > 100 {
		risk = 100
	}
	if risk < 0 {
		risk = 0
	}
	rep.Risk = risk
	switch {
	case risk >= 70:
		rep.RiskLabel = "高风险"
	case risk >= 40:
		rep.RiskLabel = "中等"
	default:
		rep.RiskLabel = "干净"
	}
}
