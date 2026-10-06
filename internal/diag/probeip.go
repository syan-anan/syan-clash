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
	Region      string    `json:"region,omitempty"`
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
	urlIPApi           = "http://ip-api.com/json/?fields=status,country,countryCode,regionName,city,isp,org,as,asname,mobile,proxy,hosting,query&lang=zh-CN"
	urlCNPlace         = "https://ip.zxinc.org/api.php?type=json&ip="
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
			RegionName  string `json:"regionName"`
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
		if out.RegionName != "" {
			rep.Region = out.RegionName
		}
		if out.City != "" {
			rep.City = out.City
		}
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

	// A source that only knows English (ipwho.is, api.ip.sb) must not leave the
	// card reading "United States" when the country code has a Chinese name we
	// already know. ip-api's own answer wins whenever it came back Chinese.
	rep.CountryName = localisedCountry(rep.Country, rep.CountryName)

	// ip-api has no Chinese name for some mainland districts (a Hohhot address
	// came back as "Haoxinying"), and a Chinese library is the only thing that
	// fills that in. It is asked for CN exits only: for anything else its data
	// is wrong - a US address came back as Canada.
	if rep.Country == "CN" {
		if place, ok := p.probeCNPlace(ctx, via, rep.IP); ok {
			if place.City != "" {
				rep.City = place.City
			}
			if rep.Region == "" && place.Province != "" {
				rep.Region = place.Province
			}
			// The carrier only replaces an English one: "Chinanet" is not what a
			// Chinese reader calls their own line, the Chinese name is.
			if place.ISP != "" && !hasHan(rep.ISP) {
				rep.ISP = place.ISP
			}
			note("ip.zxinc.org")
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

// countryZH names the country codes that show up as proxy exits. It is only
// consulted when no source answered in Chinese, so a working ip-api call always
// wins over this table.
var countryZH = map[string]string{
	"CN": "中国",
	"HK": "中国香港",
	"MO": "中国澳门",
	"TW": "中国台湾",
	"US": "美国",
	"CA": "加拿大",
	"MX": "墨西哥",
	"BR": "巴西",
	"AR": "阿根廷",
	"CL": "智利",
	"JP": "日本",
	"KR": "韩国",
	"SG": "新加坡",
	"MY": "马来西亚",
	"TH": "泰国",
	"VN": "越南",
	"PH": "菲律宾",
	"ID": "印度尼西亚",
	"IN": "印度",
	"PK": "巴基斯坦",
	"BD": "孟加拉国",
	"GB": "英国",
	"IE": "爱尔兰",
	"FR": "法国",
	"DE": "德国",
	"NL": "荷兰",
	"BE": "比利时",
	"LU": "卢森堡",
	"CH": "瑞士",
	"AT": "奥地利",
	"IT": "意大利",
	"ES": "西班牙",
	"PT": "葡萄牙",
	"SE": "瑞典",
	"NO": "挪威",
	"DK": "丹麦",
	"FI": "芬兰",
	"IS": "冰岛",
	"PL": "波兰",
	"CZ": "捷克",
	"SK": "斯洛伐克",
	"HU": "匈牙利",
	"RO": "罗马尼亚",
	"BG": "保加利亚",
	"GR": "希腊",
	"UA": "乌克兰",
	"RU": "俄罗斯",
	"TR": "土耳其",
	"AE": "阿联酋",
	"SA": "沙特阿拉伯",
	"IL": "以色列",
	"IR": "伊朗",
	"EG": "埃及",
	"ZA": "南非",
	"NG": "尼日利亚",
	"KE": "肯尼亚",
	"AU": "澳大利亚",
	"NZ": "新西兰",
	"KZ": "哈萨克斯坦",
	"AM": "亚美尼亚",
	"GE": "格鲁吉亚",
	"MD": "摩尔多瓦",
}

// localisedCountry keeps a Chinese country name when there is one, and otherwise
// looks the country code up in the table above.
func localisedCountry(code, name string) string {
	if hasHan(name) {
		return name
	}
	if zh, ok := countryZH[strings.ToUpper(strings.TrimSpace(code))]; ok {
		return zh
	}
	return name
}

func hasHan(s string) bool {
	for _, r := range s {
		if r >= 0x4e00 && r <= 0x9fff {
			return true
		}
	}
	return false
}

// cnPlace is what the Chinese library knows: province, city and carrier, all
// in Chinese.
type cnPlace struct {
	Province string
	City     string
	ISP      string
}

// probeCNPlace asks the one Chinese library that answers in Chinese for a
// mainland address. Callers must only use it for CN exits: for anything else
// its data is wrong (a US address came back as Canada).
func (p *Prober) probeCNPlace(ctx context.Context, via Via, ip string) (cnPlace, bool) {
	if ip == "" {
		return cnPlace{}, false
	}
	var out struct {
		Code int `json:"code"`
		Data struct {
			Country string `json:"country"`
			Local   string `json:"local"`
		} `json:"data"`
	}
	if err := p.getJSON(ctx, via, urlCNPlace+ip, &out); err != nil {
		return cnPlace{}, false
	}
	if out.Code != 0 {
		return cnPlace{}, false
	}
	// country reads country<dash>province<dash>city.
	parts := strings.FieldsFunc(out.Data.Country, func(r rune) bool {
		return r == '\u2013' || r == '\u2014' || r == '-'
	})
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	place := cnPlace{ISP: strings.TrimSpace(out.Data.Local)}
	if len(parts) >= 2 {
		place.Province = parts[1]
	}
	if len(parts) >= 3 {
		place.City = parts[len(parts)-1]
	}
	return place, true
}
