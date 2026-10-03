package diag

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// UnlockTarget describes one service check. The markers are the evidence: a
// check without a matched marker on both sides cannot tell "this region is
// fine" from "this region gets a marketing page", so every target carries the
// strings that distinguish them and the panel reports which one matched.
type UnlockTarget struct {
	ID      string
	Name    string
	Group   string // stream | ai | other
	URL     string
	Regions string // optional: the same URL but answering with a region name
	// Unlocked / Blocked are comma-separated, case-insensitive substrings.
	Unlocked string
	Blocked  string
	// Trace marks a Cloudflare-style key=value body where loc= carries the
	// region and a 200 means the service answered at all.
	Trace bool
}

// unlockTargets is the built-in list. It is deliberately small and every entry
// has a plain-HTTP-visible signal: a panel that guesses is worse than a panel
// that says 无法判定.
var unlockTargets = []UnlockTarget{
	{
		ID: "netflix", Name: "Netflix", Group: "stream",
		URL:      "https://www.netflix.com/title/81215567",
		Unlocked: "netflix,剧集,watch,season,episode,play",
		Blocked:  "not available in your country,不可用,unavailable,oh no",
	},
	{
		ID: "youtube", Name: "YouTube Premium", Group: "stream",
		URL:      "https://www.youtube.com/premium",
		Unlocked: "premium,试用,subscribe",
		Blocked:  "not available in your country",
	},
	{
		ID: "disney", Name: "Disney+", Group: "stream",
		URL:      "https://www.disneyplus.com/",
		Unlocked: "disney,subscribe,stream",
		Blocked:  "not available,unavailable in your region",
	},
	{
		ID: "chatgpt", Name: "ChatGPT", Group: "ai",
		URL:   "https://chatgpt.com/cdn-cgi/trace",
		Trace: true,
	},
	{
		ID: "gemini", Name: "Gemini", Group: "ai",
		URL:      "https://gemini.google.com/app",
		Unlocked: "gemini,bard,google",
		Blocked:  "not available in your country,region",
	},
	{
		ID: "claude", Name: "Claude", Group: "ai",
		URL:      "https://claude.ai/",
		Unlocked: "claude,anthropic",
		Blocked:  "not available in your country,unavailable",
	},
}

// UnlockTargets lists the built-in checks.
func UnlockTargets() []UnlockTarget {
	out := make([]UnlockTarget, len(unlockTargets))
	copy(out, unlockTargets)
	return out
}

// UnlockStatus values.
const (
	UnlockOK      = "unlocked"
	UnlockPartial = "partial"
	UnlockBlocked = "blocked"
	UnlockTimeout = "timeout"
	UnlockError   = "error"
)

// UnlockResult is one service's verdict.
type UnlockResult struct {
	Service    string `json:"service"`
	Name       string `json:"name"`
	Group      string `json:"group"`
	Status     string `json:"status"`
	Region     string `json:"region,omitempty"`
	MS         int64  `json:"ms"`
	HTTPStatus int    `json:"http_status,omitempty"`
	FinalHost  string `json:"final_host,omitempty"`
	Marker     string `json:"matched_marker,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// UnlockReport is the whole sweep.
type UnlockReport struct {
	ViaUsed   string         `json:"via_used"`
	Results   []UnlockResult `json:"results"`
	ElapsedMS int64          `json:"elapsed_ms"`
	TS        int64          `json:"ts"`
	Cached    bool           `json:"cached"`
}

// ProbeUnlock checks every target through one path. only narrows the list to
// specific ids; an unknown id is ignored rather than failing the sweep.
func (p *Prober) ProbeUnlock(ctx context.Context, via Via, only []string) (UnlockReport, bool, error) {
	targets := filterTargets(only)
	key := cacheKey("unlock", string(via), ids(targets), p.proxyAddr())
	if hit, stored, ok := p.cache.get(key); ok {
		if rep, isRep := hit.(UnlockReport); isRep {
			rep.Cached = true
			rep.TS = stored.Unix()
			return rep, true, nil
		}
	}

	start := p.nowTime()
	rep := UnlockReport{ViaUsed: p.ViaUsed(via), Results: make([]UnlockResult, 0, len(targets)), TS: start.Unix()}

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t UnlockTarget) {
			defer wg.Done()
			res := p.checkOne(ctx, via, t)
			mu.Lock()
			rep.Results = append(rep.Results, res)
			mu.Unlock()
		}(t)
	}
	wg.Wait()

	sort.Slice(rep.Results, func(i, j int) bool { return rep.Results[i].Service < rep.Results[j].Service })
	rep.ElapsedMS = p.nowTime().Sub(start).Milliseconds()
	p.cache.put(key, rep)
	return rep, false, nil
}

// checkOne runs a single service check. A service that cannot be judged is
// reported as such: guessing here would send the user to a node that does not
// actually work.
func (p *Prober) checkOne(ctx context.Context, via Via, t UnlockTarget) UnlockResult {
	res := UnlockResult{Service: t.ID, Name: t.Name, Group: t.Group}
	reqCtx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()

	req, err := http.NewRequest(http.MethodGet, t.URL, nil)
	if err != nil {
		res.Status, res.Detail = UnlockError, err.Error()
		return res
	}
	start := p.nowTime()
	resp, body, err := p.do(reqCtx, via, req, clientOpts{ua: UABrowser, maxRedirects: 5, maxBytes: 256 << 10})
	res.MS = p.nowTime().Sub(start).Milliseconds()
	if err != nil {
		res.Status = UnlockError
		if reqCtx.Err() != nil {
			res.Status = UnlockTimeout
		}
		res.Detail = err.Error()
		if code := statusOf(err); code > 0 {
			res.HTTPStatus = code
			res.Status = UnlockBlocked
			res.Detail = "HTTP " + itoa(code)
		}
		return res
	}
	res.HTTPStatus = resp.StatusCode
	if resp.Request != nil && resp.Request.URL != nil {
		res.FinalHost = resp.Request.URL.Host
	}

	text := strings.ToLower(string(body))
	if t.Trace {
		fields := parseTrace(string(body))
		if loc := fields["loc"]; loc != "" {
			res.Region = strings.ToUpper(loc)
		}
		if resp.StatusCode == 200 {
			res.Status = UnlockOK
			res.Detail = "trace 200"
			if res.Region != "" {
				res.Detail += " loc=" + res.Region
			}
			return res
		}
	}

	if marker := matchMarker(text, t.Blocked); marker != "" {
		res.Status, res.Marker = UnlockBlocked, marker
		res.Detail = "命中封锁标记：" + marker
		return res
	}
	if marker := matchMarker(text, t.Unlocked); marker != "" {
		res.Status, res.Marker = UnlockOK, marker
		res.Detail = "命中解锁标记：" + marker
		return res
	}
	switch {
	case resp.StatusCode == 403 || resp.StatusCode == 451:
		res.Status = UnlockBlocked
		res.Detail = "HTTP " + itoa(resp.StatusCode)
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// The service answered and nothing on the page says "not here", but
		// the page did not confirm the region either.
		res.Status = UnlockPartial
		res.Detail = "HTTP 200，但没有命中判定标记"
	default:
		res.Status = UnlockPartial
		res.Detail = "HTTP " + itoa(resp.StatusCode)
	}
	return res
}

// matchMarker returns the first sub-string from a comma-separated list that the
// body contains.
func matchMarker(lowerBody, markers string) string {
	for _, m := range strings.Split(markers, ",") {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if strings.Contains(lowerBody, m) {
			return m
		}
	}
	return ""
}

// filterTargets honours an explicit id list and keeps the built-in order.
func filterTargets(only []string) []UnlockTarget {
	if len(only) == 0 {
		return UnlockTargets()
	}
	want := map[string]bool{}
	for _, id := range only {
		id = strings.ToLower(strings.TrimSpace(id))
		if id != "" {
			want[id] = true
		}
	}
	out := make([]UnlockTarget, 0, len(want))
	for _, t := range unlockTargets {
		if want[t.ID] {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return UnlockTargets()
	}
	return out
}

// ids is the cache-key form of a target list.
func ids(targets []UnlockTarget) string {
	parts := make([]string, 0, len(targets))
	for _, t := range targets {
		parts = append(parts, t.ID)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
