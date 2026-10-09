package diag

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// This file implements the AI 直达页 probe: it walks a selector group's members
// one at a time, asks whether ChatGPT and Gemini answer through each one, and
// always puts the group back on the member it started on.
//
// The sweep is deliberately serial. A selector holds a single value, so two
// workers switching the same group would each measure a node the other one had
// just replaced, and the table would describe nothing.

// The check vocabulary answers one question - can this node use the service -
// and it answers it without a session, because a login is not what the page is
// asking about. Green therefore means "the service answered from this exit and
// the region is supported"; whether a session was present is evidence carried
// in the keyword, not the bar the grade has to clear.
//
//	ok      绿  - 服务从该出口可达，且地区受支持（登录与否都算）
//	risk    黄  - 出口被风控 / Cloudflare 挑战，真实浏览器可能仍可用
//	region  红  - 服务明确表示该地区不受支持
//	blocked 红  - 状态码与内容都落在已知形态之外
//	timeout / error - 没有拿到响应
const (
	AICheckOK      = "ok"
	AICheckRisk    = "risk"
	AICheckRegion  = "region"
	AICheckBlocked = "blocked"
	AICheckTimeout = "timeout"
	AICheckError   = "error"
)

// aiGradeRank orders the grades from best to worst so two probes of the same
// service can be combined without hand-written if-chains: the worse answer wins,
// because one blocked path means the service is not usable.
func aiGradeRank(status string) int {
	switch status {
	case AICheckOK:
		return 0
	case AICheckRisk:
		return 1
	case AICheckRegion:
		return 2
	case AICheckBlocked:
		return 3
	case AICheckTimeout:
		return 4
	default:
		return 5
	}
}

// aiBest returns the better of two probes of the same service. It is the mirror
// of aiWorst, for the services where either proof is enough: ChatGPT is usable
// when the page opens *or* when the session endpoint answers, because both mean
// this exit reaches the service.
func aiBest(a, b AICheck) AICheck {
	if aiGradeRank(b.Status) < aiGradeRank(a.Status) {
		return b
	}
	if aiGradeRank(b.Status) == aiGradeRank(a.Status) && a.Keyword == "" && b.Keyword != "" {
		return b
	}
	return a
}

// aiWorst returns the worse of two checks, keeping the evidence of whichever
// one decided the answer.
func aiWorst(a, b AICheck) AICheck {
	if aiGradeRank(b.Status) > aiGradeRank(a.Status) {
		return b
	}
	if aiGradeRank(b.Status) == aiGradeRank(a.Status) && a.Keyword == "" && b.Keyword != "" {
		return b
	}
	return a
}

// The phase vocabulary: a run detects, restores, then is done. Cancel and
// failure take the same last two steps, so a stopped run never leaves the
// group on a test node.
const (
	AIPhaseDetect  = "detect"
	AIPhaseRestore = "restore"
	AIPhaseDone    = "done"
)

// The restore outcomes.
const (
	AIRestoreOK     = "ok"
	AIRestoreFailed = "failed"
)

// aiDetailLimit is the longest excerpt carried in detail. The contract allows
// 200 characters; the limit is applied in characters, not bytes, so a Chinese
// body is never cut in the middle of a rune.
const aiDetailLimit = 200

// aiRestoreTimeout bounds the switch back. It runs on its own context because
// a cancelled sweep still has to leave the group where it found it.
const aiRestoreTimeout = 20 * time.Second

// AICheck is one service's verdict for one node, together with the evidence
// that produced it. The evidence is what makes the verdict reviewable: the
// exact URL, the status code, the keyword that matched, and - for the ChatGPT
// probe, which asks Cloudflare who it thinks we are - the exit IP and colo.
type AICheck struct {
	Status     string `json:"status"`
	HTTPStatus int    `json:"http_status"`
	Detail     string `json:"detail"`
	MS         int    `json:"ms"`
	Path       string `json:"path,omitempty"`
	Keyword    string `json:"keyword,omitempty"`
	ExitIP     string `json:"exit_ip,omitempty"`
	Colo       string `json:"colo,omitempty"`
	At         string `json:"at,omitempty"`
	Extra      string `json:"extra,omitempty"`
	// FinalURL is where the request ended up when it was redirected. It is the
	// AI Studio region test's whole evidence: the same 200 lands either on the
	// Google sign-in page or on the available-regions page.
	FinalURL string `json:"final_url,omitempty"`
	// raw keeps the body as it arrived for the one caller that needs its line
	// structure - the cdn-cgi/trace parser. Detail is flattened to a single
	// line on purpose, so it cannot be used for that.
	raw string
}

// AIRow is one node's line in the table.
type AIRow struct {
	Node    string  `json:"node"`
	ChatGPT AICheck `json:"chatgpt"`
	Gemini  AICheck `json:"gemini"`
	Verdict string  `json:"verdict"`
}

// AIBest names the fastest node that answered on both services. Its zero value
// - an empty node - means the run found none.
type AIBest struct {
	Node    string `json:"node"`
	ChatGPT bool   `json:"chatgpt"`
	Gemini  bool   `json:"gemini"`
	MS      int    `json:"ms"`
}

// AIStatus is the whole answer of GET /api/diag/ai/status.
type AIStatus struct {
	Job           string   `json:"job"`
	Group         string   `json:"group"`
	Running       bool     `json:"running"`
	Phase         string   `json:"phase"`
	Total         int      `json:"total"`
	Done          int      `json:"done"`
	RestoreState  string   `json:"restore_state"`
	RestoreDetail string   `json:"restore_detail"`
	Rows          []AIRow  `json:"rows"`
	Best          AIBest   `json:"best"`
	Errors        []string `json:"errors"`
}

// AIJob is the answer of POST /api/diag/ai/run.
type AIJob struct {
	Job     string `json:"job"`
	Group   string `json:"group"`
	Total   int    `json:"total"`
	Restore string `json:"restore"`
}

// AIRequest is one sweep: the group to walk, the members to test, and the
// member the group has to be put back on afterwards.
type AIRequest struct {
	Group   string
	Nodes   []string
	Restore string
}

// AISelector switches one selector group. The sweep owns the order and the
// restore; the app supplies the control-plane call, so this package needs no
// core client of its own.
type AISelector interface {
	Select(ctx context.Context, group, name string) error
}

// keywordOf reports which of the markers was found, so the evidence can name
// the exact phrase the verdict was based on.
func keywordOf(lower string, markers ...string) string {
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return m
		}
	}
	return ""
}

// isCloudflareChallenge recognises the interstitial / block pages Cloudflare
// serves when it does not like the client. They are a rate limit, not a region
// block, and they are the most common reason a "the AI site does not work"
// report turns out to be about the exit IP's reputation.
// cfChallengeMarkers are the pages Cloudflare serves when it wants the client to
// prove it is a browser. A real browser walks straight through them, which is
// why they are not a "blocked" answer for a service the user opens in the
// built-in sign-in window.
var cfChallengeMarkers = []string{
	"just a moment", "cf-chl", "cf_chl", "enable javascript and cookies", "checking your browser",
}

// cfBlockMarkers are the pages Cloudflare serves once it has decided the client
// will never get through. That is a different answer from a challenge, and the
// only one that is risk control.
var cfBlockMarkers = []string{
	"error 1020", "attention required", "access denied", "you have been blocked",
	"sorry, you have been blocked",
}

func isCloudflareChallenge(lower string) bool {
	return keywordOf(lower, cfChallengeMarkers...) != ""
}

// ClassifyChatGPT grades both ChatGPT probes: the page the built-in sign-in
// window opens (https://chatgpt.com/) and the session endpoint behind it.
//
// ChatGPT carries no region restriction the way Gemini does, so "the site
// answered from this exit" is the whole question. A Cloudflare *managed
// challenge* counts as an answer: it is served by chatgpt.com itself, and a real
// browser - which is exactly what the sign-in window is - walks through it. Only
// a hard Cloudflare block, a rate limit or an explicit region refusal is a
// warning.
//
//	200 / 401                       -> 绿：站点答了
//	200 + accessToken               -> 绿：而且带登录态
//	403 + 托管挑战（cf_chl 等）      -> 绿：站点在，只是要浏览器自证
//	403 + 硬封禁 / 429              -> 黄：风控
//	403 + unsupported_country       -> 红：地区不支持
func ClassifyChatGPT(httpStatus int, body, finalURL string) (string, string) {
	lower := strings.ToLower(body)
	if kw := keywordOf(lower,
		"unsupported_country",
		"country, region, or territory not supported",
		"not available in your country",
		"unsupported region"); kw != "" {
		return AICheckRegion, kw
	}
	if kw := keywordOf(lower, "accesstoken", "session_token"); kw != "" {
		return AICheckOK, kw
	}
	if kw := keywordOf(lower, cfBlockMarkers...); kw != "" {
		return AICheckRisk, kw
	}
	if kw := keywordOf(lower, cfChallengeMarkers...); kw != "" {
		return AICheckOK, kw
	}
	switch httpStatus {
	case http.StatusOK, http.StatusUnauthorized:
		return AICheckOK, "site answered"
	case http.StatusTooManyRequests:
		return AICheckRisk, "429 rate limited"
	case http.StatusForbidden:
		return AICheckRisk, "403 forbidden"
	default:
		return AICheckBlocked, ""
	}
}

// ClassifyGeminiApp grades https://gemini.google.com/app - the page a person
// actually opens. A sign-in page is green: it proves the region is served and
// only the account is missing, which is the question the page asks.
func ClassifyGeminiApp(httpStatus int, body, finalURL string) (string, string) {
	lower := strings.ToLower(body)
	if kw := keywordOf(lower, "not available in your country", "unsupported region", "isn't available in your country"); kw != "" {
		return AICheckRegion, kw
	}
	if kw := keywordOf(lower, cfBlockMarkers...); kw != "" {
		return AICheckRisk, kw
	}
	if isCloudflareChallenge(lower) {
		return AICheckRisk, "cloudflare challenge"
	}
	switch httpStatus {
	case http.StatusOK:
		if kw := keywordOf(lower, "sign in", "accounts.google.com", "service=accountchooser"); kw != "" {
			return AICheckOK, kw
		}
		if kw := keywordOf(lower, "gemini", "bard"); kw != "" {
			return AICheckOK, kw
		}
		return AICheckOK, "200"
	case http.StatusTooManyRequests:
		return AICheckRisk, "429 rate limited"
	case http.StatusUnauthorized, http.StatusForbidden:
		return AICheckRisk, "needs credentials"
	default:
		return AICheckBlocked, ""
	}
}

// ClassifyGeminiAPI grades the API host. This service answers a region block
// with 400 and a credential complaint with 400/403 - the opposite of OpenAI -
// so the body decides, not the status. A missing key is green: the region
// answered, and that is the only thing this page is asking about.
func ClassifyGeminiAPI(httpStatus int, body, finalURL string) (string, string) {
	lower := strings.ToLower(body)
	if kw := keywordOf(lower, "user location is not supported", "unsupported region"); kw != "" {
		return AICheckRegion, kw
	}
	if kw := keywordOf(lower, "api key not valid", "missing a valid api key", "unregistered callers", "api_key_invalid"); kw != "" {
		return AICheckOK, kw
	}
	if kw := keywordOf(lower, cfBlockMarkers...); kw != "" {
		return AICheckRisk, kw
	}
	if isCloudflareChallenge(lower) {
		return AICheckRisk, "cloudflare challenge"
	}
	switch httpStatus {
	case http.StatusOK:
		if kw := keywordOf(lower, "models", "gemini"); kw != "" {
			return AICheckOK, kw
		}
		return AICheckOK, "200"
	case http.StatusTooManyRequests:
		return AICheckRisk, "429 rate limited"
	default:
		return AICheckBlocked, ""
	}
}

// ClassifyAIStudio grades the login-free region test the page documents: ask
// for a new AI Studio chat and follow the answer to its end. A redirect to
// .../docs/available-regions is the service saying the region is not served;
// anything else - the Google sign-in page in particular - means the region is
// fine and only an account is missing. The final URL is therefore the evidence,
// not the status code, which is 200 in both cases.
func ClassifyAIStudio(httpStatus int, body, finalURL string) (string, string) {
	lower := strings.ToLower(body)
	if strings.Contains(strings.ToLower(finalURL), "available-regions") {
		return AICheckRegion, "available-regions"
	}
	if kw := keywordOf(lower,
		"not available in your country",
		"isn't available in your country",
		"not currently available in your country",
		"unsupported region"); kw != "" {
		return AICheckRegion, kw
	}
	if kw := keywordOf(lower, cfBlockMarkers...); kw != "" {
		return AICheckRisk, kw
	}
	if isCloudflareChallenge(lower) {
		return AICheckRisk, "cloudflare challenge"
	}
	switch httpStatus {
	case http.StatusOK:
		if strings.Contains(strings.ToLower(finalURL), "accounts.google.com") {
			return AICheckOK, "sign-in redirect"
		}
		return AICheckOK, "aistudio page"
	case http.StatusTooManyRequests:
		return AICheckRisk, "429 rate limited"
	case http.StatusForbidden:
		return AICheckRisk, "403 forbidden"
	default:
		return AICheckBlocked, ""
	}
}

// parseCloudflareTrace reads the ip=, loc= and colo= lines out of a
// cdn-cgi/trace body. That body is the service's own statement about which IP
// and which edge it saw, which is exactly the evidence a "is this node really
// usable" question needs.
func parseCloudflareTrace(body string) (ip, loc, colo string) {
	for _, line := range strings.Split(body, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "ip":
			ip = value
		case "loc":
			loc = value
		case "colo":
			colo = value
		}
	}
	return ip, loc, colo
}

// ClassifyAIError maps a transport failure to the same vocabulary. Only a
// deadline is a timeout; everything else (refused, DNS, TLS, reset) is an
// error, because the node never produced an answer.
func ClassifyAIError(err error) string {
	if err == nil {
		return ""
	}
	if errKind(err) == "timeout" {
		return AICheckTimeout
	}
	return AICheckError
}

// AIVerdict says what a node is good for. Only a green check counts as usable:
// 黄绿 means "the network reached it", which is not the same promise, and the
// table must not blur the two.
func AIVerdict(chatgpt, gemini AICheck) string {
	okChatGPT, okGemini := chatgpt.Status == AICheckOK, gemini.Status == AICheckOK
	switch {
	case okChatGPT && okGemini:
		return "both"
	case okChatGPT:
		return "chatgpt"
	case okGemini:
		return "gemini"
	default:
		return "none"
	}
}

// PickAIBest picks the fastest node that answered on both services. A row's
// time is the sum of its two probes because they run one after the other, so
// it is the wall time the node needed to prove itself.
func PickAIBest(rows []AIRow) AIBest {
	best := AIBest{}
	for _, row := range rows {
		if row.Verdict != "both" {
			continue
		}
		ms := row.ChatGPT.MS + row.Gemini.MS
		if best.Node == "" || ms < best.MS {
			best = AIBest{Node: row.Node, ChatGPT: true, Gemini: true, MS: ms}
		}
	}
	return best
}

// aiExcerpt flattens a body into one line of at most aiDetailLimit characters.
// The real status and body are always reported, whatever the verdict: an
// honest answer beats a tidy one.
func aiExcerpt(raw string) string {
	s := strings.Join(strings.Fields(raw), " ")
	if runes := []rune(s); len(runes) > aiDetailLimit {
		s = string(runes[:aiDetailLimit])
	}
	return s
}

// aiEndpoint is one URL the sweep asks.
type aiEndpoint struct {
	ID  string
	URL string
	// Service names the cookie jar the request should carry. Empty means the
	// endpoint is answered without a session: the Cloudflare trace, and the AI
	// Studio region test, which has to be asked as a stranger to mean anything.
	Service string
	// Redirects is how many hops the probe follows before it reads the answer.
	// The AI Studio region test *is* a redirect, so without following it the
	// probe would only ever see the 302 and never the page that decides.
	Redirects int
	Classify  func(httpStatus int, body, finalURL string) (string, string)
}

var (
	aiTraceEndpoint = aiEndpoint{
		ID:  "trace",
		URL: "https://chatgpt.com/cdn-cgi/trace",
		// The trace body is not a verdict, it is evidence: it is parsed
		// separately and never classified as a service answer.
		Classify: func(int, string, string) (string, string) { return AICheckOK, "" },
	}
	// Cloudflare challenges chatgpt.com's own trace from an exit IP it does not
	// like, and then the row would carry no exit IP at all. The plain
	// cloudflare.com trace answers from the same edge without the service's own
	// rules, so the evidence still names the IP and the colo.
	aiTraceFallback = aiEndpoint{
		ID:       "trace-fallback",
		URL:      "https://www.cloudflare.com/cdn-cgi/trace",
		Classify: func(int, string, string) (string, string) { return AICheckOK, "" },
	}
	// ChatGPT is judged from the page the built-in sign-in window opens and from
	// the session endpoint behind it. Either one answering means this exit
	// reaches ChatGPT, so the pair is combined with aiBest, not aiWorst.
	aiChatGPTPage = aiEndpoint{
		ID:        "chatgpt",
		URL:       "https://chatgpt.com/",
		Redirects: 3,
		Classify:  ClassifyChatGPT,
	}
	aiChatGPTSession = aiEndpoint{
		ID:       "chatgpt-session",
		URL:      "https://chatgpt.com/api/auth/session",
		Service:  "chatgpt",
		Classify: ClassifyChatGPT,
	}
	// The login-free region test. It is asked without the sign-in cookies on
	// purpose: the answer is about the region, and a session would only hide it.
	aiAIStudio = aiEndpoint{
		ID:        "aistudio",
		URL:       "https://aistudio.google.com/prompts/new_chat?model=gemini-3-flash-preview",
		Redirects: 5,
		Classify:  ClassifyAIStudio,
	}
	aiGeminiApp = aiEndpoint{
		ID:       "gemini-app",
		URL:      "https://gemini.google.com/app",
		Service:  "gemini",
		Classify: ClassifyGeminiApp,
	}
	aiGeminiAPI = aiEndpoint{
		ID:       "gemini-api",
		URL:      "https://generativelanguage.googleapis.com/v1beta/models",
		Service:  "gemini",
		Classify: ClassifyGeminiAPI,
	}
)

// hasAICookies reports whether a sign-in session is stored for one service. The
// session probe only earns its round trip when there is something to prove.
func (p *Prober) hasAICookies(service string) bool {
	return p.opts.AICookies != nil && len(p.opts.AICookies(service)) > 0
}

// probeTrace asks Cloudflare who it thinks we are. The answer is the exit IP,
// the country and the edge that served it - the evidence a user can check
// against any "what is my IP" page. A failure is not fatal: the service probes
// still run and simply carry no exit IP.
func (p *Prober) probeTrace(ctx context.Context, via Via) (ip, loc, colo string) {
	for _, ep := range []aiEndpoint{aiTraceEndpoint, aiTraceFallback} {
		check := p.probeAI(ctx, via, ep)
		if check.HTTPStatus != http.StatusOK {
			continue
		}
		if ip, loc, colo = parseCloudflareTrace(check.raw); ip != "" {
			return ip, loc, colo
		}
	}
	return "", "", ""
}

// probeAI asks one endpoint through one path. It never consults the answer
// cache: the contract says a run is always a fresh measurement, so a second
// run may honestly disagree with the first.
func (p *Prober) probeAI(ctx context.Context, via Via, ep aiEndpoint) AICheck {
	start := p.nowTime()
	req, err := http.NewRequest(http.MethodGet, ep.URL, nil)
	if err != nil {
		return p.stamp(aiErrorCheck(err, p.sinceMS(start), ep))
	}
	if ep.Service != "" && p.opts.AICookies != nil {
		// The sign-in cookies turn "the network answered" into "the account
		// answered": with them the session endpoint returns real data, without
		// them it returns the anonymous session. Both are green; the cookies
		// only sharpen the evidence.
		for _, c := range p.opts.AICookies(ep.Service) {
			req.AddCookie(c)
		}
	}
	pctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	resp, body, err := p.do(pctx, via, req, clientOpts{maxRedirects: ep.Redirects})
	ms := p.sinceMS(start)
	final := ep.URL
	if resp != nil && resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	if err != nil {
		// A read that failed after the headers arrived still has a real status
		// and a real body prefix, so it is classified like a normal answer.
		if resp != nil && resp.StatusCode > 0 {
			return p.stamp(aiCheckFromResponse(ep, resp.StatusCode, body, final, ms))
		}
		return p.stamp(aiErrorCheck(err, ms, ep))
	}
	return p.stamp(aiCheckFromResponse(ep, resp.StatusCode, body, final, ms))
}

// stamp records when the measurement was taken. A verdict without a timestamp
// cannot be re-checked later, and "it worked five minutes ago" is a different
// statement from "it works".
func (p *Prober) stamp(check AICheck) AICheck {
	check.At = p.nowTime().UTC().Format(time.RFC3339)
	return check
}

// aiCheckFromResponse builds one check from a real HTTP answer.
func aiCheckFromResponse(ep aiEndpoint, httpStatus int, body []byte, finalURL string, ms int) AICheck {
	status, keyword := ep.Classify(httpStatus, string(body), finalURL)
	check := AICheck{
		Status:     status,
		HTTPStatus: httpStatus,
		Detail:     aiExcerpt(string(body)),
		MS:         ms,
		Path:       ep.URL,
		Keyword:    keyword,
		raw:        string(body),
	}
	// The final URL is only carried when it differs from the one that was asked
	// for: that difference is the region test's whole answer.
	if finalURL != "" && finalURL != ep.URL {
		check.FinalURL = finalURL
	}
	return check
}

// aiErrorCheck builds the check for a failure that produced no response.
func aiErrorCheck(err error, ms int, ep aiEndpoint) AICheck {
	return AICheck{
		Status:     ClassifyAIError(err),
		HTTPStatus: statusOf(err),
		Detail:     aiExcerpt(err.Error()),
		MS:         ms,
		Path:       ep.URL,
	}
}

// sinceMS is the elapsed time since start, never negative.
func (p *Prober) sinceMS(start time.Time) int {
	ms := int(p.nowTime().Sub(start).Milliseconds())
	if ms < 0 {
		ms = 0
	}
	return ms
}

// aiRun is the mutex-guarded state of one sweep. Every field the status route
// returns is read from here, so polling never touches the worker.
type aiRun struct {
	mu sync.Mutex

	group     string
	phase     string
	total     int
	restoreTo string

	restoreState  string
	restoreDetail string

	rows   []AIRow
	errors []string
}

// StartAI registers an AI sweep and starts its worker. The caller resolves the
// group, its members and the member to restore first, so the run route can
// answer the real total before the first node is switched.
func (p *Prober) StartAI(sel AISelector, req AIRequest) (*Job, error) {
	run := &aiRun{
		group:     req.Group,
		phase:     AIPhaseDetect,
		total:     len(req.Nodes),
		restoreTo: strings.TrimSpace(req.Restore),
		rows:      make([]AIRow, 0, len(req.Nodes)),
		errors:    []string{},
	}
	job, ctx, err := p.jobs.Begin("ai", run.snapshot)
	if err != nil {
		return nil, err
	}
	nodes := append([]string{}, req.Nodes...)
	go run.work(p, ctx, job, sel, nodes)
	return job, nil
}

// work is the serial sweep. It checks the context once per node, and it always
// ends with the restore step, however it was stopped.
func (r *aiRun) work(p *Prober, ctx context.Context, job *Job, sel AISelector, nodes []string) {
	defer func() {
		state := JobDone
		if ctx.Err() != nil {
			state = JobCanceled
		}
		p.jobs.Finish(job, state, "")
	}()

	for _, node := range nodes {
		if ctx.Err() != nil {
			break
		}
		if err := sel.Select(ctx, r.group, node); err != nil {
			// One node the kernel refuses to switch must not end the sweep;
			// the row says what happened and the next node gets its turn.
			r.addError("切换到 " + node + " 失败：" + err.Error())
			r.addRow(AIRow{
				Node:    node,
				ChatGPT: p.stamp(aiErrorCheck(err, 0, aiChatGPTPage)),
				Gemini:  p.stamp(aiErrorCheck(err, 0, aiGeminiApp)),
				Verdict: "none",
			})
			continue
		}
		// One trace per node, then the three service probes. The trace is what
		// makes the verdict reviewable: it is Cloudflare's own statement about
		// which IP and which edge it saw, and it is attached to both rows.
		// One node's probes are independent of each other, so they go out
		// together. The sweep is still serial across nodes - a selector holds a
		// single value - but there is no reason to wait for the trace before
		// asking ChatGPT. The prober's concurrency gate bounds the burst, so
		// this stays inside the same limit every other panel uses.
		var (
			exitIP, loc, colo string
			chatgpt, gemini   AICheck
		)
		var wg sync.WaitGroup
		run := func(fn func()) {
			wg.Add(1)
			go func() { defer wg.Done(); fn() }()
		}
		run(func() { exitIP, loc, colo = p.probeTrace(ctx, ViaProxy) })
		run(func() {
			chatgpt = p.probeAI(ctx, ViaProxy, aiChatGPTPage)
			// The session endpoint is only worth a round trip when there is a
			// sign-in to prove: without cookies it answers the same anonymous
			// payload the page probe already saw.
			if p.hasAICookies("chatgpt") {
				chatgpt = aiBest(chatgpt, p.probeAI(ctx, ViaProxy, aiChatGPTSession))
			}
		})
		run(func() {
			// Gemini is judged from three places: the login-free AI Studio
			// region test, the page a person opens, and the API host. The worse
			// of the three decides, because one blocked path means the service
			// is not usable from this node.
			gemini = aiWorst(
				aiWorst(p.probeAI(ctx, ViaProxy, aiAIStudio), p.probeAI(ctx, ViaProxy, aiGeminiApp)),
				p.probeAI(ctx, ViaProxy, aiGeminiAPI),
			)
		})
		wg.Wait()
		for _, c := range []*AICheck{&chatgpt, &gemini} {
			c.ExitIP, c.Colo = exitIP, colo
			if loc != "" {
				c.Extra = "出口地区 " + loc
			}
		}
		r.addRow(AIRow{
			Node:    node,
			ChatGPT: chatgpt,
			Gemini:  gemini,
			Verdict: AIVerdict(chatgpt, gemini),
		})
	}

	r.setPhase(AIPhaseRestore)
	r.restore(sel)
	r.setPhase(AIPhaseDone)
}

// restore puts the group back on the member it had before the first switch. It
// runs on a fresh context: a cancelled sweep must still leave the group where
// it found it, and the cancelled context would refuse the call before it left
// the process.
func (r *aiRun) restore(sel AISelector) {
	r.mu.Lock()
	group, to := r.group, r.restoreTo
	r.mu.Unlock()
	if to == "" {
		r.setRestore(AIRestoreOK, "原始选择为空，没有需要恢复的节点")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), aiRestoreTimeout)
	defer cancel()
	if err := sel.Select(ctx, group, to); err != nil {
		r.setRestore(AIRestoreFailed, "切回 "+to+" 失败："+err.Error())
		return
	}
	r.setRestore(AIRestoreOK, "已切回 "+to)
}

func (r *aiRun) addRow(row AIRow) {
	r.mu.Lock()
	r.rows = append(r.rows, row)
	r.mu.Unlock()
}

func (r *aiRun) addError(msg string) {
	r.mu.Lock()
	r.errors = append(r.errors, msg)
	r.mu.Unlock()
}

func (r *aiRun) setPhase(phase string) {
	r.mu.Lock()
	r.phase = phase
	r.mu.Unlock()
}

func (r *aiRun) setRestore(state, detail string) {
	r.mu.Lock()
	r.restoreState, r.restoreDetail = state, detail
	r.mu.Unlock()
}

// snapshot is the incremental view the status route renders. The keys are the
// JSON names of AIStatus, so a poll and the typed reader cannot disagree.
func (r *aiRun) snapshot() map[string]any {
	r.mu.Lock()
	rows := append([]AIRow{}, r.rows...)
	errs := append([]string{}, r.errors...)
	out := map[string]any{
		"group":          r.group,
		"running":        r.phase != AIPhaseDone,
		"phase":          r.phase,
		"total":          r.total,
		"done":           len(rows),
		"restore_state":  r.restoreState,
		"restore_detail": r.restoreDetail,
		"rows":           rows,
		"best":           PickAIBest(rows),
		"errors":         errs,
	}
	r.mu.Unlock()
	return out
}

// AIStatus reads one job's live state. The second result is false when the id
// is unknown or belongs to another kind of job, which the route turns into a
// 404.
func (p *Prober) AIStatus(job string) (AIStatus, bool) {
	j, ok := p.jobs.Get(job)
	if !ok || j.Kind != "ai" {
		return AIStatus{}, false
	}
	raw, err := json.Marshal(j.Status())
	if err != nil {
		return AIStatus{}, false
	}
	var out AIStatus
	if err := json.Unmarshal(raw, &out); err != nil {
		return AIStatus{}, false
	}
	if out.Rows == nil {
		out.Rows = []AIRow{}
	}
	if out.Errors == nil {
		out.Errors = []string{}
	}
	out.Running = out.Phase != AIPhaseDone
	return out, true
}
