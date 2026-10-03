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

// The check vocabulary. It is graded on purpose: "the request reached the
// service" and "the service actually works with this IP" are different answers,
// and a client that paints both green is lying to the user.
//
//	ok      绿  - 带登录态（或密钥）真的拿到了数据
//	nologin 黄绿 - IP 没被拦，但没有登录态 / 没有密钥，只能证明网络通
//	risk    黄  - 被风控：Cloudflare 挑战、429 限流
//	region  红  - 地区不支持（明确的关键字命中）
//	blocked 灰  - 其它非预期响应（状态码不在这几种里）
//	timeout / error - 没拿到响应
const (
	AICheckOK      = "ok"
	AICheckNoLogin = "nologin"
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
	case AICheckNoLogin:
		return 1
	case AICheckRisk:
		return 2
	case AICheckRegion:
		return 3
	case AICheckBlocked:
		return 4
	case AICheckTimeout:
		return 5
	default:
		return 6
	}
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
func isCloudflareChallenge(lower string) bool {
	return keywordOf(lower, "just a moment", "cf-chl", "cf_chl", "attention required",
		"error 1020", "access denied", "ray id") != ""
}

// ClassifyChatGPTSession grades https://chatgpt.com/api/auth/session.
//
//	200 + accessToken/user  -> 绿：这是一次带登录态的真实会话
//	200 + {}                -> 黄绿：IP 没被拦，但没人登录
//	401                     -> 黄绿：服务在，只是要凭据
//	403 + unsupported_country / not available -> 红
//	403 + Cloudflare 挑战   -> 黄
func ClassifyChatGPTSession(httpStatus int, body string) (string, string) {
	lower := strings.ToLower(body)
	if kw := keywordOf(lower,
		"unsupported_country",
		"country, region, or territory not supported",
		"not available in your country",
		"unsupported region"); kw != "" {
		return AICheckRegion, kw
	}
	if kw := keywordOf(lower, "accesstoken", "\"user\"", "session_token", "user_id"); kw != "" {
		return AICheckOK, kw
	}
	if isCloudflareChallenge(lower) {
		return AICheckRisk, "cloudflare challenge"
	}
	switch httpStatus {
	case http.StatusOK:
		return AICheckNoLogin, "empty session"
	case http.StatusUnauthorized:
		return AICheckNoLogin, "401 needs credentials"
	case http.StatusTooManyRequests:
		return AICheckRisk, "429 rate limited"
	case http.StatusForbidden:
		return AICheckRisk, "403 forbidden"
	default:
		return AICheckBlocked, ""
	}
}

// ClassifyGeminiApp grades https://gemini.google.com/app - the page a person
// actually opens. Without a session it answers with a sign-in page; that is
// 黄绿, not 绿, because nothing has proved the account works from here.
func ClassifyGeminiApp(httpStatus int, body string) (string, string) {
	lower := strings.ToLower(body)
	if kw := keywordOf(lower, "not available in your country", "unsupported region", "isn't available in your country"); kw != "" {
		return AICheckRegion, kw
	}
	if isCloudflareChallenge(lower) {
		return AICheckRisk, "cloudflare challenge"
	}
	switch httpStatus {
	case http.StatusOK:
		if kw := keywordOf(lower, "sign in", "accounts.google.com", "service=accountchooser"); kw != "" {
			return AICheckNoLogin, kw
		}
		if kw := keywordOf(lower, "gemini", "bard"); kw != "" {
			return AICheckNoLogin, "app page without a session"
		}
		return AICheckNoLogin, "200 without a session"
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
// so the body decides, not the status.
func ClassifyGeminiAPI(httpStatus int, body string) (string, string) {
	lower := strings.ToLower(body)
	if kw := keywordOf(lower, "user location is not supported", "unsupported region"); kw != "" {
		return AICheckRegion, kw
	}
	if kw := keywordOf(lower, "api key not valid", "missing a valid api key", "unregistered callers", "api_key_invalid"); kw != "" {
		// 可达，但没有密钥：只证明网络通，不证明能用。
		return AICheckNoLogin, kw
	}
	if isCloudflareChallenge(lower) {
		return AICheckRisk, "cloudflare challenge"
	}
	switch httpStatus {
	case http.StatusOK:
		// A 200 only counts as 绿 when it really carries the model list: the
		// host also answers 200 with pages that are not data, and calling that
		// "usable" is exactly the shortcut this grading exists to avoid.
		if kw := keywordOf(lower, "models", "gemini"); kw != "" {
			return AICheckOK, "models returned"
		}
		return AICheckNoLogin, "200 without a model list"
	case http.StatusTooManyRequests:
		return AICheckRisk, "429 rate limited"
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
	// endpoint is answered without a session (the Cloudflare trace).
	Service  string
	Classify func(httpStatus int, body string) (string, string)
}

var (
	aiTraceEndpoint = aiEndpoint{
		ID:  "trace",
		URL: "https://chatgpt.com/cdn-cgi/trace",
		// The trace body is not a verdict, it is evidence: it is parsed
		// separately and never classified as a service answer.
		Classify: func(int, string) (string, string) { return AICheckNoLogin, "" },
	}
	// Cloudflare challenges chatgpt.com's own trace from an exit IP it does not
	// like, and then the row would carry no exit IP at all. The plain
	// cloudflare.com trace answers from the same edge without the service's own
	// rules, so the evidence still names the IP and the colo.
	aiTraceFallback = aiEndpoint{
		ID:       "trace-fallback",
		URL:      "https://www.cloudflare.com/cdn-cgi/trace",
		Classify: func(int, string) (string, string) { return AICheckNoLogin, "" },
	}
	aiChatGPTSession = aiEndpoint{
		ID:       "chatgpt",
		URL:      "https://chatgpt.com/api/auth/session",
		Service:  "chatgpt",
		Classify: ClassifyChatGPTSession,
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
		// The sign-in cookies are what turn "the network answered" into "the
		// account answered": with them the session endpoint returns real data
		// (绿), without them it returns an empty session (黄绿).
		for _, c := range p.opts.AICookies(ep.Service) {
			req.AddCookie(c)
		}
	}
	pctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	resp, body, err := p.do(pctx, via, req, clientOpts{})
	ms := p.sinceMS(start)
	if err != nil {
		// A read that failed after the headers arrived still has a real status
		// and a real body prefix, so it is classified like a normal answer.
		if resp != nil && resp.StatusCode > 0 {
			return p.stamp(aiCheckFromResponse(ep, resp.StatusCode, body, ms))
		}
		return p.stamp(aiErrorCheck(err, ms, ep))
	}
	return p.stamp(aiCheckFromResponse(ep, resp.StatusCode, body, ms))
}

// stamp records when the measurement was taken. A verdict without a timestamp
// cannot be re-checked later, and "it worked five minutes ago" is a different
// statement from "it works".
func (p *Prober) stamp(check AICheck) AICheck {
	check.At = p.nowTime().UTC().Format(time.RFC3339)
	return check
}

// aiCheckFromResponse builds one check from a real HTTP answer.
func aiCheckFromResponse(ep aiEndpoint, httpStatus int, body []byte, ms int) AICheck {
	status, keyword := ep.Classify(httpStatus, string(body))
	return AICheck{
		Status:     status,
		HTTPStatus: httpStatus,
		Detail:     aiExcerpt(string(body)),
		MS:         ms,
		Path:       ep.URL,
		Keyword:    keyword,
		raw:        string(body),
	}
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
				ChatGPT: p.stamp(aiErrorCheck(err, 0, aiChatGPTSession)),
				Gemini:  p.stamp(aiErrorCheck(err, 0, aiGeminiApp)),
				Verdict: "none",
			})
			continue
		}
		// One trace per node, then the three service probes. The trace is what
		// makes the verdict reviewable: it is Cloudflare's own statement about
		// which IP and which edge it saw, and it is attached to both rows.
		exitIP, loc, colo := p.probeTrace(ctx, ViaProxy)
		chatgpt := p.probeAI(ctx, ViaProxy, aiChatGPTSession)
		// Gemini is judged from two places: the page a person opens and the API
		// host. The worse of the two decides, because one blocked path means
		// the service is not usable from this node.
		gemini := aiWorst(p.probeAI(ctx, ViaProxy, aiGeminiApp), p.probeAI(ctx, ViaProxy, aiGeminiAPI))
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
