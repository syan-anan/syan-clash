package diag

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// The graded vocabulary is the whole point of the AI page: ok must mean "the
// service answered from this exit and the region is supported", which is a
// question a caller without an account can still answer. ChatGPT is judged from
// the page the sign-in window opens as well as from the session endpoint, and a
// managed challenge counts as an answer because that is exactly what a browser
// walks through.
func TestClassifyChatGPTGrades(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"logged in", http.StatusOK, `{"user":{"id":"u"},"accessToken":"eyJhbGci","expires":"2026"}`, AICheckOK},
		{"anonymous session", http.StatusOK, `{"WARNING_BANNER":"do not share"}`, AICheckOK},
		{"the page came back", http.StatusOK, `<!DOCTYPE html><html lang="en-US"><head>`, AICheckOK},
		{"needs credentials", http.StatusUnauthorized, `{"detail":"Unauthorized"}`, AICheckOK},
		{"region block", http.StatusForbidden, `{"detail":{"code":"unsupported_country"}}`, AICheckRegion},
		{"region block by phrase", http.StatusForbidden, `ChatGPT is not available in your country`, AICheckRegion},
		{"managed challenge is still the site", http.StatusForbidden, `<html><title>Just a moment...</title><script>window._cf_chl_opt={cType:"managed"}</script>`, AICheckOK},
		{"hard block is risk control", http.StatusForbidden, `<html><title>Attention Required! | Cloudflare</title> Error 1020`, AICheckRisk},
		{"rate limited", http.StatusTooManyRequests, `slow down`, AICheckRisk},
		{"plain forbidden", http.StatusForbidden, `nope`, AICheckRisk},
		{"unexpected", http.StatusBadGateway, `bad gateway`, AICheckBlocked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, keyword := ClassifyChatGPT(c.status, c.body, "")
			if got != c.want {
				t.Errorf("ClassifyChatGPT(%d, %q) = %q, want %q", c.status, c.body, got, c.want)
			}
			if got != AICheckBlocked && keyword == "" {
				t.Errorf("a graded answer must name the keyword it matched (status %q)", got)
			}
		})
	}
}

func TestClassifyGeminiGrades(t *testing.T) {
	if got, kw := ClassifyGeminiApp(http.StatusOK, `<html>Sign in - Google Accounts</html>`, ""); got != AICheckOK || kw == "" {
		t.Errorf("sign-in page = (%q, %q), want ok with a keyword", got, kw)
	}
	if got, _ := ClassifyGeminiApp(http.StatusOK, `Gemini is not available in your country`, ""); got != AICheckRegion {
		t.Errorf("region phrase on the app page = %q, want region", got)
	}
	if got, _ := ClassifyGeminiAPI(http.StatusBadRequest, `{"error":{"message":"API key not valid. Please pass a valid API key."}}`, ""); got != AICheckOK {
		t.Errorf("missing key = %q, want ok (the region answered)", got)
	}
	if got, _ := ClassifyGeminiAPI(http.StatusBadRequest, `{"error":{"message":"User location is not supported for the API use."}}`, ""); got != AICheckRegion {
		t.Errorf("location message = %q, want region", got)
	}
	if got, _ := ClassifyGeminiAPI(http.StatusOK, `{"models":[]}`, ""); got != AICheckOK {
		t.Errorf("200 from the API host = %q, want ok", got)
	}
	if got, _ := ClassifyGeminiAPI(http.StatusTooManyRequests, `quota`, ""); got != AICheckRisk {
		t.Errorf("429 = %q, want risk", got)
	}
}

// The AI Studio probe is the login-free region test: both answers arrive as 200,
// so the final URL is the only thing that tells them apart.
func TestClassifyAIStudioReadsTheFinalURL(t *testing.T) {
	const signIn = "https://accounts.google.com/v3/signin/identifier?continue=https://aistudio.google.com/prompts/new_chat"
	const blocked = "https://aistudio.google.com/docs/available-regions"
	if got, kw := ClassifyAIStudio(http.StatusOK, `<html>Sign in</html>`, signIn); got != AICheckOK || kw == "" {
		t.Errorf("sign-in redirect = (%q, %q), want ok with a keyword", got, kw)
	}
	if got, _ := ClassifyAIStudio(http.StatusOK, `<html>Available regions</html>`, blocked); got != AICheckRegion {
		t.Errorf("available-regions redirect = %q, want region", got)
	}
	if got, _ := ClassifyAIStudio(http.StatusOK, `<html>regions</html>`, blocked+"?hl=en"); got != AICheckRegion {
		t.Errorf("available-regions with a query = %q, want region", got)
	}
	if got, _ := ClassifyAIStudio(http.StatusOK, `<html>AI Studio</html>`, "https://aistudio.google.com/prompts/new_chat"); got != AICheckOK {
		t.Errorf("aistudio page = %q, want ok", got)
	}
	if got, _ := ClassifyAIStudio(http.StatusForbidden, `<html><title>Just a moment...</title>`, ""); got != AICheckRisk {
		t.Errorf("cloudflare challenge = %q, want risk", got)
	}
}

// The trace body is the evidence attached to both rows, so its three fields
// have to survive a real body.
func TestParseCloudflareTrace(t *testing.T) {
	body := "fl=1f2\nh=chatgpt.com\nip=151.248.68.116\nts=1791000000.1\nvisit_scheme=https\nuag=curl\ncolo=NRT\nsliver=none\nhttp=http/2\nloc=JP\ntls=TLSv1.3\n"
	ip, loc, colo := parseCloudflareTrace(body)
	if ip != "151.248.68.116" || loc != "JP" || colo != "NRT" {
		t.Errorf("parseCloudflareTrace = (%q, %q, %q), want (151.248.68.116, JP, NRT)", ip, loc, colo)
	}
	if ip, loc, colo := parseCloudflareTrace(""); ip != "" || loc != "" || colo != "" {
		t.Errorf("an empty body must not invent evidence: (%q, %q, %q)", ip, loc, colo)
	}
}

// The worse of two probes decides, and the evidence of the deciding probe is
// the one that is kept.
func TestAIWorstKeepsTheWorseGradeAndItsEvidence(t *testing.T) {
	ok := AICheck{Status: AICheckOK, Keyword: "accessToken", Path: "a"}
	risk := AICheck{Status: AICheckRisk, Keyword: "cloudflare challenge", Path: "b"}
	region := AICheck{Status: AICheckRegion, Keyword: "unsupported_country", Path: "c"}
	if got := aiWorst(ok, risk); got.Status != AICheckRisk || got.Path != "b" {
		t.Errorf("aiWorst(ok, risk) = %+v, want the risk check", got)
	}
	if got := aiWorst(region, ok); got.Status != AICheckRegion {
		t.Errorf("aiWorst(region, ok) = %q, want region", got.Status)
	}
	if got := aiWorst(ok, risk); got.Keyword != "cloudflare challenge" {
		t.Errorf("the deciding probe's keyword must be kept, got %q", got.Keyword)
	}
}

// A reachable service is a green light whether or not anyone is signed in: that
// is the whole point of grading availability instead of a session.
func TestAIVerdictCountsAnAvailableService(t *testing.T) {
	ok := AICheck{Status: AICheckOK}
	risk := AICheck{Status: AICheckRisk}
	red := AICheck{Status: AICheckRegion}
	if got := AIVerdict(ok, ok); got != "both" {
		t.Errorf("two green checks = %q, want both", got)
	}
	if got := AIVerdict(ok, risk); got != "chatgpt" {
		t.Errorf("green + risk = %q, want chatgpt", got)
	}
	if got := AIVerdict(risk, ok); got != "gemini" {
		t.Errorf("risk + green = %q, want gemini", got)
	}
	if got := AIVerdict(risk, risk); got != "none" {
		t.Errorf("two risk checks = %q, want none", got)
	}
	if got := AIVerdict(ok, red); got != "chatgpt" {
		t.Errorf("green + red = %q, want chatgpt", got)
	}
}

// One node's probes now go out together, so the prober has to stay correct when
// several probes run at once: each probe owns its own client and transport, and
// the only shared piece is the concurrency gate.
func TestProbeAIRunsConcurrentlyWithoutLosingAnswers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	p := New(Options{TimeoutMS: func() int { return 5000 }})
	ep := aiEndpoint{
		ID:       "local",
		URL:      srv.URL,
		Classify: func(int, string, string) (string, string) { return AICheckOK, "ok" },
	}
	results := make([]AICheck, 8)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = p.probeAI(context.Background(), ViaDirect, ep)
		}(i)
	}
	wg.Wait()
	for i, c := range results {
		if c.Status != AICheckOK || c.HTTPStatus != http.StatusOK {
			t.Errorf("probe %d = (%q, %d), want (ok, 200)", i, c.Status, c.HTTPStatus)
		}
	}
}
