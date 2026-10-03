package diag

import (
	"net/http"
	"testing"
)

// The graded vocabulary is the whole point of the AI page: 绿 must mean "a real
// session answered", 黄绿 must mean "the network reached it but nobody is
// logged in", 黄 must mean risk control and 红 must mean a region block. These
// payloads are the shapes those four states actually arrive in.
func TestClassifyChatGPTSessionGrades(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"logged in", http.StatusOK, `{"user":{"id":"u"},"accessToken":"eyJ…","expires":"2026"}`, AICheckOK},
		{"not logged in", http.StatusOK, `{}`, AICheckNoLogin},
		{"needs credentials", http.StatusUnauthorized, `{"detail":"Unauthorized"}`, AICheckNoLogin},
		{"region block", http.StatusForbidden, `{"detail":{"code":"unsupported_country"}}`, AICheckRegion},
		{"region block by phrase", http.StatusForbidden, `ChatGPT is not available in your country`, AICheckRegion},
		{"cloudflare challenge", http.StatusForbidden, `<html><title>Just a moment...</title>`, AICheckRisk},
		{"rate limited", http.StatusTooManyRequests, `slow down`, AICheckRisk},
		{"plain forbidden", http.StatusForbidden, `nope`, AICheckRisk},
		{"unexpected", http.StatusBadGateway, `bad gateway`, AICheckBlocked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, keyword := ClassifyChatGPTSession(c.status, c.body)
			if got != c.want {
				t.Errorf("ClassifyChatGPTSession(%d, %q) = %q, want %q", c.status, c.body, got, c.want)
			}
			if got != AICheckBlocked && keyword == "" {
				t.Errorf("a graded answer must name the keyword it matched (status %q)", got)
			}
		})
	}
}

func TestClassifyGeminiGrades(t *testing.T) {
	if got, kw := ClassifyGeminiApp(http.StatusOK, `<html>Sign in - Google Accounts</html>`); got != AICheckNoLogin || kw == "" {
		t.Errorf("sign-in page = (%q, %q), want nologin with a keyword", got, kw)
	}
	if got, _ := ClassifyGeminiApp(http.StatusOK, `Gemini is not available in your country`); got != AICheckRegion {
		t.Errorf("region phrase on the app page = %q, want region", got)
	}
	if got, _ := ClassifyGeminiAPI(http.StatusBadRequest, `{"error":{"message":"API key not valid. Please pass a valid API key."}}`); got != AICheckNoLogin {
		t.Errorf("missing key = %q, want nologin (reachable, not usable)", got)
	}
	if got, _ := ClassifyGeminiAPI(http.StatusBadRequest, `{"error":{"message":"User location is not supported for the API use."}}`); got != AICheckRegion {
		t.Errorf("location message = %q, want region", got)
	}
	if got, _ := ClassifyGeminiAPI(http.StatusOK, `{"models":[]}`); got != AICheckOK {
		t.Errorf("200 from the API host = %q, want ok", got)
	}
	if got, _ := ClassifyGeminiAPI(http.StatusTooManyRequests, `quota`); got != AICheckRisk {
		t.Errorf("429 = %q, want risk", got)
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
	nologin := AICheck{Status: AICheckNoLogin, Keyword: "sign-in page", Path: "b"}
	region := AICheck{Status: AICheckRegion, Keyword: "unsupported_country", Path: "c"}
	if got := aiWorst(ok, nologin); got.Status != AICheckNoLogin || got.Path != "b" {
		t.Errorf("aiWorst(ok, nologin) = %+v, want the nologin check", got)
	}
	if got := aiWorst(region, ok); got.Status != AICheckRegion {
		t.Errorf("aiWorst(region, ok) = %q, want region", got.Status)
	}
	if got := aiWorst(ok, nologin); got.Keyword != "sign-in page" {
		t.Errorf("the deciding probe's keyword must be kept, got %q", got.Keyword)
	}
}

// 黄绿 is not a green light: only two real sessions may produce "both".
func TestAIVerdictOnlyCountsGreen(t *testing.T) {
	green := AICheck{Status: AICheckOK}
	yellowGreen := AICheck{Status: AICheckNoLogin}
	red := AICheck{Status: AICheckRegion}
	if got := AIVerdict(green, green); got != "both" {
		t.Errorf("two green checks = %q, want both", got)
	}
	if got := AIVerdict(yellowGreen, yellowGreen); got != "none" {
		t.Errorf("two 黄绿 checks = %q, want none (reachable is not usable)", got)
	}
	if got := AIVerdict(green, red); got != "chatgpt" {
		t.Errorf("green + red = %q, want chatgpt", got)
	}
	if got := AIVerdict(yellowGreen, green); got != "gemini" {
		t.Errorf("黄绿 + green = %q, want gemini", got)
	}
}
