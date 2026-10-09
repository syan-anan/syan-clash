package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"vvpn/internal/clashapi"
	"vvpn/internal/diag"
)

// The AI 直达页 has two pure decisions worth locking down - how one HTTP answer
// is classified, and which members of a group are worth probing at all - plus
// the field names the frozen contract hands to the page. All of it is tested
// without a kernel and without a network, which is exactly why the logic lives
// outside the sweep.

func TestClassifyChatGPT(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"带登录态拿到会话是绿", 200, `{"user":{"id":"u"},"accessToken":"eyJhbGci"`, diag.AICheckOK},
		{"匿名会话同样是绿", 200, `{"WARNING_BANNER":"do not share"`, diag.AICheckOK},
		{"首页回来了也是绿", 200, `<!DOCTYPE html><html lang="en-US"><head>`, diag.AICheckOK},
		{"401 只是没凭据", 401, `{"detail":"Unauthorized"}`, diag.AICheckOK},
		{"403 地区不支持是红", 403, `{"error":{"message":"Country, region, or territory not supported"}}`, diag.AICheckRegion},
		{"403 托管挑战算站点可达", 403, `<html><title>Just a moment...</title><script>window._cf_chl_opt={cType:"managed"}</script>`, diag.AICheckOK},
		{"403 硬封禁是黄", 403, `<html><title>Attention Required! | Cloudflare</title> Error 1020`, diag.AICheckRisk},
		{"429 限流是黄", 429, `rate limited`, diag.AICheckRisk},
		{"500 落在已知形态之外", 500, `{"error":{"message":"internal"}}`, diag.AICheckBlocked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := diag.ClassifyChatGPT(tc.status, tc.body, ""); got != tc.want {
				t.Fatalf("ClassifyChatGPT(%d, %q) = %q, want %q", tc.status, tc.body, got, tc.want)
			}
		})
	}
}

// The API host answers JSON, so it is judged on its own bodies. A missing key is
// green: the region answered, and that is what the page is asking about.
func TestClassifyGeminiAPI(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"403 缺 key 是绿（地区答了）", 403, `{"error":{"code":403,"message":"Method doesn't allow unregistered callers (callers without established identity). Please use API Key."}}`, diag.AICheckOK},
		{"400 地区不支持是红", 400, `{"error":{"code":400,"message":"User location is not supported for the API use."}}`, diag.AICheckRegion},
		{"400 API key not valid 是绿", 400, `{"error":{"code":400,"message":"API key not valid. Please pass a valid API key."}}`, diag.AICheckOK},
		{"200 带模型列表是绿", 200, `{"models":[{"name":"models/gemini-2.5-pro"}]}`, diag.AICheckOK},
		{"200 不带模型列表也是绿", 200, `{"ok":true}`, diag.AICheckOK},
		{"500 落在已知形态之外", 500, `{"error":{"message":"backend error"}}`, diag.AICheckBlocked},
		{"429 限流是黄", 429, `quota exceeded`, diag.AICheckRisk},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := diag.ClassifyGeminiAPI(tc.status, tc.body, ""); got != tc.want {
				t.Fatalf("ClassifyGeminiAPI(%d, %q) = %q, want %q", tc.status, tc.body, got, tc.want)
			}
		})
	}
}

// The page a person opens is judged separately: without a session it is a
// sign-in page, and a sign-in page is green - the region is served, only the
// account is missing.
func TestClassifyGeminiApp(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"登录页是绿", 200, `<html>Sign in - Google Accounts</html>`, diag.AICheckOK},
		{"地区不支持是红", 200, `Gemini is not available in your country`, diag.AICheckRegion},
		{"风控挑战是黄", 403, `<html><title>Just a moment...</title>`, diag.AICheckRisk},
		{"429 限流是黄", 429, `too many requests`, diag.AICheckRisk},
		{"其它状态算 blocked", 502, `bad gateway`, diag.AICheckBlocked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := diag.ClassifyGeminiApp(tc.status, tc.body, ""); got != tc.want {
				t.Fatalf("ClassifyGeminiApp(%d, %q) = %q, want %q", tc.status, tc.body, got, tc.want)
			}
		})
	}
}

// AI Studio is the login-free region test: both answers arrive as 200, so the
// final URL is the only thing that separates "region is served" from "region is
// not served".
func TestClassifyAIStudio(t *testing.T) {
	const signIn = "https://accounts.google.com/v3/signin/identifier?continue=https://aistudio.google.com/prompts/new_chat"
	const blocked = "https://aistudio.google.com/docs/available-regions"
	cases := []struct {
		name     string
		status   int
		body     string
		finalURL string
		want     string
	}{
		{"跳登录页=地区可用", 200, `<html>Sign in</html>`, signIn, diag.AICheckOK},
		{"跳 available-regions=地区不支持", 200, `<html>Available regions</html>`, blocked, diag.AICheckRegion},
		{"available-regions 带查询串也是红", 200, `<html>regions</html>`, blocked + "?hl=en", diag.AICheckRegion},
		{"留在 aistudio 也是绿", 200, `<html>AI Studio</html>`, "https://aistudio.google.com/prompts/new_chat", diag.AICheckOK},
		{"风控挑战是黄", 403, `<html><title>Just a moment...</title>`, "", diag.AICheckRisk},
		{"429 限流是黄", 429, `slow down`, "", diag.AICheckRisk},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := diag.ClassifyAIStudio(tc.status, tc.body, tc.finalURL); got != tc.want {
				t.Fatalf("ClassifyAIStudio(%d, %q, %q) = %q, want %q", tc.status, tc.body, tc.finalURL, got, tc.want)
			}
		})
	}
}

// Three probes, one service: the worse answer wins, because one blocked path
// means the service is not usable from that node.
func TestGeminiCombinationTakesTheWorse(t *testing.T) {
	app, _ := diag.ClassifyGeminiApp(200, `<html>Sign in - Google Accounts</html>`, "")
	api, _ := diag.ClassifyGeminiAPI(200, `{"models":[{"name":"models/gemini-2.5-pro"}]}`, "")
	studio, _ := diag.ClassifyAIStudio(200, `<html>Sign in</html>`, "https://accounts.google.com/v3/signin/x")
	if app != diag.AICheckOK || api != diag.AICheckOK || studio != diag.AICheckOK {
		t.Fatalf("fixtures drifted: studio=%q api=%q app=%q", studio, api, app)
	}
	blocked, _ := diag.ClassifyAIStudio(200, `<html>regions</html>`, "https://aistudio.google.com/docs/available-regions")
	if blocked != diag.AICheckRegion {
		t.Fatalf("region fixture drifted: %q", blocked)
	}
	if aiRank(blocked) <= aiRank(studio) {
		t.Fatal("a region block must outrank a usable region")
	}
	risk, _ := diag.ClassifyGeminiApp(403, `<html><title>Just a moment...</title>`, "")
	if aiRank(risk) <= aiRank(studio) {
		t.Fatal("a challenge must outrank a usable region")
	}
}

// aiRank mirrors the package's ordering so this test can assert on the pair of
// answers the way the sweep combines them.
func aiRank(status string) int {
	switch status {
	case diag.AICheckOK:
		return 0
	case diag.AICheckRisk:
		return 1
	case diag.AICheckRegion:
		return 2
	case diag.AICheckBlocked:
		return 3
	case diag.AICheckTimeout:
		return 4
	default:
		return 5
	}
}

func TestClassifyAIError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"超时", context.DeadlineExceeded, diag.AICheckTimeout},
		{"包装过的超时", fmt.Errorf("probe: %w", context.DeadlineExceeded), diag.AICheckTimeout},
		{"连不上", errors.New("dial tcp 1.2.3.4:443: connect: connection refused"), diag.AICheckError},
		{"DNS 失败", errors.New("dial tcp: lookup api.openai.com: no such host"), diag.AICheckError},
		{"没有错误", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := diag.ClassifyAIError(tc.err); got != tc.want {
				t.Fatalf("ClassifyAIError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

func TestAICandidates(t *testing.T) {
	table := map[string]clashapi.Proxy{
		"示例机场":       {Name: "示例机场", Type: "Selector", Now: "香港 01"},
		"自动选择":       {Name: "自动选择", Type: "URLTest"},
		"故障转移":       {Name: "故障转移", Type: "Fallback"},
		"香港 01":      {Name: "香港 01", Type: "Vmess"},
		"香港 02":      {Name: "香港 02", Type: "Trojan"},
		"剩余流量：1.2TB": {Name: "剩余流量：1.2TB", Type: "Vmess"},
		"DIRECT":     {Name: "DIRECT", Type: "Direct"},
		"REJECT":     {Name: "REJECT", Type: "Reject"},
		"PROXY":      {Name: "PROXY", Type: "Selector"},
	}
	members := []string{
		"自动选择", "香港 01", "香港 02", "剩余流量：1.2TB",
		"DIRECT", "REJECT", "PROXY", "官网 https://example.com",
		"没在表里的节点", "香港 01", "   ",
	}
	got := aiCandidates(members, table)
	want := []string{"香港 01", "香港 02"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("aiCandidates = %v, want %v", got, want)
	}
}

func TestAICandidatesKeepsOrderWithoutDroppingRealNodes(t *testing.T) {
	table := map[string]clashapi.Proxy{
		"美国 03": {Name: "美国 03", Type: "Shadowsocks"},
		"日本 01": {Name: "日本 01", Type: "Hysteria2"},
		"香港 09": {Name: "香港 09", Type: "Vless"},
	}
	members := []string{"美国 03", "日本 01", "香港 09"}
	got := aiCandidates(members, table)
	if strings.Join(got, "|") != strings.Join(members, "|") {
		t.Fatalf("aiCandidates reordered or dropped real nodes: %v", got)
	}
}

func TestPickAIBest(t *testing.T) {
	rows := []diag.AIRow{
		{
			Node:    "慢的",
			ChatGPT: diag.AICheck{Status: diag.AICheckOK, MS: 900},
			Gemini:  diag.AICheck{Status: diag.AICheckOK, MS: 900},
			Verdict: "both",
		},
		{
			Node:    "快的",
			ChatGPT: diag.AICheck{Status: diag.AICheckOK, MS: 100},
			Gemini:  diag.AICheck{Status: diag.AICheckOK, MS: 150},
			Verdict: "both",
		},
		{
			Node:    "只有 ChatGPT",
			ChatGPT: diag.AICheck{Status: diag.AICheckOK, MS: 1},
			Gemini:  diag.AICheck{Status: diag.AICheckBlocked, MS: 1},
			Verdict: "chatgpt",
		},
	}
	best := diag.PickAIBest(rows)
	if best.Node != "快的" || best.MS != 250 || !best.ChatGPT || !best.Gemini {
		t.Fatalf("PickAIBest = %+v, want 快的/250", best)
	}
	if zero := diag.PickAIBest(nil); zero.Node != "" {
		t.Fatalf("no both-row must give the zero value, got %+v", zero)
	}
}

// TestAIFieldNames pins the JSON keys the frozen contract gives the page: the
// field names are what the frontend was written against, so a rename here
// breaks the page silently.
func TestAIFieldNames(t *testing.T) {
	cases := []struct {
		name string
		v    any
		want []string
	}{
		{
			"status",
			diag.AIStatus{},
			[]string{"best", "done", "errors", "group", "job", "phase", "restore_detail", "restore_state", "rows", "running", "total"},
		},
		{"row", diag.AIRow{}, []string{"chatgpt", "gemini", "node", "verdict"}},
		{"check", diag.AICheck{}, []string{"detail", "http_status", "ms", "status"}},
		{"job", diag.AIJob{}, []string{"group", "job", "restore", "total"}},
		{"best", diag.AIBest{}, []string{"chatgpt", "gemini", "ms", "node"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.v)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var m map[string]json.RawMessage
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			got := make([]string, 0, len(m))
			for k := range m {
				got = append(got, k)
			}
			sort.Strings(got)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("%s keys = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}
