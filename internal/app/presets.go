package app

import (
	"context"
	"fmt"

	"vvpn/internal/core"
)

// Preset is a named bundle of rules the user can apply with one click.
//
// The rules are written against the neutral model, so the same preset works
// with every core: each emitter translates process/domain/IP kinds into that
// core's own syntax.
type Preset struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Rules       []core.Rule `json:"rules"`
	// Applied reports whether every rule of this preset is already present.
	Applied bool `json:"applied,omitempty"`
}

// Presets are the built-in rule bundles, ordered from the most commonly wanted
// to the most specialized.
func Presets() []Preset {
	return []Preset{
		{
			ID:          "smart-split",
			Name:        "智能分流（国内直连 · 国外走节点）",
			Description: "内网、局域网、国内域名与国内 IP 一律直连，其余流量走节点。开着客户端，内网和外网都能正常访问——这是最省心的一套默认规则。",
			Rules: []core.Rule{
				// 内网直连：局域网、回环与链路本地地址永远不该走代理。
				{Kind: core.RuleIPCIDR, Value: "127.0.0.0/8", Action: core.ActionDirect},
				{Kind: core.RuleIPCIDR, Value: "10.0.0.0/8", Action: core.ActionDirect},
				{Kind: core.RuleIPCIDR, Value: "172.16.0.0/12", Action: core.ActionDirect},
				{Kind: core.RuleIPCIDR, Value: "192.168.0.0/16", Action: core.ActionDirect},
				{Kind: core.RuleIPCIDR, Value: "169.254.0.0/16", Action: core.ActionDirect},
				{Kind: core.RuleIPCIDR, Value: "224.0.0.0/4", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "local", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "localhost", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "lan", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "home.arpa", Action: core.ActionDirect},
				// 国内直连：域名库与 IP 归属地两条都留，谁先生效都能兜住。
				{Kind: core.RuleGeoSite, Value: "cn", Action: core.ActionDirect},
				{Kind: core.RuleGeoSite, Value: "geolocation-cn", Action: core.ActionDirect},
				{Kind: core.RuleGeoSite, Value: "private", Action: core.ActionDirect},
				{Kind: core.RuleGeoIP, Value: "cn", Action: core.ActionDirect},
				{Kind: core.RuleGeoIP, Value: "private", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "cn", Action: core.ActionDirect},
			},
		},
		{
			ID:          "private-direct",
			Name:        "内网直连",
			Description: "局域网、回环与本机链路一律直连，避免代理软件把内网请求送出去",
			Rules: []core.Rule{
				{Kind: core.RuleIPCIDR, Value: "127.0.0.0/8", Action: core.ActionDirect},
				{Kind: core.RuleIPCIDR, Value: "10.0.0.0/8", Action: core.ActionDirect},
				{Kind: core.RuleIPCIDR, Value: "172.16.0.0/12", Action: core.ActionDirect},
				{Kind: core.RuleIPCIDR, Value: "192.168.0.0/16", Action: core.ActionDirect},
				{Kind: core.RuleIPCIDR, Value: "169.254.0.0/16", Action: core.ActionDirect},
				{Kind: core.RuleIPCIDR, Value: "224.0.0.0/4", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "local", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "localhost", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "lan", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "home.arpa", Action: core.ActionDirect},
			},
		},
		{
			ID:          "ads-block",
			Name:        "广告与追踪拦截",
			Description: "拦截常见广告、统计与遥测域名（命中即断开，不消耗代理流量）",
			Rules: []core.Rule{
				{Kind: core.RuleDomainKeyword, Value: "doubleclick", Action: core.ActionReject},
				{Kind: core.RuleDomainKeyword, Value: "googlesyndication", Action: core.ActionReject},
				{Kind: core.RuleDomainKeyword, Value: "google-analytics", Action: core.ActionReject},
				{Kind: core.RuleDomainKeyword, Value: "googletagmanager", Action: core.ActionReject},
				{Kind: core.RuleDomainKeyword, Value: "adservice", Action: core.ActionReject},
				{Kind: core.RuleDomainKeyword, Value: "adsystem", Action: core.ActionReject},
				{Kind: core.RuleDomainKeyword, Value: "adnxs", Action: core.ActionReject},
				{Kind: core.RuleDomainKeyword, Value: "criteo", Action: core.ActionReject},
				{Kind: core.RuleDomainKeyword, Value: "taboola", Action: core.ActionReject},
				{Kind: core.RuleDomainKeyword, Value: "outbrain", Action: core.ActionReject},
				{Kind: core.RuleDomainKeyword, Value: "scorecardresearch", Action: core.ActionReject},
				{Kind: core.RuleDomainKeyword, Value: "branch.io", Action: core.ActionReject},
				{Kind: core.RuleDomainKeyword, Value: "appsflyer", Action: core.ActionReject},
				{Kind: core.RuleDomainKeyword, Value: "adjust.com", Action: core.ActionReject},
				{Kind: core.RuleDomainSuffix, Value: "umeng.com", Action: core.ActionReject},
				{Kind: core.RuleDomainSuffix, Value: "umengcloud.com", Action: core.ActionReject},
				{Kind: core.RuleDomainSuffix, Value: "cnzz.com", Action: core.ActionReject},
				{Kind: core.RuleDomainSuffix, Value: "bugly.qq.com", Action: core.ActionReject},
			},
		},
		{
			ID:          "direct-cn",
			Name:        "国内直连",
			Description: "中国域名与 IP 段走直连，其余流量走代理（最常用的分流方式）",
			Rules: []core.Rule{
				{Kind: core.RuleGeoSite, Value: "cn", Action: core.ActionDirect},
				{Kind: core.RuleGeoSite, Value: "geolocation-cn", Action: core.ActionDirect},
				{Kind: core.RuleGeoSite, Value: "private", Action: core.ActionDirect},
				{Kind: core.RuleGeoIP, Value: "cn", Action: core.ActionDirect},
				{Kind: core.RuleGeoIP, Value: "private", Action: core.ActionDirect},
			},
		},
		{
			ID:          "ai-direct",
			Name:        "AI 服务走代理",
			Description: "常见 AI 服务固定走代理，避免因地区限制被拒",
			Rules: []core.Rule{
				{Kind: core.RuleDomainSuffix, Value: "openai.com", Action: core.ActionProxy},
				{Kind: core.RuleDomainSuffix, Value: "chatgpt.com", Action: core.ActionProxy},
				{Kind: core.RuleDomainSuffix, Value: "oaistatic.com", Action: core.ActionProxy},
				{Kind: core.RuleDomainSuffix, Value: "oaiusercontent.com", Action: core.ActionProxy},
				{Kind: core.RuleDomainSuffix, Value: "anthropic.com", Action: core.ActionProxy},
				{Kind: core.RuleDomainSuffix, Value: "claude.ai", Action: core.ActionProxy},
				{Kind: core.RuleDomainSuffix, Value: "gemini.google.com", Action: core.ActionProxy},
				{Kind: core.RuleDomainSuffix, Value: "generativelanguage.googleapis.com", Action: core.ActionProxy},
				{Kind: core.RuleDomainSuffix, Value: "perplexity.ai", Action: core.ActionProxy},
				{Kind: core.RuleDomainSuffix, Value: "copilot.microsoft.com", Action: core.ActionProxy},
				{Kind: core.RuleDomainSuffix, Value: "x.ai", Action: core.ActionProxy},
				{Kind: core.RuleDomainSuffix, Value: "huggingface.co", Action: core.ActionProxy},
			},
		},
		{
			ID:          "dev-direct",
			Name:        "开发资源直连",
			Description: "代码托管与包管理走直连，避免大文件下载被代理拖慢或触发风控",
			Rules: []core.Rule{
				{Kind: core.RuleDomainSuffix, Value: "githubusercontent.com", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "npmjs.org", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "npmjs.com", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "pypi.org", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "pythonhosted.org", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "crates.io", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "goproxy.cn", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "maven.org", Action: core.ActionDirect},
				{Kind: core.RuleDomainSuffix, Value: "nuget.org", Action: core.ActionDirect},
			},
		},
		{
			ID:          "bgp-reject",
			Name:        "屏蔽常见扫描与探测",
			Description: "丢弃 NetBIOS、SMB、mDNS 等易被内网探测利用的端口流量",
			Rules: []core.Rule{
				{Kind: core.RulePort, Value: "137-139", Action: core.ActionReject},
				{Kind: core.RulePort, Value: "445", Action: core.ActionReject},
				{Kind: core.RulePort, Value: "5353", Action: core.ActionReject},
				{Kind: core.RulePort, Value: "1900", Action: core.ActionReject},
			},
		},
	}
}

// PresetView is a preset plus how many of its rules are already applied.
type PresetView struct {
	Preset
	AppliedCount int `json:"applied_count"`
	TotalCount   int `json:"total_count"`
}

// DefaultPresetID is the bundle a fresh client starts with: 国内直连 / 国外走节点.
const DefaultPresetID = "smart-split"

// ApplyDefaultPresetOnce gives a new install its default routing rules without
// making the user find the 规则 page first. It runs at most once: the flag it
// leaves behind is also set by any manual apply or remove, so a user who deleted
// the preset does not get it back on the next launch.
func (a *App) ApplyDefaultPresetOnce(ctx context.Context) {
	if a.PresetAutoDone() {
		return
	}
	view, err := a.ApplyPreset(ctx, DefaultPresetID)
	if err != nil {
		a.log.Warnf("默认预设规则集应用失败：%v", err)
		return
	}
	a.log.Infof("默认预设规则集已应用：%d/%d 条规则", view.AppliedCount, view.TotalCount)
}

// PresetList reports the built-in presets and their current application state.
func (a *App) PresetList() []PresetView {
	existing := a.Profile().Rules
	index := make(map[string]bool, len(existing))
	for _, r := range existing {
		index[ruleKey(r)] = true
	}

	presets := Presets()
	out := make([]PresetView, 0, len(presets))
	for _, p := range presets {
		count := 0
		for _, r := range p.Rules {
			if index[ruleKey(r)] {
				count++
			}
		}
		view := PresetView{Preset: p, AppliedCount: count, TotalCount: len(p.Rules)}
		view.Applied = count == len(p.Rules) && len(p.Rules) > 0
		out = append(out, view)
	}
	return out
}

// ApplyPreset adds every rule of a preset that is not present yet, inserting
// them before the catch-all rule. A manual apply counts as the user having
// dealt with the built-in default, so the startup pass never re-adds it.
func (a *App) ApplyPreset(ctx context.Context, id string) (PresetView, error) {
	view, err := a.applyPreset(ctx, id)
	if err == nil {
		a.markPresetAutoDone()
	}
	return view, err
}

func (a *App) applyPreset(ctx context.Context, id string) (PresetView, error) {
	var preset Preset
	found := false
	for _, p := range Presets() {
		if p.ID == id {
			preset = p
			found = true
			break
		}
	}
	if !found {
		return PresetView{}, fmt.Errorf("预设规则集 %q 不存在", id)
	}

	profile := a.Profile()
	index := make(map[string]bool, len(profile.Rules))
	for _, r := range profile.Rules {
		index[ruleKey(r)] = true
	}

	added := make([]core.Rule, 0, len(preset.Rules))
	for _, r := range preset.Rules {
		key := ruleKey(r)
		if index[key] {
			continue
		}
		index[key] = true
		added = append(added, r)
	}
	if len(added) == 0 {
		return a.presetView(id), nil
	}

	// Preset rules belong after the user's own rules but before the catch-all,
	// so nothing shadows them and they never become dead rules.
	insert := len(profile.Rules)
	for i, r := range profile.Rules {
		if r.Kind == core.RuleFinal {
			insert = i
			break
		}
	}
	rules := make([]core.Rule, 0, len(profile.Rules)+len(added))
	rules = append(rules, profile.Rules[:insert]...)
	rules = append(rules, added...)
	rules = append(rules, profile.Rules[insert:]...)
	profile.Rules = rules

	if err := a.SetProfile(ctx, profile); err != nil {
		return PresetView{}, err
	}
	a.log.Infof("预设规则集 %s：新增 %d 条规则", preset.Name, len(added))
	return a.presetView(id), nil
}

// RemovePreset deletes every rule that belongs to a preset. Removing one is
// the clearest possible statement that the default is not wanted.
func (a *App) RemovePreset(ctx context.Context, id string) (PresetView, error) {
	view, err := a.removePreset(ctx, id)
	if err == nil {
		a.markPresetAutoDone()
	}
	return view, err
}

func (a *App) removePreset(ctx context.Context, id string) (PresetView, error) {
	var preset Preset
	found := false
	for _, p := range Presets() {
		if p.ID == id {
			preset = p
			found = true
			break
		}
	}
	if !found {
		return PresetView{}, fmt.Errorf("预设规则集 %q 不存在", id)
	}
	drop := make(map[string]bool, len(preset.Rules))
	for _, r := range preset.Rules {
		drop[ruleKey(r)] = true
	}

	profile := a.Profile()
	rules := make([]core.Rule, 0, len(profile.Rules))
	removed := 0
	for _, r := range profile.Rules {
		if drop[ruleKey(r)] {
			removed++
			continue
		}
		rules = append(rules, r)
	}
	if removed == 0 {
		return a.presetView(id), nil
	}
	profile.Rules = rules
	if err := a.SetProfile(ctx, profile); err != nil {
		return PresetView{}, err
	}
	a.log.Infof("预设规则集 %s：移除 %d 条规则", preset.Name, removed)
	return a.presetView(id), nil
}

// presetView returns one preset with its refreshed application state.
func (a *App) presetView(id string) PresetView {
	for _, v := range a.PresetList() {
		if v.ID == id {
			return v
		}
	}
	return PresetView{}
}

// ruleKey identifies a rule by kind, value and action, ignoring position.
func ruleKey(r core.Rule) string {
	return ruleIdentity(r)
}
