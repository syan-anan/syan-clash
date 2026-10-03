package subscription

import (
	"strings"
	"testing"

	"vvpn/internal/core"
)

// A subscription that ships rule-providers has to arrive with both halves: the
// named sets and the RULE-SET rules that point at them. Dropping either one
// would silently change how traffic is routed.
const clashWithRuleProviders = `mixed-port: 7890
proxies:
  - name: n1
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: pw
proxy-groups:
  - name: PROXY
    type: select
    proxies: [n1]
rule-providers:
  ads:
    type: http
    behavior: classical
    url: https://example.com/ads.yaml
    interval: 3600
  cn:
    type: inline
    behavior: domain
    payload:
      - example.cn
      - example.com.cn
rules:
  - RULE-SET,ads,REJECT
  - RULE-SET,cn,DIRECT
  - RULE-SET,missing,DIRECT
  - DOMAIN-SUFFIX,keep.example,DIRECT
  - MATCH,PROXY
`

func TestParseClashImportsRuleProviders(t *testing.T) {
	profile, err := ParseClash(clashWithRuleProviders)
	if err != nil {
		t.Fatalf("ParseClash: %v", err)
	}
	if len(profile.RuleProviders) != 2 {
		t.Fatalf("imported %d rule providers, want 2: %+v", len(profile.RuleProviders), profile.RuleProviders)
	}
	byName := map[string]core.RuleProvider{}
	for _, rp := range profile.RuleProviders {
		byName[rp.Name] = rp
	}
	ads, ok := byName["ads"]
	if !ok {
		t.Fatalf("the http provider was not imported: %+v", byName)
	}
	if ads.Type != core.ProviderHTTP || ads.Behavior != core.ProviderBehaviorClassical {
		t.Errorf("ads = %+v, want an http/classical provider", ads)
	}
	if ads.URL != "https://example.com/ads.yaml" || ads.Interval != 3600 {
		t.Errorf("ads = %+v, want the url and interval from the document", ads)
	}
	cn, ok := byName["cn"]
	if !ok {
		t.Fatalf("the inline provider was not imported: %+v", byName)
	}
	if len(cn.Payload) != 2 || cn.Payload[0] != "example.cn" {
		t.Errorf("cn payload = %v, want the two inline domains", cn.Payload)
	}
}

func TestParseClashKeepsOnlyResolvableRuleSetRules(t *testing.T) {
	profile, err := ParseClash(clashWithRuleProviders)
	if err != nil {
		t.Fatalf("ParseClash: %v", err)
	}
	var refs []string
	for _, r := range profile.Rules {
		if r.Kind == core.RuleProviderRef {
			refs = append(refs, r.Value)
		}
	}
	if strings.Join(refs, ",") != "ads,cn" {
		t.Errorf("kept rule-set references %v, want only ads and cn (missing has no provider)", refs)
	}
	// The rest of the rule list is untouched.
	kept := false
	for _, r := range profile.Rules {
		if r.Kind == core.RuleDomainSuffix && r.Value == "keep.example" {
			kept = true
		}
	}
	if !kept {
		t.Errorf("the domain-suffix rule after the RULE-SET lines was lost: %+v", profile.Rules)
	}
	// And the result still compiles for every core.
	p := core.DefaultProfile()
	p.Nodes = profile.Nodes
	p.Groups = profile.Groups
	p.RuleProviders = profile.RuleProviders
	p.Rules = append([]core.Rule{}, profile.Rules...)
	p.Final = "PROXY"
	if err := p.Validate(); err != nil {
		t.Fatalf("the imported profile does not validate: %v", err)
	}
	for _, id := range []string{"sing-box", "mihomo", "xray"} {
		if _, err := core.Render(id, p); err != nil {
			t.Errorf("the imported profile cannot be compiled for %s: %v", id, err)
		}
	}
}
