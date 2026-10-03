// Package rules implements the ordered domain/IP/port routing decision engine
// that picks an outbound for every proxied connection.
//
// Evaluation is a single ordered scan, exactly like Clash/sing-box: the first
// matching rule wins. IP rules need the resolved address, so Match reports
// NeedResolve instead of guessing when it reaches an ip-cidr rule with no
// address yet; the caller resolves and calls Match again with the same host.
package rules

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Action is what the engine decides to do with a connection.
type Action string

const (
	ActionDirect Action = "direct"
	ActionProxy  Action = "proxy"
	ActionReject Action = "reject"
)

// Valid reports whether a is a known action.
func (a Action) Valid() bool {
	switch a {
	case ActionDirect, ActionProxy, ActionReject:
		return true
	}
	return false
}

// Supported rule kinds.
const (
	KindDomain        = "domain"
	KindDomainSuffix  = "domain-suffix"
	KindDomainKeyword = "domain-keyword"
	KindIPCIDR        = "ip-cidr"
	KindPort          = "port"
	KindGeoIP         = "geoip"
	KindGeoSite       = "geosite"
	KindProcessName   = "process-name"
	KindProcessPath   = "process-path"
	KindFinal         = "final"
	// KindRuleProvider names an external rule list (mihomo's RULE-SET). The
	// built-in engine has no rule-provider loader, so it accepts the rule and
	// skips it during matching, exactly like the geo and process kinds.
	KindRuleProvider = "rule-provider"
)

// Kinds lists every supported rule kind in the order they are documented.
var Kinds = []string{
	KindDomain, KindDomainSuffix, KindDomainKeyword,
	KindIPCIDR, KindPort, KindGeoIP, KindGeoSite,
	KindProcessName, KindProcessPath, KindRuleProvider, KindFinal,
}

// Rule is one routing rule, evaluated in list order.
type Rule struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Action string `json:"action"`
}

// Validate checks a single rule definition.
func Validate(kind, value, action string) error {
	if !Action(action).Valid() {
		return fmt.Errorf("rule %s %q: unknown action %q", kind, value, action)
	}
	switch kind {
	case KindDomain:
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("rule %s: value must not be empty", kind)
		}
	case KindDomainSuffix, KindDomainKeyword:
		if strings.Trim(strings.TrimSpace(value), ".") == "" {
			return fmt.Errorf("rule %s: value must not be empty", kind)
		}
	case KindIPCIDR:
		if _, err := parsePrefix(value); err != nil {
			return err
		}
	case KindPort:
		if _, _, err := parsePortRange(value); err != nil {
			return err
		}
	case KindGeoIP, KindGeoSite, KindProcessName, KindProcessPath, KindRuleProvider:
		// The built-in engine cannot act on these (it has no geo database, does
		// not see the owning process, and does not load rule sets), so they are
		// accepted and skipped during matching. Rejecting them would make a
		// profile that is valid for an external core invalid in built-in mode.
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("rule %s: value must not be empty", kind)
		}
	case KindFinal:
		if strings.TrimSpace(value) != "" {
			return fmt.Errorf("rule %s: value must be empty", kind)
		}
	default:
		return fmt.Errorf("unknown rule kind %q (supported: %s)", kind, strings.Join(Kinds, ", "))
	}
	return nil
}

func parsePrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if p, err := netip.ParsePrefix(value); err == nil {
		return p.Masked(), nil
	}
	// Accept a bare address as a host route.
	if addr, err := netip.ParseAddr(value); err == nil {
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("rule %s: %q is not a CIDR prefix or address", KindIPCIDR, value)
}

func parsePortRange(value string) (uint16, uint16, error) {
	value = strings.TrimSpace(value)
	lo, hi, ok := strings.Cut(value, "-")
	if !ok {
		p, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return 0, 0, fmt.Errorf("rule %s: %q is not a port or port range", KindPort, value)
		}
		return uint16(p), uint16(p), nil
	}
	l, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("rule %s: %q is not a port range", KindPort, value)
	}
	h, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("rule %s: %q is not a port range", KindPort, value)
	}
	if l > h {
		return 0, 0, fmt.Errorf("rule %s: range %q is inverted", KindPort, value)
	}
	return uint16(l), uint16(h), nil
}

type compiled struct {
	rule   Rule
	prefix netip.Prefix
	lo, hi uint16
}

// Result is the outcome of one evaluation pass.
type Result struct {
	Action      Action `json:"action"`
	Rule        string `json:"rule"`
	Index       int    `json:"index"`
	NeedResolve bool   `json:"need_resolve"`
}

// Engine is an immutable, pre-compiled rule list.
type Engine struct {
	rules []compiled
}

// New compiles a rule list. An empty list is valid: every connection then falls
// through to the documented proxy fallback.
func New(rs []Rule) (*Engine, error) {
	e := &Engine{rules: make([]compiled, 0, len(rs))}
	for i, r := range rs {
		r.Kind = strings.ToLower(strings.TrimSpace(r.Kind))
		r.Action = strings.ToLower(strings.TrimSpace(r.Action))
		if err := Validate(r.Kind, r.Value, r.Action); err != nil {
			return nil, fmt.Errorf("rule #%d: %w", i+1, err)
		}
		c := compiled{rule: r}
		switch r.Kind {
		case KindIPCIDR:
			p, err := parsePrefix(r.Value)
			if err != nil {
				return nil, fmt.Errorf("rule #%d: %w", i+1, err)
			}
			c.prefix = p
		case KindPort:
			lo, hi, err := parsePortRange(r.Value)
			if err != nil {
				return nil, fmt.Errorf("rule #%d: %w", i+1, err)
			}
			c.lo, c.hi = lo, hi
		}
		e.rules = append(e.rules, c)
	}
	return e, nil
}

// Rules returns the uncompiled rule list, for display and editing.
func (e *Engine) Rules() []Rule {
	out := make([]Rule, 0, len(e.rules))
	for _, c := range e.rules {
		out = append(out, c.rule)
	}
	return out
}

func describe(r Rule) string {
	if r.Kind == KindFinal {
		return fmt.Sprintf("final -> %s", r.Action)
	}
	return fmt.Sprintf("%s %s -> %s", r.Kind, r.Value, r.Action)
}

// Match evaluates the rule list for host (may be empty), resolved address ip
// (zero value when unknown) and port.
func (e *Engine) Match(host string, ip netip.Addr, port uint16) Result {
	h := normalizeHost(host)
	if ip.IsValid() {
		ip = ip.Unmap()
	}
	// An ip-cidr rule cannot decide without the resolved address, but it must
	// not stop the scan: a later domain rule still has everything it needs and
	// has to be allowed to win. Only when nothing else matches do we ask the
	// caller to resolve and come back.
	needResolve := false
	for i, c := range e.rules {
		switch c.rule.Kind {
		case KindFinal:
			if needResolve {
				return Result{Rule: describe(c.rule), Index: i, NeedResolve: true}
			}
			return Result{Action: Action(c.rule.Action), Rule: describe(c.rule), Index: i}
		case KindDomain:
			if h != "" && h == strings.ToLower(strings.TrimSpace(c.rule.Value)) {
				return Result{Action: Action(c.rule.Action), Rule: describe(c.rule), Index: i}
			}
		case KindDomainSuffix:
			v := strings.ToLower(strings.Trim(strings.TrimSpace(c.rule.Value), "."))
			if h != "" && v != "" && (h == v || strings.HasSuffix(h, "."+v)) {
				return Result{Action: Action(c.rule.Action), Rule: describe(c.rule), Index: i}
			}
		case KindDomainKeyword:
			v := strings.ToLower(strings.TrimSpace(c.rule.Value))
			if h != "" && v != "" && strings.Contains(h, v) {
				return Result{Action: Action(c.rule.Action), Rule: describe(c.rule), Index: i}
			}
		case KindIPCIDR:
			if !ip.IsValid() {
				needResolve = true
				continue
			}
			if c.prefix.Contains(ip) {
				return Result{Action: Action(c.rule.Action), Rule: describe(c.rule), Index: i}
			}
		case KindPort:
			if port >= c.lo && port <= c.hi {
				return Result{Action: Action(c.rule.Action), Rule: describe(c.rule), Index: i}
			}
		case KindGeoIP, KindGeoSite, KindProcessName, KindProcessPath, KindRuleProvider:
			// Not evaluable in built-in mode; skip so the next rule decides.
			continue
		}
	}
	if needResolve {
		return Result{Rule: "ip rules need the resolved address", Index: -1, NeedResolve: true}
	}
	return Result{Action: ActionProxy, Rule: "fallback: no rule matched", Index: -1}
}

func normalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.Trim(h, "[]")
	h = strings.TrimSuffix(h, ".")
	return h
}
