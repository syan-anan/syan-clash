package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"vvpn/internal/clashapi"
	"vvpn/internal/core"
	"vvpn/internal/subscription"
	"vvpn/internal/urlscheme"
)

// ImportResult summarises what a subscription import produced.
type ImportResult struct {
	Nodes  int                `json:"nodes"`
	Groups int                `json:"groups"`
	Rules  int                `json:"rules"`
	Names  []string           `json:"names"`
	Source string             `json:"source"`
	Format string             `json:"format"`
	Info   *subscription.Info `json:"info,omitempty"`
}

// ImportSubscription parses a subscription (raw payload or a URL to fetch) and
// installs the result as the core profile.
func (a *App) ImportSubscription(ctx context.Context, payload string) (ImportResult, error) {
	return a.ImportSubscriptionAs(ctx, "", payload)
}

// ImportSubscriptionAs imports under a subscription name. When name is set, the
// nodes that name previously contributed are replaced and every other
// subscription's nodes are kept; an empty name merges by name.
func (a *App) ImportSubscriptionAs(ctx context.Context, name, payload string) (ImportResult, error) {
	return a.importSubscriptionAs(ctx, name, payload, "")
}

// ImportSubscriptionWithUserAgent is ImportSubscriptionAs with an explicit
// User-Agent. An empty value falls back to the one saved for the subscription,
// then to the client default.
func (a *App) ImportSubscriptionWithUserAgent(ctx context.Context, name, payload, userAgent string) (ImportResult, error) {
	return a.importSubscriptionAs(ctx, name, payload, userAgent)
}

func (a *App) importSubscriptionAs(ctx context.Context, name, payload, userAgent string) (ImportResult, error) {
	text := strings.TrimSpace(payload)
	if text == "" {
		return ImportResult{}, fmt.Errorf("subscription: nothing to import")
	}
	// A clash:// link pasted into the import box carries the subscription
	// address inside it. Unwrapping it here means the box, the clipboard
	// button and the clash:// handler all accept the same thing, and a link
	// copied out of a chat works exactly like the address inside it.
	if resolved, ok := urlscheme.ResolveSubscriptionURL(text); ok {
		text = resolved
	}
	result := ImportResult{Source: "payload"}
	if looksLikeSubscriptionURL(text) {
		// An airport decides what to serve from this header, so a per
		// subscription choice has to win over the built-in default.
		if userAgent == "" {
			userAgent = a.subscriptionUserAgent(name)
		}
		fetched, info, err := fetchSubscriptionAs(ctx, text, userAgent)
		if err != nil {
			return ImportResult{}, err
		}
		text = fetched
		result.Source = "url"
		result.Info = info
	}

	cfg := a.Config()
	profile := EffectiveProfile(cfg)

	if looksLikeClashText(text) {
		imported, err := subscription.ParseClash(text)
		if err != nil {
			return ImportResult{}, err
		}
		result.Format = "clash"
		if len(imported.Nodes) > 0 {
			profile.Nodes, _ = replaceNodesFrom(name, profile.Nodes, imported.Nodes)
			if name != "" {
				recordNodes(name, imported.Nodes)
			}
			result.Names = nodeNamesOf(imported.Nodes)
			result.Nodes = len(imported.Nodes)
		}
		if len(imported.Groups) > 0 {
			profile.Groups = mergeGroups(imported.Groups, profile.Nodes)
			result.Groups = len(imported.Groups)
		}
		if len(imported.Rules) > 0 {
			profile.Rules = imported.Rules
			result.Rules = len(imported.Rules)
		}
	} else {
		nodes, err := subscription.Parse(text)
		if err != nil {
			return ImportResult{}, err
		}
		result.Format = "links"
		// Merge rather than replace: another subscription's nodes must survive.
		profile.Nodes, _ = replaceNodesFrom(name, profile.Nodes, nodes)
		if name != "" {
			recordNodes(name, nodes)
		}
		result.Names = nodeNamesOf(nodes)
		result.Nodes = len(nodes)
		profile.Groups = mergeGroups(profile.Groups, profile.Nodes)
		result.Groups = len(profile.Groups)
	}

	// The pre-filter list is what the subscription actually delivered, and it
	// is the baseline every filter run recomputes from. Saving it here is what
	// makes renaming and excluding survive a subscription update.
	if err := a.saveNodeBase(profile.Nodes, nil); err != nil {
		a.log.Warnf("保存节点基线失败：%v", err)
	}
	if filter := cfg.NodeFilter; !filter.IsZero() {
		kept, renamed, dropped := applyNodeFilter(profile.Nodes, filter)
		if len(kept) == 0 {
			return ImportResult{}, fmt.Errorf("过滤后一个节点都不剩（丢弃 %d 个）：请放宽节点过滤设置", dropped)
		}
		profile.Nodes = kept
		// A freshly imported node list has no earlier renames to undo.
		profile.Groups = mergeGroups(rebindGroups(profile.Groups, nil, renamed), kept)
		profile.Rules = rebindRules(profile.Rules, nil, renamed)
		profile.Final = mapName(profile.Final, renamed)
	}

	// Importing a subscription replaces the node list, so the profile would
	// otherwise lose the private-network shortcuts and send LAN/loopback
	// requests to a remote server. Re-apply them unless already present.
	profile.Rules = ensurePrivateDirect(profile.Rules)

	// A final rule that points at a group which no longer exists would make the
	// profile invalid, so it is recomputed from the imported groups.
	profile.Final = ""
	profile.Rules = stripStaleFinal(profile.Rules)
	if len(profile.Groups) > 0 {
		profile.Final = profile.Groups[0].Name
	}
	if err := profile.Validate(); err != nil {
		return ImportResult{}, fmt.Errorf("subscription: imported profile is not usable: %w", err)
	}

	cfg.Core.Profile = &profile
	if err := a.Reload(cfg); err != nil {
		return ImportResult{}, err
	}
	for _, n := range profile.Nodes {
		result.Names = append(result.Names, n.Name)
	}
	if err := a.restartRunningCore(ctx, profile); err != nil {
		return result, err
	}
	return result, nil
}

// SetProfile replaces the neutral profile and restarts the core when running.
func (a *App) SetProfile(ctx context.Context, profile core.Profile) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	cfg := a.Config()
	cfg.Core.Profile = &profile
	if err := a.Reload(cfg); err != nil {
		return err
	}
	return a.restartRunningCore(ctx, profile)
}

// Profile returns the effective neutral profile.
func (a *App) Profile() core.Profile { return EffectiveProfile(a.Config()) }

// restartRunningCore applies a new profile to the core if it is running.
func (a *App) restartRunningCore(ctx context.Context, profile core.Profile) error {
	id := a.RunningCoreID()
	if id == "" {
		return nil
	}
	if err := a.cores.Stop(id); err != nil {
		return err
	}
	_, err := a.StartCore(ctx, id)
	return err
}

// DefaultGroups builds the conventional PROXY / AUTO pair for a node list.
func DefaultGroups(nodes []core.Node) []core.Group {
	if len(nodes) == 0 {
		return nil
	}
	names := make([]string, 0, len(nodes))
	for _, n := range nodes {
		names = append(names, n.Name)
	}
	if len(names) == 1 {
		return []core.Group{{Name: "PROXY", Type: core.GroupSelect, Members: names}}
	}
	return []core.Group{
		{Name: "PROXY", Type: core.GroupSelect, Members: append(append([]string{}, names...), "AUTO")},
		{Name: "AUTO", Type: core.GroupURLTest, Members: names, Interval: 300},
	}
}

func stripStaleFinal(rules []core.Rule) []core.Rule {
	out := make([]core.Rule, 0, len(rules))
	for _, r := range rules {
		if r.Kind == core.RuleFinal {
			continue
		}
		out = append(out, r)
	}
	return out
}

// privateDirectRules are the shortcuts that must survive a subscription import:
// without them, requests to the local machine and the LAN would be routed
// through a remote node (slow at best, broken at worst).
var privateDirectRules = []core.Rule{
	{Kind: core.RuleIPCIDR, Value: "127.0.0.0/8", Action: core.ActionDirect},
	{Kind: core.RuleIPCIDR, Value: "10.0.0.0/8", Action: core.ActionDirect},
	{Kind: core.RuleIPCIDR, Value: "172.16.0.0/12", Action: core.ActionDirect},
	{Kind: core.RuleIPCIDR, Value: "192.168.0.0/16", Action: core.ActionDirect},
	{Kind: core.RuleIPCIDR, Value: "169.254.0.0/16", Action: core.ActionDirect},
	{Kind: core.RuleDomainSuffix, Value: "local", Action: core.ActionDirect},
	{Kind: core.RuleDomainSuffix, Value: "localhost", Action: core.ActionDirect},
	{Kind: core.RuleDomainSuffix, Value: "lan", Action: core.ActionDirect},
}

// ensurePrivateDirect prepends the private-network shortcuts that are missing,
// keeping any equivalent rule the user already configured.
func ensurePrivateDirect(rules []core.Rule) []core.Rule {
	have := make(map[string]bool, len(rules))
	for _, r := range rules {
		have[ruleIdentity(r)] = true
	}
	var missing []core.Rule
	for _, r := range privateDirectRules {
		if !have[ruleIdentity(r)] {
			missing = append(missing, r)
		}
	}
	if len(missing) == 0 {
		return rules
	}
	// They go first: a rule a provider shipped later could otherwise shadow them.
	out := make([]core.Rule, 0, len(missing)+len(rules))
	out = append(out, missing...)
	return append(out, rules...)
}

// ruleIdentity keys a rule by kind, value and action, ignoring case and spacing.
func ruleIdentity(r core.Rule) string {
	return strings.ToLower(strings.TrimSpace(r.Kind)) + "\x00" +
		strings.ToLower(strings.TrimSpace(r.Value)) + "\x00" +
		strings.ToLower(strings.TrimSpace(r.Action))
}

// subscriptionUserAgent is what the client presents when it fetches a
// subscription. It matters: airports routinely fingerprint the User-Agent and
// answer anything they do not recognise with a placeholder node list ("你的
// 客户端太旧") instead of the real servers — verified against a live airport
// that serves decoys to unknown agents and the real list to current clients.
// syan-clash drives mihomo and speaks the Clash wire protocol, so it identifies
// the same way Clash Verge Rev does.
// It is a variable rather than a constant because the settings page lets the
// operator override it per subscription; fetchSubscriptionAs takes the value
// to use, and everything with no opinion falls back to this default.
var subscriptionUserAgent = "clash-verge-rev/2.0.3"

// Subscription fetches get their own budget: a few tries with a short backoff,
// a cap on redirects, and a hard ceiling on the body so a misbehaving mirror
// cannot exhaust memory.
var (
	subscriptionAttempts     = 3
	subscriptionRetryDelay   = 700 * time.Millisecond
	subscriptionMaxBody      = int64(8 << 20)
	subscriptionMaxRedirects = 5
)

// Deterministic failures. Retrying either of them would repeat the same
// outcome, so both are marked non-retryable below.
var (
	errSubscriptionRedirects = errors.New("subscription: too many redirects")
	errSubscriptionTooLarge  = errors.New("subscription: response too large")
)

// subscriptionTransport is built by hand instead of using http.DefaultTransport:
//
//   - Proxy is nil, so a fetch never inherits HTTP_PROXY / HTTPS_PROXY from the
//     environment. Other clients on the same machine set those variables, and
//     inheriting them would route the fetch through a proxy that may be down —
//     or through syan-clash's own inbound port, which is circular.
//   - Every phase gets an explicit timeout. The stock transport has none for
//     response headers, so a half-open connection hangs for the full client
//     timeout and the UI just looks frozen.
//   - Connections are reused, because the settings page refetches every
//     subscription when the list is refreshed.
var subscriptionTransport = &http.Transport{
	Proxy:                 nil,
	DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          8,
	MaxIdleConnsPerHost:   4,
	IdleConnTimeout:       60 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
}

var subscriptionClient = &http.Client{
	Timeout:   120 * time.Second,
	Transport: subscriptionTransport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= subscriptionMaxRedirects {
			return fmt.Errorf("%w (limit %d)", errSubscriptionRedirects, subscriptionMaxRedirects)
		}
		return nil
	},
}

func looksLikeSubscriptionURL(s string) bool {
	if strings.ContainsAny(s, "\n\r ") {
		return false
	}
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func looksLikeClashText(text string) bool {
	return strings.Contains(text, "proxies:") || strings.Contains(text, "proxy-groups:")
}

// fetchSubscription downloads a subscription with the default User-Agent.
func fetchSubscription(ctx context.Context, url string) (string, *subscription.Info, error) {
	return fetchSubscriptionAs(ctx, url, "")
}

// fetchSubscriptionAs downloads a subscription and reads the usage metadata its
// response headers carry. An empty userAgent means "use the default".
//
// Transient failures — transport errors, 408, 425, 429 and 5xx — are retried up
// to subscriptionAttempts times with a short backoff. A 4xx, an oversized body
// or a redirect loop is not retried, because repeating it only wastes time.
func fetchSubscriptionAs(ctx context.Context, url, userAgent string) (string, *subscription.Info, error) {
	if userAgent == "" {
		userAgent = subscriptionUserAgent
	}
	var lastErr error
	for attempt := 1; attempt <= subscriptionAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return "", nil, fmt.Errorf("subscription: fetch %s: %w", url, ctx.Err())
			case <-time.After(subscriptionRetryDelay):
			}
		}
		body, info, err := fetchSubscriptionOnce(ctx, url, userAgent)
		if err == nil {
			return body, info, nil
		}
		lastErr = err
		if !retryableSubscriptionError(err) || ctx.Err() != nil {
			return "", nil, err
		}
	}
	return "", nil, lastErr
}

// subscriptionStatusError is a response the server itself declared a failure.
type subscriptionStatusError struct {
	url    string
	status string
	code   int
}

func (e *subscriptionStatusError) Error() string {
	return fmt.Sprintf("subscription: fetch %s: %s", e.url, e.status)
}

// retryableSubscriptionError decides whether another attempt could plausibly
// succeed. Anything that is not a server-declared failure is a transport
// problem (DNS, TCP, TLS, a stalled read) and is worth one more try.
func retryableSubscriptionError(err error) bool {
	if errors.Is(err, errSubscriptionRedirects) || errors.Is(err, errSubscriptionTooLarge) {
		return false
	}
	var se *subscriptionStatusError
	if errors.As(err, &se) {
		switch se.code {
		case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
			return true
		}
		return se.code >= 500
	}
	return true
}

// fetchSubscriptionOnce performs a single attempt.
func fetchSubscriptionOnce(ctx context.Context, url, userAgent string) (string, *subscription.Info, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := subscriptionClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("subscription: fetch %s: %w", url, err)
	}
	defer func() {
		// Drain a little so the connection can be reused, then close.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return "", nil, &subscriptionStatusError{url: url, status: resp.Status, code: resp.StatusCode}
	}
	// Read one byte past the ceiling so an oversized body is an error rather
	// than a silently truncated (and therefore unparsable) document.
	body, err := io.ReadAll(io.LimitReader(resp.Body, subscriptionMaxBody+1))
	if err != nil {
		return "", nil, fmt.Errorf("subscription: fetch %s: %w", url, err)
	}
	if int64(len(body)) > subscriptionMaxBody {
		return "", nil, fmt.Errorf("%w: fetch %s: response exceeds %d MiB", errSubscriptionTooLarge, url, subscriptionMaxBody>>20)
	}
	info := subscription.ParseUserInfo(resp.Header.Get("subscription-userinfo"))
	info.UpdateEvery = subscription.ParseUpdateInterval(resp.Header.Get("profile-update-interval"))
	info.Filename = subscription.FilenameFromDisposition(resp.Header.Get("content-disposition"))
	var infoPtr *subscription.Info
	if info.Upload != 0 || info.Download != 0 || info.Total != 0 || info.Expire != 0 ||
		info.UpdateEvery != 0 || info.Filename != "" {
		infoPtr = &info
	}
	return string(body), infoPtr, nil
}

// ProxyView is one row of the running core's proxy table, normalised for the UI.
type ProxyView struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Now      string   `json:"now,omitempty"`
	Members  []string `json:"members,omitempty"`
	Delay    int      `json:"delay"`
	IsGroup  bool     `json:"is_group"`
	Selected bool     `json:"selected"`
}

// ConnectionView is one row of the running core's connection table, with the
// fields this UI actually shows.
type ConnectionView struct {
	ID          string   `json:"id"`
	Host        string   `json:"host"`
	Destination string   `json:"destination"`
	Source      string   `json:"source"`
	Network     string   `json:"network"`
	Process     string   `json:"process,omitempty"`
	ProcessName string   `json:"process_name,omitempty"`
	Rule        string   `json:"rule"`
	RulePayload string   `json:"rule_payload"`
	Chains      []string `json:"chains"`
	Upload      int64    `json:"upload"`
	Download    int64    `json:"download"`
	Start       string   `json:"start"`
}

// ProxiesView is the running core's proxy table split into groups and nodes.
type ProxiesView struct {
	Groups []ProxyView `json:"groups"`
	Nodes  []ProxyView `json:"nodes"`
}

// CoreClient builds a control-API client for a running core.
func (a *App) CoreClient(id string) (*clashapi.Client, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		// The console always names the core it means, but a bare call -
		// curl, a script, an older page - must not answer 502 just because it
		// left the id out. "The core that is running" is the only useful
		// reading of an empty id.
		id = a.RunningCoreID()
	}
	if id == "" {
		return nil, fmt.Errorf("没有内核在运行（先在内核页启动 mihomo）")
	}
	addr, secret, ok := a.cores.ControlAPI(id)
	if !ok {
		return nil, fmt.Errorf("内核 %s 未在运行或未开放控制接口", id)
	}
	return clashapi.New(addr, secret), nil
}

// CoreVersion reads the running core's version banner.
func (a *App) CoreVersion(ctx context.Context, id string) (clashapi.Version, error) {
	client, err := a.CoreClient(id)
	if err != nil {
		return clashapi.Version{}, err
	}
	return client.Version(ctx)
}

// CoreProxies returns the running core's proxy table, split for the UI.
func (a *App) CoreProxies(ctx context.Context, id string) (ProxiesView, error) {
	client, err := a.CoreClient(id)
	if err != nil {
		return ProxiesView{}, err
	}
	table, err := client.Proxies(ctx)
	if err != nil {
		return ProxiesView{}, err
	}
	var view ProxiesView
	for name, proxy := range table {
		entry := ProxyView{
			Name:    name,
			Type:    proxy.Type,
			Now:     proxy.Now,
			Members: proxy.All,
			Delay:   proxy.LastDelay(),
		}
		switch strings.ToLower(proxy.Type) {
		case "selector", "urltest", "fallback", "loadbalance", "relay":
			entry.IsGroup = true
			view.Groups = append(view.Groups, entry)
		case "direct", "reject", "compatible", "pass", "dns", "global",
			"passrule", "rejectdrop", "rematch", "dnsproxy":
			continue
		default:
			view.Nodes = append(view.Nodes, entry)
		}
	}
	sortProxyViews(view.Groups)
	sortProxyViews(view.Nodes)
	return view, nil
}

// SelectProxy switches the member of a selector group on the running core.
func (a *App) SelectProxy(ctx context.Context, id, group, name string) error {
	client, err := a.CoreClient(id)
	if err != nil {
		return err
	}
	return client.Select(ctx, group, name)
}

// CoreDelay measures latency through the running core.
func (a *App) CoreDelay(ctx context.Context, id, name, testURL string, timeoutMS int) (map[string]int, error) {
	client, err := a.CoreClient(id)
	if err != nil {
		return nil, err
	}
	return client.Delay(ctx, name, testURL, timeoutMS)
}

// CoreTraffic reads one traffic sample from the running core.
func (a *App) CoreTraffic(ctx context.Context, id string) (clashapi.Traffic, error) {
	client, err := a.CoreClient(id)
	if err != nil {
		return clashapi.Traffic{}, err
	}
	return client.Traffic(ctx)
}

// CoreConnections reads the running core's connection table.
func (a *App) CoreConnections(ctx context.Context, id string) (clashapi.Connections, error) {
	client, err := a.CoreClient(id)
	if err != nil {
		return clashapi.Connections{}, err
	}
	return client.Connections(ctx)
}

// CoreCloseConnection terminates one connection on the running core.
func (a *App) CoreCloseConnection(ctx context.Context, id, connID string) error {
	client, err := a.CoreClient(id)
	if err != nil {
		return err
	}
	return client.CloseConnection(ctx, connID)
}

// CoreCloseAllConnections terminates every connection on the running core in
// one request. The connections panel uses it instead of looping single
// closes, which cost one round trip per connection.
func (a *App) CoreCloseAllConnections(ctx context.Context, id string) error {
	client, err := a.CoreClient(id)
	if err != nil {
		return err
	}
	return client.CloseAllConnections(ctx)
}

// CoreUpdates reports the newest upstream release of every known core.
func (a *App) CoreUpdates(ctx context.Context) []core.UpdateInfo {
	return a.cores.CheckAll(ctx)
}

// UpdateCore installs the newest release of one core.
func (a *App) UpdateCore(ctx context.Context, id, mirror string) (core.UpdateInfo, error) {
	if mirror == "" {
		mirror = a.Config().Core.Mirror
	}
	wasRunning := false
	if _, _, running := a.cores.ControlAPI(id); running {
		wasRunning = true
		if err := a.cores.Stop(id); err != nil {
			return core.UpdateInfo{}, err
		}
	}
	info, err := a.cores.InstallLatest(ctx, id, mirror)
	if err != nil {
		return info, err
	}
	if wasRunning {
		if _, err := a.StartCore(ctx, id); err != nil {
			return info, fmt.Errorf("core updated but restart failed: %w", err)
		}
	}
	return info, nil
}

func sortProxyViews(views []ProxyView) {
	sort.Slice(views, func(i, j int) bool {
		return strings.ToLower(views[i].Name) < strings.ToLower(views[j].Name)
	})
}
