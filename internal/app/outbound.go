package app

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"vvpn/internal/clashapi"
)

// The built-in entry point and an external core listen on different ports, so
// the client's own addresses (inbound.http_addr / socks5_addr) stay valid no
// matter which engine is running. That design only holds up if "proxy" traffic
// is actually handed to the core once one is up: without it the client answers
// on 2890/2891, matches the profile's rules, and then sends everything out of
// the local machine - the core runs, the node is healthy, and the exit address
// is still the user's own.

// nodeTracker holds what the running core is doing: the node traffic leaves
// through, and the routing mode it reported. It is written by the watcher
// goroutine and read by the status handler on every UI poll, so it is plain
// values behind an RWMutex rather than a live API call: the console must never
// wait on the core to draw itself.
type nodeTracker struct {
	mu   sync.RWMutex
	name string
	mode string
}

func (n *nodeTracker) set(name string) {
	n.mu.Lock()
	n.name = name
	n.mu.Unlock()
}

func (n *nodeTracker) get() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.name
}

// setMode records the routing mode of the last watcher tick. A core in direct
// mode sends every packet out of the local machine, so the status handler reads
// this to avoid naming a node that traffic never reaches.
func (n *nodeTracker) setMode(mode string) {
	n.mu.Lock()
	n.mode = mode
	n.mu.Unlock()
}

func (n *nodeTracker) coreMode() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.mode
}

// SelectedNode is the node the running core currently uses, "" when no core is
// running or the name is not known yet.
func (a *App) SelectedNode() string { return a.node.get() }

// syncUpstream points the built-in entry point at the running core. Called
// after every core start/stop and from the status poll, which is what keeps it
// honest when the supervisor's watchdog restarts a crashed core without the
// client asking.
func (a *App) syncUpstream() {
	a.mu.Lock()
	srv := a.srv
	a.mu.Unlock()
	if srv == nil {
		return
	}
	srv.SetUpstream(a.CoreAddr())
}

// StartCoreNodeWatcher keeps two things true while a core runs: the built-in
// entry point hands "proxy" traffic to it, and the UI knows which node that
// traffic leaves through. Both are refreshed on a timer rather than on the
// request path, so a slow or restarting core can never stall the console.
func (a *App) StartCoreNodeWatcher(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 3 * time.Second
	}
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			a.guardTick("节点跟随", func() { a.refreshCoreLink(ctx) })
			select {
			case <-ctx.Done():
				a.node.set("")
				a.syncUpstream()
				return
			case <-ticker.C:
			}
		}
	}()
}

// refreshCoreLink is one watcher tick: make the entry point match the running
// core, repair any selection that cannot be dialled, and remember which node
// that core is using.
//
// The repair lives on this path and not only in startCoreRepair because a core
// can come back without the client asking: the supervisor watchdog relaunches a
// crashed core straight from cache.db, and a cache written while the client was
// in direct mode restores "GLOBAL -> DIRECT" - a core that is up, rules that
// match, and every connection still leaving from the local address. Reading the
// proxy table on every tick makes one repair cover every way a core can appear,
// and it is a no-op once nothing is broken.
func (a *App) refreshCoreLink(ctx context.Context) {
	a.syncUpstream()
	id := a.RunningCoreID()
	if id == "" {
		a.node.set("")
		a.node.setMode("")
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	client, err := a.CoreClient(id)
	if err != nil {
		return
	}
	table, err := client.Proxies(cctx)
	if err != nil {
		return
	}
	if mode, err := client.Mode(cctx); err == nil {
		a.node.setMode(mode)
	}
	var failed []string
	for _, r := range repairTargets(table) {
		if err := client.Select(cctx, r.Group, r.Pick); err != nil {
			failed = append(failed, r.Group)
			continue
		}
		a.log.Infof("内核选择器已指向可用节点：%s -> %s", r.Group, r.Pick)
		// The name below is resolved from this same snapshot, so it has to
		// carry the repair: otherwise a repaired chain would still read as
		// "not a node" and the console would keep the stale answer.
		if child, ok := table[r.Group]; ok {
			child.Now = r.Pick
			table[r.Group] = child
		}
	}
	a.warnRepairFailures(id, failed)
	if name := resolveNodeName(a.coreNodeStart(), table); name != "" {
		a.node.set(name)
	}
}

// warnRepairFailures reports a repair the core refused, but only when the set of
// refused groups changes: the watcher retries every tick, and a core that keeps
// saying no would otherwise print the same line for as long as it runs.
func (a *App) warnRepairFailures(id string, groups []string) {
	key := id + ":" + strings.Join(groups, ",")
	a.mu.Lock()
	changed := a.repairWarn != key
	a.repairWarn = key
	a.mu.Unlock()
	if changed && len(groups) > 0 {
		a.log.Warnf("内核选择器修复失败，下个周期重试：%s", strings.Join(groups, "、"))
	}
}

// coreGroupTypes are the proxy types a Clash-compatible core uses for a group
// of other proxies.
var coreGroupTypes = map[string]bool{
	"selector": true, "urltest": true, "fallback": true,
	"loadbalance": true, "relay": true,
}

// coreBuiltinProxies are the entries a core understands without a node behind
// them: they are decisions, not servers, and picking one as a target is what
// leaves the user with a healthy core that still exits from their own address.
var coreBuiltinProxies = map[string]bool{
	"direct": true, "reject": true, "rejectdrop": true, "pass": true,
	"compatible": true, "dns": true, "global": true, "passrule": true,
	"rematch": true, "dnsproxy": true,
}

// isGroupType reports whether a proxy entry is a group rather than a server.
func isGroupType(proxyType string) bool {
	return coreGroupTypes[strings.ToLower(strings.TrimSpace(proxyType))]
}

// realMember reports whether a name is a server the core can actually dial:
// not a built-in decision (DIRECT / REJECT), not one of the airport's
// information rows ("剩余流量: ..."), not a group, and present in the table.
func realMember(name string, table map[string]clashapi.Proxy) bool {
	name = strings.TrimSpace(name)
	if name == "" || isInfoNode(name) {
		return false
	}
	p, ok := table[name]
	if !ok {
		return false
	}
	if coreBuiltinProxies[strings.ToLower(strings.TrimSpace(p.Type))] {
		return false
	}
	return !isGroupType(p.Type)
}

// pickMember chooses a replacement for a group whose current selection cannot
// be dialled. A group member wins over a bare node: the airport's url-test
// group measures every node and keeps the fastest, which is a better default
// than whichever node happens to be listed first.
func pickMember(p clashapi.Proxy, table map[string]clashapi.Proxy) string {
	for _, name := range p.All {
		if child, ok := table[name]; ok && isGroupType(child.Type) {
			return name
		}
	}
	for _, name := range p.All {
		if realMember(name, table) {
			return name
		}
	}
	return ""
}

// resolveNodeName follows the selection chain from start down to the server
// that will actually be dialled. A chain that ends on a built-in decision
// (DIRECT / REJECT) resolves to "", because that is not a node and the console
// must not claim it is one. Pure, so the rule can be tested without a core.
func resolveNodeName(start string, table map[string]clashapi.Proxy) string {
	seen := map[string]bool{}
	for name := strings.TrimSpace(start); name != ""; {
		if seen[name] {
			break
		}
		seen[name] = true
		p, ok := table[name]
		if !ok {
			break
		}
		if !isGroupType(p.Type) {
			if realMember(name, table) {
				return name
			}
			return ""
		}
		name = strings.TrimSpace(p.Now)
	}
	return ""
}

// coreNodeStart is where the node-name chain begins: the profile final
// outbound - the group every rule that falls through lands on - or GLOBAL when
// the profile does not name one.
func (a *App) coreNodeStart() string {
	if p := a.Config().Core.Profile; p != nil {
		if s := strings.TrimSpace(p.Final); s != "" {
			return s
		}
	}
	return "GLOBAL"
}

// coreNodeName is resolveNodeName against the running core.
func (a *App) coreNodeName(ctx context.Context, id string) (string, error) {
	client, err := a.CoreClient(id)
	if err != nil {
		return "", err
	}
	table, err := client.Proxies(ctx)
	if err != nil {
		return "", err
	}
	return resolveNodeName(a.coreNodeStart(), table), nil
}

// repairCoreSelection fixes a group whose selection came back as something that
// cannot be dialled.
//
// mihomo restores the last selection from cache.db. A cache written while the
// client was in direct mode - or by an older build that never selected
// anything - comes back as GLOBAL -> DIRECT: the core starts, the rules match,
// and every connection still leaves from the local address. Airports also
// inject "剩余流量: ..." style rows as nodes, and a group that fell back to one
// of those cannot be dialled either.
//
// Only a selection that is not a real member is touched: a node the user picked
// is never overridden.
// selectionRepair is one group whose stored selection has to be replaced.
type selectionRepair struct {
	Group string
	Pick  string
}

// repairTargets lists every group whose selection is not dialable, with the
// member that should replace it. Pure so the rule can be tested without a
// running core; the result is sorted so neither a log line nor a test depends
// on map iteration order.
func repairTargets(table map[string]clashapi.Proxy) []selectionRepair {
	var out []selectionRepair
	for name, p := range table {
		if !isGroupType(p.Type) {
			continue
		}
		now := strings.TrimSpace(p.Now)
		if realMember(now, table) {
			continue
		}
		// A selector may legitimately point at another group, which is a real
		// target even though it is not a server itself.
		if child, ok := table[now]; ok && isGroupType(child.Type) {
			continue
		}
		if pick := pickMember(p, table); pick != "" {
			out = append(out, selectionRepair{Group: name, Pick: pick})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Group < out[j].Group })
	return out
}

// repairCoreSelection applies repairTargets to the running core.
func (a *App) repairCoreSelection(ctx context.Context, id string) ([]string, error) {
	client, err := a.CoreClient(id)
	if err != nil {
		return nil, err
	}
	table, err := client.Proxies(ctx)
	if err != nil {
		return nil, err
	}
	var fixed []string
	for _, r := range repairTargets(table) {
		if err := client.Select(ctx, r.Group, r.Pick); err != nil {
			a.log.Warnf("内核选择器 %s 修复失败：%v", r.Group, err)
			continue
		}
		fixed = append(fixed, r.Group+" -> "+r.Pick)
	}
	return fixed, nil
}

// startCoreRepair runs the selection repair off the request path: the core has
// just been launched and its control API needs a moment before it answers.
func (a *App) startCoreRepair(id string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		for attempt := 0; attempt < 20; attempt++ {
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
			if a.RunningCoreID() != id {
				return
			}
			fixed, err := a.repairCoreSelection(ctx, id)
			if err != nil {
				continue
			}
			if len(fixed) > 0 {
				a.log.Infof("内核选择器已指向可用节点：%s", strings.Join(fixed, ", "))
			}
			a.refreshCoreLink(ctx)
			return
		}
	}()
}
