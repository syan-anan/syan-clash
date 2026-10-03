package app

import (
	"context"
	"strings"

	"vvpn/internal/clashapi"
	"vvpn/internal/diag"
)

// The AI 直达页 backend: resolve one selector group's members, walk them one at
// a time through the running kernel, and put the group back where it started.

// The contract types are aliases of the diag types, so the two layers cannot
// drift apart on a field name.
type (
	AIJob    = diag.AIJob
	AIStatus = diag.AIStatus
	AIRow    = diag.AIRow
	AIBest   = diag.AIBest
	AICheck  = diag.AICheck
)

// AIBadRequestError marks a request the caller can fix: an empty group, a group
// the kernel does not have, or no running kernel. The route answers 400.
type AIBadRequestError struct{ Reason string }

func (e *AIBadRequestError) Error() string { return e.Reason }

// AINotFoundError marks a job id that this client does not know. The route
// answers 404.
type AINotFoundError struct{ Job string }

func (e *AINotFoundError) Error() string { return "没有这个任务：" + e.Job }

// aiSubGroupTypes are the kernel proxy types that are groups rather than
// servers. Switching the parent to one of them would only delegate, and the
// probe would then describe the sub-group's own choice instead of the member.
var aiSubGroupTypes = map[string]bool{
	"selector": true, "urltest": true, "fallback": true,
	"loadbalance": true, "relay": true,
}

// aiBuiltinTypes are the entries a core provides itself. They are never
// servers, so probing through one would measure nothing at all.
var aiBuiltinTypes = map[string]bool{
	"direct": true, "reject": true, "compatible": true, "pass": true,
	"dns": true, "global": true, "passrule": true, "rejectdrop": true,
	"rematch": true, "dnsproxy": true,
}

// aiCandidates turns one group's member list into the nodes worth probing, in
// the order the kernel listed them. Sub-groups, airport information rows, the
// core's built-ins and names the proxy table does not know are skipped: a name
// the table does not have could not be switched to anyway.
func aiCandidates(members []string, table map[string]clashapi.Proxy) []string {
	out := make([]string, 0, len(members))
	seen := make(map[string]bool, len(members))
	for _, raw := range members {
		name := strings.TrimSpace(raw)
		if name == "" || seen[name] {
			continue
		}
		if IsBuiltinGroup(name) || coreBuiltins[strings.ToUpper(name)] || isInfoNode(name) {
			continue
		}
		entry, ok := table[name]
		if !ok {
			continue
		}
		typ := strings.ToLower(strings.TrimSpace(entry.Type))
		if aiSubGroupTypes[typ] || aiBuiltinTypes[typ] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// aiSelector adapts the control-API client to the sweep's one need: switching
// a group's member.
type aiSelector struct{ client *clashapi.Client }

func (s aiSelector) Select(ctx context.Context, group, name string) error {
	return s.client.Select(ctx, group, name)
}

// StartAIJob resolves a selector group and starts the serial sweep. The answer
// carries the job id, the group's original member and the candidate count,
// which is what the page needs before the first poll.
func (a *App) StartAIJob(ctx context.Context, group string, onlyMissing bool) (AIJob, error) {
	group = strings.TrimSpace(group)
	if group == "" {
		return AIJob{}, &AIBadRequestError{Reason: "group 不能为空"}
	}
	client, err := a.CoreClient("")
	if err != nil {
		// "内核没在跑" is something the caller can fix, so it is a 400.
		return AIJob{}, &AIBadRequestError{Reason: err.Error()}
	}
	table, err := client.Proxies(ctx)
	if err != nil {
		return AIJob{}, err
	}
	entry, ok := table[group]
	if !ok {
		return AIJob{}, &AIBadRequestError{Reason: "内核里没有分组 " + group}
	}
	if typ := strings.ToLower(strings.TrimSpace(entry.Type)); typ != "selector" {
		return AIJob{}, &AIBadRequestError{Reason: group + " 不是可选组（type=" + entry.Type + "），无法逐个切换节点"}
	}
	restore := strings.TrimSpace(entry.Now)
	nodes := aiCandidates(entry.All, table)
	if len(nodes) == 0 {
		return AIJob{}, &AIBadRequestError{Reason: "分组 " + group + " 里没有可测的节点"}
	}
	// only_missing is part of the frozen request contract, but it changes
	// nothing here: AI verdicts are never cached across runs, so every run is a
	// full fresh sweep. Reported as a contract note in the handoff.
	_ = onlyMissing
	job, err := a.DiagProber().StartAI(aiSelector{client: client}, diag.AIRequest{
		Group:   group,
		Nodes:   nodes,
		Restore: restore,
	})
	if err != nil {
		return AIJob{}, err
	}
	return AIJob{Job: job.ID, Group: group, Total: len(nodes), Restore: restore}, nil
}

// AIStatus reads a job's live state. An unknown id answers the zero value,
// whose empty job field is what the route turns into a 404.
func (a *App) AIStatus(job string) AIStatus {
	job = strings.TrimSpace(job)
	if job == "" {
		return AIStatus{}
	}
	st, ok := a.DiagProber().AIStatus(job)
	if !ok {
		return AIStatus{}
	}
	return st
}

// CancelAIJob stops a running sweep. The worker still performs its restore
// step, so a cancelled job ends in phase done with the group back in place.
func (a *App) CancelAIJob(job string) error {
	job = strings.TrimSpace(job)
	if job == "" {
		return &AIBadRequestError{Reason: "job 不能为空"}
	}
	p := a.DiagProber()
	j, ok := p.Jobs().Get(job)
	if !ok || j.Kind != "ai" {
		return &AINotFoundError{Job: job}
	}
	p.Jobs().Cancel(job)
	return nil
}
