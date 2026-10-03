package diag

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// MatrixSite is one column of the latency matrix.
type MatrixSite struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// presetSites are the columns a user gets without configuring anything: a
// general 204, a CDN, video, a big site, an AI endpoint and a domestic
// control. The domestic one matters because "everything is 300ms" and "the
// proxy is down" look identical without it.
var presetSites = []MatrixSite{
	{ID: "google", Name: "Google", URL: "http://www.gstatic.com/generate_204"},
	{ID: "cloudflare", Name: "Cloudflare", URL: "https://cp.cloudflare.com/generate_204"},
	{ID: "youtube", Name: "YouTube", URL: "https://i.ytimg.com/generate_204"},
	{ID: "github", Name: "GitHub", URL: "https://github.com/robots.txt"},
	{ID: "openai", Name: "OpenAI", URL: "https://chatgpt.com/"},
	{ID: "baidu", Name: "百度", URL: "https://www.baidu.com/"},
}

// PresetSites returns a copy so a caller cannot reorder the defaults for
// everybody else in the process.
func PresetSites() []MatrixSite {
	out := make([]MatrixSite, len(presetSites))
	copy(out, presetSites)
	return out
}

// SiteByID finds a preset column.
func SiteByID(id string) (MatrixSite, bool) {
	for _, s := range presetSites {
		if s.ID == id {
			return s, true
		}
	}
	return MatrixSite{}, false
}

// MatrixCell is one node tested against one site.
type MatrixCell struct {
	Node  string `json:"node"`
	Site  string `json:"site"`
	URL   string `json:"url"`
	Delay int    `json:"delay"`
	Err   string `json:"err,omitempty"`
	TS    int64  `json:"ts"`
}

// Delayer is the single core capability the matrix needs: ask the running core
// to time one node against one URL. It is an interface because the matrix must
// not know how the core is reached - and because the tests drive it directly.
type Delayer interface {
	DelayNode(ctx context.Context, node, rawURL string, timeoutMS int) (int, error)
}

// MatrixRequest is one sweep.
type MatrixRequest struct {
	Nodes       []string
	Sites       []MatrixSite
	Concurrency int
	TimeoutMS   int
	OnlyMissing bool
}

// StartMatrix launches a sweep and returns immediately. Cells are produced
// incrementally and are visible through the job snapshot while it runs.
func (p *Prober) StartMatrix(delayer Delayer, req MatrixRequest) (*Job, error) {
	if delayer == nil {
		return nil, &sourceError{Msg: "没有可用的内核测速接口"}
	}
	sites := req.Sites
	if len(sites) == 0 {
		sites = presetSites[:3]
	}
	nodes := req.Nodes
	if len(nodes) == 0 {
		return nil, &sourceError{Msg: "没有可测的节点"}
	}
	run := &matrixRun{
		sites:  sites,
		nodes:  nodes,
		cells:  map[string]MatrixCell{},
		total:  len(nodes) * len(sites),
		now:    p.nowTime,
		cached: 0,
	}
	job, ctx, err := p.jobs.Begin("matrix", run.snapshot)
	if err != nil {
		return nil, err
	}
	conc := req.Concurrency
	if conc < 1 {
		conc = 1
	}
	if conc > 8 {
		conc = 8
	}
	timeout := req.TimeoutMS
	if timeout < 1000 {
		timeout = 5000
	}
	ttl := p.cache.ttlNow()

	go func() {
		defer func() {
			state := JobDone
			if ctx.Err() != nil {
				state = JobCanceled
			}
			p.jobs.Finish(job, state, "")
		}()

		type task struct {
			node string
			site MatrixSite
		}
		tasks := make(chan task)
		var wg sync.WaitGroup
		for i := 0; i < conc; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for t := range tasks {
					if ctx.Err() != nil {
						return
					}
					cell := p.runCell(ctx, delayer, t.node, t.site, timeout, ttl, req.OnlyMissing)
					run.add(cell)
				}
			}()
		}
	feed:
		for _, n := range nodes {
			for _, s := range sites {
				select {
				case tasks <- task{node: n, site: s}:
				case <-ctx.Done():
					break feed
				}
			}
		}
		close(tasks)
		wg.Wait()
	}()
	return job, nil
}

// runCell produces one cell, reusing a fresh cached answer when there is one.
func (p *Prober) runCell(ctx context.Context, delayer Delayer, node string, site MatrixSite, timeoutMS int, ttl time.Duration, onlyMissing bool) MatrixCell {
	cell := MatrixCell{Node: node, Site: site.ID, URL: site.URL, TS: p.nowTime().Unix()}
	key := cacheKey("mx", node, site.URL)
	// only_missing means "do not re-measure what is still fresh"; a plain run
	// means "measure again", which is what a user pressing 开始 expects even
	// when a cached answer from a minute ago exists.
	if ttl > 0 && onlyMissing {
		if hit, _, ok := p.cache.get(key); ok {
			if cached, isCell := hit.(MatrixCell); isCell {
				cached.TS = cell.TS
				return cached
			}
		}
	}
	cellCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMS)*time.Millisecond+p.timeout())
	defer cancel()
	gate := p.gate()
	if err := gate.acquire(cellCtx); err != nil {
		cell.Err = "timeout"
		return cell
	}
	delay, err := delayer.DelayNode(cellCtx, node, site.URL, timeoutMS)
	gate.release()
	if err != nil {
		cell.Err = classifyCoreErr(err)
		cell.TS = p.nowTime().Unix()
		p.cache.put(key, cell)
		return cell
	}
	cell.Delay = delay
	cell.TS = p.nowTime().Unix()
	p.cache.put(key, cell)
	return cell
}

// classifyCoreErr turns a core API failure into the small vocabulary the cell
// tooltip shows.
func classifyCoreErr(err error) string {
	if err == nil {
		return ""
	}
	if code := statusOf(err); code > 0 {
		switch code {
		case 404:
			return "notfound"
		case 408:
			return "timeout"
		default:
			return "status:" + itoa(code)
		}
	}
	return errKind(err)
}

// matrixRun is the shared, mutex-guarded state of one sweep.
type matrixRun struct {
	mu     sync.Mutex
	sites  []MatrixSite
	nodes  []string
	cells  map[string]MatrixCell
	total  int
	cached int
	now    func() time.Time
}

func (r *matrixRun) add(cell MatrixCell) {
	r.mu.Lock()
	r.cells[cell.Node+"|"+cell.Site] = cell
	r.mu.Unlock()
}

// snapshot is the incremental view a polling UI renders.
func (r *matrixRun) snapshot() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	cells := make([]MatrixCell, 0, len(r.cells))
	for _, c := range r.cells {
		cells = append(cells, c)
	}
	sort.Slice(cells, func(i, j int) bool {
		if cells[i].Node != cells[j].Node {
			return cells[i].Node < cells[j].Node
		}
		return cells[i].Site < cells[j].Site
	})
	return map[string]any{
		"nodes": append([]string{}, r.nodes...),
		"sites": append([]MatrixSite{}, r.sites...),
		"cells": cells,
		"done":  len(cells),
		"total": r.total,
	}
}

// ResolveSites turns request site ids into columns. An entry may be a preset id
// ("github"), a custom id with a URL ("custom:https://example.com/") or a bare
// URL, which is what a user who pastes one into the box will produce.
func ResolveSites(ids []string) []MatrixSite {
	out := make([]MatrixSite, 0, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if site, ok := SiteByID(id); ok {
			out = append(out, site)
			continue
		}
		if _, url, ok := strings.Cut(id, ":"); ok && strings.Contains(url, "://") {
			id, url = strings.TrimSpace(id), strings.TrimSpace(url)
			out = append(out, MatrixSite{ID: id, Name: id, URL: url})
			continue
		}
		if strings.Contains(id, "://") {
			out = append(out, MatrixSite{ID: shortSiteID(id), Name: shortSiteID(id), URL: id})
		}
	}
	return out
}

// shortSiteID is the column label for an ad-hoc URL.
func shortSiteID(rawURL string) string {
	s := rawURL
	if _, rest, ok := strings.Cut(s, "://"); ok {
		s = rest
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 28 {
		s = s[:28]
	}
	return s
}
