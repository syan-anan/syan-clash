package control

import (
	"net/http"
	"runtime"
	"strconv"
)

// The about card answers three questions in one call: which build is running,
// what it is listening on, and what open-source pieces it is made of. It is a
// single request on purpose - a version page that needs five round trips is a
// version page nobody reads.

type aboutView struct {
	Version   string            `json:"version"`
	Build     string            `json:"build,omitempty"`
	Commit    string            `json:"commit,omitempty"`
	Go        string            `json:"go"`
	Platform  string            `json:"platform"`
	StartedAt string            `json:"started_at"`
	UptimeSec int64             `json:"uptime_sec"`
	Config    string            `json:"config"`
	DataDir   string            `json:"data_dir"`
	Console   string            `json:"console"`
	Ports     []aboutPort       `json:"ports"`
	Core      *aboutCore        `json:"core,omitempty"`
	Host      map[string]string `json:"host,omitempty"`
	Credits   []aboutCredit     `json:"credits"`
}

// aboutPort is one listening address, named the way the UI says it.
type aboutPort struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
}

// aboutCore describes the core that is running, if one is.
type aboutCore struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	License   string `json:"license"`
	Repo      string `json:"repo"`
	PID       int    `json:"pid"`
	UptimeSec int64  `json:"uptime_sec"`
	Restarts  int    `json:"restarts"`
}

// aboutCredit names one third-party component and its licence.
type aboutCredit struct {
	Name    string `json:"name"`
	License string `json:"license"`
	Note    string `json:"note,omitempty"`
}

// buildAbout assembles the view.
func (h *API) buildAbout() aboutView {
	st := h.app.Status()
	cfg := h.app.Config()
	stamp, commit := h.app.Build()
	cores := h.app.CoreStatuses()
	view := aboutView{
		Version:   st.Version,
		Build:     stamp,
		Commit:    commit,
		Go:        runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		StartedAt: st.StartedAt,
		UptimeSec: st.UptimeSec,
		Config:    h.app.ConfigPath(),
		DataDir:   h.app.DataDir(),
		Console:   h.app.ConsoleAddr(),
		Ports: []aboutPort{
			{Name: "混合 / HTTP 入口", Addr: cfg.Inbound.HTTPAddr},
			{Name: "SOCKS5 入口", Addr: cfg.Inbound.SOCKS5Addr},
			{Name: "内核 API（external-controller）", Addr: h.app.CoreAPIAddr()},
			{Name: "内核混合端口", Addr: "127.0.0.1:" + strconv.Itoa(cfg.Core.Port)},
		},
		Host: h.app.HostInfo(),
	}
	// The credits are the cores this client actually carries support for, read
	// from the supervisor, so the list cannot drift away from reality.
	view.Credits = append(view.Credits, aboutCredit{Name: "Go", License: "BSD-3-Clause", Note: "客户端本体"})
	for _, c := range cores {
		if c.Name == "" {
			continue
		}
		view.Credits = append(view.Credits, aboutCredit{
			Name:    c.Name,
			License: firstNonEmpty(c.License, "见项目主页"),
			Note:    c.Repo,
		})
	}
	if view.Host["WebView2 运行时"] != "" {
		view.Credits = append(view.Credits, aboutCredit{
			Name:    "Microsoft Edge WebView2",
			License: "Microsoft 软件许可条款",
			Note:    "内嵌界面渲染",
		})
	}
	for _, c := range cores {
		if !c.Running {
			continue
		}
		view.Core = &aboutCore{
			ID: c.ID, Name: c.Name, Version: c.Version, License: c.License, Repo: c.Repo,
			PID: c.PID, UptimeSec: c.UptimeSec, Restarts: c.Restarts,
		}
		break
	}
	return view
}

// handleAbout answers GET /api/about.
func (h *API) handleAbout(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.buildAbout())
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
