package app

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"vvpn/internal/clashapi"
)

// CoreConnectionView reads the running core's connection table and normalises
// it for the UI, including the process that owns each connection when the core
// reports it.
func (a *App) CoreConnectionView(ctx context.Context, id string) ([]ConnectionView, int64, int64, error) {
	client, err := a.CoreClient(id)
	if err != nil {
		return nil, 0, 0, err
	}
	table, err := client.Connections(ctx)
	if err != nil {
		return nil, 0, 0, err
	}
	views := make([]ConnectionView, 0, len(table.Connections))
	for _, c := range table.Connections {
		view := ConnectionView{
			ID:          c.ID,
			Host:        c.Metadata.Host,
			Destination: c.Destination(),
			Source:      sourceWithPort(c),
			Network:     c.Metadata.Network,
			Process:     c.Metadata.ProcessPath,
			Rule:        c.Rule,
			RulePayload: c.RulePayload,
			Chains:      c.Chains,
			Upload:      c.Upload,
			Download:    c.Download,
			Start:       c.Start,
		}
		view.ProcessName = processBase(view.Process)
		if view.ProcessName == "" {
			// The core did not report an owner, so resolve it locally from the
			// connection's source port. Without this the UI shows nothing for
			// cores that do not fill in process metadata.
			if name := processByLocalPort(view.Source); name != "" {
				view.ProcessName = name
			}
		}
		views = append(views, view)
	}
	// Busiest connections first: that is what a user looking at this table
	// wants to see.
	sort.Slice(views, func(i, j int) bool {
		return views[i].Download+views[i].Upload > views[j].Download+views[j].Upload
	})
	return views, table.UploadTotal, table.DownloadTotal, nil
}

// ProcessSeen is a process that the running core has attributed traffic to.
type ProcessSeen struct {
	Name     string `json:"name"`
	Path     string `json:"path,omitempty"`
	Conns    int    `json:"conns"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
}

// SeenProcesses lists the processes that have sent traffic through the core,
// accumulated over time rather than sampled once, so the UI can offer them for
// process-based rules instead of asking the user to type a path by hand.
func (a *App) SeenProcesses(ctx context.Context, id string) ([]ProcessSeen, error) {
	return a.seenProcesses(ctx, id)
}

func sourceWithPort(c clashapi.Connection) string {
	if c.Metadata.SourceIP == "" {
		return ""
	}
	if c.Metadata.SourcePort == "" {
		return c.Metadata.SourceIP
	}
	return c.Metadata.SourceIP + ":" + c.Metadata.SourcePort
}

func processBase(path string) string {
	if path == "" {
		return ""
	}
	return strings.TrimSpace(filepath.Base(path))
}
