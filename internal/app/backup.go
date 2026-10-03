package app

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ExportBackup packs the user's configuration into a zip archive.
func (a *App) ExportBackup() ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	manifest := map[string]any{
		"created_at": time.Now().Format(time.RFC3339),
		"version":    a.version,
		"files":      []string{},
	}
	written := []string{}

	// The configuration file may have any name (it is chosen with -config), so
	// the archive always stores it as config.json.
	entries := []struct{ path, name string }{
		{a.cfgPath, "config.json"},
		{a.subsPath(), "subscriptions.json"},
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(entry.path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			_ = zw.Close()
			return nil, fmt.Errorf("备份 %s：%w", entry.path, err)
		}
		w, err := zw.Create(entry.name)
		if err != nil {
			_ = zw.Close()
			return nil, err
		}
		if _, err := w.Write(raw); err != nil {
			_ = zw.Close()
			return nil, err
		}
		written = append(written, entry.name)
	}
	manifest["files"] = written

	w, err := zw.Create("manifest.json")
	if err != nil {
		_ = zw.Close()
		return nil, err
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		_ = zw.Close()
		return nil, err
	}
	if _, err := w.Write(raw); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ImportBackup restores configuration from an archive produced by
// ExportBackup. Nothing is written until every entry has been validated, so a
// corrupt archive cannot leave a half-applied configuration behind.
func (a *App) ImportBackup(ctx context.Context, raw []byte) (map[string]any, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("不是有效的 zip 备份：%w", err)
	}

	staged := map[string][]byte{}
	var manifest map[string]any
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := filepath.Base(f.Name)
		if name != f.Name {
			return nil, fmt.Errorf("备份里包含不允许的路径：%s", f.Name)
		}
		switch name {
		case "config.json", "subscriptions.json", "manifest.json":
		default:
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		content, err := io.ReadAll(io.LimitReader(rc, 8<<20))
		_ = rc.Close()
		if err != nil {
			return nil, err
		}
		staged[name] = content
	}

	cfgRaw, ok := staged["config.json"]
	if !ok {
		return nil, fmt.Errorf("备份里没有 config.json")
	}
	cfg, err := decodeConfig(cfgRaw)
	if err != nil {
		return nil, err
	}
	if manifestRaw, ok := staged["manifest.json"]; ok {
		_ = json.Unmarshal(manifestRaw, &manifest)
	}

	// Apply the configuration through the normal reload path so listeners,
	// cores and the UI all see the new state.
	if err := a.Reload(cfg); err != nil {
		return nil, err
	}

	var subsRaw []byte
	if saved, ok := staged["subscriptions.json"]; ok {
		var subs []Subscription
		if err := json.Unmarshal(saved, &subs); err != nil {
			return nil, fmt.Errorf("备份里的订阅列表无法解析：%w", err)
		}
		a.mu.Lock()
		a.subs = subs
		a.mu.Unlock()
		if err := a.saveSubs(); err != nil {
			return nil, err
		}
		subsRaw = saved
	}

	result := map[string]any{
		"applied":       true,
		"nodes":         len(a.Profile().Nodes),
		"subscriptions": len(a.Subscriptions()),
	}
	if manifest != nil {
		result["manifest"] = manifest
	}
	if len(subsRaw) > 0 {
		result["subscriptions_restored"] = true
	}
	return result, nil
}

// BackupName is the suggested file name for a fresh export.
func BackupName() string {
	return "syan-clash-backup-" + time.Now().Format("20060102-150405") + ".zip"
}

// decodeConfig parses and validates a configuration document.
func decodeConfig(raw []byte) (configT, error) {
	var cfg configT
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("备份里的配置无法解析：%w", err)
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// TrimBackupName keeps a user-supplied download name sane.
func TrimBackupName(name string) string {
	name = strings.TrimSpace(filepath.Base(name))
	if name == "" || name == "." || name == string(filepath.Separator) {
		return BackupName()
	}
	if !strings.HasSuffix(strings.ToLower(name), ".zip") {
		name += ".zip"
	}
	return name
}
