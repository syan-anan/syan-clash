package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"vvpn/internal/config"
)

// ProfileEntry is one saved profile as the UI sees it.
type ProfileEntry struct {
	Name    string `json:"name"`
	Active  bool   `json:"active"`
	SavedAt string `json:"saved_at"`
	Nodes   int    `json:"nodes"`
	Subs    int    `json:"subs"`
}

// profileMeta is the sidecar next to each profile. The profile itself is a full
// configuration file; the sidecar only remembers what the summary line needs
// (how many nodes it had, and how many subscriptions the client was carrying
// when it was saved), because counting those from the configuration alone would
// lose the subscription number.
type profileMeta struct {
	Name    string `json:"name"`
	SavedAt string `json:"saved_at"`
	Nodes   int    `json:"nodes"`
	Subs    int    `json:"subs"`
}

const (
	profilesDirName   = "profiles"
	activeProfileFile = ".active"
	// lastUsedProfile is the automatic backup taken before every switch, so a
	// wrong click is always one "apply _last-used" away from being undone.
	lastUsedProfile = "_last-used"
	maxProfileName  = 48
)

// profilesDir is where the profiles live: beside the configuration file, so a
// portable install keeps everything in one tree.
func (a *App) profilesDir() string {
	return filepath.Join(filepath.Dir(a.cfgPath), profilesDirName)
}

func (a *App) profilePath(name string) string {
	return filepath.Join(a.profilesDir(), name+".json")
}

func (a *App) profileMetaPath(name string) string {
	return filepath.Join(a.profilesDir(), name+".meta.json")
}

// validProfileName normalises and checks a user-supplied profile name. Names
// become file names, so the separators and the two system prefixes are refused.
func validProfileName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("档案名不能为空")
	}
	if utf8.RuneCountInString(name) > maxProfileName {
		return "", fmt.Errorf("档案名最多 %d 个字", maxProfileName)
	}
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
		return "", fmt.Errorf("档案名不能以 . 或 _ 开头（这两个前缀留作系统文件）")
	}
	if strings.ContainsAny(name, "/\\:*?\"<>|") {
		return "", fmt.Errorf("档案名不能包含 / \\ : * ? \" < > | 这些字符")
	}
	return name, nil
}

// ActiveProfile returns the name of the profile the client last applied, empty
// when the client is running on its own configuration.
func (a *App) ActiveProfile() string {
	raw, err := os.ReadFile(filepath.Join(a.profilesDir(), activeProfileFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// setActiveProfile records (or clears) the active profile marker.
func (a *App) setActiveProfile(name string) error {
	dir := a.profilesDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, activeProfileFile)
	if name == "" {
		_ = os.Remove(path)
		return nil
	}
	return os.WriteFile(path, []byte(name+"\n"), 0o644)
}

// writeFileAtomic writes a small file through a temporary name so a crash
// mid-write cannot leave a half-written profile behind.
func writeFileAtomic(path string, raw []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".profile-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// saveProfileAs writes the current configuration into a profile. markActive is
// false for the automatic _last-used backup: that one must never look like the
// profile the user chose.
func (a *App) saveProfileAs(name string, markActive bool) error {
	if err := os.MkdirAll(a.profilesDir(), 0o755); err != nil {
		return err
	}
	cfg := a.Config()
	if err := config.Save(a.profilePath(name), cfg); err != nil {
		return err
	}
	meta := profileMeta{
		Name:    name,
		SavedAt: time.Now().Format(time.RFC3339),
		Nodes:   len(a.Profile().Nodes),
		Subs:    len(a.Subscriptions()),
	}
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(a.profileMetaPath(name), append(raw, '\n')); err != nil {
		return err
	}
	if markActive {
		return a.setActiveProfile(name)
	}
	return nil
}

// SaveProfile stores the running configuration as a named profile and marks it
// active.
func (a *App) SaveProfile(name string) error {
	clean, err := validProfileName(name)
	if err != nil {
		return err
	}
	if err := a.saveProfileAs(clean, true); err != nil {
		return err
	}
	a.log.Infof("配置已保存为档案 %s", clean)
	return nil
}

// ListProfiles lists the saved profiles, newest name order, with the active one
// flagged.
func (a *App) ListProfiles() ([]ProfileEntry, error) {
	entries, err := os.ReadDir(a.profilesDir())
	if err != nil {
		if os.IsNotExist(err) {
			return []ProfileEntry{}, nil
		}
		return nil, err
	}
	active := a.ActiveProfile()
	out := make([]ProfileEntry, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		base := strings.TrimSuffix(name, ".json")
		if strings.HasPrefix(base, ".") || strings.HasPrefix(base, "_") {
			continue
		}
		// <name>.meta.json is the sidecar that carries the summary numbers, not
		// a profile of its own.
		if strings.HasSuffix(base, ".meta") {
			continue
		}
		entry := ProfileEntry{Name: base, Active: base == active}
		if info, err := e.Info(); err == nil {
			entry.SavedAt = info.ModTime().Format(time.RFC3339)
		}
		if raw, err := os.ReadFile(a.profileMetaPath(base)); err == nil {
			var meta profileMeta
			if json.Unmarshal(raw, &meta) == nil {
				entry.Nodes, entry.Subs = meta.Nodes, meta.Subs
				if meta.SavedAt != "" {
					entry.SavedAt = meta.SavedAt
				}
			}
		}
		if entry.Nodes == 0 {
			if cfg, err := config.Load(a.profilePath(base)); err == nil && cfg.Core.Profile != nil {
				entry.Nodes = len(cfg.Core.Profile.Nodes)
			}
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// LoadProfile applies a saved profile. The configuration in force right before
// the switch is kept as _last-used, so the switch can always be undone.
func (a *App) LoadProfile(ctx context.Context, name string) error {
	clean, err := validProfileName(name)
	if err != nil {
		return err
	}
	next, err := config.Load(a.profilePath(clean))
	if err != nil {
		return fmt.Errorf("档案 %q 读不出来：%w", clean, err)
	}
	if err := a.saveProfileAs(lastUsedProfile, false); err != nil {
		a.log.Warnf("保存切换前的配置失败：%v", err)
	}
	if err := a.Reload(next); err != nil {
		return err
	}
	if err := a.setActiveProfile(clean); err != nil {
		return err
	}
	// The profile carries its own node list, so the filter baseline has to
	// follow it: otherwise the next 应用过滤 would resurrect nodes from the
	// configuration the profile just replaced.
	if err := a.saveNodeBase(a.Profile().Nodes, nil); err != nil {
		a.log.Warnf("更新节点基线失败：%v", err)
	}
	if err := a.restartRunningCore(ctx, a.Profile()); err != nil {
		return err
	}
	a.log.Infof("已切换到档案 %s", clean)
	return nil
}

// DeleteProfile removes a profile and its sidecar.
func (a *App) DeleteProfile(name string) error {
	clean, err := validProfileName(name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(a.profilePath(clean)); err != nil {
		return fmt.Errorf("档案 %q 不存在", clean)
	}
	if err := os.Remove(a.profilePath(clean)); err != nil {
		return err
	}
	_ = os.Remove(a.profileMetaPath(clean))
	if a.ActiveProfile() == clean {
		_ = a.setActiveProfile("")
	}
	a.log.Infof("档案 %s 已删除", clean)
	return nil
}

// RenameProfile renames a profile without touching the running configuration.
func (a *App) RenameProfile(oldName, newName string) error {
	from, err := validProfileName(oldName)
	if err != nil {
		return err
	}
	to, err := validProfileName(newName)
	if err != nil {
		return err
	}
	if from == to {
		return nil
	}
	if _, err := os.Stat(a.profilePath(from)); err != nil {
		return fmt.Errorf("档案 %q 不存在", from)
	}
	if _, err := os.Stat(a.profilePath(to)); err == nil {
		return fmt.Errorf("已经有叫 %q 的档案了", to)
	}
	if err := os.Rename(a.profilePath(from), a.profilePath(to)); err != nil {
		return err
	}
	_ = os.Rename(a.profileMetaPath(from), a.profileMetaPath(to))
	if a.ActiveProfile() == from {
		_ = a.setActiveProfile(to)
	}
	return nil
}
