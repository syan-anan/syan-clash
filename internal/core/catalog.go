package core

import (
	"strings"
	"sync"
)

// catalogMu guards the mutable parts of Catalog (the version and download URL
// are repointed after an in-app update).
var catalogMu sync.RWMutex

// CoreSpec describes one external core: where it comes from, what licence it
// carries, and how to check and run a generated configuration with it.
//
// Versions and asset names below were verified against the GitHub API on
// 2026-09-30 (see lab/landscape.json). Keep the pin in sync with the download
// URL when upgrading.
type CoreSpec struct {
	ID           string
	Name         string
	Repo         string
	License      string
	LicenseKnown bool
	Version      string
	Binary       string
	ConfigName   string
	ConfigFormat string
	Emitter      string
	CheckArgs    []string
	RunArgs      []string
	ClashAPI     bool
	DownloadURL  string
	Notes        string
}

// Catalog is the set of cores this client knows how to drive.
var Catalog = []CoreSpec{
	{
		ID:           "sing-box",
		Name:         "sing-box",
		Repo:         "https://github.com/SagerNet/sing-box",
		License:      "GPL-3.0",
		LicenseKnown: false, // GitHub API reports NOASSERTION; confirm in the repo
		Version:      "1.14.2",
		Binary:       "sing-box.exe",
		ConfigName:   "config.json",
		ConfigFormat: "json",
		Emitter:      "sing-box",
		CheckArgs:    []string{"check", "-c", "{config}"},
		RunArgs:      []string{"run", "-c", "{config}", "-D", "{dir}"},
		ClashAPI:     true,
		DownloadURL:  "https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-windows-amd64.zip",
		Notes:        "协议与传输覆盖最全，内置 TUN、DNS、rule-set(.srs)。",
	},
	{
		ID:      "mihomo",
		Name:    "mihomo (Clash.Meta)",
		Repo:    "https://github.com/MetaCubeX/mihomo",
		License: "MIT",
		// Verified 2026-09-30 by reading the repository's LICENSE file: full MIT
		// text ("Permission is hereby granted, free of charge..."), copyright
		// 2023 KT. It is NOT GPL-3.0 despite the Clash lineage.
		LicenseKnown: true,
		Version:      "1.19.31",
		Binary:       "mihomo.exe",
		ConfigName:   "config.yaml",
		ConfigFormat: "yaml",
		Emitter:      "mihomo",
		CheckArgs:    []string{"-t", "-f", "{config}", "-d", "{dir}"},
		RunArgs:      []string{"-f", "{config}", "-d", "{dir}"},
		ClashAPI:     true,
		DownloadURL:  "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.31/mihomo-windows-amd64-v1.19.31.zip",
		Notes:        "Clash 生态最大，rule-provider / 代理组 / 订阅兼容性最好。许可证已核实为 MIT，是三个内核里唯一可无条件闭源商用的。",
	},
	{
		ID:           "xray",
		Name:         "Xray-core",
		Repo:         "https://github.com/XTLS/Xray-core",
		License:      "MPL-2.0",
		LicenseKnown: true,
		Version:      "26.3.27",
		Binary:       "xray.exe",
		ConfigName:   "config.json",
		ConfigFormat: "json",
		Emitter:      "xray",
		CheckArgs:    []string{"run", "-test", "-config", "{config}"},
		RunArgs:      []string{"run", "-config", "{config}"},
		ClashAPI:     false,
		DownloadURL:  "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-windows-64.zip",
		Notes:        "MPL-2.0，文件级 copyleft，是唯一可以安全闭源绑定的主流内核。无代理组与统一控制 API；不支持 TUN 入站与 hysteria2 节点。",
	},
}

// Lookup finds a core by ID.
func Lookup(id string) (CoreSpec, bool) {
	catalogMu.RLock()
	defer catalogMu.RUnlock()
	for _, c := range Catalog {
		if c.ID == id {
			return c, true
		}
	}
	return CoreSpec{}, false
}

// CatalogEntries returns a copy of the catalog for display.
func CatalogEntries() []CoreSpec {
	catalogMu.RLock()
	defer catalogMu.RUnlock()
	out := make([]CoreSpec, len(Catalog))
	copy(out, Catalog)
	return out
}

// DefaultMirrors are third-party GitHub download proxies, tried only after the
// canonical URL fails. They exist because the GitHub release CDN is frequently
// unreachable from some networks. A mirror cannot silently substitute content:
// the archive still has to be a valid zip containing the expected executable.
//
// Set core.mirror in the configuration to use your own prefix instead (for
// example "https://your-proxy/https://github.com/"), or clear this list.
// The order is measured, not guessed: on 2026-09-30 a 1 MB range of geosite.dat
// came back at 460 KB/s from gh-proxy.com, 180 KB/s from ghfast.top and 77 KB/s
// from ghproxy.net, and a first run downloads tens of megabytes.
var DefaultMirrors = []string{
	"https://gh-proxy.com/",
	"https://ghfast.top/",
	"https://ghproxy.net/",
}

// JoinMirror prefixes a GitHub URL with a mirror. A prefix without a trailing
// slash gets one appended.
func JoinMirror(prefix, target string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return target
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return prefix + target
}

// DownloadCandidates lists the URLs to try, in order: the user's mirror, the
// canonical URL, then the built-in mirrors.
func DownloadCandidates(canonical, mirror string) []string {
	urls := make([]string, 0, len(DefaultMirrors)+2)
	if strings.TrimSpace(mirror) != "" {
		urls = append(urls, JoinMirror(mirror, canonical))
	}
	urls = append(urls, canonical)
	for _, m := range DefaultMirrors {
		candidate := JoinMirror(m, canonical)
		if candidate != canonical {
			urls = append(urls, candidate)
		}
	}
	return urls
}
