// Package corebundle carries the proxy core inside the executable.
//
// The user asked for one file to copy and run: an exe that needs a sibling
// "cores" folder is two things, not one. The core (mihomo), the geo databases
// it needs for geoip/geosite rules and the wintun driver TUN mode loads are
// therefore gzipped into this package and unpacked next to the configuration
// the first time the client starts somewhere new.
//
// Unpacking is idempotent and cheap on the common path: a file whose size
// already matches the recorded size is left alone, so a normal start only
// stats four files. Data is verified against the recorded SHA-256 before it is
// renamed into place, so a half-written or corrupted copy can never be used.
package corebundle

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// The packed assets. Sizes and digests describe the *unpacked* bytes; they were
// recorded from the files this client actually ships with and are re-checked by
// corebundle_test.go on every test run, so a stale asset fails the build.
//
//go:embed assets/mihomo.exe.gz
var mihomoGz []byte

//go:embed assets/geoip.metadb.gz
var geoipGz []byte

//go:embed assets/geosite.dat.gz
var geositeGz []byte

//go:embed assets/wintun.dll.gz
var wintunGz []byte

// Asset is one packed file.
type Asset struct {
	Name    string // file name on disk, e.g. "mihomo.exe"
	RawSize int64  // size after unpacking
	SHA256  string // digest of the unpacked bytes, lower-case hex
	packed  []byte
}

// assets is the ordered list of packed files. The order is stable so the
// unpack report reads the same way every time.
func assets() []Asset {
	return []Asset{
		{Name: "mihomo.exe", RawSize: 61047808, SHA256: "532ed88b3a37d72f6b5ee5d24a45ce5d8799f3ba34931d6a167d4345f7ebca50", packed: mihomoGz},
		{Name: "geoip.metadb", RawSize: 8428327, SHA256: "76ad4ba5d45b1d35b57c3ef26a31c420f7e5afa1e03baf18a47f2d2c933f783b", packed: geoipGz},
		{Name: "geosite.dat", RawSize: 4253375, SHA256: "bff76f6b4d87c3a4c7d9612b926e762b21ba4fe2c5bf8c5a43af25fe8de71b7e", packed: geositeGz},
		{Name: "wintun.dll", RawSize: 427552, SHA256: "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce", packed: wintunGz},
	}
}

// Assets reports the packed file list (without the payloads).
func Assets() []Asset {
	list := assets()
	out := make([]Asset, len(list))
	for i, a := range list {
		a.packed = nil
		out[i] = a
	}
	return out
}

// PackedSize is how many bytes the executable carries for these assets.
func PackedSize() int64 {
	var n int64
	for _, a := range assets() {
		n += int64(len(a.packed))
	}
	return n
}

// RawSize is how many bytes they occupy once unpacked.
func RawSize() int64 {
	var n int64
	for _, a := range assets() {
		n += a.RawSize
	}
	return n
}

// Result reports what Ensure did.
type Result struct {
	Dir     string   // core root the assets were unpacked under
	Wrote   []string // files written or rewritten this call
	Skipped []string // files that were already there and left untouched
}

// Changed reports whether anything was written.
func (r Result) Changed() bool { return len(r.Wrote) > 0 }

// String renders a one-line summary for the startup log.
func (r Result) String() string {
	if !r.Changed() {
		return fmt.Sprintf("内嵌内核已就位（%s）", r.Dir)
	}
	return fmt.Sprintf("已释放内嵌内核到 %s：%s", r.Dir, strings.Join(r.Wrote, "、"))
}

// DirForConfig answers where this configuration keeps its cores. It mirrors the
// rule the rest of the client uses (core.dir relative to the folder holding the
// configuration file) by reading that one field, so it can run before the
// configuration is loaded and without creating anything.
func DirForConfig(cfgPath string) string {
	dir := "cores"
	if raw, err := os.ReadFile(cfgPath); err == nil {
		var probe struct {
			Core struct {
				Dir string
			}
		}
		if json.Unmarshal(raw, &probe) == nil {
			if v := strings.TrimSpace(probe.Core.Dir); v != "" {
				dir = v
			}
		}
	}
	if filepath.IsAbs(dir) {
		return dir
	}
	return filepath.Join(filepath.Dir(cfgPath), dir)
}

// EnsureForConfig is Ensure with the directory taken from the configuration.
func EnsureForConfig(cfgPath string) (Result, error) {
	return Ensure(DirForConfig(cfgPath))
}

// Ensure unpacks every asset under <root>/mihomo and returns what it did. A
// file whose size already matches is skipped, so calling this on every start is
// free once the client has run once. Assets are written to a temporary name and
// renamed into place only after the digest matches, so an interrupted call
// leaves the previous copy intact.
func Ensure(root string) (Result, error) {
	res := Result{Dir: filepath.Join(root, "mihomo")}
	if err := os.MkdirAll(res.Dir, 0o755); err != nil {
		return res, fmt.Errorf("corebundle: 创建目录 %s：%w", res.Dir, err)
	}
	var errs []error
	for _, a := range assets() {
		target := filepath.Join(res.Dir, a.Name)
		if st, err := os.Stat(target); err == nil && st.Size() == a.RawSize {
			res.Skipped = append(res.Skipped, a.Name)
			continue
		}
		if err := unpack(a, target); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", a.Name, err))
			continue
		}
		res.Wrote = append(res.Wrote, a.Name)
	}
	return res, errors.Join(errs...)
}

// unpack decompresses one asset, checks it against the recorded digest and
// moves it into place.
func unpack(a Asset, target string) error {
	zr, err := gzip.NewReader(bytes.NewReader(a.packed))
	if err != nil {
		return fmt.Errorf("解压失败：%w", err)
	}
	defer func() { _ = zr.Close() }()
	data, err := io.ReadAll(zr)
	if err != nil {
		return fmt.Errorf("解压失败：%w", err)
	}
	if int64(len(data)) != a.RawSize {
		return fmt.Errorf("大小不符：解出 %d 字节，应为 %d", len(data), a.RawSize)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != a.SHA256 {
		return fmt.Errorf("校验失败：sha256 %s，应为 %s", got, a.SHA256)
	}
	tmp := fmt.Sprintf("%s.tmp-%d", target, os.Getpid())
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return fmt.Errorf("写入失败：%w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("改名失败：%w", err)
	}
	return nil
}
