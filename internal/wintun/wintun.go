// Package wintun carries the prebuilt Wintun driver that mihomo loads the
// moment its TUN inbound starts. The DLL is embedded into syan-clash.exe, so a
// fresh install reaches working TUN mode without any download and without a
// second file the user could lose.
//
// The payload is the official prebuilt amd64 binary from wintun.net
// (wintun-0.14.1.zip), kept byte-for-byte and pinned by SHA-256. It is
// redistributed under the Prebuilt Binaries License that ships with it; see
// LICENSE-wintun.txt in this directory.
package wintun

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// dllAMD64 is the official prebuilt 64-bit driver.
//
//go:embed wintun-amd64.dll
var dllAMD64 []byte

// FileName is the name mihomo loads: it resolves wintun.dll from its own
// executable directory (or the working directory, which the supervisor pins to
// the same folder).
const FileName = "wintun.dll"

// shaAMD64 pins the exact binary. Ensure() trusts an existing file only when it
// hashes to this value, so a truncated or trojaned DLL gets replaced instead
// of loaded.
const shaAMD64 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"

// Supported reports whether this build carries a driver for the running CPU
// architecture. The client itself only ships amd64 builds today.
func Supported() bool { return runtime.GOARCH == "amd64" }

// payload returns the embedded binary and its expected hash.
func payload() ([]byte, string, error) {
	if runtime.GOARCH == "amd64" {
		return dllAMD64, shaAMD64, nil
	}
	return nil, "", fmt.Errorf("内置 wintun 驱动只覆盖 amd64 架构（当前运行在 %s）", runtime.GOARCH)
}

// Ensure makes sure dir holds a verified wintun.dll and returns its path.
// dir is the core's own directory (cores\mihomo), the first place mihomo
// looks and the folder it runs from.
//
// An identical copy is left untouched: the common case costs one 427 KB hash,
// not a write. Everything else is written to a temporary file and renamed into
// place, so a crash mid-write can never leave a half DLL for the loader to
// pick up.
func Ensure(dir string) (string, error) {
	data, want, err := payload()
	if err != nil {
		return "", err
	}
	target := filepath.Join(dir, FileName)
	if fileMatches(target, want) {
		return target, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("释放 wintun 驱动失败：无法创建目录 %s：%v", dir, err)
	}
	// A read-only leftover would make the rename below fail with a confusing
	// error; clearing the flag is cheaper than explaining it.
	_ = os.Chmod(target, 0o644)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return "", fmt.Errorf("释放 wintun 驱动失败：无法写入 %s：%v", tmp, err)
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("释放 wintun 驱动失败：无法替换 %s：%v", target, err)
	}
	if !fileMatches(target, want) {
		return "", fmt.Errorf("释放 wintun 驱动失败：写出后校验不通过（%s）", target)
	}
	return target, nil
}

// Present reports whether dir already holds a verified copy. It never writes.
func Present(dir string) bool {
	_, want, err := payload()
	if err != nil {
		return false
	}
	return fileMatches(filepath.Join(dir, FileName), want)
}

func fileMatches(path, want string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == want
}
