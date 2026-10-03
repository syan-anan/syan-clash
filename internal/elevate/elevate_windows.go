//go:build windows

// Package elevate reports whether the process can create a TUN adapter, which
// on Windows requires administrator rights.
package elevate

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var (
	shell32           = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin = shell32.NewProc("IsUserAnAdmin")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")
)

// swShowNormal is SW_SHOWNORMAL.
const swShowNormal = 1

// IsElevated reports whether the current process runs with administrator rights.
func IsElevated() bool {
	ret, _, _ := procIsUserAnAdmin.Call()
	return ret != 0
}

// CanCreateTun explains whether TUN mode can work right now, in the user's
// language, so the UI can show exactly what to do.
func CanCreateTun() (bool, string) {
	if IsElevated() {
		return true, "当前进程有管理员权限，可以创建 TUN 虚拟网卡"
	}
	return false, "TUN 模式需要管理员权限：请以管理员身份重新启动 syan-clash（右键 → 以管理员身份运行）"
}

// Elevate relaunches the current executable elevated through the UAC prompt.
//
// It goes through ShellExecuteW with the "runas" verb on purpose: PowerShell,
// cmd and every other console helper are avoided, because any of them would
// flash a console window on the user's screen.
func Elevate(executable string, args []string) error {
	verb, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return fmt.Errorf("elevate: %v", err)
	}
	file, err := syscall.UTF16PtrFromString(executable)
	if err != nil {
		return fmt.Errorf("elevate: %v", err)
	}
	params, err := syscall.UTF16PtrFromString(joinArgs(args))
	if err != nil {
		return fmt.Errorf("elevate: %v", err)
	}
	ret, _, _ := procShellExecuteW.Call(
		0, // owner window: none
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)),
		0, // working directory: the executable's own
		swShowNormal,
	)
	// ShellExecuteW returns an HINSTANCE; anything at or below 32 is an error
	// code rather than a handle.
	if ret <= 32 {
		if ret == 5 { // SE_ERR_ACCESSDENIED: the UAC prompt was declined
			return fmt.Errorf("elevate: 用户取消了管理员授权，TUN 模式没有开启")
		}
		return fmt.Errorf("elevate: 请求管理员权限失败（ShellExecuteW 代码 %d）", ret)
	}
	return nil
}

// joinArgs renders arguments the way the Windows command line parser expects,
// so a path with spaces survives the round trip through the UAC prompt.
func joinArgs(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, a := range args {
		quoted = append(quoted, quoteArg(a))
	}
	return strings.Join(quoted, " ")
}

func quoteArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	backslashes := 0
	for _, r := range s {
		switch r {
		case '\\':
			backslashes++
			b.WriteRune(r)
		case '"':
			// Backslashes in front of a quote have to be doubled, and the
			// quote itself escaped.
			b.WriteString(strings.Repeat(`\`, backslashes+1))
			b.WriteByte('"')
			backslashes = 0
		default:
			backslashes = 0
			b.WriteRune(r)
		}
	}
	// A trailing backslash would otherwise escape the closing quote.
	b.WriteString(strings.Repeat(`\`, backslashes))
	b.WriteByte('"')
	return b.String()
}
