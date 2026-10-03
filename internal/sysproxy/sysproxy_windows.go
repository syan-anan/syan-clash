//go:build windows

// Package sysproxy toggles the per-user WinINET proxy settings. That is the
// setting Chrome, Edge, Electron apps and most Windows tooling read, so it is
// the cheapest way to route a desktop's traffic through a local proxy without
// installing a TUN adapter.
//
// It intentionally does not touch WinHTTP (netsh winhttp), WPAD/PAC files or
// per-process proxy environment variables.
//
// The registry is reached through advapi32 directly: this package is polled by
// the UI and by the tray, and shelling out to reg.exe would flash a console
// window on every single poll.
package sysproxy

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"vvpn/internal/winreg"
)

// regKeyPath is a variable rather than a constant so a test can point the whole
// package at a scratch key under HKCU instead of the machine's real Internet
// Settings. Production code never assigns it.
var regKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

const (
	valueProxyEnable   = "ProxyEnable"
	valueProxyServer   = "ProxyServer"
	valueProxyOverride = "ProxyOverride"
)

const (
	internetOptionRefresh         = 37
	internetOptionSettingsChanged = 39
)

// OpenProcess access rights and process state, spelled out instead of relying
// on syscall constants that differ between Go releases.
const (
	processQueryLimitedInformation = 0x1000
	synchronizeAccess              = 0x00100000
	stillActive                    = 259
	waitTimeoutCode                = 258
)

var procInternetSetOption = syscall.NewLazyDLL("wininet.dll").NewProc("InternetSetOptionW")

// ErrForeignOwner marks the case where the machine already has a system proxy
// that points somewhere other than this client. Overwriting it would silently
// cut the other program off, so Enable refuses unless the caller explicitly
// takes the setting over.
var ErrForeignOwner = errors.New("系统代理已被其他程序占用")

// ErrNotOwner marks "there is no system proxy written by this client to
// switch off". It is not a failure of the machine; it is the refusal to touch
// a setting that belongs to somebody else.
var ErrNotOwner = errors.New("系统代理不是本客户端开启的")

// ForeignOwner reports the existing system proxy entry that does not belong to
// this client. ownAddrs are the local inbound addresses this client publishes
// (for example 127.0.0.1:2890); an enabled proxy pointing anywhere else means
// another program got there first. The returned string is the raw entry, so the
// UI can name the port the user has to decide about.
func ForeignOwner(ownAddrs ...string) (string, bool) {
	on, server, err := Current()
	if err != nil || !on || server == "" {
		return "", false
	}
	return foreignEntry(server, ownAddrs...)
}

// Enable points the system proxy at the local inbound addresses. An empty
// address is simply left out of the bypass list.
//
// Before the first write it records what the machine looked like, because the
// system proxy survives this process: without that record a crash would leave
// the user's browser pointed at a port nothing listens on.
// Enable publishes the built-in bypass list (see DefaultBypass).
func Enable(httpAddr, socksAddr string) error {
	return EnableForced(httpAddr, socksAddr, "", false)
}

// EnableForced is Enable with two explicit overrides: the ProxyOverride list
// to publish, and whether to take the setting over from another program.
//
// bypass is the raw WinINET list (";"-separated); an empty value keeps the
// historical default, so a caller that has nothing to say about bypassing
// behaves exactly like the old hard-coded version did. force=true takes the
// setting even when it currently belongs to another program; the UI only asks
// for that after the user has been shown whose proxy is in the way. Either way
// the previous value is snapshotted first, so quitting hands it back.
func EnableForced(httpAddr, socksAddr, bypass string, force bool) error {
	parts := make([]string, 0, 3)
	if httpAddr != "" {
		parts = append(parts, "http="+httpAddr, "https="+httpAddr)
	}
	if socksAddr != "" {
		parts = append(parts, "socks="+socksAddr)
	}
	if len(parts) == 0 {
		return fmt.Errorf("sysproxy: no inbound address to publish")
	}
	if !force {
		if owner, foreign := ForeignOwner(httpAddr, socksAddr); foreign {
			return fmt.Errorf("%w（当前指向 %s）", ErrForeignOwner, owner)
		}
	}
	if err := record(httpAddr, socksAddr, strings.Join(parts, ";")); err != nil {
		return err
	}
	if err := winreg.SetString(regKeyPath, valueProxyServer, strings.Join(parts, ";")); err != nil {
		return fmt.Errorf("sysproxy: %w", err)
	}
	if err := winreg.SetString(regKeyPath, valueProxyOverride, BypassOrDefault(bypass)); err != nil {
		return fmt.Errorf("sysproxy: %w", err)
	}
	if err := winreg.SetDWORD(regKeyPath, valueProxyEnable, 1); err != nil {
		return fmt.Errorf("sysproxy: %w", err)
	}
	notify()
	return nil
}

// record writes the pre-enable snapshot, but only the first time: re-enabling
// while the client already owns the setting would otherwise save our own
// addresses as "the previous value" and a later restore would put them back.
func record(httpAddr, socksAddr, published string) error {
	if prev, ok := LoadSnapshot(StatePath()); ok && prev.Applied {
		return nil
	}
	on, server, err := Current()
	if err != nil {
		return fmt.Errorf("sysproxy: %w", err)
	}
	override, err := winreg.GetString(regKeyPath, valueProxyOverride)
	if err != nil && !errors.Is(err, winreg.ErrNotFound) {
		return fmt.Errorf("sysproxy: %w", err)
	}
	snap := Snapshot{
		PID:      os.Getpid(),
		Applied:  true,
		WasOn:    on,
		Server:   server,
		Override: override,
		Addr:     published,
		At:       time.Now().Format(time.RFC3339),
	}
	if err := SaveSnapshot(StatePath(), snap); err != nil {
		return fmt.Errorf("sysproxy: 记录系统代理原状态失败：%w", err)
	}
	return nil
}

// Disable turns this client's system proxy off. The address values it wrote are
// put back first: leaving them behind would mean a later external switch-on
// silently routes the machine at a port that may no longer be listening.
//
// Handing the setting back is not the same as switching it off. When the
// snapshot shows another program had the switch on before this client took it
// over, switching our own proxy off gives that program its switch back -
// forcing the flag to 0 here would silently disable it, which is exactly the
// damage the takeover prompt promised not to do. When the machine had no proxy
// of its own, or the snapshot was this client's own leftover, the switch still
// ends up off. Either way the snapshot goes away: nothing is left for a guard to
// undo.
func Disable() error {
	snap, ok := LoadSnapshot(StatePath())
	if !ok || !snap.Applied {
		// Nothing was ever written by this client, so there is nothing of ours
		// to switch off. Forcing ProxyEnable to 0 here is what used to turn a
		// second proxy client on the same machine off: the switch was up, so
		// this function assumed the switch was ours. Ownership comes from the
		// snapshot, never from the registry value.
		return ErrNotOwner
	}
	if err := restoreString(valueProxyServer, snap.Server); err != nil {
		return err
	}
	if err := restoreString(valueProxyOverride, snap.Override); err != nil {
		return err
	}
	// A machine that had another program's proxy on keeps it on: handing the
	// setting back is not the same as switching it off.
	if snap.WasOn && !oursOnly(snap.Server, ourAddrsFrom(snap.Addr)...) {
		if err := winreg.SetDWORD(regKeyPath, valueProxyEnable, 1); err != nil {
			return fmt.Errorf("sysproxy: %w", err)
		}
		notify()
		return ClearSnapshot(StatePath())
	}
	if err := winreg.SetDWORD(regKeyPath, valueProxyEnable, 0); err != nil {
		return fmt.Errorf("sysproxy: %w", err)
	}
	notify()
	return ClearSnapshot(StatePath())
}

// Restore puts the machine's proxy settings back the way they were before this
// client touched them and forgets the snapshot. It reports whether there was
// anything to undo, so an exit path can log the difference between "restored"
// and "was never on". A snapshot whose owner is still running is left alone.
func Restore() (bool, error) {
	snap, ok := LoadSnapshot(StatePath())
	if !ok || !snap.Applied {
		return false, nil
	}
	if snap.PID != os.Getpid() && OwnerAlive(snap.PID) {
		return false, nil
	}
	// Put the address values back first, then the switch: a machine that had
	// its own proxy on keeps working through the same sequence, and one that
	// had none gets the values this client wrote deleted instead of a dead
	// address left behind a disabled switch.
	if err := restoreString(valueProxyServer, snap.Server); err != nil {
		return true, err
	}
	if err := restoreString(valueProxyOverride, snap.Override); err != nil {
		return true, err
	}
	enable := uint32(0)
	if snap.WasOn && !oursOnly(snap.Server, ourAddrsFrom(snap.Addr)...) {
		enable = 1
	}
	if err := winreg.SetDWORD(regKeyPath, valueProxyEnable, enable); err != nil {
		return true, fmt.Errorf("sysproxy: %w", err)
	}
	notify()
	if err := ClearSnapshot(StatePath()); err != nil {
		return true, err
	}
	return true, nil
}

// restoreString writes a value back, or deletes it when the machine did not
// have one - restoring "absent" is not the same as writing an empty string.
func restoreString(name, value string) error {
	if value == "" {
		if err := winreg.DeleteValue(regKeyPath, name); err != nil && !errors.Is(err, winreg.ErrNotFound) {
			return fmt.Errorf("sysproxy: %w", err)
		}
		return nil
	}
	if err := winreg.SetString(regKeyPath, name, value); err != nil {
		return fmt.Errorf("sysproxy: %w", err)
	}
	return nil
}

// Current reports whether the system proxy is on and which server it points at.
// A missing ProxyEnable value means "off" rather than an error: that is the
// state of a machine the client has never touched.
func Current() (bool, string, error) {
	var enabled uint32
	v, err := winreg.GetDWORD(regKeyPath, valueProxyEnable)
	if err != nil && !errors.Is(err, winreg.ErrNotFound) {
		return false, "", err
	}
	if err == nil {
		enabled = v
	}
	server, err := winreg.GetString(regKeyPath, valueProxyServer)
	if err != nil && !errors.Is(err, winreg.ErrNotFound) {
		return enabled != 0, "", err
	}
	return enabled != 0, strings.TrimSpace(server), nil
}

// OwnerAlive reports whether the process that wrote a snapshot is still
// running. A pid that cannot be opened is gone (or not ours), which is exactly
// the answer the leftover cleanup and the guard need.
func OwnerAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}

// WaitForExit blocks until the process is gone, or until the timeout expires.
// It returns true when the process has exited. Used by the guard process, which
// has nothing to do but outlive the client.
func WaitForExit(pid int, timeout time.Duration) bool {
	if pid <= 0 {
		return true
	}
	h, err := syscall.OpenProcess(synchronizeAccess, false, uint32(pid))
	if err != nil {
		return true
	}
	defer syscall.CloseHandle(h)
	ms := uint32(timeout / time.Millisecond)
	if ms == 0 {
		ms = 1
	}
	ev, err := syscall.WaitForSingleObject(h, ms)
	if err != nil {
		return true
	}
	return ev != waitTimeoutCode
}

// notify makes running applications re-read the settings immediately.
func notify() {
	for _, opt := range []uintptr{internetOptionSettingsChanged, internetOptionRefresh} {
		_, _, _ = procInternetSetOption.Call(0, opt, 0, 0)
	}
}
