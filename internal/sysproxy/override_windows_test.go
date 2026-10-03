//go:build windows

package sysproxy

import (
	"os"
	"path/filepath"
	"testing"

	"vvpn/internal/winreg"
)

// scratchKey is a throwaway key directly under HKCU\Software, so deleting it
// leaves nothing behind at all. Pointing the package at it is what
// lets these tests drive the real registry code path - the same EnableForced
// and Restore the running client uses - without touching the machine's own
// Internet Settings, which is somebody else's setting while the test runs.
const scratchKey = `Software\syan-clash-p32-sysproxy-test`

func withScratchKey(t *testing.T) {
	t.Helper()
	prevKey := regKeyPath
	prevState := StatePath()
	_ = winreg.DeleteKey(scratchKey)
	regKeyPath = scratchKey
	SetStatePath(filepath.Join(t.TempDir(), "sysproxy-state.json"))
	t.Cleanup(func() {
		_ = winreg.DeleteKey(scratchKey)
		regKeyPath = prevKey
		SetStatePath(prevState)
	})
}

// The list the user typed must be what lands in ProxyOverride, and Restore must
// put the machine back exactly as it was found.
func TestEnableForcedWritesTheConfiguredBypass(t *testing.T) {
	withScratchKey(t)

	const bypass = "<local>;*.corp.example.com;10.0.0.0/8"
	if err := EnableForced("127.0.0.1:3750", "127.0.0.1:3751", bypass, false); err != nil {
		t.Fatalf("EnableForced: %v", err)
	}
	if got, err := winreg.GetString(regKeyPath, valueProxyOverride); err != nil || got != bypass {
		t.Fatalf("ProxyOverride = %q, err=%v, want %q", got, err, bypass)
	}
	if got, err := winreg.GetString(regKeyPath, valueProxyServer); err != nil ||
		got != "http=127.0.0.1:3750;https=127.0.0.1:3750;socks=127.0.0.1:3751" {
		t.Fatalf("ProxyServer = %q, err=%v", got, err)
	}
	if v, err := winreg.GetDWORD(regKeyPath, valueProxyEnable); err != nil || v != 1 {
		t.Fatalf("ProxyEnable = %d, err=%v", v, err)
	}

	restored, err := Restore()
	if err != nil || !restored {
		t.Fatalf("Restore = %v, %v", restored, err)
	}
	if _, err := winreg.GetString(regKeyPath, valueProxyOverride); err == nil {
		t.Fatal("ProxyOverride survived Restore; a machine that had none must end with none")
	}
	if _, err := winreg.GetString(regKeyPath, valueProxyServer); err == nil {
		t.Fatal("ProxyServer survived Restore")
	}
	if v, err := winreg.GetDWORD(regKeyPath, valueProxyEnable); err != nil || v != 0 {
		t.Fatalf("ProxyEnable after Restore = %d, err=%v, want 0", v, err)
	}
}

// A caller with nothing to say about bypassing gets the historical value.
func TestEnableForcedKeepsTheDefaultWhenNoBypassIsGiven(t *testing.T) {
	withScratchKey(t)
	if err := EnableForced("127.0.0.1:3750", "127.0.0.1:3750", "", false); err != nil {
		t.Fatalf("EnableForced: %v", err)
	}
	if got, err := winreg.GetString(regKeyPath, valueProxyOverride); err != nil || got != DefaultBypass {
		t.Fatalf("ProxyOverride = %q, err=%v, want %q", got, err, DefaultBypass)
	}
}

// Taking the setting over must not eat the other program's bypass list: it is
// handed back on the way out, together with its switch.
func TestEnableForcedRoundTripsAPreviousBypass(t *testing.T) {
	withScratchKey(t)
	if err := winreg.SetString(regKeyPath, valueProxyOverride, "<local>;intranet.local"); err != nil {
		t.Fatal(err)
	}
	if err := winreg.SetString(regKeyPath, valueProxyServer, "http=127.0.0.1:6468"); err != nil {
		t.Fatal(err)
	}
	if err := winreg.SetDWORD(regKeyPath, valueProxyEnable, 1); err != nil {
		t.Fatal(err)
	}

	if err := EnableForced("127.0.0.1:3750", "127.0.0.1:3750", "*.corp.example.com", true); err != nil {
		t.Fatalf("EnableForced: %v", err)
	}
	if got, _ := winreg.GetString(regKeyPath, valueProxyOverride); got != "*.corp.example.com" {
		t.Fatalf("ProxyOverride while taken over = %q", got)
	}

	if _, err := Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got, err := winreg.GetString(regKeyPath, valueProxyOverride); err != nil || got != "<local>;intranet.local" {
		t.Fatalf("ProxyOverride after Restore = %q, err=%v", got, err)
	}
	if got, err := winreg.GetString(regKeyPath, valueProxyServer); err != nil || got != "http=127.0.0.1:6468" {
		t.Fatalf("ProxyServer after Restore = %q, err=%v", got, err)
	}
	if v, _ := winreg.GetDWORD(regKeyPath, valueProxyEnable); v != 1 {
		t.Fatalf("ProxyEnable after Restore = %d, want 1", v)
	}
}

// TestEnableForcedAgainstTheRealKey is opt-in. It drives the same code path
// against the machine's own Internet Settings and hands the values back, but
// while it runs the system proxy briefly points at a port nothing listens on.
// That is not something a plain `go test ./...` should do to whoever is using
// the machine, so it is skipped unless SYANV_SYSPROXY_REALKEY=1.
func TestEnableForcedAgainstTheRealKey(t *testing.T) {
	if os.Getenv("SYANV_SYSPROXY_REALKEY") != "1" {
		t.Skip("set SYANV_SYSPROXY_REALKEY=1 to run against the real Internet Settings key")
	}
	prevState := StatePath()
	SetStatePath(filepath.Join(t.TempDir(), "sysproxy-state.json"))
	t.Cleanup(func() { SetStatePath(prevState) })

	// Whatever the machine looked like, it has to look like that again.
	onBefore, srvBefore, _ := Current()
	ovBefore, _ := winreg.GetString(regKeyPath, valueProxyOverride)

	const bypass = "<local>;*.p32.example.com;172.16.0.0/12"
	if err := EnableForced("127.0.0.1:3751", "127.0.0.1:3752", bypass, true); err != nil {
		t.Fatalf("EnableForced: %v", err)
	}
	if got, err := winreg.GetString(regKeyPath, valueProxyOverride); err != nil || got != bypass {
		t.Fatalf("real ProxyOverride = %q, err=%v, want %q", got, err, bypass)
	}
	restored, err := Restore()
	if err != nil || !restored {
		t.Fatalf("Restore = %v, %v", restored, err)
	}
	onAfter, srvAfter, _ := Current()
	ovAfter, _ := winreg.GetString(regKeyPath, valueProxyOverride)
	if onBefore != onAfter || srvBefore != srvAfter || ovBefore != ovAfter {
		t.Fatalf("the machine was not handed back: before (on=%v server=%q override=%q) after (on=%v server=%q override=%q)",
			onBefore, srvBefore, ovBefore, onAfter, srvAfter, ovAfter)
	}
}
