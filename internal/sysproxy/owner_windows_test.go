//go:build windows

package sysproxy

import (
	"errors"
	"os"
	"testing"

	"vvpn/internal/winreg"
)

// The bug this pins down: on a machine where another client owns the system
// proxy, ProxyEnable is 1 and this client has no snapshot at all. Switching
// "our" proxy off in that state forced ProxyEnable to 0 and cut the other
// program off - which the user sees as "my other proxy stopped working".
func TestDisableRefusesAProxyThatIsNotOurs(t *testing.T) {
	withScratchKey(t)

	if err := winreg.SetString(regKeyPath, valueProxyServer, "http=127.0.0.1:6468"); err != nil {
		t.Fatal(err)
	}
	if err := winreg.SetDWORD(regKeyPath, valueProxyEnable, 1); err != nil {
		t.Fatal(err)
	}

	if err := Disable(); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("Disable = %v, want ErrNotOwner", err)
	}
	if v, err := winreg.GetDWORD(regKeyPath, valueProxyEnable); err != nil || v != 1 {
		t.Fatalf("ProxyEnable = %d, err=%v: another program's proxy was switched off", v, err)
	}
	if got, err := winreg.GetString(regKeyPath, valueProxyServer); err != nil || got != "http=127.0.0.1:6468" {
		t.Fatalf("ProxyServer = %q, err=%v: another program's address was rewritten", got, err)
	}
}

// OwnedBy answers "did this process write the current setting", which is the
// question the tray and the guard have to ask instead of "is the switch up".
func TestOwnedByTracksTheSnapshot(t *testing.T) {
	withScratchKey(t)

	if OwnedBy(StatePath(), os.Getpid()) {
		t.Fatal("OwnedBy reported ownership with no snapshot")
	}
	if err := EnableForced("127.0.0.1:3750", "127.0.0.1:3751", "", false); err != nil {
		t.Fatalf("EnableForced: %v", err)
	}
	if !OwnedBy(StatePath(), os.Getpid()) {
		t.Fatal("OwnedBy did not see the snapshot this process just wrote")
	}
	if OwnedBy(StatePath(), os.Getpid()+1) {
		t.Fatal("OwnedBy reported ownership for a different pid")
	}
	if err := Disable(); err != nil {
		t.Fatalf("Disable after our own enable: %v", err)
	}
	if OwnedBy(StatePath(), os.Getpid()) {
		t.Fatal("OwnedBy still reports ownership after Disable")
	}
}
