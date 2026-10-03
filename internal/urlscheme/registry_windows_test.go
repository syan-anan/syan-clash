//go:build windows

package urlscheme

import (
	"errors"
	"path/filepath"
	"testing"

	"vvpn/internal/winreg"
)

// The registry round-trip runs on a scratch scheme, never on clash:// itself.
// The machine this test runs on usually has a real client registered for
// clash:// - FlyClash on the development box - and a test that touched it
// would be exactly the hijack the package exists to prevent.
const testScheme = "syan-clash-urlscheme-test"

func cleanupScheme(t *testing.T, scheme string) {
	t.Helper()
	if err := winreg.DeleteKey(KeyPath(scheme)); err != nil && !errors.Is(err, winreg.ErrNotFound) {
		t.Fatalf("cleanup %s: %v", KeyPath(scheme), err)
	}
}

func TestRegisterUnregisterRoundTrip(t *testing.T) {
	cleanupScheme(t, testScheme)
	t.Cleanup(func() { cleanupScheme(t, testScheme) })

	if cur := Current(testScheme); cur.Registered || cur.Foreign || cur.Ours {
		t.Fatalf("a scratch scheme should start unregistered: %+v", cur)
	}

	// The registered path is a stand-in for the shipped client: the test binary
	// is urlscheme.test.exe, and ownership is decided by the file name, so a
	// test that registered itself would be testing the "foreign" branch by
	// accident.
	exe := filepath.Join(t.TempDir(), ExeName)
	got, err := Register(testScheme, exe)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !got.Registered || !got.Ours || got.Foreign {
		t.Fatalf("after Register: %+v", got)
	}
	if want := Command(exe); got.Command != want {
		t.Errorf("command = %q, want %q", got.Command, want)
	}
	if got.Owner != exe {
		t.Errorf("owner = %q, want %q", got.Owner, exe)
	}

	// The marker Explorer needs, and the default value that makes the scheme
	// show up as a protocol in the shell.
	if _, err := winreg.GetString(KeyPath(testScheme), "URL Protocol"); err != nil {
		t.Errorf("URL Protocol value is missing: %v", err)
	}
	if v, err := winreg.GetString(KeyPath(testScheme), ""); err != nil || v != "URL:"+testScheme {
		t.Errorf("default value = (%q, %v), want URL:%s", v, err, testScheme)
	}

	// Registering twice is not an error and does not change the command.
	again, err := Register(testScheme, exe)
	if err != nil {
		t.Fatalf("second Register: %v", err)
	}
	if again.Command != got.Command {
		t.Errorf("second Register changed the command: %q -> %q", got.Command, again.Command)
	}

	if err := Unregister(testScheme); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if cur := Current(testScheme); cur.Registered {
		t.Errorf("after Unregister the scheme is still registered: %+v", cur)
	}
	// Unregistering again is a no-op, not an error: the switch may be turned
	// off on a machine where it was never on.
	if err := Unregister(testScheme); err != nil {
		t.Errorf("second Unregister: %v", err)
	}
}

// A registration that belongs to another program must survive Register and
// Unregister untouched - both in the registry and in what Current reports.
func TestForeignRegistrationIsNeverTouched(t *testing.T) {
	cleanupScheme(t, testScheme)
	t.Cleanup(func() { cleanupScheme(t, testScheme) })

	foreign := filepath.Join(t.TempDir(), "FlyClash.exe")
	if err := winreg.SetString(KeyPath(testScheme), "URL Protocol", ""); err != nil {
		t.Fatalf("seed URL Protocol: %v", err)
	}
	if err := winreg.SetString(KeyPath(testScheme)+`\shell\open\command`, "", Command(foreign)); err != nil {
		t.Fatalf("seed command: %v", err)
	}

	cur := Current(testScheme)
	if !cur.Registered || !cur.Foreign || cur.Ours {
		t.Fatalf("the seeded registration should read as foreign: %+v", cur)
	}
	if cur.Owner != foreign {
		t.Errorf("owner = %q, want %q", cur.Owner, foreign)
	}

	exe := filepath.Join(t.TempDir(), ExeName)
	if _, err := Register(testScheme, exe); !errors.Is(err, ErrForeignOwner) {
		t.Fatalf("Register over a foreign registration returned %v, want ErrForeignOwner", err)
	}
	if err := Unregister(testScheme); !errors.Is(err, ErrForeignOwner) {
		t.Fatalf("Unregister of a foreign registration returned %v, want ErrForeignOwner", err)
	}
	after := Current(testScheme)
	if after.Command != cur.Command {
		t.Errorf("the foreign command changed: %q -> %q", cur.Command, after.Command)
	}
}
