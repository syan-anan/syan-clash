package app

import (
	"testing"

	"vvpn/internal/config"
)

// The tray preference lives in the same file as the proxy configuration, so the
// assertion that matters is "is it on disk?", not "is the field set?".
func TestSilentStartIsPersisted(t *testing.T) {
	a := newTestApp(t)
	if a.SilentStart() {
		t.Fatal("a fresh client must show its window")
	}
	if err := a.SetSilentStart(true); err != nil {
		t.Fatalf("SetSilentStart(true): %v", err)
	}
	if !a.SilentStart() {
		t.Fatal("the preference did not stick in memory")
	}
	cfg, err := config.Load(a.ConfigPath())
	if err != nil {
		t.Fatalf("reload the configuration from disk: %v", err)
	}
	if !cfg.App.SilentStart {
		t.Fatal("the preference was not written to the configuration file")
	}
	// Turning it off again must not need a restart either.
	if err := a.SetSilentStart(false); err != nil {
		t.Fatalf("SetSilentStart(false): %v", err)
	}
	if a.SilentStart() {
		t.Fatal("the preference did not turn off")
	}
	cfg, err = config.Load(a.ConfigPath())
	if err != nil {
		t.Fatalf("reload after turning it off: %v", err)
	}
	if cfg.App.SilentStart {
		t.Fatal("turning it off was not written to disk")
	}
}
