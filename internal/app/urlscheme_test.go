package app

import (
	"context"
	"strings"
	"testing"
)

// A link that names a subscription the client already has must resolve to that
// subscription, so clicking the same link twice refreshes instead of failing.
func TestExistingSubscriptionFor(t *testing.T) {
	subs := []Subscription{
		{Name: "示例机场", URL: "https://dy11.example.com/api/v1/client/subscribe?token=abc"},
		{Name: "备用", URL: "  https://example.com/backup.yaml  "},
	}
	got, ok := existingSubscriptionFor(subs, "https://dy11.example.com/api/v1/client/subscribe?token=abc")
	if !ok || got.Name != "示例机场" {
		t.Errorf("existingSubscriptionFor = (%+v, %v), want the 示例机场 entry", got, ok)
	}
	// Whitespace on either side must not hide a match.
	if got, ok := existingSubscriptionFor(subs, "https://example.com/backup.yaml"); !ok || got.Name != "备用" {
		t.Errorf("existingSubscriptionFor with padded URL = (%+v, %v)", got, ok)
	}
	if _, ok := existingSubscriptionFor(subs, "https://example.com/other.yaml"); ok {
		t.Error("an unknown URL must not match a saved subscription")
	}
	if _, ok := existingSubscriptionFor(nil, "https://example.com/x"); ok {
		t.Error("an empty list must not match")
	}
}

// HandleURLScheme is the one door every arrival path goes through, so a bad
// link has to be refused there rather than half-way through an import.
func TestHandleURLSchemeRefusesBadLinks(t *testing.T) {
	a := &App{}
	for _, raw := range []string{
		"",
		"https://example.com/sub",
		"clash://open-config?url=https://example.com/sub",
		"clash://install-config?url=file%3A%2F%2F%2FC%3A%2Fx",
		"clash://install-config",
	} {
		_, err := a.HandleURLScheme(context.Background(), raw)
		if err == nil {
			t.Errorf("HandleURLScheme(%q) succeeded, want an error", raw)
			continue
		}
		if strings.Contains(err.Error(), "nil pointer") || strings.Contains(err.Error(), "panic") {
			t.Errorf("HandleURLScheme(%q) reached the import path: %v", raw, err)
		}
	}
}

// The status hint is what the console shows; a foreign owner has to be named
// rather than reported as a plain failure.
func TestURLSchemeHintNamesTheOwner(t *testing.T) {
	st := URLSchemeStatus{Foreign: true, Registered: true, Owner: `H:\VPN\FlyClash\FlyClash.exe`}
	if hint := urlSchemeHint(st); !strings.Contains(hint, "FlyClash.exe") {
		t.Errorf("hint = %q, want it to name the owner", hint)
	}
	if hint := urlSchemeHint(URLSchemeStatus{}); !strings.Contains(hint, "未开启") {
		t.Errorf("hint for a switched-off client = %q", hint)
	}
	if hint := urlSchemeHint(URLSchemeStatus{Enabled: true, Ours: true, Registered: true}); !strings.Contains(hint, "已注册") {
		t.Errorf("hint for a registered client = %q", hint)
	}
}
