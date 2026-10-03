package app

import (
	"testing"
	"time"

	"vvpn/internal/subscription"
)

// The interval the provider sends wins; a provider that stays silent gets the
// client default. Without this a subscription could be refreshed every few
// minutes or never at all.
func TestAutoIntervalPrefersTheProviderHeader(t *testing.T) {
	if got := AutoInterval(Subscription{}); got != defaultAutoInterval {
		t.Errorf("silent provider interval = %v, want %v", got, defaultAutoInterval)
	}
	sub := Subscription{Info: &subscription.Info{UpdateEvery: 5}}
	if got := AutoInterval(sub); got != 5*time.Hour {
		t.Errorf("provider interval = %v, want 5h", got)
	}
}

// A subscription that was switched off must never look scheduled.
func TestManualSubscriptionHasNoNextUpdate(t *testing.T) {
	sub := Subscription{Name: "manual", AddedAt: time.Now().Add(-100 * time.Hour)}
	if next := sub.NextUpdate(); !next.IsZero() {
		t.Errorf("manual subscription has a next update: %v", next)
	}
}

// Due is computed from the last successful update, so an automatic
// subscription becomes due as soon as its interval has passed.
func TestNextUpdateUsesTheInterval(t *testing.T) {
	now := time.Now()
	sub := Subscription{
		Name:      "auto",
		Auto:      true,
		AddedAt:   now.Add(-10 * time.Hour),
		UpdatedAt: now.Add(-3 * time.Hour),
		Info:      &subscription.Info{UpdateEvery: 2},
	}
	next := sub.NextUpdate()
	if next.IsZero() {
		t.Fatal("automatic subscription has no next update")
	}
	if next.After(now) {
		t.Errorf("next update %v should already be due", next)
	}

	fresh := Subscription{Auto: true, UpdatedAt: now, Info: &subscription.Info{UpdateEvery: 2}}
	if next := fresh.NextUpdate(); !next.After(now) {
		t.Errorf("a just-updated subscription is due again immediately: %v", next)
	}
}
