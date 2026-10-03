package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"vvpn/internal/subscription"
)

// An interval the operator set has to win over the provider's own header,
// otherwise "自定义间隔" is a control that visibly does nothing.
func TestAutoIntervalOverrideBeatsProviderHeader(t *testing.T) {
	sub := Subscription{Info: &subscription.Info{UpdateEvery: 5}, IntervalOverrideHours: 2}
	if got := AutoInterval(sub); got != 2*time.Hour {
		t.Errorf("override interval = %v, want 2h", got)
	}
	sub.IntervalOverrideHours = 0
	if got := AutoInterval(sub); got != 5*time.Hour {
		t.Errorf("provider interval = %v, want 5h", got)
	}
	if got := AutoInterval(Subscription{}); got != defaultAutoInterval {
		t.Errorf("silent provider interval = %v, want %v", got, defaultAutoInterval)
	}
}

func TestSetSubscriptionOptionsValidatesAndPersists(t *testing.T) {
	a := newTestApp(t)
	seedSubscription(t, a, "机场A", "https://example.invalid/sub", "香港 01")

	sub, err := a.SetSubscriptionOptions("机场A", "  syan-clash/1.0  ", 6)
	if err != nil {
		t.Fatalf("SetSubscriptionOptions: %v", err)
	}
	if sub.UserAgent != "syan-clash/1.0" {
		t.Errorf("UserAgent = %q, want it trimmed", sub.UserAgent)
	}
	if sub.IntervalOverrideHours != 6 {
		t.Errorf("IntervalOverrideHours = %d, want 6", sub.IntervalOverrideHours)
	}
	if got := AutoInterval(sub); got != 6*time.Hour {
		t.Errorf("effective interval = %v, want 6h", got)
	}

	// The choice has to reach disk, otherwise the console forgets it on restart.
	raw, err := os.ReadFile(a.subsPath())
	if err != nil {
		t.Fatalf("read %s: %v", a.subsPath(), err)
	}
	for _, want := range []string{"\"user_agent\": \"syan-clash/1.0\"", "\"interval_override_hours\": 6"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("subscriptions.json is missing %s\n%s", want, raw)
		}
	}

	// Clearing the override puts the subscription back on the provider's header.
	cleared, err := a.SetSubscriptionOptions("机场A", "", 0)
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if cleared.UserAgent != "" || cleared.IntervalOverrideHours != 0 {
		t.Errorf("cleared = %+v", cleared)
	}
}

func TestSetSubscriptionOptionsRejectsBadInput(t *testing.T) {
	a := newTestApp(t)
	seedSubscription(t, a, "机场A", "https://example.invalid/sub", "香港 01")

	cases := []struct {
		why   string
		name  string
		ua    string
		hours int64
	}{
		{"empty name", "", "syan-clash", 0},
		{"unknown subscription", "不存在", "syan-clash", 0},
		{"newline in User-Agent", "机场A", "syan-clash\r\nX-Injected: 1", 0},
		{"oversized User-Agent", "机场A", strings.Repeat("a", 257), 0},
		{"negative interval", "机场A", "syan-clash", -1},
		{"interval past the cap", "机场A", "syan-clash", maxIntervalOverrideHours + 1},
	}
	for _, c := range cases {
		if _, err := a.SetSubscriptionOptions(c.name, c.ua, c.hours); err == nil {
			t.Errorf("%s: accepted invalid input", c.why)
		}
	}
}

// The saved User-Agent must actually be presented on the next refresh.
func TestRefreshUsesTheSavedUserAgent(t *testing.T) {
	a := newTestApp(t)
	seen := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("User-Agent")
		_, _ = fmt.Fprint(w, editClashSample)
	}))
	defer srv.Close()

	seedSubscription(t, a, "机场A", srv.URL, "香港 01")
	if _, err := a.SetSubscriptionOptions("机场A", "syan-clash/custom", 0); err != nil {
		t.Fatalf("SetSubscriptionOptions: %v", err)
	}
	if _, err := a.UpdateSubscription(context.Background(), "机场A"); err != nil {
		t.Fatalf("UpdateSubscription: %v", err)
	}
	if ua := <-seen; ua != "syan-clash/custom" {
		t.Errorf("User-Agent = %q, want syan-clash/custom", ua)
	}

	// A subscription with no override still identifies as the client default.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("User-Agent")
		_, _ = fmt.Fprint(w, editClashSample)
	}))
	defer srv2.Close()
	seedSubscription(t, a, "机场B", srv2.URL, "香港 02")
	if _, err := a.UpdateSubscription(context.Background(), "机场B"); err != nil {
		t.Fatalf("UpdateSubscription: %v", err)
	}
	if ua := <-seen; ua != subscriptionUserAgent {
		t.Errorf("default User-Agent = %q, want %q", ua, subscriptionUserAgent)
	}
}

// ImportSubscriptionWithUserAgent has to override whatever is saved, so a
// one-off fetch (for example "try this agent before saving it") is possible.
func TestImportSubscriptionWithUserAgentOverridesTheSavedOne(t *testing.T) {
	a := newTestApp(t)
	seen := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("User-Agent")
		_, _ = fmt.Fprint(w, editClashSample)
	}))
	defer srv.Close()

	seedSubscription(t, a, "机场A", srv.URL, "香港 01")
	if _, err := a.SetSubscriptionOptions("机场A", "syan-clash/saved", 0); err != nil {
		t.Fatalf("SetSubscriptionOptions: %v", err)
	}
	if _, err := a.ImportSubscriptionWithUserAgent(context.Background(), "机场A", srv.URL, "syan-clash/oneoff"); err != nil {
		t.Fatalf("ImportSubscriptionWithUserAgent: %v", err)
	}
	if ua := <-seen; ua != "syan-clash/oneoff" {
		t.Errorf("User-Agent = %q, want syan-clash/oneoff", ua)
	}
}
