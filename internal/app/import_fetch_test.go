package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fastRetry shrinks the retry backoff so the suite does not sleep for real.
func fastRetry(t *testing.T) {
	t.Helper()
	old := subscriptionRetryDelay
	subscriptionRetryDelay = time.Millisecond
	t.Cleanup(func() { subscriptionRetryDelay = old })
}

// tinyBodyLimit lowers the body ceiling so oversize cases stay cheap.
func tinyBodyLimit(t *testing.T, n int64) {
	t.Helper()
	old := subscriptionMaxBody
	subscriptionMaxBody = n
	t.Cleanup(func() { subscriptionMaxBody = old })
}

func TestFetchSubscriptionRetriesTransientStatus(t *testing.T) {
	fastRetry(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = fmt.Fprint(w, "proxies: []\n")
	}))
	defer srv.Close()

	body, info, err := fetchSubscription(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchSubscription: %v", err)
	}
	if !strings.Contains(body, "proxies:") {
		t.Errorf("body = %q", body)
	}
	if info != nil {
		t.Errorf("the server sent no metadata headers, info = %+v", info)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Errorf("hits = %d, want 3", got)
	}
}

func TestFetchSubscriptionGivesUpAfterAttempts(t *testing.T) {
	fastRetry(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	_, _, err := fetchSubscription(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("want an error once every attempt has failed")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("err = %v, want it to name the status", err)
	}
	if got := atomic.LoadInt32(&hits); got != int32(subscriptionAttempts) {
		t.Errorf("hits = %d, want %d", got, subscriptionAttempts)
	}
}

func TestFetchSubscriptionDoesNotRetryClientError(t *testing.T) {
	fastRetry(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if _, _, err := fetchSubscription(context.Background(), srv.URL); err == nil {
		t.Fatal("want an error for 404")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("hits = %d, want 1: a 404 must not be retried", got)
	}
}

func TestFetchSubscriptionStopsWhenContextIsCancelled(t *testing.T) {
	fastRetry(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = fmt.Fprint(w, "proxies: []\n")
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := fetchSubscription(ctx, srv.URL); err == nil {
		t.Fatal("want an error for a cancelled context")
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("hits = %d, want 0", got)
	}
}

func TestFetchSubscriptionBodyCeiling(t *testing.T) {
	fastRetry(t)
	tinyBodyLimit(t, 64)
	payload := strings.Repeat("a", 64)

	exact := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, payload)
	}))
	defer exact.Close()
	body, _, err := fetchSubscription(context.Background(), exact.URL)
	if err != nil || len(body) != 64 {
		t.Fatalf("a body exactly at the ceiling must be accepted: len=%d err=%v", len(body), err)
	}

	var hits int32
	over := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = fmt.Fprint(w, payload+"x")
	}))
	defer over.Close()
	_, _, err = fetchSubscription(context.Background(), over.URL)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want an oversize error", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("hits = %d, want 1: an oversize body must not be retried", got)
	}
}

func TestFetchSubscriptionUserAgent(t *testing.T) {
	fastRetry(t)
	seen := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("User-Agent")
		_, _ = fmt.Fprint(w, "proxies: []\n")
	}))
	defer srv.Close()

	if _, _, err := fetchSubscription(context.Background(), srv.URL); err != nil {
		t.Fatalf("default UA: %v", err)
	}
	if ua := <-seen; ua != "clash-verge-rev/2.0.3" {
		t.Errorf("default UA = %q", ua)
	}
	if _, _, err := fetchSubscriptionAs(context.Background(), srv.URL, "syan-clash/9.9"); err != nil {
		t.Fatalf("custom UA: %v", err)
	}
	if ua := <-seen; ua != "syan-clash/9.9" {
		t.Errorf("custom UA = %q", ua)
	}
	// An empty override has to fall back to the default, not send an empty UA:
	// airports fingerprint the header and answer unknown agents with decoys.
	if _, _, err := fetchSubscriptionAs(context.Background(), srv.URL, ""); err != nil {
		t.Fatalf("empty UA: %v", err)
	}
	if ua := <-seen; ua != "clash-verge-rev/2.0.3" {
		t.Errorf("empty override UA = %q", ua)
	}
}

func TestFetchSubscriptionIgnoresAmbientProxyEnvironment(t *testing.T) {
	fastRetry(t)
	// A dead proxy in the environment must not be used: the fetch has to reach
	// the server directly. Inheriting these would also route the fetch through
	// syan-clash's own inbound port when the operator has it exported.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "proxies: []\n")
	}))
	defer srv.Close()
	if _, _, err := fetchSubscription(context.Background(), srv.URL); err != nil {
		t.Fatalf("an ambient proxy leaked into the fetch: %v", err)
	}
}

func TestFetchSubscriptionCapsRedirects(t *testing.T) {
	fastRetry(t)
	var hits int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Redirect(w, r, srv.URL+"/next", http.StatusFound)
	}))
	defer srv.Close()

	_, _, err := fetchSubscription(context.Background(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("err = %v, want a redirect error", err)
	}
	if got := atomic.LoadInt32(&hits); got > int32(subscriptionMaxRedirects+1) {
		t.Errorf("hits = %d, want at most %d: a redirect loop must not be retried",
			got, subscriptionMaxRedirects+1)
	}
}

func TestFetchSubscriptionReadsMetadataHeaders(t *testing.T) {
	fastRetry(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("subscription-userinfo", "upload=1; download=2; total=3; expire=4")
		w.Header().Set("profile-update-interval", "12")
		w.Header().Set("content-disposition", "attachment; filename=\"airport.yaml\"")
		_, _ = fmt.Fprint(w, "proxies: []\n")
	}))
	defer srv.Close()

	_, info, err := fetchSubscription(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchSubscription: %v", err)
	}
	if info == nil {
		t.Fatal("info = nil, want the parsed metadata")
	}
	if info.Upload != 1 || info.Download != 2 || info.Total != 3 || info.Expire != 4 {
		t.Errorf("traffic = %+v", *info)
	}
	if info.UpdateEvery != 12 {
		t.Errorf("UpdateEvery = %d, want 12", info.UpdateEvery)
	}
	// FilenameFromDisposition strips the known config suffixes, so the header
	// "airport.yaml" surfaces as the bare name the console shows.
	if info.Filename != "airport" {
		t.Errorf("Filename = %q, want airport", info.Filename)
	}
}
