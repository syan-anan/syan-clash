package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vvpn/internal/core"
)

// editClashSample is what the fake provider serves after a link change: one node
// with a name the previous provider never used, so "the old node is gone and the
// new one arrived" is a single, unambiguous assertion.
const editClashSample = `
proxies:
  - name: "新机场-香港"
    type: ss
    server: 9.9.9.9
    port: 8388
    cipher: aes-256-gcm
    password: pw
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - 新机场-香港
rules:
  - MATCH,PROXY
`

// seedSubscription stores one subscription the way the client does - list plus
// ownership - so an edit has something real to move around.
func seedSubscription(t *testing.T, a *App, name, url, nodeName string) {
	t.Helper()
	resetNodeSources()
	a.mu.Lock()
	a.subs = []Subscription{{
		Name: name, URL: url, AddedAt: time.Now(), Auto: true,
		NodeNames: []string{nodeName},
	}}
	a.mu.Unlock()
	if err := a.saveSubs(); err != nil {
		t.Fatalf("saveSubs: %v", err)
	}
	recordNodes(name, []core.Node{{Name: nodeName, Type: core.TypeSocks5, Server: "127.0.0.1", Port: 1080}})
}

// reloadFromDisk throws the in-memory list away and reads it back, which is the
// exact path a restart takes. Anything that only lived in memory fails here.
func reloadFromDisk(t *testing.T, a *App) {
	t.Helper()
	a.mu.Lock()
	a.subs = nil
	a.mu.Unlock()
	if err := a.loadSubs(); err != nil {
		t.Fatalf("loadSubs: %v", err)
	}
}

// A rename has to move the nodes with it. The ownership map is what tells the
// next import which servers to replace, so a rename that left it behind would
// make the following refresh duplicate or drop the wrong ones.
func TestEditSubscriptionRenamesAndMovesNodeOwnership(t *testing.T) {
	a := newTestApp(t)
	seedSubscription(t, a, "机场A", "https://a.example/sub", "A-香港")

	sub, err := a.EditSubscription(context.Background(), "机场A", "机场B", "")
	if err != nil {
		t.Fatalf("EditSubscription: %v", err)
	}
	if sub.Name != "机场B" || sub.URL != "https://a.example/sub" {
		t.Fatalf("renamed subscription = %+v", sub)
	}
	if owner, ok := nodeOwner("A-香港"); !ok || owner != "机场B" {
		t.Fatalf("node ownership = %q/%v, want 机场B/true", owner, ok)
	}
	if len(sub.NodeNames) != 1 || sub.NodeNames[0] != "A-香港" {
		t.Fatalf("the node list was not carried across the rename: %v", sub.NodeNames)
	}

	reloadFromDisk(t, a)
	if _, err := a.subscriptionByName("机场B"); err != nil {
		t.Fatalf("the new name did not survive a reload: %v", err)
	}
	if _, err := a.subscriptionByName("机场A"); err == nil {
		t.Fatal("the old name is still on disk")
	}
}

// Changing the link has to re-import, because a subscription whose URL changed
// but whose nodes are still the old provider's is worse than no edit at all.
func TestEditSubscriptionRelinkReimportsFromTheNewURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("subscription-userinfo", "upload=1; download=2; total=100; expire=1893456000")
		_, _ = io.WriteString(w, editClashSample)
	}))
	defer srv.Close()

	a := newTestApp(t)
	seedSubscription(t, a, "机场A", "https://a.example/sub", "A-香港")

	sub, err := a.EditSubscription(context.Background(), "机场A", "", srv.URL)
	if err != nil {
		t.Fatalf("EditSubscription: %v", err)
	}
	if sub.URL != srv.URL {
		t.Fatalf("the new link was not stored: %q", sub.URL)
	}
	if sub.Nodes != 1 || sub.LastError != "" {
		t.Fatalf("the re-import did not run: nodes=%d last_error=%q", sub.Nodes, sub.LastError)
	}
	if sub.Info == nil || sub.Info.Total != 100 {
		t.Fatalf("the provider's usage metadata was not picked up: %+v", sub.Info)
	}
	names := map[string]bool{}
	for _, n := range a.Profile().Nodes {
		names[n.Name] = true
	}
	if names["A-香港"] {
		t.Error("the previous provider's node survived the relink")
	}
	if !names["新机场-香港"] {
		t.Errorf("the new provider's node is missing: %v", names)
	}

	reloadFromDisk(t, a)
	back, err := a.subscriptionByName("机场A")
	if err != nil {
		t.Fatalf("the subscription did not survive a reload: %v", err)
	}
	if back.URL != srv.URL {
		t.Fatalf("the new link did not survive a reload: %q", back.URL)
	}
}

// Rejections have to leave the list exactly as it was, and a form that sends
// both fields on every save must not turn an untouched edit into an error.
func TestEditSubscriptionRejectsCollisionsAndUnknownNames(t *testing.T) {
	a := newTestApp(t)
	seedSubscription(t, a, "机场A", "https://a.example/sub", "A-香港")
	a.mu.Lock()
	a.subs = append(a.subs, Subscription{Name: "机场B", URL: "https://b.example/sub", AddedAt: time.Now()})
	a.mu.Unlock()
	if err := a.saveSubs(); err != nil {
		t.Fatalf("saveSubs: %v", err)
	}
	ctx := context.Background()

	if _, err := a.EditSubscription(ctx, "机场A", "机场B", ""); err == nil {
		t.Error("renaming onto an existing name must fail")
	}
	if _, err := a.EditSubscription(ctx, "机场A", "", "https://b.example/sub"); err == nil {
		t.Error("reusing another subscription's link must fail")
	}
	if _, err := a.EditSubscription(ctx, "不存在", "X", ""); err == nil {
		t.Error("editing an unknown subscription must fail")
	}
	if subs := a.Subscriptions(); len(subs) != 2 {
		t.Fatalf("a rejected edit changed the list: %+v", subs)
	}
	if owner, _ := nodeOwner("A-香港"); owner != "机场A" {
		t.Fatalf("a rejected rename moved node ownership to %q", owner)
	}

	sub, err := a.EditSubscription(ctx, "机场A", "机场A", "https://a.example/sub")
	if err != nil || sub.Name != "机场A" || sub.URL != "https://a.example/sub" {
		t.Fatalf("a no-op edit failed: %+v %v", sub, err)
	}
}
