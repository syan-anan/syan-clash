package control

import (
	"strings"
	"testing"
)

// The five-fix batch (2026-10-03) repaired the window controls, the toast
// placement, the subscription action row, the node table's refresh churn and the
// node list / switch path. Each repair is a small piece of the page, so each one
// can silently disappear the next time the file is edited. These tests pin the
// shape of every repair to the embedded asset the server actually ships.
//
// They are deliberately structural: they look for the mechanism that makes the
// fix work, not for a screenshot.

// requireOnce fails when a marker that must exist exactly once is missing or has
// been duplicated by a careless edit.
func requireOnce(t *testing.T, html, marker, what string) {
	t.Helper()
	switch strings.Count(html, marker) {
	case 1:
	case 0:
		t.Errorf("%s is gone: %q not found in the console", what, marker)
	default:
		t.Errorf("%s appears %d times, want 1: %q", what, strings.Count(html, marker), marker)
	}
}

func TestToastsAreAnchoredToTheBottomEdge(t *testing.T) {
	html := webAsset(t)

	// The 56px top offset put every toast on top of the title bar and the page
	// heading. Toasts now grow upward from the bottom edge.
	if strings.Contains(html, "top: 56px") {
		t.Error("the toast stack is back under the title bar (top: 56px)")
	}
	requireOnce(t, html, "top: auto; bottom: 22px", "the frameless toast override")
	if !strings.Contains(html, ".toasts {") {
		t.Fatal("the toast container lost its style block")
	}
	block := html[strings.Index(html, ".toasts {"):]
	if end := strings.Index(block, "}"); end > 0 {
		block = block[:end]
	}
	if !strings.Contains(block, "bottom:") {
		t.Errorf("the toast container is no longer bottom-anchored: %q", block)
	}
	if strings.Contains(block, "top:") {
		t.Errorf("the toast container still sets top, which fights the bottom anchor: %q", block)
	}
}

func TestSubscriptionActionsShareOneWidth(t *testing.T) {
	html := webAsset(t)

	// Four buttons whose width followed their label (二维码 60.69px against
	// 49.11px for the rest) never lined up. A floor plus centring makes the row
	// flush whatever the label is.
	idx := strings.Index(html, ".sub-actions .btn {")
	if idx < 0 {
		t.Fatal("the subscription action row lost its style block")
	}
	block := html[idx:]
	if end := strings.Index(block, "}"); end > 0 {
		block = block[:end]
	}
	for _, want := range []string{"min-width: 64px", "justify-content: center", "text-align: center"} {
		if !strings.Contains(block, want) {
			t.Errorf("the subscription action row lost %q: %q", want, block)
		}
	}
}

func TestNodeTableRebuildsOnlyOnStructuralChange(t *testing.T) {
	html := webAsset(t)

	// The table used to be rebuilt from the poll payload, which threw away the
	// button the person was pressing and every hover state. Rebuilding now
	// depends on the structure alone; selection is repainted in place.
	requireOnce(t, html, "const structSig = JSON.stringify([", "the structural signature")
	requireOnce(t, html, "if (structSig !== nodeList.dataSig) {", "the structural rebuild gate")
	requireOnce(t, html, "function paintNodeSelection() {", "the in-place selection repaint")
	requireOnce(t, html, "function syncGroupSelects(groups) {", "the group select sync")
	requireOnce(t, html, "syncGroupSelects(groups);", "the group select sync call")
	requireOnce(t, html, "paintNodeSelection();", "the selection repaint call")
}

func TestSubscriptionEditorIsReboundAfterEveryRender(t *testing.T) {
	html := webAsset(t)

	// The editor buttons are built by the table render, so a binding made once at
	// parse time was attached to markup that no longer existed. The bind call has
	// to appear after the render as well as at parse time.
	if got := strings.Count(html, "bindSubsEditors();"); got < 2 {
		t.Errorf("bindSubsEditors() is called %d time(s); it must run once at parse time and again after each render", got)
	}
	requireOnce(t, html, "function bindSubsEditors() {", "the subscription editor binder")

	render := strings.Index(html, `if (!setHTML($("#subs-body"), html)) return;`)
	if render < 0 {
		t.Fatal("the subscription table no longer guards its render with setHTML")
	}
	tail := html[render:]
	if end := strings.Index(tail, "\n}"); end > 0 {
		tail = tail[:end]
	}
	if !strings.Contains(tail, "bindSubsEditors();") {
		t.Error("the subscription table renders without rebinding its editors")
	}
}

func TestNarrowViewportsScrollInsideTheirCards(t *testing.T) {
	html := webAsset(t)

	// At 390px the whole document used to scroll sideways. The tables now scroll
	// inside their card instead of pushing the page wider.
	for _, marker := range []string{
		".vscroll table { min-width: 520px; }",
		"#page-subs table { min-width: 620px; }",
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("the narrow-screen table floor is gone: %q", marker)
		}
	}
	if !strings.Contains(html, "overflow-x: auto") {
		t.Error("the card no longer offers its own horizontal scroll")
	}
}

func TestWindowControlsSendStructuredCommands(t *testing.T) {
	html := webAsset(t)

	// The native side decodes a JSON object, and accepts it either raw or as a
	// JSON-encoded string. A page that went back to posting a bare word would
	// stop being understood, which is exactly what broke the title bar.
	requireOnce(t, html, `postMessage(JSON.stringify({ cmd: cmd }))`, "the structured window command")
	for _, cmd := range []string{`send("drag")`, `send("min")`, `send("max")`, `send("close")`} {
		if !strings.Contains(html, cmd) {
			t.Errorf("the title bar no longer sends %s", cmd)
		}
	}
}
