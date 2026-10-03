package control

import (
	"strings"
	"testing"
)

// The five console defects fixed on 2026-10-03 each had one structural cause,
// and every one of them came back at least once because the structure was only
// held in place by hand. These tests pin the structure - not the pixels - so a
// later edit that re-buries the toast column, rebuilds the node table on every
// poll, drops the subscription editor rebind or stops wiring the title bar
// fails here instead of in front of the person using the client.

// cssBlock returns the body of the first "selector { ... }" block, with nested
// braces balanced. Selectors are matched literally, including their leading
// whitespace-free form, so callers pass exactly what the stylesheet writes.
func cssBlock(t *testing.T, html, selector string) string {
	t.Helper()
	i := strings.Index(html, selector)
	if i < 0 {
		t.Fatalf("the console stylesheet has no %q rule", selector)
	}
	open := strings.IndexByte(html[i:], '{')
	if open < 0 {
		t.Fatalf("%q has no opening brace", selector)
	}
	depth := 0
	for j := i + open; j < len(html); j++ {
		switch html[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return html[i+open+1 : j]
			}
		}
	}
	t.Fatalf("the %q block is never closed", selector)
	return ""
}

// jsFunction returns the whole body of "function name(...) { ... }" from the
// console script, with nested braces balanced.
func jsFunction(t *testing.T, script, name string) string {
	t.Helper()
	marker := "function " + name + "("
	i := strings.Index(script, marker)
	if i < 0 {
		t.Fatalf("the console script has no function %s", name)
	}
	open := strings.IndexByte(script[i:], '{')
	if open < 0 {
		t.Fatalf("function %s has no body", name)
	}
	depth := 0
	for j := i + open; j < len(script); j++ {
		switch script[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return script[i : j+1]
			}
		}
	}
	t.Fatalf("function %s is never closed", name)
	return ""
}

// Defect 2: a toast pinned to the top edge landed on the top bar and on the
// page title underneath it. The column is anchored to the bottom now.
func TestToastColumnIsAnchoredToTheBottomEdge(t *testing.T) {
	html := webAsset(t)
	body := cssBlock(t, html, ".toasts")
	if !strings.Contains(body, "position: fixed") {
		t.Errorf("the toast column is no longer fixed: %q", body)
	}
	if !strings.Contains(body, "bottom:") {
		t.Errorf("the toast column has no bottom anchor: %q", body)
	}
	if strings.Contains(body, "top:") {
		t.Errorf("the toast column is anchored to the top again: %q", body)
	}
	// Inside the frameless client the title bar is drawn by the page, so the
	// bottom anchor has to survive that override as well.
	frameless := cssBlock(t, html, "html.win-frameless .toasts")
	if !strings.Contains(frameless, "top: auto") {
		t.Errorf("the frameless override does not clear the top anchor: %q", frameless)
	}
	if !strings.Contains(frameless, "bottom:") {
		t.Errorf("the frameless override has no bottom anchor: %q", frameless)
	}
}

// Defect 3: the four subscription buttons took their width from their label,
// so "二维码" was wider than "更新" and the row looked ragged. One minimum
// width and centred content makes every button the same shape.
func TestSubscriptionActionButtonsShareOneWidth(t *testing.T) {
	html := webAsset(t)
	row := cssBlock(t, html, ".sub-actions {")
	if !strings.Contains(row, "inline-flex") {
		t.Errorf(".sub-actions no longer lays the buttons out in one row: %q", row)
	}
	btn := cssBlock(t, html, ".sub-actions .btn")
	if !strings.Contains(btn, "min-width: 64px") {
		t.Errorf("the subscription buttons lost their shared minimum width: %q", btn)
	}
	if !strings.Contains(btn, "justify-content: center") {
		t.Errorf("the subscription button labels are no longer centred: %q", btn)
	}
}

// Defect 5: the node table sat below every other card on the page, so the page
// opened on the "add a node" form and the list was nowhere in sight.
func TestNodeTableIsRenderedBeforeTheNodeCards(t *testing.T) {
	html := webAsset(t)
	table := strings.Index(html, `id="nodes-body"`)
	card := strings.Index(html, `id="node-add"`)
	if table < 0 || card < 0 {
		t.Fatalf("the console no longer has both the node table (%d) and the add-node card (%d)", table, card)
	}
	if table > card {
		t.Error("the node table is placed after the add-node card again")
	}
	script := longestScript(t, html)
	fn := jsFunction(t, script, "refreshProxies")
	shell := strings.Index(fn, "nodeShellHTML()")
	groups := strings.Index(fn, "<h3>代理组</h3>")
	if shell < 0 || groups < 0 || shell > groups {
		t.Errorf("refreshProxies builds the proxy-group card before the node table (shell=%d groups=%d)", shell, groups)
	}
}

// Defect 4: the node table was rebuilt from scratch on every poll, which threw
// away the row (and the button) the person was pointing at, and made the table
// flicker. The table is now rebuilt only when its structure changes, and the
// highlight is repainted in place.
func TestNodeTableRefreshesInPlace(t *testing.T) {
	html := webAsset(t)
	script := longestScript(t, html)
	fn := jsFunction(t, script, "refreshProxies")
	for _, marker := range []string{
		"structSig",
		"syncGroupSelects(groups)",
		"paintNodeSelection()",
		"nodeList.rows.onclick = onNodeRowClick",
	} {
		if !strings.Contains(fn, marker) {
			t.Errorf("refreshProxies no longer keeps the table stable: missing %s", marker)
		}
	}
	if !strings.Contains(script, "const structSig") {
		t.Error("the structural signature that decides whether to rebuild the table is gone")
	}
	// Switching a node must not bump the version: a rebuild would drop the very
	// row the click came from. The buttons are released by hand instead.
	sw := jsFunction(t, script, "switchNode")
	if strings.Contains(sw, "nodeList.version++") {
		t.Error("switchNode bumps the table version again, which rebuilds the clicked row")
	}
	if !strings.Contains(sw, "button.disabled = false") {
		t.Error("switchNode no longer releases the switch buttons, so a failed switch leaves them dead")
	}
}

// The subscription editor row is created by the same render that rebuilds the
// table, so the editor has to be rewired after every render. Wiring it once at
// parse time left every 编辑 button dead.
func TestSubscriptionEditorsAreRewiredAfterEveryRender(t *testing.T) {
	html := webAsset(t)
	script := longestScript(t, html)
	if !strings.Contains(script, "function bindSubsEditors(") {
		t.Fatal("bindSubsEditors is gone; the subscription editor has no wiring step")
	}
	if n := strings.Count(script, "bindSubsEditors()"); n < 2 {
		t.Errorf("bindSubsEditors() is called %d time(s); it has to run at load and after every render", n)
	}
	fn := jsFunction(t, script, "loadSubscriptions")
	if !strings.Contains(fn, "bindSubsEditors()") {
		t.Error("loadSubscriptions renders the table without rewiring the per-row editor")
	}
	if !strings.Contains(fn, "if (!setHTML($(\"#subs-body\"), html)) return;") {
		t.Error("loadSubscriptions no longer stops when the table markup did not change")
	}
}

// The 390 px report: the page scrolled sideways because the wide tables pushed
// the document wider than the window. Each table scrolls inside its own card.
func TestNarrowScreensScrollTablesInsideTheirCard(t *testing.T) {
	html := webAsset(t)
	media := cssBlock(t, html, "@media (max-width: 980px)")
	for _, want := range []string{
		".vscroll { overflow-x: auto; }",
		".vscroll table { min-width: 520px; }",
		"#page-subs .card { overflow-x: auto; }",
		"#page-subs table { min-width: 620px; }",
		"flex-wrap: wrap",
	} {
		if !strings.Contains(media, want) {
			t.Errorf("the narrow-screen block no longer contains %q", want)
		}
	}
}

// Defect 1: the title bar sends one command per control, and a drag only starts
// on the bar itself - not on the minimise/maximise/close buttons.
func TestFramelessTitleBarSendsOneCommandPerControl(t *testing.T) {
	html := webAsset(t)
	for _, id := range []string{`id="wb-min"`, `id="wb-max"`, `id="wb-close"`, `id="winbar"`, `id="wb-grip"`} {
		if !strings.Contains(html, id) {
			t.Errorf("the frameless title bar is missing %s", id)
		}
	}
	script := longestScript(t, html)
	for _, cmd := range []string{`send("drag")`, `send("min")`, `send("max")`, `send("close")`} {
		if !strings.Contains(script, cmd) {
			t.Errorf("the title bar no longer emits %s", cmd)
		}
	}
	if !strings.Contains(script, `closest(".wb-btn")`) {
		t.Error("the title bar drag no longer skips the window buttons")
	}
	// The message is a JSON document the native side decodes; the command name
	// must stay the only thing that selects an action.
	if !strings.Contains(script, `JSON.stringify({ cmd: cmd })`) {
		t.Error("the title bar no longer sends a structured command object")
	}
}
