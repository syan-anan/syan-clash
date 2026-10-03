package control

import (
	"encoding/json"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The console is translated at runtime: whole pieces of rendered text are looked
// up in web/i18n.en.json and replaced. Nothing in the type system ties the page
// to that file, so this test does.
//
// It harvests every Chinese string the page can put in front of a person - text
// nodes and the attributes a reader actually sees, both from the static markup
// and from the HTML the script builds - and fails on any that has no entry. A
// missing entry is not a crash: the page simply keeps the Chinese. That
// graceful failure is exactly why it needs a test rather than an eyeball.

var (
	blockPattern = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	stripPattern = regexp.MustCompile(`(?s)<script>.*?</script>|<style>.*?</style>|<!--.*?-->`)
	textPattern  = regexp.MustCompile(`>([^<>]+)<`)
	attrPattern  = regexp.MustCompile(`(?i)(?:placeholder|title|aria-label|alt)="([^"]*)"`)
	cjkPattern   = regexp.MustCompile(`[\p{Han}]`)
	spacePattern = regexp.MustCompile(`\s+`)
)

// i18nAttrs are the attributes a person reads. They have to be translated too;
// a page whose buttons are English but whose input hints are Chinese is not
// translated, it is half-translated.
var i18nAttrs = []string{"placeholder", "title", "aria-label", "alt"}

func visibleStrings(t *testing.T) []string {
	t.Helper()
	html := webAsset(t)
	found := map[string]bool{}

	harvest := func(fragment string) {
		for _, m := range textPattern.FindAllStringSubmatch(fragment, -1) {
			addVisible(found, m[1])
		}
		for _, m := range attrPattern.FindAllStringSubmatch(fragment, -1) {
			addVisible(found, m[1])
		}
	}

	harvest(stripPattern.ReplaceAllString(html, " "))

	for _, block := range blockPattern.FindAllStringSubmatch(html, -1) {
		for _, lit := range scanJSStrings(block[1]) {
			if !cjkPattern.MatchString(lit.val) {
				continue
			}
			// A literal that builds markup is a fragment; harvest the text it
			// will actually render.
			trimmed := strings.TrimSpace(lit.val)
			if strings.HasPrefix(trimmed, "<") && !strings.Contains(lit.val, "\n") {
				harvest(trimmed)
				continue
			}
			if strings.Contains(lit.val, "\n") {
				continue // a multi-line template literal is code, not a label
			}
			// Glued to a neighbour with +: this is one piece of a sentence the
			// page assembles at runtime. $rules owns those, not the dictionary.
			if lit.joined {
				continue
			}
			addVisible(found, lit.val)
		}
	}

	out := make([]string, 0, len(found))
	for s := range found {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func addVisible(set map[string]bool, raw string) {
	s := strings.TrimSpace(spacePattern.ReplaceAllString(raw, " "))
	if s == "" || !cjkPattern.MatchString(s) {
		return
	}
	set[s] = true
}

// scanJSStrings returns every string literal in a script block. It skips
// comments and regular expressions, because a regex like /[&<>"']/ would
// otherwise look like the start of a string and swallow the code after it.
// jsLiteral is one string literal plus whether the source joins it to
// something with +. A fragment like "还有 " is never rendered on its own,
// so demanding a dictionary entry for it would be demanding the wrong
// thing: the sentence it builds is what a reader sees, and $rules covers
// those.
type jsLiteral struct {
	val    string
	joined bool
}

func scanJSStrings(src string) []jsLiteral {
	var out []jsLiteral
	prevSignificant := func(i int) byte {
		for j := i - 1; j >= 0; j-- {
			switch src[j] {
			case ' ', '\t', '\n', '\r':
				continue
			}
			return src[j]
		}
		return 0
	}
	for i := 0; i < len(src); {
		c := src[i]
		if c == '/' && i+1 < len(src) && src[i+1] == '/' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(src) && src[i+1] == '*' {
			i += 2
			for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			i += 2
			continue
		}
		if c == '/' {
			switch prevSignificant(i) {
			case 0, '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '<', '>':
				i++
				for i < len(src) {
					if src[i] == '\\' {
						i += 2
						continue
					}
					if src[i] == '/' {
						i++
						break
					}
					if src[i] == '\n' {
						break
					}
					i++
				}
				continue
			}
			i++
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			quote := c
			j := i + 1
			var b strings.Builder
			for j < len(src) {
				if src[j] == '\\' {
					// Unescape the common sequences before the value reaches the
					// dictionary: the page renders a real newline, so a key that
					// still says backslash-n would never match what is on screen.
					if j+1 < len(src) {
						switch src[j+1] {
						case 'n':
							b.WriteByte('\n')
						case 't':
							b.WriteByte('\t')
						case 'r':
							b.WriteByte('\r')
						case '\\':
							b.WriteByte('\\')
						case '"':
							b.WriteByte('"')
						default:
							b.WriteByte(src[j])
							b.WriteByte(src[j+1])
						}
					}
					j += 2
					continue
				}
				if src[j] == quote {
					break
				}
				if quote != '`' && src[j] == '\n' {
					break
				}
				b.WriteByte(src[j])
				j++
			}
			out = append(out, jsLiteral{val: b.String(), joined: isJoined(src, i, j)})
			i = j + 1
			continue
		}
		i++
	}
	return out
}

// isJoined reports whether a literal at [start,end) is glued to its
// neighbours with +, which makes it a fragment rather than a label.
func isJoined(src string, start, end int) bool {
	before := byte(0)
	for j := start - 1; j >= 0; j-- {
		switch src[j] {
		case ' ', '\t', '\n', '\r':
			continue
		}
		before = src[j]
		break
	}
	after := byte(0)
	for j := end; j < len(src); j++ {
		switch src[j] {
		case ' ', '\t', '\n', '\r':
			continue
		}
		after = src[j]
		break
	}
	return before == '+' || after == '+'
}

func loadEnglishDict(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	raw, err := fs.ReadFile(webFS, "web/i18n.en.json")
	if err != nil {
		t.Fatalf("web/i18n.en.json is missing: %v", err)
	}
	dict := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &dict); err != nil {
		t.Fatalf("web/i18n.en.json is not a JSON object: %v", err)
	}
	return dict
}

// compiledRules turns $rules into matchers. A sentence the page assembles at
// runtime has no whole-text key, so a rule that matches it counts as covered -
// otherwise the coverage test would demand dictionary entries for strings that
// by construction can never be a key.
func compiledRules(t *testing.T, dict map[string]json.RawMessage) []*regexp.Regexp {
	t.Helper()
	raw, ok := dict["$rules"]
	if !ok {
		return nil
	}
	var rules [][]string
	if err := json.Unmarshal(raw, &rules); err != nil {
		t.Fatalf("$rules is not a list of [pattern, replacement] pairs: %v", err)
	}
	out := make([]*regexp.Regexp, 0, len(rules))
	for i, r := range rules {
		if len(r) != 2 {
			t.Errorf("$rules[%d] has %d elements, want 2", i, len(r))
			continue
		}
		re, err := regexp.Compile(r[0])
		if err != nil {
			t.Errorf("$rules[%d] pattern %q does not compile: %v", i, r[0], err)
			continue
		}
		out = append(out, re)
	}
	return out
}

func TestEveryVisibleStringHasAnEnglishEntry(t *testing.T) {
	dict := loadEnglishDict(t)
	rules := compiledRules(t, dict)
	visible := visibleStrings(t)
	covered := func(s string) bool {
		if _, ok := dict[s]; ok {
			return true
		}
		for _, re := range rules {
			if re.MatchString(s) {
				return true
			}
		}
		return false
	}
	if len(visible) < 500 {
		t.Fatalf("only %d visible strings harvested; the extraction is probably broken", len(visible))
	}

	var missing []string
	for _, s := range visible {
		if !covered(s) {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		sort.Slice(missing, func(i, j int) bool { return len(missing[i]) < len(missing[j]) })
		head := missing
		if len(head) > 40 && os.Getenv("SYANV_I18N_DUMP") == "" {
			head = head[:40]
		}
		t.Errorf("%d of %d visible strings have no English entry:\n  %s",
			len(missing), len(visible), strings.Join(head, "\n  "))
	}
}

// A dictionary that has drifted - entries for text the page no longer shows -
// is dead weight that hides real gaps during review.
func TestEnglishDictionaryHasNoDeadEntries(t *testing.T) {
	dict := loadEnglishDict(t)
	visible := map[string]bool{}
	for _, s := range visibleStrings(t) {
		visible[s] = true
	}
	var dead []string
	for key := range dict {
		if key == "$rules" || key == "$comment" {
			continue
		}
		if !visible[key] {
			dead = append(dead, key)
		}
	}
	if len(dead) > 0 {
		sort.Strings(dead)
		if len(dead) > 40 && os.Getenv("SYANV_I18N_DUMP") == "" {
			dead = dead[:40]
		}
		t.Errorf("%d dictionary entries match nothing the page shows, e.g.:\n  %s",
			len(dead), strings.Join(dead, "\n  "))
	}
}

// The rules cover the sentences the page assembles at runtime, which no
// whole-text dictionary can match.
func TestEnglishDictionaryRulesCompile(t *testing.T) {
	dict := loadEnglishDict(t)
	if _, ok := dict["$rules"]; !ok {
		t.Fatal("the dictionary has no $rules; concatenated sentences would stay Chinese")
	}
	if got := compiledRules(t, dict); len(got) == 0 {
		t.Fatal("$rules produced no usable patterns")
	}
}

// A key whose value is the key itself is a translation that was never written -
// the entry looks present, the coverage test is satisfied, and the page still
// shows Chinese. The only legitimate case is a language's own name, which stays
// in its own language in a language picker.
func TestNoEntryIsLeftUntranslated(t *testing.T) {
	dict := loadEnglishDict(t)
	allowed := map[string]bool{"简体中文": true}
	var same []string
	for key, raw := range dict {
		if strings.HasPrefix(key, "$") {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Errorf("entry %q is not a string: %v", key, err)
			continue
		}
		if value == key && !allowed[key] {
			same = append(same, key)
		}
	}
	if len(same) > 0 {
		sort.Strings(same)
		t.Errorf("%d entries were never actually translated:\n  %s", len(same), strings.Join(same, "\n  "))
	}
}
