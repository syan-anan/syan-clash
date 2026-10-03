// Package yamlmin implements the small YAML subset this project needs: block
// mappings, block sequences, flow sequences and scalars.
//
// It is deliberately not a general YAML implementation — no anchors, aliases,
// tags, multi-document streams or block scalars — which keeps it auditable,
// dependency free, and enough both for emitting core configs and for reading
// imported Clash configurations.
package yamlmin

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// KV is one mapping entry.
type KV struct {
	K string
	V any
}

// Map is an insertion-ordered mapping, so generated configs stay readable and
// diffable.
type Map []KV

// Get returns the value stored under key.
func (m Map) Get(key string) (any, bool) {
	for _, e := range m {
		if e.K == key {
			return e.V, true
		}
	}
	return nil, false
}

// Set appends or replaces a key.
func (m Map) Set(key string, value any) Map {
	for i, e := range m {
		if e.K == key {
			m[i].V = value
			return m
		}
	}
	return append(m, KV{key, value})
}

var plainScalar = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./:@%+,#-]*$`)

// Emit renders a value tree as YAML. Supported inputs: Map, map[string]any,
// []any and the scalar types.
func Emit(v any) string {
	var b strings.Builder
	emitNode(&b, v, 0)
	return b.String()
}

func pad(level int) string { return strings.Repeat("  ", level) }

func emitNode(b *strings.Builder, v any, level int) {
	switch t := v.(type) {
	case Map:
		for _, e := range t {
			emitEntry(b, e.K, e.V, pad(level), level+1)
		}
	case map[string]any:
		for _, k := range sortedKeys(t) {
			emitEntry(b, k, t[k], pad(level), level+1)
		}
	case []any:
		for _, item := range t {
			emitSeqItem(b, item, level)
		}
	default:
		fmt.Fprintf(b, "%s%s\n", pad(level), scalarText(v))
	}
}

// emitEntry writes "prefix + key" and the value. child is the nesting level of
// any nested block, which keeps sequences aligned under their parent key.
func emitEntry(b *strings.Builder, key string, val any, prefix string, child int) {
	if isEmptyCollection(val) {
		fmt.Fprintf(b, "%s%s: %s\n", prefix, key, emptyText(val))
		return
	}
	switch val.(type) {
	case Map, map[string]any, []any:
		fmt.Fprintf(b, "%s%s:\n", prefix, key)
		emitNode(b, val, child)
	default:
		fmt.Fprintf(b, "%s%s: %s\n", prefix, key, scalarText(val))
	}
}

func emitSeqItem(b *strings.Builder, item any, level int) {
	first := pad(level) + "- "
	cont := pad(level) + "  "
	switch t := item.(type) {
	case Map:
		if len(t) == 0 {
			fmt.Fprintf(b, "%s{}\n", first)
			return
		}
		for i, e := range t {
			prefix := cont
			if i == 0 {
				prefix = first
			}
			// A sequence item's keys start two columns right of the dash, so
			// their nested blocks sit one level deeper than the sequence.
			emitEntry(b, e.K, e.V, prefix, level+2)
		}
	case map[string]any:
		if len(t) == 0 {
			fmt.Fprintf(b, "%s{}\n", first)
			return
		}
		for i, k := range sortedKeys(t) {
			prefix := cont
			if i == 0 {
				prefix = first
			}
			emitEntry(b, k, t[k], prefix, level+2)
		}
	case []any:
		if len(t) == 0 {
			fmt.Fprintf(b, "%s[]\n", first)
			return
		}
		fmt.Fprintf(b, "%s\n", pad(level)+"-")
		emitNode(b, t, level+1)
	default:
		fmt.Fprintf(b, "%s%s\n", first, scalarText(item))
	}
}

func isEmptyCollection(v any) bool {
	switch t := v.(type) {
	case Map:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	case []any:
		return len(t) == 0
	}
	return false
}

func emptyText(v any) string {
	if _, ok := v.([]any); ok {
		return "[]"
	}
	return "{}"
}

func scalarText(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	case string:
		return QuoteScalar(t)
	default:
		return QuoteScalar(fmt.Sprint(v))
	}
}

// QuoteScalar renders a string as YAML, quoting only when it would otherwise
// change meaning.
func QuoteScalar(s string) string {
	if s == "" {
		return `""`
	}
	if plainScalar.MatchString(s) && !ambiguousScalar(s) {
		return s
	}
	if !strings.ContainsAny(s, "\"\\\n\r\t") {
		return `"` + s + `"`
	}
	return strconv.Quote(s)
}

// ambiguousScalar reports strings that look like another type and therefore
// need quoting to stay strings.
func ambiguousScalar(s string) bool {
	switch strings.ToLower(s) {
	case "true", "false", "null", "~", "yes", "no", "on", "off":
		return true
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return true
	}
	return false
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
