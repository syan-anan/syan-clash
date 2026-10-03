package yamlmin

import (
	"fmt"
	"strconv"
	"strings"
)

type sourceLine struct {
	num    int
	indent int
	text   string
}

type parser struct {
	lines []sourceLine
	pos   int
}

// Parse decodes a YAML document into Map / []any / scalars.
func Parse(data []byte) (any, error) { return ParseString(string(data)) }

// ParseString decodes a YAML document into Map / []any / scalars.
func ParseString(s string) (any, error) {
	p := &parser{lines: splitLines(s)}
	if len(p.lines) == 0 {
		return Map{}, nil
	}
	v, err := p.parseBlock(p.lines[0].indent)
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.lines) {
		return nil, fmt.Errorf("yaml: line %d: unexpected content %q", p.lines[p.pos].num, p.lines[p.pos].text)
	}
	return v, nil
}

func splitLines(s string) []sourceLine {
	var out []sourceLine
	for i, raw := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		raw = strings.TrimRight(raw, " \t")
		if strings.TrimSpace(raw) == "" {
			continue
		}
		indent := 0
		for indent < len(raw) && raw[indent] == ' ' {
			indent++
		}
		text := raw[indent:]
		if strings.HasPrefix(text, "#") || text == "---" {
			continue
		}
		out = append(out, sourceLine{num: i + 1, indent: indent, text: text})
	}
	return out
}

func (p *parser) parseBlock(minIndent int) (any, error) {
	if p.pos >= len(p.lines) {
		return nil, nil
	}
	ln := p.lines[p.pos]
	if ln.indent < minIndent {
		return nil, nil
	}
	if isSeqItem(ln.text) {
		return p.parseSequence(ln.indent)
	}
	return p.parseMapping(ln.indent)
}

func (p *parser) parseMapping(indent int) (Map, error) {
	m := Map{}
	for p.pos < len(p.lines) {
		ln := p.lines[p.pos]
		if ln.indent < indent {
			break
		}
		if ln.indent > indent {
			return nil, fmt.Errorf("yaml: line %d: unexpected indentation", ln.num)
		}
		if isSeqItem(ln.text) {
			break
		}
		key, rest, ok := splitKey(ln.text)
		if !ok {
			return nil, fmt.Errorf("yaml: line %d: expected 'key: value', got %q", ln.num, ln.text)
		}
		p.pos++
		val, err := p.parseValue(rest, indent, ln.num)
		if err != nil {
			return nil, err
		}
		m = m.Set(key, val)
	}
	return m, nil
}

func (p *parser) parseSequence(indent int) ([]any, error) {
	out := []any{}
	for p.pos < len(p.lines) {
		ln := p.lines[p.pos]
		if ln.indent != indent || !isSeqItem(ln.text) {
			break
		}
		rest := strings.TrimSpace(strings.TrimPrefix(ln.text, "-"))
		p.pos++
		if rest == "" {
			val, err := p.parseBlock(indent + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, val)
			continue
		}
		if strings.HasPrefix(rest, "{") || strings.HasPrefix(rest, "[") {
			// "- { ... }" / "- [ ... ]": the item is one flow collection, not
			// the start of a block mapping. Clash exports write their proxy
			// tables exactly this way ("- { name: x, type: ss, ... }"), and
			// parsing it as a mapping would bury every field behind a bogus
			// "{ name" key, silently dropping the whole proxy list.
			val, err := parseScalarOrFlow(rest)
			if err != nil {
				return nil, err
			}
			out = append(out, val)
			continue
		}
		if key, value, ok := splitKey(rest); ok {
			// "- key: value" starts a mapping item; its keys sit two columns
			// right of the dash, so nested blocks must be deeper than that.
			val, err := p.parseValue(value, indent+2, ln.num)
			if err != nil {
				return nil, err
			}
			item := Map{}.Set(key, val)
			if p.pos < len(p.lines) && p.lines[p.pos].indent > indent {
				more, err := p.parseMapping(p.lines[p.pos].indent)
				if err != nil {
					return nil, err
				}
				for _, e := range more {
					item = item.Set(e.K, e.V)
				}
			}
			out = append(out, item)
			continue
		}
		out = append(out, parseScalar(rest))
	}
	return out, nil
}

// parseValue handles what follows "key:". keyIndent is the column the key
// starts at, used to decide whether the following lines are a nested block.
func (p *parser) parseValue(rest string, keyIndent, lineNum int) (any, error) {
	if rest == "" {
		if p.pos < len(p.lines) && p.lines[p.pos].indent > keyIndent {
			return p.parseBlock(p.lines[p.pos].indent)
		}
		return nil, nil
	}
	if strings.HasPrefix(rest, "|") || strings.HasPrefix(rest, ">") {
		return nil, fmt.Errorf("yaml: line %d: block scalars are not supported", lineNum)
	}
	return parseScalarOrFlow(rest)
}

func isSeqItem(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

// splitKey splits "key: value" at the first structural colon.
func splitKey(s string) (string, string, bool) {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == ':' && !inSingle && !inDouble:
			if i+1 == len(s) || s[i+1] == ' ' {
				key := unquoteKey(strings.TrimSpace(s[:i]))
				if key == "" {
					return "", "", false
				}
				return key, strings.TrimSpace(s[i+1:]), true
			}
		}
	}
	return "", "", false
}

func unquoteKey(s string) string {
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			if v := parseScalar(s); v != nil {
				return AsString(v)
			}
		}
	}
	return s
}

func parseScalarOrFlow(s string) (any, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "["):
		if !strings.HasSuffix(s, "]") {
			return nil, fmt.Errorf("yaml: unterminated flow sequence %q", s)
		}
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if inner == "" {
			return []any{}, nil
		}
		parts := splitFlow(inner)
		out := make([]any, 0, len(parts))
		for _, part := range parts {
			val, err := parseScalarOrFlow(part)
			if err != nil {
				return nil, err
			}
			out = append(out, val)
		}
		return out, nil
	case strings.HasPrefix(s, "{"):
		if !strings.HasSuffix(s, "}") {
			return nil, fmt.Errorf("yaml: unterminated flow mapping %q", s)
		}
		inner := strings.TrimSpace(s[1 : len(s)-1])
		m := Map{}
		if inner == "" {
			return m, nil
		}
		for _, part := range splitFlow(inner) {
			k, v, ok := splitKey(part)
			if !ok {
				return nil, fmt.Errorf("yaml: bad flow mapping entry %q", part)
			}
			val, err := parseScalarOrFlow(v)
			if err != nil {
				return nil, err
			}
			m = m.Set(k, val)
		}
		return m, nil
	default:
		return parseScalar(s), nil
	}
}

// splitFlow splits a flow collection body on top-level commas.
func splitFlow(s string) []string {
	var out []string
	depth := 0
	inSingle, inDouble := false, false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case inSingle || inDouble:
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, strings.TrimSpace(s[start:]))
	return out
}

func parseScalar(s string) any {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	switch s[0] {
	case '"':
		if v, err := strconv.Unquote(s); err == nil {
			return v
		}
		return strings.Trim(s, `"`)
	case '\'':
		if len(s) >= 2 && s[len(s)-1] == '\'' {
			return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
		}
		return strings.Trim(s, "'")
	}
	// A trailing comment only starts after whitespace in a plain scalar.
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	switch strings.ToLower(s) {
	case "null", "~":
		return nil
	case "true":
		return true
	case "false":
		return false
	}
	// Only convert numbers that round-trip exactly, so "007" and "1.19.31"
	// stay strings.
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && strconv.FormatInt(n, 10) == s {
		return n
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && strconv.FormatFloat(f, 'g', -1, 64) == s {
		return f
	}
	return s
}

// AsMap returns v as a Map when it is one.
func AsMap(v any) (Map, bool) {
	m, ok := v.(Map)
	return m, ok
}

// AsSeq returns v as a slice when it is one.
func AsSeq(v any) ([]any, bool) {
	s, ok := v.([]any)
	return s, ok
}

// AsString renders a scalar as a string.
func AsString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
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
	default:
		return fmt.Sprint(v)
	}
}

// AsInt renders a scalar as an int, returning 0 when it is not numeric.
func AsInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

// AsBool renders a scalar as a bool.
func AsBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true", "yes", "on", "1":
			return true
		}
		return false
	case int:
		return t != 0
	case int64:
		return t != 0
	default:
		return false
	}
}

// AsStrings renders a value as a string slice (scalar or sequence).
func AsStrings(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			out = append(out, AsString(item))
		}
		return out
	case nil:
		return nil
	default:
		if s := AsString(t); s != "" {
			return strings.Split(s, ",")
		}
		return nil
	}
}
