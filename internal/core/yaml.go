package core

import "vvpn/internal/yamlmin"

// The core emitters build their documents with the shared minimal YAML writer,
// so generated configs and the configuration importer agree on one subset.
//
// kv/omap are local types rather than aliases: unkeyed literals are idiomatic
// for this small ordered map, and vet only flags unkeyed literals of imported
// types.
type kv struct {
	K string
	V any
}

type omap []kv

func yamlEmit(v any) string { return yamlmin.Emit(toYAML(v)) }

func yamlString(s string) string { return yamlmin.QuoteScalar(s) }

// toYAML converts the local ordered map into the writer's types.
func toYAML(v any) any {
	switch t := v.(type) {
	case omap:
		out := make(yamlmin.Map, 0, len(t))
		for _, e := range t {
			out = append(out, yamlmin.KV{K: e.K, V: toYAML(e.V)})
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = toYAML(val)
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, item := range t {
			out = append(out, toYAML(item))
		}
		return out
	default:
		return v
	}
}
