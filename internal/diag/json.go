package diag

import (
	"encoding/json"
	"strconv"
)

// itoa avoids pulling strconv into every file for one call.
func itoa(n int) string { return strconv.Itoa(n) }

// decodeJSON is json.Unmarshal with the error wrapped once, here, so the
// callers can just return it.
func decodeJSON(raw []byte, out any) error { return json.Unmarshal(raw, out) }

// firstString returns the first non-empty value: the IP sources disagree about
// which field carries which fact, and an empty string must never overwrite a
// fact another source already established.
func firstString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
