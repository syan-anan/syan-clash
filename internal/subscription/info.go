package subscription

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Info is the usage metadata subscription providers publish in their response
// headers: how much traffic has been used, the quota, and when it expires.
type Info struct {
	Upload      int64  `json:"upload"`
	Download    int64  `json:"download"`
	Total       int64  `json:"total"`
	Expire      int64  `json:"expire"`
	UpdateEvery int64  `json:"update_interval_hours,omitempty"`
	Filename    string `json:"filename,omitempty"`
}

// Used is the traffic consumed so far.
func (i Info) Used() int64 { return i.Upload + i.Download }

// Remaining is the traffic left; it is negative when the provider reports an
// unlimited quota (total = 0).
func (i Info) Remaining() int64 {
	if i.Total <= 0 {
		return -1
	}
	return i.Total - i.Used()
}

// ExpiresAt is the expiry time, or the zero time when unset.
func (i Info) ExpiresAt() time.Time {
	if i.Expire <= 0 {
		return time.Time{}
	}
	return time.Unix(i.Expire, 0)
}

// ParseUserInfo reads the "subscription-userinfo" header. Providers format it
// as "upload=0; download=1024; total=107374182400; expire=1893456000", but
// separators vary, so parsing is deliberately forgiving.
func ParseUserInfo(header string) Info {
	var info Info
	header = strings.TrimSpace(header)
	if header == "" {
		return info
	}
	for _, field := range strings.FieldsFunc(header, func(r rune) bool { return r == ';' || r == ',' }) {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "upload":
			info.Upload = n
		case "download":
			info.Download = n
		case "total":
			info.Total = n
		case "expire":
			info.Expire = n
		}
	}
	return info
}

// ParseUpdateInterval reads the "profile-update-interval" header, which holds
// the provider's recommended refresh period in hours.
func ParseUpdateInterval(header string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(header), 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// FilenameFromDisposition extracts a suggested name from a
// "content-disposition: attachment; filename=xxx" header, including the
// RFC 5987 "filename*=UTF-8”..." form that providers use for non-ASCII names.
func FilenameFromDisposition(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	var plain, extended string
	for _, field := range strings.Split(header, ";") {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch {
		case strings.EqualFold(strings.TrimSpace(key), "filename"):
			plain = value
		case strings.EqualFold(strings.TrimSpace(key), "filename*"):
			extended = decodeExtendedFilename(value)
		}
	}
	name := extended
	if name == "" {
		name = plain
	}
	for _, suffix := range []string{".yaml", ".yml", ".txt", ".json", ".conf"} {
		name = strings.TrimSuffix(name, suffix)
	}
	return strings.TrimSpace(name)
}

// decodeExtendedFilename reads the "UTF-8”percent-encoded" payload of the
// filename* parameter. It falls back to the raw value when the shape is
// unexpected, so a provider quirk cannot lose the name entirely.
func decodeExtendedFilename(value string) string {
	_, rest, ok := strings.Cut(value, "''")
	if !ok {
		return value
	}
	if decoded, err := url.QueryUnescape(rest); err == nil {
		return decoded
	}
	return rest
}
