// Package clashapi speaks the Clash-compatible control API that both mihomo
// and sing-box expose, so the client has one set of calls regardless of which
// core is running underneath.
package clashapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client talks to one core's control API.
type Client struct {
	base   string
	secret string
	http   *http.Client
}

// New creates a client for the given host:port control address.
func New(addr, secret string) *Client {
	return &Client{
		base:   "http://" + strings.TrimSuffix(strings.TrimPrefix(addr, "http://"), "/"),
		secret: secret,
		http:   &http.Client{Timeout: 15 * time.Second},
	}
}

// Addr is the control address this client targets.
func (c *Client) Addr() string { return c.base }

// Version is the core's version banner.
type Version struct {
	Version string `json:"version"`
	Meta    bool   `json:"meta"`
	Premium bool   `json:"premium"`
}

// Delay is one latency sample.
type Delay struct {
	Time  time.Time `json:"time"`
	Delay int       `json:"delay"`
}

// Proxy is one entry of the core's proxy table.
type Proxy struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Now     string   `json:"now,omitempty"`
	All     []string `json:"all,omitempty"`
	History []Delay  `json:"history,omitempty"`
	UDP     bool     `json:"udp,omitempty"`
	Alive   bool     `json:"alive,omitempty"`
}

// LastDelay is the most recent latency sample, or 0 when never tested.
func (p Proxy) LastDelay() int {
	if len(p.History) == 0 {
		return 0
	}
	return p.History[len(p.History)-1].Delay
}

// Connection is one entry of the core's connection table.
type Connection struct {
	ID          string   `json:"id"`
	Upload      int64    `json:"upload"`
	Download    int64    `json:"download"`
	Start       string   `json:"start"`
	Chains      []string `json:"chains"`
	Rule        string   `json:"rule"`
	RulePayload string   `json:"rulePayload"`
	Metadata    struct {
		Network         string `json:"network"`
		Type            string `json:"type"`
		SourceIP        string `json:"sourceIP"`
		DestinationIP   string `json:"destinationIP"`
		SourcePort      string `json:"sourcePort"`
		DestinationPort string `json:"destinationPort"`
		Host            string `json:"host"`
		ProcessPath     string `json:"processPath"`
	} `json:"metadata"`
}

// Destination is the human readable target of a connection.
func (c Connection) Destination() string {
	host := c.Metadata.Host
	if host == "" {
		host = c.Metadata.DestinationIP
	}
	if host == "" {
		return ""
	}
	if c.Metadata.DestinationPort == "" {
		return host
	}
	return host + ":" + c.Metadata.DestinationPort
}

// Connections is the connection table snapshot.
type Connections struct {
	DownloadTotal int64        `json:"downloadTotal"`
	UploadTotal   int64        `json:"uploadTotal"`
	Memory        int64        `json:"memory"`
	Connections   []Connection `json:"connections"`
}

// Traffic is one traffic sample in bytes per second.
type Traffic struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

func (c *Client) request(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	return req, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	req, err := c.request(ctx, method, path, body)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("clash api %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("clash api %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(detail)))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out); err != nil {
		return fmt.Errorf("clash api %s %s: decode: %w", method, path, err)
	}
	return nil
}

// Version fetches the core's version banner.
func (c *Client) Version(ctx context.Context) (Version, error) {
	var out Version
	err := c.do(ctx, http.MethodGet, "/version", nil, &out)
	return out, err
}

// Proxies fetches the whole proxy table (nodes and groups).
func (c *Client) Proxies(ctx context.Context) (map[string]Proxy, error) {
	var out struct {
		Proxies map[string]Proxy `json:"proxies"`
	}
	if err := c.do(ctx, http.MethodGet, "/proxies", nil, &out); err != nil {
		return nil, err
	}
	return out.Proxies, nil
}

// Select switches the member of a selector group.
func (c *Client) Select(ctx context.Context, group, name string) error {
	return c.do(ctx, http.MethodPut, "/proxies/"+url.PathEscape(group), map[string]string{"name": name}, nil)
}

// Mode reads the core's routing mode. mihomo answers rule/global/direct;
// sing-box answers its own mode string.
func (c *Client) Mode(ctx context.Context) (string, error) {
	var out struct {
		Mode string `json:"mode"`
	}
	if err := c.do(ctx, http.MethodGet, "/configs", nil, &out); err != nil {
		return "", err
	}
	return out.Mode, nil
}

// SetMode switches the core's routing mode through PATCH /configs.
func (c *Client) SetMode(ctx context.Context, mode string) error {
	return c.do(ctx, http.MethodPatch, "/configs", map[string]string{"mode": mode}, nil)
}

// Delay measures the latency of one proxy or of every member of a group.
// The returned map is keyed by proxy name.
func (c *Client) Delay(ctx context.Context, name, testURL string, timeoutMS int) (map[string]int, error) {
	if testURL == "" {
		testURL = "http://www.gstatic.com/generate_204"
	}
	if timeoutMS <= 0 {
		timeoutMS = 5000
	}
	path := "/proxies/" + url.PathEscape(name) + "/delay?url=" + url.QueryEscape(testURL) +
		"&timeout=" + strconv.Itoa(timeoutMS)
	var single struct {
		Delay int `json:"delay"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &single); err == nil {
		return map[string]int{name: single.Delay}, nil
	}
	// Group delay answers with a map; retry with the map shape so a group works
	// through the same call.
	var group map[string]int
	if err := c.do(ctx, http.MethodGet, path, nil, &group); err != nil {
		return nil, err
	}
	return group, nil
}

// groupDelayTimeout is the budget for one whole-group measurement. The core
// fans the members out itself, but a large group with several dead nodes can
// still take a while, and the short timeout the single-proxy calls use would
// cut it off half way.
const groupDelayTimeout = 3 * time.Minute

// GroupDelay measures every member of a group in one call. The core runs the
// members in parallel and answers with a name -> delay map, which is both
// faster and more complete than walking the members one request at a time.
// Cores that predate the endpoint answer 404 and the caller falls back to the
// walk.
func (c *Client) GroupDelay(ctx context.Context, name, testURL string, timeoutMS int) (map[string]int, error) {
	if testURL == "" {
		testURL = "http://www.gstatic.com/generate_204"
	}
	if timeoutMS <= 0 {
		timeoutMS = 5000
	}
	path := "/group/" + url.PathEscape(name) + "/delay?url=" + url.QueryEscape(testURL) +
		"&timeout=" + strconv.Itoa(timeoutMS)
	req, err := c.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	httpc := *c.http
	httpc.Timeout = groupDelayTimeout
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clash api group delay %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("clash api group delay %s: %s: %s", name, resp.Status, strings.TrimSpace(string(detail)))
	}
	var out map[string]int
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("clash api group delay %s: decode: %w", name, err)
	}
	return out, nil
}

// Connections fetches the core's connection table.
func (c *Client) Connections(ctx context.Context) (Connections, error) {
	var out Connections
	err := c.do(ctx, http.MethodGet, "/connections", nil, &out)
	return out, err
}

// CloseConnection terminates one connection by ID.
func (c *Client) CloseConnection(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/connections/"+url.PathEscape(id), nil, nil)
}

// CloseAllConnections terminates every tracked connection.
func (c *Client) CloseAllConnections(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "/connections", nil, nil)
}

// Traffic reads a single traffic sample. The endpoint is a stream, so the
// request is cancelled as soon as the first object is decoded.
func (c *Client) Traffic(ctx context.Context) (Traffic, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := c.request(ctx, http.MethodGet, "/traffic", nil)
	if err != nil {
		return Traffic{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Traffic{}, fmt.Errorf("clash api traffic: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Traffic{}, fmt.Errorf("clash api traffic: %s", resp.Status)
	}
	var out Traffic
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Traffic{}, fmt.Errorf("clash api traffic: decode: %w", err)
	}
	return out, nil
}

// RuleProviderStatus is what the core reports about one rule set it fetched
// itself: how many entries it ended up with and when it last refreshed them.
// Only a core that actually downloads the set can answer this, which is why an
// inline set - one the client keeps in its own configuration - has no
// counterpart here.
type RuleProviderStatus struct {
	RuleCount int    `json:"ruleCount"`
	UpdatedAt string `json:"updatedAt"`
	Behavior  string `json:"behavior"`
	Vehicle   string `json:"vehicleType"`
}

// RuleProviders lists the rule sets the core has loaded, keyed by name. A core
// that was started without any rule providers answers with an empty map rather
// than an error, so the console can show the list either way.
//
// mihomo wraps the report - the body is {"providers":{"<name>":{...}}} - and
// decoding it straight into the map keyed by name produced exactly one entry
// called "providers" with nothing in it, which turned every real set into
// "unknown". Both shapes are accepted here: the wrapper is the core's business
// and a console must not go blind because it changed.
func (c *Client) RuleProviders(ctx context.Context) (map[string]RuleProviderStatus, error) {
	var fields map[string]json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/providers/rules", nil, &fields); err != nil {
		return nil, err
	}
	out := map[string]RuleProviderStatus{}
	if raw, ok := fields["providers"]; ok {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("clash api /providers/rules: decode providers: %w", err)
		}
		return out, nil
	}
	for name, raw := range fields {
		var st RuleProviderStatus
		if err := json.Unmarshal(raw, &st); err != nil {
			continue
		}
		out[name] = st
	}
	return out, nil
}
