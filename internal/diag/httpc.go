package diag

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// UAProbe identifies the client to the public endpoints used by the probe
// panels. It is deliberately not a browser string: those endpoints are asked
// for facts, not for pages.
const UAProbe = "syan-clash/0.1 (+diagnostics)"

// UABrowser is presented to the services in the unlock sweep. Some of them
// answer differently to an unknown agent, and a plain 403 there would be read
// as "blocked" when the region is in fact fine.
const UABrowser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

// clientOpts tweaks one probe client. The defaults are the cautious ones:
// follow no redirects, stop reading after 128KB, no keep-alive.
type clientOpts struct {
	ua           string
	maxRedirects int
	maxBytes     int64
	noTimeout    bool
	tlsSkip      bool
}

// newClient builds an HTTP client that leaves the machine through the given
// path. Every client owns its transport, so a cancelled job cannot leave a
// half-open pooled connection behind for the next probe to trip over.
func (p *Prober) newClient(via Via, opts clientOpts) *http.Client {
	d := &dialer{
		via:          via,
		proxyAddr:    p.proxyAddr,
		fallbackAddr: p.fallbackAddr,
		timeout:      p.timeout(),
		userAgent:    UAProbe,
	}
	tr := &http.Transport{
		DialContext:           d.dial,
		DisableKeepAlives:     true,
		MaxIdleConns:          0,
		MaxIdleConnsPerHost:   0,
		TLSHandshakeTimeout:   p.timeout(),
		ResponseHeaderTimeout: p.timeout(),
		ExpectContinueTimeout: 2 * time.Second,
		IdleConnTimeout:       10 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if opts.tlsSkip {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	redirects := 0
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via_ []*http.Request) error {
			if redirects >= opts.maxRedirects {
				return http.ErrUseLastResponse
			}
			redirects++
			return nil
		},
		Timeout: 0, // the per-request context owns the deadline
	}
}

// do runs one probe request. It takes a slot from the concurrency gate, applies
// the caller's deadline, and returns the body already limited so one huge
// answer cannot balloon the client's memory.
func (p *Prober) do(ctx context.Context, via Via, req *http.Request, opts clientOpts) (*http.Response, []byte, error) {
	gate := p.gate()
	if err := gate.acquire(ctx); err != nil {
		return nil, nil, err
	}
	defer gate.release()

	client := p.newClient(via, opts)
	req = req.WithContext(ctx)
	if opts.ua == "" {
		opts.ua = UAProbe
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", opts.ua)
	}
	if req.Header.Get("Cache-Control") == "" {
		req.Header.Set("Cache-Control", "no-cache")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	limit := opts.maxBytes
	if limit <= 0 {
		limit = 128 << 10
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return resp, nil, err
	}
	return resp, body, nil
}

// getJSON is the one-line form used by every IP source.
func (p *Prober) getJSON(ctx context.Context, via Via, rawURL string, out any) error {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, body, err := p.do(ctx, via, req, clientOpts{})
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &statusError{URL: rawURL, Code: resp.StatusCode}
	}
	return decodeJSON(body, out)
}

// getText returns a small text body (the Cloudflare trace, for instance).
func (p *Prober) getText(ctx context.Context, via Via, rawURL, ua string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, body, err := p.do(ctx, via, req, clientOpts{ua: ua})
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", &statusError{URL: rawURL, Code: resp.StatusCode}
	}
	return string(body), nil
}

// statusError carries the HTTP status so callers can classify a cell as
// "blocked" rather than "broken".
type statusError struct {
	URL  string
	Code int
}

func (e *statusError) Error() string {
	return "HTTP " + itoa(e.Code) + " from " + e.URL
}

// statusOf extracts the status code from an error produced by this package.
func statusOf(err error) int {
	if se, ok := err.(*statusError); ok {
		return se.Code
	}
	return 0
}

// errKind classifies a probe failure into the small vocabulary the UI shows.
func errKind(err error) string {
	if err == nil {
		return ""
	}
	if se, ok := err.(*statusError); ok {
		return "status:" + itoa(se.Code)
	}
	if err == context.DeadlineExceeded || err == context.Canceled {
		return "timeout"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "context deadline exceeded"):
		return "timeout"
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "refused"):
		return "refused"
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "not found"):
		return "dns"
	case strings.Contains(msg, "tls"), strings.Contains(msg, "certificate"):
		return "tls"
	}
	return "error"
}

// splitHostPort is net.SplitHostPort with a clearer failure for the panels.
func splitHostPort(addr string) (string, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", err
	}
	return host, port, nil
}
