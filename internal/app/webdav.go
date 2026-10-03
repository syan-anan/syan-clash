package app

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"vvpn/internal/config"
)

// The WebDAV backup target (P1-11) is a deliberately small client: the four
// verbs a backup rotation needs, spoken over net/http with no third-party
// WebDAV library. That keeps go.mod at its single dependency and keeps every
// failure message something the user can act on.
//
// All remote work is headless: the client builds requests itself and never
// inherits the environment proxy, so a backup cannot be silently sent through
// whatever HTTP_PROXY another program left behind.

// ErrWebDAVNotConfigured is returned when the feature is asked to do something
// without a URL. The control layer maps it to a 400 carrying the same text.
var ErrWebDAVNotConfigured = errors.New("还没配置 WebDAV 地址")

// ErrWebDAVBadName is returned for a file name that is not a plain name inside
// the backup directory: no separators, no traversal.
var ErrWebDAVBadName = errors.New("备份文件名不合法")

// webdavMask is the placeholder the console shows in place of a stored
// password. The real value never leaves the process.
const webdavMask = "••••••"

// WebDAVFile is one entry of the remote backup directory.
type WebDAVFile struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Modified string `json:"modified,omitempty"`
}

// WebDAVView is the console-facing description of the stored settings. The
// password is never part of it: the UI only needs to know whether one exists,
// and it gets a fixed mask so a password field can show "something is set"
// without the value ever being echoed back.
type WebDAVView struct {
	Enabled     bool   `json:"enabled"`
	URL         string `json:"url"`
	Username    string `json:"username"`
	HasPassword bool   `json:"has_password"`
	Password    string `json:"password"`
}

// WebDAVConfigView renders the stored settings with the password masked.
func (a *App) WebDAVConfigView() WebDAVView {
	s := a.Config().WebDAV
	v := WebDAVView{
		Enabled:     s.Enabled,
		URL:         s.URL,
		Username:    s.Username,
		HasPassword: strings.TrimSpace(s.Password) != "",
	}
	if v.HasPassword {
		v.Password = webdavMask
	}
	return v
}

// SetWebDAVSettings stores the target. keepPassword means the request carried
// no usable password field and the stored secret must survive: the console
// sends only what the user touched, so saving a new URL must not wipe the
// password.
func (a *App) SetWebDAVSettings(next config.WebDAVSettings, keepPassword bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if keepPassword {
		next.Password = a.cfg.WebDAV.Password
	}
	next.URL = strings.TrimSpace(next.URL)
	next.Username = strings.TrimSpace(next.Username)
	prev := a.cfg
	a.cfg.WebDAV = next
	if err := config.Save(a.cfgPath, a.cfg); err != nil {
		a.cfg = prev
		return err
	}
	return nil
}

// webdavTransport mirrors subscriptionTransport: Proxy is nil so a backup is
// never routed through HTTP_PROXY / HTTPS_PROXY that another client on the
// machine set, and every phase has an explicit timeout.
var webdavTransport = &http.Transport{
	Proxy:                 nil,
	DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          4,
	MaxIdleConnsPerHost:   2,
	IdleConnTimeout:       60 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
}

// webdavClient is the per-target WebDAV handle. One is built per operation
// from the stored settings, so a settings change takes effect immediately.
type webdavClient struct {
	base     *url.URL
	username string
	password string
	http     *http.Client
}

// parseWebDAVURL validates a user-typed directory address and normalises it so
// a file name can be appended directly.
func parseWebDAVURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrWebDAVNotConfigured
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("WebDAV 地址无法解析：%w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("WebDAV 地址必须以 http:// 或 https:// 开头")
	}
	if u.Host == "" {
		return nil, errors.New("WebDAV 地址缺少主机名")
	}
	if u.User != nil {
		// Refusing userinfo keeps the password out of the stored URL, which is
		// what the console reads back.
		return nil, errors.New("WebDAV 地址不要包含用户名密码，请分别填写用户名和密码")
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u, nil
}

// ValidateWebDAVURL reports whether raw is a usable WebDAV directory address.
// An empty value is rejected with ErrWebDAVNotConfigured; the control layer
// only calls this once it has decided the request actually carries an address,
// so clearing the target never goes through here.
func ValidateWebDAVURL(raw string) error {
	_, err := parseWebDAVURL(raw)
	return err
}

func newWebDAVClient(s config.WebDAVSettings) (*webdavClient, error) {
	base, err := parseWebDAVURL(s.URL)
	if err != nil {
		return nil, err
	}
	return &webdavClient{
		base:     base,
		username: s.Username,
		password: s.Password,
		http: &http.Client{
			// The overall budget covers connect, TLS, upload and download; the
			// transport's own timeouts keep a single phase from eating it all.
			Timeout:   60 * time.Second,
			Transport: webdavTransport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("WebDAV 重定向次数过多")
				}
				return nil
			},
		},
	}, nil
}

// mask removes the stored password from text that is about to be logged or
// returned to the console. Transport errors can embed the URL, and a body can
// echo credentials back, so this runs before either can escape.
func (c *webdavClient) mask(s string) string {
	if c.password == "" {
		return s
	}
	return strings.ReplaceAll(s, c.password, "***")
}

// urlFor builds the URL of one file inside the configured directory. The name
// is a plain base name (safeWebDAVName enforces that), so a plain path join is
// correct and url.URL re-escapes anything unusual.
func (c *webdavClient) urlFor(name string) string {
	u := *c.base
	u.Path = c.base.Path + name
	u.RawPath = ""
	return u.String()
}

func (c *webdavClient) newRequest(ctx context.Context, method, target string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	req.Header.Set("User-Agent", "syan-clash")
	return req, nil
}

func (c *webdavClient) do(req *http.Request) (*http.Response, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接 WebDAV 失败：%s", c.mask(err.Error()))
	}
	return resp, nil
}

// fail turns a non-2xx response into a message a user can act on: the status
// code is always present, and the common cases name the fix.
func (c *webdavClient) fail(op string, resp *http.Response) error {
	detail := ""
	if resp.Body != nil {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		detail = strings.TrimSpace(c.mask(string(raw)))
		if len(detail) > 200 {
			detail = detail[:200] + "…"
		}
	}
	msg := fmt.Sprintf("WebDAV %s失败（%d %s）", op, resp.StatusCode, http.StatusText(resp.StatusCode))
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		msg = fmt.Sprintf("WebDAV %s失败（401 未授权）：请检查用户名和密码", op)
	case http.StatusForbidden:
		msg = fmt.Sprintf("WebDAV %s失败（403 被拒绝）：账号没有这个目录的权限", op)
	case http.StatusNotFound:
		msg = fmt.Sprintf("WebDAV %s失败（404 不存在）：请检查地址和文件名", op)
	case http.StatusConflict:
		msg = fmt.Sprintf("WebDAV %s失败（409 冲突）：目录可能不存在或不允许写入", op)
	}
	if detail != "" {
		msg += "：" + detail
	}
	return errors.New(msg)
}

func okStatus(code int) bool { return code >= 200 && code <= 299 }

// put uploads one file.
func (c *webdavClient) put(ctx context.Context, name string, data []byte) error {
	req, err := c.newRequest(ctx, http.MethodPut, c.urlFor(name), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/zip")
	req.ContentLength = int64(len(data))
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if !okStatus(resp.StatusCode) {
		return c.fail("上传", resp)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return nil
}

// get downloads one file. The body cap keeps a hostile or misconfigured server
// from exhausting memory; a real backup is a few megabytes at most.
func (c *webdavClient) get(ctx context.Context, name string) ([]byte, error) {
	req, err := c.newRequest(ctx, http.MethodGet, c.urlFor(name), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if !okStatus(resp.StatusCode) {
		return nil, c.fail("下载", resp)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("读取 WebDAV 响应失败：%s", c.mask(err.Error()))
	}
	return raw, nil
}

// delete removes one file.
func (c *webdavClient) delete(ctx context.Context, name string) error {
	req, err := c.newRequest(ctx, http.MethodDelete, c.urlFor(name), nil)
	if err != nil {
		return err
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if !okStatus(resp.StatusCode) {
		return c.fail("删除", resp)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return nil
}

// webdavPropfindBody asks for exactly the three properties the listing shows.
// A server that only supports the allprop form still answers this one.
const webdavPropfindBody = `<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:"><d:prop><d:getcontentlength/><d:getlastmodified/><d:resourcetype/></d:prop></d:propfind>`

// list reads the directory with PROPFIND Depth: 1.
func (c *webdavClient) list(ctx context.Context) ([]WebDAVFile, error) {
	req, err := c.newRequest(ctx, "PROPFIND", c.base.String(), strings.NewReader(webdavPropfindBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Depth", "1")
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// 207 is the spec answer; a few servers reply 200 with the same body.
	if resp.StatusCode != http.StatusMultiStatus && resp.StatusCode != http.StatusOK {
		return nil, c.fail("列目录", resp)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("读取 WebDAV 目录失败：%s", c.mask(err.Error()))
	}
	return parseWebDAVMultiStatus(raw)
}

// The DAV: namespace is matched by local name (no namespace in the tags) so a
// server that uses a different prefix, or none at all, still parses.
type davMultiStatus struct {
	XMLName   xml.Name      `xml:"multistatus"`
	Responses []davResponse `xml:"response"`
}

type davResponse struct {
	Href      string        `xml:"href"`
	Propstats []davPropstat `xml:"propstat"`
}

type davPropstat struct {
	Status string  `xml:"status"`
	Prop   davProp `xml:"prop"`
}

type davProp struct {
	ContentLength string          `xml:"getcontentlength"`
	LastModified  string          `xml:"getlastmodified"`
	ResourceType  davResourceType `xml:"resourcetype"`
}

type davResourceType struct {
	Collection *struct{} `xml:"collection"`
}

func parseWebDAVMultiStatus(raw []byte) ([]WebDAVFile, error) {
	var ms davMultiStatus
	if err := xml.Unmarshal(raw, &ms); err != nil {
		return nil, fmt.Errorf("WebDAV 目录响应无法解析：%w", err)
	}
	files := make([]WebDAVFile, 0, len(ms.Responses))
	for _, r := range ms.Responses {
		name := webdavHrefName(r.Href)
		if name == "" {
			continue // the directory itself, or a sub-collection
		}
		f := WebDAVFile{Name: name}
		collection := false
		for _, ps := range r.Propstats {
			if ps.Prop.ResourceType.Collection != nil {
				collection = true
				break
			}
			if v := strings.TrimSpace(ps.Prop.ContentLength); v != "" {
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					f.Size = n
				}
			}
			if v := strings.TrimSpace(ps.Prop.LastModified); v != "" {
				f.Modified = v
				if t, err := http.ParseTime(v); err == nil {
					f.Modified = t.Format(time.RFC3339)
				}
			}
		}
		if collection {
			continue
		}
		files = append(files, f)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, nil
}

// webdavHrefName turns a PROPFIND href into a plain file name, or "" when the
// entry is a collection (the directory itself or a sub-directory).
func webdavHrefName(href string) string {
	href = strings.TrimSpace(href)
	if href == "" {
		return ""
	}
	if u, err := url.Parse(href); err == nil && u.Path != "" {
		href = u.Path
	}
	if strings.HasSuffix(href, "/") {
		return ""
	}
	name := href
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if decoded, err := url.PathUnescape(name); err == nil {
		name = decoded
	}
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return ""
	}
	return name
}

// safeWebDAVName keeps a user-supplied download/delete name inside the backup
// directory: a plain base name, never a path.
func safeWebDAVName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return "", ErrWebDAVBadName
	}
	if strings.ContainsAny(name, `/\`) {
		return "", ErrWebDAVBadName
	}
	return name, nil
}

// webdavClientFor builds a client for the stored settings, or reports that no
// target is configured yet.
func (a *App) webdavClientFor() (*webdavClient, error) {
	s := a.Config().WebDAV
	if strings.TrimSpace(s.URL) == "" {
		return nil, ErrWebDAVNotConfigured
	}
	return newWebDAVClient(s)
}

// WebDAVList returns the backups currently stored in the configured directory.
func (a *App) WebDAVList(ctx context.Context) ([]WebDAVFile, error) {
	client, err := a.webdavClientFor()
	if err != nil {
		return nil, err
	}
	files, err := client.list(ctx)
	if err != nil {
		a.log.Warnf("WebDAV 列目录失败：%v", err)
		return nil, err
	}
	return files, nil
}

// WebDAVUpload exports the current configuration and stores it in the
// configured directory under a fresh timestamped name.
func (a *App) WebDAVUpload(ctx context.Context) (WebDAVFile, error) {
	client, err := a.webdavClientFor()
	if err != nil {
		return WebDAVFile{}, err
	}
	raw, err := a.ExportBackup()
	if err != nil {
		return WebDAVFile{}, err
	}
	name := BackupName()
	if err := client.put(ctx, name, raw); err != nil {
		a.log.Warnf("WebDAV 备份上传失败：%v", err)
		return WebDAVFile{}, err
	}
	a.log.Infof("WebDAV 备份已上传：%s（%d 字节）", name, len(raw))
	return WebDAVFile{Name: name, Size: int64(len(raw)), Modified: time.Now().Format(time.RFC3339)}, nil
}

// WebDAVDownload fetches one stored backup and returns the raw archive; the
// control layer feeds it to ImportBackup.
func (a *App) WebDAVDownload(ctx context.Context, name string) ([]byte, error) {
	client, err := a.webdavClientFor()
	if err != nil {
		return nil, err
	}
	clean, err := safeWebDAVName(name)
	if err != nil {
		return nil, err
	}
	raw, err := client.get(ctx, clean)
	if err != nil {
		a.log.Warnf("WebDAV 备份下载失败：%v", err)
		return nil, err
	}
	return raw, nil
}

// WebDAVDelete removes one stored backup.
func (a *App) WebDAVDelete(ctx context.Context, name string) error {
	client, err := a.webdavClientFor()
	if err != nil {
		return err
	}
	clean, err := safeWebDAVName(name)
	if err != nil {
		return err
	}
	if err := client.delete(ctx, clean); err != nil {
		a.log.Warnf("WebDAV 备份删除失败：%v", err)
		return err
	}
	a.log.Infof("WebDAV 备份已删除：%s", clean)
	return nil
}
