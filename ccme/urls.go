package ccme

import (
	"net/url"
	"strconv"
	"strings"
)

// DefaultBaseURL is the public cc.me endpoint.
const DefaultBaseURL = "https://cc.me/"

// InboxOptions controls the optional query parameters on an inbox URL.
type InboxOptions struct {
	// Limit, when > 0, sets the `l` query parameter.
	Limit int
	// Cursor, when non-empty, sets the `c` query parameter.
	Cursor string
	// Poll, when true, sets the `p` query parameter with an empty value.
	Poll bool
}

func joinBase(baseURL, path string) string {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		// Fall back to naive join; the caller supplied an unusual base.
		return strings.TrimRight(baseURL, "/") + path
	}
	ref, _ := url.Parse(path)
	return base.ResolveReference(ref).String()
}

// TrampolineURL builds GET {base}/?at={target} plus any extra query params.
func TrampolineURL(target string, opts ...func(*urlConfig)) string {
	cfg := newURLConfig(opts)
	u, _ := url.Parse(joinBase(cfg.baseURL, "/"))
	q := u.Query()
	q.Set("at", target)
	for k, v := range cfg.params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// urlConfig holds shared options for URL builders and requests.
type urlConfig struct {
	baseURL string
	params  map[string]string
}

func newURLConfig(opts []func(*urlConfig)) *urlConfig {
	cfg := &urlConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// WithBaseURL overrides the base URL for a builder call.
func WithBaseURL(baseURL string) func(*urlConfig) {
	return func(c *urlConfig) { c.baseURL = baseURL }
}

// WithParams adds extra query parameters (used by TrampolineURL).
func WithParams(params map[string]string) func(*urlConfig) {
	return func(c *urlConfig) {
		if c.params == nil {
			c.params = map[string]string{}
		}
		for k, v := range params {
			c.params[k] = v
		}
	}
}

// inboxPath returns the path+query (no scheme/host) for an inbox URL, with
// query parameters ordered l, c, then p as the protocol requires. This is the
// exact byte string used both for signing and for the request target.
func inboxPath(pub string, opts InboxOptions) string {
	path := "/i/" + url.PathEscape(pub)
	var params []string
	if opts.Limit > 0 {
		params = append(params, "l="+url.QueryEscape(strconv.Itoa(opts.Limit)))
	}
	if opts.Cursor != "" {
		params = append(params, "c="+url.QueryEscape(opts.Cursor))
	}
	if opts.Poll {
		params = append(params, "p=")
	}
	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}
	return path
}

func protocolPath(pub, protocol string) string {
	return "/i/" + url.PathEscape(pub) + "/" + protocol
}

func pathEscape(s string) string  { return url.PathEscape(s) }
func queryEscape(s string) string { return url.QueryEscape(s) }
