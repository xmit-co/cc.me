package ccme

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// AliasResponse is the result of CreateAlias.
type AliasResponse struct {
	URL string `json:"url"`
}

// CreateAlias registers a permanent alias for target: POST {base}/c with
// {"at": target}. It is idempotent and requires no authentication.
func CreateAlias(target string, opts ...func(*urlConfig)) (AliasResponse, error) {
	cfg := newURLConfig(opts)
	body, err := json.Marshal(map[string]string{"at": target})
	if err != nil {
		return AliasResponse{}, err
	}
	req, err := http.NewRequest(http.MethodPost, joinBase(cfg.baseURL, "/c"), bytes.NewReader(body))
	if err != nil {
		return AliasResponse{}, err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return AliasResponse{}, err
	}
	var out AliasResponse
	if err := parseJSONResponse(resp, &out); err != nil {
		return AliasResponse{}, err
	}
	return out, nil
}

// Client talks to a cc.me inbox using a private key for owner authentication.
type Client struct {
	baseURL    string
	privateKey string
	httpClient *http.Client
	publicKey  string
}

// NewClient constructs a Client. If baseURL is empty, DefaultBaseURL is used.
func NewClient(baseURL, privateKey string) (*Client, error) {
	if privateKey == "" {
		return nil, fmt.Errorf("privateKey is required")
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	pub, err := publicKeyB64u(privateKey)
	if err != nil {
		return nil, err
	}
	return &Client{
		baseURL:    baseURL,
		privateKey: privateKey,
		httpClient: http.DefaultClient,
		publicKey:  pub,
	}, nil
}

// InboxURL returns the inbox URL with optional query parameters.
func (c *Client) InboxURL(opts InboxOptions) string {
	return joinBase(c.baseURL, inboxPath(c.publicKey, opts))
}

// WebmentionURL returns the webmention receiver URL.
func (c *Client) WebmentionURL() string { return c.protocolURL("webmention") }

// WebsubURL returns the websub receiver URL.
func (c *Client) WebsubURL() string { return c.protocolURL("websub") }

// SlackURL returns the slack receiver URL.
func (c *Client) SlackURL() string { return c.protocolURL("slack") }

// PingbackURL returns the pingback receiver URL.
func (c *Client) PingbackURL() string { return c.protocolURL("pingback") }

// CloudEventsURL returns the cloudevents receiver URL.
func (c *Client) CloudEventsURL() string { return c.protocolURL("cloudevents") }

// MetaURL returns the meta receiver URL, appending ?v={verifyToken} when set.
func (c *Client) MetaURL(verifyToken string) string {
	base := c.protocolURL("meta")
	if verifyToken == "" {
		return base
	}
	return base + "?v=" + queryEscape(verifyToken)
}

// DiscordURL returns the discord receiver URL for the given app public key.
func (c *Client) DiscordURL(appPublicKey string) string {
	return joinBase(c.baseURL, protocolPath(c.publicKey, "discord")+"/"+pathEscape(appPublicKey))
}

func (c *Client) protocolURL(protocol string) string {
	return joinBase(c.baseURL, protocolPath(c.publicKey, protocol))
}

// DeliveryResponse holds the decrypted deliveries from peek/claim.
type DeliveryResponse struct {
	Count    int
	Cursor   string
	Requests []*Delivery
}

// PeekOptions controls Peek.
type PeekOptions = InboxOptions

// Peek fetches deliveries without reserving them.
func (c *Client) Peek(opts PeekOptions) (*DeliveryResponse, error) {
	path := inboxPath(c.publicKey, opts)
	ts, sig, err := signRequest(c.privateKey, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, joinBase(c.baseURL, path), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(authTimestampHeader, ts)
	req.Header.Set(authSignatureHeader, sig)
	return c.doDeliveries(req)
}

// ClaimOptions controls Claim.
type ClaimOptions struct {
	Limit int
	Poll  bool
}

// Claim reserves up to Limit deliveries until they are acked or released.
func (c *Client) Claim(opts ClaimOptions) (*DeliveryResponse, error) {
	payload := map[string]any{}
	if opts.Limit > 0 {
		payload["limit"] = opts.Limit
	}
	if opts.Poll {
		payload["poll"] = true
	}
	req, err := c.signedJSONRequest("claim", payload)
	if err != nil {
		return nil, err
	}
	return c.doDeliveries(req)
}

// IDResponse is the result of Ack and Release.
type IDResponse struct {
	Acked    int      `json:"acked"`
	Released int      `json:"released"`
	Missing  []string `json:"missing"`
}

// Ack confirms handling of the given delivery ids.
func (c *Client) Ack(ids []string) (IDResponse, error) {
	return c.postIDs("ack", ids)
}

// Release returns the given delivery ids to the queue.
func (c *Client) Release(ids []string) (IDResponse, error) {
	return c.postIDs("release", ids)
}

func (c *Client) postIDs(action string, ids []string) (IDResponse, error) {
	if ids == nil {
		ids = []string{}
	}
	req, err := c.signedJSONRequest(action, map[string]any{"ids": ids})
	if err != nil {
		return IDResponse{}, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return IDResponse{}, err
	}
	var out IDResponse
	if err := parseJSONResponse(resp, &out); err != nil {
		return IDResponse{}, err
	}
	return out, nil
}

// signedJSONRequest builds a signed POST to /i/KEY/{action} with a JSON body.
func (c *Client) signedJSONRequest(action string, payload any) (*http.Request, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	path := inboxPath(c.publicKey, InboxOptions{}) + "/" + action
	ts, sig, err := signRequest(c.privateKey, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, joinBase(c.baseURL, path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set(authTimestampHeader, ts)
	req.Header.Set(authSignatureHeader, sig)
	return req, nil
}

func (c *Client) doDeliveries(req *http.Request) (*DeliveryResponse, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	var body struct {
		Count  int    `json:"count"`
		Cursor string `json:"cursor"`
		Items  []struct {
			ID     string `json:"id"`
			Sealed string `json:"sealed"`
		} `json:"items"`
	}
	if err := parseJSONResponse(resp, &body); err != nil {
		return nil, err
	}
	out := &DeliveryResponse{
		Count:    body.Count,
		Cursor:   body.Cursor,
		Requests: make([]*Delivery, 0, len(body.Items)),
	}
	for _, item := range body.Items {
		delivery, err := decryptEnvelope(c.privateKey, item.ID, item.Sealed)
		if err != nil {
			return nil, err
		}
		out.Requests = append(out.Requests, delivery)
	}
	return out, nil
}

// parseJSONResponse decodes a successful response into v, or surfaces the
// server's {"error": ...} message on a non-2xx status.
func parseJSONResponse(resp *http.Response, v any) error {
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errBody struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &errBody) == nil && errBody.Error != "" {
			return fmt.Errorf("%s", errBody.Error)
		}
		return fmt.Errorf("cc.me request failed with %d", resp.StatusCode)
	}
	if v == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, v)
}
