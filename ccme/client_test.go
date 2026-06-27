package ccme

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// capturedHTTP records what an httptest handler received.
type capturedHTTP struct {
	method string
	path   string // URL.Path
	rawURL string // URL.RequestURI(), includes query
	body   []byte
	header http.Header
}

func recordingServer(t *testing.T, status int, respBody string, sink *capturedHTTP) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*sink = capturedHTTP{
			method: r.Method,
			path:   r.URL.Path,
			rawURL: r.URL.RequestURI(),
			body:   body,
			header: r.Header.Clone(),
		}
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// verifyAuth checks the two auth headers verify over the canonical string for
// the recorded request.
func verifyAuth(t *testing.T, got capturedHTTP) {
	t.Helper()
	ts := got.header.Get(authTimestampHeader)
	sig := got.header.Get(authSignatureHeader)
	if ts == "" || sig == "" {
		t.Fatalf("missing auth headers: ts=%q sig=%q", ts, sig)
	}
	bodyHash := b64.EncodeToString(sha256Sum(got.body))
	canonical := authVersion + "\n" + got.method + "\n" + got.rawURL + "\n" + ts + "\n" + bodyHash
	pub := ed25519.NewKeyFromSeed(mustSeed(t, knownSeed)).Public().(ed25519.PublicKey)
	sigBytes, err := b64.DecodeString(sig)
	if err != nil {
		t.Fatalf("signature not base64url: %v", err)
	}
	if !ed25519.Verify(pub, []byte(canonical), sigBytes) {
		t.Fatalf("auth signature did not verify for %s %s", got.method, got.rawURL)
	}
}

func newTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	c, err := NewClient(baseURL, knownSeed)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewClientRequiresKey(t *testing.T) {
	if _, err := NewClient("", ""); err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestNewClientDefaultsBaseURL(t *testing.T) {
	c := newTestClient(t, "")
	if c.baseURL != DefaultBaseURL {
		t.Fatalf("baseURL = %q, want default", c.baseURL)
	}
}

func TestPeekSendsGETWithAuth(t *testing.T) {
	cr := captured("m_1", "GET", "/x", "", nil, []byte("hello"))
	sealed := sealForKey(t, knownSeed, sampleCaptured(t, cr))
	resp := `{"count":1,"cursor":"cur1","items":[{"id":"m_1","sealed":"` + sealed + `"}]}`

	var got capturedHTTP
	srv := recordingServer(t, 200, resp, &got)
	c := newTestClient(t, srv.URL)

	out, err := c.Peek(PeekOptions{Limit: 10, Poll: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodGet {
		t.Fatalf("method = %q", got.method)
	}
	if got.rawURL != "/i/"+knownPublicKey+"?l=10&p=" {
		t.Fatalf("request URI = %q", got.rawURL)
	}
	if len(got.body) != 0 {
		t.Fatalf("GET sent a body: %q", got.body)
	}
	verifyAuth(t, got)

	if out.Count != 1 || out.Cursor != "cur1" {
		t.Fatalf("response = %+v", out)
	}
	if len(out.Requests) != 1 || out.Requests[0].Text() != "hello" {
		t.Fatalf("decrypted = %+v", out.Requests)
	}
}

func TestClaimPostsJSONWithAuth(t *testing.T) {
	cr := captured("m_2", "GET", "/x", "", nil, nil)
	sealed := sealForKey(t, knownSeed, sampleCaptured(t, cr))
	resp := `{"count":1,"items":[{"id":"m_2","sealed":"` + sealed + `"}]}`

	var got capturedHTTP
	srv := recordingServer(t, 200, resp, &got)
	c := newTestClient(t, srv.URL)

	if _, err := c.Claim(ClaimOptions{Limit: 5, Poll: true}); err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodPost {
		t.Fatalf("method = %q", got.method)
	}
	if got.path != "/i/"+knownPublicKey+"/claim" {
		t.Fatalf("path = %q", got.path)
	}
	if got.header.Get("content-type") != "application/json" {
		t.Fatalf("content-type = %q", got.header.Get("content-type"))
	}
	var payload map[string]any
	if err := json.Unmarshal(got.body, &payload); err != nil {
		t.Fatalf("body not JSON: %v (%q)", err, got.body)
	}
	if payload["limit"] != float64(5) || payload["poll"] != true {
		t.Fatalf("payload = %+v", payload)
	}
	verifyAuth(t, got)
}

func TestClaimOmitsZeroLimitAndFalsePoll(t *testing.T) {
	var got capturedHTTP
	srv := recordingServer(t, 200, `{"count":0,"items":[]}`, &got)
	c := newTestClient(t, srv.URL)
	if _, err := c.Claim(ClaimOptions{}); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(got.body, &payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["limit"]; ok {
		t.Fatalf("limit should be omitted: %+v", payload)
	}
	if _, ok := payload["poll"]; ok {
		t.Fatalf("poll should be omitted: %+v", payload)
	}
}

func TestAckPostsIDs(t *testing.T) {
	var got capturedHTTP
	srv := recordingServer(t, 200, `{"acked":2,"missing":[]}`, &got)
	c := newTestClient(t, srv.URL)

	out, err := c.Ack([]string{"m_1", "m_2"})
	if err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodPost || got.path != "/i/"+knownPublicKey+"/ack" {
		t.Fatalf("method=%q path=%q", got.method, got.path)
	}
	var payload struct {
		IDs []string `json:"ids"`
	}
	if err := json.Unmarshal(got.body, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.IDs) != 2 || payload.IDs[0] != "m_1" {
		t.Fatalf("ids = %+v", payload.IDs)
	}
	verifyAuth(t, got)
	if out.Acked != 2 {
		t.Fatalf("acked = %d", out.Acked)
	}
}

func TestReleasePostsIDs(t *testing.T) {
	var got capturedHTTP
	srv := recordingServer(t, 200, `{"released":1,"missing":["m_x"]}`, &got)
	c := newTestClient(t, srv.URL)

	out, err := c.Release([]string{"m_1"})
	if err != nil {
		t.Fatal(err)
	}
	if got.path != "/i/"+knownPublicKey+"/release" {
		t.Fatalf("path = %q", got.path)
	}
	if out.Released != 1 || len(out.Missing) != 1 || out.Missing[0] != "m_x" {
		t.Fatalf("response = %+v", out)
	}
	verifyAuth(t, got)
}

func TestAckNilIDsSendsEmptyArray(t *testing.T) {
	var got capturedHTTP
	srv := recordingServer(t, 200, `{"acked":0,"missing":[]}`, &got)
	c := newTestClient(t, srv.URL)
	if _, err := c.Ack(nil); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		IDs []string `json:"ids"`
	}
	if err := json.Unmarshal(got.body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.IDs == nil {
		t.Fatal("ids should serialize as [] not null")
	}
	if string(got.body) != `{"ids":[]}` {
		t.Fatalf("body = %q, want empty array", got.body)
	}
}

func TestNonOKSurfacesErrorMessage(t *testing.T) {
	var got capturedHTTP
	srv := recordingServer(t, 403, `{"error":"bad signature"}`, &got)
	c := newTestClient(t, srv.URL)

	_, err := c.Ack([]string{"m_1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "bad signature" {
		t.Fatalf("error = %q, want %q", err.Error(), "bad signature")
	}
}

func TestNonOKWithoutErrorBody(t *testing.T) {
	var got capturedHTTP
	srv := recordingServer(t, 500, `not json`, &got)
	c := newTestClient(t, srv.URL)
	_, err := c.Peek(PeekOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "cc.me request failed with 500" {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestPeekDecryptFailureSurfaced(t *testing.T) {
	var got capturedHTTP
	srv := recordingServer(t, 200, `{"count":1,"items":[{"id":"m_1","sealed":"@@@"}]}`, &got)
	c := newTestClient(t, srv.URL)
	if _, err := c.Peek(PeekOptions{}); err == nil {
		t.Fatal("expected decrypt error to surface")
	}
}

func TestCreateAlias(t *testing.T) {
	var got capturedHTTP
	srv := recordingServer(t, 200, `{"url":"https://cc.me/a/abcd"}`, &got)

	out, err := CreateAlias("https://target.example/hook", WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodPost || got.path != "/c" {
		t.Fatalf("method=%q path=%q", got.method, got.path)
	}
	if got.header.Get(authTimestampHeader) != "" || got.header.Get(authSignatureHeader) != "" {
		t.Fatal("CreateAlias must not send auth headers")
	}
	var payload map[string]string
	if err := json.Unmarshal(got.body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["at"] != "https://target.example/hook" {
		t.Fatalf("payload = %+v", payload)
	}
	if out.URL != "https://cc.me/a/abcd" {
		t.Fatalf("url = %q", out.URL)
	}
}

func TestCreateAliasErrorSurfaced(t *testing.T) {
	var got capturedHTTP
	srv := recordingServer(t, 400, `{"error":"invalid target"}`, &got)
	if _, err := CreateAlias("nope", WithBaseURL(srv.URL)); err == nil || err.Error() != "invalid target" {
		t.Fatalf("error = %v", err)
	}
}
