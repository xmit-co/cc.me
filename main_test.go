package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"

	ccme "cc.me/ccme"
)

var b64 = base64.RawURLEncoding

// knownSeed matches the package-level test seed in the parent package.
const knownSeed = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

func TestParseArgs(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		wantTarget string
		wantKey    string // "" means don't check
		wantErr    bool
	}{
		{"just target", []string{"http://localhost:8080"}, "http://localhost:8080", "", false},
		{"key flag separate", []string{"--key", "/tmp/k", "http://t"}, "http://t", "/tmp/k", false},
		{"key flag equals", []string{"--key=/tmp/k2", "http://t"}, "http://t", "/tmp/k2", false},
		{"target before key", []string{"http://t", "--key", "/tmp/k"}, "http://t", "/tmp/k", false},
		{"no target", []string{}, "", "", false},
		{"key missing value", []string{"--key"}, "", "", true},
		{"key empty value", []string{"--key", ""}, "", "", true},
		{"key equals empty", []string{"--key="}, "", "", true},
		{"unknown option", []string{"--bogus"}, "", "", true},
		{"two targets", []string{"http://a", "http://b"}, "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := parseArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %v", tc.args)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if opts.target != tc.wantTarget {
				t.Fatalf("target = %q, want %q", opts.target, tc.wantTarget)
			}
			if tc.wantKey != "" && opts.keyFile != tc.wantKey {
				t.Fatalf("keyFile = %q, want %q", opts.keyFile, tc.wantKey)
			}
		})
	}
}

func TestIsHopByHop(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"connection", true},
		{"Connection", true},
		{"CONTENT-LENGTH", true},
		{"host", true},
		{"keep-alive", true},
		{"proxy-authenticate", true},
		{"proxy-authorization", true},
		{"te", true},
		{"trailer", true},
		{"transfer-encoding", true},
		{"upgrade", true},
		{"content-type", false},
		{"x-custom", false},
		{"authorization", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isHopByHop(tc.name); got != tc.want {
				t.Fatalf("isHopByHop(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestForwardURL(t *testing.T) {
	cases := []struct {
		name  string
		base  string
		query string
		want  string
	}{
		{"no query", "http://t/path", "", "http://t/path"},
		{"merge into empty", "http://t/path", "a=1", "http://t/path?a=1"},
		{"merge into existing", "http://t/path?x=9", "a=1&b=2", "http://t/path?x=9&a=1&b=2"},
		{"empty query keeps base", "http://t/p?z=1", "", "http://t/p?z=1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, err := url.Parse(tc.base)
			if err != nil {
				t.Fatal(err)
			}
			if got := forwardURL(base, tc.query); got != tc.want {
				t.Fatalf("forwardURL = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestForwardRequestStripsHopByHopAndMergesQuery(t *testing.T) {
	var got struct {
		method string
		uri    string
		body   []byte
		header http.Header
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.method = r.Method
		got.uri = r.URL.RequestURI()
		got.body = body
		got.header = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	base, _ := url.Parse(srv.URL + "/hook?fixed=1")
	d := &ccme.Delivery{
		Method: "POST",
		Path:   "/i/KEY",
		Query:  "a=1",
		Headers: []ccme.Header{
			{Name: "content-type", Value: "application/json"},
			{Name: "connection", Value: "keep-alive"}, // hop-by-hop, must drop
			{Name: "transfer-encoding", Value: "chunked"},
			{Name: "x-custom", Value: "kept"},
		},
		BodyBytes: []byte(`{"k":"v"}`),
	}
	if err := forwardRequest(srv.Client(), base, d); err != nil {
		t.Fatal(err)
	}
	if got.method != "POST" {
		t.Fatalf("method = %q", got.method)
	}
	if got.uri != "/hook?fixed=1&a=1" {
		t.Fatalf("uri = %q", got.uri)
	}
	if string(got.body) != `{"k":"v"}` {
		t.Fatalf("body = %q", got.body)
	}
	if got.header.Get("x-custom") != "kept" {
		t.Fatal("x-custom header dropped")
	}
	if got.header.Get("content-type") != "application/json" {
		t.Fatal("content-type dropped")
	}
	if got.header.Get("connection") != "" {
		t.Fatalf("connection header should be stripped, got %q", got.header.Get("connection"))
	}
}

func TestForwardRequestGETSendsNoBody(t *testing.T) {
	var sawBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(204)
	}))
	defer srv.Close()
	base, _ := url.Parse(srv.URL + "/")
	d := &ccme.Delivery{Method: "GET", BodyBytes: []byte("ignored for GET")}
	if err := forwardRequest(srv.Client(), base, d); err != nil {
		t.Fatal(err)
	}
	if len(sawBody) != 0 {
		t.Fatalf("GET forwarded a body: %q", sawBody)
	}
}

func TestForwardRequestFailsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	base, _ := url.Parse(srv.URL + "/")
	d := &ccme.Delivery{Method: "GET"}
	if err := forwardRequest(srv.Client(), base, d); err == nil {
		t.Fatal("expected error on 500")
	}
}

// --- forwardLoop integration via a fake cc.me server + target ---

// ccmeServer simulates the cc.me inbox endpoints for the forward loop.
type ccmeServer struct {
	mu       sync.Mutex
	claims   int      // number of claim calls served
	acked    []string // ids passed to ack
	released []string // ids passed to release
	// batches indexed by claim number; nil triggers a 500 to break the loop.
	batches [][]string
	sealer  func(id string) string
}

func (s *ccmeServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/claim"):
			idx := s.claims
			s.claims++
			if idx >= len(s.batches) || s.batches[idx] == nil {
				w.WriteHeader(500)
				_, _ = io.WriteString(w, `{"error":"stop"}`)
				return
			}
			items := make([]map[string]string, 0)
			for _, id := range s.batches[idx] {
				items = append(items, map[string]string{"id": id, "sealed": s.sealer(id)})
			}
			resp := map[string]any{"count": len(items), "items": items}
			_ = json.NewEncoder(w).Encode(resp)
		case strings.HasSuffix(r.URL.Path, "/ack"):
			var p struct {
				IDs []string `json:"ids"`
			}
			_ = json.Unmarshal(body, &p)
			s.acked = append(s.acked, p.IDs...)
			_, _ = io.WriteString(w, `{"acked":0,"missing":[]}`)
		case strings.HasSuffix(r.URL.Path, "/release"):
			var p struct {
				IDs []string `json:"ids"`
			}
			_ = json.Unmarshal(body, &p)
			s.released = append(s.released, p.IDs...)
			_, _ = io.WriteString(w, `{"released":0,"missing":[]}`)
		default:
			w.WriteHeader(404)
		}
	}
}

// sealForKey reproduces crypto_box_seal to the recipient derived from key.
func sealForKey(t *testing.T, key string, plaintext []byte) string {
	t.Helper()
	recipientPub := x25519PublicKey(t, key)
	ephPub, ephPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [24]byte
	h, err := blake2b.New(24, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.Write(ephPub[:])
	h.Write(recipientPub[:])
	copy(nonce[:], h.Sum(nil))
	sealed := box.Seal(nil, plaintext, &nonce, &recipientPub, ephPriv)
	out := append(append([]byte{}, ephPub[:]...), sealed...)
	return b64.EncodeToString(out)
}

func x25519PublicKey(t *testing.T, key string) [32]byte {
	t.Helper()
	seed, err := b64.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	edPub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	point, err := edwards25519.NewIdentityPoint().SetBytes(edPub)
	if err != nil {
		t.Fatal(err)
	}
	var pub [32]byte
	copy(pub[:], point.BytesMontgomery())
	return pub
}

func capturedJSON(t *testing.T, id string) []byte {
	t.Helper()
	cr := map[string]any{
		"id":                  id,
		"received_at_unix_ms": 1781337600000,
		"method":              "GET",
		"path":                "/i/KEY",
		"query":               "",
		"headers":             []any{},
		"body_b64u":           "",
	}
	data, err := json.Marshal(cr)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeKeyFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")
	if err := os.WriteFile(path, []byte(knownSeed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestForwardLoopAcksOnSuccess(t *testing.T) {
	keyFile := writeKeyFile(t)

	var targetHits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		w.WriteHeader(200)
	}))
	defer target.Close()

	cc := &ccmeServer{
		batches: [][]string{{"m_1", "m_2"}, nil}, // 2nd claim returns 500 to stop
		sealer:  func(id string) string { return sealForKey(t, knownSeed, capturedJSON(t, id)) },
	}
	ccSrv := httptest.NewServer(cc.handler())
	defer ccSrv.Close()

	t.Setenv("CC_ME_URL", ccSrv.URL)
	t.Setenv("CC_ME_LIMIT", "10")

	err := forwardLoop(options{keyFile: keyFile, target: target.URL + "/hook"})
	if err == nil {
		t.Fatal("expected loop to terminate with error from 2nd claim")
	}
	if targetHits != 2 {
		t.Fatalf("target hits = %d, want 2", targetHits)
	}
	if len(cc.acked) != 2 || cc.acked[0] != "m_1" || cc.acked[1] != "m_2" {
		t.Fatalf("acked = %v, want [m_1 m_2]", cc.acked)
	}
	if len(cc.released) != 0 {
		t.Fatalf("released = %v, want none", cc.released)
	}
}

func TestForwardLoopReleasesRemainderOnFailure(t *testing.T) {
	keyFile := writeKeyFile(t)

	var targetHits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		if targetHits >= 2 {
			w.WriteHeader(500) // fail the 2nd delivery
			return
		}
		w.WriteHeader(200)
	}))
	defer target.Close()

	cc := &ccmeServer{
		batches: [][]string{{"m_1", "m_2", "m_3"}},
		sealer:  func(id string) string { return sealForKey(t, knownSeed, capturedJSON(t, id)) },
	}
	ccSrv := httptest.NewServer(cc.handler())
	defer ccSrv.Close()

	t.Setenv("CC_ME_URL", ccSrv.URL)

	err := forwardLoop(options{keyFile: keyFile, target: target.URL + "/hook"})
	if err == nil {
		t.Fatal("expected error after failed delivery")
	}
	// m_1 succeeded → acked. m_2 failed and m_3 remaining → released.
	if len(cc.acked) != 1 || cc.acked[0] != "m_1" {
		t.Fatalf("acked = %v, want [m_1]", cc.acked)
	}
	if len(cc.released) != 2 || cc.released[0] != "m_2" || cc.released[1] != "m_3" {
		t.Fatalf("released = %v, want [m_2 m_3]", cc.released)
	}
}

func TestForwardLoopFirstDeliveryFailsReleasesAll(t *testing.T) {
	keyFile := writeKeyFile(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer target.Close()

	cc := &ccmeServer{
		batches: [][]string{{"m_1", "m_2"}},
		sealer:  func(id string) string { return sealForKey(t, knownSeed, capturedJSON(t, id)) },
	}
	ccSrv := httptest.NewServer(cc.handler())
	defer ccSrv.Close()
	t.Setenv("CC_ME_URL", ccSrv.URL)

	if err := forwardLoop(options{keyFile: keyFile, target: target.URL}); err == nil {
		t.Fatal("expected error")
	}
	if len(cc.acked) != 0 {
		t.Fatalf("acked = %v, want none", cc.acked)
	}
	if len(cc.released) != 2 {
		t.Fatalf("released = %v, want both", cc.released)
	}
}

func TestLimitFromEnv(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		t.Setenv("CC_ME_LIMIT", "")
		if got := limitFromEnv(); got != defaultLimit {
			t.Fatalf("limit = %d, want %d", got, defaultLimit)
		}
	})
	t.Run("set", func(t *testing.T) {
		t.Setenv("CC_ME_LIMIT", "42")
		if got := limitFromEnv(); got != 42 {
			t.Fatalf("limit = %d, want 42", got)
		}
	})
	t.Run("invalid falls back", func(t *testing.T) {
		t.Setenv("CC_ME_LIMIT", "notanumber")
		if got := limitFromEnv(); got != defaultLimit {
			t.Fatalf("limit = %d, want %d", got, defaultLimit)
		}
	})
}

func TestDefaultKeyFile(t *testing.T) {
	t.Run("env override", func(t *testing.T) {
		t.Setenv("CC_ME_KEY", "/custom/path.key")
		if got := defaultKeyFile(); got != "/custom/path.key" {
			t.Fatalf("keyFile = %q", got)
		}
	})
	t.Run("home default", func(t *testing.T) {
		t.Setenv("CC_ME_KEY", "")
		home, err := os.UserHomeDir()
		if err != nil {
			t.Skip("no home dir")
		}
		if got := defaultKeyFile(); got != filepath.Join(home, ".cc-me.key") {
			t.Fatalf("keyFile = %q", got)
		}
	})
}

// TestMissingTargetExits builds the binary and runs it with no target to assert
// exit code 64 (forwardLoop calls os.Exit, which can't be tested in-process).
func TestMissingTargetExits(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary build in short mode")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "cc-me")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}

	cmd := exec.Command(bin)
	// Avoid touching the real home key by pointing at a temp path.
	cmd.Env = append(os.Environ(), "CC_ME_KEY="+filepath.Join(dir, "k.key"))
	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if code := exitErr.ExitCode(); code != 64 {
		t.Fatalf("exit code = %d, want 64", code)
	}
}
