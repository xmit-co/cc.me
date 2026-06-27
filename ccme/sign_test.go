package ccme

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBase64URLRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", []byte{}},
		{"single byte", []byte{0x00}},
		{"one byte ff", []byte{0xff}},
		{"two bytes", []byte{0xfb, 0xff}},
		{"five bytes needs no pad", []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
		{"32 bytes", func() []byte {
			b := make([]byte, 32)
			for i := range b {
				b[i] = byte(i * 7)
			}
			return b
		}()},
		{"url-unsafe bytes", []byte{0xfb, 0xef, 0xbe}}, // would yield +/ in std base64
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc := b64.EncodeToString(tc.in)
			if strings.ContainsAny(enc, "=+/") {
				t.Fatalf("encoding %q contains padding or non-url chars", enc)
			}
			dec, err := b64.DecodeString(enc)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if string(dec) != string(tc.in) {
				t.Fatalf("round trip = %v, want %v", dec, tc.in)
			}
		})
	}
}

func TestBase64URLNoPad(t *testing.T) {
	// 1 byte normally needs 2 pad chars; 2 bytes need 1. Confirm none appear.
	for n := 0; n < 8; n++ {
		enc := b64.EncodeToString(make([]byte, n))
		if strings.Contains(enc, "=") {
			t.Fatalf("encoding of %d zero bytes has padding: %q", n, enc)
		}
	}
}

func TestSignRequestCanonicalString(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		body   []byte
	}{
		{"GET empty body", "GET", "/i/KEY?l=10&p=", nil},
		{"GET empty body explicit", "GET", "/i/KEY", []byte{}},
		{"POST claim", "POST", "/i/KEY/claim", []byte(`{"limit":10}`)},
		{"POST ack", "POST", "/i/KEY/ack", []byte(`{"ids":["m_1"]}`)},
		{"path with query", "POST", "/i/KEY?c=cur", []byte("x")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, sig, err := signRequest(knownSeed, tc.method, tc.path, tc.body)
			if err != nil {
				t.Fatal(err)
			}

			// Timestamp must be Unix seconds, roughly now.
			tsInt, err := strconv.ParseInt(ts, 10, 64)
			if err != nil {
				t.Fatalf("timestamp not an integer: %v", err)
			}
			if delta := time.Now().Unix() - tsInt; delta < 0 || delta > 5 {
				t.Fatalf("timestamp %d not within 5s of now", tsInt)
			}

			bodyHash := sha256.Sum256(tc.body)
			wantCanonical := strings.Join([]string{
				authVersion, tc.method, tc.path, ts, b64.EncodeToString(bodyHash[:]),
			}, "\n")

			// Exact format check including no trailing newline.
			if strings.HasSuffix(wantCanonical, "\n") {
				t.Fatal("canonical string must not have a trailing newline")
			}
			if got := strings.Count(wantCanonical, "\n"); got != 4 {
				t.Fatalf("canonical string has %d newlines, want 4", got)
			}

			// Signature must verify against the canonical string.
			pub := ed25519.NewKeyFromSeed(mustSeed(t, knownSeed)).Public().(ed25519.PublicKey)
			sigBytes, err := b64.DecodeString(sig)
			if err != nil {
				t.Fatalf("signature not base64url: %v", err)
			}
			if !ed25519.Verify(pub, []byte(wantCanonical), sigBytes) {
				t.Fatal("signature does not verify over canonical string")
			}
		})
	}
}

func TestSignRequestCanonicalLiteral(t *testing.T) {
	// Pin the exact canonical layout: cc-me-v1\n{METHOD}\n{path}\n{ts}\n{hash}.
	ts, sig, err := signRequest(knownSeed, "POST", "/i/KEY/claim", []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("hi"))
	canonical := "cc-me-v1\nPOST\n/i/KEY/claim\n" + ts + "\n" + b64.EncodeToString(hash[:])
	pub := ed25519.NewKeyFromSeed(mustSeed(t, knownSeed)).Public().(ed25519.PublicKey)
	sigBytes, _ := b64.DecodeString(sig)
	if !ed25519.Verify(pub, []byte(canonical), sigBytes) {
		t.Fatal("literal canonical string did not verify")
	}
}

func TestEmptyBodyHashMatchesEmptySha256(t *testing.T) {
	empty := sha256.Sum256([]byte{})
	got := b64.EncodeToString(sha256Sum(nil))
	if got != b64.EncodeToString(empty[:]) {
		t.Fatalf("empty-body hash = %q, want %q", got, b64.EncodeToString(empty[:]))
	}
	// Known SHA256 of empty input.
	const wantEmpty = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
	if got != wantEmpty {
		t.Fatalf("empty-body hash = %q, want %q", got, wantEmpty)
	}
}

func TestSignRequestRejectsBadKey(t *testing.T) {
	if _, _, err := signRequest("bad-key!!", "GET", "/i/KEY", nil); err == nil {
		t.Fatal("expected error for malformed key")
	}
}

func mustSeed(t *testing.T, key string) []byte {
	t.Helper()
	seed, err := b64.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	return seed
}
