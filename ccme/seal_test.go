package ccme

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// sealForKey reproduces libsodium crypto_box_seal: it generates an ephemeral
// keypair, derives the nonce as BLAKE2b(ephPub || recipientPub, 24), and seals
// the plaintext to the recipient's X25519 public key. The output matches what
// decryptItem expects: base64url-no-pad(ephPub || box).
func sealForKey(t *testing.T, key string, plaintext []byte) string {
	t.Helper()
	recipientPub, _, err := x25519Keys(key)
	if err != nil {
		t.Fatal(err)
	}
	ephPub, ephPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := sealedBoxNonce(*ephPub, recipientPub)
	if err != nil {
		t.Fatal(err)
	}
	sealed := box.Seal(nil, plaintext, &nonce, &recipientPub, ephPriv)
	out := append(append([]byte{}, ephPub[:]...), sealed...)
	return b64.EncodeToString(out)
}

// sampleCaptured marshals a captured-request plaintext with the given fields.
func sampleCaptured(t *testing.T, cr capturedRequest) []byte {
	t.Helper()
	data, err := json.Marshal(cr)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func captured(id, method, path, query string, headers []struct {
	Name     string `json:"name"`
	ValueB64 string `json:"value_b64u"`
}, body []byte) capturedRequest {
	return capturedRequest{
		ID:               id,
		ReceivedAtUnixMs: 1781337600000,
		Method:           method,
		Path:             path,
		Query:            query,
		Headers:          headers,
		BodyB64:          b64.EncodeToString(body),
	}
}

func hdr(name string, value []byte) struct {
	Name     string `json:"name"`
	ValueB64 string `json:"value_b64u"`
} {
	return struct {
		Name     string `json:"name"`
		ValueB64 string `json:"value_b64u"`
	}{Name: name, ValueB64: b64.EncodeToString(value)}
}

func TestDecryptEnvelopeRoundTrip(t *testing.T) {
	headers := []struct {
		Name     string `json:"name"`
		ValueB64 string `json:"value_b64u"`
	}{
		hdr("content-type", []byte("application/json")),
		hdr("x-binary", []byte{0x00, 0xff, 0x10}),
	}
	body := []byte(`{"hello":"world"}`)
	cr := captured("m_abc", "POST", "/i/KEY", "a=1&b=2", headers, body)
	sealed := sealForKey(t, knownSeed, sampleCaptured(t, cr))

	d, err := decryptEnvelope(knownSeed, "m_abc", sealed)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if d.ID != "m_abc" {
		t.Fatalf("id = %q", d.ID)
	}
	if d.Method != "POST" {
		t.Fatalf("method = %q", d.Method)
	}
	if d.Path != "/i/KEY" {
		t.Fatalf("path = %q", d.Path)
	}
	if d.Query != "a=1&b=2" {
		t.Fatalf("query = %q", d.Query)
	}
	if d.ReceivedAtUnixMs != 1781337600000 {
		t.Fatalf("received_at = %d", d.ReceivedAtUnixMs)
	}
	if len(d.Headers) != 2 {
		t.Fatalf("headers = %d", len(d.Headers))
	}
	if d.Headers[0].Name != "content-type" || d.Headers[0].Value != "application/json" {
		t.Fatalf("header[0] = %+v", d.Headers[0])
	}
	if string(d.Headers[1].ValueBytes) != string([]byte{0x00, 0xff, 0x10}) {
		t.Fatalf("header[1] bytes = %v", d.Headers[1].ValueBytes)
	}
	if d.Text() != `{"hello":"world"}` {
		t.Fatalf("text = %q", d.Text())
	}
	var parsed map[string]string
	if err := d.JSON(&parsed); err != nil {
		t.Fatalf("json: %v", err)
	}
	if parsed["hello"] != "world" {
		t.Fatalf("json body = %v", parsed)
	}
}

func TestDecryptEmptyQueryAndBody(t *testing.T) {
	cr := captured("m_empty", "GET", "/i/KEY", "", nil, nil)
	sealed := sealForKey(t, knownSeed, sampleCaptured(t, cr))

	d, err := decryptEnvelope(knownSeed, "m_empty", sealed)
	if err != nil {
		t.Fatal(err)
	}
	if d.Query != "" {
		t.Fatalf("query = %q, want empty", d.Query)
	}
	if len(d.BodyBytes) != 0 {
		t.Fatalf("body = %v, want empty", d.BodyBytes)
	}
	if d.Text() != "" {
		t.Fatalf("text = %q, want empty", d.Text())
	}
	if len(d.Headers) != 0 {
		t.Fatalf("headers = %d, want 0", len(d.Headers))
	}
}

func TestDecryptEnvelopeIDMismatch(t *testing.T) {
	cr := captured("m_real", "GET", "/i/KEY", "", nil, nil)
	sealed := sealForKey(t, knownSeed, sampleCaptured(t, cr))
	_, err := decryptEnvelope(knownSeed, "m_different", sealed)
	if err == nil {
		t.Fatal("expected id mismatch error")
	}
	if err.Error() != "delivery id mismatch" {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestDecryptTooShort(t *testing.T) {
	cases := []struct {
		name   string
		sealed string
	}{
		{"empty", ""},
		{"one byte", b64.EncodeToString([]byte{0x01})},
		{"only ephemeral key", b64.EncodeToString(make([]byte, 32))},
		{"ephemeral plus partial tag", b64.EncodeToString(make([]byte, 32+box.Overhead-1))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decryptItem(knownSeed, tc.sealed)
			if err == nil {
				t.Fatal("expected too-short error")
			}
		})
	}
}

func TestDecryptNotBase64(t *testing.T) {
	if _, err := decryptItem(knownSeed, "@@@not base64@@@"); err == nil {
		t.Fatal("expected base64url decode error")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	cr := captured("m_tamper", "GET", "/i/KEY", "", nil, nil)
	sealed := sealForKey(t, knownSeed, sampleCaptured(t, cr))
	raw, err := b64.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff // flip a byte of the box
	if _, err := decryptItem(knownSeed, b64.EncodeToString(raw)); err == nil {
		t.Fatal("expected authentication failure on tampered ciphertext")
	}
}

func TestDecryptWrongRecipient(t *testing.T) {
	cr := captured("m_wrong", "GET", "/i/KEY", "", nil, nil)
	sealed := sealForKey(t, knownSeed, sampleCaptured(t, cr))
	other := mustGenerate(t)
	if _, err := decryptItem(other, sealed); err == nil {
		t.Fatal("expected decryption failure for wrong recipient")
	}
}

func TestDecryptInvalidPlaintextJSON(t *testing.T) {
	sealed := sealForKey(t, knownSeed, []byte("not json"))
	if _, err := decryptItem(knownSeed, sealed); err == nil {
		t.Fatal("expected JSON parse error")
	}
}

func TestDecryptInvalidBodyB64(t *testing.T) {
	cr := capturedRequest{ID: "m_x", BodyB64: "@@@"}
	sealed := sealForKey(t, knownSeed, sampleCaptured(t, cr))
	if _, err := decryptItem(knownSeed, sealed); err == nil {
		t.Fatal("expected invalid body_b64u error")
	}
}
