package ccme

import (
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"
)

const (
	sealedBoxPublicKeyBytes = 32
	sealedBoxNonceBytes     = 24
	// box.Overhead is the Poly1305 authentication tag length.
	sealedBoxOverhead = box.Overhead
)

// Header is a single captured request header. Value is the UTF-8 decoding of
// ValueBytes; ValueBytes holds the raw bytes.
type Header struct {
	Name       string
	Value      string
	ValueBytes []byte
}

// Delivery is a decrypted captured request.
type Delivery struct {
	ID               string
	ReceivedAtUnixMs int64
	Method           string
	Path             string
	Query            string
	Headers          []Header
	BodyBytes        []byte
}

// Text returns the body decoded as a UTF-8 string.
func (d *Delivery) Text() string {
	return string(d.BodyBytes)
}

// JSON unmarshals the body into v.
func (d *Delivery) JSON(v any) error {
	return json.Unmarshal(d.BodyBytes, v)
}

// capturedRequest mirrors the decrypted plaintext JSON shape.
type capturedRequest struct {
	ID               string `json:"id"`
	ReceivedAtUnixMs int64  `json:"received_at_unix_ms"`
	Method           string `json:"method"`
	Path             string `json:"path"`
	Query            string `json:"query"`
	Headers          []struct {
		Name     string `json:"name"`
		ValueB64 string `json:"value_b64u"`
	} `json:"headers"`
	BodyB64 string `json:"body_b64u"`
}

// decryptEnvelope opens a sealed delivery and verifies the inner id matches the
// envelope id.
func decryptEnvelope(key, id, sealed string) (*Delivery, error) {
	delivery, err := decryptItem(key, sealed)
	if err != nil {
		return nil, err
	}
	if delivery.ID != id {
		return nil, errors.New("delivery id mismatch")
	}
	return delivery, nil
}

func decryptItem(key, sealed string) (*Delivery, error) {
	raw, err := b64.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("sealed delivery is not base64url: %w", err)
	}
	if len(raw) < sealedBoxPublicKeyBytes+sealedBoxOverhead {
		return nil, errors.New("encrypted delivery is too short")
	}

	recipientPub, recipientSecret, err := x25519Keys(key)
	if err != nil {
		return nil, err
	}

	var eph [32]byte
	copy(eph[:], raw[:sealedBoxPublicKeyBytes])
	ciphertext := raw[sealedBoxPublicKeyBytes:]

	nonce, err := sealedBoxNonce(eph, recipientPub)
	if err != nil {
		return nil, err
	}

	plaintext, ok := box.Open(nil, ciphertext, &nonce, &eph, &recipientSecret)
	if !ok {
		return nil, errors.New("failed to decrypt delivery")
	}
	return decodeCapturedRequest(plaintext)
}

// sealedBoxNonce = BLAKE2b(ephemeralPublicKey || recipientPublicKey, 24 bytes).
func sealedBoxNonce(eph, recipientPub [32]byte) ([24]byte, error) {
	var nonce [24]byte
	h, err := blake2b.New(sealedBoxNonceBytes, nil)
	if err != nil {
		return nonce, err
	}
	h.Write(eph[:])
	h.Write(recipientPub[:])
	copy(nonce[:], h.Sum(nil))
	return nonce, nil
}

func decodeCapturedRequest(plaintext []byte) (*Delivery, error) {
	var parsed capturedRequest
	if err := json.Unmarshal(plaintext, &parsed); err != nil {
		return nil, fmt.Errorf("invalid delivery plaintext: %w", err)
	}

	bodyBytes, err := b64.DecodeString(parsed.BodyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid body_b64u: %w", err)
	}

	headers := make([]Header, 0, len(parsed.Headers))
	for _, h := range parsed.Headers {
		valueBytes, err := b64.DecodeString(h.ValueB64)
		if err != nil {
			return nil, fmt.Errorf("invalid header value_b64u: %w", err)
		}
		headers = append(headers, Header{
			Name:       h.Name,
			Value:      string(valueBytes),
			ValueBytes: valueBytes,
		})
	}

	return &Delivery{
		ID:               parsed.ID,
		ReceivedAtUnixMs: parsed.ReceivedAtUnixMs,
		Method:           parsed.Method,
		Path:             parsed.Path,
		Query:            parsed.Query,
		Headers:          headers,
		BodyBytes:        bodyBytes,
	}, nil
}
