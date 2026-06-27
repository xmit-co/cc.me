package ccme

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/edwards25519"
)

const seedLen = 32

// b64 is base64url without padding, used throughout the protocol.
var b64 = base64.RawURLEncoding

// GeneratePrivateKey returns a freshly generated private key: a 32-byte
// Ed25519 seed encoded as base64url without padding.
func GeneratePrivateKey() (string, error) {
	seed := make([]byte, seedLen)
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}
	return b64.EncodeToString(seed), nil
}

// PrivateKey loads the base64url seed from path, creating it (mode 0600) with a
// freshly generated key if it does not exist. An existing file is reused and
// re-secured to 0600. The file contains the base64url seed followed by a
// newline.
func PrivateKey(path string) (string, error) {
	if path == "" {
		return GeneratePrivateKey()
	}

	data, err := os.ReadFile(path)
	if err == nil {
		key := strings.TrimSpace(string(data))
		if _, err := seedBytes(key); err != nil {
			return "", err
		}
		if err := securePrivateKeyFile(path); err != nil {
			return "", err
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	key, err := GeneratePrivateKey()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := securePrivateKeyFile(path); err != nil {
		return "", err
	}
	return key, nil
}

func securePrivateKeyFile(path string) error {
	return os.Chmod(path, 0o600)
}

// seedBytes decodes and validates a base64url private key into its 32-byte seed.
func seedBytes(key string) ([]byte, error) {
	bytes, err := b64.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("privateKey must be base64url: %w", err)
	}
	if len(bytes) != seedLen {
		return nil, errors.New("privateKey must be 32 bytes of base64url")
	}
	return bytes, nil
}

// ed25519Key returns the full Ed25519 private key derived from the seed.
func ed25519Key(key string) (ed25519.PrivateKey, error) {
	seed, err := seedBytes(key)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// publicKeyB64u returns the base64url-no-pad Ed25519 public key for the inbox.
func publicKeyB64u(key string) (string, error) {
	priv, err := ed25519Key(key)
	if err != nil {
		return "", err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return b64.EncodeToString(pub), nil
}

// x25519Keys derives the recipient X25519 public and secret keys from the
// Ed25519 identity, matching libsodium's sealed-box recipient derivation.
func x25519Keys(key string) (pub [32]byte, secret [32]byte, err error) {
	seed, err := seedBytes(key)
	if err != nil {
		return pub, secret, err
	}

	// Secret = clamp(SHA512(seed)[:32])
	// (libsodium crypto_sign_ed25519_sk_to_curve25519).
	h := sha512.Sum512(seed)
	copy(secret[:], h[:32])
	secret[0] &= 248
	secret[31] &= 127
	secret[31] |= 64

	// Public = Montgomery form of the Ed25519 public key.
	edPub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	point, err := edwards25519.NewIdentityPoint().SetBytes(edPub)
	if err != nil {
		return pub, secret, fmt.Errorf("invalid public key: %w", err)
	}
	copy(pub[:], point.BytesMontgomery())
	return pub, secret, nil
}
