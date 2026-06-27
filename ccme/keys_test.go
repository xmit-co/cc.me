package ccme

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// knownSeed is a fixed 32-byte seed used to pin deterministic derivations.
// It is the bytes 0,1,2,...,31.
const knownSeed = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

// These constants are derived from knownSeed and asserted to be stable. They
// double as a cross-implementation reference for the other client ports.
const (
	knownPublicKey = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
	knownInboxURL  = "https://cc.me/i/A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
)

func TestGeneratePrivateKey(t *testing.T) {
	t.Run("length and format", func(t *testing.T) {
		key, err := GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		seed, err := b64.DecodeString(key)
		if err != nil {
			t.Fatalf("key is not base64url-no-pad: %v", err)
		}
		if len(seed) != seedLen {
			t.Fatalf("seed length = %d, want %d", len(seed), seedLen)
		}
		if strings.ContainsAny(key, "=+/") {
			t.Fatalf("key %q contains padding or non-url chars", key)
		}
	})

	t.Run("unique across calls", func(t *testing.T) {
		seen := map[string]bool{}
		for i := 0; i < 16; i++ {
			key, err := GeneratePrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			if seen[key] {
				t.Fatalf("duplicate key generated: %q", key)
			}
			seen[key] = true
		}
	})
}

func TestPrivateKeyEmptyPath(t *testing.T) {
	// An empty path means: generate an ephemeral key, do not touch disk.
	key, err := PrivateKey("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seedBytes(key); err != nil {
		t.Fatalf("generated key invalid: %v", err)
	}
}

func TestPrivateKeyCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".cc-me.key")

	key, err := PrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read created key: %v", err)
	}

	if !strings.HasSuffix(string(data), "\n") {
		t.Fatalf("key file %q must end with a newline", string(data))
	}
	if got := strings.TrimSpace(string(data)); got != key {
		t.Fatalf("file contents %q != returned key %q", got, key)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("file mode = %o, want 600", perm)
		}
	}
}

func TestPrivateKeyReusesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reuse.key")

	first, err := PrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("second load %q != first %q", second, first)
	}
}

func TestPrivateKeyResecuresExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not POSIX on windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "loose.key")

	key, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(key+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := PrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != key {
		t.Fatalf("reused key %q != written %q", got, key)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file mode = %o, want 600 after re-securing", perm)
	}
}

func TestPrivateKeyRejectsMalformed(t *testing.T) {
	cases := []struct {
		name     string
		contents string
	}{
		{"not base64url", "this is not base64!!!"},
		{"too short", b64.EncodeToString(make([]byte, 16))},
		{"too long", b64.EncodeToString(make([]byte, 48))},
		{"empty", ""},
		{"padded base64", "AAAA=="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "bad.key")
			if err := os.WriteFile(path, []byte(tc.contents+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := PrivateKey(path); err == nil {
				t.Fatalf("expected error for %q", tc.contents)
			}
		})
	}
}

func TestSeedBytes(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"valid known seed", knownSeed, false},
		{"valid random", mustGenerate(t), false},
		{"non base64url", "@@@", true},
		{"wrong length 31", b64.EncodeToString(make([]byte, 31)), true},
		{"wrong length 33", b64.EncodeToString(make([]byte, 33)), true},
		{"empty", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seed, err := seedBytes(tc.key)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.key)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(seed) != seedLen {
				t.Fatalf("seed length = %d", len(seed))
			}
		})
	}
}

func TestDeterministicPublicKey(t *testing.T) {
	pub, err := publicKeyB64u(knownSeed)
	if err != nil {
		t.Fatal(err)
	}
	if pub != knownPublicKey {
		t.Fatalf("public key = %q, want %q", pub, knownPublicKey)
	}

	// Cross-check against crypto/ed25519 directly.
	seed, err := b64.DecodeString(knownSeed)
	if err != nil {
		t.Fatal(err)
	}
	want := b64.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if pub != want {
		t.Fatalf("public key = %q, crypto/ed25519 = %q", pub, want)
	}
}

func TestDeterministicInboxURL(t *testing.T) {
	c, err := NewClient("", knownSeed)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.InboxURL(InboxOptions{}); got != knownInboxURL {
		t.Fatalf("inbox URL = %q, want %q", got, knownInboxURL)
	}
}

func TestX25519KeysDeterministic(t *testing.T) {
	pub1, sec1, err := x25519Keys(knownSeed)
	if err != nil {
		t.Fatal(err)
	}
	pub2, sec2, err := x25519Keys(knownSeed)
	if err != nil {
		t.Fatal(err)
	}
	if pub1 != pub2 || sec1 != sec2 {
		t.Fatal("x25519Keys is not deterministic")
	}
	// Secret must be clamped per X25519 rules.
	if sec1[0]&7 != 0 {
		t.Fatalf("secret low bits not cleared: %08b", sec1[0])
	}
	if sec1[31]&0x80 != 0 {
		t.Fatalf("secret high bit not cleared: %08b", sec1[31])
	}
	if sec1[31]&0x40 == 0 {
		t.Fatalf("secret bit 254 not set: %08b", sec1[31])
	}
}

func TestX25519KeysRejectsBadSeed(t *testing.T) {
	if _, _, err := x25519Keys("not-base64!!"); err == nil {
		t.Fatal("expected error for malformed seed")
	}
}

func mustGenerate(t *testing.T) string {
	t.Helper()
	key, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}
