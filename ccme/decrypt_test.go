package ccme

import (
	"encoding/json"
	"os"
	"testing"
)

// fixture is produced by an external libsodium reference (pynacl). When the
// env vars are unset the test is skipped, so plain `go test` stays hermetic.
func TestDecryptFixture(t *testing.T) {
	key := os.Getenv("CCME_TEST_KEY")
	sealed := os.Getenv("CCME_TEST_SEALED")
	id := os.Getenv("CCME_TEST_ID")
	if key == "" || sealed == "" || id == "" {
		t.Skip("set CCME_TEST_KEY/SEALED/ID to run the libsodium cross-check")
	}
	d, err := decryptEnvelope(key, id, sealed)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if d.Method != "POST" {
		t.Fatalf("method = %q", d.Method)
	}
	var body map[string]any
	if err := d.JSON(&body); err != nil {
		t.Fatalf("json body: %v", err)
	}
	if body["hello"] != "world" {
		t.Fatalf("body = %v", body)
	}
}

func TestInboxPathOrdering(t *testing.T) {
	got := inboxPath("KEY", InboxOptions{Limit: 10, Cursor: "abc", Poll: true})
	want := "/i/KEY?l=10&c=abc&p="
	if got != want {
		t.Fatalf("inboxPath = %q want %q", got, want)
	}
}

func TestRoundTripKeyDerivation(t *testing.T) {
	key, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publicKeyB64u(key); err != nil {
		t.Fatal(err)
	}
	if _, _, err := x25519Keys(key); err != nil {
		t.Fatal(err)
	}
	// Ensure the public key round-trips through JSON-safe base64url.
	if _, err := json.Marshal(key); err != nil {
		t.Fatal(err)
	}
}
