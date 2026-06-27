package ccme

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strconv"
	"time"
)

const (
	authVersion         = "cc-me-v1"
	authTimestampHeader = "x-cc-me-timestamp"
	authSignatureHeader = "x-cc-me-signature"
)

// signRequest produces the timestamp and signature headers for a request.
// pathAndQuery must be exactly the request target sent on the wire so the
// signed bytes equal the sent bytes.
func signRequest(key, method, pathAndQuery string, body []byte) (timestamp, signature string, err error) {
	priv, err := ed25519Key(key)
	if err != nil {
		return "", "", err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	bodyHash := b64.EncodeToString(sha256Sum(body))
	canonical := authVersion + "\n" + method + "\n" + pathAndQuery + "\n" + ts + "\n" + bodyHash
	sig := ed25519.Sign(priv, []byte(canonical))
	return ts, b64.EncodeToString(sig), nil
}

func sha256Sum(body []byte) []byte {
	sum := sha256.Sum256(body)
	return sum[:]
}
