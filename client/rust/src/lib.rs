//! Client library for [cc.me](https://cc.me/).
//!
//! Mirrors the canonical JavaScript implementation in `client/js/index.js` and
//! follows the wire protocol described in `client/PROTOCOL.md`. The Rust server
//! in `src/main.rs` is the source of truth for the wire format; the crypto
//! crates here are pinned to the exact versions the server locks so the
//! sealed-box decrypt path interoperates with the server's `PublicKey::seal`.

use std::error::Error as StdError;
use std::fmt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use crypto_box::SecretKey;
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha512};

/// Default cc.me base URL.
pub const DEFAULT_BASE_URL: &str = "https://cc.me/";

const AUTH_VERSION: &str = "cc-me-v1";
const AUTH_TIMESTAMP_HEADER: &str = "x-cc-me-timestamp";
const AUTH_SIGNATURE_HEADER: &str = "x-cc-me-signature";
const SEALED_BOX_PUBLIC_KEY_BYTES: usize = 32;

/// Errors surfaced by the client.
#[derive(Debug)]
pub enum Error {
    /// I/O error (key file access).
    Io(std::io::Error),
    /// The private key was not a valid 32-byte base64url seed.
    InvalidKey(String),
    /// An HTTP transport error or a non-2xx response.
    Http(String),
    /// A response could not be parsed or decrypted.
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::InvalidKey(m) => write!(f, "invalid key: {m}"),
            Error::Http(m) => write!(f, "{m}"),
            Error::Protocol(m) => write!(f, "{m}"),
        }
    }
}

impl StdError for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, Error>;

fn b64u_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn b64u_decode(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value.trim())
        .map_err(|e| Error::Protocol(format!("invalid base64url: {e}")))
}

/// Decode a base64url private key into its 32 seed bytes, validating length.
fn private_key_bytes(key: &str) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(key.trim())
        .map_err(|e| Error::InvalidKey(format!("not base64url: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| Error::InvalidKey("private key must be 32 bytes of base64url".into()))
}

fn signing_key(key: &str) -> Result<SigningKey> {
    Ok(SigningKey::from_bytes(&private_key_bytes(key)?))
}

/// The base64url Ed25519 public key derived from a private key, used to address
/// the inbox.
fn public_key_b64u(key: &str) -> Result<String> {
    let sk = signing_key(key)?;
    Ok(b64u_encode(sk.verifying_key().as_bytes()))
}

/// The recipient X25519 secret key, derived from the Ed25519 seed the same way
/// libsodium's `crypto_sign_ed25519_sk_to_curve25519` does: the first 32 bytes
/// of `SHA512(seed)`. `SecretKey::from_bytes` applies X25519 clamping on use.
fn x25519_secret_key(key: &str) -> Result<SecretKey> {
    let seed = private_key_bytes(key)?;
    let hash = Sha512::digest(seed);
    let mut clamped = [0u8; 32];
    clamped.copy_from_slice(&hash[..32]);
    Ok(SecretKey::from_bytes(clamped))
}

/// Generate a fresh private key: 32 random seed bytes from the OS CSPRNG,
/// base64url-no-pad encoded.
fn generate_private_key() -> Result<String> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| Error::Protocol(format!("randomness failed: {e}")))?;
    Ok(b64u_encode(&seed))
}

/// Load or create the private key.
///
/// With `None`, a fresh random key is generated and returned (not persisted).
/// With a path: if the file exists, its trimmed contents are validated, the
/// file mode is tightened to `0600` (unix), and the key is returned. If it does
/// not exist, a new key is generated, written with mode `0600`, and returned.
pub fn private_key(path: Option<&Path>) -> Result<String> {
    let Some(path) = path else {
        return generate_private_key();
    };

    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let key = contents.trim().to_string();
            // Validate.
            private_key_bytes(&key)?;
            secure_key_file(path)?;
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = generate_private_key()?;
            write_new_key_file(path, &key)?;
            Ok(key)
        }
        Err(e) => Err(Error::Io(e)),
    }
}

#[cfg(unix)]
fn write_new_key_file(path: &Path, key: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(key.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

#[cfg(not(unix))]
fn write_new_key_file(path: &Path, key: &str) -> Result<()> {
    std::fs::write(path, format!("{key}\n"))?;
    Ok(())
}

#[cfg(unix)]
fn secure_key_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn secure_key_file(_path: &Path) -> Result<()> {
    Ok(())
}

fn normalize_base(base_url: &str) -> String {
    if base_url.ends_with('/') {
        base_url.to_string()
    } else {
        format!("{base_url}/")
    }
}

/// Percent-encode a query value (used for the trampoline `at` target and meta
/// verify token). Encodes everything that is not an unreserved character.
fn encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => {
                out.push('%');
                out.push_str(&format!("{other:02X}"));
            }
        }
    }
    out
}

/// Build the trampoline URL: `{base}/?at={target}` plus any extra params.
///
/// `params` are appended in iteration order after `at`.
pub fn trampoline_url(target: &str, base_url: Option<&str>, params: &[(&str, &str)]) -> String {
    let base = normalize_base(base_url.unwrap_or(DEFAULT_BASE_URL));
    let mut url = format!("{base}?at={}", encode_query_value(target));
    for (k, v) in params {
        url.push('&');
        url.push_str(&encode_query_value(k));
        url.push('=');
        url.push_str(&encode_query_value(v));
    }
    url
}

#[derive(Deserialize)]
struct AliasResponse {
    url: String,
}

/// Create (or look up) an alias: `POST {base}/c` with `{"at": target}` →
/// returns the alias URL. Idempotent. No auth.
pub fn create_alias(target: &str, base_url: Option<&str>) -> Result<String> {
    let base = normalize_base(base_url.unwrap_or(DEFAULT_BASE_URL));
    let url = format!("{base}c");
    let body = serde_json::json!({ "at": target }).to_string();
    let resp = ureq::post(&url)
        .set("content-type", "application/json")
        .send_bytes(body.as_bytes());
    let text = read_response(resp)?;
    let parsed: AliasResponse = serde_json::from_str(&text)
        .map_err(|e| Error::Protocol(format!("invalid alias response: {e}")))?;
    Ok(parsed.url)
}

/// Options for listing deliveries (peek/claim).
#[derive(Debug, Default, Clone)]
pub struct ListOptions {
    /// Maximum number of deliveries to return.
    pub limit: Option<u32>,
    /// Opaque cursor (peek only).
    pub cursor: Option<String>,
    /// Long-poll for deliveries.
    pub poll: bool,
}

/// A single header from a decrypted delivery.
#[derive(Debug, Clone)]
pub struct Header {
    /// Lower-cased header name.
    pub name: String,
    /// Header value decoded as UTF-8 (lossy).
    pub value: String,
    /// Raw header value bytes.
    pub value_bytes: Vec<u8>,
}

/// A decrypted delivery (the captured HTTP request).
#[derive(Debug, Clone)]
pub struct Delivery {
    /// Delivery id (matches the envelope id).
    pub id: String,
    /// Server receive time, Unix milliseconds.
    pub received_at_unix_ms: u128,
    /// HTTP method of the captured request.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Request query string, if any (without leading `?`).
    pub query: Option<String>,
    /// Request headers.
    pub headers: Vec<Header>,
    /// Raw request body bytes.
    pub body_bytes: Vec<u8>,
}

impl Delivery {
    /// Body decoded as UTF-8 (lossy).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body_bytes).into_owned()
    }

    /// Body parsed as JSON.
    pub fn json(&self) -> Result<serde_json::Value> {
        serde_json::from_slice(&self.body_bytes)
            .map_err(|e| Error::Protocol(format!("body is not valid JSON: {e}")))
    }
}

/// Response from peek/claim: the count, decrypted deliveries, and (peek) cursor.
#[derive(Debug, Clone)]
pub struct DeliveryResponse {
    /// Number of items returned.
    pub count: u64,
    /// Decrypted deliveries.
    pub requests: Vec<Delivery>,
    /// Cursor to pass to a subsequent peek, if any.
    pub cursor: Option<String>,
}

/// Response from ack/release.
#[derive(Debug, Clone, Deserialize)]
pub struct BatchResponse {
    /// Number acked (ack only).
    #[serde(default)]
    pub acked: u64,
    /// Number released (release only).
    #[serde(default)]
    pub released: u64,
    /// Ids that were not found.
    #[serde(default)]
    pub missing: Vec<String>,
}

#[derive(Deserialize)]
struct Envelope {
    id: String,
    sealed: String,
}

#[derive(Deserialize)]
struct RawDeliveryResponse {
    #[serde(default)]
    count: u64,
    #[serde(default)]
    items: Vec<Envelope>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct RawCapturedHeader {
    name: String,
    value_b64u: String,
}

#[derive(Deserialize)]
struct RawCapturedRequest {
    id: String,
    received_at_unix_ms: u128,
    method: String,
    path: String,
    #[serde(default)]
    query: Option<String>,
    headers: Vec<RawCapturedHeader>,
    body_b64u: String,
}

/// A client bound to a single private key and base URL.
pub struct CcMeClient {
    base_url: String,
    private_key: String,
    public_key: String,
    secret_key: SecretKey,
}

impl CcMeClient {
    /// Build a client. `base_url` defaults to [`DEFAULT_BASE_URL`].
    pub fn new(private_key: String, base_url: Option<&str>) -> Result<Self> {
        // Validate up front and cache derived material.
        let public_key = public_key_b64u(&private_key)?;
        let secret_key = x25519_secret_key(&private_key)?;
        Ok(Self {
            base_url: normalize_base(base_url.unwrap_or(DEFAULT_BASE_URL)),
            private_key,
            public_key,
            secret_key,
        })
    }

    /// The inbox base path, `/i/{publicKey}`.
    fn inbox_path(&self) -> String {
        format!("/i/{}", self.public_key)
    }

    /// The inbox URL with optional `l`, `c`, `p` query params (in that order).
    pub fn inbox_url(&self, options: &ListOptions) -> String {
        format!(
            "{}{}",
            trim_trailing_slash(&self.base_url),
            self.inbox_query(options)
        )
    }

    /// Build the inbox path+query string used both for signing and the wire.
    fn inbox_query(&self, options: &ListOptions) -> String {
        let mut path = self.inbox_path();
        let mut params: Vec<String> = Vec::new();
        if let Some(limit) = options.limit {
            params.push(format!("l={limit}"));
        }
        if let Some(cursor) = &options.cursor {
            params.push(format!("c={}", encode_query_value(cursor)));
        }
        if options.poll {
            params.push("p=".to_string());
        }
        if !params.is_empty() {
            path.push('?');
            path.push_str(&params.join("&"));
        }
        path
    }

    fn protocol_url(&self, protocol: &str) -> String {
        format!(
            "{}{}/{}",
            trim_trailing_slash(&self.base_url),
            self.inbox_path(),
            protocol
        )
    }

    /// Webmention receiver URL.
    pub fn webmention_url(&self) -> String {
        self.protocol_url("webmention")
    }

    /// WebSub receiver URL.
    pub fn websub_url(&self) -> String {
        self.protocol_url("websub")
    }

    /// Slack receiver URL.
    pub fn slack_url(&self) -> String {
        self.protocol_url("slack")
    }

    /// Pingback receiver URL.
    pub fn pingback_url(&self) -> String {
        self.protocol_url("pingback")
    }

    /// Meta (webhooks) receiver URL, with optional verify token (`?v=`).
    pub fn meta_url(&self, verify_token: Option<&str>) -> String {
        let base = self.protocol_url("meta");
        match verify_token {
            Some(token) => format!("{base}?v={}", encode_query_value(token)),
            None => base,
        }
    }

    /// CloudEvents receiver URL.
    pub fn cloud_events_url(&self) -> String {
        self.protocol_url("cloudevents")
    }

    /// Discord interaction receiver URL for the given application public key.
    pub fn discord_url(&self, discord_public_key: &str) -> String {
        format!(
            "{}{}/discord/{}",
            trim_trailing_slash(&self.base_url),
            self.inbox_path(),
            encode_path_segment(discord_public_key)
        )
    }

    /// Peek at deliveries without reserving them (signed GET).
    pub fn peek(&self, options: &ListOptions) -> Result<DeliveryResponse> {
        let path_and_query = self.inbox_query(options);
        let url = format!("{}{}", trim_trailing_slash(&self.base_url), path_and_query);
        let headers = self.sign("GET", &path_and_query, b"")?;
        let mut req = ureq::get(&url);
        for (k, v) in &headers {
            req = req.set(k, v);
        }
        let text = read_response(req.call())?;
        self.decrypt_response(&text)
    }

    /// Claim deliveries, reserving them until ack/release (signed POST).
    pub fn claim(&self, options: &ListOptions) -> Result<DeliveryResponse> {
        let mut body = serde_json::Map::new();
        if let Some(limit) = options.limit {
            body.insert("limit".into(), serde_json::json!(limit));
        }
        if options.poll {
            body.insert("poll".into(), serde_json::json!(true));
        }
        let body = serde_json::Value::Object(body).to_string();
        let path_and_query = format!("{}/claim", self.inbox_path());
        let text = self.signed_post(&path_and_query, body.as_bytes())?;
        self.decrypt_response(&text)
    }

    /// Acknowledge (consume) the given delivery ids.
    pub fn ack(&self, ids: &[String]) -> Result<BatchResponse> {
        self.post_ids("ack", ids)
    }

    /// Release the given delivery ids back to the queue.
    pub fn release(&self, ids: &[String]) -> Result<BatchResponse> {
        self.post_ids("release", ids)
    }

    fn post_ids(&self, action: &str, ids: &[String]) -> Result<BatchResponse> {
        let body = serde_json::json!({ "ids": ids }).to_string();
        let path_and_query = format!("{}/{}", self.inbox_path(), action);
        let text = self.signed_post(&path_and_query, body.as_bytes())?;
        serde_json::from_str(&text)
            .map_err(|e| Error::Protocol(format!("invalid {action} response: {e}")))
    }

    fn signed_post(&self, path_and_query: &str, body: &[u8]) -> Result<String> {
        let url = format!("{}{}", trim_trailing_slash(&self.base_url), path_and_query);
        let headers = self.sign("POST", path_and_query, body)?;
        let mut req = ureq::post(&url).set("content-type", "application/json");
        for (k, v) in &headers {
            req = req.set(k, v);
        }
        read_response(req.send_bytes(body))
    }

    /// Build the two owner-auth headers for a request.
    ///
    /// The `path_and_query` bytes signed here MUST equal the bytes sent on the
    /// wire (protocol consistency rule).
    fn sign(
        &self,
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> Result<Vec<(String, String)>> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Protocol(format!("clock error: {e}")))?
            .as_secs();
        let body_hash = b64u_encode(&Sha256::digest(body));
        let message =
            format!("{AUTH_VERSION}\n{method}\n{path_and_query}\n{timestamp}\n{body_hash}");
        let sk = signing_key(&self.private_key)?;
        let signature = sk.sign(message.as_bytes());
        Ok(vec![
            (AUTH_TIMESTAMP_HEADER.to_string(), timestamp.to_string()),
            (
                AUTH_SIGNATURE_HEADER.to_string(),
                b64u_encode(&signature.to_bytes()),
            ),
        ])
    }

    fn decrypt_response(&self, text: &str) -> Result<DeliveryResponse> {
        let raw: RawDeliveryResponse = serde_json::from_str(text)
            .map_err(|e| Error::Protocol(format!("invalid delivery response: {e}")))?;
        let mut requests = Vec::with_capacity(raw.items.len());
        for envelope in &raw.items {
            requests.push(self.decrypt_envelope(envelope)?);
        }
        Ok(DeliveryResponse {
            count: raw.count,
            requests,
            cursor: raw.cursor,
        })
    }

    fn decrypt_envelope(&self, envelope: &Envelope) -> Result<Delivery> {
        let sealed = b64u_decode(&envelope.sealed)?;
        if sealed.len() <= SEALED_BOX_PUBLIC_KEY_BYTES {
            return Err(Error::Protocol("encrypted delivery is too short".into()));
        }
        let plaintext = self
            .secret_key
            .unseal(&sealed)
            .map_err(|_| Error::Protocol("failed to decrypt delivery".into()))?;
        let delivery = decode_captured_request(&plaintext)?;
        if delivery.id != envelope.id {
            return Err(Error::Protocol("delivery id mismatch".into()));
        }
        Ok(delivery)
    }
}

fn decode_captured_request(plaintext: &[u8]) -> Result<Delivery> {
    let raw: RawCapturedRequest = serde_json::from_slice(plaintext)
        .map_err(|e| Error::Protocol(format!("invalid delivery payload: {e}")))?;
    let body_bytes = b64u_decode(&raw.body_b64u)?;
    let mut headers = Vec::with_capacity(raw.headers.len());
    for h in &raw.headers {
        let value_bytes = b64u_decode(&h.value_b64u)?;
        let value = String::from_utf8_lossy(&value_bytes).into_owned();
        headers.push(Header {
            name: h.name.clone(),
            value,
            value_bytes,
        });
    }
    Ok(Delivery {
        id: raw.id,
        received_at_unix_ms: raw.received_at_unix_ms,
        method: raw.method,
        path: raw.path,
        query: raw.query,
        headers,
        body_bytes,
    })
}

fn trim_trailing_slash(s: &str) -> &str {
    s.strip_suffix('/').unwrap_or(s)
}

/// Percent-encode a single path segment (everything but unreserved).
fn encode_path_segment(value: &str) -> String {
    encode_query_value(value)
}

#[derive(Deserialize)]
struct ErrorBody {
    error: Option<String>,
}

/// Convert a ureq result into a body string, surfacing `{"error": ...}`.
fn read_response(result: std::result::Result<ureq::Response, ureq::Error>) -> Result<String> {
    match result {
        Ok(resp) => resp
            .into_string()
            .map_err(|e| Error::Http(format!("failed to read response: {e}"))),
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            let message = serde_json::from_str::<ErrorBody>(&body)
                .ok()
                .and_then(|b| b.error)
                .unwrap_or_else(|| format!("cc.me request failed with {code}"));
            Err(Error::Http(message))
        }
        Err(ureq::Error::Transport(t)) => Err(Error::Http(format!("transport error: {t}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_box::aead::rand_core::{OsRng, TryRngCore};
    use crypto_box::PublicKey;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use ed25519_dalek::VerifyingKey;

    const SEED: [u8; 32] = [7u8; 32];

    fn key_b64u() -> String {
        b64u_encode(&SEED)
    }

    fn ed25519_pubkey_b64u() -> String {
        let vk = SigningKey::from_bytes(&SEED).verifying_key();
        b64u_encode(vk.as_bytes())
    }

    // Reproduces the server's seal path: derive the X25519 public key from the
    // Ed25519 verifying key the same way `derive_x25519_public_key` does, then
    // `PublicKey::seal`.
    fn server_seal(plaintext: &[u8]) -> String {
        server_seal_for(&SEED, plaintext)
    }

    fn server_seal_for(seed: &[u8; 32], plaintext: &[u8]) -> String {
        let vk: VerifyingKey = SigningKey::from_bytes(seed).verifying_key();
        let edwards = CompressedEdwardsY(vk.to_bytes()).decompress().unwrap();
        let pk = PublicKey::from_slice(edwards.to_montgomery().as_bytes()).unwrap();
        let sealed = pk.seal(&mut OsRng.unwrap_err(), plaintext).unwrap();
        b64u_encode(&sealed)
    }

    /// Build a sealed envelope-response JSON for a single delivery payload.
    fn sealed_response(id: &str, plaintext: &serde_json::Value) -> String {
        let sealed = server_seal(plaintext.to_string().as_bytes());
        serde_json::json!({
            "count": 1,
            "items": [{ "id": id, "sealed": sealed }],
            "cursor": serde_json::Value::Null,
        })
        .to_string()
    }

    // ====================================================================
    // base64url round-trips and no-pad behaviour
    // ====================================================================

    #[test]
    fn b64u_roundtrip_arbitrary_bytes() {
        for len in [0usize, 1, 2, 3, 4, 5, 16, 31, 32, 33, 100, 4096] {
            let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            let encoded = b64u_encode(&data);
            assert_eq!(b64u_decode(&encoded).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn b64u_has_no_padding() {
        // 1, 2 input bytes would normally produce '=' padding in standard b64.
        assert!(!b64u_encode(b"a").contains('='));
        assert!(!b64u_encode(b"ab").contains('='));
        assert!(!b64u_encode(b"abcde").contains('='));
    }

    #[test]
    fn b64u_uses_url_safe_alphabet() {
        // 0xFB 0xFF encodes to bytes that exercise the '+'/'/' -> '-'/'_' map.
        let encoded = b64u_encode(&[0xfb, 0xff, 0xbf]);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert_eq!(b64u_decode(&encoded).unwrap(), vec![0xfb, 0xff, 0xbf]);
    }

    #[test]
    fn b64u_empty_is_empty_string() {
        assert_eq!(b64u_encode(b""), "");
        assert_eq!(b64u_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn b64u_decode_trims_whitespace() {
        let encoded = b64u_encode(b"trimmed");
        let padded = format!("  {encoded}\n");
        assert_eq!(b64u_decode(&padded).unwrap(), b"trimmed");
    }

    #[test]
    fn b64u_decode_rejects_invalid() {
        // '!' is not in the base64url alphabet.
        assert!(b64u_decode("not valid!!").is_err());
    }

    // ====================================================================
    // Keys
    // ====================================================================

    #[test]
    fn in_memory_private_key_is_32_byte_seed() {
        let key = private_key(None).unwrap();
        let bytes = b64u_decode(&key).unwrap();
        assert_eq!(bytes.len(), 32);
        // Round-trips through validation.
        assert_eq!(private_key_bytes(&key).unwrap().to_vec(), bytes);
    }

    #[test]
    fn generated_keys_are_random() {
        let a = private_key(None).unwrap();
        let b = private_key(None).unwrap();
        assert_ne!(a, b, "two generated keys should differ");
    }

    #[test]
    fn private_key_bytes_rejects_wrong_length() {
        // 31 bytes.
        let short = b64u_encode(&[0u8; 31]);
        assert!(matches!(
            private_key_bytes(&short),
            Err(Error::InvalidKey(_))
        ));
        // 33 bytes.
        let long = b64u_encode(&[0u8; 33]);
        assert!(matches!(
            private_key_bytes(&long),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn private_key_bytes_rejects_non_base64url() {
        assert!(matches!(
            private_key_bytes("definitely not base64!!"),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn fixed_seed_has_deterministic_public_key() {
        // The Ed25519 public key for the all-7s seed is stable across runs.
        let expected = ed25519_pubkey_b64u();
        assert_eq!(public_key_b64u(&key_b64u()).unwrap(), expected);
        // 32 raw bytes once decoded.
        assert_eq!(b64u_decode(&expected).unwrap().len(), 32);
    }

    #[test]
    fn fixed_seed_has_deterministic_inbox_url() {
        let client = CcMeClient::new(key_b64u(), Some("https://cc.me/")).unwrap();
        assert_eq!(
            client.inbox_url(&ListOptions::default()),
            format!("https://cc.me/i/{}", ed25519_pubkey_b64u())
        );
    }

    #[test]
    fn private_key_file_has_trailing_newline() {
        let dir = std::env::temp_dir().join(format!("cc-me-nl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key");
        let _ = std::fs::remove_file(&path);
        let key = private_key(Some(&path)).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert_eq!(raw, format!("{key}\n"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn newly_created_key_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("cc-me-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key");
        let _ = std::fs::remove_file(&path);
        private_key(Some(&path)).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn existing_key_file_mode_is_tightened_on_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("cc-me-tighten-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key");
        let _ = std::fs::remove_file(&path);
        // Write a valid key with loose permissions.
        std::fs::write(&path, format!("{}\n", key_b64u())).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let reused = private_key(Some(&path)).unwrap();
        assert_eq!(reused, key_b64u());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode tightened to 0600");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn private_key_file_reused_on_second_call() {
        let dir = std::env::temp_dir().join(format!("cc-me-reuse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key");
        let _ = std::fs::remove_file(&path);
        let first = private_key(Some(&path)).unwrap();
        let second = private_key(Some(&path)).unwrap();
        let third = private_key(Some(&path)).unwrap();
        assert_eq!(first, second);
        assert_eq!(second, third);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn private_key_file_rejects_malformed_contents() {
        let dir = std::env::temp_dir().join(format!("cc-me-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key");
        // Wrong length (not 32 bytes once decoded).
        std::fs::write(&path, b64u_encode(b"too-short")).unwrap();
        assert!(matches!(
            private_key(Some(&path)),
            Err(Error::InvalidKey(_))
        ));
        // Not base64url at all.
        std::fs::write(&path, "this is not a key!!").unwrap();
        assert!(matches!(
            private_key(Some(&path)),
            Err(Error::InvalidKey(_))
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn client_new_rejects_bad_key() {
        assert!(matches!(
            CcMeClient::new("nope!!".into(), None),
            Err(Error::InvalidKey(_))
        ));
    }

    // ====================================================================
    // Signing
    // ====================================================================

    #[test]
    fn canonical_string_format_for_get() {
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        let headers = client.sign("GET", "/i/KEY?l=10&p=", b"").unwrap();
        let ts: u64 = headers[0].1.parse().unwrap();
        // Empty body hash is SHA256 of zero bytes.
        let empty_hash = b64u_encode(&Sha256::digest(b""));
        let message = format!("cc-me-v1\nGET\n/i/KEY?l=10&p=\n{ts}\n{empty_hash}");
        let vk = SigningKey::from_bytes(&SEED).verifying_key();
        let sig =
            ed25519_dalek::Signature::from_slice(&b64u_decode(&headers[1].1).unwrap()).unwrap();
        use ed25519_dalek::Verifier;
        vk.verify(message.as_bytes(), &sig).expect("verifies");
    }

    #[test]
    fn empty_body_hash_is_sha256_of_empty() {
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        let headers = client.sign("GET", "/x", b"").unwrap();
        let ts: u64 = headers[0].1.parse().unwrap();
        // sha256("") = e3b0c442... ; base64url-no-pad form:
        let empty_hash = b64u_encode(&Sha256::digest(b""));
        assert_eq!(empty_hash, "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
        let message = format!("cc-me-v1\nGET\n/x\n{ts}\n{empty_hash}");
        let vk = SigningKey::from_bytes(&SEED).verifying_key();
        let sig =
            ed25519_dalek::Signature::from_slice(&b64u_decode(&headers[1].1).unwrap()).unwrap();
        use ed25519_dalek::Verifier;
        vk.verify(message.as_bytes(), &sig).unwrap();
    }

    #[test]
    fn signature_headers_have_expected_names() {
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        let headers = client.sign("POST", "/y", b"body").unwrap();
        assert_eq!(headers[0].0, "x-cc-me-timestamp");
        assert_eq!(headers[1].0, "x-cc-me-signature");
        // Signature is base64url-no-pad of 64 bytes.
        let sig_bytes = b64u_decode(&headers[1].1).unwrap();
        assert_eq!(sig_bytes.len(), 64);
    }

    #[test]
    fn signature_changes_with_body() {
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        // Pin the same timestamp by recomputing manually so only the body differs.
        let body_hash_a = b64u_encode(&Sha256::digest(b"a"));
        let body_hash_b = b64u_encode(&Sha256::digest(b"b"));
        assert_ne!(body_hash_a, body_hash_b);
        // And the produced signature differs across distinct bodies.
        let ha = client.sign("POST", "/p", b"a").unwrap();
        let hb = client.sign("POST", "/p", b"b").unwrap();
        // With overwhelming probability ts is equal (same second); even if not,
        // the messages differ, so signatures differ.
        if ha[0].1 == hb[0].1 {
            assert_ne!(ha[1].1, hb[1].1);
        }
    }

    #[test]
    fn signed_path_with_query_equals_requested() {
        // inbox_query builds the exact bytes used for both signing and the wire.
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        let opts = ListOptions {
            limit: Some(7),
            cursor: Some("c1".into()),
            poll: true,
        };
        let pq = client.inbox_query(&opts);
        assert_eq!(pq, format!("/i/{}?l=7&c=c1&p=", ed25519_pubkey_b64u()));
        // The inbox_url is base + that same path+query.
        assert_eq!(
            client.inbox_url(&opts),
            format!("https://cc.me/i/{}?l=7&c=c1&p=", ed25519_pubkey_b64u())
        );
    }

    // ====================================================================
    // URL builders
    // ====================================================================

    #[test]
    fn trampoline_default_base() {
        let url = trampoline_url("https://x/cb", None, &[]);
        assert_eq!(url, "https://cc.me/?at=https%3A%2F%2Fx%2Fcb");
    }

    #[test]
    fn trampoline_base_override_without_trailing_slash() {
        let url = trampoline_url("t", Some("https://alt.example"), &[]);
        assert_eq!(url, "https://alt.example/?at=t");
    }

    #[test]
    fn trampoline_params_in_order() {
        let url = trampoline_url(
            "t",
            Some("https://cc.me/"),
            &[("a", "1"), ("b", "2"), ("c", "3")],
        );
        assert_eq!(url, "https://cc.me/?at=t&a=1&b=2&c=3");
    }

    #[test]
    fn encode_query_value_leaves_unreserved() {
        assert_eq!(encode_query_value("AZaz09-_.~"), "AZaz09-_.~");
    }

    #[test]
    fn encode_query_value_percent_encodes_reserved() {
        assert_eq!(encode_query_value("a b&c=d?/"), "a%20b%26c%3Dd%3F%2F");
        assert_eq!(encode_query_value("/"), "%2F");
    }

    #[test]
    fn inbox_url_param_order_l_c_p() {
        let client = CcMeClient::new(key_b64u(), Some("https://cc.me/")).unwrap();
        let pk = ed25519_pubkey_b64u();
        assert_eq!(
            client.inbox_url(&ListOptions {
                limit: Some(3),
                cursor: Some("cur".into()),
                poll: true,
            }),
            format!("https://cc.me/i/{pk}?l=3&c=cur&p=")
        );
        // Cursor only.
        assert_eq!(
            client.inbox_url(&ListOptions {
                cursor: Some("c".into()),
                ..Default::default()
            }),
            format!("https://cc.me/i/{pk}?c=c")
        );
        // Poll only -> empty value.
        assert_eq!(
            client.inbox_url(&ListOptions {
                poll: true,
                ..Default::default()
            }),
            format!("https://cc.me/i/{pk}?p=")
        );
        // Limit only.
        assert_eq!(
            client.inbox_url(&ListOptions {
                limit: Some(1),
                ..Default::default()
            }),
            format!("https://cc.me/i/{pk}?l=1")
        );
    }

    #[test]
    fn inbox_url_encodes_cursor_value() {
        let client = CcMeClient::new(key_b64u(), Some("https://cc.me/")).unwrap();
        let pk = ed25519_pubkey_b64u();
        assert_eq!(
            client.inbox_url(&ListOptions {
                cursor: Some("a b".into()),
                ..Default::default()
            }),
            format!("https://cc.me/i/{pk}?c=a%20b")
        );
    }

    #[test]
    fn all_protocol_urls() {
        let client = CcMeClient::new(key_b64u(), Some("https://cc.me/")).unwrap();
        let pk = ed25519_pubkey_b64u();
        assert_eq!(
            client.webmention_url(),
            format!("https://cc.me/i/{pk}/webmention")
        );
        assert_eq!(client.websub_url(), format!("https://cc.me/i/{pk}/websub"));
        assert_eq!(client.slack_url(), format!("https://cc.me/i/{pk}/slack"));
        assert_eq!(
            client.pingback_url(),
            format!("https://cc.me/i/{pk}/pingback")
        );
        assert_eq!(
            client.cloud_events_url(),
            format!("https://cc.me/i/{pk}/cloudevents")
        );
        assert_eq!(client.meta_url(None), format!("https://cc.me/i/{pk}/meta"));
    }

    #[test]
    fn meta_url_with_and_without_token() {
        let client = CcMeClient::new(key_b64u(), Some("https://cc.me/")).unwrap();
        let pk = ed25519_pubkey_b64u();
        assert_eq!(client.meta_url(None), format!("https://cc.me/i/{pk}/meta"));
        assert_eq!(
            client.meta_url(Some("tok")),
            format!("https://cc.me/i/{pk}/meta?v=tok")
        );
        assert_eq!(
            client.meta_url(Some("a b/c")),
            format!("https://cc.me/i/{pk}/meta?v=a%20b%2Fc")
        );
    }

    #[test]
    fn discord_url_path_and_encoding() {
        let client = CcMeClient::new(key_b64u(), Some("https://cc.me/")).unwrap();
        let pk = ed25519_pubkey_b64u();
        assert_eq!(
            client.discord_url("app"),
            format!("https://cc.me/i/{pk}/discord/app")
        );
        assert_eq!(
            client.discord_url("a/b"),
            format!("https://cc.me/i/{pk}/discord/a%2Fb")
        );
    }

    #[test]
    fn base_url_normalisation_adds_trailing_slash() {
        let with = CcMeClient::new(key_b64u(), Some("https://cc.me")).unwrap();
        let without = CcMeClient::new(key_b64u(), Some("https://cc.me/")).unwrap();
        assert_eq!(
            with.inbox_url(&ListOptions::default()),
            without.inbox_url(&ListOptions::default())
        );
    }

    #[test]
    fn default_base_url_constant() {
        assert_eq!(DEFAULT_BASE_URL, "https://cc.me/");
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        assert!(client
            .inbox_url(&ListOptions::default())
            .starts_with("https://cc.me/i/"));
    }

    // ====================================================================
    // Sealed-box decryption variants
    // ====================================================================

    #[test]
    fn decrypts_empty_body() {
        let id = "m_empty";
        let payload = serde_json::json!({
            "id": id,
            "received_at_unix_ms": 1u64,
            "method": "GET",
            "path": "/i/x",
            "query": serde_json::Value::Null,
            "headers": [],
            "body_b64u": "",
        });
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        let resp = client
            .decrypt_response(&sealed_response(id, &payload))
            .unwrap();
        let d = &resp.requests[0];
        assert!(d.body_bytes.is_empty());
        assert_eq!(d.text(), "");
        assert!(d.query.is_none());
        assert!(d.headers.is_empty());
    }

    #[test]
    fn decrypts_query_none_vs_some() {
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        // query absent entirely.
        let no_query = serde_json::json!({
            "id": "m_a", "received_at_unix_ms": 1u64, "method": "GET",
            "path": "/p", "headers": [], "body_b64u": "",
        });
        let d = &client
            .decrypt_response(&sealed_response("m_a", &no_query))
            .unwrap()
            .requests[0];
        assert_eq!(d.query, None);

        // query present.
        let with_query = serde_json::json!({
            "id": "m_b", "received_at_unix_ms": 1u64, "method": "GET",
            "path": "/p", "query": "x=1", "headers": [], "body_b64u": "",
        });
        let d = &client
            .decrypt_response(&sealed_response("m_b", &with_query))
            .unwrap()
            .requests[0];
        assert_eq!(d.query.as_deref(), Some("x=1"));
    }

    #[test]
    fn decrypts_various_body_sizes() {
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        for len in [0usize, 1, 16, 1024, 4096, 9000] {
            let body: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let id = format!("m_{len}");
            let payload = serde_json::json!({
                "id": id, "received_at_unix_ms": 1u64, "method": "POST",
                "path": "/p", "headers": [], "body_b64u": b64u_encode(&body),
            });
            let resp = client
                .decrypt_response(&sealed_response(&id, &payload))
                .unwrap();
            assert_eq!(resp.requests[0].body_bytes, body, "len {len}");
        }
    }

    #[test]
    fn decrypts_many_headers_with_value_and_value_bytes() {
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        let mut headers = Vec::new();
        for i in 0..25 {
            headers.push(serde_json::json!({
                "name": format!("x-h{i}"),
                "value_b64u": b64u_encode(format!("v{i}").as_bytes()),
            }));
        }
        let payload = serde_json::json!({
            "id": "m_h", "received_at_unix_ms": 1u64, "method": "POST",
            "path": "/p", "headers": headers, "body_b64u": "",
        });
        let resp = client
            .decrypt_response(&sealed_response("m_h", &payload))
            .unwrap();
        let d = &resp.requests[0];
        assert_eq!(d.headers.len(), 25);
        for (i, h) in d.headers.iter().enumerate() {
            assert_eq!(h.name, format!("x-h{i}"));
            assert_eq!(h.value, format!("v{i}"));
            assert_eq!(h.value_bytes, format!("v{i}").into_bytes());
        }
    }

    #[test]
    fn decrypts_non_utf8_header_value_lossily() {
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        let raw = vec![0xff, 0xfe, 0x41];
        let payload = serde_json::json!({
            "id": "m_nb", "received_at_unix_ms": 1u64, "method": "GET", "path": "/p",
            "headers": [{"name": "x-bin", "value_b64u": b64u_encode(&raw)}],
            "body_b64u": "",
        });
        let resp = client
            .decrypt_response(&sealed_response("m_nb", &payload))
            .unwrap();
        let h = &resp.requests[0].headers[0];
        assert_eq!(h.value_bytes, raw);
        // value is lossy UTF-8 and still ends with the valid 'A'.
        assert!(h.value.ends_with('A'));
    }

    #[test]
    fn json_helper_parses_body() {
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        let payload = serde_json::json!({
            "id": "m_j", "received_at_unix_ms": 1u64, "method": "POST", "path": "/p",
            "headers": [], "body_b64u": b64u_encode(br#"{"k":[1,2,3]}"#),
        });
        let resp = client
            .decrypt_response(&sealed_response("m_j", &payload))
            .unwrap();
        assert_eq!(resp.requests[0].json().unwrap()["k"][1], 2);
    }

    #[test]
    fn json_helper_errors_on_non_json_body() {
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        let payload = serde_json::json!({
            "id": "m_nj", "received_at_unix_ms": 1u64, "method": "POST", "path": "/p",
            "headers": [], "body_b64u": b64u_encode(b"not json"),
        });
        let resp = client
            .decrypt_response(&sealed_response("m_nj", &payload))
            .unwrap();
        assert!(matches!(resp.requests[0].json(), Err(Error::Protocol(_))));
    }

    #[test]
    fn too_short_ciphertext_errors() {
        // Sealed box must be longer than the 32-byte ephemeral public key.
        let response = serde_json::json!({
            "count": 1,
            "items": [{ "id": "m_short", "sealed": b64u_encode(&[0u8; 16]) }],
        })
        .to_string();
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        let err = client.decrypt_response(&response).unwrap_err();
        assert!(matches!(err, Error::Protocol(m) if m.contains("too short")));
    }

    #[test]
    fn exactly_32_byte_ciphertext_errors() {
        let response = serde_json::json!({
            "count": 1,
            "items": [{ "id": "m_32", "sealed": b64u_encode(&[0u8; 32]) }],
        })
        .to_string();
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        let err = client.decrypt_response(&response).unwrap_err();
        assert!(matches!(err, Error::Protocol(m) if m.contains("too short")));
    }

    #[test]
    fn undecryptable_ciphertext_errors() {
        // 33+ bytes of garbage: passes the length check but fails to unseal.
        let response = serde_json::json!({
            "count": 1,
            "items": [{ "id": "m_g", "sealed": b64u_encode(&[3u8; 80]) }],
        })
        .to_string();
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        let err = client.decrypt_response(&response).unwrap_err();
        assert!(matches!(err, Error::Protocol(m) if m.contains("decrypt")));
    }

    #[test]
    fn ciphertext_for_wrong_recipient_fails_to_decrypt() {
        // Seal to a different identity; our client must not be able to open it.
        let other_seed = [42u8; 32];
        let payload = serde_json::json!({
            "id": "m_w", "received_at_unix_ms": 1u64, "method": "GET", "path": "/p",
            "headers": [], "body_b64u": "",
        })
        .to_string();
        let sealed = server_seal_for(&other_seed, payload.as_bytes());
        let response = serde_json::json!({
            "count": 1, "items": [{ "id": "m_w", "sealed": sealed }],
        })
        .to_string();
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        assert!(client.decrypt_response(&response).is_err());
    }

    #[test]
    fn decrypts_multiple_deliveries() {
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        let mut items = Vec::new();
        for i in 0..3 {
            let id = format!("m_{i}");
            let payload = serde_json::json!({
                "id": id, "received_at_unix_ms": (i as u64), "method": "GET",
                "path": format!("/p/{i}"), "headers": [],
                "body_b64u": b64u_encode(format!("body{i}").as_bytes()),
            })
            .to_string();
            items.push(serde_json::json!({ "id": id, "sealed": server_seal(payload.as_bytes()) }));
        }
        let response = serde_json::json!({ "count": 3, "items": items }).to_string();
        let resp = client.decrypt_response(&response).unwrap();
        assert_eq!(resp.requests.len(), 3);
        for (i, d) in resp.requests.iter().enumerate() {
            assert_eq!(d.id, format!("m_{i}"));
            assert_eq!(d.text(), format!("body{i}"));
        }
    }

    #[test]
    fn empty_delivery_response_decodes() {
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        let resp = client
            .decrypt_response(r#"{"count":0,"items":[],"cursor":null}"#)
            .unwrap();
        assert_eq!(resp.count, 0);
        assert!(resp.requests.is_empty());
        assert!(resp.cursor.is_none());
    }

    #[test]
    fn malformed_delivery_response_errors() {
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        assert!(matches!(
            client.decrypt_response("not json"),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn batch_response_defaults_missing_fields() {
        let r: BatchResponse = serde_json::from_str("{}").unwrap();
        assert_eq!(r.acked, 0);
        assert_eq!(r.released, 0);
        assert!(r.missing.is_empty());
    }

    #[test]
    fn error_display_passes_through_http_and_protocol() {
        assert_eq!(Error::Http("boom".into()).to_string(), "boom");
        assert_eq!(Error::Protocol("oops".into()).to_string(), "oops");
        assert!(Error::InvalidKey("k".into())
            .to_string()
            .contains("invalid key"));
    }

    #[test]
    fn decrypts_a_server_sealed_delivery() {
        let id = "m_test123";
        let pubkey = ed25519_pubkey_b64u();
        let plaintext = serde_json::json!({
            "id": id,
            "received_at_unix_ms": 1781337600000u64,
            "method": "POST",
            "path": format!("/i/{pubkey}/slack"),
            "query": "a=1&b=2",
            "headers": [
                {"name": "content-type", "value_b64u": b64u_encode(b"application/json")}
            ],
            "body_b64u": b64u_encode(b"{\"hello\":\"world\"}"),
        })
        .to_string();
        let sealed = server_seal(plaintext.as_bytes());

        let response = serde_json::json!({
            "count": 1,
            "items": [{ "id": id, "sealed": sealed }],
            "cursor": serde_json::Value::Null,
        })
        .to_string();

        let client = CcMeClient::new(key_b64u(), Some("https://cc.me/")).unwrap();
        let decoded = client.decrypt_response(&response).unwrap();
        assert_eq!(decoded.count, 1);
        assert_eq!(decoded.requests.len(), 1);
        let d = &decoded.requests[0];
        assert_eq!(d.id, id);
        assert_eq!(d.method, "POST");
        assert_eq!(d.query.as_deref(), Some("a=1&b=2"));
        assert_eq!(d.text(), "{\"hello\":\"world\"}");
        assert_eq!(d.headers[0].name, "content-type");
        assert_eq!(d.headers[0].value, "application/json");
        assert_eq!(d.json().unwrap()["hello"], "world");
    }

    #[test]
    fn rejects_id_mismatch() {
        let plaintext = serde_json::json!({
            "id": "m_real",
            "received_at_unix_ms": 1u64,
            "method": "GET",
            "path": "/i/x",
            "query": serde_json::Value::Null,
            "headers": [],
            "body_b64u": "",
        })
        .to_string();
        let sealed = server_seal(plaintext.as_bytes());
        let response = serde_json::json!({
            "count": 1,
            "items": [{ "id": "m_envelope", "sealed": sealed }],
        })
        .to_string();
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        let err = client.decrypt_response(&response).unwrap_err();
        assert!(matches!(err, Error::Protocol(m) if m.contains("id mismatch")));
    }

    #[test]
    fn signs_with_canonical_string() {
        let client = CcMeClient::new(key_b64u(), None).unwrap();
        let headers = client.sign("POST", "/i/KEY/claim", b"{}").unwrap();
        let ts: u64 = headers[0].1.parse().unwrap();
        let sig_b64u = &headers[1].1;
        let body_hash = b64u_encode(&Sha256::digest(b"{}"));
        let message = format!("cc-me-v1\nPOST\n/i/KEY/claim\n{ts}\n{body_hash}");
        // Verify the signature with the Ed25519 verifying key.
        let vk = SigningKey::from_bytes(&SEED).verifying_key();
        let sig_bytes = b64u_decode(sig_b64u).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).expect("valid signature length");
        use ed25519_dalek::Verifier;
        vk.verify(message.as_bytes(), &sig)
            .expect("signature verifies");
    }

    #[test]
    fn builds_urls() {
        let client = CcMeClient::new(key_b64u(), Some("https://cc.me/")).unwrap();
        let pk = ed25519_pubkey_b64u();
        assert_eq!(
            client.inbox_url(&ListOptions::default()),
            format!("https://cc.me/i/{pk}")
        );
        assert_eq!(
            client.inbox_url(&ListOptions {
                limit: Some(10),
                poll: true,
                ..Default::default()
            }),
            format!("https://cc.me/i/{pk}?l=10&p=")
        );
        assert_eq!(
            client.webmention_url(),
            format!("https://cc.me/i/{pk}/webmention")
        );
        assert_eq!(
            client.meta_url(Some("tok en")),
            format!("https://cc.me/i/{pk}/meta?v=tok%20en")
        );
        assert_eq!(
            client.discord_url("app123"),
            format!("https://cc.me/i/{pk}/discord/app123")
        );
    }

    #[test]
    fn trampoline_encodes_target() {
        assert_eq!(
            trampoline_url(
                "https://x/cb?a=1",
                Some("https://cc.me/"),
                &[("state", "s 1")]
            ),
            "https://cc.me/?at=https%3A%2F%2Fx%2Fcb%3Fa%3D1&state=s%201"
        );
    }

    #[test]
    fn private_key_roundtrips_through_file() {
        let dir = std::env::temp_dir().join(format!("cc-me-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key");
        let _ = std::fs::remove_file(&path);
        let created = private_key(Some(&path)).unwrap();
        let reused = private_key(Some(&path)).unwrap();
        assert_eq!(created, reused);
        private_key_bytes(&created).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_file(&path);
    }
}
