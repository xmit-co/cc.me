//! Integration tests for [`CcMeClient`] methods against a local mock HTTP
//! server. These exercise only the crate's public API (no TLS, no network).

mod common;

use common::{MockResponse, MockServer};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cc_me::{CcMeClient, ListOptions};
use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

const SEED: [u8; 32] = [7u8; 32];

fn key_b64u() -> String {
    URL_SAFE_NO_PAD.encode(SEED)
}

fn pubkey_b64u() -> String {
    let vk = SigningKey::from_bytes(&SEED).verifying_key();
    URL_SAFE_NO_PAD.encode(vk.as_bytes())
}

fn verifying_key() -> VerifyingKey {
    SigningKey::from_bytes(&SEED).verifying_key()
}

fn client(base: &str) -> CcMeClient {
    CcMeClient::new(key_b64u(), Some(base)).unwrap()
}

/// Recompute the canonical string and verify the captured signature headers.
fn assert_signed(req: &common::CapturedRequest, method: &str, body: &[u8]) {
    let ts = req
        .header("x-cc-me-timestamp")
        .expect("timestamp header present");
    let sig_b64u = req
        .header("x-cc-me-signature")
        .expect("signature header present");
    let body_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(body));
    let message = format!(
        "cc-me-v1\n{}\n{}\n{}\n{}",
        method, req.target, ts, body_hash
    );
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64u).unwrap();
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
    verifying_key()
        .verify(message.as_bytes(), &sig)
        .expect("signature verifies against the canonical string");
}

#[test]
fn peek_sends_get_with_both_auth_headers() {
    let server = MockServer::always(MockResponse::ok(r#"{"count":0,"items":[],"cursor":null}"#));
    let c = client(server.base_url());
    let resp = c.peek(&ListOptions::default()).unwrap();
    assert_eq!(resp.count, 0);
    assert!(resp.requests.is_empty());

    let reqs = server.requests();
    assert_eq!(reqs.len(), 1);
    let req = &reqs[0];
    assert_eq!(req.method, "GET");
    assert_eq!(req.target, format!("/i/{}", pubkey_b64u()));
    assert!(req.header("x-cc-me-timestamp").is_some());
    assert!(req.header("x-cc-me-signature").is_some());
    assert!(req.body.is_empty());
    assert_signed(req, "GET", b"");
}

#[test]
fn peek_with_options_signs_path_and_query_with_l_c_p_order() {
    let server = MockServer::always(MockResponse::ok(r#"{"count":0,"items":[],"cursor":null}"#));
    let c = client(server.base_url());
    c.peek(&ListOptions {
        limit: Some(5),
        cursor: Some("abc".into()),
        poll: true,
    })
    .unwrap();

    let req = &server.requests()[0];
    assert_eq!(req.target, format!("/i/{}?l=5&c=abc&p=", pubkey_b64u()));
    // The bytes signed must equal the bytes sent.
    assert_signed(req, "GET", b"");
}

#[test]
fn peek_returns_cursor_when_present() {
    let server = MockServer::always(MockResponse::ok(
        r#"{"count":0,"items":[],"cursor":"next-page"}"#,
    ));
    let c = client(server.base_url());
    let resp = c.peek(&ListOptions::default()).unwrap();
    assert_eq!(resp.cursor.as_deref(), Some("next-page"));
}

#[test]
fn claim_posts_json_body_and_auth_headers() {
    let server = MockServer::always(MockResponse::ok(r#"{"count":0,"items":[]}"#));
    let c = client(server.base_url());
    c.claim(&ListOptions {
        limit: Some(10),
        poll: true,
        ..Default::default()
    })
    .unwrap();

    let req = &server.requests()[0];
    assert_eq!(req.method, "POST");
    assert_eq!(req.target, format!("/i/{}/claim", pubkey_b64u()));
    assert_eq!(req.header("content-type"), Some("application/json"));
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(body["limit"], 10);
    assert_eq!(body["poll"], true);
    assert_signed(req, "POST", &req.body);
}

#[test]
fn claim_without_options_posts_empty_object() {
    let server = MockServer::always(MockResponse::ok(r#"{"count":0,"items":[]}"#));
    let c = client(server.base_url());
    c.claim(&ListOptions::default()).unwrap();

    let req = &server.requests()[0];
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(body, serde_json::json!({}));
    assert_signed(req, "POST", &req.body);
}

#[test]
fn ack_posts_ids_and_parses_response() {
    let server = MockServer::always(MockResponse::ok(r#"{"acked":2,"missing":["m_x"]}"#));
    let c = client(server.base_url());
    let resp = c.ack(&["m_a".into(), "m_b".into()]).unwrap();
    assert_eq!(resp.acked, 2);
    assert_eq!(resp.missing, vec!["m_x".to_string()]);
    assert_eq!(resp.released, 0);

    let req = &server.requests()[0];
    assert_eq!(req.method, "POST");
    assert_eq!(req.target, format!("/i/{}/ack", pubkey_b64u()));
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(body, serde_json::json!({"ids": ["m_a", "m_b"]}));
    assert_signed(req, "POST", &req.body);
}

#[test]
fn release_posts_ids_and_parses_response() {
    let server = MockServer::always(MockResponse::ok(r#"{"released":3,"missing":[]}"#));
    let c = client(server.base_url());
    let resp = c.release(&["m_a".into()]).unwrap();
    assert_eq!(resp.released, 3);
    assert_eq!(resp.acked, 0);
    assert!(resp.missing.is_empty());

    let req = &server.requests()[0];
    assert_eq!(req.target, format!("/i/{}/release", pubkey_b64u()));
}

#[test]
fn non_2xx_surfaces_error_message() {
    let server = MockServer::always(MockResponse::status(403, r#"{"error":"bad signature"}"#));
    let c = client(server.base_url());
    let err = c.peek(&ListOptions::default()).unwrap_err();
    assert!(
        err.to_string().contains("bad signature"),
        "expected surfaced error, got: {err}"
    );
}

#[test]
fn non_2xx_without_error_field_falls_back_to_status() {
    let server = MockServer::always(MockResponse::status(500, "oops not json"));
    let c = client(server.base_url());
    let err = c.ack(&["m_a".into()]).unwrap_err();
    assert!(
        err.to_string().contains("500"),
        "expected status fallback, got: {err}"
    );
}

#[test]
fn create_alias_posts_at_and_returns_url() {
    let server = MockServer::always(MockResponse::ok(r#"{"url":"https://cc.me/a/xyz"}"#));
    let url = cc_me::create_alias("https://example.test/cb", Some(server.base_url())).unwrap();
    assert_eq!(url, "https://cc.me/a/xyz");

    let req = &server.requests()[0];
    assert_eq!(req.method, "POST");
    assert_eq!(req.target, "/c");
    assert_eq!(req.header("content-type"), Some("application/json"));
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(body, serde_json::json!({"at": "https://example.test/cb"}));
    // No auth headers for alias creation.
    assert!(req.header("x-cc-me-signature").is_none());
}

#[test]
fn create_alias_surfaces_error() {
    let server = MockServer::always(MockResponse::status(400, r#"{"error":"bad target"}"#));
    let err = cc_me::create_alias("nope", Some(server.base_url())).unwrap_err();
    assert!(err.to_string().contains("bad target"));
}

#[test]
fn peek_decrypts_sealed_delivery_over_http() {
    use crypto_box::aead::rand_core::{OsRng, TryRngCore};
    use crypto_box::PublicKey;
    use curve25519_dalek::edwards::CompressedEdwardsY;

    let id = "m_http_seal";
    let plaintext = serde_json::json!({
        "id": id,
        "received_at_unix_ms": 1781337600000u64,
        "method": "POST",
        "path": format!("/i/{}/meta", pubkey_b64u()),
        "query": "hub.challenge=42",
        "headers": [{"name":"x-test","value_b64u": URL_SAFE_NO_PAD.encode(b"val")}],
        "body_b64u": URL_SAFE_NO_PAD.encode(b"payload-bytes"),
    })
    .to_string();

    let vk = verifying_key();
    let edwards = CompressedEdwardsY(vk.to_bytes()).decompress().unwrap();
    let pk = PublicKey::from_slice(edwards.to_montgomery().as_bytes()).unwrap();
    let sealed = pk
        .seal(&mut OsRng.unwrap_err(), plaintext.as_bytes())
        .unwrap();
    let sealed_b64u = URL_SAFE_NO_PAD.encode(&sealed);

    let response = serde_json::json!({
        "count": 1,
        "items": [{"id": id, "sealed": sealed_b64u}],
        "cursor": serde_json::Value::Null,
    })
    .to_string();

    let server = MockServer::always(MockResponse::ok(response));
    let c = client(server.base_url());
    let resp = c.peek(&ListOptions::default()).unwrap();
    assert_eq!(resp.requests.len(), 1);
    let d = &resp.requests[0];
    assert_eq!(d.id, id);
    assert_eq!(d.method, "POST");
    assert_eq!(d.query.as_deref(), Some("hub.challenge=42"));
    assert_eq!(d.headers[0].name, "x-test");
    assert_eq!(d.headers[0].value, "val");
    assert_eq!(d.text(), "payload-bytes");
}
