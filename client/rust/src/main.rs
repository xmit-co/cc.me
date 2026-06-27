//! `cc-me [--key <path>] <forward-url>`
//!
//! The forward loop: claim deliveries, replay each to a local target URL, and
//! ack/release as it goes. Mirrors the `forward.js` CLI (the `inspect`
//! subcommand is intentionally not ported).

use std::path::PathBuf;
use std::process::ExitCode;

use cc_me::{CcMeClient, Delivery, ListOptions};

const DEFAULT_LIMIT: u32 = 10;

/// Hop-by-hop headers that must not be forwarded.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "content-length"
            | "host"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn usage() {
    eprintln!("usage:\n  cc-me [--key <path>] <forward-url>");
}

struct Options {
    key_file: Option<PathBuf>,
    target: Option<String>,
}

fn parse_args() -> std::result::Result<Options, String> {
    let env_key = std::env::var("CC_ME_KEY").ok();
    let mut options = Options {
        key_file: env_key.map(PathBuf::from),
        target: None,
    };
    let mut positionals: Vec<String> = Vec::new();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--help" || arg == "-h" {
            usage();
            std::process::exit(0);
        } else if arg == "--key" {
            i += 1;
            let value = args
                .get(i)
                .ok_or_else(|| "--key needs a value".to_string())?;
            if value.is_empty() {
                return Err("--key needs a value".into());
            }
            options.key_file = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--key=") {
            if value.is_empty() {
                return Err("--key needs a value".into());
            }
            options.key_file = Some(PathBuf::from(value));
        } else if arg.starts_with('-') {
            return Err(format!("unknown option: {arg}"));
        } else {
            positionals.push(arg.clone());
        }
        i += 1;
    }

    if positionals.len() > 1 {
        return Err("only one forward URL is supported".into());
    }
    options.target = positionals.into_iter().next();
    Ok(options)
}

/// Default key file `~/.cc-me.key`.
fn default_key_file() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".cc-me.key")
}

/// Build the forward target URL by merging the delivery query into the base.
///
/// If the base already has a query, the delivery query is appended with `&`;
/// otherwise it becomes the query.
fn forward_url(base: &str, query: Option<&str>) -> String {
    let Some(query) = query.filter(|q| !q.is_empty()) else {
        return base.to_string();
    };
    // Split off any existing fragment is out of scope; the JS version operates
    // on URL.search only. We merge on the query component.
    match base.split_once('?') {
        Some((path, existing)) if !existing.is_empty() => {
            format!("{path}?{existing}&{query}")
        }
        Some((path, _)) => format!("{path}?{query}"),
        None => format!("{base}?{query}"),
    }
}

/// Replay a single delivery to the target. Returns Err on transport failure or
/// a non-2xx response.
fn forward_request(target: &str, delivery: &Delivery) -> std::result::Result<(), String> {
    let url = forward_url(target, delivery.query.as_deref());
    let mut req = ureq::request(&delivery.method, &url);
    for header in &delivery.headers {
        if !is_hop_by_hop(&header.name) {
            req = req.set(&header.name, &header.value);
        }
    }

    let has_body =
        delivery.method != "GET" && delivery.method != "HEAD" && !delivery.body_bytes.is_empty();

    let result = if has_body {
        req.send_bytes(&delivery.body_bytes)
    } else {
        req.call()
    };

    match result {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(code, _)) => Err(format!("forward failed with {code}")),
        Err(ureq::Error::Transport(t)) => Err(format!("forward transport error: {t}")),
    }
}

/// Process one claimed batch: replay each delivery in order, acking on success.
///
/// On a forward failure, ack the ids already handled, release the current and
/// remaining ids, and return the error. On full success, ack every handled id.
///
/// Factored out of [`run`] so it is unit-testable against a mock server. The
/// `forward` closure replays a single delivery (in production this is
/// [`forward_request`]).
fn process_batch<F>(
    client: &CcMeClient,
    requests: &[Delivery],
    mut forward: F,
) -> std::result::Result<(), String>
where
    F: FnMut(&Delivery) -> std::result::Result<(), String>,
{
    let mut acked: Vec<String> = Vec::new();

    for (i, delivery) in requests.iter().enumerate() {
        match forward(delivery) {
            Ok(()) => {
                acked.push(delivery.id.clone());
                match &delivery.query {
                    Some(q) if !q.is_empty() => {
                        eprintln!("{} {}?{}", delivery.method, delivery.path, q)
                    }
                    _ => eprintln!("{} {}", delivery.method, delivery.path),
                }
            }
            Err(err) => {
                let release_ids: Vec<String> = requests[i..].iter().map(|d| d.id.clone()).collect();
                if !acked.is_empty() {
                    let _ = client.ack(&acked);
                }
                if !release_ids.is_empty() {
                    let _ = client.release(&release_ids);
                }
                return Err(err);
            }
        }
    }

    if !acked.is_empty() {
        client.ack(&acked).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn run() -> std::result::Result<(), String> {
    let options = parse_args().inspect_err(|_| usage())?;

    let Some(target) = options.target.clone() else {
        usage();
        std::process::exit(64);
    };

    let key_path = options.key_file.unwrap_or_else(default_key_file);
    let key = cc_me::private_key(Some(&key_path)).map_err(|e| e.to_string())?;

    let base_url = std::env::var("CC_ME_URL").ok();
    let client = CcMeClient::new(key, base_url.as_deref()).map_err(|e| e.to_string())?;

    eprintln!("cc.me inbox: {}", client.inbox_url(&ListOptions::default()));
    eprintln!("forwarding to: {target}");

    let limit = std::env::var("CC_ME_LIMIT")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(DEFAULT_LIMIT);

    loop {
        let response = client
            .claim(&ListOptions {
                limit: Some(limit),
                poll: true,
                ..Default::default()
            })
            .map_err(|e| e.to_string())?;

        process_batch(&client, &response.requests, |delivery| {
            forward_request(&target, delivery)
        })?;
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use cc_me::CcMeClient;
    use ed25519_dalek::SigningKey;

    const SEED: [u8; 32] = [9u8; 32];

    fn key_b64u() -> String {
        URL_SAFE_NO_PAD.encode(SEED)
    }

    fn pubkey_b64u() -> String {
        let vk = SigningKey::from_bytes(&SEED).verifying_key();
        URL_SAFE_NO_PAD.encode(vk.as_bytes())
    }

    fn delivery(id: &str, method: &str, query: Option<&str>) -> Delivery {
        Delivery {
            id: id.to_string(),
            received_at_unix_ms: 0,
            method: method.to_string(),
            path: format!("/i/{}", pubkey_b64u()),
            query: query.map(|q| q.to_string()),
            headers: Vec::new(),
            body_bytes: Vec::new(),
        }
    }

    // --- is_hop_by_hop ------------------------------------------------------

    #[test]
    fn hop_by_hop_headers_are_recognised() {
        for name in [
            "connection",
            "content-length",
            "host",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ] {
            assert!(is_hop_by_hop(name), "{name} should be hop-by-hop");
            // Case-insensitive.
            assert!(is_hop_by_hop(&name.to_ascii_uppercase()));
        }
    }

    #[test]
    fn end_to_end_headers_are_not_hop_by_hop() {
        for name in [
            "content-type",
            "x-test",
            "authorization",
            "accept",
            "user-agent",
        ] {
            assert!(!is_hop_by_hop(name), "{name} should pass through");
        }
    }

    // --- forward_url --------------------------------------------------------

    #[test]
    fn forward_url_no_query_is_unchanged() {
        assert_eq!(forward_url("http://x/cb", None), "http://x/cb");
        assert_eq!(forward_url("http://x/cb", Some("")), "http://x/cb");
    }

    #[test]
    fn forward_url_adds_query_when_base_has_none() {
        assert_eq!(
            forward_url("http://x/cb", Some("a=1&b=2")),
            "http://x/cb?a=1&b=2"
        );
    }

    #[test]
    fn forward_url_merges_with_existing_query() {
        assert_eq!(
            forward_url("http://x/cb?z=9", Some("a=1")),
            "http://x/cb?z=9&a=1"
        );
    }

    #[test]
    fn forward_url_handles_trailing_question_mark() {
        assert_eq!(forward_url("http://x/cb?", Some("a=1")), "http://x/cb?a=1");
    }

    // --- minimal mock server ------------------------------------------------

    struct Recorded {
        method: String,
        target: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    struct Server {
        base: String,
        recorded: Arc<Mutex<Vec<Recorded>>>,
        shutdown: Arc<Mutex<bool>>,
    }

    impl Server {
        /// Serve `status` for every request, recording each one.
        fn new(status: u16, body: &'static str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let base = format!("http://127.0.0.1:{port}/");
            let recorded = Arc::new(Mutex::new(Vec::new()));
            let shutdown = Arc::new(Mutex::new(false));
            let rec = Arc::clone(&recorded);
            let sd = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if *sd.lock().unwrap() {
                        break;
                    }
                    let Ok(stream) = stream else { break };
                    if let Some(r) = serve(stream, status, body) {
                        rec.lock().unwrap().push(r);
                    }
                }
            });
            Self {
                base,
                recorded,
                shutdown,
            }
        }

        fn url(&self) -> &str {
            &self.base
        }

        /// Targets (path+query) of recorded POSTs whose target ends in `suffix`.
        fn posts_ending(&self, suffix: &str) -> Vec<HashMap<String, String>> {
            self.recorded
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.method == "POST" && r.target.ends_with(suffix))
                .map(|r| {
                    let body: serde_json::Value =
                        serde_json::from_slice(&r.body).unwrap_or(serde_json::Value::Null);
                    let mut m = HashMap::new();
                    m.insert("ids".into(), body["ids"].to_string());
                    m
                })
                .collect()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            *self.shutdown.lock().unwrap() = true;
            if let Ok(addr) = self
                .base
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .parse::<std::net::SocketAddr>()
            {
                let _ = TcpStream::connect(addr);
            }
        }
    }

    fn serve(mut stream: TcpStream, status: u16, body: &str) -> Option<Recorded> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let header_end = loop {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            match stream.read(&mut tmp) {
                Ok(0) => return None,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(_) => return None,
            }
        };
        let text = String::from_utf8_lossy(&buf[..header_end]).into_owned();
        let mut lines = text.split("\r\n");
        let mut parts = lines.next().unwrap_or("").split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("").to_string();
        let mut headers = HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
        let len: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut bytes = buf[header_end..].to_vec();
        while bytes.len() < len {
            match stream.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&tmp[..n]),
                Err(_) => break,
            }
        }
        bytes.truncate(len);
        let resp = format!(
            "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
        Some(Recorded {
            method,
            target,
            headers,
            body: bytes,
        })
    }

    // --- forward_request ----------------------------------------------------

    #[test]
    fn forward_request_replays_method_headers_and_body() {
        let server = Server::new(200, "{}");
        let mut d = delivery("m_1", "POST", Some("a=1"));
        d.headers.push(cc_me::Header {
            name: "x-custom".into(),
            value: "v".into(),
            value_bytes: b"v".to_vec(),
        });
        d.headers.push(cc_me::Header {
            name: "host".into(),
            value: "evil.example".into(),
            value_bytes: b"evil.example".to_vec(),
        });
        d.body_bytes = b"hello-body".to_vec();

        forward_request(server.url(), &d).unwrap();

        let recorded = server.recorded.lock().unwrap();
        let r = &recorded[0];
        assert_eq!(r.method, "POST");
        assert_eq!(r.target, "/?a=1");
        assert_eq!(r.body, b"hello-body");
        assert_eq!(r.headers.get("x-custom").map(String::as_str), Some("v"));
        // Hop-by-hop host header is stripped (ureq sets its own host).
        assert_ne!(
            r.headers.get("host").map(String::as_str),
            Some("evil.example")
        );
    }

    #[test]
    fn forward_request_get_sends_no_body() {
        let server = Server::new(200, "{}");
        let mut d = delivery("m_g", "GET", None);
        d.body_bytes = b"should-be-ignored".to_vec();
        forward_request(server.url(), &d).unwrap();
        let recorded = server.recorded.lock().unwrap();
        assert!(recorded[0].body.is_empty());
    }

    #[test]
    fn forward_request_non_2xx_is_error() {
        let server = Server::new(500, "{}");
        let d = delivery("m_e", "POST", None);
        let err = forward_request(server.url(), &d).unwrap_err();
        assert!(err.contains("500"), "got: {err}");
    }

    #[test]
    fn forward_request_transport_error() {
        // Nothing listening on this port.
        let err =
            forward_request("http://127.0.0.1:1/", &delivery("m_t", "GET", None)).unwrap_err();
        assert!(err.contains("transport"), "got: {err}");
    }

    // --- process_batch ------------------------------------------------------

    #[test]
    fn process_batch_acks_all_on_success() {
        let server = Server::new(200, "{\"acked\":2,\"missing\":[]}");
        let client = CcMeClient::new(key_b64u(), Some(server.url())).unwrap();
        let requests = vec![delivery("m_1", "POST", None), delivery("m_2", "POST", None)];
        process_batch(&client, &requests, |_| Ok(())).unwrap();

        let acks = server.posts_ending("/ack");
        let releases = server.posts_ending("/release");
        assert_eq!(acks.len(), 1, "exactly one ack call");
        assert_eq!(releases.len(), 0, "no release on full success");
        assert_eq!(acks[0]["ids"], r#"["m_1","m_2"]"#);
    }

    #[test]
    fn process_batch_acks_handled_and_releases_remainder_on_failure() {
        let server = Server::new(200, "{}");
        let client = CcMeClient::new(key_b64u(), Some(server.url())).unwrap();
        let requests = vec![
            delivery("m_1", "POST", None),
            delivery("m_2", "POST", None),
            delivery("m_3", "POST", None),
        ];
        // First succeeds, second fails -> ack [m_1], release [m_2, m_3].
        let mut calls = 0;
        let err = process_batch(&client, &requests, |_| {
            calls += 1;
            if calls == 1 {
                Ok(())
            } else {
                Err("boom".to_string())
            }
        })
        .unwrap_err();
        assert_eq!(err, "boom");

        let acks = server.posts_ending("/ack");
        let releases = server.posts_ending("/release");
        assert_eq!(acks.len(), 1);
        assert_eq!(acks[0]["ids"], r#"["m_1"]"#);
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0]["ids"], r#"["m_2","m_3"]"#);
    }

    #[test]
    fn process_batch_first_failure_releases_all_and_skips_ack() {
        let server = Server::new(200, "{}");
        let client = CcMeClient::new(key_b64u(), Some(server.url())).unwrap();
        let requests = vec![delivery("m_1", "POST", None), delivery("m_2", "POST", None)];
        let err = process_batch(&client, &requests, |_| Err("nope".to_string())).unwrap_err();
        assert_eq!(err, "nope");

        let acks = server.posts_ending("/ack");
        let releases = server.posts_ending("/release");
        assert_eq!(acks.len(), 0, "nothing handled, no ack");
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0]["ids"], r#"["m_1","m_2"]"#);
    }

    #[test]
    fn process_batch_empty_does_nothing() {
        let server = Server::new(200, "{}");
        let client = CcMeClient::new(key_b64u(), Some(server.url())).unwrap();
        process_batch(&client, &[], |_| Ok(())).unwrap();
        assert_eq!(server.recorded.lock().unwrap().len(), 0);
    }
}
