//! A tiny hand-rolled HTTP/1.1 mock server for client tests.
//!
//! It speaks just enough HTTP/1.1 over a `TcpListener` (no TLS) to exercise the
//! blocking `ureq` client: it reads the request line, headers, and a
//! `Content-Length`-delimited body, records them, and replies with a scripted
//! response. Point the client at `server.base_url()` (an `http://127.0.0.1:PORT`
//! URL).

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// A single request captured by the mock server.
#[derive(Debug, Clone)]
pub struct CapturedRequest {
    pub method: String,
    /// Request target exactly as sent on the wire (path plus any query).
    pub target: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl CapturedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(|s| s.as_str())
    }

    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A scripted response.
#[derive(Clone)]
pub struct MockResponse {
    pub status: u16,
    pub reason: String,
    pub body: String,
    pub content_type: String,
}

impl MockResponse {
    pub fn ok(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            reason: "OK".into(),
            body: body.into(),
            content_type: "application/json".into(),
        }
    }

    pub fn status(code: u16, body: impl Into<String>) -> Self {
        Self {
            status: code,
            reason: reason_phrase(code).into(),
            body: body.into(),
            content_type: "application/json".into(),
        }
    }
}

fn reason_phrase(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Status",
    }
}

/// A running mock HTTP server. Drops close the listener thread.
pub struct MockServer {
    base_url: String,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    handle: Option<JoinHandle<()>>,
    shutdown: Arc<Mutex<bool>>,
}

impl MockServer {
    /// Start a server that replies to every request with the same response.
    pub fn always(response: MockResponse) -> Self {
        Self::scripted(vec![response], true)
    }

    /// Start a server with a queue of responses, one per request in order.
    ///
    /// When `repeat_last` is true the final response is reused for any extra
    /// requests; otherwise extra requests get a 500.
    pub fn scripted(responses: Vec<MockResponse>, repeat_last: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("local addr");
        let base_url = format!("http://127.0.0.1:{}/", addr.port());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(Mutex::new(false));

        let requests_thread = Arc::clone(&requests);
        let shutdown_thread = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            for (index, stream) in listener.incoming().enumerate() {
                if *shutdown_thread.lock().unwrap() {
                    break;
                }
                let Ok(stream) = stream else { break };
                let response = pick(&responses, index, repeat_last);
                if let Some(req) = handle_connection(stream, &response) {
                    requests_thread.lock().unwrap().push(req);
                }
            }
        });

        Self {
            base_url,
            requests,
            handle: Some(handle),
            shutdown,
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// All requests captured so far, in arrival order.
    pub fn requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().unwrap().clone()
    }

    pub fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        // Nudge the accept loop with a throwaway connection so it observes the
        // shutdown flag and exits.
        if let Ok(host) = self
            .base_url
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .parse::<std::net::SocketAddr>()
        {
            let _ = TcpStream::connect(host);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn pick(responses: &[MockResponse], index: usize, repeat_last: bool) -> MockResponse {
    if let Some(r) = responses.get(index) {
        return r.clone();
    }
    if repeat_last {
        if let Some(last) = responses.last() {
            return last.clone();
        }
    }
    MockResponse::status(500, "{\"error\":\"no scripted response\"}")
}

fn handle_connection(mut stream: TcpStream, response: &MockResponse) -> Option<CapturedRequest> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];

    // Read until we have the full header block (terminated by CRLFCRLF).
    let header_end = loop {
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        match stream.read(&mut tmp) {
            Ok(0) => return None,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => return None,
        }
    };

    let header_text = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    body.truncate(content_length);

    let payload = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response.status,
        response.reason,
        response.content_type,
        response.body.len(),
        response.body,
    );
    let _ = stream.write_all(payload.as_bytes());
    let _ = stream.flush();

    Some(CapturedRequest {
        method,
        target,
        headers,
        body,
    })
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Spawn a one-shot server that captures exactly one request and hands it back
/// over a channel. Useful for tests that only care about a single replay.
pub fn one_shot(response: MockResponse) -> (String, Receiver<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind one-shot");
    let addr = listener.local_addr().unwrap();
    let base = format!("http://127.0.0.1:{}/", addr.port());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            if let Some(req) = handle_connection(stream, &response) {
                let _ = tx.send(req);
            }
        }
    });
    (base, rx)
}
