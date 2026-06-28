//! `cc-me-mail <rcpt> <sender>` — the catch-all MDA for the cc.me domain.
//!
//! Reads the message on stdin and dispatches on the recipient's local part:
//! `echo@` bounces the message back, `hi@` issues a login magic link, and any
//! other address is treated as an alias and forwarded to its owner's inbox.

use std::{
    env,
    error::Error,
    hash::{DefaultHasher, Hash, Hasher},
    io::{self, BufRead, BufReader, Read, Write},
    net::TcpStream,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crypto_box::aead::rand_core::{OsRng, TryRngCore};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use time::{OffsetDateTime, format_description::well_known::Rfc2822};

const EMAIL_KEY_BYTES: usize = 32;
const EMAIL_LINK_ID_BYTES: usize = 10;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut message = String::new();
    io::stdin().read_to_string(&mut message)?;

    let mut args = env::args().skip(1);
    let rcpt = args
        .next()
        .or_else(|| env::var("RECIPIENT").ok())
        .unwrap_or_default();
    let sender = args
        .next()
        .or_else(|| env::var("SENDER").ok())
        .filter(|value| !value.is_empty())
        .or_else(|| Headers::parse(&message).get("from").and_then(extract_address));

    let local = rcpt
        .rsplit_once('@')
        .map(|(local, _)| local)
        .unwrap_or(&rcpt)
        .to_ascii_lowercase();

    let config = Config::from_env();

    match local.as_str() {
        "echo" => handle_echo(&message, sender.as_deref(), &config),
        "hi" => handle_login(sender.as_deref(), &config).await,
        _ => handle_alias(&message, &local, sender.as_deref(), &config).await,
    }
}

struct Config {
    database_url: String,
    login_from: String,
    echo_from: String,
    host: String,
    public_url: String,
    smtp: String,
}

impl Config {
    fn from_env() -> Self {
        Self {
            database_url: env::var("DATABASE_URL").unwrap_or_default(),
            login_from: env::var("CC_ME_LOGIN_FROM").unwrap_or_else(|_| "hi@cc.me".to_string()),
            echo_from: env::var("CC_ME_ECHO_FROM").unwrap_or_else(|_| "echo@cc.me".to_string()),
            host: env::var("CC_ME_MAIL_HOST").unwrap_or_else(|_| "cc.me".to_string()),
            public_url: env::var("CC_ME_PUBLIC_URL")
                .unwrap_or_else(|_| "https://cc.me".to_string()),
            // SMTP submission host:port (where rspamd can DKIM-sign). "-" prints
            // the message to stdout instead, for local testing / bin/hi.
            smtp: env::var("CC_ME_SMTP").unwrap_or_else(|_| "127.0.0.1:10587".to_string()),
        }
    }

    async fn pool(&self) -> Result<PgPool, Box<dyn Error>> {
        if self.database_url.is_empty() {
            return Err("DATABASE_URL is required".into());
        }
        Ok(PgPoolOptions::new()
            .max_connections(1)
            .connect(&self.database_url)
            .await?)
    }
}

// --- echo ------------------------------------------------------------------

fn handle_echo(message: &str, sender: Option<&str>, config: &Config) -> Result<(), Box<dyn Error>> {
    if let Some((to, reply)) = build_echo_reply(message, sender, config)? {
        submit(&config.echo_from, &to, &reply, config)?;
    }
    Ok(())
}

fn build_echo_reply(
    message: &str,
    envelope_sender: Option<&str>,
    config: &Config,
) -> Result<Option<(String, String)>, Box<dyn Error>> {
    let headers = Headers::parse(message);
    let sender = envelope_sender
        .map(clean_one_line)
        .filter(|sender| !sender.is_empty())
        .or_else(|| headers.get("from").and_then(extract_address));

    let Some(sender) = sender else {
        return Ok(None);
    };
    if sender == "<>" || is_auto_submitted(&headers) || is_bulkish(&headers) {
        return Ok(None);
    }

    let subject = reply_subject(headers.get("subject").as_deref(), &config.echo_from);
    let date = OffsetDateTime::now_utc().format(&Rfc2822)?;
    let message_id = reply_message_id(message, &config.host);
    let original_message_id = headers.get("message-id").map(|value| clean_one_line(&value));

    let mut reply = String::new();
    push_header(&mut reply, "From", &config.echo_from);
    push_header(&mut reply, "To", &sender);
    push_header(&mut reply, "Subject", &subject);
    push_header(&mut reply, "Date", &date);
    push_header(&mut reply, "Message-ID", &format!("<{message_id}>"));
    if let Some(original_message_id) = original_message_id.filter(|value| !value.is_empty()) {
        push_header(&mut reply, "In-Reply-To", &original_message_id);
        push_header(&mut reply, "References", &original_message_id);
    }
    push_header(&mut reply, "Auto-Submitted", "auto-replied");
    push_header(&mut reply, "MIME-Version", "1.0");
    push_header(&mut reply, "Content-Type", "text/plain; charset=UTF-8");
    push_header(&mut reply, "Content-Transfer-Encoding", "8bit");
    reply.push('\n');
    reply.push_str("cc.me echo service received your message and is sending it back.\n\n");
    reply.push_str("Envelope sender: ");
    reply.push_str(&sender);
    reply.push_str("\n\n----- original message -----\n");
    for line in message.lines() {
        reply.push_str("> ");
        reply.push_str(line);
        reply.push('\n');
    }

    Ok(Some((sender, reply)))
}

// --- login -----------------------------------------------------------------

async fn handle_login(sender: Option<&str>, config: &Config) -> Result<(), Box<dyn Error>> {
    let sender = sender.filter(|value| !value.is_empty()).ok_or("sender is required")?;
    if sender == "<>" {
        return Ok(());
    }
    let pool = config.pool().await?;
    let link = create_magic_link(&pool, sender, &config.public_url).await?;
    let reply = login_reply(sender, &link, config)?;
    submit(&config.login_from, sender, &reply, config)?;
    Ok(())
}

async fn create_magic_link(
    pool: &PgPool,
    email: &str,
    public_url: &str,
) -> Result<String, Box<dyn Error>> {
    for _ in 0..4 {
        let mut key = [0u8; EMAIL_KEY_BYTES];
        OsRng.unwrap_err().try_fill_bytes(&mut key)?;
        let token = URL_SAFE_NO_PAD.encode(key);
        let token_hash = Sha256::digest(key).to_vec();

        let mut id = [0u8; EMAIL_LINK_ID_BYTES];
        OsRng.unwrap_err().try_fill_bytes(&mut id)?;
        let id = URL_SAFE_NO_PAD.encode(id);

        let inserted = sqlx::query(
            r#"
            INSERT INTO email_login_keys (id, token_hash, email, expires_at)
            VALUES ($1, $2, lower($3), now() + interval '7 days')
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(&id)
        .bind(token_hash)
        .bind(email)
        .execute(pool)
        .await?;

        if inserted.rows_affected() == 1 {
            return Ok(format!("{}/hi#code={}", public_url.trim_end_matches('/'), token));
        }
    }

    Err("could not allocate magic link".into())
}

fn login_reply(to: &str, link: &str, config: &Config) -> Result<String, Box<dyn Error>> {
    let date = OffsetDateTime::now_utc().format(&Rfc2822)?;
    Ok(format!(
        "From: {from}\n\
         To: {to}\n\
         Subject: Your cc.me email alias link\n\
         Date: {date}\n\
         Auto-Submitted: auto-replied\n\
         MIME-Version: 1.0\n\
         Content-Type: text/plain; charset=UTF-8\n\
         Content-Transfer-Encoding: 8bit\n\
         \n\
         Use this link to manage cc.me aliases for {to}:\n\
         \n\
         {link}\n",
        from = config.login_from,
    ))
}

// --- alias forwarding ------------------------------------------------------

async fn handle_alias(
    message: &str,
    alias: &str,
    sender: Option<&str>,
    config: &Config,
) -> Result<(), Box<dyn Error>> {
    let pool = config.pool().await?;
    let owner: Option<String> = sqlx::query_scalar(
        r#"
        SELECT email FROM email_aliases
        WHERE alias = $1 AND (expires_at IS NULL OR expires_at > now())
        "#,
    )
    .bind(alias)
    .fetch_optional(&pool)
    .await?;

    // Unknown or expired alias: fail so the MDA bounces the message.
    let Some(owner) = owner else {
        return Err(format!("no active alias {alias}@{}", config.host).into());
    };

    sqlx::query("UPDATE email_aliases SET last_received_at = now() WHERE alias = $1")
        .bind(alias)
        .execute(&pool)
        .await?;

    forward_message(message, &owner, sender, config)?;
    record_forward(&pool).await?;
    Ok(())
}

/// Bump the "emails forwarded" counter the homepage stats read (kind `f`),
/// for the current hour and day buckets. Mirrors the server's `stat_counts`.
async fn record_forward(pool: &PgPool) -> Result<(), Box<dyn Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    for (period, bucket) in [("h", now / 3600), ("d", now / 86_400)] {
        sqlx::query(
            r#"
            INSERT INTO stat_counts (period, kind, bucket, count)
            VALUES ($1, 'f', $2, 1)
            ON CONFLICT (period, kind, bucket)
            DO UPDATE SET count = stat_counts.count + 1
            "#,
        )
        .bind(period)
        .bind(bucket)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Forward the original message verbatim to the alias owner. The envelope
/// sender is preserved (so replies and bounces reach the original sender) when
/// it is a real address; a null sender is sent as `MAIL FROM:<>`.
fn forward_message(
    message: &str,
    owner: &str,
    sender: Option<&str>,
    config: &Config,
) -> Result<(), Box<dyn Error>> {
    let from = sender
        .filter(|value| !value.is_empty() && *value != "<>")
        .unwrap_or("");
    submit(from, owner, message, config)
}

// --- sending ---------------------------------------------------------------

/// Submit a message via SMTP to `CC_ME_SMTP` (a local listener where rspamd can
/// DKIM-sign), or print it to stdout when `CC_ME_SMTP` is "-".
fn submit(from: &str, rcpt: &str, message: &str, config: &Config) -> Result<(), Box<dyn Error>> {
    if config.smtp == "-" {
        io::stdout().write_all(message.as_bytes())?;
        return Ok(());
    }
    smtp_submit(&config.smtp, from, rcpt, message)
}

fn smtp_submit(addr: &str, from: &str, rcpt: &str, message: &str) -> Result<(), Box<dyn Error>> {
    let stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    expect(&mut reader, b'2')?; // greeting
    cmd(&mut writer, &mut reader, "EHLO cc.me", b'2')?;
    cmd(&mut writer, &mut reader, &format!("MAIL FROM:<{from}>"), b'2')?;
    cmd(&mut writer, &mut reader, &format!("RCPT TO:<{rcpt}>"), b'2')?;
    cmd(&mut writer, &mut reader, "DATA", b'3')?;
    writer.write_all(dot_stuffed(message).as_bytes())?;
    writer.write_all(b"\r\n.\r\n")?;
    writer.flush()?;
    expect(&mut reader, b'2')?; // accepted
    let _ = cmd(&mut writer, &mut reader, "QUIT", b'2');
    Ok(())
}

fn cmd(
    writer: &mut impl Write,
    reader: &mut impl BufRead,
    line: &str,
    expected: u8,
) -> Result<(), Box<dyn Error>> {
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\r\n")?;
    writer.flush()?;
    expect(reader, expected)
}

/// Read a (possibly multi-line) SMTP reply and check its first digit.
fn expect(reader: &mut impl BufRead, expected: u8) -> Result<(), Box<dyn Error>> {
    let mut last = String::new();
    loop {
        last.clear();
        if reader.read_line(&mut last)? == 0 {
            return Err("smtp connection closed".into());
        }
        // A line of the form "250-..." continues; "250 ..." (or short) ends.
        if last.as_bytes().get(3) != Some(&b'-') {
            break;
        }
    }
    if last.as_bytes().first() != Some(&expected) {
        return Err(format!("smtp error: {}", last.trim_end()).into());
    }
    Ok(())
}

/// CRLF line endings with SMTP dot-stuffing (lines starting with "." doubled).
fn dot_stuffed(message: &str) -> String {
    message
        .split('\n')
        .map(|line| {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.starts_with('.') {
                format!(".{line}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

// --- header helpers --------------------------------------------------------

fn push_header(reply: &mut String, name: &str, value: &str) {
    reply.push_str(name);
    reply.push_str(": ");
    reply.push_str(&clean_one_line(value));
    reply.push('\n');
}

fn clean_one_line(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch == '\r' || ch == '\n' { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .to_string()
}

fn reply_subject(subject: Option<&str>, from: &str) -> String {
    let subject = subject.map(clean_one_line).unwrap_or_default();
    if subject.is_empty() {
        return format!("Re: message to {from}");
    }
    if subject
        .get(..3)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("re:"))
    {
        subject
    } else {
        format!("Re: {subject}")
    }
}

fn reply_message_id(message: &str, host: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let mut hasher = DefaultHasher::new();
    message.hash(&mut hasher);
    format!("{now}.{}.{}@{host}", std::process::id(), hasher.finish())
}

fn is_auto_submitted(headers: &Headers) -> bool {
    headers
        .get("auto-submitted")
        .map(|value| {
            let value = value.trim();
            !value.is_empty() && !value.eq_ignore_ascii_case("no")
        })
        .unwrap_or(false)
}

fn is_bulkish(headers: &Headers) -> bool {
    headers
        .get("precedence")
        .map(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("bulk") || value.contains("junk") || value.contains("list")
        })
        .unwrap_or(false)
}

fn extract_address(value: String) -> Option<String> {
    let value = clean_one_line(&value);
    if let (Some(start), Some(end)) = (value.find('<'), value.find('>')) {
        let candidate = value[start + 1..end].trim();
        if looks_like_address(candidate) {
            return Some(candidate.to_ascii_lowercase());
        }
    }
    value
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .find(|part| looks_like_address(part.trim()))
        .map(|part| part.trim().to_ascii_lowercase())
}

fn looks_like_address(value: &str) -> bool {
    let value = value.trim_matches(|ch| ch == '<' || ch == '>');
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !value.contains(char::is_whitespace)
        && !value.contains('<')
        && !value.contains('>')
}

#[derive(Debug)]
struct Headers(Vec<(String, String)>);

impl Headers {
    fn parse(message: &str) -> Self {
        let mut headers: Vec<(String, String)> = Vec::new();
        for line in message.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                break;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                if let Some((_, value)) = headers.last_mut() {
                    value.push(' ');
                    value.push_str(line.trim());
                }
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        Self(headers)
    }

    fn get(&self, name: &str) -> Option<String> {
        let wanted = name.to_ascii_lowercase();
        self.0
            .iter()
            .rev()
            .find_map(|(header, value)| (header == &wanted).then(|| value.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            database_url: String::new(),
            login_from: "hi@cc.me".to_string(),
            echo_from: "echo@cc.me".to_string(),
            host: "cc.me".to_string(),
            public_url: "https://cc.me".to_string(),
            smtp: "-".to_string(),
        }
    }

    #[test]
    fn echo_replies_to_envelope_sender() {
        let (to, reply) = build_echo_reply(
            "From: Alice <alice@example.net>\nSubject: Test\nMessage-ID: <m@example.net>\n\nHello\n",
            Some("bounce@example.net"),
            &config(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(to, "bounce@example.net");
        assert!(reply.contains("To: bounce@example.net\n"));
        assert!(reply.contains("Subject: Re: Test\n"));
        assert!(reply.contains("In-Reply-To: <m@example.net>\n"));
        assert!(reply.contains("> Hello\n"));
    }

    #[test]
    fn echo_falls_back_to_from_header() {
        let (to, reply) =
            build_echo_reply("From: Alice <alice@example.net>\n\nHi\n", None, &config())
                .unwrap()
                .unwrap();
        assert_eq!(to, "alice@example.net");
        assert!(reply.contains("To: alice@example.net\n"));
    }

    #[test]
    fn dot_stuffing_and_crlf() {
        let out = dot_stuffed("a\n.b\nc\n");
        assert_eq!(out, "a\r\n..b\r\nc\r\n");
    }

    #[test]
    fn echo_suppresses_auto_replies_and_null_sender() {
        assert!(
            build_echo_reply(
                "From: bot@example.net\nAuto-Submitted: auto-replied\n\nHi\n",
                Some("bot@example.net"),
                &config(),
            )
            .unwrap()
            .is_none()
        );
        assert!(
            build_echo_reply("From: x@example.net\n\nHi\n", Some("<>"), &config())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn forward_uses_envelope_sender_and_owner() {
        // The "-" path just writes the payload; here we exercise the address
        // helpers the submit path relies on.
        assert_eq!(
            extract_address("Bob <bob@example.net>".to_string()).as_deref(),
            Some("bob@example.net")
        );
        assert!(looks_like_address("a@b.co"));
        assert!(!looks_like_address("not-an-address"));
    }
}
