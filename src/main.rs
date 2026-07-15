use std::{
    collections::{HashMap, HashSet},
    env,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::{
        Arc, LazyLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, RawQuery, Request, State},
    http::{HeaderMap, Method, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
};
use base64::{
    Engine,
    engine::general_purpose::{self, URL_SAFE_NO_PAD},
};
use crypto_box::{
    PublicKey,
    aead::rand_core::{OsRng, TryRngCore},
};
use curve25519_dalek::edwards::CompressedEdwardsY;
#[cfg(test)]
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{
    PgPool, Row,
    postgres::{PgListener, PgPoolOptions},
};
use tokio::{
    sync::{broadcast, mpsc, oneshot},
    time::Instant,
};
use tokio_tungstenite::tungstenite::Message;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info};
use url::{Url, form_urlencoded};
use uuid::Uuid;

const ACK_ID_LIMIT: usize = 1000;
const ALIAS_ID_BYTES: usize = 10;
const AUTH_SIGNATURE_HEADER: &str = "x-cc-me-signature";
const AUTH_TIMESTAMP_HEADER: &str = "x-cc-me-timestamp";
const AUTH_VERSION: &str = "cc-me-v1";
const AUTH_WINDOW_SECONDS: u64 = 5 * 60;
const DOCS_INDEX_HTML: &str = include_str!("../docs/index.html");
const DOCS_HTTP_HTML: &str = include_str!("../docs/http.html");
const DOCS_LIB_HTML: &str = include_str!("../docs/lib.html");
const DOCS_STYLES_CSS: &str = include_str!("../docs/styles.css");
const TWEETNACL_JS: &str = include_str!("../docs/tweetnacl.js");
const DOCS_CSP: &str = "frame-ancestors https://pcarrier.com";
const EMAIL_ALIAS_DOMAIN: &str = "cc.me";
const EMAIL_KEY_BYTES: usize = 32;
const GO_IMPORT_HTML: &str = concat!(
    "<!doctype html>\n",
    "<meta name=\"go-import\" content=\"cc.me git https://github.com/xmit-co/cc.me\">\n",
    "<meta name=\"go-source\" content=\"cc.me https://github.com/xmit-co/cc.me ",
    "https://github.com/xmit-co/cc.me/tree/main{/dir} ",
    "https://github.com/xmit-co/cc.me/blob/main{/dir}/{file}#L{line}\">\n",
);
const EMAIL_PAGE_HTML: &str = include_str!("../docs/hi.html");
const CLAIM_RECOVERY_SECONDS: u64 = 10 * 60;
const INBOX_NOTIFY_CHANNEL: &str = "cc_i";
const INBOX_NOTIFY_CAPACITY: usize = 4096;
const LIBRARY_NOTIFY_CHANNEL: &str = "cc_l";
const LIBRARY_NOTIFY_CAPACITY: usize = 4096;
const MAX_CAPTURE_BYTES: usize = 64 * 1024;
const MAX_INBOX_RECIPIENTS: usize = 16;
const MAX_INBOX_RESPONSE_BYTES: usize = 1024 * 1024;
const INBOX_RESPONSE_OVERHEAD_BYTES: usize = 128;
const PUBLIC_BASE_URL: &str = "https://cc.me";
const STATS_BITS: usize = 2048;
const STATS_BYTES: usize = STATS_BITS / 8;
const STATS_HOURS: u64 = 48;
const STATS_DAYS: u64 = 30;
const STATS_CHANNEL_CAPACITY: usize = 4096;
const STATS_BATCH_MAX: usize = 256;
const SECRET_ID_BYTES: usize = 12;
const SECRET_NONCE_BYTES: usize = 24;
const SECRET_DEFAULT_TTL_HOURS: u64 = 24;
const SECRET_MAX_TTL_HOURS: u64 = 168;
const SECRET_MAX_BYTES: usize = 256 * 1024;
const SECRET_MAX_REQUEST_BYTES: usize = 512 * 1024;
const SECRET_CLEANUP_INTERVAL_SECONDS: u64 = 60;
const SECRET_CSP_NONCE_BYTES: usize = 16;
const DOCS_ICON_HTML: &str = include_str!("../docs/icon.html");
const ICON_MAX_BYTES: usize = 256 * 1024;
const ICON_MAX_HTML_BYTES: usize = 512 * 1024;
const ICON_CACHE_OK_TTL_SECONDS: i64 = 7 * 24 * 3600;
const ICON_CACHE_ERR_TTL_SECONDS: i64 = 3600;
const ICON_CONNECT_TIMEOUT_SECONDS: u64 = 4;
const ICON_FETCH_TIMEOUT_SECONDS: u64 = 8;
const ICON_MAX_REDIRECTS: usize = 5;
const ICON_USER_AGENT: &str = "cc.me-favicon/1.0 (+https://cc.me/icon)";
const MIGRATE_ADVISORY_LOCK: i64 = 0x6363_6d65; // "ccme"
const DOCS_FONTS_HTML: &str = include_str!("../docs/fonts.html");
const DOCS_POW_HTML: &str = include_str!("../docs/pow.html");
const POW_JS: &str = include_str!("../docs/pow.js");
const DOCS_SHOT_HTML: &str = include_str!("../docs/shot.html");
const SHOT_MAX_DIM: u32 = 2048;
const SHOT_SETTLE_MS: u64 = 500;
const SHOT_CACHE_MAX_BYTES: usize = 8 * 1024 * 1024;
const SHOT_MAX_CONCURRENT: usize = 4;
const SHOT_CHROME_START_TIMEOUT_SECONDS: u64 = 15;
const FONTS_DEFAULT_DIR: &str = "/var/lib/fonts";
// Google Fonts groups families by license directory.
const FONTS_LICENSE_DIRS: [&str; 4] = ["ofl", "apache", "ufl", "cc-by-sa"];
const FONTS_DEFAULT_LIMIT: usize = 20;
const FONTS_MAX_LIMIT: usize = 100;
const FONTS_REFRESH_INTERVAL_SECONDS: u64 = 600;

static EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);
static EVENT_PREFIX: LazyLock<String> = LazyLock::new(|| {
    base36(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0),
    )
});

#[derive(Clone)]
struct AppState {
    db: PgPool,
    inbox_tx: broadcast::Sender<String>,
    library_tx: broadcast::Sender<String>,
    stats_tx: mpsc::Sender<StatEvent>,
    http: reqwest::Client,
    fonts: Arc<RwLock<Arc<FontIndex>>>,
    chrome: Arc<tokio::sync::Mutex<Option<CdpClient>>>,
    shot_permits: Arc<tokio::sync::Semaphore>,
    config: Config,
}

impl AppState {
    // Cheap lock-free-ish read: clone the current index Arc out of the lock so
    // handlers never hold the lock (which the refresh worker takes to swap) across
    // an await or a long scan.
    fn fonts_snapshot(&self) -> Arc<FontIndex> {
        self.fonts
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

#[derive(Clone)]
struct Config {
    bind_addr: SocketAddr,
    database_url: String,
    max_requests: usize,
    default_get_limit: usize,
    max_get_limit: usize,
    long_poll_seconds: f64,
    library_max_count: i64,
    library_max_ttl_seconds: f64,
    library_max_wait_seconds: f64,
    secret_default_ttl_hours: u64,
    secret_max_ttl_hours: u64,
    secret_max_bytes: usize,
    secret_cleanup_interval_seconds: u64,
    fonts_dir: PathBuf,
    fonts_refresh_interval_seconds: u64,
    shot_chrome_bin: String,
    shot_chrome_args: Vec<String>,
    shot_pow_level: u32,
    shot_ts_window_seconds: i64,
    shot_nav_timeout_seconds: f64,
    shot_cache_seconds: f64,
}

#[derive(Debug)]
struct AppError {
    status: StatusCode,
    message: String,
}

type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Default)]
struct InboxQuery {
    l: Option<usize>,
    p: bool,
    c: Option<Cursor>,
}

#[derive(Debug)]
struct Cursor {
    created_at_us: i64,
    id: String,
}

#[derive(Deserialize)]
struct AliasRequest {
    at: String,
}

#[derive(Serialize)]
struct AliasResponse {
    url: String,
}

#[derive(Deserialize)]
struct EmailSessionRequest {
    key: String,
}

#[derive(Serialize)]
struct EmailSessionResponse {
    email: String,
    aliases: Vec<EmailAliasResponse>,
    magic_links: Vec<EmailMagicLinkResponse>,
}

#[derive(Deserialize)]
struct EmailAliasCreateRequest {
    key: String,
    alias: String,
    #[serde(default)]
    expiry_days: Option<i64>,
}

#[derive(Deserialize)]
struct EmailAliasDeleteRequest {
    key: String,
}

#[derive(Deserialize)]
struct EmailAliasUpdateRequest {
    key: String,
    #[serde(default)]
    expires_at_unix: Option<i64>,
}

#[derive(Deserialize)]
struct EmailMagicLinkDeleteRequest {
    key: String,
}

#[derive(Serialize)]
struct EmailAliasResponse {
    alias: String,
    address: String,
    last_received_at_unix: Option<i64>,
    expires_at_unix: Option<i64>,
}

#[derive(Serialize)]
struct EmailMagicLinkResponse {
    id: String,
    created_at_unix: i64,
    last_used_at_unix: Option<i64>,
    expires_at_unix: i64,
    current: bool,
}

#[derive(Serialize)]
struct EnqueueResponse {
    queued: bool,
    recipients: usize,
}

#[derive(Serialize)]
struct SlackChallengeResponse {
    challenge: String,
}

#[derive(Serialize)]
struct DiscordInteractionResponse {
    r#type: u8,
}

#[derive(Serialize)]
struct MessageEnvelope {
    id: String,
    sealed: String,
}

#[derive(Serialize)]
struct PeekResponse {
    count: usize,
    items: Vec<MessageEnvelope>,
    cursor: Option<String>,
}

struct MessagePage {
    items: Vec<MessageEnvelope>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct ClaimRequest {
    limit: Option<usize>,
    poll: Option<bool>,
}

#[derive(Serialize)]
struct ClaimResponse {
    count: usize,
    items: Vec<MessageEnvelope>,
}

#[derive(Deserialize)]
struct BatchIds {
    ids: Vec<String>,
}

#[derive(Serialize)]
struct AckResponse {
    acked: usize,
    missing: Vec<String>,
}

#[derive(Serialize)]
struct ReleaseResponse {
    released: usize,
    missing: Vec<String>,
}

#[derive(Deserialize)]
struct PutResourceRequest {
    count: i64,
}

#[derive(Serialize, Deserialize)]
struct ResourceResponse {
    id: String,
    count: i64,
    in_use: i64,
    available: i64,
}

#[derive(Deserialize)]
struct BorrowRequest {
    ttl: f64,
    #[serde(default)]
    wait: f64,
}

#[derive(Serialize, Deserialize)]
struct BorrowResponse {
    lease: String,
    position: i64,
    expires_at_unix: i64,
    expires_in: i64,
}

#[derive(Deserialize)]
struct ReturnRequest {
    lease: String,
}

#[derive(Serialize, Deserialize)]
struct ReturnResponse {
    returned: bool,
}

#[derive(Serialize, Deserialize)]
struct DeleteResponse {
    deleted: bool,
}

#[derive(Deserialize)]
struct CreateSecretRequest {
    ciphertext: String,
    expires_hours: Option<u64>,
    #[serde(default = "default_auto_destroy")]
    auto_destroy: bool,
}

fn default_auto_destroy() -> bool {
    true
}

#[derive(Serialize)]
struct CreateSecretResponse {
    id: String,
    url: String,
}

#[derive(Serialize)]
struct SecretContentResponse {
    ciphertext: String,
    created_at_unix: u64,
    expires_at_unix: u64,
    auto_destroy: bool,
}

#[derive(Serialize)]
struct StatsResponse {
    now_unix: u64,
    last_48_hours: StatCounts,
    last_30_days: StatCounts,
    hourly: Vec<StatsBucket>,
    daily: Vec<StatsBucket>,
}

#[derive(Serialize)]
struct StatsBucket {
    start_unix: u64,
    redirects: usize,
    inboxes: usize,
    inboxed_messages: usize,
    aliases: usize,
    forwarded: usize,
    secrets: usize,
    favicons: usize,
    fonts: usize,
}

#[derive(Serialize)]
struct StatCounts {
    redirects: usize,
    inboxes: usize,
    inboxed_messages: usize,
    aliases: usize,
    forwarded: usize,
    secrets: usize,
    favicons: usize,
    fonts: usize,
}

#[derive(Debug, Serialize)]
struct CapturedRequest {
    id: String,
    received_at_unix_ms: u128,
    method: String,
    path: String,
    query: Option<String>,
    headers: Vec<CapturedHeader>,
    body_b64u: String,
}

#[derive(Debug, Serialize)]
struct CapturedHeader {
    name: String,
    value_b64u: String,
}

#[derive(Clone)]
struct StatEvent {
    kind: StatKind,
    member: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cc_me=info,tower_http=info".into()),
        )
        .init();

    let config = Config::from_env()?;
    let db = PgPoolOptions::new()
        .max_connections(env_usize("DATABASE_MAX_CONNECTIONS", 16) as u32)
        .connect(&config.database_url)
        .await?;
    migrate(&db).await?;

    let (inbox_tx, _) = broadcast::channel(INBOX_NOTIFY_CAPACITY);
    tokio::spawn(inbox_notification_worker(
        config.database_url.clone(),
        inbox_tx.clone(),
    ));

    let (library_tx, _) = broadcast::channel(LIBRARY_NOTIFY_CAPACITY);
    tokio::spawn(library_notification_worker(
        config.database_url.clone(),
        library_tx.clone(),
    ));

    let (stats_tx, stats_rx) = mpsc::channel(STATS_CHANNEL_CAPACITY);
    tokio::spawn(stats_worker(db.clone(), stats_rx));
    tokio::spawn(secret_cleanup_worker(
        db.clone(),
        config.secret_cleanup_interval_seconds,
    ));

    let http = build_http_client();

    let fonts_dir = config.fonts_dir.clone();
    let initial_fonts = {
        let dir = fonts_dir.clone();
        tokio::task::spawn_blocking(move || FontIndex::load(&dir)).await?
    };
    info!(
        "indexed {} font families from {}",
        initial_fonts.families.len(),
        config.fonts_dir.display()
    );
    let fonts = Arc::new(RwLock::new(Arc::new(initial_fonts)));
    if config.fonts_refresh_interval_seconds > 0 {
        tokio::spawn(fonts_refresh_worker(
            fonts_dir,
            Duration::from_secs(config.fonts_refresh_interval_seconds),
            fonts.clone(),
        ));
    }

    let app = Router::new()
        .route("/", get(root))
        .route("/http", get(http_docs))
        .route("/lib", get(library_docs))
        .route("/icon", get(icon))
        .route("/fonts", get(fonts_search))
        .route("/fonts/{slug}", get(font_family))
        .route("/fonts/{slug}/{filename}", get(font_file))
        .route("/pow", get(pow_docs))
        .route("/pow.js", get(pow_js))
        .route("/shot", get(shot))
        .route("/shot/config", get(shot_config))
        .route(
            "/l/{id}",
            put(put_resource).get(get_resource).delete(delete_resource),
        )
        .route("/l/{id}/borrow", post(borrow_resource))
        .route("/l/{id}/return", post(return_lease))
        .route("/styles.css", get(docs_styles))
        .route("/tweetnacl.js", get(tweetnacl_js))
        .route("/hi", get(email_page))
        .route("/email/session", post(email_session))
        .route("/email/aliases", post(create_email_alias))
        .route(
            "/email/aliases/{alias}",
            delete(delete_email_alias).patch(update_email_alias),
        )
        .route("/email/magic-links/{id}", delete(delete_email_magic_link))
        .route("/c", post(create_alias))
        .route("/c/{alias}", get(alias_redirect))
        .route("/stats", get(stats))
        .route("/i/{public_keys}", get(peek_inbox).post(enqueue_inbox))
        .route(
            "/i/{public_keys}/websub",
            get(websub_verify).post(enqueue_websub),
        )
        .route("/i/{public_keys}/webmention", post(enqueue_webmention))
        .route("/i/{public_keys}/slack", post(enqueue_slack))
        .route("/i/{public_keys}/pingback", post(enqueue_pingback))
        .route("/i/{public_keys}/meta", get(meta_verify).post(enqueue_meta))
        .route("/i/{public_keys}/cloudevents", post(enqueue_cloudevents))
        .route(
            "/i/{public_keys}/discord/{discord_public_key}",
            post(enqueue_discord),
        )
        .route("/i/{public_key}/claim", post(claim_inbox))
        .route("/i/{public_key}/ack", post(ack_inbox))
        .route("/i/{public_key}/release", post(release_inbox))
        .route("/p", get(paste_create_page).post(create_secret))
        .route("/p/{id}", get(paste_view_page).delete(burn_secret))
        .route("/p/{id}/content", get(read_secret_content))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(DefaultBodyLimit::max(MAX_CAPTURE_BYTES.max(SECRET_MAX_REQUEST_BYTES)))
        .layer(middleware::from_fn(serve_go_import))
        .with_state(AppState {
            db,
            inbox_tx,
            library_tx,
            stats_tx,
            http,
            fonts,
            chrome: Arc::new(tokio::sync::Mutex::new(None)),
            shot_permits: Arc::new(tokio::sync::Semaphore::new(SHOT_MAX_CONCURRENT)),
            config: config.clone(),
        });

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    info!("listening on http://{}", config.bind_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            error!(%err, "failed to install Ctrl-C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                error!(%err, "failed to install SIGTERM handler");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

// Serialize schema setup with a session-scoped advisory lock: Postgres
// `CREATE ... IF NOT EXISTS` is not race-safe, so concurrent callers (multiple
// app instances, or parallel tests) could otherwise fail with duplicate-object
// errors. The lock is held on a dedicated connection for the whole run and
// released when it returns.
async fn migrate(db: &PgPool) -> Result<(), sqlx::Error> {
    let mut lock = db.acquire().await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(MIGRATE_ADVISORY_LOCK)
        .execute(&mut *lock)
        .await?;
    let result = run_migrations(db).await;
    let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(MIGRATE_ADVISORY_LOCK)
        .execute(&mut *lock)
        .await;
    result
}

async fn run_migrations(db: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS aliases (
            id text PRIMARY KEY,
            target text NOT NULL
        )
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        DELETE FROM aliases duplicate
        USING aliases keep
        WHERE duplicate.target = keep.target
          AND duplicate.id > keep.id
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS aliases_target_idx ON aliases (target)")
        .execute(db)
        .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS email_login_keys (
            id text UNIQUE,
            token_hash bytea PRIMARY KEY,
            email text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            last_used_at timestamptz,
            expires_at timestamptz NOT NULL DEFAULT now() + interval '7 days',
            revoked_at timestamptz
        )
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query("ALTER TABLE email_login_keys ADD COLUMN IF NOT EXISTS id text")
        .execute(db)
        .await?;

    sqlx::query("ALTER TABLE email_login_keys ADD COLUMN IF NOT EXISTS expires_at timestamptz")
        .execute(db)
        .await?;

    sqlx::query("ALTER TABLE email_login_keys ADD COLUMN IF NOT EXISTS revoked_at timestamptz")
        .execute(db)
        .await?;

    sqlx::query(
        r#"
        UPDATE email_login_keys
        SET id = encode(substring(token_hash from 1 for 10), 'hex')
        WHERE id IS NULL
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        UPDATE email_login_keys
        SET expires_at = created_at + interval '30 days'
        WHERE expires_at IS NULL
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query("ALTER TABLE email_login_keys ALTER COLUMN id SET NOT NULL")
        .execute(db)
        .await?;

    sqlx::query("ALTER TABLE email_login_keys ALTER COLUMN expires_at SET NOT NULL")
        .execute(db)
        .await?;

    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS email_login_keys_id_idx ON email_login_keys (id)",
    )
    .execute(db)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS email_login_keys_email_idx ON email_login_keys (email, created_at DESC)",
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS email_aliases (
            alias text PRIMARY KEY,
            email text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now()
        )
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS email_aliases_email_idx ON email_aliases (email, alias)",
    )
    .execute(db)
    .await?;

    sqlx::query("ALTER TABLE email_aliases ADD COLUMN IF NOT EXISTS last_received_at timestamptz")
        .execute(db)
        .await?;

    sqlx::query("ALTER TABLE email_aliases ADD COLUMN IF NOT EXISTS expires_at timestamptz")
        .execute(db)
        .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS inbox_messages (
            inbox_key text NOT NULL,
            id text NOT NULL,
            sealed bytea NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            lease_until timestamptz,
            PRIMARY KEY (inbox_key, id)
        )
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = 'inbox_messages'
                  AND column_name = 'sealed'
                  AND data_type <> 'bytea'
            ) THEN
                ALTER TABLE inbox_messages
                ALTER COLUMN sealed TYPE bytea
                USING decode(
                    rpad(
                        translate(sealed, '-_', '+/'),
                        length(sealed) + ((4 - length(sealed) % 4) % 4),
                        '='
                    ),
                    'base64'
                );
            END IF;
        END $$;
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS inbox_messages_ready_idx ON inbox_messages (inbox_key, created_at, id)",
    )
    .execute(db)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS inbox_messages_lease_idx ON inbox_messages (inbox_key, lease_until, created_at, id)",
    )
    .execute(db)
    .await?;

    sqlx::query("DROP INDEX IF EXISTS inbox_messages_retention_idx")
        .execute(db)
        .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS inbox_messages_newest_idx ON inbox_messages (inbox_key, created_at DESC, id DESC)",
    )
    .execute(db)
    .await?;

    sqlx::query("DROP TABLE IF EXISTS inbox_drops")
        .execute(db)
        .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS inbox_counts (
            inbox_key text PRIMARY KEY,
            count bigint NOT NULL DEFAULT 0
        )
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO inbox_counts (inbox_key, count)
        SELECT inbox_key, count(*)::bigint
        FROM inbox_messages
        GROUP BY inbox_key
        ON CONFLICT (inbox_key)
        DO UPDATE SET count = EXCLUDED.count
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS stat_counts (
            period text NOT NULL,
            kind text NOT NULL,
            bucket bigint NOT NULL,
            count bigint NOT NULL,
            PRIMARY KEY (period, kind, bucket)
        )
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = 'stat_uniques'
                  AND column_name = 'member'
            ) THEN
                DROP TABLE stat_uniques;
            END IF;
        END $$;
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS stat_uniques (
            period text NOT NULL,
            kind text NOT NULL,
            bucket bigint NOT NULL,
            bits bytea NOT NULL,
            PRIMARY KEY (period, kind, bucket)
        )
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS library_resources (
            id         uuid PRIMARY KEY,
            count      bigint NOT NULL CHECK (count >= 0),
            created_at timestamptz NOT NULL DEFAULT now()
        )
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS secrets (
            id text PRIMARY KEY,
            ciphertext bytea NOT NULL,
            auto_destroy boolean NOT NULL DEFAULT true,
            created_at timestamptz NOT NULL DEFAULT now(),
            expires_at timestamptz NOT NULL
        )
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS library_leases (
            id          uuid PRIMARY KEY,
            resource_id uuid NOT NULL REFERENCES library_resources(id) ON DELETE CASCADE,
            position    bigint NOT NULL CHECK (position >= 0),
            acquired_at timestamptz NOT NULL DEFAULT now(),
            expires_at  timestamptz NOT NULL
        )
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        CREATE UNIQUE INDEX IF NOT EXISTS library_leases_slot_idx
            ON library_leases (resource_id, position)
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS library_leases_expiry_idx
            ON library_leases (resource_id, expires_at)
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS secrets_expires_at_idx ON secrets (expires_at)")
        .execute(db)
        .await?;

    sqlx::query(
        "ALTER TABLE secrets ADD COLUMN IF NOT EXISTS auto_destroy boolean NOT NULL DEFAULT true",
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS favicon_cache (
            origin       text PRIMARY KEY,
            content_type text,
            bytes        bytea,
            ok           boolean NOT NULL,
            fetched_at   timestamptz NOT NULL DEFAULT now()
        )
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS shot_cache (
            key        text PRIMARY KEY,
            bytes      bytea NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now()
        )
        "#,
    )
    .execute(db)
    .await?;

    Ok(())
}

async fn root(State(state): State<AppState>, RawQuery(raw_query): RawQuery) -> AppResult<Response> {
    let Some(query) = raw_query.as_deref() else {
        return Ok(docs_html_response());
    };

    let Some(target) = callback_target(query)? else {
        return Ok(docs_html_response());
    };

    let response = redirect(target.as_str())?;
    record_stat_soon(&state, StatKind::Redirect, None);
    Ok(response)
}

async fn docs_styles() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        DOCS_STYLES_CSS,
    )
}

async fn tweetnacl_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        TWEETNACL_JS,
    )
}

async fn http_docs() -> Response {
    docs_html(DOCS_HTTP_HTML)
}

async fn library_docs() -> Response {
    docs_html(DOCS_LIB_HTML)
}

async fn pow_docs() -> Response {
    docs_html(DOCS_POW_HTML)
}

// Favicon proxy. `GET /icon?url=<url>` returns the site's favicon bytes with a
// permissive CORS header (set by the global layer) so any page — e.g. found.as —
// can embed `<img src="https://cc.me/icon?url=https://example.com">`. With no
// `url` it serves the docs page. Missing favicons return 404, never a placeholder.
async fn icon(State(state): State<AppState>, RawQuery(raw_query): RawQuery) -> AppResult<Response> {
    let url = raw_query.as_deref().and_then(|query| {
        form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == "url")
            .map(|(_, value)| value.into_owned())
    });
    let Some(url) = url else {
        return Ok(docs_html(DOCS_ICON_HTML));
    };

    let origin = origin_of(&url)?;

    if let Some(hit) = favicon_cache_lookup(&state, &origin).await? {
        return match hit {
            Some((content_type, bytes)) => {
                record_stat_soon(&state, StatKind::Favicon, None);
                Ok(icon_image_response(&content_type, bytes))
            }
            None => Err(icon_not_found()),
        };
    }

    match fetch_favicon(&state.http, &origin).await {
        Some((content_type, bytes)) => {
            favicon_cache_store(&state, &origin, Some((&content_type, &bytes))).await?;
            record_stat_soon(&state, StatKind::Favicon, None);
            Ok(icon_image_response(&content_type, bytes))
        }
        None => {
            favicon_cache_store(&state, &origin, None).await?;
            Err(icon_not_found())
        }
    }
}

fn icon_not_found() -> AppError {
    AppError::new(StatusCode::NOT_FOUND, "favicon not found")
}

fn icon_image_response(content_type: &str, bytes: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type.to_owned()),
            (
                header::CACHE_CONTROL,
                format!("public, max-age={ICON_CACHE_OK_TTL_SECONDS}"),
            ),
        ],
        bytes,
    )
        .into_response()
}

// Normalize a user URL to its origin ("scheme://host[:port]"), used as the cache
// key and fetch base. Rejects non-http(s) URLs and literal forbidden IP hosts
// (defense in depth; the DNS resolver blocks hostnames that resolve to them).
fn origin_of(input: &str) -> AppResult<String> {
    let parsed =
        Url::parse(input).map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "url is invalid"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "url must be http or https",
        ));
    }
    // Reject literal-IP hosts pointing at non-public addresses. HTTP clients skip
    // the DNS resolver for IP literals, so this check (covering both v4 and v6,
    // brackets and all, via the typed Host) is the only guard for them.
    let forbidden = match parsed.host() {
        Some(url::Host::Ipv4(ip)) => ip_is_forbidden(&IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => ip_is_forbidden(&IpAddr::V6(ip)),
        Some(url::Host::Domain(_)) => false,
        None => return Err(AppError::new(StatusCode::BAD_REQUEST, "url has no host")),
    };
    if forbidden {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "url host is not allowed",
        ));
    }
    // `origin()` gives "scheme://host[:port]" with the host lowercased, IPv6
    // bracketed, and default ports dropped — a stable cache key and fetch base.
    Ok(parsed.origin().ascii_serialization())
}

// Ok(None) = cache miss (fetch); Ok(Some(None)) = fresh negative (return 404);
// Ok(Some(Some(..))) = fresh hit. Stale rows are treated as a miss.
async fn favicon_cache_lookup(
    state: &AppState,
    origin: &str,
) -> AppResult<Option<Option<(String, Vec<u8>)>>> {
    let row = sqlx::query(
        r#"
        SELECT content_type,
               bytes,
               ok,
               extract(epoch from (now() - fetched_at))::bigint AS age
        FROM favicon_cache
        WHERE origin = $1
        "#,
    )
    .bind(origin)
    .fetch_optional(&state.db)
    .await
    .map_err(db_error)?;

    let Some(row) = row else {
        return Ok(None);
    };
    let ok: bool = row.get("ok");
    let age: i64 = row.get("age");
    let ttl = if ok {
        ICON_CACHE_OK_TTL_SECONDS
    } else {
        ICON_CACHE_ERR_TTL_SECONDS
    };
    if age > ttl {
        return Ok(None);
    }
    if !ok {
        return Ok(Some(None));
    }
    let content_type: Option<String> = row.get("content_type");
    let bytes: Option<Vec<u8>> = row.get("bytes");
    match (content_type, bytes) {
        (Some(content_type), Some(bytes)) => Ok(Some(Some((content_type, bytes)))),
        _ => Ok(None),
    }
}

async fn favicon_cache_store(
    state: &AppState,
    origin: &str,
    image: Option<(&str, &[u8])>,
) -> AppResult<()> {
    let ok = image.is_some();
    let content_type = image.map(|(content_type, _)| content_type.to_owned());
    let bytes = image.map(|(_, bytes)| bytes.to_vec());
    sqlx::query(
        r#"
        INSERT INTO favicon_cache (origin, content_type, bytes, ok, fetched_at)
        VALUES ($1, $2, $3, $4, now())
        ON CONFLICT (origin) DO UPDATE
        SET content_type = EXCLUDED.content_type,
            bytes = EXCLUDED.bytes,
            ok = EXCLUDED.ok,
            fetched_at = now()
        "#,
    )
    .bind(origin)
    .bind(content_type)
    .bind(bytes)
    .bind(ok)
    .execute(&state.db)
    .await
    .map_err(db_error)?;
    Ok(())
}

// Discover and fetch the site's favicon: parse the homepage for <link rel="icon">
// candidates, then fall back to /favicon.ico. Returns the first response whose
// bytes are a recognizable image.
async fn fetch_favicon(client: &reqwest::Client, origin: &str) -> Option<(String, Vec<u8>)> {
    let mut candidates: Vec<String> = Vec::new();
    if let Some(html) = fetch_text(client, origin, ICON_MAX_HTML_BYTES).await {
        if let Ok(base) = Url::parse(origin) {
            for href in extract_icon_hrefs(&html) {
                // Inline `data:` icons (e.g. the emoji-favicon trick) carry the
                // image directly — decode and return it without a network hop.
                if href.starts_with("data:") || href.starts_with("DATA:") {
                    if let Some(image) = decode_data_uri(&href) {
                        return Some(image);
                    }
                    continue;
                }
                if let Ok(absolute) = base.join(&href) {
                    if matches!(absolute.scheme(), "http" | "https") {
                        candidates.push(absolute.to_string());
                    }
                }
            }
        }
    }
    candidates.push(format!("{origin}/favicon.ico"));

    for candidate in candidates {
        if let Some(image) = fetch_image(client, &candidate).await {
            return Some(image);
        }
    }
    None
}

// Decode a `data:` URI into (content_type, bytes), per RFC 2397. Handles both
// base64 and percent-encoded payloads. Only image payloads are accepted: a
// declared `image/*` media type is trusted (mirroring fetch_image's handling of
// server content types), otherwise the bytes must sniff as a known image format.
fn decode_data_uri(uri: &str) -> Option<(String, Vec<u8>)> {
    let rest = uri.get("data:".len()..)?;
    let (meta, data) = rest.split_once(',')?;
    let meta_lower = meta.to_ascii_lowercase();
    let is_base64 = meta_lower.ends_with(";base64");
    let media_type = meta_lower
        .strip_suffix(";base64")
        .unwrap_or(&meta_lower)
        .split(';')
        .next()
        .unwrap_or("")
        .trim();

    let bytes = if is_base64 {
        // Base64 data URIs may contain whitespace that must be stripped first.
        let cleaned: String = data.chars().filter(|c| !c.is_whitespace()).collect();
        general_purpose::STANDARD.decode(cleaned).ok()?
    } else {
        percent_encoding::percent_decode_str(data).collect()
    };
    if bytes.is_empty() || bytes.len() > ICON_MAX_BYTES {
        return None;
    }

    let content_type = if media_type.starts_with("image/") {
        media_type.to_owned()
    } else {
        sniff_image_content_type(&bytes)?.to_owned()
    };
    Some((content_type, bytes))
}

async fn fetch_text(client: &reqwest::Client, url: &str, cap: usize) -> Option<String> {
    let bytes = fetch_capped(client, url, cap).await?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

async fn fetch_image(client: &reqwest::Client, url: &str) -> Option<(String, Vec<u8>)> {
    let response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let server_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase());
    let bytes = read_capped(response, ICON_MAX_BYTES).await?;
    if bytes.is_empty() {
        return None;
    }
    let content_type = match server_type {
        Some(value) if value.starts_with("image/") => {
            value.split(';').next().unwrap_or(&value).trim().to_owned()
        }
        _ => sniff_image_content_type(&bytes)?.to_owned(),
    };
    Some((content_type, bytes))
}

async fn fetch_capped(client: &reqwest::Client, url: &str, cap: usize) -> Option<Vec<u8>> {
    let response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    read_capped(response, cap).await
}

// Stream the body, aborting (None) if it exceeds `cap` so a hostile server can't
// exhaust memory.
async fn read_capped(mut response: reqwest::Response, cap: usize) -> Option<Vec<u8>> {
    let mut buffer = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if buffer.len() + chunk.len() > cap {
            return None;
        }
        buffer.extend_from_slice(&chunk);
    }
    Some(buffer)
}

// Parse the page with a real HTML parser (html5ever, via scraper) and collect the
// href of every <link> whose rel mentions "icon" — covering "icon",
// "shortcut icon", and "apple-touch-icon". html5ever tolerates broken markup and
// decodes entities; /favicon.ico is always tried as a fallback.
fn extract_icon_hrefs(html: &str) -> Vec<String> {
    let document = scraper::Html::parse_document(html);
    let Ok(selector) = scraper::Selector::parse(r#"link[rel*="icon" i]"#) else {
        return Vec::new();
    };
    document
        .select(&selector)
        .filter_map(|element| element.value().attr("href"))
        .map(str::trim)
        .filter(|href| !href.is_empty())
        .map(str::to_owned)
        .collect()
}

fn sniff_image_content_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 4 && bytes[..4] == [0x00, 0x00, 0x01, 0x00] {
        return Some("image/x-icon");
    }
    if bytes.len() >= 8 && bytes[..8] == [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'] {
        return Some("image/png");
    }
    if bytes.len() >= 3 && &bytes[..3] == b"GIF" {
        return Some("image/gif");
    }
    if bytes.len() >= 3 && bytes[..3] == [0xff, 0xd8, 0xff] {
        return Some("image/jpeg");
    }
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    let head = &bytes[..bytes.len().min(512)];
    if String::from_utf8_lossy(head).to_ascii_lowercase().contains("<svg") {
        return Some("image/svg+xml");
    }
    None
}

fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(ICON_USER_AGENT)
        .connect_timeout(Duration::from_secs(ICON_CONNECT_TIMEOUT_SECONDS))
        .timeout(Duration::from_secs(ICON_FETCH_TIMEOUT_SECONDS))
        .redirect(reqwest::redirect::Policy::limited(ICON_MAX_REDIRECTS))
        .dns_resolver(Arc::new(SafeResolver))
        .build()
        .expect("build http client")
}

// A reqwest DNS resolver that drops non-global addresses before connecting.
// Because reqwest connects to exactly the addresses this returns, filtering here
// closes the DNS-rebinding TOCTOU gap and applies to every redirect hop too.
struct SafeResolver;

impl reqwest::dns::Resolve for SafeResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let resolved = tokio::task::spawn_blocking(move || {
                (host.as_str(), 0u16)
                    .to_socket_addrs()
                    .map(|addrs| addrs.collect::<Vec<SocketAddr>>())
            })
            .await
            .map_err(|err| -> Box<dyn std::error::Error + Send + Sync> { Box::new(err) })?
            .map_err(|err| -> Box<dyn std::error::Error + Send + Sync> { Box::new(err) })?;

            let allowed: Vec<SocketAddr> = resolved
                .into_iter()
                .filter(|addr| !ip_is_forbidden(&addr.ip()))
                .collect();
            if allowed.is_empty() {
                return Err("host resolves only to blocked addresses".into());
            }
            Ok(Box::new(allowed.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

// True for addresses we must never fetch from: loopback, private, link-local,
// CGNAT, multicast/reserved, unspecified, and their IPv6 equivalents.
fn ip_is_forbidden(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || octets[0] == 0
                || (octets[0] == 100 && (0x40..0x80).contains(&octets[1])) // 100.64.0.0/10 CGNAT
                || octets[0] >= 224 // multicast + reserved
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return ip_is_forbidden(&IpAddr::V4(mapped));
            }
            let segments = v6.segments();
            v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (segments[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

// ------------------------------------------------------------------
// Fonts: search and download over a clone of github.com/google/fonts.
// The clone lives at FONTS_DIR (default /var/lib/fonts) and is indexed
// into memory at startup; nothing is stored in Postgres.
// ------------------------------------------------------------------

#[derive(Default, Clone)]
struct FontFile {
    filename: String,
    style: Option<String>,
    weight: Option<i64>,
}

#[derive(Default, Clone)]
struct FontAxis {
    tag: String,
    min: Option<f64>,
    max: Option<f64>,
}

struct FontFamily {
    slug: String,
    name: String,
    name_lower: String,
    license: String,
    category: Option<String>,
    designer: Option<String>,
    subsets: Vec<String>,
    files: Vec<FontFile>,
    axes: Vec<FontAxis>,
    dir: PathBuf,
}

struct FontIndex {
    families: Vec<FontFamily>,
    by_slug: HashMap<String, usize>,
}

impl FontIndex {
    #[cfg(test)]
    fn empty() -> Self {
        Self {
            families: Vec::new(),
            by_slug: HashMap::new(),
        }
    }

    // Walk each license directory for family folders and parse their METADATA.pb.
    // Missing or unreadable entries are skipped so a partial clone still serves.
    fn load(dir: &std::path::Path) -> Self {
        let mut families = Vec::new();
        for license in FONTS_LICENSE_DIRS {
            let Ok(entries) = std::fs::read_dir(dir.join(license)) else {
                continue;
            };
            for entry in entries.flatten() {
                let family_dir = entry.path();
                if !family_dir.is_dir() {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(family_dir.join("METADATA.pb")) else {
                    continue;
                };
                let Ok(slug) = entry.file_name().into_string() else {
                    continue;
                };
                let metadata = parse_font_metadata(&text);
                let name = if metadata.name.is_empty() {
                    slug.clone()
                } else {
                    metadata.name
                };
                families.push(FontFamily {
                    name_lower: name.to_lowercase(),
                    slug,
                    name,
                    license: license.to_owned(),
                    category: metadata.category,
                    designer: metadata.designer,
                    subsets: metadata.subsets,
                    files: metadata.fonts,
                    axes: metadata.axes,
                    dir: family_dir,
                });
            }
        }
        families.sort_by(|a, b| a.name.cmp(&b.name));
        let by_slug = families
            .iter()
            .enumerate()
            .map(|(index, family)| (family.slug.to_lowercase(), index))
            .collect();
        Self { families, by_slug }
    }

    fn get(&self, slug: &str) -> Option<&FontFamily> {
        self.by_slug
            .get(&slug.to_lowercase())
            .map(|&index| &self.families[index])
    }
}

// Periodically re-index the clone (e.g. after a `git pull`) and swap the result
// in atomically. Interval 0 disables refresh (handled by the caller).
async fn fonts_refresh_worker(
    dir: PathBuf,
    interval: Duration,
    handle: Arc<RwLock<Arc<FontIndex>>>,
) {
    loop {
        tokio::time::sleep(interval).await;
        let dir = dir.clone();
        match tokio::task::spawn_blocking(move || FontIndex::load(&dir)).await {
            Ok(index) => {
                let count = index.families.len();
                *handle.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(index);
                info!("refreshed {count} font families");
            }
            Err(err) => error!(%err, "font index refresh failed"),
        }
    }
}

#[derive(Default)]
struct FontMetadata {
    name: String,
    designer: Option<String>,
    category: Option<String>,
    subsets: Vec<String>,
    fonts: Vec<FontFile>,
    axes: Vec<FontAxis>,
}

enum MetaBlock {
    Fonts,
    Axes,
    Other,
}

// A focused reader for the fields we serve out of protobuf text-format
// METADATA.pb. The format is line-oriented: `key: value`, `key {` opening a
// nested message, and `}` closing it. We only descend into `fonts {}` and
// `axes {}` (one level), and ignore everything else.
fn parse_font_metadata(text: &str) -> FontMetadata {
    let mut metadata = FontMetadata::default();
    let mut depth = 0usize;
    let mut block: Option<MetaBlock> = None;
    let mut font = FontFile::default();
    let mut axis = FontAxis::default();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(key) = line.strip_suffix('{') {
            if depth == 0 {
                block = Some(match key.trim() {
                    "fonts" => MetaBlock::Fonts,
                    "axes" => MetaBlock::Axes,
                    _ => MetaBlock::Other,
                });
                font = FontFile::default();
                axis = FontAxis::default();
            }
            depth += 1;
            continue;
        }
        if line == "}" {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                match block {
                    Some(MetaBlock::Fonts) if !font.filename.is_empty() => {
                        metadata.fonts.push(std::mem::take(&mut font));
                    }
                    Some(MetaBlock::Axes) if !axis.tag.is_empty() => {
                        metadata.axes.push(std::mem::take(&mut axis));
                    }
                    _ => {}
                }
                block = None;
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match (depth, block.as_ref()) {
            (0, _) => match key {
                "name" => metadata.name = unquote_textproto(value),
                "designer" => metadata.designer = Some(unquote_textproto(value)),
                "category" => metadata.category = Some(unquote_textproto(value)),
                "subsets" => {
                    let subset = unquote_textproto(value);
                    if !subset.is_empty() {
                        metadata.subsets.push(subset);
                    }
                }
                _ => {}
            },
            (1, Some(MetaBlock::Fonts)) => match key {
                "filename" => font.filename = unquote_textproto(value),
                "style" => font.style = Some(unquote_textproto(value)),
                "weight" => font.weight = value.parse().ok(),
                _ => {}
            },
            (1, Some(MetaBlock::Axes)) => match key {
                "tag" => axis.tag = unquote_textproto(value),
                "min_value" => axis.min = value.parse().ok(),
                "max_value" => axis.max = value.parse().ok(),
                _ => {}
            },
            _ => {}
        }
    }
    metadata
}

fn unquote_textproto(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        value[1..value.len() - 1]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    } else {
        value.to_owned()
    }
}

#[derive(Serialize)]
struct FontFileEntry {
    filename: String,
    style: Option<String>,
    weight: Option<i64>,
    path: String,
}

#[derive(Serialize)]
struct FontAxisEntry {
    tag: String,
    min: Option<f64>,
    max: Option<f64>,
}

#[derive(Serialize)]
struct FontSummary {
    slug: String,
    name: String,
    license: String,
    category: Option<String>,
    designer: Option<String>,
    subsets: Vec<String>,
    variable: bool,
    files: Vec<FontFileEntry>,
}

#[derive(Serialize)]
struct FontDetail {
    #[serde(flatten)]
    summary: FontSummary,
    axes: Vec<FontAxisEntry>,
}

#[derive(Serialize)]
struct FontSearchResponse {
    total: usize,
    count: usize,
    offset: usize,
    limit: usize,
    families: Vec<FontSummary>,
}

fn font_summary(family: &FontFamily) -> FontSummary {
    FontSummary {
        slug: family.slug.clone(),
        name: family.name.clone(),
        license: family.license.clone(),
        category: family.category.clone(),
        designer: family.designer.clone(),
        subsets: family.subsets.clone(),
        variable: !family.axes.is_empty(),
        files: family
            .files
            .iter()
            .map(|file| FontFileEntry {
                path: format!("/fonts/{}/{}", family.slug, file.filename),
                filename: file.filename.clone(),
                style: file.style.clone(),
                weight: file.weight,
            })
            .collect(),
    }
}

// `GET /fonts` — search when a query string is present, otherwise the docs page.
// Filters: q (name/slug substring), category, subset; paginated with limit/offset.
async fn fonts_search(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<Response> {
    let Some(query) = raw_query.as_deref().filter(|query| !query.is_empty()) else {
        return Ok(docs_html(DOCS_FONTS_HTML));
    };

    let mut q = String::new();
    let mut category: Option<String> = None;
    let mut subset: Option<String> = None;
    let mut limit = FONTS_DEFAULT_LIMIT;
    let mut offset = 0usize;
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "q" => q = value.into_owned().to_lowercase(),
            "category" => category = Some(value.into_owned().to_uppercase()),
            "subset" => subset = Some(value.into_owned().to_lowercase()),
            "limit" => {
                limit = value
                    .parse::<usize>()
                    .unwrap_or(FONTS_DEFAULT_LIMIT)
                    .clamp(1, FONTS_MAX_LIMIT);
            }
            "offset" => offset = value.parse::<usize>().unwrap_or(0),
            _ => {}
        }
    }

    let fonts = state.fonts_snapshot();
    let matched = fonts.families.iter().filter(|family| {
        (q.is_empty() || family.name_lower.contains(&q) || family.slug.contains(&q))
            && category
                .as_deref()
                .is_none_or(|wanted| family.category.as_deref() == Some(wanted))
            && subset
                .as_deref()
                .is_none_or(|wanted| family.subsets.iter().any(|subset| subset == wanted))
    });

    let total = matched.clone().count();
    let families: Vec<FontSummary> = matched.skip(offset).take(limit).map(font_summary).collect();

    Ok(Json(FontSearchResponse {
        total,
        count: families.len(),
        offset,
        limit,
        families,
    })
    .into_response())
}

async fn font_family(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> AppResult<Json<FontDetail>> {
    let fonts = state.fonts_snapshot();
    let family = fonts
        .get(&slug)
        .ok_or_else(|| AppError::new(StatusCode::NOT_FOUND, "font family not found"))?;
    Ok(Json(FontDetail {
        summary: font_summary(family),
        axes: family
            .axes
            .iter()
            .map(|axis| FontAxisEntry {
                tag: axis.tag.clone(),
                min: axis.min,
                max: axis.max,
            })
            .collect(),
    }))
}

async fn font_file(
    State(state): State<AppState>,
    Path((slug, filename)): Path<(String, String)>,
) -> AppResult<Response> {
    let fonts = state.fonts_snapshot();
    let family = fonts
        .get(&slug)
        .ok_or_else(|| AppError::new(StatusCode::NOT_FOUND, "font family not found"))?;
    // Only serve files listed in the family's metadata — this whitelist is what
    // prevents path traversal out of the family directory.
    if !family.files.iter().any(|file| file.filename == filename) {
        return Err(AppError::new(StatusCode::NOT_FOUND, "font file not found"));
    }
    let bytes = tokio::fs::read(family.dir.join(&filename))
        .await
        .map_err(|_| AppError::new(StatusCode::NOT_FOUND, "font file not found"))?;
    record_stat_soon(&state, StatKind::Font, None);
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, font_content_type(&filename).to_owned()),
            (
                header::CACHE_CONTROL,
                "public, max-age=604800".to_owned(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("inline; filename=\"{filename}\""),
            ),
        ],
        bytes,
    )
        .into_response())
}

fn font_content_type(filename: &str) -> &'static str {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".woff2") {
        "font/woff2"
    } else if lower.ends_with(".woff") {
        "font/woff"
    } else if lower.ends_with(".otf") {
        "font/otf"
    } else if lower.ends_with(".ttf") {
        "font/ttf"
    } else {
        "application/octet-stream"
    }
}

fn parse_uuid(id: &str) -> AppResult<Uuid> {
    Uuid::parse_str(id).map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "id must be a UUID"))
}

async fn put_resource(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<PutResourceRequest>,
) -> AppResult<Json<ResourceResponse>> {
    let id = parse_uuid(&id)?;
    if body.count < 0 || body.count > state.config.library_max_count {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "count out of range"));
    }

    sqlx::query(
        r#"
        INSERT INTO library_resources (id, count)
        VALUES ($1, $2)
        ON CONFLICT (id) DO UPDATE SET count = EXCLUDED.count
        "#,
    )
    .bind(id)
    .bind(body.count)
    .execute(&state.db)
    .await
    .map_err(db_error)?;

    notify_library(&state, &id.to_string()).await;
    resource_response(&state, id).await
}

async fn get_resource(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<ResourceResponse>> {
    let id = parse_uuid(&id)?;
    resource_response(&state, id).await
}

async fn resource_response(state: &AppState, id: Uuid) -> AppResult<Json<ResourceResponse>> {
    let Some(row) = sqlx::query(
        r#"
        SELECT r.count,
               (SELECT count(*) FROM library_leases l
                WHERE l.resource_id = r.id
                  AND l.expires_at > now()
                  AND l.position < r.count) AS in_use
        FROM library_resources r
        WHERE r.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(db_error)?
    else {
        return Err(AppError::new(StatusCode::NOT_FOUND, "resource not found"));
    };

    let count: i64 = row.get("count");
    let in_use: i64 = row.get("in_use");
    Ok(Json(ResourceResponse {
        id: id.to_string(),
        count,
        in_use,
        available: count - in_use,
    }))
}

async fn delete_resource(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<DeleteResponse>> {
    let id = parse_uuid(&id)?;
    let result = sqlx::query("DELETE FROM library_resources WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(db_error)?;

    Ok(Json(DeleteResponse {
        deleted: result.rows_affected() == 1,
    }))
}

async fn borrow_resource(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<BorrowRequest>,
) -> AppResult<Json<BorrowResponse>> {
    let id = parse_uuid(&id)?;
    if body.ttl <= 0.0 {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "ttl must be positive",
        ));
    }
    let ttl = body.ttl.clamp(0.0, state.config.library_max_ttl_seconds);
    let wait = body.wait.clamp(0.0, state.config.library_max_wait_seconds);

    let deadline = Instant::now() + Duration::from_secs_f64(wait);
    let mut rx = state.library_tx.subscribe();

    loop {
        match try_borrow(&state, id, ttl).await? {
            BorrowOutcome::Acquired {
                lease,
                position,
                expires_at_unix,
            } => {
                let now = current_unix_seconds()? as i64;
                return Ok(Json(BorrowResponse {
                    lease: lease.to_string(),
                    position,
                    expires_at_unix,
                    expires_in: (expires_at_unix - now).max(0),
                }));
            }
            BorrowOutcome::Missing => {
                return Err(AppError::new(StatusCode::NOT_FOUND, "resource not found"));
            }
            BorrowOutcome::Full { next_expiry } => {
                if Instant::now() >= deadline {
                    return Err(AppError::new(StatusCode::CONFLICT, "no resource available"));
                }
                let wait_deadline = match next_expiry {
                    Some(expiry) => {
                        let now = current_unix_seconds()? as i64;
                        let seconds = (expiry - now).max(0) as u64;
                        let expiry_instant = Instant::now() + Duration::from_secs(seconds);
                        deadline.min(expiry_instant)
                    }
                    None => deadline,
                };
                if !wait_for_library_notification(&mut rx, &id.to_string(), wait_deadline).await {
                    // timeout: take one last look
                }
            }
        }
    }
}

enum BorrowOutcome {
    Acquired {
        lease: Uuid,
        position: i64,
        expires_at_unix: i64,
    },
    Full {
        next_expiry: Option<i64>,
    },
    Missing,
}

async fn try_borrow(state: &AppState, id: Uuid, ttl: f64) -> AppResult<BorrowOutcome> {
    let mut tx = state.db.begin().await.map_err(db_error)?;

    let Some(row) = sqlx::query("SELECT count FROM library_resources WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?
    else {
        return Ok(BorrowOutcome::Missing);
    };
    let count: i64 = row.get("count");

    sqlx::query("DELETE FROM library_leases WHERE resource_id = $1 AND expires_at <= now()")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;

    // `min(gs)` is an aggregate: it always returns exactly one row, whose value is
    // NULL when no position is free (full pool, or count == 0 → empty series). Decode
    // as Option<i64> with fetch_one; None means "no free slot".
    let position = sqlx::query_scalar::<_, Option<i64>>(
        r#"
        SELECT min(gs)
        FROM generate_series(0, $2 - 1) AS gs
        WHERE NOT EXISTS (
            SELECT 1 FROM library_leases l
            WHERE l.resource_id = $1 AND l.position = gs
        )
        "#,
    )
    .bind(id)
    .bind(count)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_error)?;

    if let Some(position) = position {
        let lease = Uuid::new_v4();
        let row = sqlx::query(
            r#"
            INSERT INTO library_leases (id, resource_id, position, expires_at)
            VALUES ($1, $2, $3, now() + ($4 * interval '1 second'))
            RETURNING position, extract(epoch from expires_at)::bigint AS expires_at_unix
            "#,
        )
        .bind(lease)
        .bind(id)
        .bind(position)
        .bind(ttl)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;

        tx.commit().await.map_err(db_error)?;
        let expires_at_unix: i64 = row.get("expires_at_unix");
        return Ok(BorrowOutcome::Acquired {
            lease,
            position,
            expires_at_unix,
        });
    }

    let next_expiry = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT extract(epoch from min(expires_at))::bigint FROM library_leases WHERE resource_id = $1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_error)?;

    Ok(BorrowOutcome::Full { next_expiry })
}

async fn return_lease(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ReturnRequest>,
) -> AppResult<Json<ReturnResponse>> {
    let id = parse_uuid(&id)?;
    let lease = Uuid::parse_str(&body.lease)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "lease must be a UUID"))?;

    let result = sqlx::query(
        "DELETE FROM library_leases WHERE id = $1 AND resource_id = $2 AND expires_at > now() RETURNING id",
    )
    .bind(lease)
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(db_error)?;

    let returned = result.rows_affected() == 1;
    if returned {
        notify_library(&state, &id.to_string()).await;
    }

    Ok(Json(ReturnResponse { returned }))
}

async fn notify_library(state: &AppState, id: &str) {
    let _ = state.library_tx.send(id.to_owned());
    if let Err(err) = sqlx::query("SELECT pg_notify($1, $2)")
        .bind(LIBRARY_NOTIFY_CHANNEL)
        .bind(id)
        .execute(&state.db)
        .await
    {
        error!(%err, "library notification failed");
    }
}

async fn library_notification_worker(database_url: String, library_tx: broadcast::Sender<String>) {
    loop {
        match PgListener::connect(&database_url).await {
            Ok(mut listener) => {
                if let Err(err) = listener.listen(LIBRARY_NOTIFY_CHANNEL).await {
                    error!(%err, "failed to listen for library notifications");
                } else {
                    while let Ok(notification) = listener.recv().await {
                        let _ = library_tx.send(notification.payload().to_owned());
                    }
                }
            }
            Err(err) => {
                error!(%err, "failed to connect library notification listener");
            }
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn wait_for_library_notification(
    library_rx: &mut broadcast::Receiver<String>,
    resource_id: &str,
    deadline: Instant,
) -> bool {
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return false;
        };

        match tokio::time::timeout(remaining, library_rx.recv()).await {
            Ok(Ok(notified_id)) if notified_id == resource_id => return true,
            Ok(Ok(_)) => {}
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => return true,
            Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => return false,
        }
    }
}

fn docs_html_response() -> Response {
    docs_html(DOCS_INDEX_HTML)
}

fn docs_html(body: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, DOCS_CSP),
        ],
        body,
    )
        .into_response()
}

async fn create_alias(
    State(state): State<AppState>,
    Json(body): Json<AliasRequest>,
) -> AppResult<(StatusCode, Json<AliasResponse>)> {
    let target = parse_callback_target(&body.at)?;
    let alias = insert_alias(&state, target.as_str()).await?;

    Ok((
        StatusCode::CREATED,
        Json(AliasResponse {
            url: format!("{PUBLIC_BASE_URL}/c/{alias}"),
        }),
    ))
}

async fn email_page() -> Html<&'static str> {
    Html(EMAIL_PAGE_HTML)
}

async fn email_session(
    State(state): State<AppState>,
    Json(body): Json<EmailSessionRequest>,
) -> AppResult<Json<EmailSessionResponse>> {
    let email = email_for_key(&state, &body.key).await?;
    let aliases = load_email_aliases(&state, &email).await?;
    let magic_links = load_email_magic_links(&state, &email, &body.key).await?;
    Ok(Json(EmailSessionResponse {
        email,
        aliases,
        magic_links,
    }))
}

async fn create_email_alias(
    State(state): State<AppState>,
    Json(body): Json<EmailAliasCreateRequest>,
) -> AppResult<(StatusCode, Json<EmailAliasResponse>)> {
    let email = email_for_key(&state, &body.key).await?;
    let alias = normalize_email_alias(&body.alias)?;
    let expiry_days = match body.expiry_days {
        Some(days) if !(1..=3650).contains(&days) => {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                "expiry must be between 1 and 3650 days",
            ));
        }
        other => other.map(|days| days as i32),
    };

    let expires_at_unix = sqlx::query_scalar::<_, Option<i64>>(
        r#"
        INSERT INTO email_aliases (alias, email, expires_at)
        VALUES (
            $1, $2,
            CASE WHEN $3::int IS NULL THEN NULL ELSE now() + ($3::int * interval '1 day') END
        )
        RETURNING extract(epoch from expires_at)::bigint
        "#,
    )
    .bind(&alias)
    .bind(&email)
    .bind(expiry_days)
    .fetch_one(&state.db)
    .await
    .map_err(|err| match err {
        sqlx::Error::Database(db_err) if db_err.is_unique_violation() => {
            AppError::new(StatusCode::CONFLICT, "alias is already taken")
        }
        err => db_error(err),
    })?;

    record_stat_soon(&state, StatKind::Alias, None);

    Ok((
        StatusCode::CREATED,
        Json(EmailAliasResponse {
            address: email_alias_address(&alias),
            alias,
            last_received_at_unix: None,
            expires_at_unix,
        }),
    ))
}

async fn delete_email_alias(
    State(state): State<AppState>,
    Path(alias): Path<String>,
    Json(body): Json<EmailAliasDeleteRequest>,
) -> AppResult<Json<EmailAliasResponse>> {
    let email = email_for_key(&state, &body.key).await?;
    let alias = normalize_email_alias(&alias)?;
    let Some(row) = sqlx::query(
        r#"
        DELETE FROM email_aliases
        WHERE alias = $1 AND email = $2
        RETURNING alias
        "#,
    )
    .bind(&alias)
    .bind(&email)
    .fetch_optional(&state.db)
    .await
    .map_err(db_error)?
    else {
        return Err(AppError::new(StatusCode::NOT_FOUND, "alias not found"));
    };
    let alias = row.get::<String, _>("alias");

    Ok(Json(EmailAliasResponse {
        address: email_alias_address(&alias),
        alias,
        last_received_at_unix: None,
        expires_at_unix: None,
    }))
}

async fn update_email_alias(
    State(state): State<AppState>,
    Path(alias): Path<String>,
    Json(body): Json<EmailAliasUpdateRequest>,
) -> AppResult<Json<EmailAliasResponse>> {
    let email = email_for_key(&state, &body.key).await?;
    let alias = normalize_email_alias(&alias)?;
    let expires_at_unix = match body.expires_at_unix {
        Some(ts) if !(0..=4_102_444_800).contains(&ts) => {
            return Err(AppError::new(StatusCode::BAD_REQUEST, "invalid expiry"));
        }
        other => other,
    };

    let Some(row) = sqlx::query(
        r#"
        UPDATE email_aliases
        SET expires_at = CASE WHEN $3::bigint IS NULL THEN NULL ELSE to_timestamp($3::bigint) END
        WHERE alias = $1 AND email = $2
        RETURNING extract(epoch from last_received_at)::bigint AS last_received_at_unix,
                  extract(epoch from expires_at)::bigint AS expires_at_unix
        "#,
    )
    .bind(&alias)
    .bind(&email)
    .bind(expires_at_unix)
    .fetch_optional(&state.db)
    .await
    .map_err(db_error)?
    else {
        return Err(AppError::new(StatusCode::NOT_FOUND, "alias not found"));
    };

    Ok(Json(EmailAliasResponse {
        address: email_alias_address(&alias),
        alias,
        last_received_at_unix: row.get::<Option<i64>, _>("last_received_at_unix"),
        expires_at_unix: row.get::<Option<i64>, _>("expires_at_unix"),
    }))
}

async fn delete_email_magic_link(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<EmailMagicLinkDeleteRequest>,
) -> AppResult<Json<EmailMagicLinkResponse>> {
    let email = email_for_key(&state, &body.key).await?;
    let current_hash = email_key_hash(&body.key)?;
    let Some(row) = sqlx::query(
        r#"
        UPDATE email_login_keys
        SET revoked_at = COALESCE(revoked_at, now())
        WHERE id = $1 AND email = $2
        RETURNING id,
                  extract(epoch from created_at)::bigint AS created_at_unix,
                  extract(epoch from last_used_at)::bigint AS last_used_at_unix,
                  extract(epoch from expires_at)::bigint AS expires_at_unix,
                  token_hash = $3 AS current
        "#,
    )
    .bind(&id)
    .bind(&email)
    .bind(&current_hash)
    .fetch_optional(&state.db)
    .await
    .map_err(db_error)?
    else {
        return Err(AppError::new(StatusCode::NOT_FOUND, "magic link not found"));
    };

    Ok(Json(email_magic_link_from_row(row)))
}

async fn insert_alias(state: &AppState, target: &str) -> AppResult<String> {
    for _ in 0..4 {
        let alias = random_alias_id()?;
        let existing_or_inserted = sqlx::query_scalar::<_, String>(
            r#"
            WITH inserted AS (
                INSERT INTO aliases (id, target)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
                RETURNING id
            )
            SELECT id FROM inserted
            UNION ALL
            SELECT id FROM aliases WHERE target = $2
            LIMIT 1
            "#,
        )
        .bind(&alias)
        .bind(target)
        .fetch_optional(&state.db)
        .await
        .map_err(db_error)?;

        if let Some(alias) = existing_or_inserted {
            return Ok(alias);
        }
    }

    let alias = random_alias_id()?;
    sqlx::query_scalar::<_, String>(
        r#"
            INSERT INTO aliases (id, target)
            VALUES ($1, $2)
            ON CONFLICT (target) DO UPDATE SET target = aliases.target
            RETURNING id
        "#,
    )
    .bind(alias)
    .bind(target)
    .fetch_one(&state.db)
    .await
    .map_err(db_error)
}

async fn alias_redirect(
    State(state): State<AppState>,
    Path(alias): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<Response> {
    let Some(row) = sqlx::query("SELECT target FROM aliases WHERE id = $1")
        .bind(&alias)
        .fetch_optional(&state.db)
        .await
        .map_err(db_error)?
    else {
        return Err(AppError::new(StatusCode::NOT_FOUND, "alias not found"));
    };

    let mut target = parse_callback_target(row.get::<String, _>("target").as_str())?;
    append_query_params(&mut target, raw_query.as_deref());
    let response = redirect(target.as_str())?;
    record_stat_soon(&state, StatKind::Redirect, None);
    Ok(response)
}

async fn paste_create_page(State(_state): State<AppState>) -> AppResult<Response> {
    let nonce = csp_nonce()?;
    let html = include_str!("paste_create.html").replace("{{nonce}}", &nonce);
    Ok(secret_page_response(&html, &nonce))
}

async fn paste_view_page(State(_state): State<AppState>, Path(_id): Path<String>) -> AppResult<Response> {
    let nonce = csp_nonce()?;
    let html = include_str!("paste_view.html").replace("{{nonce}}", &nonce);
    Ok(secret_page_response(&html, &nonce))
}

fn secret_page_response(html: &str, nonce: &str) -> Response {
    let csp = format!(
        "default-src 'none'; script-src 'nonce-{0}' 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'",
        nonce
    );
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "text/html; charset=utf-8".parse().unwrap());
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert(
        header::HeaderName::from_static("referrer-policy"),
        "no-referrer".parse().unwrap(),
    );
    headers.insert(header::CONTENT_SECURITY_POLICY, csp.parse().unwrap());
    (StatusCode::OK, headers, html.to_owned()).into_response()
}

fn csp_nonce() -> AppResult<String> {
    let mut bytes = [0u8; SECRET_CSP_NONCE_BYTES];
    OsRng
        .unwrap_err()
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "randomness failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

async fn create_secret(
    State(state): State<AppState>,
    Json(body): Json<CreateSecretRequest>,
) -> AppResult<(StatusCode, Json<CreateSecretResponse>)> {
    let ciphertext = decode_secret_ciphertext(&state.config, &body.ciphertext)?;
    let ttl_hours = body
        .expires_hours
        .unwrap_or(state.config.secret_default_ttl_hours)
        .clamp(1, state.config.secret_max_ttl_hours);
    let id = insert_secret(&state, &ciphertext, body.auto_destroy, ttl_hours).await?;
    record_stat_soon(&state, StatKind::Secret, None);

    Ok((
        StatusCode::CREATED,
        Json(CreateSecretResponse {
            id: id.clone(),
            url: format!("{PUBLIC_BASE_URL}/p/{id}"),
        }),
    ))
}

async fn insert_secret(
    state: &AppState,
    ciphertext: &[u8],
    auto_destroy: bool,
    ttl_hours: u64,
) -> AppResult<String> {
    for _ in 0..4 {
        let id = random_secret_id()?;
        let inserted = sqlx::query_scalar::<_, String>(
            r#"
            INSERT INTO secrets (id, ciphertext, auto_destroy, expires_at)
            VALUES ($1, $2, $3, now() + make_interval(hours => $4::int))
            ON CONFLICT DO NOTHING
            RETURNING id
            "#,
        )
        .bind(&id)
        .bind(ciphertext)
        .bind(auto_destroy)
        .bind(ttl_hours as i32)
        .fetch_optional(&state.db)
        .await
        .map_err(db_error)?;

        if let Some(id) = inserted {
            return Ok(id);
        }
    }

    Err(AppError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "failed to generate a unique secret id",
    ))
}

async fn read_secret_content(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<(StatusCode, HeaderMap, Json<SecretContentResponse>)> {
    let row = sqlx::query(
        r#"
        DELETE FROM secrets
        WHERE id = $1 AND expires_at > now() AND auto_destroy = true
        RETURNING ciphertext, auto_destroy, extract(epoch from created_at)::bigint AS created_at_unix, extract(epoch from expires_at)::bigint AS expires_at_unix
        "#,
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .map_err(db_error)?;

    let row = match row {
        Some(row) => row,
        None => sqlx::query(
            r#"
            SELECT ciphertext, auto_destroy, extract(epoch from created_at)::bigint AS created_at_unix, extract(epoch from expires_at)::bigint AS expires_at_unix
            FROM secrets
            WHERE id = $1 AND expires_at > now() AND auto_destroy = false
            "#,
        )
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .map_err(db_error)?
        .ok_or_else(|| AppError::new(StatusCode::GONE, "secret has already been read or has expired"))?,
    };

    record_stat_soon(&state, StatKind::Secret, None);
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    Ok((
        StatusCode::OK,
        headers,
        Json(SecretContentResponse {
            ciphertext: URL_SAFE_NO_PAD.encode(row.get::<Vec<u8>, _>("ciphertext")),
            created_at_unix: row.get::<i64, _>("created_at_unix") as u64,
            expires_at_unix: row.get::<i64, _>("expires_at_unix") as u64,
            auto_destroy: row.get::<bool, _>("auto_destroy"),
        }),
    ))
}

async fn burn_secret(State(state): State<AppState>, Path(id): Path<String>) -> AppResult<StatusCode> {
    let deleted = sqlx::query("DELETE FROM secrets WHERE id = $1 RETURNING id")
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .map_err(db_error)?;

    if deleted.is_none() {
        return Err(AppError::new(
            StatusCode::GONE,
            "secret has already been read or has expired",
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn enqueue_inbox(
    State(state): State<AppState>,
    Path(public_keys): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<impl IntoResponse> {
    enqueue_request(&state, &public_keys, method, uri, headers, body).await
}

async fn enqueue_webmention(
    State(state): State<AppState>,
    Path(public_keys): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<impl IntoResponse> {
    validate_webmention(&headers, &body)?;
    enqueue_request(&state, &public_keys, method, uri, headers, body).await
}

async fn websub_verify(
    Path(public_keys): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<Response> {
    let _ = decode_public_keys(&public_keys)?;
    let challenge = websub_challenge(raw_query.as_deref())?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        challenge,
    )
        .into_response())
}

async fn enqueue_websub(
    State(state): State<AppState>,
    Path(public_keys): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<impl IntoResponse> {
    enqueue_request(&state, &public_keys, method, uri, headers, body).await
}

async fn enqueue_slack(
    State(state): State<AppState>,
    Path(public_keys): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    if let Some(challenge) = slack_challenge(&headers, &body)? {
        return Ok(Json(SlackChallengeResponse { challenge }).into_response());
    }

    Ok(
        enqueue_request(&state, &public_keys, method, uri, headers, body)
            .await?
            .into_response(),
    )
}

async fn enqueue_pingback(
    State(state): State<AppState>,
    Path(public_keys): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    validate_pingback(&headers, &body)?;
    let _ = enqueue_request(&state, &public_keys, method, uri, headers, body).await?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/xml; charset=utf-8")],
        pingback_success_response(),
    )
        .into_response())
}

async fn meta_verify(
    Path(public_keys): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<Response> {
    let _ = decode_public_keys(&public_keys)?;
    let challenge = meta_challenge(raw_query.as_deref())?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        challenge,
    )
        .into_response())
}

async fn enqueue_meta(
    State(state): State<AppState>,
    Path(public_keys): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<impl IntoResponse> {
    enqueue_request(&state, &public_keys, method, uri, headers, body).await
}

async fn enqueue_cloudevents(
    State(state): State<AppState>,
    Path(public_keys): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<impl IntoResponse> {
    validate_cloudevent(&headers, &body)?;
    enqueue_request(&state, &public_keys, method, uri, headers, body).await
}

async fn enqueue_discord(
    State(state): State<AppState>,
    Path((public_keys, discord_public_key)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    verify_discord_signature(&discord_public_key, &headers, &body)?;
    let interaction_type = discord_interaction_type(&headers, &body)?;
    if interaction_type == 1 {
        return Ok(Json(DiscordInteractionResponse { r#type: 1 }).into_response());
    }

    let _ = enqueue_request(&state, &public_keys, method, uri, headers, body).await?;
    Ok(Json(DiscordInteractionResponse { r#type: 5 }).into_response())
}

async fn enqueue_request(
    state: &AppState,
    public_keys: &str,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<(StatusCode, Json<EnqueueResponse>)> {
    let public_keys = decode_public_keys(public_keys)?;
    let id = next_message_id();
    let payload = capture_request(id.clone(), method, uri, headers, body)?;
    let plaintext = encode_captured_request(&payload)?;
    let mut messages = Vec::with_capacity(public_keys.len());

    for (key_suffix, verifying_key) in &public_keys {
        let public_key = derive_x25519_public_key(verifying_key)?;
        let ciphertext = public_key
            .seal(&mut OsRng.unwrap_err(), &plaintext)
            .map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "encryption failed"))?;

        messages.push((key_suffix.clone(), ciphertext));
    }

    insert_inbox_messages(state, &id, &messages).await?;

    for (key_suffix, _) in &messages {
        record_stat_soon(state, StatKind::Message, None);
        record_stat_soon(state, StatKind::Inbox, Some(key_suffix.clone()));
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(EnqueueResponse {
            queued: true,
            recipients: public_keys.len(),
        }),
    ))
}

async fn insert_inbox_messages(
    state: &AppState,
    id: &str,
    messages: &[(String, Vec<u8>)],
) -> AppResult<()> {
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let mut inbox_keys = messages
        .iter()
        .map(|(inbox_key, _)| inbox_key.clone())
        .collect::<Vec<_>>();
    inbox_keys.sort();

    for inbox_key in &inbox_keys {
        sqlx::query(
            r#"
            INSERT INTO inbox_counts (inbox_key, count)
            VALUES ($1, 0)
            ON CONFLICT (inbox_key)
            DO NOTHING
            "#,
        )
        .bind(inbox_key)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    }

    for inbox_key in &inbox_keys {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT count FROM inbox_counts WHERE inbox_key = $1 FOR UPDATE",
        )
        .bind(inbox_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;

        if count as usize >= state.config.max_requests {
            return Err(AppError::new(StatusCode::CONFLICT, "inbox is full"));
        }
    }

    let mut inserted_keys = Vec::with_capacity(messages.len());
    for (inbox_key, sealed) in messages {
        let result = sqlx::query(
            r#"
            INSERT INTO inbox_messages (inbox_key, id, sealed)
            VALUES ($1, $2, $3)
            ON CONFLICT (inbox_key, id) DO NOTHING
            "#,
        )
        .bind(inbox_key)
        .bind(id)
        .bind(sealed)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;

        if result.rows_affected() == 1 {
            inserted_keys.push(inbox_key.clone());
        }
    }

    for inbox_key in &inserted_keys {
        sqlx::query("UPDATE inbox_counts SET count = count + 1 WHERE inbox_key = $1")
            .bind(inbox_key)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
    }

    tx.commit().await.map_err(db_error)?;
    for inbox_key in inserted_keys {
        notify_inbox(state, &inbox_key).await;
    }
    Ok(())
}

async fn stats(State(state): State<AppState>) -> AppResult<Json<StatsResponse>> {
    let stats = load_stats(&state).await?;
    Ok(Json(stats))
}

fn verify_inbox_request(
    verifying_key: &VerifyingKey,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &Bytes,
) -> AppResult<()> {
    let timestamp = header_string(headers, AUTH_TIMESTAMP_HEADER)
        .ok_or_else(|| AppError::new(StatusCode::UNAUTHORIZED, "timestamp is required"))?
        .parse::<u64>()
        .map_err(|_| {
            AppError::new(
                StatusCode::UNAUTHORIZED,
                "timestamp must be a positive integer",
            )
        })?;

    let signature = header_string(headers, AUTH_SIGNATURE_HEADER)
        .ok_or_else(|| AppError::new(StatusCode::UNAUTHORIZED, "signature is required"))?;

    let now = current_unix_seconds()?;
    if timestamp.saturating_add(AUTH_WINDOW_SECONDS) < now || timestamp > now + AUTH_WINDOW_SECONDS
    {
        return Err(AppError::new(
            StatusCode::UNAUTHORIZED,
            "timestamp is outside acceptable window",
        ));
    }

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&signature)
        .map_err(|_| AppError::new(StatusCode::UNAUTHORIZED, "signature must be base64url"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| AppError::new(StatusCode::UNAUTHORIZED, "signature is invalid"))?;

    let body_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(body));
    let path = uri
        .path_and_query()
        .map(|path_and_query| path_and_query.as_str())
        .unwrap_or_else(|| uri.path());
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}",
        AUTH_VERSION,
        method.as_str(),
        path,
        timestamp,
        body_hash
    );

    verifying_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|_| AppError::new(StatusCode::UNAUTHORIZED, "signature is invalid"))
}

async fn peek_inbox(
    State(state): State<AppState>,
    Path(public_key): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> AppResult<Json<PeekResponse>> {
    let public_key = decode_public_key(&public_key)?;
    verify_inbox_request(&public_key, &method, &uri, &headers, &Bytes::new())?;
    let key_suffix = public_key_key(&public_key);
    let query = parse_inbox_query(uri.query())?;
    let limit = inbox_limit(query.l, &state.config);

    let mut page = peek_messages(&state, &key_suffix, limit, query.c.as_ref()).await?;
    if query.p && page.items.is_empty() {
        page = long_poll_peek(&state, &key_suffix, limit, query.c.as_ref()).await?;
    }

    Ok(Json(PeekResponse {
        count: page.items.len(),
        items: page.items,
        cursor: page.cursor,
    }))
}

async fn claim_inbox(
    State(state): State<AppState>,
    Path(public_key): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Json<ClaimResponse>> {
    let public_key = decode_public_key(&public_key)?;
    verify_inbox_request(&public_key, &method, &uri, &headers, &body)?;
    let key_suffix = public_key_key(&public_key);
    let request: ClaimRequest = serde_json::from_slice(&body)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "invalid request body"))?;
    let limit = inbox_limit(request.limit, &state.config);

    let mut items = claim_once(&state, &key_suffix, limit).await?;
    if request.poll.unwrap_or(false) && items.is_empty() {
        items = long_poll_claim(&state, &key_suffix, limit).await?;
    }
    let count = items.len();

    Ok(Json(ClaimResponse { count, items }))
}

async fn ack_inbox(
    State(state): State<AppState>,
    Path(public_key): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Json<AckResponse>> {
    let public_key = decode_public_key(&public_key)?;
    verify_inbox_request(&public_key, &method, &uri, &headers, &body)?;
    let key_suffix = public_key_key(&public_key);
    let request: BatchIds = serde_json::from_slice(&body)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "invalid request body"))?;
    validate_batch_ids(&request.ids)?;
    let (acked, missing) = ack_messages(&state, &key_suffix, &request.ids).await?;
    Ok(Json(AckResponse { acked, missing }))
}

async fn release_inbox(
    State(state): State<AppState>,
    Path(public_key): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Json<ReleaseResponse>> {
    let public_key = decode_public_key(&public_key)?;
    verify_inbox_request(&public_key, &method, &uri, &headers, &body)?;
    let key_suffix = public_key_key(&public_key);
    let request: BatchIds = serde_json::from_slice(&body)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "invalid request body"))?;
    validate_batch_ids(&request.ids)?;
    let (released, missing) = release_messages(&state, &key_suffix, &request.ids).await?;
    if released > 0 {
        notify_inbox(&state, &key_suffix).await;
    }
    Ok(Json(ReleaseResponse { released, missing }))
}

async fn peek_messages(
    state: &AppState,
    inbox_key: &str,
    limit: usize,
    cursor: Option<&Cursor>,
) -> AppResult<MessagePage> {
    let cursor_us = cursor.map(|cursor| cursor.created_at_us);
    let cursor_id = cursor.map(|cursor| cursor.id.as_str());
    let rows = sqlx::query(
        r#"
        WITH ready AS (
            SELECT id,
                   sealed,
                   created_at,
                   floor(extract(epoch from created_at) * 1000000)::bigint AS created_at_us
            FROM inbox_messages
            WHERE inbox_key = $1
              AND (lease_until IS NULL OR lease_until <= now())
        )
        SELECT id, sealed, created_at_us
        FROM ready
        WHERE $3::bigint IS NULL
           OR created_at_us > $3
           OR (created_at_us = $3 AND id > $4::text)
        ORDER BY created_at ASC, id ASC
        LIMIT $2
        "#,
    )
    .bind(inbox_key)
    .bind(limit as i64)
    .bind(cursor_us)
    .bind(cursor_id)
    .fetch_all(&state.db)
    .await
    .map_err(db_error)?;

    Ok(page_from_rows(rows, cursor))
}

async fn claim_once(
    state: &AppState,
    inbox_key: &str,
    limit: usize,
) -> AppResult<Vec<MessageEnvelope>> {
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let rows = sqlx::query(
        r#"
        WITH candidates AS (
            SELECT id, sealed, created_at
            FROM inbox_messages
            WHERE inbox_key = $1
              AND (lease_until IS NULL OR lease_until <= now())
            ORDER BY created_at ASC, id ASC
            LIMIT $2
            FOR UPDATE SKIP LOCKED
        ),
        sized AS (
            SELECT id, sealed,
                   sum(length(id) + ((length(sealed) * 4 + 2) / 3) + 64)
                   OVER (ORDER BY created_at ASC, id ASC) AS used
            FROM candidates
        ),
        chosen AS (
            SELECT id, sealed
            FROM sized
            WHERE used <= $3
        ),
        updated AS (
            UPDATE inbox_messages m
            SET lease_until = now() + ($4::double precision * interval '1 second')
            FROM chosen
            WHERE m.inbox_key = $1 AND m.id = chosen.id
            RETURNING m.id, m.sealed
        )
        SELECT id, sealed FROM updated
        "#,
    )
    .bind(inbox_key)
    .bind(limit as i64)
    .bind(inbox_item_budget() as i64)
    .bind(CLAIM_RECOVERY_SECONDS as f64)
    .fetch_all(&mut *tx)
    .await
    .map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;

    Ok(envelopes_from_rows(rows))
}

async fn ack_messages(
    state: &AppState,
    inbox_key: &str,
    ids: &[String],
) -> AppResult<(usize, Vec<String>)> {
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let rows = sqlx::query(
        r#"
        DELETE FROM inbox_messages
        WHERE inbox_key = $1 AND id = ANY($2)
        RETURNING id
        "#,
    )
    .bind(inbox_key)
    .bind(ids)
    .fetch_all(&mut *tx)
    .await
    .map_err(db_error)?;

    let acked = rows.len();
    if acked > 0 {
        sqlx::query(
            r#"
            UPDATE inbox_counts
            SET count = GREATEST(count - $2, 0::bigint)
            WHERE inbox_key = $1
            "#,
        )
        .bind(inbox_key)
        .bind(acked as i64)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    }

    tx.commit().await.map_err(db_error)?;
    Ok(batch_result(ids, rows))
}

async fn release_messages(
    state: &AppState,
    inbox_key: &str,
    ids: &[String],
) -> AppResult<(usize, Vec<String>)> {
    let rows = sqlx::query(
        r#"
        UPDATE inbox_messages
        SET lease_until = NULL
        WHERE inbox_key = $1 AND id = ANY($2)
        RETURNING id
        "#,
    )
    .bind(inbox_key)
    .bind(ids)
    .fetch_all(&state.db)
    .await
    .map_err(db_error)?;

    Ok(batch_result(ids, rows))
}

async fn long_poll_peek(
    state: &AppState,
    inbox_key: &str,
    limit: usize,
    cursor: Option<&Cursor>,
) -> AppResult<MessagePage> {
    let deadline = Instant::now() + Duration::from_secs_f64(state.config.long_poll_seconds);
    let mut inbox_rx = state.inbox_tx.subscribe();
    loop {
        let page = peek_messages(state, inbox_key, limit, cursor).await?;
        if !page.items.is_empty() || Instant::now() >= deadline {
            return Ok(page);
        }
        if !wait_for_inbox_notification(&mut inbox_rx, inbox_key, deadline).await {
            return peek_messages(state, inbox_key, limit, cursor).await;
        }
    }
}

async fn long_poll_claim(
    state: &AppState,
    inbox_key: &str,
    limit: usize,
) -> AppResult<Vec<MessageEnvelope>> {
    let deadline = Instant::now() + Duration::from_secs_f64(state.config.long_poll_seconds);
    let mut inbox_rx = state.inbox_tx.subscribe();
    loop {
        let items = claim_once(state, inbox_key, limit).await?;
        if !items.is_empty() || Instant::now() >= deadline {
            return Ok(items);
        }
        if !wait_for_inbox_notification(&mut inbox_rx, inbox_key, deadline).await {
            return claim_once(state, inbox_key, limit).await;
        }
    }
}

fn envelopes_from_rows(rows: Vec<sqlx::postgres::PgRow>) -> Vec<MessageEnvelope> {
    let mut items = Vec::with_capacity(rows.len());
    let mut used = 0usize;

    for row in rows {
        let id = row.get::<String, _>("id");
        let sealed = row.get::<Vec<u8>, _>("sealed");
        let cost = inbox_item_cost(&id, sealed.len());
        if used + cost > inbox_item_budget() {
            break;
        }
        used += cost;
        items.push(MessageEnvelope {
            id,
            sealed: URL_SAFE_NO_PAD.encode(sealed),
        });
    }

    items
}

fn page_from_rows(rows: Vec<sqlx::postgres::PgRow>, cursor: Option<&Cursor>) -> MessagePage {
    let mut items = Vec::with_capacity(rows.len());
    let mut cursor = cursor.map(encode_cursor);
    let mut used = 0usize;

    for row in rows {
        let id = row.get::<String, _>("id");
        let sealed = row.get::<Vec<u8>, _>("sealed");
        let cost = inbox_item_cost(&id, sealed.len());
        if used + cost > inbox_item_budget() {
            break;
        }
        used += cost;
        cursor = Some(encode_cursor(&Cursor {
            created_at_us: row.get::<i64, _>("created_at_us"),
            id: id.clone(),
        }));
        items.push(MessageEnvelope {
            id,
            sealed: URL_SAFE_NO_PAD.encode(sealed),
        });
    }

    MessagePage { items, cursor }
}

async fn wait_for_inbox_notification(
    inbox_rx: &mut broadcast::Receiver<String>,
    inbox_key: &str,
    deadline: Instant,
) -> bool {
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return false;
        };

        match tokio::time::timeout(remaining, inbox_rx.recv()).await {
            Ok(Ok(notified_key)) if notified_key == inbox_key => return true,
            Ok(Ok(_)) => {}
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => return true,
            Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => return false,
        }
    }
}

async fn notify_inbox(state: &AppState, inbox_key: &str) {
    let _ = state.inbox_tx.send(inbox_key.to_owned());
    if let Err(err) = sqlx::query("SELECT pg_notify($1, $2)")
        .bind(INBOX_NOTIFY_CHANNEL)
        .bind(inbox_key)
        .execute(&state.db)
        .await
    {
        error!(%err, "inbox notification failed");
    }
}

fn batch_result(ids: &[String], rows: Vec<sqlx::postgres::PgRow>) -> (usize, Vec<String>) {
    let found = rows
        .into_iter()
        .map(|row| row.get::<String, _>("id"))
        .collect::<HashSet<_>>();
    let missing = ids
        .iter()
        .filter(|id| !found.contains(*id))
        .cloned()
        .collect::<Vec<_>>();
    (found.len(), missing)
}

async fn load_stats(state: &AppState) -> AppResult<StatsResponse> {
    let now = current_unix_seconds()?;
    let hour_buckets = recent_buckets(hour_bucket(now), STATS_HOURS);
    let day_buckets = recent_buckets(day_bucket(now), STATS_DAYS);

    let last_48_hours = StatCounts {
        redirects: count_total(
            &state.db,
            StatKind::Redirect,
            StatPeriod::Hour,
            &hour_buckets,
        )
        .await?,
        inboxes: count_total(&state.db, StatKind::Inbox, StatPeriod::Hour, &hour_buckets).await?,
        inboxed_messages: count_total(
            &state.db,
            StatKind::Message,
            StatPeriod::Hour,
            &hour_buckets,
        )
        .await?,
        aliases: count_total(&state.db, StatKind::Alias, StatPeriod::Hour, &hour_buckets).await?,
        forwarded: count_total(
            &state.db,
            StatKind::Forward,
            StatPeriod::Hour,
            &hour_buckets,
        )
        .await?,
        secrets: count_total(&state.db, StatKind::Secret, StatPeriod::Hour, &hour_buckets).await?,
        favicons: count_total(&state.db, StatKind::Favicon, StatPeriod::Hour, &hour_buckets)
            .await?,
        fonts: count_total(&state.db, StatKind::Font, StatPeriod::Hour, &hour_buckets).await?,
    };
    let last_30_days = StatCounts {
        redirects: count_total(&state.db, StatKind::Redirect, StatPeriod::Day, &day_buckets)
            .await?,
        inboxes: count_total(&state.db, StatKind::Inbox, StatPeriod::Day, &day_buckets).await?,
        inboxed_messages: count_total(&state.db, StatKind::Message, StatPeriod::Day, &day_buckets)
            .await?,
        aliases: count_total(&state.db, StatKind::Alias, StatPeriod::Day, &day_buckets).await?,
        forwarded: count_total(&state.db, StatKind::Forward, StatPeriod::Day, &day_buckets).await?,
        secrets: count_total(&state.db, StatKind::Secret, StatPeriod::Day, &day_buckets).await?,
        favicons: count_total(&state.db, StatKind::Favicon, StatPeriod::Day, &day_buckets).await?,
        fonts: count_total(&state.db, StatKind::Font, StatPeriod::Day, &day_buckets).await?,
    };

    let hourly = stat_buckets(&state.db, hour_buckets, 3600, StatPeriod::Hour).await?;
    let daily = stat_buckets(&state.db, day_buckets, 86_400, StatPeriod::Day).await?;

    Ok(StatsResponse {
        now_unix: now,
        last_48_hours,
        last_30_days,
        hourly,
        daily,
    })
}

async fn stat_buckets(
    db: &PgPool,
    buckets: Vec<u64>,
    bucket_seconds: u64,
    period: StatPeriod,
) -> AppResult<Vec<StatsBucket>> {
    let redirects = count_series(db, StatKind::Redirect, period, &buckets).await?;
    let inboxes = count_series(db, StatKind::Inbox, period, &buckets).await?;
    let messages = count_series(db, StatKind::Message, period, &buckets).await?;
    let aliases = count_series(db, StatKind::Alias, period, &buckets).await?;
    let forwarded = count_series(db, StatKind::Forward, period, &buckets).await?;
    let secrets = count_series(db, StatKind::Secret, period, &buckets).await?;
    let favicons = count_series(db, StatKind::Favicon, period, &buckets).await?;
    let fonts = count_series(db, StatKind::Font, period, &buckets).await?;

    Ok(buckets
        .into_iter()
        .map(|bucket| StatsBucket {
            start_unix: bucket * bucket_seconds,
            redirects: *redirects.get(&bucket).unwrap_or(&0),
            inboxes: *inboxes.get(&bucket).unwrap_or(&0),
            inboxed_messages: *messages.get(&bucket).unwrap_or(&0),
            aliases: *aliases.get(&bucket).unwrap_or(&0),
            forwarded: *forwarded.get(&bucket).unwrap_or(&0),
            secrets: *secrets.get(&bucket).unwrap_or(&0),
            favicons: *favicons.get(&bucket).unwrap_or(&0),
            fonts: *fonts.get(&bucket).unwrap_or(&0),
        })
        .collect())
}

async fn count_total(
    db: &PgPool,
    kind: StatKind,
    period: StatPeriod,
    buckets: &[u64],
) -> AppResult<usize> {
    let buckets = buckets
        .iter()
        .map(|bucket| *bucket as i64)
        .collect::<Vec<_>>();
    let count = if kind == StatKind::Inbox {
        Some(unique_total(db, period, kind, &buckets).await? as i64)
    } else {
        sqlx::query_scalar::<_, Option<i64>>(
            "SELECT sum(count)::bigint FROM stat_counts WHERE period = $1 AND kind = $2 AND bucket = ANY($3)",
        )
        .bind(period.code())
        .bind(kind.code())
        .bind(&buckets)
        .fetch_one(db)
        .await
        .map_err(db_error)?
    };

    Ok(count.unwrap_or(0) as usize)
}

async fn count_series(
    db: &PgPool,
    kind: StatKind,
    period: StatPeriod,
    buckets: &[u64],
) -> AppResult<HashMap<u64, usize>> {
    let bucket_args = buckets
        .iter()
        .map(|bucket| *bucket as i64)
        .collect::<Vec<_>>();
    let rows = if kind == StatKind::Inbox {
        sqlx::query(
            r#"
            SELECT bucket, bits
            FROM stat_uniques
            WHERE period = $1 AND kind = $2 AND bucket = ANY($3)
            "#,
        )
        .bind(period.code())
        .bind(kind.code())
        .bind(&bucket_args)
        .fetch_all(db)
        .await
        .map_err(db_error)?
    } else {
        sqlx::query(
            r#"
            SELECT bucket, sum(count)::bigint AS count
            FROM stat_counts
            WHERE period = $1 AND kind = $2 AND bucket = ANY($3)
            GROUP BY bucket
            "#,
        )
        .bind(period.code())
        .bind(kind.code())
        .bind(&bucket_args)
        .fetch_all(db)
        .await
        .map_err(db_error)?
    };

    if kind == StatKind::Inbox {
        Ok(rows
            .into_iter()
            .map(|row| {
                (
                    row.get::<i64, _>("bucket") as u64,
                    estimate_unique_bits(&row.get::<Vec<u8>, _>("bits")),
                )
            })
            .collect())
    } else {
        Ok(rows
            .into_iter()
            .map(|row| {
                (
                    row.get::<i64, _>("bucket") as u64,
                    row.get::<i64, _>("count") as usize,
                )
            })
            .collect())
    }
}

async fn unique_total(
    db: &PgPool,
    period: StatPeriod,
    kind: StatKind,
    buckets: &[i64],
) -> AppResult<usize> {
    let rows = sqlx::query(
        r#"
        SELECT bits
        FROM stat_uniques
        WHERE period = $1 AND kind = $2 AND bucket = ANY($3)
        "#,
    )
    .bind(period.code())
    .bind(kind.code())
    .bind(buckets)
    .fetch_all(db)
    .await
    .map_err(db_error)?;

    let mut merged = vec![0u8; STATS_BYTES];
    for row in rows {
        merge_unique_bits(&mut merged, &row.get::<Vec<u8>, _>("bits"));
    }
    Ok(estimate_unique_bits(&merged))
}

fn record_stat_soon(state: &AppState, kind: StatKind, member: Option<String>) {
    let _ = state.stats_tx.try_send(StatEvent { kind, member });
}

async fn inbox_notification_worker(database_url: String, inbox_tx: broadcast::Sender<String>) {
    loop {
        match PgListener::connect(&database_url).await {
            Ok(mut listener) => {
                if let Err(err) = listener.listen(INBOX_NOTIFY_CHANNEL).await {
                    error!(%err, "failed to listen for inbox notifications");
                } else {
                    while let Ok(notification) = listener.recv().await {
                        let _ = inbox_tx.send(notification.payload().to_owned());
                    }
                }
            }
            Err(err) => {
                error!(%err, "failed to connect inbox notification listener");
            }
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn secret_cleanup_worker(db: PgPool, interval_seconds: u64) {
    let mut interval = tokio::time::interval(Duration::from_secs(interval_seconds));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        match sqlx::query("DELETE FROM secrets WHERE expires_at <= now()")
            .execute(&db)
            .await
        {
            Ok(result) => {
                let rows = result.rows_affected();
                if rows > 0 {
                    info!(rows, "expired secrets cleaned up");
                }
            }
            Err(err) => error!(%err, "secret cleanup failed"),
        }
    }
}

async fn stats_worker(db: PgPool, mut rx: mpsc::Receiver<StatEvent>) {
    let mut batch = Vec::with_capacity(STATS_BATCH_MAX);
    while let Some(event) = rx.recv().await {
        batch.clear();
        batch.push(event);
        while batch.len() < STATS_BATCH_MAX {
            match rx.try_recv() {
                Ok(event) => batch.push(event),
                Err(_) => break,
            }
        }

        if let Err(err) = record_stat_batch(&db, &batch).await {
            error!(status = %err.status, message = %err.message, "stats record failed");
        }
    }
}

async fn record_stat_batch(db: &PgPool, batch: &[StatEvent]) -> AppResult<()> {
    let now = current_unix_seconds()?;
    let periods = [
        (StatPeriod::Hour, hour_bucket(now)),
        (StatPeriod::Day, day_bucket(now)),
    ];
    let mut tx = db.begin().await.map_err(db_error)?;

    for (period, bucket) in periods {
        for kind in [
            StatKind::Redirect,
            StatKind::Message,
            StatKind::Alias,
            StatKind::Forward,
            StatKind::Secret,
            StatKind::Favicon,
            StatKind::Font,
        ] {
            let count = batch.iter().filter(|event| event.kind == kind).count();
            if count > 0 {
                insert_stat_count(&mut tx, period, kind, bucket, count).await?;
            }
        }

        for event in batch.iter().filter(|event| event.kind == StatKind::Inbox) {
            if let Some(member) = event.member.as_deref() {
                insert_stat_unique(&mut tx, period, StatKind::Inbox, bucket, member).await?;
            }
        }
    }

    tx.commit().await.map_err(db_error)?;
    Ok(())
}

async fn insert_stat_count(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    period: StatPeriod,
    kind: StatKind,
    bucket: u64,
    count: usize,
) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO stat_counts (period, kind, bucket, count)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (period, kind, bucket)
        DO UPDATE SET count = stat_counts.count + EXCLUDED.count
        "#,
    )
    .bind(period.code())
    .bind(kind.code())
    .bind(bucket as i64)
    .bind(count as i64)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(())
}

async fn insert_stat_unique(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    period: StatPeriod,
    kind: StatKind,
    bucket: u64,
    member: &str,
) -> AppResult<()> {
    let empty = vec![0u8; STATS_BYTES];
    let bit = unique_bit(member);
    sqlx::query(
        r#"
        INSERT INTO stat_uniques (period, kind, bucket, bits)
        VALUES ($1, $2, $3, set_bit($4::bytea, $5, 1))
        ON CONFLICT (period, kind, bucket)
        DO UPDATE SET bits = set_bit(stat_uniques.bits, $5, 1)
        "#,
    )
    .bind(period.code())
    .bind(kind.code())
    .bind(bucket as i64)
    .bind(empty)
    .bind(bit)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(())
}

fn capture_request(
    id: String,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<CapturedRequest> {
    if body.len() > MAX_CAPTURE_BYTES {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "captured request must be at most 64 KiB",
        ));
    }

    let received_at_unix_ms = current_unix_millis()?;
    let headers = headers
        .iter()
        .map(|(name, value)| CapturedHeader {
            name: name.as_str().to_owned(),
            value_b64u: URL_SAFE_NO_PAD.encode(value.as_bytes()),
        })
        .collect();

    Ok(CapturedRequest {
        id,
        received_at_unix_ms,
        method: method.as_str().to_owned(),
        path: uri.path().to_owned(),
        query: uri.query().map(ToOwned::to_owned),
        headers,
        body_b64u: URL_SAFE_NO_PAD.encode(body),
    })
}

fn encode_captured_request(payload: &CapturedRequest) -> AppResult<Vec<u8>> {
    let plaintext = serde_json::to_vec(payload).map_err(internal)?;
    if plaintext.len() > MAX_CAPTURE_BYTES {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "captured request must be at most 64 KiB",
        ));
    }

    Ok(plaintext)
}

fn validate_webmention(headers: &HeaderMap, body: &Bytes) -> AppResult<()> {
    if !is_form_urlencoded(headers) {
        return Err(AppError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "webmention must use application/x-www-form-urlencoded",
        ));
    }

    let mut source = None;
    let mut target = None;
    for (key, value) in form_urlencoded::parse(body) {
        match key.as_ref() {
            "source" if source.is_none() => {
                source = Some(parse_webmention_url("source", &value)?);
            }
            "target" if target.is_none() => {
                target = Some(parse_webmention_url("target", &value)?);
            }
            _ => {}
        }
    }

    if source.is_none() {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "webmention source is required",
        ));
    }
    if target.is_none() {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "webmention target is required",
        ));
    }

    Ok(())
}

fn websub_challenge(raw_query: Option<&str>) -> AppResult<String> {
    let mut challenge = None;
    for (key, value) in form_urlencoded::parse(raw_query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "hub.challenge" if challenge.is_none() => {
                challenge = Some(value.into_owned());
            }
            "hub.mode" if value != "subscribe" && value != "unsubscribe" => {
                return Err(AppError::new(
                    StatusCode::BAD_REQUEST,
                    "hub.mode must be subscribe or unsubscribe",
                ));
            }
            "hub.topic" => {
                let _ = parse_protocol_url("hub.topic", &value)?;
            }
            _ => {}
        }
    }

    challenge.ok_or_else(|| AppError::new(StatusCode::BAD_REQUEST, "hub.challenge is required"))
}

fn meta_challenge(raw_query: Option<&str>) -> AppResult<String> {
    let mut challenge = None;
    let mut verify_token = None;
    let mut expected_token = None;
    for (key, value) in form_urlencoded::parse(raw_query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "hub.challenge" if challenge.is_none() => {
                challenge = Some(value.into_owned());
            }
            "hub.mode" if value != "subscribe" => {
                return Err(AppError::new(
                    StatusCode::BAD_REQUEST,
                    "hub.mode must be subscribe",
                ));
            }
            "hub.verify_token" if verify_token.is_none() => {
                verify_token = Some(value.into_owned());
            }
            "v" | "verify_token" if expected_token.is_none() => {
                expected_token = Some(value.into_owned());
            }
            _ => {}
        }
    }

    if let Some(expected_token) = expected_token
        && verify_token.as_deref() != Some(expected_token.as_str())
    {
        return Err(AppError::new(
            StatusCode::FORBIDDEN,
            "hub.verify_token did not match",
        ));
    }

    challenge.ok_or_else(|| AppError::new(StatusCode::BAD_REQUEST, "hub.challenge is required"))
}

fn slack_challenge(headers: &HeaderMap, body: &Bytes) -> AppResult<Option<String>> {
    if !is_json(headers) {
        return Err(AppError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "slack events must use application/json",
        ));
    }

    let value = serde_json::from_slice::<serde_json::Value>(body)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "slack event must be JSON"))?;
    if value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|kind| kind == "url_verification")
    {
        let challenge = value
            .get("challenge")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                AppError::new(
                    StatusCode::BAD_REQUEST,
                    "slack url_verification challenge is required",
                )
            })?;
        return Ok(Some(challenge.to_owned()));
    }

    Ok(None)
}

fn validate_cloudevent(headers: &HeaderMap, body: &Bytes) -> AppResult<()> {
    let content_type = content_type(headers);
    if content_type
        .as_deref()
        .is_some_and(|mime| mime.eq_ignore_ascii_case("application/cloudevents+json"))
    {
        let value = serde_json::from_slice::<serde_json::Value>(body).map_err(|_| {
            AppError::new(
                StatusCode::BAD_REQUEST,
                "structured CloudEvent must be JSON",
            )
        })?;
        validate_cloudevent_value(&value)
    } else if content_type
        .as_deref()
        .is_some_and(|mime| mime.eq_ignore_ascii_case("application/cloudevents-batch+json"))
    {
        let value = serde_json::from_slice::<serde_json::Value>(body).map_err(|_| {
            AppError::new(
                StatusCode::BAD_REQUEST,
                "CloudEvents batch must be a JSON array",
            )
        })?;
        let Some(events) = value.as_array() else {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                "CloudEvents batch must be a JSON array",
            ));
        };
        for event in events {
            validate_cloudevent_value(event)?;
        }
        Ok(())
    } else {
        for name in ["ce-specversion", "ce-id", "ce-source", "ce-type"] {
            if header_string(headers, name).is_none_or(|value| value.is_empty()) {
                return Err(AppError::new(
                    StatusCode::BAD_REQUEST,
                    format!("CloudEvents binary mode requires {name}"),
                ));
            }
        }
        Ok(())
    }
}

fn validate_cloudevent_value(value: &serde_json::Value) -> AppResult<()> {
    let Some(event) = value.as_object() else {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "CloudEvent must be a JSON object",
        ));
    };

    for name in ["specversion", "id", "source", "type"] {
        if event
            .get(name)
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                format!("CloudEvent requires {name}"),
            ));
        }
    }
    Ok(())
}

fn verify_discord_signature(public_key: &str, headers: &HeaderMap, body: &Bytes) -> AppResult<()> {
    let signature = header_string(headers, "x-signature-ed25519")
        .ok_or_else(|| AppError::new(StatusCode::UNAUTHORIZED, "discord signature is required"))?;
    let timestamp = header_string(headers, "x-signature-timestamp").ok_or_else(|| {
        AppError::new(
            StatusCode::UNAUTHORIZED,
            "discord signature timestamp is required",
        )
    })?;
    let mut signed = Vec::with_capacity(timestamp.len() + body.len());
    signed.extend_from_slice(timestamp.as_bytes());
    signed.extend_from_slice(body);

    verify_ed25519_signature(public_key, &signature, &signed)
}

fn verify_ed25519_signature(public_key: &str, signature: &str, message: &[u8]) -> AppResult<()> {
    let public_key = decode_hex_exact(
        public_key,
        32,
        StatusCode::BAD_REQUEST,
        "discord public key",
    )?;
    let public_key: [u8; 32] = public_key.try_into().map_err(|_| {
        AppError::new(
            StatusCode::BAD_REQUEST,
            "discord public key must be 32 bytes",
        )
    })?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "discord public key is invalid"))?;
    let signature = decode_hex_exact(signature, 64, StatusCode::UNAUTHORIZED, "discord signature")?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| AppError::new(StatusCode::UNAUTHORIZED, "discord signature is invalid"))?;

    verifying_key
        .verify(message, &signature)
        .map_err(|_| AppError::new(StatusCode::UNAUTHORIZED, "discord signature is invalid"))
}

fn discord_interaction_type(headers: &HeaderMap, body: &Bytes) -> AppResult<u8> {
    if !is_json(headers) {
        return Err(AppError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "discord interactions must use application/json",
        ));
    }

    let value = serde_json::from_slice::<serde_json::Value>(body)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "discord interaction must be JSON"))?;
    let kind = value
        .get("type")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            AppError::new(
                StatusCode::BAD_REQUEST,
                "discord interaction type is required",
            )
        })?;
    u8::try_from(kind).map_err(|_| {
        AppError::new(
            StatusCode::BAD_REQUEST,
            "discord interaction type is invalid",
        )
    })
}

fn validate_pingback(headers: &HeaderMap, body: &Bytes) -> AppResult<()> {
    if !is_xml(headers) {
        return Err(AppError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "pingback must use text/xml or application/xml",
        ));
    }

    let body = std::str::from_utf8(body)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "pingback must be UTF-8 XML"))?;
    if !body.contains("pingback.ping") {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "pingback.ping method is required",
        ));
    }

    let urls = xml_rpc_string_values(body)
        .into_iter()
        .filter(|value| Url::parse(value).is_ok_and(|url| matches!(url.scheme(), "http" | "https")))
        .count();
    if urls < 2 {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "pingback source and target URLs are required",
        ));
    }

    Ok(())
}

fn is_form_urlencoded(headers: &HeaderMap) -> bool {
    content_type_is(headers, &["application/x-www-form-urlencoded"])
}

fn is_json(headers: &HeaderMap) -> bool {
    content_type_is(headers, &["application/json"])
}

fn is_xml(headers: &HeaderMap) -> bool {
    content_type_is(headers, &["text/xml", "application/xml"])
}

fn content_type_is(headers: &HeaderMap, expected: &[&str]) -> bool {
    content_type(headers)
        .map(|mime| {
            expected
                .iter()
                .any(|expected| mime.eq_ignore_ascii_case(expected))
        })
        .unwrap_or(false)
}

fn content_type(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_owned)
}

fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .map(str::to_owned)
}

fn decode_hex_exact(
    value: &str,
    bytes: usize,
    status: StatusCode,
    label: &str,
) -> AppResult<Vec<u8>> {
    if value.len() != bytes * 2 {
        return Err(AppError::new(
            status,
            format!("{label} must be {bytes} bytes of hex"),
        ));
    }

    let mut out = Vec::with_capacity(bytes);
    for index in (0..value.len()).step_by(2) {
        let byte = u8::from_str_radix(&value[index..index + 2], 16)
            .map_err(|_| AppError::new(status, format!("{label} must be hex")))?;
        out.push(byte);
    }
    Ok(out)
}

fn parse_webmention_url(name: &str, value: &str) -> AppResult<Url> {
    parse_protocol_url(&format!("webmention {name}"), value)
}

fn parse_protocol_url(name: &str, value: &str) -> AppResult<Url> {
    let url = Url::parse(value).map_err(|_| {
        AppError::new(
            StatusCode::BAD_REQUEST,
            format!("{name} must be an absolute URL"),
        )
    })?;
    match url.scheme() {
        "http" | "https" => Ok(url),
        _ => Err(AppError::new(
            StatusCode::BAD_REQUEST,
            format!("{name} must use http or https"),
        )),
    }
}

fn xml_rpc_string_values(body: &str) -> Vec<&str> {
    let mut values = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find("<string>") {
        rest = &rest[start + "<string>".len()..];
        let Some(end) = rest.find("</string>") else {
            break;
        };
        values.push(&rest[..end]);
        rest = &rest[end + "</string>".len()..];
    }
    values
}

fn pingback_success_response() -> &'static str {
    r#"<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value><string>Pingback queued.</string></value>
    </param>
  </params>
</methodResponse>"#
}

fn inbox_item_budget() -> usize {
    MAX_INBOX_RESPONSE_BYTES - INBOX_RESPONSE_OVERHEAD_BYTES
}

fn inbox_item_cost(id: &str, sealed_len: usize) -> usize {
    id.len() + base64_url_len(sealed_len) + 64
}

fn base64_url_len(bytes: usize) -> usize {
    (bytes * 4).div_ceil(3)
}

fn inbox_limit(limit: Option<usize>, config: &Config) -> usize {
    limit
        .unwrap_or(config.default_get_limit)
        .clamp(1, config.max_get_limit)
}

fn callback_target(raw_query: &str) -> AppResult<Option<Url>> {
    let mut target = None;
    let mut before_target: Vec<(String, String)> = Vec::new();

    for (key, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        if key == "at" && target.is_none() {
            target = Some(parse_callback_target(&value)?);
            if let Some(url) = target.as_mut() {
                let mut query = url.query_pairs_mut();
                for (key, value) in before_target.drain(..) {
                    query.append_pair(&key, &value);
                }
            }
        } else if key == "at" {
            continue;
        } else if let Some(url) = target.as_mut() {
            url.query_pairs_mut().append_pair(&key, &value);
        } else {
            before_target.push((key.into_owned(), value.into_owned()));
        }
    }

    Ok(target)
}

fn append_query_params(target: &mut Url, raw_query: Option<&str>) {
    let Some(raw_query) = raw_query else {
        return;
    };

    for (key, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        target.query_pairs_mut().append_pair(&key, &value);
    }
}

fn parse_callback_target(target: &str) -> AppResult<Url> {
    let url = Url::parse(target)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "at must be an absolute URL"))?;
    match url.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                "at must use http or https",
            ));
        }
    }

    Ok(url)
}

async fn email_for_key(state: &AppState, key: &str) -> AppResult<String> {
    let token_hash = email_key_hash(key)?;
    let Some(row) = sqlx::query(
        r#"
        UPDATE email_login_keys
        SET last_used_at = now()
        WHERE token_hash = $1
          AND revoked_at IS NULL
          AND expires_at > now()
        RETURNING email
        "#,
    )
    .bind(token_hash)
    .fetch_optional(&state.db)
    .await
    .map_err(db_error)?
    else {
        return Err(AppError::new(
            StatusCode::UNAUTHORIZED,
            "email key is invalid",
        ));
    };

    Ok(row.get::<String, _>("email"))
}

async fn load_email_magic_links(
    state: &AppState,
    email: &str,
    current_key: &str,
) -> AppResult<Vec<EmailMagicLinkResponse>> {
    let current_hash = email_key_hash(current_key)?;
    let rows = sqlx::query(
        r#"
        SELECT id,
               extract(epoch from created_at)::bigint AS created_at_unix,
               extract(epoch from last_used_at)::bigint AS last_used_at_unix,
               extract(epoch from expires_at)::bigint AS expires_at_unix,
               token_hash = $2 AS current
        FROM email_login_keys
        WHERE email = $1
          AND revoked_at IS NULL
        ORDER BY created_at DESC
        "#,
    )
    .bind(email)
    .bind(current_hash)
    .fetch_all(&state.db)
    .await
    .map_err(db_error)?;

    Ok(rows.into_iter().map(email_magic_link_from_row).collect())
}

fn email_magic_link_from_row(row: sqlx::postgres::PgRow) -> EmailMagicLinkResponse {
    EmailMagicLinkResponse {
        id: row.get::<String, _>("id"),
        created_at_unix: row.get::<i64, _>("created_at_unix"),
        last_used_at_unix: row.get::<Option<i64>, _>("last_used_at_unix"),
        expires_at_unix: row.get::<i64, _>("expires_at_unix"),
        current: row.get::<bool, _>("current"),
    }
}

async fn load_email_aliases(state: &AppState, email: &str) -> AppResult<Vec<EmailAliasResponse>> {
    let rows = sqlx::query(
        r#"
        SELECT alias,
               extract(epoch from last_received_at)::bigint AS last_received_at_unix,
               extract(epoch from expires_at)::bigint AS expires_at_unix
        FROM email_aliases
        WHERE email = $1
        ORDER BY alias
        "#,
    )
    .bind(email)
    .fetch_all(&state.db)
    .await
    .map_err(db_error)?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let alias = row.get::<String, _>("alias");
            EmailAliasResponse {
                address: email_alias_address(&alias),
                alias,
                last_received_at_unix: row.get::<Option<i64>, _>("last_received_at_unix"),
                expires_at_unix: row.get::<Option<i64>, _>("expires_at_unix"),
            }
        })
        .collect())
}

fn email_key_hash(key: &str) -> AppResult<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(key)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "email key must be base64url"))?;
    if bytes.len() != EMAIL_KEY_BYTES {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "email key must be 32 bytes",
        ));
    }
    Ok(Sha256::digest(&bytes).to_vec())
}

fn normalize_email_alias(alias: &str) -> AppResult<String> {
    let mut alias = alias.trim().to_ascii_lowercase();
    if let Some(local) = alias.strip_suffix(&format!("@{EMAIL_ALIAS_DOMAIN}")) {
        alias = local.to_owned();
    }
    if alias.is_empty()
        || alias.len() < 4
        || alias.len() > 64
        || alias.starts_with('.')
        || alias.ends_with('.')
        || alias.contains("..")
        || !alias.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b'+')
        })
    {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "invalid alias"));
    }
    if is_reserved_email_alias(&alias) {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "alias is reserved"));
    }
    Ok(alias)
}

fn is_reserved_email_alias(alias: &str) -> bool {
    matches!(
        alias,
        "abuse"
            | "admin"
            | "administrator"
            | "hi"
            | "hostmaster"
            | "mailer-daemon"
            | "postmaster"
            | "root"
            | "security"
            | "webmaster"
            | "echo"
            | "todo"
    )
}

fn email_alias_address(alias: &str) -> String {
    format!("{alias}@{EMAIL_ALIAS_DOMAIN}")
}

fn decode_public_keys(encoded: &str) -> AppResult<Vec<(String, VerifyingKey)>> {
    let parts = encoded.split('.').collect::<Vec<_>>();
    if parts.is_empty() || parts.len() > MAX_INBOX_RECIPIENTS {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "invalid recipient count",
        ));
    }

    let mut seen = HashSet::with_capacity(parts.len());
    let mut out = Vec::with_capacity(parts.len());
    for part in parts {
        let public_key = decode_public_key(part)?;
        let key = public_key_key(&public_key);
        if seen.insert(key.clone()) {
            out.push((key, public_key));
        }
    }
    Ok(out)
}

fn decode_public_key(encoded: &str) -> AppResult<VerifyingKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "public key must be base64url"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "public key is invalid"))
}

fn derive_x25519_public_key(verifying_key: &VerifyingKey) -> AppResult<PublicKey> {
    let edwards_point = CompressedEdwardsY(verifying_key.to_bytes())
        .decompress()
        .ok_or_else(|| AppError::new(StatusCode::BAD_REQUEST, "public key is invalid"))?;
    PublicKey::from_slice(edwards_point.to_montgomery().as_bytes()).map_err(|_| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "encryption key derivation failed",
        )
    })
}

fn public_key_key(public_key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(public_key.as_bytes())
}

fn validate_batch_ids(ids: &[String]) -> AppResult<()> {
    if ids.len() > ACK_ID_LIMIT {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "too many ids in one request",
        ));
    }

    for id in ids {
        if id.is_empty()
            || id.len() > 80
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(AppError::new(StatusCode::BAD_REQUEST, "invalid message id"));
        }
    }
    Ok(())
}

fn random_alias_id() -> AppResult<String> {
    let mut bytes = [0u8; ALIAS_ID_BYTES];
    OsRng
        .unwrap_err()
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "randomness failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn random_secret_id() -> AppResult<String> {
    let mut bytes = [0u8; SECRET_ID_BYTES];
    OsRng
        .unwrap_err()
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "randomness failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_secret_ciphertext(config: &Config, ciphertext: &str) -> AppResult<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(ciphertext)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "ciphertext is not valid base64url"))?;
    if bytes.len() < SECRET_NONCE_BYTES + 16 {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "ciphertext is too short"));
    }
    if bytes.len() > config.secret_max_bytes {
        return Err(AppError::new(StatusCode::PAYLOAD_TOO_LARGE, "ciphertext is too large"));
    }
    Ok(bytes)
}

fn current_unix_seconds() -> AppResult<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(internal)?
        .as_secs())
}

fn current_unix_millis() -> AppResult<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(internal)?
        .as_millis())
}

fn hour_bucket(unix_seconds: u64) -> u64 {
    unix_seconds / 3600
}

fn day_bucket(unix_seconds: u64) -> u64 {
    unix_seconds / 86_400
}

fn recent_buckets(current: u64, count: u64) -> Vec<u64> {
    let first = current.saturating_sub(count.saturating_sub(1));
    (first..=current).collect()
}

fn next_event_id() -> String {
    format!(
        "{}{}",
        EVENT_PREFIX.as_str(),
        base36(EVENT_COUNTER.fetch_add(1, Ordering::Relaxed))
    )
}

fn next_message_id() -> String {
    format!("m_{}", next_event_id())
}

fn base36(mut value: u64) -> String {
    if value == 0 {
        return "0".to_owned();
    }

    let mut out = Vec::new();
    while value > 0 {
        let digit = (value % 36) as u8;
        out.push(match digit {
            0..=9 => b'0' + digit,
            _ => b'a' + digit - 10,
        });
        value /= 36;
    }
    out.reverse();
    String::from_utf8(out).expect("base36 only emits ASCII")
}

fn unique_bit(member: &str) -> i32 {
    (stable_hash(member.as_bytes()) as usize % STATS_BITS) as i32
}

fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn merge_unique_bits(target: &mut [u8], source: &[u8]) {
    for (target, source) in target.iter_mut().zip(source) {
        *target |= *source;
    }
}

fn estimate_unique_bits(bits: &[u8]) -> usize {
    let set = bits
        .iter()
        .map(|byte| byte.count_ones() as usize)
        .sum::<usize>();
    let zero = STATS_BITS.saturating_sub(set);
    if zero == 0 {
        return STATS_BITS;
    }

    let estimate = -(STATS_BITS as f64) * ((zero as f64) / (STATS_BITS as f64)).ln();
    estimate.round() as usize
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StatKind {
    Redirect,
    Inbox,
    Message,
    Alias,
    Forward,
    Secret,
    Favicon,
    Font,
}

impl StatKind {
    fn code(self) -> &'static str {
        match self {
            Self::Redirect => "r",
            Self::Inbox => "i",
            Self::Message => "m",
            Self::Alias => "a",
            Self::Forward => "f",
            Self::Secret => "s",
            Self::Favicon => "c",
            Self::Font => "o",
        }
    }
}

#[derive(Clone, Copy)]
enum StatPeriod {
    Hour,
    Day,
}

impl StatPeriod {
    fn code(self) -> &'static str {
        match self {
            Self::Hour => "h",
            Self::Day => "d",
        }
    }
}

fn parse_inbox_query(raw_query: Option<&str>) -> AppResult<InboxQuery> {
    let Some(raw_query) = raw_query else {
        return Ok(InboxQuery::default());
    };

    let mut query = InboxQuery::default();
    for (key, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match key.as_ref() {
            "l" => {
                query.l = Some(value.parse().map_err(|_| {
                    AppError::new(StatusCode::BAD_REQUEST, "l must be a positive integer")
                })?);
            }
            "p" => {
                query.p = true;
            }
            "c" => {
                query.c = Some(decode_cursor(&value)?);
            }
            _ => {}
        }
    }
    Ok(query)
}

fn encode_cursor(cursor: &Cursor) -> String {
    URL_SAFE_NO_PAD.encode(format!("{}:{}", cursor.created_at_us, cursor.id))
}

fn decode_cursor(encoded: &str) -> AppResult<Cursor> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "c must be a cursor"))?;
    let raw = std::str::from_utf8(&bytes)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "c must be a cursor"))?;
    let Some((created_at_us, id)) = raw.split_once(':') else {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "c must be a cursor"));
    };
    let created_at_us = created_at_us
        .parse::<i64>()
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "c must be a cursor"))?;
    if created_at_us < 0 {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "c must be a cursor"));
    }

    let cursor = Cursor {
        created_at_us,
        id: id.to_owned(),
    };
    validate_cursor(&cursor)?;
    Ok(cursor)
}

fn validate_cursor(cursor: &Cursor) -> AppResult<()> {
    if cursor.id.is_empty()
        || cursor.id.len() > 80
        || !cursor
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "c must be a cursor"));
    }
    Ok(())
}

// `go get`/`go install` fetch `https://cc.me/<path>?go-get=1` and look for a
// go-import meta tag. The Go tool hits this server (cc.me), not the static docs
// at www.cc.me, so we answer the handshake here for every path.
async fn serve_go_import(request: Request, next: Next) -> Response {
    if request.uri().query().is_some_and(query_wants_go_import) {
        return (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            GO_IMPORT_HTML,
        )
            .into_response();
    }
    next.run(request).await
}

fn query_wants_go_import(query: &str) -> bool {
    form_urlencoded::parse(query.as_bytes()).any(|(key, value)| key == "go-get" && value == "1")
}

fn redirect(location: &str) -> AppResult<Response> {
    let location = header::HeaderValue::from_str(location)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "invalid redirect target"))?;
    Ok((StatusCode::FOUND, [(header::LOCATION, location)]).into_response())
}

fn db_error(err: sqlx::Error) -> AppError {
    error!(%err, "database command failed");
    AppError::new(StatusCode::BAD_GATEWAY, "database command failed")
}

fn internal(err: impl std::fmt::Display) -> AppError {
    error!(%err, "internal error");
    AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

impl Config {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let max_requests = env_usize("INBOX_MAX_REQUESTS", 100).max(1);
        let max_get_limit = env_usize("INBOX_MAX_GET_LIMIT", 1000).max(1);
        let default_get_limit = env_usize("INBOX_DEFAULT_GET_LIMIT", 1).clamp(1, max_get_limit);
        let library_max_count = env_usize("LIBRARY_MAX_COUNT", 1000) as i64;
        let secret_max_ttl_hours = env_u64("SECRET_MAX_TTL_HOURS", SECRET_MAX_TTL_HOURS).max(1);
        let secret_default_ttl_hours = env_u64("SECRET_DEFAULT_TTL_HOURS", SECRET_DEFAULT_TTL_HOURS)
            .clamp(1, secret_max_ttl_hours);

        Ok(Self {
            bind_addr: env::var("BIND_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:3000".to_owned())
                .parse()?,
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://127.0.0.1:5432/postgres".to_owned()),
            max_requests,
            default_get_limit,
            max_get_limit,
            long_poll_seconds: env_f64("INBOX_LONG_POLL_SECONDS", 25.0).max(0.1),
            library_max_count,
            library_max_ttl_seconds: env_f64("LIBRARY_MAX_TTL_SECONDS", 86_400.0).max(1.0),
            library_max_wait_seconds: env_f64("LIBRARY_MAX_WAIT_SECONDS", 300.0).max(0.0),
            secret_default_ttl_hours,
            secret_max_ttl_hours,
            secret_max_bytes: env_usize("SECRET_MAX_BYTES", SECRET_MAX_BYTES).max(1024),
            secret_cleanup_interval_seconds: env_u64("SECRET_CLEANUP_INTERVAL_SECONDS", SECRET_CLEANUP_INTERVAL_SECONDS).max(1),
            fonts_dir: env::var_os("FONTS_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(FONTS_DEFAULT_DIR)),
            fonts_refresh_interval_seconds: env_u64(
                "FONTS_REFRESH_INTERVAL_SECONDS",
                FONTS_REFRESH_INTERVAL_SECONDS,
            ),
            shot_chrome_bin: env::var("SHOT_CHROME_BIN").unwrap_or_else(|_| "chromium".to_owned()),
            shot_chrome_args: env::var("SHOT_CHROME_ARGS")
                .map(|args| args.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_default(),
            // Default sized for GPUs: ~17M hashes is a few milliseconds on one
            // (see pow/README.md), seconds for browser workers.
            shot_pow_level: env_u64("SHOT_POW_LEVEL", 24).clamp(1, 64) as u32,
            shot_ts_window_seconds: env_u64("SHOT_TS_WINDOW_SECONDS", 300).max(1) as i64,
            shot_nav_timeout_seconds: env_f64("SHOT_NAV_TIMEOUT_SECONDS", 10.0).max(1.0),
            shot_cache_seconds: env_f64("SHOT_CACHE_SECONDS", 3600.0).max(1.0),
        })
    }
}

impl AppError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct ErrorBody<'a> {
            error: &'a str,
        }

        (
            self.status,
            Json(ErrorBody {
                error: &self.message,
            }),
        )
            .into_response()
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_f64(name: &str, default: f64) -> f64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

// ---- screenshots (/shot) ----------------------------------------------------
//
// `GET /shot?token=<pow token>` renders a page in a managed headless Chrome and
// returns a PNG. The proof-of-work document (see /pow) is a JSON spec binding
// the URL, viewport, downscale factor, and a fresh timestamp; results are
// cached in Postgres. Every render happens in its own ephemeral browser
// context (incognito equivalent), disposed afterwards.

async fn pow_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        POW_JS,
    )
}

// The published solving expectations: what the doc must contain is documented
// on /shot; how much work it must carry is served here so clients can adapt.
async fn shot_config(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "level": state.config.shot_pow_level,
        "ts_window_seconds": state.config.shot_ts_window_seconds,
        "max_dimension": SHOT_MAX_DIM,
        "cache_seconds": state.config.shot_cache_seconds,
    }))
}

fn pow_trailing_zero_bits(digest: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in digest.iter().rev() {
        if *byte == 0 {
            bits += 8;
        } else {
            bits += byte.trailing_zeros();
            break;
        }
    }
    bits
}

// Splits and checks a `b64u(doc).b64u(suffix)` token, returning the doc and
// the level it reaches. The base64 engine rejects padding and non-canonical
// trailing bits, matching the spec on /pow.
fn pow_token_doc_and_level(token: &str) -> AppResult<(Vec<u8>, u32)> {
    let Some((doc_b64, suffix_b64)) = token.split_once('.') else {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "token must be b64u(doc).b64u(suffix)",
        ));
    };
    let invalid = |_| AppError::new(StatusCode::BAD_REQUEST, "token segments must be canonical unpadded base64url");
    let doc = URL_SAFE_NO_PAD.decode(doc_b64).map_err(invalid)?;
    let suffix = URL_SAFE_NO_PAD.decode(suffix_b64).map_err(invalid)?;
    if suffix.len() > 32 {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "suffix longer than 32 bytes",
        ));
    }
    let inner = Sha256::digest(&doc);
    let mut outer = Sha256::new();
    outer.update(inner);
    outer.update(&suffix);
    let level = pow_trailing_zero_bits(&outer.finalize());
    Ok((doc, level))
}

fn shot_default_scale() -> f64 {
    1.0
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShotSpec {
    url: String,
    width: u32,
    height: u32,
    #[serde(default = "shot_default_scale")]
    scale: f64,
    ts: i64,
}

impl ShotSpec {
    fn validate(&self, config: &Config) -> AppResult<()> {
        if !(1..=SHOT_MAX_DIM).contains(&self.width) || !(1..=SHOT_MAX_DIM).contains(&self.height) {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                format!("width and height must be 1..={SHOT_MAX_DIM}"),
            ));
        }
        if !(self.scale > 0.0 && self.scale <= 1.0) {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                "scale must be in (0, 1]",
            ));
        }
        if self.width as f64 * self.scale < 1.0 || self.height as f64 * self.scale < 1.0 {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                "scaled size is below one pixel",
            ));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(internal)?
            .as_secs() as i64;
        if (now - self.ts).abs() > config.shot_ts_window_seconds {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                format!("ts must be within {} seconds of now", config.shot_ts_window_seconds),
            ));
        }
        Ok(())
    }

    // `ts` is deliberately absent: retries with a fresh timestamp share the
    // cache entry for an otherwise identical request.
    fn cache_key(&self) -> String {
        let digest = Sha256::digest(format!(
            "{}\n{}\n{}\n{}",
            self.url, self.width, self.height, self.scale
        ));
        URL_SAFE_NO_PAD.encode(digest)
    }
}

// Chrome resolves hostnames itself, so unlike the favicon fetcher we cannot
// filter addresses at connect time; refuse names with any non-public address
// up front instead.
async fn shot_check_url(url_text: &str) -> AppResult<()> {
    let parsed = Url::parse(url_text)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "url is invalid"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "url must be http or https",
        ));
    }
    let not_allowed = || AppError::new(StatusCode::BAD_REQUEST, "url host is not allowed");
    match parsed.host() {
        Some(url::Host::Ipv4(ip)) if ip_is_forbidden(&IpAddr::V4(ip)) => Err(not_allowed()),
        Some(url::Host::Ipv6(ip)) if ip_is_forbidden(&IpAddr::V6(ip)) => Err(not_allowed()),
        Some(url::Host::Domain(domain)) => {
            let host = domain.to_owned();
            let port = parsed.port_or_known_default().unwrap_or(443);
            let addrs = tokio::task::spawn_blocking(move || {
                (host.as_str(), port)
                    .to_socket_addrs()
                    .map(|addrs| addrs.collect::<Vec<_>>())
                    .unwrap_or_default()
            })
            .await
            .map_err(internal)?;
            if addrs.is_empty() {
                return Err(AppError::new(
                    StatusCode::BAD_GATEWAY,
                    "url host did not resolve",
                ));
            }
            if addrs.iter().any(|addr| ip_is_forbidden(&addr.ip())) {
                return Err(not_allowed());
            }
            Ok(())
        }
        Some(_) => Ok(()),
        None => Err(AppError::new(StatusCode::BAD_REQUEST, "url has no host")),
    }
}

// A handle to the managed Chrome's CDP connection. Cloning shares the
// connection; when the actor exits (Chrome died) the channel closes and the
// next request respawns the browser.
#[derive(Clone)]
struct CdpClient {
    tx: mpsc::Sender<CdpRequest>,
}

enum CdpRequest {
    Call {
        session_id: Option<String>,
        method: String,
        params: Value,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    WaitEvent {
        session_id: String,
        method: String,
        reply: oneshot::Sender<()>,
    },
}

impl CdpClient {
    async fn call(&self, session_id: Option<&str>, method: &str, params: Value) -> Result<Value, String> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(CdpRequest::Call {
                session_id: session_id.map(str::to_owned),
                method: method.to_owned(),
                params,
                reply,
            })
            .await
            .map_err(|_| "chrome connection closed".to_owned())?;
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("chrome connection closed".to_owned()),
            Err(_) => Err(format!("{method} timed out")),
        }
    }

    // Registers interest in a session event; register before triggering it.
    async fn wait_event(&self, session_id: &str, method: &str) -> Result<oneshot::Receiver<()>, String> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(CdpRequest::WaitEvent {
                session_id: session_id.to_owned(),
                method: method.to_owned(),
                reply,
            })
            .await
            .map_err(|_| "chrome connection closed".to_owned())?;
        Ok(rx)
    }
}

// Owns the websocket: multiplexes calls by id, fans events out to waiters.
async fn cdp_actor(
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    mut rx: mpsc::Receiver<CdpRequest>,
    mut child: tokio::process::Child,
    user_data_dir: PathBuf,
) {
    let (mut sink, mut stream) = ws.split();
    let mut next_id: u64 = 1;
    let mut pending: HashMap<u64, oneshot::Sender<Result<Value, String>>> = HashMap::new();
    let mut waiters: Vec<(String, String, oneshot::Sender<()>)> = Vec::new();
    loop {
        tokio::select! {
            request = rx.recv() => match request {
                None => break,
                Some(CdpRequest::Call { session_id, method, params, reply }) => {
                    let id = next_id;
                    next_id += 1;
                    let mut message = json!({ "id": id, "method": method, "params": params });
                    if let Some(session_id) = session_id {
                        message["sessionId"] = session_id.into();
                    }
                    if sink.send(Message::Text(message.to_string().into())).await.is_err() {
                        let _ = reply.send(Err("chrome connection closed".to_owned()));
                        break;
                    }
                    pending.insert(id, reply);
                }
                Some(CdpRequest::WaitEvent { session_id, method, reply }) => {
                    waiters.push((session_id, method, reply));
                }
            },
            message = stream.next() => match message {
                Some(Ok(Message::Text(text))) => {
                    let Ok(value) = serde_json::from_str::<Value>(text.as_str()) else {
                        continue;
                    };
                    if let Some(id) = value.get("id").and_then(Value::as_u64) {
                        if let Some(reply) = pending.remove(&id) {
                            let result = match value.get("error") {
                                Some(error) => Err(error
                                    .get("message")
                                    .and_then(Value::as_str)
                                    .unwrap_or("CDP error")
                                    .to_owned()),
                                None => Ok(value.get("result").cloned().unwrap_or(Value::Null)),
                            };
                            let _ = reply.send(result);
                        }
                    } else if let (Some(method), Some(session_id)) = (
                        value.get("method").and_then(Value::as_str),
                        value.get("sessionId").and_then(Value::as_str),
                    ) {
                        let mut i = 0;
                        while i < waiters.len() {
                            if waiters[i].0 == session_id && waiters[i].1 == method {
                                let (_, _, reply) = waiters.swap_remove(i);
                                let _ = reply.send(());
                            } else {
                                i += 1;
                            }
                        }
                    }
                }
                Some(Ok(_)) => {}
                _ => break,
            },
        }
    }
    let _ = child.kill().await;
    let _ = tokio::fs::remove_dir_all(&user_data_dir).await;
    info!("chrome for screenshots exited");
}

async fn spawn_chrome(config: &Config) -> Result<CdpClient, String> {
    let user_data_dir = env::temp_dir().join(format!("cc-me-shot-{}", Uuid::new_v4()));
    tokio::fs::create_dir_all(&user_data_dir)
        .await
        .map_err(|err| format!("create profile dir: {err}"))?;
    let mut command = tokio::process::Command::new(&config.shot_chrome_bin);
    command
        .arg("--headless=new")
        .arg("--remote-debugging-port=0")
        .arg(format!("--user-data-dir={}", user_data_dir.display()))
        .args([
            "--no-first-run",
            "--no-default-browser-check",
            "--hide-scrollbars",
            "--mute-audio",
            "--disable-background-networking",
            "--disable-extensions",
            "--disable-sync",
            "--disable-dev-shm-usage",
            "--force-color-profile=srgb",
            // Crashpad insists on a writable database under $HOME; under a
            // hardened unit (ReadOnlyDirectories=/) that kills Chrome before
            // it publishes DevToolsActivePort.
            "--disable-crash-reporter",
            "--disable-breakpad",
        ])
        // Chrome scribbles dotfiles wherever $HOME points; give it the
        // profile dir we already clean up.
        .env("HOME", &user_data_dir)
        .args(&config.shot_chrome_args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let child = command
        .spawn()
        .map_err(|err| format!("spawn {}: {err}", config.shot_chrome_bin))?;
    // Chrome publishes its ephemeral CDP endpoint in the profile directory.
    let port_file = user_data_dir.join("DevToolsActivePort");
    let mut ws_url = None;
    for _ in 0..SHOT_CHROME_START_TIMEOUT_SECONDS * 10 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Ok(contents) = tokio::fs::read_to_string(&port_file).await {
            let mut lines = contents.lines();
            if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                ws_url = Some(format!("ws://127.0.0.1:{port}{path}"));
                break;
            }
        }
    }
    let Some(ws_url) = ws_url else {
        return Err("chrome did not publish DevToolsActivePort".to_owned());
    };
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(|err| format!("connect to chrome: {err}"))?;
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(cdp_actor(ws, rx, child, user_data_dir));
    info!("chrome ready for screenshots");
    Ok(CdpClient { tx })
}

async fn chrome_client(state: &AppState) -> AppResult<CdpClient> {
    let mut guard = state.chrome.lock().await;
    if let Some(client) = guard.as_ref() {
        if !client.tx.is_closed() {
            return Ok(client.clone());
        }
    }
    let client = spawn_chrome(&state.config).await.map_err(|err| {
        error!(%err, "chrome spawn failed");
        AppError::new(StatusCode::SERVICE_UNAVAILABLE, "screenshot backend unavailable")
    })?;
    *guard = Some(client.clone());
    Ok(client)
}

fn shot_backend_error(err: String) -> AppError {
    error!(%err, "screenshot backend error");
    AppError::new(StatusCode::SERVICE_UNAVAILABLE, "screenshot backend unavailable")
}

// Disposes the render's browser context — closing its tab and dropping all its
// state — on every exit path: normal completion, errors, and cancellation
// (timeouts and disconnecting clients drop the render future mid-flight, so an
// inline call after the render would not run).
struct ShotContextGuard {
    client: CdpClient,
    context_id: String,
}

impl Drop for ShotContextGuard {
    fn drop(&mut self) {
        let client = self.client.clone();
        let context_id = std::mem::take(&mut self.context_id);
        tokio::spawn(async move {
            let _ = client
                .call(
                    None,
                    "Target.disposeBrowserContext",
                    json!({ "browserContextId": context_id }),
                )
                .await;
        });
    }
}

async fn shot_render(client: &CdpClient, spec: &ShotSpec, nav_timeout: Duration) -> AppResult<Vec<u8>> {
    let context = client
        .call(None, "Target.createBrowserContext", json!({}))
        .await
        .map_err(shot_backend_error)?;
    let Some(context_id) = context.get("browserContextId").and_then(Value::as_str) else {
        return Err(shot_backend_error("no browserContextId".to_owned()));
    };
    let _guard = ShotContextGuard {
        client: client.clone(),
        context_id: context_id.to_owned(),
    };
    shot_render_in_context(client, context_id, spec, nav_timeout).await
}

async fn shot_render_in_context(
    client: &CdpClient,
    context_id: &str,
    spec: &ShotSpec,
    nav_timeout: Duration,
) -> AppResult<Vec<u8>> {
    let target = client
        .call(
            None,
            "Target.createTarget",
            json!({ "url": "about:blank", "browserContextId": context_id }),
        )
        .await
        .map_err(shot_backend_error)?;
    let Some(target_id) = target.get("targetId").and_then(Value::as_str) else {
        return Err(shot_backend_error("no targetId".to_owned()));
    };
    let attached = client
        .call(
            None,
            "Target.attachToTarget",
            json!({ "targetId": target_id, "flatten": true }),
        )
        .await
        .map_err(shot_backend_error)?;
    let Some(session) = attached.get("sessionId").and_then(Value::as_str) else {
        return Err(shot_backend_error("no sessionId".to_owned()));
    };
    client
        .call(Some(session), "Page.enable", json!({}))
        .await
        .map_err(shot_backend_error)?;
    // deviceScaleFactor is where the downscaling happens: the PNG comes out at
    // width×scale by height×scale device pixels.
    client
        .call(
            Some(session),
            "Emulation.setDeviceMetricsOverride",
            json!({
                "width": spec.width,
                "height": spec.height,
                "deviceScaleFactor": spec.scale,
                "mobile": false,
            }),
        )
        .await
        .map_err(shot_backend_error)?;
    let loaded = client
        .wait_event(session, "Page.loadEventFired")
        .await
        .map_err(shot_backend_error)?;
    let navigation = client
        .call(Some(session), "Page.navigate", json!({ "url": spec.url }))
        .await
        .map_err(shot_backend_error)?;
    if let Some(error_text) = navigation.get("errorText").and_then(Value::as_str) {
        if !error_text.is_empty() {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                format!("navigation failed: {error_text}"),
            ));
        }
    }
    match tokio::time::timeout(nav_timeout, loaded).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Err(shot_backend_error("chrome connection closed".to_owned())),
        Err(_) => {
            return Err(AppError::new(
                StatusCode::GATEWAY_TIMEOUT,
                "page did not finish loading in time",
            ));
        }
    }
    tokio::time::sleep(Duration::from_millis(SHOT_SETTLE_MS)).await;
    let screenshot = client
        .call(Some(session), "Page.captureScreenshot", json!({ "format": "png" }))
        .await
        .map_err(shot_backend_error)?;
    let Some(data) = screenshot.get("data").and_then(Value::as_str) else {
        return Err(shot_backend_error("no screenshot data".to_owned()));
    };
    general_purpose::STANDARD
        .decode(data)
        .map_err(|_| shot_backend_error("undecodable screenshot data".to_owned()))
}

async fn shot_cache_lookup(state: &AppState, key: &str) -> AppResult<Option<Vec<u8>>> {
    let row = sqlx::query(
        "SELECT bytes FROM shot_cache WHERE key = $1 AND created_at > now() - make_interval(secs => $2)",
    )
    .bind(key)
    .bind(state.config.shot_cache_seconds)
    .fetch_optional(&state.db)
    .await
    .map_err(internal)?;
    Ok(row.map(|row| row.get("bytes")))
}

async fn shot_cache_store(state: &AppState, key: &str, bytes: &[u8]) -> AppResult<()> {
    if bytes.len() > SHOT_CACHE_MAX_BYTES {
        return Ok(());
    }
    sqlx::query(
        r#"
        INSERT INTO shot_cache (key, bytes) VALUES ($1, $2)
        ON CONFLICT (key) DO UPDATE SET bytes = EXCLUDED.bytes, created_at = now()
        "#,
    )
    .bind(key)
    .bind(bytes)
    .execute(&state.db)
    .await
    .map_err(internal)?;
    // Opportunistic cleanup; renders are PoW-limited so this stays cheap.
    let _ = sqlx::query("DELETE FROM shot_cache WHERE created_at < now() - make_interval(secs => $1)")
        .bind(state.config.shot_cache_seconds * 2.0)
        .execute(&state.db)
        .await;
    Ok(())
}

fn shot_png_response(bytes: Vec<u8>, cache_hit: bool) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
            (
                header::HeaderName::from_static("x-cache"),
                if cache_hit { "hit" } else { "miss" },
            ),
        ],
        bytes,
    )
        .into_response()
}

async fn shot(State(state): State<AppState>, RawQuery(raw_query): RawQuery) -> AppResult<Response> {
    let token = raw_query.as_deref().and_then(|query| {
        form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == "token")
            .map(|(_, value)| value.into_owned())
    });
    let Some(token) = token else {
        return Ok(docs_html(DOCS_SHOT_HTML));
    };

    let (doc, level) = pow_token_doc_and_level(&token)?;
    if level < state.config.shot_pow_level {
        return Err(AppError::new(
            StatusCode::FORBIDDEN,
            format!(
                "proof of work reaches level {level}, {} required",
                state.config.shot_pow_level
            ),
        ));
    }
    let spec: ShotSpec = serde_json::from_slice(&doc).map_err(|err| {
        AppError::new(StatusCode::BAD_REQUEST, format!("doc is not a valid spec: {err}"))
    })?;
    spec.validate(&state.config)?;
    shot_check_url(&spec.url).await?;

    let key = spec.cache_key();
    if let Some(bytes) = shot_cache_lookup(&state, &key).await? {
        return Ok(shot_png_response(bytes, true));
    }

    let _permit = state
        .shot_permits
        .clone()
        .acquire_owned()
        .await
        .map_err(internal)?;
    // A queued identical request may have been rendered while we waited.
    if let Some(bytes) = shot_cache_lookup(&state, &key).await? {
        return Ok(shot_png_response(bytes, true));
    }

    let client = chrome_client(&state).await?;
    let nav_timeout = Duration::from_secs_f64(state.config.shot_nav_timeout_seconds);
    let png = match tokio::time::timeout(
        nav_timeout + Duration::from_secs(20),
        shot_render(&client, &spec, nav_timeout),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            return Err(AppError::new(
                StatusCode::GATEWAY_TIMEOUT,
                "render timed out",
            ));
        }
    };
    shot_cache_store(&state, &key, &png).await?;
    Ok(shot_png_response(png, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use ed25519_dalek::Signer;
    use http_body_util::BodyExt;
    use sha2::Sha512;
    use tower::ServiceExt;

    #[test]
    fn go_import_query_matches_go_get_one() {
        assert!(query_wants_go_import("go-get=1"));
        assert!(query_wants_go_import("foo=bar&go-get=1"));
        assert!(!query_wants_go_import("go-get=0"));
        assert!(!query_wants_go_import("go-get"));
        assert!(!query_wants_go_import("at=https%3A%2F%2Fexample.com"));
        assert!(!query_wants_go_import(""));
    }

    #[test]
    fn email_alias_normalization_accepts_cc_me_local_parts() {
        assert_eq!(normalize_email_alias("Example").unwrap(), "example");
        assert_eq!(
            normalize_email_alias("Example+tag@CC.ME").unwrap(),
            "example+tag"
        );
        assert_eq!(email_alias_address("example"), "example@cc.me");
    }

    #[test]
    fn email_alias_normalization_rejects_invalid_names() {
        for alias in [
            "abc",
            ".abcd",
            "abcd.",
            "ab..cd",
            "ab cd",
            "ab/cd",
            "hi",
            "postmaster",
        ] {
            assert!(normalize_email_alias(alias).is_err(), "{alias}");
        }
    }

    fn go_import_router() -> Router {
        Router::new()
            .route("/", get(|| async { "root" }))
            .layer(middleware::from_fn(serve_go_import))
    }

    async fn body_text(response: Response) -> (StatusCode, String) {
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn serves_go_import_meta_for_module_root() {
        let response = go_import_router()
            .oneshot(
                Request::builder()
                    .uri("/?go-get=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, body) = body_text(response).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(
            r#"<meta name="go-import" content="cc.me git https://github.com/xmit-co/cc.me">"#
        ));
    }

    #[tokio::test]
    async fn serves_go_import_meta_for_unrouted_subpackage() {
        // `go get cc.me/ccme` fetches /ccme?go-get=1, which has no route.
        let response = go_import_router()
            .oneshot(
                Request::builder()
                    .uri("/ccme?go-get=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, body) = body_text(response).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(r#"content="cc.me git"#));
    }

    #[tokio::test]
    async fn passes_through_without_go_get() {
        let response = go_import_router()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (status, body) = body_text(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "root");
    }

    #[test]
    fn trampoline_appends_oauth_params_to_target() {
        let url = callback_target(
            "at=http%3A%2F%2Fexample.local%2Fauth%2Fcallback%3Ffrom%3Dtarget&code=abc&state=s",
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            url.as_str(),
            "http://example.local/auth/callback?from=target&code=abc&state=s"
        );
    }

    #[test]
    fn trampoline_keeps_params_before_target() {
        let url =
            callback_target("code=abc&state=s&at=http%3A%2F%2Fexample.local%2Fauth%2Fcallback")
                .unwrap()
                .unwrap();

        assert_eq!(
            url.as_str(),
            "http://example.local/auth/callback?code=abc&state=s"
        );
    }

    #[test]
    fn trampoline_rejects_non_http_targets() {
        let err = callback_target("at=file%3A%2F%2F%2Ftmp%2Fx").unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn inbox_query_accepts_bare_p() {
        let query = parse_inbox_query(Some("p&l=10")).unwrap();

        assert!(query.p);
        assert_eq!(query.l, Some(10));
    }

    #[test]
    fn inbox_query_defaults_without_p() {
        let query = parse_inbox_query(Some("l=10")).unwrap();

        assert!(!query.p);
        assert_eq!(query.l, Some(10));
    }

    #[test]
    fn inbox_query_accepts_cursor() {
        let cursor = Cursor {
            created_at_us: 123,
            id: "m_test".to_owned(),
        };
        let query = parse_inbox_query(Some(&format!("c={}", encode_cursor(&cursor)))).unwrap();
        let parsed = query.c.unwrap();

        assert_eq!(parsed.created_at_us, cursor.created_at_us);
        assert_eq!(parsed.id, cursor.id);
    }

    #[test]
    fn inbox_query_rejects_bad_cursor() {
        let err = parse_inbox_query(Some("c=bad")).unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn webmention_requires_source_and_target() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );

        assert!(
            validate_webmention(
                &headers,
                &Bytes::from_static(
                    b"source=https%3A%2F%2Fexample.com%2Fpost&target=https%3A%2F%2Fexample.net%2Fpage"
                ),
            )
            .is_ok()
        );

        let err = validate_webmention(&headers, &Bytes::from_static(b"source=https://example.com"))
            .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn websub_challenge_echoes_challenge() {
        let challenge = websub_challenge(Some(
            "hub.mode=subscribe&hub.topic=https%3A%2F%2Fexample.com%2Ffeed&hub.challenge=abc",
        ))
        .unwrap();

        assert_eq!(challenge, "abc");
    }

    #[test]
    fn meta_challenge_checks_optional_verify_token() {
        let challenge = meta_challenge(Some(
            "v=secret&hub.mode=subscribe&hub.verify_token=secret&hub.challenge=abc",
        ))
        .unwrap();

        assert_eq!(challenge, "abc");

        let err = meta_challenge(Some(
            "v=secret&hub.mode=subscribe&hub.verify_token=wrong&hub.challenge=abc",
        ))
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn slack_challenge_detects_url_verification() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        let challenge = slack_challenge(
            &headers,
            &Bytes::from_static(br#"{"type":"url_verification","challenge":"abc"}"#),
        )
        .unwrap();

        assert_eq!(challenge, Some("abc".to_owned()));
    }

    #[test]
    fn cloudevent_accepts_binary_structured_and_batch_modes() {
        let mut binary_headers = HeaderMap::new();
        binary_headers.insert("ce-specversion", "1.0".parse().unwrap());
        binary_headers.insert("ce-id", "evt_1".parse().unwrap());
        binary_headers.insert("ce-source", "https://example.com/source".parse().unwrap());
        binary_headers.insert("ce-type", "com.example.test".parse().unwrap());
        binary_headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(validate_cloudevent(&binary_headers, &Bytes::from_static(b"{}")).is_ok());

        let mut structured_headers = HeaderMap::new();
        structured_headers.insert(
            header::CONTENT_TYPE,
            "application/cloudevents+json; charset=utf-8"
                .parse()
                .unwrap(),
        );
        assert!(
            validate_cloudevent(
                &structured_headers,
                &Bytes::from_static(
                    br#"{"specversion":"1.0","id":"evt_1","source":"/tests","type":"com.example.test","data":{}}"#
                ),
            )
            .is_ok()
        );

        let mut batch_headers = HeaderMap::new();
        batch_headers.insert(
            header::CONTENT_TYPE,
            "application/cloudevents-batch+json".parse().unwrap(),
        );
        assert!(
            validate_cloudevent(
                &batch_headers,
                &Bytes::from_static(
                    br#"[{"specversion":"1.0","id":"evt_1","source":"/tests","type":"com.example.test"}]"#
                ),
            )
            .is_ok()
        );
    }

    #[test]
    fn cloudevent_requires_binary_mode_metadata() {
        let err = validate_cloudevent(&HeaderMap::new(), &Bytes::new()).unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn discord_verifies_ed25519_signatures() {
        let public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let signature = concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );

        assert!(verify_ed25519_signature(public_key, signature, b"").is_ok());

        let err = verify_ed25519_signature(public_key, signature, b"bad").unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn discord_interaction_type_requires_json_type() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());

        assert_eq!(
            discord_interaction_type(&headers, &Bytes::from_static(br#"{"type":1}"#)).unwrap(),
            1
        );

        let err = discord_interaction_type(&headers, &Bytes::from_static(br#"{}"#)).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn pingback_requires_pingback_ping() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "text/xml".parse().unwrap());

        assert!(
            validate_pingback(
                &headers,
                &Bytes::from_static(
                    br#"<methodCall><methodName>pingback.ping</methodName><params><param><value><string>https://example.com/post</string></value></param><param><value><string>https://example.net/page</string></value></param></params></methodCall>"#
                ),
            )
            .is_ok()
        );

        let err = validate_pingback(
            &headers,
            &Bytes::from_static(
                br#"<methodCall><methodName>system.listMethods</methodName></methodCall>"#,
            ),
        )
        .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn capture_request_rejects_bodies_over_64_kib() {
        let err = capture_request(
            "m_test".to_owned(),
            Method::POST,
            Uri::from_static("/i/6JgMhuAy8espdQUujWW93RXDtZZBF07JZ4pTeJ2Sx1Q"),
            HeaderMap::new(),
            Bytes::from(vec![0; MAX_CAPTURE_BYTES + 1]),
        )
        .unwrap_err();

        assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn encode_captured_request_rejects_headers_over_64_kib() {
        let mut headers = HeaderMap::new();
        headers.insert("x-large", "a".repeat(MAX_CAPTURE_BYTES).parse().unwrap());

        let payload = capture_request(
            "m_test".to_owned(),
            Method::POST,
            Uri::from_static("/i/6JgMhuAy8espdQUujWW93RXDtZZBF07JZ4pTeJ2Sx1Q"),
            headers,
            Bytes::new(),
        )
        .unwrap();
        let err = encode_captured_request(&payload).unwrap_err();

        assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn inbox_budget_reserves_space_for_response_json() {
        assert_eq!(
            inbox_item_budget() + INBOX_RESPONSE_OVERHEAD_BYTES,
            MAX_INBOX_RESPONSE_BYTES
        );
        assert_eq!(base64_url_len(0), 0);
        assert_eq!(base64_url_len(1), 2);
        assert_eq!(base64_url_len(2), 3);
        assert_eq!(base64_url_len(3), 4);
        assert_eq!(inbox_item_cost("abc", 6), 75);
    }

    #[test]
    fn decode_public_keys_accepts_unique_fanout() {
        let public_key = test_public_key();
        let encoded = URL_SAFE_NO_PAD.encode(public_key.as_bytes());
        let keys = decode_public_keys(&format!("{encoded}.{encoded}")).unwrap();

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, encoded);
    }

    #[test]
    fn ed25519_public_key_derives_x25519_for_encryption() {
        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();
        let x25519_public_key = derive_x25519_public_key(&verifying_key).unwrap();

        let plaintext = b"hello world";
        let ciphertext = x25519_public_key
            .seal(&mut OsRng.unwrap_err(), plaintext)
            .unwrap();

        let x25519_secret_key = derive_x25519_secret_key(&signing_key);
        let decrypted = x25519_secret_key.unseal(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn verify_inbox_request_accepts_valid_signature() {
        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();
        let uri = Uri::from_static("/i/key/claim");
        let body = Bytes::from_static(br#"{"limit":1}"#);
        let timestamp = current_unix_seconds().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTH_TIMESTAMP_HEADER,
            timestamp.to_string().parse().unwrap(),
        );
        headers.insert(
            AUTH_SIGNATURE_HEADER,
            sign_inbox_request(&signing_key, &Method::POST, &uri, timestamp, &body)
                .parse()
                .unwrap(),
        );

        assert!(verify_inbox_request(&verifying_key, &Method::POST, &uri, &headers, &body).is_ok());
    }

    #[test]
    fn verify_inbox_request_rejects_missing_signature() {
        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();
        let uri = Uri::from_static("/i/key/claim");
        let body = Bytes::new();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTH_TIMESTAMP_HEADER,
            current_unix_seconds().unwrap().to_string().parse().unwrap(),
        );

        let err =
            verify_inbox_request(&verifying_key, &Method::POST, &uri, &headers, &body).unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn verify_inbox_request_rejects_stale_timestamp() {
        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();
        let uri = Uri::from_static("/i/key/claim");
        let body = Bytes::new();
        let timestamp = current_unix_seconds().unwrap() - AUTH_WINDOW_SECONDS - 1;
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTH_TIMESTAMP_HEADER,
            timestamp.to_string().parse().unwrap(),
        );
        headers.insert(
            AUTH_SIGNATURE_HEADER,
            sign_inbox_request(&signing_key, &Method::POST, &uri, timestamp, &body)
                .parse()
                .unwrap(),
        );

        let err =
            verify_inbox_request(&verifying_key, &Method::POST, &uri, &headers, &body).unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn test_public_key() -> VerifyingKey {
        test_signing_key().verifying_key()
    }

    fn sign_inbox_request(
        signing_key: &SigningKey,
        method: &Method,
        uri: &Uri,
        timestamp: u64,
        body: &Bytes,
    ) -> String {
        let body_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(body));
        let path = uri
            .path_and_query()
            .map(|path_and_query| path_and_query.as_str())
            .unwrap_or_else(|| uri.path());
        let canonical = format!(
            "{}\n{}\n{}\n{}\n{}",
            AUTH_VERSION,
            method.as_str(),
            path,
            timestamp,
            body_hash
        );
        URL_SAFE_NO_PAD.encode(signing_key.sign(canonical.as_bytes()).to_bytes())
    }

    fn derive_x25519_secret_key(signing_key: &SigningKey) -> crypto_box::SecretKey {
        let hash = Sha512::digest(signing_key.to_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash[..32]);
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;
        crypto_box::SecretKey::from(bytes)
    }

    #[test]
    fn validate_batch_ids_caps_batches() {
        let ids = (0..=ACK_ID_LIMIT)
            .map(|index| format!("m_{index}"))
            .collect::<Vec<_>>();
        let err = validate_batch_ids(&ids).unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn base36_encodes_hours_compactly() {
        assert_eq!(base36(0), "0");
        assert_eq!(base36(35), "z");
        assert_eq!(base36(36), "10");
    }

    #[test]
    fn unique_stats_sketch_estimates_small_counts() {
        let mut bits = vec![0u8; STATS_BYTES];
        for member in ["a", "b", "c"] {
            let bit = unique_bit(member) as usize;
            bits[bit / 8] |= 1 << (bit % 8);
        }

        assert_eq!(estimate_unique_bits(&bits), 3);
    }

    #[test]
    fn secret_ciphertext_accepts_valid_nonce_and_box() {
        let config = test_secret_config();
        let mut bytes = vec![0u8; SECRET_NONCE_BYTES + 16];
        bytes[SECRET_NONCE_BYTES] = 1;
        let encoded = URL_SAFE_NO_PAD.encode(&bytes);
        assert!(decode_secret_ciphertext(&config, &encoded).is_ok());
    }

    #[test]
    fn secret_ciphertext_rejects_invalid_base64() {
        let config = test_secret_config();
        let err = decode_secret_ciphertext(&config, "not-valid-base64!!!").unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn secret_ciphertext_rejects_too_short() {
        let config = test_secret_config();
        let encoded = URL_SAFE_NO_PAD.encode(vec![0u8; SECRET_NONCE_BYTES]);
        let err = decode_secret_ciphertext(&config, &encoded).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn secret_ciphertext_rejects_too_large() {
        let config = test_secret_config();
        let mut bytes = vec![0u8; config.secret_max_bytes + 1];
        bytes[SECRET_NONCE_BYTES] = 1;
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        let err = decode_secret_ciphertext(&config, &encoded).unwrap_err();
        assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    fn test_secret_config() -> Config {
        Config {
            bind_addr: "127.0.0.1:3000".parse().unwrap(),
            database_url: String::new(),
            max_requests: 100,
            default_get_limit: 1,
            max_get_limit: 1000,
            long_poll_seconds: 25.0,
            library_max_count: 100,
            library_max_ttl_seconds: 60.0,
            library_max_wait_seconds: 5.0,
            secret_default_ttl_hours: 24,
            secret_max_ttl_hours: 168,
            secret_max_bytes: 262144,
            secret_cleanup_interval_seconds: 60,
            fonts_dir: PathBuf::from("/var/lib/fonts"),
            fonts_refresh_interval_seconds: 0,
            shot_chrome_bin: "chromium".to_owned(),
            shot_chrome_args: Vec::new(),
            shot_pow_level: 24,
            shot_ts_window_seconds: 300,
            shot_nav_timeout_seconds: 10.0,
            shot_cache_seconds: 3600.0,
        }
    }

    // ------------------------------------------------------------------
    // Library tests
    // ------------------------------------------------------------------

    async fn library_test_app() -> Option<(Router, PgPool)> {
        // Skip only when no DB is configured. If DATABASE_URL is set but the database
        // is unreachable or migration fails, panic loudly — a silent skip here would
        // report green while testing nothing.
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let db = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&database_url)
            .await
            .expect("connect to DATABASE_URL");
        migrate(&db).await.expect("run migrations");

        let (inbox_tx, _) = broadcast::channel(16);
        let (library_tx, _) = broadcast::channel(16);
        let (stats_tx, _) = mpsc::channel(16);
        let config = Config {
            bind_addr: "127.0.0.1:3000".parse().unwrap(),
            database_url,
            max_requests: 100,
            default_get_limit: 1,
            max_get_limit: 1000,
            long_poll_seconds: 25.0,
            library_max_count: 100,
            library_max_ttl_seconds: 60.0,
            library_max_wait_seconds: 5.0,
            secret_default_ttl_hours: 24,
            secret_max_ttl_hours: 168,
            secret_max_bytes: 262144,
            secret_cleanup_interval_seconds: 60,
            fonts_dir: PathBuf::from("/var/lib/fonts"),
            fonts_refresh_interval_seconds: 0,
            shot_chrome_bin: "chromium".to_owned(),
            shot_chrome_args: Vec::new(),
            shot_pow_level: 24,
            shot_ts_window_seconds: 300,
            shot_nav_timeout_seconds: 10.0,
            shot_cache_seconds: 3600.0,
        };

        let router = Router::new()
            .route(
                "/l/{id}",
                put(put_resource).get(get_resource).delete(delete_resource),
            )
            .route("/l/{id}/borrow", post(borrow_resource))
            .route("/l/{id}/return", post(return_lease))
            .with_state(AppState {
                db: db.clone(),
                inbox_tx,
                library_tx,
                stats_tx,
                http: build_http_client(),
                fonts: Arc::new(RwLock::new(Arc::new(FontIndex::empty()))),
                chrome: Arc::new(tokio::sync::Mutex::new(None)),
                shot_permits: Arc::new(tokio::sync::Semaphore::new(SHOT_MAX_CONCURRENT)),
                config,
            });

        Some((router, db))
    }

    async fn json_body<T: serde::de::DeserializeOwned>(response: Response) -> (StatusCode, T) {
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn json_status(response: Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    fn library_request(method: &str, uri: &str, body: Option<String>) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if body.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        builder.body(Body::from(body.unwrap_or_default())).unwrap()
    }

    #[tokio::test]
    async fn library_put_creates_and_updates_pool() {
        let Some((router, db)) = library_test_app().await else {
            return;
        };
        let id = Uuid::new_v4();

        let (status, body): (StatusCode, ResourceResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "PUT",
                    &format!("/l/{id}"),
                    Some(r#"{"count":4}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.count, 4);
        assert_eq!(body.in_use, 0);
        assert_eq!(body.available, 4);

        let (status, body): (StatusCode, ResourceResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "PUT",
                    &format!("/l/{id}"),
                    Some(r#"{"count":2}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.count, 2);
        assert_eq!(body.available, 2);

        drop(router);
        db.close().await;
    }

    #[tokio::test]
    async fn library_borrow_uses_lowest_positions_and_exhausts() {
        let Some((router, db)) = library_test_app().await else {
            return;
        };
        let id = Uuid::new_v4();

        let (_status, pool): (StatusCode, ResourceResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "PUT",
                    &format!("/l/{id}"),
                    Some(r#"{"count":3}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(pool.available, 3);

        let mut positions = std::collections::HashSet::new();
        for _ in 0..3 {
            let (_status, borrow): (StatusCode, BorrowResponse) = json_body(
                router
                    .clone()
                    .oneshot(library_request(
                        "POST",
                        &format!("/l/{id}/borrow"),
                        Some(r#"{"ttl":30}"#.into()),
                    ))
                    .await
                    .unwrap(),
            )
            .await;
            assert!(positions.insert(borrow.position));
            assert!((0..3).contains(&borrow.position));
        }
        assert_eq!(positions.len(), 3);

        let (status, _body): (StatusCode, serde_json::Value) = json_status(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/borrow"),
                    Some(r#"{"ttl":30,"wait":0}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        drop(router);
        db.close().await;
    }

    #[tokio::test]
    async fn library_return_frees_slot() {
        let Some((router, db)) = library_test_app().await else {
            return;
        };
        let id = Uuid::new_v4();

        let (_status, _pool): (StatusCode, ResourceResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "PUT",
                    &format!("/l/{id}"),
                    Some(r#"{"count":2}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;

        let (_status, borrow): (StatusCode, BorrowResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/borrow"),
                    Some(r#"{"ttl":30}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        let returned_position = borrow.position;

        let (status, _body): (StatusCode, ReturnResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/return"),
                    Some(format!(r#"{{"lease":"{}"}}"#, borrow.lease)),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (_status, pool): (StatusCode, ResourceResponse) = json_body(
            router
                .clone()
                .oneshot(library_request("GET", &format!("/l/{id}"), None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(pool.in_use, 0);
        assert_eq!(pool.available, 2);

        let (_status, borrow2): (StatusCode, BorrowResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/borrow"),
                    Some(r#"{"ttl":30}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(borrow2.position, returned_position);

        drop(router);
        db.close().await;
    }

    #[tokio::test]
    async fn library_lease_expires_and_reuses_slot() {
        let Some((router, db)) = library_test_app().await else {
            return;
        };
        let id = Uuid::new_v4();

        let (_status, _pool): (StatusCode, ResourceResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "PUT",
                    &format!("/l/{id}"),
                    Some(r#"{"count":1}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;

        let (_status, borrow): (StatusCode, BorrowResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/borrow"),
                    Some(r#"{"ttl":0.5}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(borrow.position, 0);

        // Force the lease to look expired so we don't wait on wall-clock time.
        let lease_id = Uuid::parse_str(&borrow.lease).unwrap();
        sqlx::query(
            "UPDATE library_leases SET expires_at = now() - interval '1 second' WHERE id = $1",
        )
        .bind(lease_id)
        .execute(&db)
        .await
        .unwrap();

        let (_status, borrow2): (StatusCode, BorrowResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/borrow"),
                    Some(r#"{"ttl":30}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(borrow2.position, 0);

        drop(router);
        db.close().await;
    }

    #[tokio::test]
    async fn library_wait_wakes_on_return() {
        let Some((router, db)) = library_test_app().await else {
            return;
        };
        let id = Uuid::new_v4();

        let (_status, _pool): (StatusCode, ResourceResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "PUT",
                    &format!("/l/{id}"),
                    Some(r#"{"count":1}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;

        let (_status, borrow): (StatusCode, BorrowResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/borrow"),
                    Some(r#"{"ttl":30}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        let lease = borrow.lease.clone();

        let waiter_router = router.clone();
        let waiter_id = id;
        let waiter = tokio::spawn(async move {
            json_body::<BorrowResponse>(
                waiter_router
                    .oneshot(library_request(
                        "POST",
                        &format!("/l/{waiter_id}/borrow"),
                        Some(r#"{"ttl":30,"wait":5}"#.into()),
                    ))
                    .await
                    .unwrap(),
            )
            .await
        });

        let (_status, returned): (StatusCode, ReturnResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/return"),
                    Some(format!(r#"{{"lease":"{lease}"}}"#)),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert!(returned.returned);

        let (status, borrow2) = waiter.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(borrow2.position, 0);

        drop(router);
        db.close().await;
    }

    #[tokio::test]
    async fn library_put_can_raise_or_lower_count() {
        let Some((router, db)) = library_test_app().await else {
            return;
        };
        let id = Uuid::new_v4();

        let (_status, _pool): (StatusCode, ResourceResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "PUT",
                    &format!("/l/{id}"),
                    Some(r#"{"count":2}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;

        let (_status, borrow): (StatusCode, BorrowResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/borrow"),
                    Some(r#"{"ttl":30}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(borrow.position, 0);

        // Lower count below one occupied position.
        let (_status, pool): (StatusCode, ResourceResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "PUT",
                    &format!("/l/{id}"),
                    Some(r#"{"count":1}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(pool.count, 1);
        assert_eq!(pool.in_use, 1);
        assert_eq!(pool.available, 0);

        // New borrows for the dropped slot should fail immediately.
        let (status, _body): (StatusCode, serde_json::Value) = json_status(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/borrow"),
                    Some(r#"{"ttl":30,"wait":0}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // Raise count back up makes the out-of-range slot available again.
        let (_status, _pool): (StatusCode, ResourceResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "PUT",
                    &format!("/l/{id}"),
                    Some(r#"{"count":2}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;

        let (_status, borrow2): (StatusCode, BorrowResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/borrow"),
                    Some(r#"{"ttl":30,"wait":0}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(borrow2.position, 1);

        drop(router);
        db.close().await;
    }

    #[tokio::test]
    async fn library_concurrent_borrows_do_not_over_issue() {
        let Some((router, db)) = library_test_app().await else {
            return;
        };
        let id = Uuid::new_v4();
        let count = 5usize;

        let (_status, _pool): (StatusCode, ResourceResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "PUT",
                    &format!("/l/{id}"),
                    Some(format!(r#"{{"count":{count}}}"#)),
                ))
                .await
                .unwrap(),
        )
        .await;

        let mut handles = Vec::new();
        for _ in 0..(count + 3) {
            let r = router.clone();
            handles.push(tokio::spawn(async move {
                r.oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/borrow"),
                    Some(r#"{"ttl":30,"wait":0}"#.into()),
                ))
                .await
                .unwrap()
            }));
        }

        let mut positions = std::collections::HashSet::new();
        let mut successes = 0;
        let mut conflicts = 0;
        for handle in handles {
            let response = handle.await.unwrap();
            if response.status() == StatusCode::OK {
                let (_status, borrow): (StatusCode, BorrowResponse) = json_body(response).await;
                assert!(positions.insert(borrow.position));
                successes += 1;
            } else {
                assert_eq!(response.status(), StatusCode::CONFLICT);
                conflicts += 1;
            }
        }
        assert_eq!(successes, count);
        assert_eq!(conflicts, 3);

        drop(router);
        db.close().await;
    }

    #[tokio::test]
    async fn library_delete_removes_pool() {
        let Some((router, db)) = library_test_app().await else {
            return;
        };
        let id = Uuid::new_v4();

        let (_status, _pool): (StatusCode, ResourceResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "PUT",
                    &format!("/l/{id}"),
                    Some(r#"{"count":2}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;

        let (_status, borrow): (StatusCode, BorrowResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/borrow"),
                    Some(r#"{"ttl":30}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        let lease = borrow.lease;

        let (status, _body): (StatusCode, DeleteResponse) = json_body(
            router
                .clone()
                .oneshot(library_request("DELETE", &format!("/l/{id}"), None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _body): (StatusCode, serde_json::Value) = json_status(
            router
                .clone()
                .oneshot(library_request("GET", &format!("/l/{id}"), None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, body): (StatusCode, ReturnResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/return"),
                    Some(format!(r#"{{"lease":"{lease}"}}"#)),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.returned);

        drop(router);
        db.close().await;
    }

    #[tokio::test]
    async fn library_validation_errors() {
        let Some((router, db)) = library_test_app().await else {
            return;
        };
        let id = Uuid::new_v4();

        let (status, _body): (StatusCode, serde_json::Value) = json_status(
            router
                .clone()
                .oneshot(library_request("GET", "/l/not-a-uuid", None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _body): (StatusCode, serde_json::Value) = json_status(
            router
                .clone()
                .oneshot(library_request(
                    "PUT",
                    &format!("/l/{id}"),
                    Some(r#"{"count":-1}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _body): (StatusCode, serde_json::Value) = json_status(
            router
                .clone()
                .oneshot(library_request(
                    "PUT",
                    &format!("/l/{id}"),
                    Some(r#"{"count":1000}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _body): (StatusCode, serde_json::Value) = json_status(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/borrow"),
                    Some(r#"{"ttl":0}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _body): (StatusCode, serde_json::Value) = json_status(
            router
                .clone()
                .oneshot(library_request("GET", &format!("/l/{id}"), None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, body): (StatusCode, ReturnResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/return"),
                    Some(r#"{"lease":"00000000-0000-0000-0000-000000000000"}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.returned);

        drop(router);
        db.close().await;
    }

    #[tokio::test]
    async fn library_zero_count_pool_conflicts() {
        let Some((router, db)) = library_test_app().await else {
            return;
        };
        let id = Uuid::new_v4();

        let (status, body): (StatusCode, ResourceResponse) = json_body(
            router
                .clone()
                .oneshot(library_request(
                    "PUT",
                    &format!("/l/{id}"),
                    Some(r#"{"count":0}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.available, 0);

        // A zero-capacity pool can never lend; borrow fails fast with 409.
        let (status, _body): (StatusCode, serde_json::Value) = json_status(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/borrow"),
                    Some(r#"{"ttl":30,"wait":0}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        drop(router);
        db.close().await;
    }

    #[tokio::test]
    async fn library_raise_count_wakes_waiter() {
        let Some((router, db)) = library_test_app().await else {
            return;
        };
        let id = Uuid::new_v4();

        // Pool of 1, fully borrowed.
        let _ = router
            .clone()
            .oneshot(library_request(
                "PUT",
                &format!("/l/{id}"),
                Some(r#"{"count":1}"#.into()),
            ))
            .await
            .unwrap();
        let _ = router
            .clone()
            .oneshot(library_request(
                "POST",
                &format!("/l/{id}/borrow"),
                Some(r#"{"ttl":30}"#.into()),
            ))
            .await
            .unwrap();

        // A waiter blocks because the only slot is taken.
        let waiter_router = router.clone();
        let waiter = tokio::spawn(async move {
            json_body::<BorrowResponse>(
                waiter_router
                    .oneshot(library_request(
                        "POST",
                        &format!("/l/{id}/borrow"),
                        Some(r#"{"ttl":30,"wait":5}"#.into()),
                    ))
                    .await
                    .unwrap(),
            )
            .await
        });

        // Let the waiter subscribe and block (no sleep — just yield the executor).
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }

        // Raising the count opens slot 1 and must wake the waiter.
        let _ = router
            .clone()
            .oneshot(library_request(
                "PUT",
                &format!("/l/{id}"),
                Some(r#"{"count":2}"#.into()),
            ))
            .await
            .unwrap();

        let (status, borrow) = waiter.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(borrow.position, 1);

        drop(router);
        db.close().await;
    }

    #[tokio::test]
    async fn library_lease_expiry_wakes_waiter() {
        let Some((router, db)) = library_test_app().await else {
            return;
        };
        let id = Uuid::new_v4();

        // Pool of 1; hold the only slot for a short ttl.
        let _ = router
            .clone()
            .oneshot(library_request(
                "PUT",
                &format!("/l/{id}"),
                Some(r#"{"count":1}"#.into()),
            ))
            .await
            .unwrap();
        let _ = router
            .clone()
            .oneshot(library_request(
                "POST",
                &format!("/l/{id}/borrow"),
                Some(r#"{"ttl":0.3}"#.into()),
            ))
            .await
            .unwrap();

        // The waiter gets no return notification; it must self-wake when the held
        // lease expires (the next_expiry timer path), then claim the freed slot.
        let (status, borrow) = json_body::<BorrowResponse>(
            router
                .clone()
                .oneshot(library_request(
                    "POST",
                    &format!("/l/{id}/borrow"),
                    Some(r#"{"ttl":30,"wait":5}"#.into()),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(borrow.position, 0);

        drop(router);
        db.close().await;
    }

    // ------------------------------------------------------------------
    // Favicon helpers (no DB / network required)
    // ------------------------------------------------------------------

    #[test]
    fn origin_of_normalizes_and_validates() {
        assert_eq!(
            origin_of("https://Example.com/path?q=1#f").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            origin_of("http://example.com:8080/").unwrap(),
            "http://example.com:8080"
        );
        // Default ports are dropped for a stable cache key.
        assert_eq!(origin_of("https://example.com:443/").unwrap(), "https://example.com");
        assert!(origin_of("ftp://example.com").is_err());
        assert!(origin_of("not a url").is_err());
        assert!(origin_of("http://127.0.0.1/").is_err());
        assert!(origin_of("http://[::1]/").is_err());
    }

    #[test]
    fn ip_is_forbidden_blocks_non_public() {
        for blocked in [
            "0.0.0.0",
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "224.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                ip_is_forbidden(&blocked.parse().unwrap()),
                "{blocked} should be forbidden"
            );
        }
        for allowed in ["1.1.1.1", "93.184.216.34", "2606:2800:220:1::1"] {
            assert!(
                !ip_is_forbidden(&allowed.parse().unwrap()),
                "{allowed} should be allowed"
            );
        }
    }

    #[test]
    fn pow_token_parsing_and_level() {
        // Level-20 example token from the /pow docs.
        let (doc, level) = pow_token_doc_and_level("aGVsbG8gd29ybGQ.XBCKI7lQ3i4").unwrap();
        assert_eq!(doc, b"hello world");
        assert_eq!(level, 20);

        // Empty doc and suffix are well-formed (and reach whatever they reach).
        let (doc, _) = pow_token_doc_and_level(".").unwrap();
        assert!(doc.is_empty());

        assert!(pow_token_doc_and_level("nodot").is_err());
        assert!(pow_token_doc_and_level("aGVsbG8=.AAAA").is_err(), "padding");
        assert!(pow_token_doc_and_level("aGVsbG8gd29ybGR.AAAA").is_err(), "trailing bits");
        let long_suffix = format!("aGVsbG8.{}", "A".repeat(60));
        assert!(pow_token_doc_and_level(&long_suffix).is_err(), "suffix > 32 bytes");
    }

    #[test]
    fn shot_spec_validation_and_cache_key() {
        let config = test_secret_config();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let spec = |width, height, scale, ts| ShotSpec {
            url: "https://example.com/".to_owned(),
            width,
            height,
            scale,
            ts,
        };

        assert!(spec(800, 600, 0.5, now).validate(&config).is_ok());
        assert!(spec(2048, 2048, 1.0, now).validate(&config).is_ok());
        assert!(spec(2049, 600, 1.0, now).validate(&config).is_err(), "too wide");
        assert!(spec(800, 0, 1.0, now).validate(&config).is_err(), "zero height");
        assert!(spec(800, 600, 0.0, now).validate(&config).is_err(), "zero scale");
        assert!(spec(800, 600, 1.5, now).validate(&config).is_err(), "upscale");
        assert!(spec(1, 1, 0.1, now).validate(&config).is_err(), "sub-pixel output");
        assert!(spec(800, 600, 1.0, now - 3600).validate(&config).is_err(), "stale ts");
        assert!(spec(800, 600, 1.0, now + 3600).validate(&config).is_err(), "future ts");

        // The cache key covers everything but ts.
        assert_eq!(spec(800, 600, 0.5, now).cache_key(), spec(800, 600, 0.5, 0).cache_key());
        assert_ne!(spec(800, 600, 0.5, now).cache_key(), spec(800, 601, 0.5, now).cache_key());

        // Unknown fields are rejected: the doc must be exactly the spec.
        assert!(
            serde_json::from_str::<ShotSpec>(
                r#"{"url":"https://example.com/","width":1,"height":1,"ts":0,"extra":1}"#
            )
            .is_err()
        );
        // scale is optional and defaults to 1.
        let parsed: ShotSpec = serde_json::from_str(
            r#"{"url":"https://example.com/","width":1,"height":1,"ts":0}"#,
        )
        .unwrap();
        assert_eq!(parsed.scale, 1.0);
    }

    #[test]
    fn extract_icon_hrefs_uses_a_real_parser() {
        let html = r#"
            <html><head>
              <link rel="stylesheet" href="/style.css">
              <link rel="ICON" href="/fav.ico">
              <link rel="shortcut icon" href="/legacy.ico">
              <link rel="apple-touch-icon" href="/apple.png?v=2&amp;x=1">
              <link rel="icon" type="image/svg+xml" href='/icon.svg'>
              <link rel="canonical" href="/self">
            </head></html>
        "#;
        let hrefs = extract_icon_hrefs(html);
        assert!(hrefs.contains(&"/fav.ico".to_owned()));
        assert!(hrefs.contains(&"/legacy.ico".to_owned()));
        assert!(hrefs.contains(&"/icon.svg".to_owned()));
        // Entities are decoded by the parser.
        assert!(hrefs.contains(&"/apple.png?v=2&x=1".to_owned()));
        // Non-icon links are ignored.
        assert!(!hrefs.iter().any(|h| h.contains("style.css") || h == "/self"));
    }

    #[test]
    fn decode_data_uri_handles_inline_icons() {
        // The emoji-favicon trick: an SVG declared inline, spaces and quotes raw.
        let (ct, bytes) = decode_data_uri(
            r#"data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg">x</svg>"#,
        )
        .unwrap();
        assert_eq!(ct, "image/svg+xml");
        assert!(String::from_utf8_lossy(&bytes).contains("<svg"));

        // Percent-encoded payloads are decoded.
        let (_, bytes) = decode_data_uri("data:image/svg+xml,%3Csvg%3E%3C/svg%3E").unwrap();
        assert_eq!(bytes, b"<svg></svg>");

        // Base64 payloads (a 1x1 transparent GIF) are decoded and, since a media
        // type is declared, trusted.
        let (ct, bytes) = decode_data_uri(
            "data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==",
        )
        .unwrap();
        assert_eq!(ct, "image/gif");
        assert_eq!(&bytes[..3], b"GIF");

        // No declared image type: accepted only if the bytes sniff as an image.
        assert!(decode_data_uri("data:,%3Csvg%3E%3C/svg%3E").is_some());
        assert!(decode_data_uri("data:text/plain,hello").is_none());

        // Malformed or empty payloads are rejected.
        assert!(decode_data_uri("data:image/png;base64,not valid base64!!!").is_none());
        assert!(decode_data_uri("data:image/svg+xml,").is_none());
        assert!(decode_data_uri("https://example.com/favicon.ico").is_none());
    }

    #[test]
    fn sniff_image_content_type_recognizes_formats() {
        assert_eq!(
            sniff_image_content_type(&[0x00, 0x00, 0x01, 0x00, 0x10]),
            Some("image/x-icon")
        );
        assert_eq!(
            sniff_image_content_type(b"\x89PNG\r\n\x1a\nrest"),
            Some("image/png")
        );
        assert_eq!(sniff_image_content_type(b"GIF89a"), Some("image/gif"));
        assert_eq!(sniff_image_content_type(&[0xff, 0xd8, 0xff, 0xe0]), Some("image/jpeg"));
        assert_eq!(
            sniff_image_content_type(b"<?xml version=\"1.0\"?><svg xmlns=\"...\">"),
            Some("image/svg+xml")
        );
        // An HTML 404 page served with 200 must not pass as an image.
        assert_eq!(sniff_image_content_type(b"<!doctype html><title>Not found</title>"), None);
    }

    // ------------------------------------------------------------------
    // Fonts
    // ------------------------------------------------------------------

    #[test]
    fn parse_font_metadata_reads_core_fields() {
        let text = r#"
name: "Test Sans"
designer: "A. Designer"
license: "OFL"
category: "SANS_SERIF"
fonts {
  name: "Test Sans"
  style: "normal"
  weight: 400
  filename: "TestSans[wght].ttf"
}
fonts {
  style: "italic"
  weight: 700
  filename: "TestSans-BoldItalic.ttf"
}
subsets: "latin"
subsets: "greek"
axes {
  tag: "wght"
  min_value: 100.0
  max_value: 900.0
}
"#;
        let md = parse_font_metadata(text);
        assert_eq!(md.name, "Test Sans");
        assert_eq!(md.designer.as_deref(), Some("A. Designer"));
        assert_eq!(md.category.as_deref(), Some("SANS_SERIF"));
        assert_eq!(md.subsets, vec!["latin", "greek"]);
        assert_eq!(md.fonts.len(), 2);
        assert_eq!(md.fonts[0].filename, "TestSans[wght].ttf");
        assert_eq!(md.fonts[0].weight, Some(400));
        assert_eq!(md.fonts[1].style.as_deref(), Some("italic"));
        assert_eq!(md.axes.len(), 1);
        assert_eq!(md.axes[0].tag, "wght");
        assert_eq!(md.axes[0].max, Some(900.0));
    }

    #[test]
    fn unquote_textproto_handles_quotes_and_escapes() {
        assert_eq!(unquote_textproto(r#""hello""#), "hello");
        assert_eq!(unquote_textproto(r#""a\"b""#), "a\"b");
        assert_eq!(unquote_textproto("SANS_SERIF"), "SANS_SERIF");
        assert_eq!(unquote_textproto("400"), "400");
    }

    fn write_test_family(root: &std::path::Path) {
        let family = root.join("ofl").join("testsans");
        std::fs::create_dir_all(&family).unwrap();
        std::fs::write(
            family.join("METADATA.pb"),
            "name: \"Test Sans\"\ncategory: \"SANS_SERIF\"\nsubsets: \"latin\"\nfonts {\n  filename: \"TestSans-Regular.ttf\"\n  weight: 400\n}\n",
        )
        .unwrap();
        std::fs::write(family.join("TestSans-Regular.ttf"), b"\x00\x01\x00\x00fake-ttf").unwrap();
    }

    #[test]
    fn font_index_loads_and_finds_by_slug() {
        let root = std::env::temp_dir().join(format!("ccme-fonts-{}", Uuid::new_v4()));
        write_test_family(&root);

        let index = FontIndex::load(&root);
        assert_eq!(index.families.len(), 1);
        let family = index.get("TestSans").expect("slug lookup is case-insensitive");
        assert_eq!(family.name, "Test Sans");
        assert_eq!(family.files[0].filename, "TestSans-Regular.ttf");
        assert!(index.get("missing").is_none());

        std::fs::remove_dir_all(&root).ok();
    }

    fn fonts_test_router(fonts: FontIndex) -> Router {
        // A lazy pool never connects; the fonts handlers don't touch the DB.
        let db = PgPoolOptions::new()
            .connect_lazy("postgres://cc_me@127.0.0.1:55432/cc_me")
            .unwrap();
        let (inbox_tx, _) = broadcast::channel(16);
        let (library_tx, _) = broadcast::channel(16);
        let (stats_tx, _) = mpsc::channel(16);
        let config = Config {
            bind_addr: "127.0.0.1:3000".parse().unwrap(),
            database_url: "postgres://cc_me@127.0.0.1:55432/cc_me".to_owned(),
            max_requests: 100,
            default_get_limit: 1,
            max_get_limit: 1000,
            long_poll_seconds: 25.0,
            library_max_count: 100,
            library_max_ttl_seconds: 60.0,
            library_max_wait_seconds: 5.0,
            secret_default_ttl_hours: 24,
            secret_max_ttl_hours: 168,
            secret_max_bytes: 262144,
            secret_cleanup_interval_seconds: 60,
            fonts_dir: PathBuf::from("/var/lib/fonts"),
            fonts_refresh_interval_seconds: 0,
            shot_chrome_bin: "chromium".to_owned(),
            shot_chrome_args: Vec::new(),
            shot_pow_level: 24,
            shot_ts_window_seconds: 300,
            shot_nav_timeout_seconds: 10.0,
            shot_cache_seconds: 3600.0,
        };
        Router::new()
            .route("/fonts", get(fonts_search))
            .route("/fonts/{slug}", get(font_family))
            .route("/fonts/{slug}/{filename}", get(font_file))
            .with_state(AppState {
                db,
                inbox_tx,
                library_tx,
                stats_tx,
                http: build_http_client(),
                fonts: Arc::new(RwLock::new(Arc::new(fonts))),
                chrome: Arc::new(tokio::sync::Mutex::new(None)),
                shot_permits: Arc::new(tokio::sync::Semaphore::new(SHOT_MAX_CONCURRENT)),
                config,
            })
    }

    #[tokio::test]
    async fn fonts_http_search_detail_and_download() {
        let root = std::env::temp_dir().join(format!("ccme-fonts-{}", Uuid::new_v4()));
        write_test_family(&root);
        let router = fonts_test_router(FontIndex::load(&root));

        // Search.
        let (status, body): (StatusCode, serde_json::Value) = json_status(
            router
                .clone()
                .oneshot(library_request("GET", "/fonts?q=test&category=SANS_SERIF", None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 1);
        assert_eq!(body["families"][0]["slug"], "testsans");
        assert_eq!(
            body["families"][0]["files"][0]["path"],
            "/fonts/testsans/TestSans-Regular.ttf"
        );

        // No query string → docs page (HTML), not JSON.
        let response = router
            .clone()
            .oneshot(library_request("GET", "/fonts", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "text/html; charset=utf-8"
        );

        // Family detail.
        let (status, _body): (StatusCode, serde_json::Value) = json_status(
            router
                .clone()
                .oneshot(library_request("GET", "/fonts/testsans", None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Download the listed file.
        let response = router
            .clone()
            .oneshot(library_request(
                "GET",
                "/fonts/testsans/TestSans-Regular.ttf",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "font/ttf"
        );
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"\x00\x01\x00\x00fake-ttf");

        // A file not listed in the family is rejected (path-traversal whitelist).
        let response = router
            .clone()
            .oneshot(library_request("GET", "/fonts/testsans/OFL.txt", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Unknown family.
        let response = router
            .clone()
            .oneshot(library_request("GET", "/fonts/missing", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        std::fs::remove_dir_all(&root).ok();
    }
}
