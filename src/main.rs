use std::{
    collections::{HashMap, HashSet},
    env,
    net::SocketAddr,
    sync::{
        LazyLock,
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
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crypto_box::{
    PublicKey,
    aead::rand_core::{OsRng, TryRngCore},
};
use curve25519_dalek::edwards::CompressedEdwardsY;
#[cfg(test)]
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    PgPool, Row,
    postgres::{PgListener, PgPoolOptions},
};
use tokio::{
    sync::{broadcast, mpsc},
    time::Instant,
};
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
    config: Config,
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
}

#[derive(Serialize)]
struct StatCounts {
    redirects: usize,
    inboxes: usize,
    inboxed_messages: usize,
    aliases: usize,
    forwarded: usize,
    secrets: usize,
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

    let app = Router::new()
        .route("/", get(root))
        .route("/http", get(http_docs))
        .route("/lib", get(library_docs))
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

async fn migrate(db: &PgPool) -> Result<(), sqlx::Error> {
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
        "default-src 'none'; script-src 'nonce-{0}' 'self'; style-src 'nonce-{0}'; connect-src 'self'; base-uri 'none'",
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
}
