use std::time::Duration;

use axum::{
    Json, Router,
    body::Body,
    extract::{
        OriginalUri, Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::trace::TraceLayer;

use crate::{
    AppError, AppResult, assets, auth, html, ids,
    storage::{AppState, NewFileRecord},
};
use tokio_util::io::ReaderStream;

const MAX_METADATA_B64_LEN: usize = 64 * 1024;
const MAX_AUTH_VALUE_LEN: usize = 256;
const WS_INIT_TIMEOUT: Duration = Duration::from_secs(10);
const WS_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Serialize)]
struct ExistsResponse {
    #[serde(rename = "requiresPassword")]
    requires_password: bool,
}

#[derive(Serialize)]
struct MetadataResponse {
    metadata: String,
    #[serde(rename = "finalDownload")]
    final_download: bool,
    ttl: u64,
}

#[derive(Serialize)]
struct InfoResponse {
    dlimit: u32,
    dtotal: u32,
    ttl: u64,
}

#[derive(Deserialize)]
struct OwnerBody {
    owner_token: String,
}

#[derive(Deserialize)]
struct PasswordBody {
    owner_token: String,
    auth: String,
}

#[derive(Deserialize)]
struct ParamsBody {
    owner_token: String,
    download_limit: u32,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct WsInit {
    fileMetadata: Option<String>,
    authorization: Option<String>,
    bearer: Option<String>,
    timeLimit: Option<u64>,
    dlimit: Option<u32>,
}

pub fn app(state: AppState) -> Router {
    let trace_requests = !state.config.node_env.eq_ignore_ascii_case("production");
    let router = Router::new()
        .route("/", get(home))
        .route("/download/{id}", get(download_page))
        .route("/download/{id}/", get(download_page))
        .route("/download/{id}/{key}", get(download_page_with_key))
        .route("/download/{id}/{key}/", get(download_page_with_key))
        .route("/unsupported/{reason}", get(unsupported))
        .route("/error", get(error_page))
        .route("/config", get(config))
        .route("/app.webmanifest", get(webmanifest))
        .route("/__version__", get(version))
        .route("/__lbheartbeat__", get(lbheartbeat))
        .route("/__heartbeat__", get(heartbeat))
        .route("/api/ws", get(ws_upload))
        .route("/api/exists/{id}", get(api_exists))
        .route("/api/metadata/{id}", get(api_metadata))
        .route("/api/download/{id}", get(api_download))
        .route("/api/download/blob/{id}", get(api_download))
        .route("/api/delete/{id}", post(api_delete))
        .route("/api/password/{id}", post(api_password))
        .route("/api/params/{id}", post(api_params))
        .route("/api/info/{id}", post(api_info))
        .fallback(static_or_not_found)
        .with_state(state)
        .layer(middleware::from_fn(no_cache_headers))
        .layer(middleware::map_response(csp_header));

    if trace_requests {
        router.layer(TraceLayer::new_for_http())
    } else {
        router
    }
}

async fn no_cache_headers(mut request: Request<Body>, next: Next) -> Response {
    // Generate CSP nonce for this request and store in extensions
    let nonce = base64::engine::general_purpose::STANDARD.encode(rand::random::<[u8; 16]>());
    request.extensions_mut().insert(nonce);
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache, no-store, must-revalidate, max-age=0"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    // CSP header will be added by csp_header middleware
    response
}

async fn csp_header(response: Response) -> Response {
    let nonce = response
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_default();
    let mut response = response;
    let headers = response.headers_mut();
    let csp = format!(
        "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; font-src 'self'; connect-src 'self' ws: wss:; script-src 'self' 'nonce-{}'; style-src 'self' 'nonce-{}'",
        nonce, nonce
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_str(&csp).unwrap(),
    );
    response
}

async fn home(State(state): State<AppState>, request: Request<Body>) -> Response {
    let nonce = request
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_default();
    let html = html::home(&state.config);
    let mut response = Html(html).into_response();
    response.extensions_mut().insert(nonce);
    response
}

async fn download_page(
    State(state): State<AppState>,
    Path(id): Path<String>,
    request: Request<Body>,
) -> Response {
    let nonce = request
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_default();
    if ids::validate_file_id(&id).is_err() {
        let html = html::not_found(&state.config);
        let mut response = (StatusCode::NOT_FOUND, HeaderMap::new(), Html(html)).into_response();
        response.extensions_mut().insert(nonce);
        return response;
    }
    let Some(record) = state.store.get(&id).await else {
        let html = html::not_found(&state.config);
        let mut response = (StatusCode::NOT_FOUND, HeaderMap::new(), Html(html)).into_response();
        response.extensions_mut().insert(nonce);
        return response;
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_str(&format!("send-v1 {}", record.nonce)).unwrap(),
    );
    let html = html::download(&state.config, &id, &record.nonce, record.pwd);
    let mut response = (StatusCode::OK, headers, Html(html)).into_response();
    response.extensions_mut().insert(nonce);
    response
}

async fn download_page_with_key(
    State(state): State<AppState>,
    Path((id, _key)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    let nonce = request
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_default();
    if ids::validate_file_id(&id).is_err() {
        let html = html::not_found(&state.config);
        let mut response = (StatusCode::NOT_FOUND, HeaderMap::new(), Html(html)).into_response();
        response.extensions_mut().insert(nonce);
        return response;
    }
    let Some(record) = state.store.get(&id).await else {
        let html = html::not_found(&state.config);
        let mut response = (StatusCode::NOT_FOUND, HeaderMap::new(), Html(html)).into_response();
        response.extensions_mut().insert(nonce);
        return response;
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_str(&format!("send-v1 {}", record.nonce)).unwrap(),
    );
    let html = html::download(&state.config, &id, &record.nonce, record.pwd);
    let mut response = (StatusCode::OK, headers, Html(html)).into_response();
    response.extensions_mut().insert(nonce);
    response
}

async fn unsupported(
    State(state): State<AppState>,
    Path(reason): Path<String>,
    request: Request<Body>,
) -> Response {
    let nonce = request
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_default();
    let html = html::unsupported(&state.config, &reason);
    let mut response = Html(html).into_response();
    response.extensions_mut().insert(nonce);
    response
}

async fn error_page(State(state): State<AppState>, request: Request<Body>) -> Response {
    let nonce = request
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_default();
    let html = html::error(&state.config);
    let mut response = Html(html).into_response();
    response.extensions_mut().insert(nonce);
    response
}

async fn static_or_not_found(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    request: Request<Body>,
) -> Response {
    let nonce = request
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_default();
    let path = uri.path().trim_start_matches('/');
    if !path.is_empty()
        && !path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        && let Some(bytes) = assets::get(path)
    {
        let content_type = mime_guess::from_path(path)
            .first_or_octet_stream()
            .to_string();
        let mut response = (
            StatusCode::OK,
            [(header::CONTENT_TYPE, content_type)],
            bytes,
        )
            .into_response();
        response.extensions_mut().insert(nonce);
        return response;
    }
    let html = html::not_found(&state.config);
    let mut response = (StatusCode::NOT_FOUND, Html(html)).into_response();
    response.extensions_mut().insert(nonce);
    response
}

async fn config(State(state): State<AppState>) -> Json<crate::config::ClientConfig> {
    Json(state.config.client_config())
}

async fn webmanifest(State(state): State<AppState>) -> impl IntoResponse {
    let manifest = json!({
        "name": "Send",
        "short_name": "Send",
        "lang": "en",
        "icons": [
            { "src": "/icon.svg", "type": "image/svg+xml", "sizes": "any", "purpose": "any maskable" }
        ],
        "start_url": "/",
        "display": "standalone",
        "orientation": "portrait",
        "theme_color": state.config.web_ui.ui_color_primary,
        "background_color": "white"
    });
    (
        [(header::CONTENT_TYPE, "application/manifest+json")],
        Json(manifest),
    )
}

async fn version() -> Json<serde_json::Value> {
    Json(json!({
        "commit": "",
        "source": "send-rs",
        "version": "3.4.27"
    }))
}

async fn lbheartbeat() -> StatusCode {
    StatusCode::OK
}

async fn heartbeat(State(state): State<AppState>) -> StatusCode {
    match state.store.ping().await {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn api_exists(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<impl IntoResponse> {
    ids::validate_file_id(&id)?;
    let record = state.store.get(&id).await.ok_or(AppError::NotFound)?;
    Ok((
        [(
            header::WWW_AUTHENTICATE,
            format!("send-v1 {}", record.nonce),
        )],
        Json(ExistsResponse {
            requires_password: record.pwd,
        }),
    ))
}

async fn api_metadata(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let record = match authorized_record_response(&state, &id, &headers).await {
        Ok(record) => record,
        Err(response) => return response,
    };
    let nonce = match state.store.rotate_nonce_if(&id, &record.nonce).await {
        Ok(nonce) => nonce,
        Err(err) => return err.into_response(),
    };
    let ttl = match state.store.ttl_ms(&id).await {
        Ok(ttl) => ttl,
        Err(err) => return err.into_response(),
    };
    (
        [(header::WWW_AUTHENTICATE, format!("send-v1 {nonce}"))],
        Json(MetadataResponse {
            metadata: record.metadata,
            final_download: record.dl + 1 == record.dlimit,
            ttl,
        }),
    )
        .into_response()
}

async fn api_download(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let record = match authorized_record_response(&state, &id, &headers).await {
        Ok(record) => record,
        Err(response) => return response,
    };
    let nonce = match state.store.rotate_nonce_if(&id, &record.nonce).await {
        Ok(nonce) => nonce,
        Err(err) => return err.into_response(),
    };
    // Open before claiming: on Unix the open descriptor remains readable when
    // a final-download claim atomically removes the directory entry.
    let blob = match state.store.open_blob(&id).await {
        Ok(blob) => blob,
        Err(err) => return err.into_response(),
    };
    if let Err(err) = state.store.claim_download(&id).await {
        return err.into_response();
    }
    let size = blob.size;
    let body = Body::from_stream(ReaderStream::new(blob.file));
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            ),
            (
                header::WWW_AUTHENTICATE,
                HeaderValue::from_str(&format!("send-v1 {nonce}")).unwrap(),
            ),
            (
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&size.to_string()).unwrap(),
            ),
        ],
        body,
    )
        .into_response()
}

async fn api_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<OwnerBody>,
) -> AppResult<StatusCode> {
    ids::validate_file_id(&id)?;
    verify_owner_body(&state, &id, &body.owner_token).await?;
    state.store.delete(&id).await?;
    Ok(StatusCode::OK)
}

async fn api_password(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<PasswordBody>,
) -> AppResult<StatusCode> {
    ids::validate_file_id(&id)?;
    if body.auth.is_empty()
        || body.auth.len() > MAX_AUTH_VALUE_LEN
        || !auth::valid_stored_auth(&body.auth)
    {
        return Err(AppError::BadRequest("auth is invalid".into()));
    }
    verify_owner_body(&state, &id, &body.owner_token).await?;
    state.store.set_password(&id, body.auth).await?;
    Ok(StatusCode::OK)
}

async fn api_params(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ParamsBody>,
) -> AppResult<StatusCode> {
    ids::validate_file_id(&id)?;
    if body.download_limit == 0 || body.download_limit > state.config.limits.max_downloads {
        return Err(AppError::BadRequest("download_limit out of range".into()));
    }
    verify_owner_body(&state, &id, &body.owner_token).await?;
    state
        .store
        .set_download_limit(&id, body.download_limit)
        .await?;
    Ok(StatusCode::OK)
}

async fn api_info(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<OwnerBody>,
) -> AppResult<Json<InfoResponse>> {
    ids::validate_file_id(&id)?;
    let record = verify_owner_body(&state, &id, &body.owner_token).await?;
    let ttl = state.store.ttl_ms(&id).await?;
    Ok(Json(InfoResponse {
        dlimit: record.dlimit,
        dtotal: record.dl,
        ttl,
    }))
}

async fn authorized_record_response(
    state: &AppState,
    id: &str,
    headers: &HeaderMap,
) -> Result<crate::storage::FileRecord, Response> {
    if let Err(err) = ids::validate_file_id(id) {
        return Err(err.into_response());
    }
    let record = match state.store.get(id).await {
        Some(record) => record,
        None => return Err(AppError::NotFound.into_response()),
    };
    if record.pwd
        && let Some(retry_after) = state.auth_throttle.retry_after(id)
    {
        return Err(rate_limited_response(&record.nonce, retry_after));
    }
    let provided = match auth::parse_send_v1(headers) {
        Ok(provided) => provided,
        Err(_) => {
            if record.pwd {
                state.auth_throttle.record_failure(id);
            }
            return Err(challenge_response(&record.nonce));
        }
    };
    match auth::verify_hmac(&record.auth, &record.nonce, &provided) {
        Ok(()) => {
            if record.pwd {
                state.auth_throttle.record_success(id);
            }
            Ok(record)
        }
        Err(_) => {
            if record.pwd {
                state.auth_throttle.record_failure(id);
            }
            Err(challenge_response(&record.nonce))
        }
    }
}

fn challenge_response(nonce: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, format!("send-v1 {nonce}"))],
    )
        .into_response()
}

fn rate_limited_response(nonce: &str, retry_after: Duration) -> Response {
    let seconds = retry_after.as_secs().max(1).to_string();
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::WWW_AUTHENTICATE, format!("send-v1 {nonce}")),
            (header::RETRY_AFTER, seconds),
        ],
    )
        .into_response()
}

async fn verify_owner_body(
    state: &AppState,
    id: &str,
    owner_token: &str,
) -> AppResult<crate::storage::FileRecord> {
    state.store.verify_owner(id, owner_token).await
}

async fn ws_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_upload(state, headers, socket))
}

async fn timeout_next_message(
    socket: &mut WebSocket,
    timeout: Duration,
) -> Option<Result<Message, axum::Error>> {
    tokio::time::timeout(timeout, socket.next())
        .await
        .ok()
        .flatten()
}

async fn handle_ws_upload(state: AppState, headers: HeaderMap, mut socket: WebSocket) {
    let Some(Ok(Message::Text(init_raw))) =
        timeout_next_message(&mut socket, WS_INIT_TIMEOUT).await
    else {
        let _ = socket
            .send(Message::Text(json!({ "error": 400 }).to_string().into()))
            .await;
        return;
    };

    let Ok(init) = serde_json::from_str::<WsInit>(&init_raw) else {
        let _ = socket
            .send(Message::Text(json!({ "error": 400 }).to_string().into()))
            .await;
        return;
    };

    let time_limit = init
        .timeLimit
        .unwrap_or(state.config.defaults.default_expire_seconds);
    let dlimit = init
        .dlimit
        .unwrap_or(state.config.defaults.default_downloads);
    let Some(metadata) = init.fileMetadata else {
        let _ = socket
            .send(Message::Text(json!({ "error": 400 }).to_string().into()))
            .await;
        return;
    };
    let Some(authorization) = init.authorization else {
        let _ = socket
            .send(Message::Text(json!({ "error": 400 }).to_string().into()))
            .await;
        return;
    };

    let _bearer_seen = init.bearer.as_deref();
    if metadata.is_empty()
        || metadata.len() > MAX_METADATA_B64_LEN
        || authorization.is_empty()
        || authorization.len() > MAX_AUTH_VALUE_LEN
        || time_limit == 0
        || time_limit > state.config.limits.max_expire_seconds
        || dlimit == 0
        || dlimit > state.config.limits.max_downloads
    {
        let _ = socket
            .send(Message::Text(json!({ "error": 400 }).to_string().into()))
            .await;
        return;
    }

    let Some(auth_key) = authorization.strip_prefix("send-v1 ") else {
        let _ = socket
            .send(Message::Text(json!({ "error": 400 }).to_string().into()))
            .await;
        return;
    };
    if !auth::valid_stored_auth(auth_key) {
        let _ = socket
            .send(Message::Text(json!({ "error": 400 }).to_string().into()))
            .await;
        return;
    }

    let id = ids::random_hex(8);
    let owner = auth::random_owner();
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok());
    let is_https =
        forwarded_proto(&headers).is_some_and(|proto| proto.eq_ignore_ascii_case("https"));
    let url = format!(
        "{}/download/{id}/",
        state
            .config
            .base_url_for_headers(host, is_https)
            .trim_end_matches('/')
    );

    let first_reply = json!({
        "url": url,
        "ownerToken": owner,
        "id": id
    });
    if socket
        .send(Message::Text(first_reply.to_string().into()))
        .await
        .is_err()
    {
        return;
    }

    let mut upload = match state.store.start_upload(&id).await {
        Ok(upload) => upload,
        Err(_) => {
            let _ = socket
                .send(Message::Text(json!({ "error": 500 }).to_string().into()))
                .await;
            return;
        }
    };
    let mut eof = false;
    while let Some(message) = timeout_next_message(&mut socket, WS_IDLE_TIMEOUT).await {
        match message {
            Ok(Message::Binary(chunk)) if chunk.len() == 1 && chunk[0] == 0 => {
                eof = true;
                break;
            }
            Ok(Message::Binary(chunk)) => {
                if upload.size().saturating_add(chunk.len() as u64)
                    > encrypted_size_limit(state.config.limits.max_file_size)
                {
                    state.store.abort_upload(upload).await;
                    let _ = socket
                        .send(Message::Text(json!({ "error": 413 }).to_string().into()))
                        .await;
                    return;
                }
                if upload.write(&chunk).await.is_err() {
                    state.store.abort_upload(upload).await;
                    let _ = socket
                        .send(Message::Text(json!({ "error": 500 }).to_string().into()))
                        .await;
                    return;
                }
            }
            Ok(Message::Close(_)) | Err(_) => {
                state.store.abort_upload(upload).await;
                return;
            }
            _ => {}
        }
    }

    if !eof {
        state.store.abort_upload(upload).await;
        return;
    }

    let result = state
        .store
        .commit_upload(
            NewFileRecord {
                id,
                owner,
                metadata,
                dlimit,
                auth: auth_key.to_string(),
                ttl: std::time::Duration::from_secs(time_limit),
            },
            upload,
        )
        .await;

    match result {
        Ok(_) => {
            let _ = socket
                .send(Message::Text(json!({ "ok": true }).to_string().into()))
                .await;
        }
        Err(_) => {
            let _ = socket
                .send(Message::Text(json!({ "error": 500 }).to_string().into()))
                .await;
        }
    }
}

fn forwarded_proto(headers: &HeaderMap) -> Option<&str> {
    if let Some(proto) = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
    {
        return Some(proto.trim());
    }

    headers
        .get("forwarded")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(';')
                .find_map(|part| part.trim().strip_prefix("proto="))
        })
        .map(|value| value.trim_matches('"'))
}

fn encrypted_size_limit(plain_limit: u64) -> u64 {
    // The Node implementation applies the limiter to encrypted bytes. The exact
    // archive/encryption overhead belongs to the client; this server-side cap
    // gives a small allowance while preserving the observable 413 behavior.
    plain_limit.saturating_add(1024 * 1024)
}
