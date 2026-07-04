use std::{net::IpAddr, time::Duration};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use send_rs::{AppState, Config, app};
use serde_json::{Value, json};
use sha2::Sha256;
use tokio_tungstenite::tungstenite::Message;
use tower::ServiceExt;

type HmacSha256 = Hmac<Sha256>;

fn test_config(dir: std::path::PathBuf) -> Config {
    Config {
        listen_address: "127.0.0.1".parse::<IpAddr>().unwrap(),
        listen_port: 0,
        base_url: "https://send.example.test".into(),
        detect_base_url: false,
        scheme: send_rs::config::Scheme::Auto,
        file_dir: dir,
        node_env: "test".into(),
        limits: send_rs::config::Limits {
            max_file_size: 1024,
            max_downloads: 5,
            max_expire_seconds: 60,
            max_files_per_archive: 64,
            max_archives_per_user: 16,
        },
        defaults: send_rs::config::Defaults {
            download_counts: vec![1, 2, 5],
            expire_times_seconds: vec![30, 60],
            default_downloads: 1,
            default_expire_seconds: 60,
        },
        web_ui: send_rs::config::WebUi {
            footer_donate_url: String::new(),
            footer_cli_url: "https://github.com/timvisee/ffsend".into(),
            footer_dmca_url: String::new(),
            footer_source_url: "https://github.com/timvisee/send".into(),
            custom_footer_text: String::new(),
            custom_footer_url: String::new(),
            main_notice_html: String::new(),
            upload_area_notice_html: String::new(),
            uploads_list_notice_html: String::new(),
            download_notice_html: String::new(),
            show_thunderbird_sponsor: false,
            colors: send_rs::config::UiColors {
                primary: "#0a84ff".into(),
                accent: "#003eaa".into(),
            },
            custom_assets: send_rs::config::CustomAssets::default(),
            ui_color_primary: "#0a84ff".into(),
            ui_color_accent: "#003eaa".into(),
            custom_title: "Send".into(),
            custom_description: "Encrypt and send files with expiring links.".into(),
        },
    }
}

async fn test_state() -> (tempfile::TempDir, AppState) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::new(test_config(dir.path().to_path_buf()))
        .await
        .unwrap();
    (dir, state)
}

async fn body_text(response: axum::response::Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn body_json(response: axum::response::Response) -> Value {
    serde_json::from_str(&body_text(response).await).unwrap()
}

fn auth_header(auth_key_b64: &str, nonce_b64: &str) -> String {
    let key = URL_SAFE_NO_PAD
        .decode(auth_key_b64)
        .or_else(|_| STANDARD.decode(auth_key_b64))
        .unwrap();
    let nonce = STANDARD.decode(nonce_b64).unwrap();
    let mut mac = HmacSha256::new_from_slice(&key).unwrap();
    mac.update(&nonce);
    format!(
        "send-v1 {}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

async fn create_file(state: &AppState, id: &str, dlimit: u32) -> (String, String) {
    let owner = "1234567890abcdef1234".to_string();
    let auth_key = URL_SAFE_NO_PAD.encode([0xfb_u8; 32]);
    state
        .store
        .create(send_rs::storage::NewFile {
            id: id.to_string(),
            owner: owner.clone(),
            metadata: "encrypted-metadata".into(),
            dlimit,
            auth: auth_key.clone(),
            ttl: Duration::from_secs(60),
            bytes: b"encrypted file bytes".to_vec(),
        })
        .await
        .unwrap();
    (owner, auth_key)
}

#[tokio::test]
async fn config_and_html_pages_expose_semantic_contract() {
    let (_dir, state) = test_state().await;
    let router = app(state);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["LIMITS"]["MAX_FILE_SIZE"], 1024);
    assert_eq!(body["DEFAULTS"]["DOWNLOADS"], 1);
    assert!(
        body["WEB_UI"]["FOOTER_CLI_URL"]
            .as_str()
            .unwrap()
            .contains("ffsend")
    );

    let response = router
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("content-security-policy"));
    assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
    let body = body_text(response).await;
    assert!(body.contains(r#"id="file-upload""#));
    assert!(body.contains(r#"<div class="file-picker">"#));
    assert!(body.contains(r#"class="file-picker-input""#));
    assert!(body.contains(r#"id="upload-btn""#));
    assert!(body.contains(r#"id="add-password""#));
    assert!(body.contains("var LIMITS="));
    assert!(body.contains(r#"href="/favicon-32x32.png""#));
    assert!(body.contains(r#"<link rel="stylesheet" href="/ui.css">"#));
    assert!(body.contains(r#"<script defer src="/theme.js"></script>"#));
    assert!(body.contains(r#"<script defer src="/send-crypto.js"></script>"#));
    assert!(body.contains(r#"<script defer src="/upload.js"></script>"#));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/download/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = body_text(response).await;
    assert!(body.contains(r#"class="status-panel""#));
    assert!(body.contains(r#"class="status-action" href="/""#));
    assert!(body.contains("expired files are permanently removed"));

    let upload_script = std::fs::read_to_string("static/upload.js").unwrap();
    assert!(!upload_script.contains("fileInput.click()"));
    let crypto_script = std::fs::read_to_string("static/send-crypto.js").unwrap();
    assert!(crypto_script.contains("Content-Encoding: aes128gcm"));
    assert!(crypto_script.contains("info: encoder.encode('authentication')"));
    assert!(crypto_script.contains("info: encoder.encode('metadata')"));
    assert!(!crypto_script.contains("send-encryption"));
    assert!(!crypto_script.contains("AES-GCM', length: 256"));
    assert!(upload_script.contains("deriveAuthenticationBytes(secretKey)"));
    let download_script = std::fs::read_to_string("static/download.js").unwrap();
    assert!(download_script.contains("decryptFile(secretKey"));
    let theme_script = std::fs::read_to_string("static/theme.js").unwrap();
    assert!(!theme_script.contains("file-upload"));
    assert!(!theme_script.contains("installFallbackInteractions"));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/__version__")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(response).await["version"], "3.4.27");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/theme.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("javascript")
    );
    let body = body_text(response).await;
    assert!(body.contains("prefers-color-scheme: dark"));
    assert!(body.contains("send-theme"));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/templates/layout.html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("text/css")
    );

    assert!(!std::path::Path::new("static/android.html").exists());
    assert!(!std::path::Path::new("static/master-logo.svg").exists());
    assert!(
        std::fs::read_dir("static")
            .expect("static directory")
            .filter_map(Result::ok)
            .all(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                !name.ends_with(".map") && !name.starts_with(|c: char| c.is_ascii_digit())
            }),
        "generated numbered chunks or source maps must not be committed"
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/app.webmanifest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let manifest = body_json(response).await;
    for icon in manifest["icons"].as_array().expect("webmanifest icons") {
        let relative = icon["src"]
            .as_str()
            .expect("webmanifest icon path")
            .trim_start_matches('/');
        assert!(
            std::path::Path::new("static").join(relative).is_file(),
            "webmanifest icon is missing: {relative}"
        );
    }
}

#[tokio::test]
async fn configured_notice_html_is_sanitized() {
    let (_dir, mut state) = test_state().await;
    std::sync::Arc::make_mut(&mut state.config).web_ui.main_notice_html =
        r#"<script>alert(1)</script><strong>Safe</strong><a href="javascript:alert(1)" onclick="alert(2)">link</a>"#
            .into();
    let response = app(state)
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(body.contains("<strong>Safe</strong>"));
    assert!(body.contains(">link</a>"));
    assert!(!body.contains("alert(1)"));
    assert!(!body.contains("javascript:"));
    assert!(!body.contains("onclick"));
}

#[tokio::test]
async fn exists_metadata_download_and_final_delete_match_contract() {
    let (_dir, state) = test_state().await;
    let id = "abcdef1234567890";
    let (_owner, auth_key) = create_file(&state, id, 1).await;
    let router = app(state);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/exists/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let nonce = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("send-v1 ")
        .unwrap()
        .to_string();
    let body = body_json(response).await;
    assert_eq!(body, json!({ "requiresPassword": false }));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/download/{id}/"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/metadata/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap(),
        format!("send-v1 {nonce}")
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/metadata/{id}"))
                .header(header::AUTHORIZATION, auth_header(&auth_key, &nonce))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let next_nonce = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("send-v1 ")
        .unwrap()
        .to_string();
    assert_ne!(next_nonce, nonce);
    let body = body_json(response).await;
    assert_eq!(body["metadata"], "encrypted-metadata");
    assert_eq!(body["finalDownload"], true);
    assert!(body["ttl"].as_u64().unwrap() > 0);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/download/blob/{id}"))
                .header(header::AUTHORIZATION, auth_header(&auth_key, &next_nonce))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/octet-stream"
    );
    assert_eq!(body_text(response).await, "encrypted file bytes");

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/exists/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn legacy_password_auth_key_remains_compatible() {
    let (_dir, state) = test_state().await;
    let id = "aaaaaa1234567890";
    let (_owner, auth_key) = create_file(&state, id, 2).await;
    state
        .store
        .set_password(id, auth_key.clone())
        .await
        .unwrap();
    let router = app(state);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/exists/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let nonce = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("send-v1 ")
        .unwrap()
        .to_string();
    let body = body_json(response).await;
    assert_eq!(body["requiresPassword"], true);
    assert!(body.get("passwordKdf").is_none());

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/metadata/{id}"))
                .header(header::AUTHORIZATION, auth_header(&auth_key, &nonce))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn repeated_failed_password_auth_is_rate_limited() {
    let (_dir, state) = test_state().await;
    let id = "ababab1234567890";
    create_file(&state, id, 2).await;
    state
        .store
        .set_password(id, URL_SAFE_NO_PAD.encode([0xee_u8; 32]))
        .await
        .unwrap();
    let router = app(state);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/exists/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let nonce = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("send-v1 ")
        .unwrap()
        .to_string();
    let wrong_auth = auth_header(&URL_SAFE_NO_PAD.encode([0xdd_u8; 32]), &nonce);

    for _ in 0..6 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/metadata/{id}"))
                    .header(header::AUTHORIZATION, &wrong_auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/metadata/{id}"))
                .header(header::AUTHORIZATION, &wrong_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key(header::RETRY_AFTER));
}

#[tokio::test]
async fn owner_operations_require_owner_token() {
    let (_dir, state) = test_state().await;
    let id = "bbbbbb1234567890";
    let (owner, _auth_key) = create_file(&state, id, 3).await;
    let router = app(state);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/info/{id}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "owner_token": "wrong" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/params/{id}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "owner_token": owner, "download_limit": 2 }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/password/{id}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "owner_token": "1234567890abcdef1234",
                        "auth": STANDARD.encode(b"new-password-auth-key")
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/delete/{id}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "owner_token": "1234567890abcdef1234" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn websocket_upload_creates_downloadable_file() {
    let (_dir, mut state) = test_state().await;
    std::sync::Arc::make_mut(&mut state.config).detect_base_url = true;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = state.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app(server_state)).await.unwrap();
    });

    let (mut socket, _response) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/ws"))
        .await
        .unwrap();

    let auth_key = STANDARD.encode(b"01234567890123456789012345678901");
    socket
        .send(Message::Text(
            json!({
                "fileMetadata": "metadata-from-ws",
                "authorization": format!("send-v1 {auth_key}"),
                "timeLimit": 60,
                "dlimit": 2
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

    let first = socket.next().await.unwrap().unwrap().into_text().unwrap();
    let first: Value = serde_json::from_str(&first).unwrap();
    let id = first["id"].as_str().unwrap().to_string();
    assert!(first["ownerToken"].as_str().unwrap().len() >= 20);
    assert_eq!(
        first["url"].as_str().unwrap(),
        format!("http://{addr}/download/{id}/")
    );

    socket
        .send(Message::Binary(
            "uploaded encrypted bytes".as_bytes().into(),
        ))
        .await
        .unwrap();
    socket.send(Message::Binary(vec![0].into())).await.unwrap();

    let second = socket.next().await.unwrap().unwrap().into_text().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&second).unwrap(),
        json!({ "ok": true })
    );

    let response = app(state)
        .oneshot(
            Request::builder()
                .uri(format!("/api/exists/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        body_text(response)
            .await
            .contains(r#""requiresPassword":false"#)
    );

    server.abort();
}

#[tokio::test]
async fn metadata_and_blob_survive_process_restart() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(dir.path().to_path_buf());
    let first_state = AppState::new(config.clone()).await.unwrap();
    let id = "cccccc1234567890";
    create_file(&first_state, id, 2).await;
    drop(first_state);

    let restarted = AppState::new(config).await.unwrap();
    let record = restarted.store.get(id).await.unwrap();
    assert_eq!(record.metadata, "encrypted-metadata");
    assert_eq!(
        restarted.store.read_blob(id).await.unwrap(),
        b"encrypted file bytes"
    );
}

#[tokio::test]
async fn storage_is_private_transactional_and_single_writer() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(dir.path().to_path_buf());
    let state = AppState::new(config.clone()).await.unwrap();
    let id = "dddddd1234567890";
    let (owner, _) = create_file(&state, id, 1).await;

    assert!(dir.path().join("metadata.sqlite3").is_file());
    assert!(!dir.path().join("records").exists());
    assert!(AppState::new(config.clone()).await.is_err());

    let database = std::fs::read(dir.path().join("metadata.sqlite3")).unwrap();
    assert!(
        !database
            .windows(owner.len())
            .any(|bytes| bytes == owner.as_bytes()),
        "owner tokens must not be stored verbatim"
    );

    drop(state);
    let restarted = AppState::new(config).await.unwrap();
    assert!(restarted.store.verify_owner(id, &owner).await.is_ok());
}

#[tokio::test]
async fn final_download_claim_is_atomic() {
    let (_dir, state) = test_state().await;
    let id = "eeeeee1234567890";
    create_file(&state, id, 1).await;

    let first = {
        let store = state.store.clone();
        tokio::spawn(async move { store.claim_download(id).await })
    };
    let second = {
        let store = state.store.clone();
        tokio::spawn(async move { store.claim_download(id).await })
    };
    let results = [first.await.unwrap(), second.await.unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(state.store.get(id).await.is_none());
}

#[tokio::test]
async fn startup_reconciliation_removes_incomplete_uploads() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(dir.path().to_path_buf());
    let state = AppState::new(config.clone()).await.unwrap();
    let mut upload = state.store.start_upload("ffffff1234567890").await.unwrap();
    upload.write(b"partial encrypted upload").await.unwrap();
    drop(upload);
    drop(state);

    let restarted = AppState::new(config).await.unwrap();
    assert_eq!(
        std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
        0
    );
    drop(restarted);
}

#[tokio::test]
async fn legacy_layout_is_rejected_without_deleting_it() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("records")).unwrap();
    std::fs::create_dir_all(dir.path().join("files")).unwrap();
    let legacy_blob = dir.path().join("files/abcdef1234567890");
    std::fs::write(&legacy_blob, b"legacy encrypted bytes").unwrap();

    let result = AppState::new(test_config(dir.path().to_path_buf())).await;
    assert!(result.is_err());
    assert_eq!(
        std::fs::read(legacy_blob).unwrap(),
        b"legacy encrypted bytes"
    );
}
