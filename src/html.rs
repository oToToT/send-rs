use crate::Config;

pub fn layout(
    config: &Config,
    title: &str,
    body: &str,
    robots: &str,
    download_metadata: &serde_json::Value,
) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="{robots}">
  <title>{title}</title>
  <meta name="description" content="{description}">
  <base href="/">
  <link rel="icon" href="/favicon-32x32.png" type="image/png" sizes="32x32">
  <link rel="manifest" href="/app.webmanifest">
  <link rel="stylesheet" href="/inter.css">
  <link rel="stylesheet" href="/app.css">
  <link rel="stylesheet" href="/ui.css">
  <script>
    (function () {{
      var preference = 'system';
      try {{ preference = localStorage.getItem('send-theme') || 'system'; }} catch (_) {{}}
      var dark = preference === 'dark' ||
        (preference === 'system' && matchMedia('(prefers-color-scheme: dark)').matches);
      document.documentElement.dataset.theme = dark ? 'dark' : 'light';
      document.documentElement.dataset.themePreference = preference;
    }})();
  </script>
  <style>
    :root {{ --color-primary: {primary}; --color-primary-accent: {accent}; }}
  </style>
  <script>
    var LIMITS={limits};
    var WEB_UI={web_ui};
    var DEFAULTS={defaults};
    var PREFS={{}};
    var downloadMetadata={download_metadata};
  </script>
  <script defer src="/theme.js"></script>

</head>
<body>
  <header class="site-header">
    <a class="site-brand" href="/" aria-label="{brand_attr} home">
      <span class="site-brand-mark" aria-hidden="true">
        <svg viewBox="0 0 24 24"><path d="M12 3v12m0 0 4-4m-4 4-4-4M5 15v4h14v-4"/></svg>
      </span>
      <strong>{brand}</strong>
    </a>
  </header>
  {body}
  <footer class="site-footer">
    <span>Private file sharing, made simple.</span>
    <nav aria-label="Footer links">
    <a href="{cli}">Command Line Tool</a>
    <a href="{source}">Source Code</a>
    </nav>
  </footer>
</body>
</html>"#,
        description = escape_attr(&config.web_ui.custom_description),
        primary = config.web_ui.ui_color_primary,
        accent = config.web_ui.ui_color_accent,
        limits = js_json(&config.limits),
        web_ui = js_json(&config.web_ui),
        defaults = js_json(&config.defaults),
        download_metadata = js_json(download_metadata),
        brand = escape_html(&config.web_ui.custom_title),
        brand_attr = escape_attr(&config.web_ui.custom_title),
        cli = escape_attr(&config.web_ui.footer_cli_url),
        source = escape_attr(&config.web_ui.footer_source_url),
    )
}

pub fn home(config: &Config) -> String {
    let body = format!(
        r#"<main class="fallback-main">
  <section class="fallback-hero">
    <span class="eyebrow">Private by design</span>
    <h1>{title}</h1>
    <p>{description}</p>
    {notice}
    <ul class="trust-list" aria-label="Service benefits">
      <li>Encrypted in your browser</li>
      <li>Links expire automatically</li>
    </ul>
  </section>
  <section class="upload-zone" aria-labelledby="upload-heading">
    <div class="section-heading">
      <div><h2 id="upload-heading">Choose files</h2><p>Select files from your device to create a secure link.</p></div>
    </div>
    {upload_notice}
    <p class="file-limit-info">Max file size: {max_file_size}</p>
    <input id="autocomplete-decoy" type="password" hidden autocomplete="off">
    <div class="file-picker">
      <strong>Drop files here</strong><span>or use the file chooser</span>
      <input class="file-picker-input" id="file-upload" name="file-upload" type="file" multiple aria-describedby="file-selection-status">
    </div>
    <ul id="file-list" class="file-list" hidden></ul>
    <p id="file-selection-status" class="file-selection-status" role="status" aria-live="polite">No files selected</p>
    <div class="password-row">
      <label><input id="add-password" name="add-password" type="checkbox"> Protect with password</label>
      <div class="input-action" hidden><input id="password-input" name="password" type="password" autocomplete="new-password" aria-label="Password"><button id="password-preview-button" type="button" aria-label="Show password" aria-pressed="false">Show</button></div>
    </div>
    <div class="option-grid">
      <label for="dlCount">Download limit<select id="dlCount" name="dlimit">{download_options}</select></label>
      <label for="timespan">Link expires<select id="timespan" name="timeLimit">{expire_options}</select></label>
    </div>
    <button id="upload-btn" type="button" disabled>Create secure link</button>
  </section>
  <section class="uploads-panel" aria-labelledby="uploads-heading">
    <h2 id="uploads-heading">Your uploads</h2>
    {uploads_notice}
  </section>
</main>
<script defer src="/upload.js"></script>"#,
        title = escape_html(&config.web_ui.custom_title),
        description = escape_html(&config.web_ui.custom_description),
        notice = config.web_ui.main_notice_html,
        upload_notice = config.web_ui.upload_area_notice_html,
        uploads_notice = config.web_ui.uploads_list_notice_html,
        max_file_size = format_file_size(config.limits.max_file_size),
        download_options = config
            .defaults
            .download_counts
            .iter()
            .map(|count| format!(r#"<option value="{count}">{count}</option>"#))
            .collect::<String>(),
        expire_options = config
            .defaults
            .expire_times_seconds
            .iter()
            .map(|seconds| format!(
                r#"<option value="{seconds}">{}</option>"#,
                format_duration(*seconds)
            ))
            .collect::<String>(),
    );
    layout(
        config,
        &config.web_ui.custom_title,
        &body,
        "all,noarchive",
        &serde_json::json!({}),
    )
}

pub fn download(config: &Config, id: &str, nonce: &str, pwd: bool) -> String {
    let body = format!(
        r#"<main class="download-main">
  <section class="download-panel" data-file-id="{id}">
    <div class="download-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 3v12m0 0 4-4m-4 4-4-4M5 15v4h14v-4"/></svg></div>
    <span class="eyebrow">Secure transfer</span>
    <h1>Preparing your download</h1>
    {notice}
    <p class="download-description">This file was shared privately with Send.</p>
    <form id="password-form" {password_hidden}>
      <input id="autocomplete-decoy" type="password" hidden autocomplete="off">
      <label for="password-input">Password</label>
      <input id="password-input" name="password" type="password" autocomplete="current-password">
      <button id="password-btn" type="submit">Unlock</button>
      <label id="password-error" hidden>Incorrect password</label>
    </form>
    <button id="download-btn" type="button" hidden>Download file</button>
    <p id="download-status" class="download-status" role="status" aria-live="polite"></p>
    <input id="share-url" name="share-url" type="text" readonly value="" hidden>
    <button id="qr-btn" type="button" hidden>QR code</button>
  </section>
</main>
<script defer src="/download.js"></script>"#,
        id = escape_attr(id),
        notice = config.web_ui.download_notice_html,
        password_hidden = if pwd { "" } else { "hidden" },
    );
    layout(
        config,
        "Download - Send",
        &body,
        "none,noarchive",
        &serde_json::json!({ "nonce": nonce, "pwd": pwd }),
    )
}

pub fn unsupported(config: &Config, reason: &str) -> String {
    let message = match reason {
        "crypto" => "Your browser does not support the Web Crypto API required by Send.",
        "ie" => "Internet Explorer is not supported.",
        "outdated" => "Your browser is out of date.",
        _ => "Your browser is not supported.",
    };
    let body = format!(
        r#"<main><h1>Browser not supported</h1><p>{}</p><a href="/">Send your files</a></main>"#,
        escape_html(message)
    );
    layout(
        config,
        "Unsupported Browser - Send",
        &body,
        "none,noarchive",
        &serde_json::json!({}),
    )
}

pub fn error(config: &Config) -> String {
    let body = r#"<main><h1>Something went wrong</h1><a href="/">Send your files</a></main>"#;
    layout(
        config,
        "Error - Send",
        body,
        "none,noarchive",
        &serde_json::json!({}),
    )
}

pub fn not_found(config: &Config) -> String {
    let body = r#"<main class="status-main">
  <section class="status-panel" aria-labelledby="status-heading">
    <div class="status-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2M18.5 18.5l3 3m0-3-3 3"/></svg>
    </div>
    <span class="eyebrow">Link unavailable</span>
    <h1 id="status-heading">Link expired</h1>
    <p class="status-description">This link has expired or never existed.</p>
    <p class="status-note">For your privacy, expired files are permanently removed and cannot be recovered.</p>
    <a class="status-action" href="/">
      <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 16V4m0 0L8 8m4-4 4 4M5 14v5h14v-5"/></svg>
      <span>Send your files</span>
    </a>
  </section>
</main>"#;
    layout(
        config,
        "Link expired - Send",
        body,
        "none,noarchive",
        &serde_json::json!({ "status": 404 }),
    )
}

fn js_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "{}".into())
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_attr(input: &str) -> String {
    escape_html(input).replace('"', "&quot;")
}

fn format_duration(seconds: u64) -> String {
    match seconds {
        0..=59 => format!("{seconds} seconds"),
        60..=3599 => {
            let minutes = seconds / 60;
            if minutes == 1 {
                "1 minute".into()
            } else {
                format!("{minutes} minutes")
            }
        }
        3600..=86399 => {
            let hours = seconds / 3600;
            if hours == 1 {
                "1 hour".into()
            } else {
                format!("{hours} hours")
            }
        }
        _ => {
            let days = seconds / 86400;
            if days == 1 {
                "1 day".into()
            } else {
                format!("{days} days")
            }
        }
    }
}

fn format_file_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{bytes} {}", UNITS[unit_idx])
    } else {
        format!("{:.1} {}", size, UNITS[unit_idx])
    }
}
