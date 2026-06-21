use std::sync::OnceLock;

use minijinja::{Environment, UndefinedBehavior};
use serde_json::{Value, json};

use crate::Config;

const TEMPLATE_SOURCES: &[(&str, &str)] = &[
    (
        "layout.html",
        include_str!("../static/templates/layout.html"),
    ),
    ("home.html", include_str!("../static/templates/home.html")),
    (
        "download.html",
        include_str!("../static/templates/download.html"),
    ),
    (
        "unsupported.html",
        include_str!("../static/templates/unsupported.html"),
    ),
    ("error.html", include_str!("../static/templates/error.html")),
    (
        "not-found.html",
        include_str!("../static/templates/not-found.html"),
    ),
];

pub fn home(config: &Config) -> String {
    let expire_options = config
        .defaults
        .expire_times_seconds
        .iter()
        .map(|seconds| (*seconds, format_duration(*seconds)))
        .collect::<Vec<_>>();
    render_page(
        config,
        "home.html",
        &config.web_ui.custom_title,
        "all,noarchive",
        &json!({}),
        json!({
            "main_notice": config.web_ui.main_notice_html,
            "upload_notice": config.web_ui.upload_area_notice_html,
            "uploads_notice": config.web_ui.uploads_list_notice_html,
            "max_file_size": format_file_size(config.limits.max_file_size),
            "download_counts": config.defaults.download_counts,
            "expire_options": expire_options,
        }),
    )
}

pub fn download(config: &Config, id: &str, nonce: &str, pwd: bool) -> String {
    render_page(
        config,
        "download.html",
        "Download - Send",
        "none,noarchive",
        &json!({ "nonce": nonce, "pwd": pwd }),
        json!({
            "file_id": id,
            "download_notice": config.web_ui.download_notice_html,
            "password_required": pwd,
        }),
    )
}

pub fn unsupported(config: &Config, reason: &str) -> String {
    let message = match reason {
        "crypto" => "Your browser does not support the Web Crypto API required by Send.",
        "ie" => "Internet Explorer is not supported.",
        "outdated" => "Your browser is out of date.",
        _ => "Your browser is not supported.",
    };
    render_page(
        config,
        "unsupported.html",
        "Unsupported Browser - Send",
        "none,noarchive",
        &json!({}),
        json!({ "message": message }),
    )
}

pub fn error(config: &Config) -> String {
    render_page(
        config,
        "error.html",
        "Error - Send",
        "none,noarchive",
        &json!({}),
        json!({}),
    )
}

pub fn not_found(config: &Config) -> String {
    render_page(
        config,
        "not-found.html",
        "Link expired - Send",
        "none,noarchive",
        &json!({ "status": 404 }),
        json!({}),
    )
}

fn render_page(
    config: &Config,
    template_name: &str,
    title: &str,
    robots: &str,
    download_metadata: &Value,
    extra: Value,
) -> String {
    let mut context = json!({
        "title": title,
        "robots": robots,
        "description": config.web_ui.custom_description,
        "primary": config.web_ui.ui_color_primary,
        "accent": config.web_ui.ui_color_accent,
        "limits_json": js_json(&config.limits),
        "web_ui_json": js_json(&config.web_ui),
        "defaults_json": js_json(&config.defaults),
        "download_metadata_json": js_json(download_metadata),
        "brand": config.web_ui.custom_title,
        "cli_url": config.web_ui.footer_cli_url,
        "source_url": config.web_ui.footer_source_url,
    });
    context
        .as_object_mut()
        .expect("page context is an object")
        .extend(
            extra
                .as_object()
                .expect("extra page context is an object")
                .clone(),
        );

    templates()
        .get_template(template_name)
        .and_then(|template| template.render(context))
        .unwrap_or_else(|error| panic!("failed to render {template_name}: {error:#}"))
}

fn templates() -> &'static Environment<'static> {
    static ENVIRONMENT: OnceLock<Environment<'static>> = OnceLock::new();
    ENVIRONMENT.get_or_init(|| {
        let mut environment = Environment::new();
        environment.set_undefined_behavior(UndefinedBehavior::Strict);
        for &(name, source) in TEMPLATE_SOURCES {
            environment
                .add_template(name, source)
                .unwrap_or_else(|error| panic!("invalid embedded template {name}: {error:#}"));
        }
        environment
    })
}

fn js_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "{}".into())
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

fn format_duration(seconds: u64) -> String {
    match seconds {
        0..=59 => format!("{seconds} seconds"),
        60..=3599 => plural(seconds / 60, "minute"),
        3600..=86399 => plural(seconds / 3600, "hour"),
        _ => plural(seconds / 86400, "day"),
    }
}

fn plural(value: u64, unit: &str) -> String {
    if value == 1 {
        format!("1 {unit}")
    } else {
        format!("{value} {unit}s")
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
        format!("{size:.1} {}", UNITS[unit_idx])
    }
}

#[cfg(test)]
mod tests {
    use super::templates;

    #[test]
    fn all_embedded_templates_compile() {
        for name in [
            "layout.html",
            "home.html",
            "download.html",
            "unsupported.html",
            "error.html",
            "not-found.html",
        ] {
            templates().get_template(name).unwrap();
        }
    }
}
