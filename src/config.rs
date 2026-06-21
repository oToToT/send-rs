use std::{env, net::IpAddr, path::PathBuf, time::Duration};

use serde::Serialize;

use crate::{AppError, AppResult};

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_address: IpAddr,
    pub listen_port: u16,
    pub base_url: String,
    pub detect_base_url: bool,
    pub file_dir: PathBuf,
    pub node_env: String,
    pub limits: Limits,
    pub defaults: Defaults,
    pub web_ui: WebUi,
}

#[derive(Clone, Debug, Serialize)]
pub struct Limits {
    #[serde(rename = "MAX_FILE_SIZE")]
    pub max_file_size: u64,
    #[serde(rename = "MAX_DOWNLOADS")]
    pub max_downloads: u32,
    #[serde(rename = "MAX_EXPIRE_SECONDS")]
    pub max_expire_seconds: u64,
    #[serde(rename = "MAX_FILES_PER_ARCHIVE")]
    pub max_files_per_archive: u32,
    #[serde(rename = "MAX_ARCHIVES_PER_USER")]
    pub max_archives_per_user: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct Defaults {
    #[serde(rename = "DOWNLOAD_COUNTS")]
    pub download_counts: Vec<u32>,
    #[serde(rename = "EXPIRE_TIMES_SECONDS")]
    pub expire_times_seconds: Vec<u64>,
    #[serde(rename = "DOWNLOADS")]
    pub default_downloads: u32,
    #[serde(rename = "EXPIRE_SECONDS")]
    pub default_expire_seconds: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct WebUi {
    #[serde(rename = "FOOTER_DONATE_URL")]
    pub footer_donate_url: String,
    #[serde(rename = "FOOTER_CLI_URL")]
    pub footer_cli_url: String,
    #[serde(rename = "FOOTER_DMCA_URL")]
    pub footer_dmca_url: String,
    #[serde(rename = "FOOTER_SOURCE_URL")]
    pub footer_source_url: String,
    #[serde(rename = "CUSTOM_FOOTER_TEXT")]
    pub custom_footer_text: String,
    #[serde(rename = "CUSTOM_FOOTER_URL")]
    pub custom_footer_url: String,
    #[serde(rename = "MAIN_NOTICE_HTML")]
    pub main_notice_html: String,
    #[serde(rename = "UPLOAD_AREA_NOTICE_HTML")]
    pub upload_area_notice_html: String,
    #[serde(rename = "UPLOADS_LIST_NOTICE_HTML")]
    pub uploads_list_notice_html: String,
    #[serde(rename = "DOWNLOAD_NOTICE_HTML")]
    pub download_notice_html: String,
    #[serde(rename = "SHOW_THUNDERBIRD_SPONSOR")]
    pub show_thunderbird_sponsor: bool,
    #[serde(rename = "COLORS")]
    pub colors: UiColors,
    #[serde(rename = "CUSTOM_ASSETS")]
    pub custom_assets: CustomAssets,
    #[serde(skip_serializing)]
    pub ui_color_primary: String,
    #[serde(skip_serializing)]
    pub ui_color_accent: String,
    #[serde(skip_serializing)]
    pub custom_title: String,
    #[serde(skip_serializing)]
    pub custom_description: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct UiColors {
    #[serde(rename = "PRIMARY")]
    pub primary: String,
    #[serde(rename = "ACCENT")]
    pub accent: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CustomAssets {
    pub android_chrome_192px: String,
    pub android_chrome_512px: String,
    pub apple_touch_icon: String,
    pub favicon_16px: String,
    pub favicon_32px: String,
    pub icon: String,
    pub safari_pinned_tab: String,
    pub facebook: String,
    pub twitter: String,
    pub wordmark: String,
    pub custom_css: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClientConfig {
    #[serde(rename = "LIMITS")]
    pub limits: Limits,
    #[serde(rename = "WEB_UI")]
    pub web_ui: WebUi,
    #[serde(rename = "DEFAULTS")]
    pub defaults: Defaults,
}

impl Config {
    pub fn from_env() -> AppResult<Self> {
        let listen_address = get("IP_ADDRESS", "0.0.0.0")
            .parse()
            .map_err(|err| AppError::Config(format!("IP_ADDRESS must be an IP address: {err}")))?;
        let listen_port = parse("PORT", 1443)?;
        let base_url = get("BASE_URL", "http://localhost:1443");
        if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
            return Err(AppError::Config(
                "BASE_URL must start with http:// or https://".into(),
            ));
        }
        // Request-based detection makes the zero-configuration development server
        // return links that point back to the server the user actually opened.
        // Deployments with a canonical public URL can disable this and set BASE_URL.
        let detect_base_url = parse_bool("DETECT_BASE_URL", true)?;
        let file_dir = env::var("FILE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data"));
        let node_env = get("NODE_ENV", "development");

        let limits = Limits {
            max_file_size: parse("MAX_FILE_SIZE", 2_684_354_560_u64)?,
            max_downloads: parse("MAX_DOWNLOADS", 100)?,
            max_expire_seconds: parse("MAX_EXPIRE_SECONDS", 604_800)?,
            max_files_per_archive: parse("MAX_FILES_PER_ARCHIVE", 64)?,
            max_archives_per_user: parse("MAX_ARCHIVES_PER_USER", 16)?,
        };
        let defaults = Defaults {
            download_counts: parse_csv("DOWNLOAD_COUNTS", "1,2,3,4,5,20,50,100")?,
            expire_times_seconds: parse_csv("EXPIRE_TIMES_SECONDS", "300,3600,86400,604800")?,
            default_downloads: parse("DEFAULT_DOWNLOADS", 1)?,
            default_expire_seconds: parse("DEFAULT_EXPIRE_SECONDS", 86_400)?,
        };
        validate_limits(&limits, &defaults)?;

        let ui_color_primary = get("UI_COLOR_PRIMARY", "#0a84ff");
        let ui_color_accent = get("UI_COLOR_ACCENT", "#003eaa");
        let web_ui = WebUi {
            footer_donate_url: get("SEND_FOOTER_DONATE_URL", ""),
            footer_cli_url: get("SEND_FOOTER_CLI_URL", "https://github.com/timvisee/ffsend"),
            footer_dmca_url: get("SEND_FOOTER_DMCA_URL", ""),
            footer_source_url: get("SEND_FOOTER_SOURCE_URL", "https://github.com/timvisee/send"),
            custom_footer_text: get("CUSTOM_FOOTER_TEXT", ""),
            custom_footer_url: get("CUSTOM_FOOTER_URL", ""),
            main_notice_html: get("SEND_MAIN_NOTICE_HTML", ""),
            upload_area_notice_html: get("SEND_UPLOAD_AREA_NOTICE_HTML", ""),
            uploads_list_notice_html: get("SEND_UPLOADS_LIST_NOTICE_HTML", ""),
            download_notice_html: get("SEND_DOWNLOAD_NOTICE_HTML", ""),
            show_thunderbird_sponsor: false,
            colors: UiColors {
                primary: ui_color_primary.clone(),
                accent: ui_color_accent.clone(),
            },
            custom_assets: CustomAssets {
                android_chrome_192px: "/icon.svg".into(),
                android_chrome_512px: "/icon.svg".into(),
                apple_touch_icon: "/icon.svg".into(),
                favicon_16px: "/icon.svg".into(),
                favicon_32px: "/favicon-32x32.png".into(),
                icon: "/icon.svg".into(),
                safari_pinned_tab: "/icon.svg".into(),
                facebook: String::new(),
                twitter: String::new(),
                wordmark: "/wordmark.svg#logo".into(),
                custom_css: String::new(),
            },
            ui_color_primary,
            ui_color_accent,
            custom_title: get("CUSTOM_TITLE", "Send"),
            custom_description: get(
                "CUSTOM_DESCRIPTION",
                "Encrypt and send files with a link that automatically expires to ensure your important documents don't stay online forever.",
            ),
        };

        Ok(Self {
            listen_address,
            listen_port,
            base_url,
            detect_base_url,
            file_dir,
            node_env,
            limits,
            defaults,
            web_ui,
        })
    }

    pub fn client_config(&self) -> ClientConfig {
        ClientConfig {
            limits: self.limits.clone(),
            web_ui: self.web_ui.clone(),
            defaults: self.defaults.clone(),
        }
    }

    pub fn default_ttl(&self) -> Duration {
        Duration::from_secs(self.defaults.default_expire_seconds)
    }

    pub fn base_url_for_headers(&self, host: Option<&str>, is_https: bool) -> String {
        if self.detect_base_url {
            let scheme = if is_https { "https" } else { "http" };
            format!("{scheme}://{}", host.unwrap_or("localhost"))
        } else {
            self.base_url.clone()
        }
    }
}

fn validate_limits(limits: &Limits, defaults: &Defaults) -> AppResult<()> {
    if defaults.default_downloads == 0 || defaults.default_downloads > limits.max_downloads {
        return Err(AppError::Config(
            "DEFAULT_DOWNLOADS must be between 1 and MAX_DOWNLOADS".into(),
        ));
    }
    if defaults.default_expire_seconds == 0
        || defaults.default_expire_seconds > limits.max_expire_seconds
    {
        return Err(AppError::Config(
            "DEFAULT_EXPIRE_SECONDS must be between 1 and MAX_EXPIRE_SECONDS".into(),
        ));
    }
    Ok(())
}

fn get(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn parse<T>(key: &str, default: T) -> AppResult<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(key) {
        Ok(value) => value
            .parse()
            .map_err(|err| AppError::Config(format!("{key} is invalid: {err}"))),
        Err(_) => Ok(default),
    }
}

fn parse_bool(key: &str, default: bool) -> AppResult<bool> {
    match env::var(key) {
        Ok(value) => match value.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err(AppError::Config(format!("{key} must be a boolean"))),
        },
        Err(_) => Ok(default),
    }
}

fn parse_csv<T>(key: &str, default: &str) -> AppResult<Vec<T>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let raw = env::var(key).unwrap_or_else(|_| default.to_string());
    raw.split(',')
        .map(|item| {
            item.trim()
                .trim_matches('"')
                .trim_matches('\'')
                .parse()
                .map_err(|err| AppError::Config(format!("{key} contains invalid value: {err}")))
        })
        .collect()
}
