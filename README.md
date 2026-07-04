# Send

A Rust rewrite of [Send](https://github.com/timvisee/send), a simple and private
file-sharing service with end-to-end encryption and expiring links.

Send encrypts files in the browser before upload. The server stores encrypted
bytes and cannot read the original file contents. Downloads are decrypted in
the recipient's browser.

This repository is standalone. The Rust server, browser client, styles, fonts,
localizations, and images required to run Send are all included. Building or
running it does not require the original Node.js repository, Node.js, Redis, or
an external object store.

## Features

- End-to-end encrypted file sharing
- Links limited by time and download count
- Optional password protection
- Multiple-file archives
- Transactional SQLite metadata and atomic local blob persistence
- Automatic light and dark themes
- Compatibility with [`ffsend`](https://github.com/timvisee/ffsend)
- Health, version, configuration, and PWA endpoints

The current web interface is English-only.

Account synchronization, Firefox Accounts, S3 storage, Redis storage, and the
legacy HTTP upload API are intentionally not included.

## Requirements

- A recent stable [Rust toolchain](https://rustup.rs/)

## Run

```sh
cargo run --release
```

Send listens on `0.0.0.0:1443` by default. Open
<http://127.0.0.1:1443> after the server starts.

Set configuration via environment variables when running:

```sh
PORT=1443 FILE_DIR=./data cargo run --release
```

Uploaded data is written to `FILE_DIR` (`./data` by default). Browser assets
and HTML templates under `static/` are embedded in the executable at build time.

`FILE_DIR` contains `metadata.sqlite3`, private service key material, immutable
encrypted blobs under `files/`, and in-progress uploads under `tmp/`. The server
holds an exclusive lock on the directory; do not run multiple instances against
the same local directory. Uploads and downloads are streamed, and incomplete
uploads are removed during startup reconciliation.

This storage format does not import the JSON sidecars used by earlier `send-rs`
versions. Start with an empty `FILE_DIR` when upgrading to this version.

## Configuration

Configuration is provided through environment variables.

| Variable | Default | Description |
| --- | --- | --- |
| `IP_ADDRESS` | `0.0.0.0` | Address to listen on |
| `PORT` | `1443` | HTTP port |
| `BASE_URL` | `http://localhost:1443` | Canonical public URL used when URL detection is disabled |
| `DETECT_BASE_URL` | `true` | Derive generated links from request headers |
| `FILE_DIR` | `./data` | Encrypted file and metadata directory |
| `NODE_ENV` | `development` | Set to `production` to disable app request-path trace logging |
| `MAX_FILE_SIZE` | `2684354560` | Maximum encrypted upload size in bytes |
| `MAX_DOWNLOADS` | `100` | Maximum download limit |
| `MAX_EXPIRE_SECONDS` | `604800` | Maximum link lifetime |
| `DEFAULT_DOWNLOADS` | `1` | Default download limit |
| `DEFAULT_EXPIRE_SECONDS` | `86400` | Default link lifetime |
| `DOWNLOAD_COUNTS` | `1,2,3,4,5,20,50,100` | Download choices shown in the UI |
| `EXPIRE_TIMES_SECONDS` | `300,3600,86400,604800` | Expiration choices shown in the UI |
| `CUSTOM_TITLE` | `Send` | Site title |
| `CUSTOM_DESCRIPTION` | Send description | Site description |
| `UI_COLOR_PRIMARY` | `#0a84ff` | Primary interface color |
| `UI_COLOR_ACCENT` | `#003eaa` | Accent interface color |

Additional footer and notice variables are documented in the `/config`
response. Configured notice HTML is sanitized before being rendered or exposed
to clients.

When `DETECT_BASE_URL` is enabled behind a reverse proxy, sanitize or replace
forwarded headers at the proxy boundary.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The WebSocket contract test binds an ephemeral localhost port.

Browser assets and templates live under [`static/`](static). A build script
embeds public assets in the executable, while [`src/html.rs`](src/html.rs)
renders the embedded templates with MiniJinja. The `static/` directory is not
needed when running the resulting executable.

## Compatibility

The server preserves the public Send v3 protocol used by the browser client and
`ffsend`, including WebSocket upload, `send-v1` HMAC authentication, owner-token
operations, metadata retrieval, and encrypted blob download.

Compatibility is intentionally behavioral. The former Node.js architecture and
its internal modules are not reproduced.

## Project status

This rewrite is functional and covered by HTTP, persistence, authentication,
and WebSocket contract tests. Before public deployment, place it behind a TLS
reverse proxy and apply deployment-specific request-size and rate limits.

Back up the entire `FILE_DIR` with an atomic filesystem snapshot, or stop the
service before copying it. Do not independently copy a live SQLite database and
its blob directory. Keep backup access restricted and test restoration; RAID
alone is not a backup.

## Acknowledgements

The browser client is derived from the community-maintained
[timvisee/send](https://github.com/timvisee/send) project, itself based on
Mozilla's discontinued [Firefox Send](https://github.com/mozilla/send). Thanks
to Mozilla and the Send community for the original protocol and client.

## License

The inherited Send browser client is distributed under the Mozilla Public
License 2.0. Third-party code and assets retain their respective licenses.
