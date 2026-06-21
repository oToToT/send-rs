use std::net::SocketAddr;

use send_rs::{AppState, Config, app};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "send_rs=info,tower_http=info".into()),
        )
        .init();

    let config = Config::from_env()?;
    let addr: SocketAddr = format!("{}:{}", config.listen_address, config.listen_port).parse()?;
    let state = AppState::new(config).await?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!("listening on http://{}", addr);
    axum::serve(listener, app(state)).await?;
    Ok(())
}
