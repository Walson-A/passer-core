//! `passer-coord`: runs a coordination server.
//!
//! ```text
//! passer-coord --home ./coord --port 4433
//! ```
//!
//! Prints the server's id and addresses. Devices point at it with
//! `passer-core --coord <id>@<ip:port> ...`.

use std::path::PathBuf;

use clap::Parser;
use passer_identity::platform_store;

#[derive(Parser)]
#[command(
    name = "passer-coord",
    version,
    about = "passer-core coordination server"
)]
struct Cli {
    /// Where the server keeps its key.
    #[arg(long, default_value = "./passer-coord")]
    home: PathBuf,
    /// UDP port to listen on.
    #[arg(long, default_value_t = 4433)]
    port: u16,
    /// Push gateway that wakes sleeping devices (`http://host:port/path`); see
    /// docs/self-hosting.md. Without it, wake requests are skipped.
    #[arg(long, env = "PASSER_COORD_WAKE_URL")]
    wake_url: Option<String>,
    /// Bearer secret sent to the push gateway.
    #[arg(long, env = "PASSER_COORD_WAKE_SECRET", hide_env_values = true)]
    wake_secret: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let identity = platform_store(cli.home.join("server.key")).load_or_create()?;
    let hook = cli
        .wake_url
        .as_deref()
        .map(|url| passer_coord::HttpWakeHook::new(url, cli.wake_secret.clone()))
        .transpose()?
        .map(|h| std::sync::Arc::new(h) as std::sync::Arc<dyn passer_coord::WakeHook>);
    let server = passer_coord::Server::spawn_with(&identity, cli.port, hook).await?;
    println!("passer-coord serving as {}", server.endpoint().id());
    for a in server.addr().ip_addrs() {
        println!("  devices use: --coord {}@{a}", server.endpoint().id());
    }
    println!("Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    server.shutdown().await
}
