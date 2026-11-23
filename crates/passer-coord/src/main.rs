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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let identity = platform_store(cli.home.join("server.key")).load_or_create()?;
    let server = passer_coord::Server::spawn(&identity, cli.port).await?;
    println!("passer-coord serving as {}", server.endpoint().id());
    for a in server.addr().ip_addrs() {
        println!("  devices use: --coord {}@{a}", server.endpoint().id());
    }
    println!("Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    server.shutdown().await
}
