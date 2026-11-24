//! `passer-push`: the reference push gateway.
//!
//! ```text
//! passer-push --listen 0.0.0.0:8080 --secret <secret> \
//!   --apns-key AuthKey_ABC123.p8 --apns-key-id ABC123 --apns-team-id TEAM456 \
//!   --apns-topic direct.passer.app [--apns-sandbox]
//! passer-coord --wake-url http://<gateway>:8080/wake --wake-secret <secret>
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use passer_push::{APNS_PRODUCTION, APNS_SANDBOX, Apns, ApnsAuth, FCM_BASE, Fcm, Gateway, router};

#[derive(Parser)]
#[command(name = "passer-push", version, about = "Push gateway for passer-core")]
struct Cli {
    /// Address to listen on. Keep it private: only the coordination server should reach it.
    #[arg(long, env = "PASSER_PUSH_LISTEN", default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    /// The bearer secret the coordination server sends (`passer-coord --wake-secret`).
    #[arg(long, env = "PASSER_PUSH_SECRET", hide_env_values = true)]
    secret: String,
    /// Apple's `.p8` key for push notifications.
    #[arg(long, env = "PASSER_PUSH_APNS_KEY")]
    apns_key: Option<PathBuf>,
    /// The key's id (10 characters, shown next to it in Apple's developer site).
    #[arg(long, env = "PASSER_PUSH_APNS_KEY_ID", requires = "apns_key")]
    apns_key_id: Option<String>,
    /// Your Apple team id.
    #[arg(long, env = "PASSER_PUSH_APNS_TEAM_ID", requires = "apns_key")]
    apns_team_id: Option<String>,
    /// The app's bundle id.
    #[arg(
        long,
        env = "PASSER_PUSH_APNS_TOPIC",
        default_value = "direct.passer.app"
    )]
    apns_topic: String,
    /// Use Apple's sandbox (development builds) instead of production.
    #[arg(long, env = "PASSER_PUSH_APNS_SANDBOX")]
    apns_sandbox: bool,
    /// Firebase service account file, to wake Android phones.
    #[arg(long, env = "PASSER_PUSH_FCM_ACCOUNT")]
    fcm_account: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.secret.len() < 16 {
        anyhow::bail!("use a secret of at least 16 characters");
    }
    let apns = match &cli.apns_key {
        Some(path) => {
            let pem = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            // Apple's ids are 10 letters and digits; catch a missing or mistyped one now
            // rather than on the first push.
            let apple_id = |value: &Option<String>, flag: &str| -> anyhow::Result<String> {
                match value.as_deref() {
                    Some(v) if v.len() == 10 && v.chars().all(|c| c.is_ascii_alphanumeric()) => {
                        Ok(v.to_owned())
                    }
                    _ => anyhow::bail!("{flag} must be Apple's 10-character id"),
                }
            };
            let auth = ApnsAuth::new(
                &pem,
                &apple_id(&cli.apns_key_id, "--apns-key-id")?,
                &apple_id(&cli.apns_team_id, "--apns-team-id")?,
            )?;
            let base = if cli.apns_sandbox {
                APNS_SANDBOX
            } else {
                APNS_PRODUCTION
            };
            Some(Apns::new(auth, &cli.apns_topic, base)?)
        }
        None => None,
    };
    let fcm = match &cli.fcm_account {
        Some(path) => {
            let json = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            Some(Fcm::new(&json, FCM_BASE)?)
        }
        None => None,
    };
    if apns.is_none() && fcm.is_none() {
        eprintln!("No APNs key and no Firebase account: every wake request will fail.");
    }
    let gateway = Arc::new(Gateway {
        secret: cli.secret,
        apns,
        fcm,
    });
    let listener = tokio::net::TcpListener::bind(cli.listen).await?;
    println!("passer-push listening on http://{}/wake", cli.listen);
    axum::serve(listener, router(gateway))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
