//! `passer-core`: a device on the command line, for trying the core without an app.
//!
//! ```text
//! passer-core init --group Walson --name PC       # on the first device
//! passer-core serve --invite                       # prints a one-time join link
//! passer-core join '<link>' --name Laptop          # on the second device
//! passer-core serve                                # on the second device, too
//! passer-core call PC device.info                  # from either one
//! ```
//!
//! Development tool. The device key is kept with DPAPI on Windows and in a plain file
//! elsewhere; the network mode `n0` uses n0's public relays, reserved for development.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand, ValueEnum};
use iroh::EndpointAddr;
use passer_bus::{Bus, Journal, Request, Response};
use passer_device_info::DeviceInfo;
use passer_identity::{DeviceId, platform_store};
use passer_membership::DeviceLog;
use passer_membership::pairing::Invitation;
use passer_node::approval::{ApprovalModule, ApprovalPrompt, Prompter, RemoteApprover};
use passer_node::{Group, Network, Node, NodeOptions, join, now_secs};

#[derive(Parser)]
#[command(
    name = "passer-core",
    version,
    about = "A passer-core device on the command line"
)]
struct Cli {
    /// Where this device keeps its key, group and journal.
    #[arg(long, env = "PASSER_CORE_HOME", global = true)]
    home: Option<PathBuf>,
    /// `local`: direct addresses only. `n0`: n0's public relays and lookup (development only).
    #[arg(long, value_enum, default_value_t = Net::N0, global = true)]
    network: Net,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Net {
    Local,
    N0,
}

impl From<Net> for Network {
    fn from(n: Net) -> Self {
        match n {
            Net::Local => Network::LocalOnly,
            Net::N0 => Network::N0Dev,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Creates a new group with this device as its first approver.
    Init {
        #[arg(long)]
        group: String,
        #[arg(long)]
        name: String,
    },
    /// Shows this device and the group's members.
    Status,
    /// Runs this device until Ctrl+C, serving calls (and, with --invite, one join).
    Serve {
        /// Print a one-time join link valid for this many minutes.
        #[arg(long, num_args = 0..=1, default_missing_value = "10")]
        invite: Option<u64>,
        /// The invited device becomes an approver (it can approve sensitive actions and
        /// invite others).
        #[arg(long, requires = "invite")]
        as_approver: bool,
    },
    /// Joins a group with a link printed by `serve --invite` on an approver.
    Join {
        link: String,
        #[arg(long)]
        name: String,
    },
    /// Calls a capability on another member, by name or id prefix.
    Call {
        device: String,
        capability: String,
        /// JSON input (defaults to `{}`).
        input: Option<String>,
        /// Direct address of the device (`ip:port`), if lookup cannot find it.
        #[arg(long)]
        addr: Vec<String>,
    },
    /// Fetches the latest signed device log from another member.
    Sync {
        device: String,
        #[arg(long)]
        addr: Vec<String>,
    },
    /// Removes a device from the group (approvers, or a device removing itself).
    Remove { device: String },
    /// Prints the recent journal of calls received by this device.
    Journal,
}

struct Home(PathBuf);

impl Home {
    fn resolve(arg: Option<PathBuf>) -> anyhow::Result<Self> {
        let path = match arg {
            Some(p) => p,
            None => directories::ProjectDirs::from("", "", "passer-core")
                .context("no home directory")?
                .data_dir()
                .to_path_buf(),
        };
        Ok(Self(path))
    }
    fn key(&self) -> PathBuf {
        self.0.join("device.key")
    }
    fn group(&self) -> PathBuf {
        self.0.join("group.json")
    }
    fn journal(&self) -> PathBuf {
        self.0.join("journal.jsonl")
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let home = Home::resolve(cli.home)?;
    let network: Network = cli.network.into();
    let identity = platform_store(home.key()).load_or_create()?;

    match cli.command {
        Command::Init { group, name } => {
            if home.group().exists() {
                bail!(
                    "this device already belongs to a group ({})",
                    home.group().display()
                );
            }
            let log = DeviceLog::create(&identity, &group, &name, now_secs())?;
            Group::new(log, Some(home.group()))?;
            println!("Group \"{group}\" created. This device ({name}) is its first approver.");
            println!("Device id: {}", identity.id());
        }
        Command::Status => {
            println!("This device: {}", identity.id());
            match Group::load(home.group()) {
                Err(_) => println!("No group yet: run `init` or `join`."),
                Ok(g) => {
                    let m = g.membership();
                    println!(
                        "Group \"{}\" ({} entries, id {})",
                        m.name,
                        m.len,
                        &m.group.to_string()[..12]
                    );
                    for (id, member) in &m.members {
                        let me = if *id == identity.id() {
                            "  <- this device"
                        } else {
                            ""
                        };
                        let role = if member.approver {
                            "approver"
                        } else {
                            "member"
                        };
                        println!("  {:<20} {:<9} {}{me}", member.name, role, id.fmt_short());
                    }
                    if !m.revoked.is_empty() {
                        println!("  revoked: {}", m.revoked.len());
                    }
                }
            }
        }
        Command::Serve {
            invite,
            as_approver,
        } => {
            let identity = Arc::new(identity);
            let group = Arc::new(
                Group::load(home.group()).context("no group: run `init` or `join` first")?,
            );
            let name = group
                .membership()
                .members
                .get(&identity.id())
                .map(|m| m.name.clone())
                .unwrap_or_default();
            let journal = Arc::new(Journal::open(home.journal())?);
            let prompter: Arc<dyn Prompter> = Arc::new(ConsolePrompter);
            let approver = RemoteApprover::new(group.clone(), Some(prompter.clone()));
            let bus = Arc::new(
                Bus::builder(group.clone())
                    .module(Arc::new(DeviceInfo::new(name.clone())))
                    .module(Arc::new(ApprovalModule::new(group.clone(), prompter)))
                    .approver(approver.clone())
                    .journal(journal)
                    .build()?,
            );
            let hook: passer_node::AdmissionHook = Arc::new(|id, name, sas| {
                println!(
                    "\n{name} joined ({}). Check that it shows the code {sas}.",
                    id.fmt_short()
                );
            });
            let options = NodeOptions {
                network,
                on_admitted: Some(hook),
                approver: Some(approver),
            };
            let node = Node::spawn(identity, group, bus, options).await?;
            if network == Network::N0Dev {
                node.endpoint().online().await;
            }
            println!("{name} is serving as {}", node.id());
            for a in node.addr().ip_addrs() {
                println!("  direct address: {a}");
            }
            if let Some(minutes) = invite {
                let inv = if as_approver {
                    node.invite_approver(minutes * 60)?
                } else {
                    node.invite(minutes * 60)?
                };
                println!(
                    "\nOne-time join link (valid {minutes} min). It contains a secret: do not share it.\n"
                );
                println!("{}\n", inv.to_link());
            }
            println!("Ctrl+C to stop.");
            tokio::signal::ctrl_c().await?;
            node.shutdown().await?;
        }
        Command::Join { link, name } => {
            if home.group().exists() {
                bail!(
                    "this device already belongs to a group ({})",
                    home.group().display()
                );
            }
            let invitation = Invitation::parse_link(&link)?;
            let (log, sas) = join(&identity, &invitation, &name, network).await?;
            let group = Group::new(log, Some(home.group()))?;
            println!("Joined \"{}\" as {name}.", group.membership().name);
            println!(
                "The inviting device should show the code {sas}. If it does not, run `remove` there."
            );
        }
        Command::Call {
            device,
            capability,
            input,
            addr,
        } => {
            let input: serde_json::Value = match input {
                Some(s) => serde_json::from_str(&s).context("input must be JSON")?,
                None => serde_json::json!({}),
            };
            let (node, peer) = client(identity, &home, network, &device, &addr).await?;
            let response = node.call(peer, Request::new(&capability, input)).await;
            node.shutdown().await?;
            match response? {
                Response::Ok { output } => println!("{}", serde_json::to_string_pretty(&output)?),
                Response::Error { code, message } => bail!("{}: {message}", code.as_str()),
            }
        }
        Command::Sync { device, addr } => {
            let (node, peer) = client(identity, &home, network, &device, &addr).await?;
            let m = node.sync_log(peer).await;
            node.shutdown().await?;
            let m = m?;
            println!(
                "Log synced: {} entries, {} members.",
                m.len,
                m.members.len()
            );
        }
        Command::Remove { device } => {
            let group = Group::load(home.group())?;
            let target = resolve(&group, &device)?;
            let identity = Arc::new(identity);
            let bus = Arc::new(Bus::builder(Arc::new(NoMembers)).build()?);
            let group = Arc::new(group);
            let node = Node::spawn(identity, group, bus, NodeOptions::default()).await?;
            node.remove(target)?;
            node.shutdown().await?;
            println!("Removed. Other devices learn it at their next `sync`.");
        }
        Command::Journal => {
            let journal = Journal::open(home.journal())?;
            for line in journal.recent() {
                let r = line.record;
                println!(
                    "{:>5} {} {} {:<20} {:<6} {}",
                    r.seq,
                    r.at,
                    &r.device[..10.min(r.device.len())],
                    r.capability,
                    r.decision,
                    r.outcome
                );
            }
        }
    }
    Ok(())
}

struct NoMembers;
impl passer_bus::MembershipView for NoMembers {
    fn is_member(&self, _: &DeviceId) -> bool {
        false
    }
}

/// A short-lived node used to make one outgoing call.
async fn client(
    identity: passer_identity::Identity,
    home: &Home,
    network: Network,
    device: &str,
    addrs: &[String],
) -> anyhow::Result<(Node, EndpointAddr)> {
    let group =
        Arc::new(Group::load(home.group()).context("no group: run `init` or `join` first")?);
    let target = resolve(&group, device)?;
    let bus = Arc::new(Bus::builder(group.clone()).build()?);
    let node = Node::spawn(
        Arc::new(identity),
        group,
        bus,
        NodeOptions {
            network,
            ..Default::default()
        },
    )
    .await?;
    let mut peer = EndpointAddr::new(target);
    for a in addrs {
        peer = peer.with_ip_addr(a.parse().with_context(|| format!("bad address {a}"))?);
    }
    Ok((node, peer))
}

/// Finds a member by exact name or by a prefix of its id.
fn resolve(group: &Group, query: &str) -> anyhow::Result<DeviceId> {
    let m = group.membership();
    let hits: Vec<DeviceId> = m
        .members
        .iter()
        .filter(|(id, member)| {
            member.name.eq_ignore_ascii_case(query)
                || id.to_string().starts_with(&query.to_lowercase())
        })
        .map(|(id, _)| *id)
        .collect();
    match hits.as_slice() {
        [one] => Ok(*one),
        [] => bail!("no member matches \"{query}\""),
        _ => bail!("\"{query}\" matches several members; use more of the id"),
    }
}

/// Asks the person at this terminal.
struct ConsolePrompter;

#[async_trait::async_trait]
impl Prompter for ConsolePrompter {
    async fn ask(&self, p: &ApprovalPrompt) -> bool {
        use tokio::io::AsyncBufReadExt;
        let who = match &p.agent {
            Some(agent) => format!("{agent} (through {})", p.requester_name),
            None => p.requester_name.clone(),
        };
        let on = match &p.target {
            Some(t) => format!(" on {t}"),
            None => String::new(),
        };
        println!(
            "
{who} asks: {} [{}]{on} on {}, for up to {} min. Allow? [y/N]",
            p.title,
            p.capability,
            if p.target_device_name.is_empty() {
                "this device"
            } else {
                &p.target_device_name
            },
            p.lease_secs.div_ceil(60)
        );
        let mut line = String::new();
        let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
        stdin.read_line(&mut line).await.is_ok() && line.trim().eq_ignore_ascii_case("y")
    }
}
