//! `passer-core`: a device on the command line, for trying the core without an app.
//!
//! ```text
//! passer-core init --group Walson --name PC       # on the first device
//! passer-core serve --invite                       # prints a one-time join link
//! passer-core join '<link>' --name Laptop          # on the second device
//! passer-core serve                                # on the second device, too
//! passer-core call PC device.info                  # from either one
//! passer-core serve --inbox ~/Inbox --share ~/Public  # receive files, share a folder
//! passer-core send PC ./video.mp4                  # from another member
//! passer-core get PC notes.pdf --to ./notes.pdf
//! ```
//!
//! Development tool. The device key is kept with DPAPI on Windows and in a plain file
//! elsewhere; the network mode `n0` uses n0's public relays, reserved for development.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand, ValueEnum};
use iroh::EndpointAddr;
use passer_bus::{Bus, Decision, Journal, Policy, Request, Response, Rule, Who};
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
    /// `local`: direct addresses only. `relay`: your own relay (`--relay`), see
    /// docs/self-hosting.md. `n0`: n0's public relays and lookup (development only).
    #[arg(long, value_enum, default_value_t = Net::N0, global = true)]
    network: Net,
    /// Your relay's URL, for `--network relay` (e.g. `https://relay.example.com`).
    #[arg(long, env = "PASSER_CORE_RELAY", global = true)]
    relay: Option<String>,
    /// Coordination server, as `<id>@<ip:port>[,<ip:port>...]`: publishes this device's
    /// presence and log, and learns where the other members are.
    #[arg(long, env = "PASSER_CORE_COORD", global = true)]
    coord: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Net {
    Local,
    Relay,
    N0,
}

fn network(net: Net, relay: Option<&str>) -> anyhow::Result<Network> {
    Ok(match net {
        Net::Local => Network::LocalOnly,
        Net::N0 => Network::N0Dev,
        Net::Relay => {
            let url = relay.context("`--network relay` needs `--relay <url>`")?;
            Network::Relay(
                url.parse()
                    .with_context(|| format!("bad relay URL {url}"))?,
            )
        }
    })
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
        /// Accept files from other members (`file.drop`) into this folder.
        #[arg(long)]
        inbox: Option<PathBuf>,
        /// Let other members get files from this folder (`file.get`).
        #[arg(long)]
        share: Option<PathBuf>,
    },
    /// Sends a file to another member's inbox (`file.drop`).
    Send {
        device: String,
        path: PathBuf,
        /// Name to give it there (defaults to its own name).
        #[arg(long = "as")]
        name: Option<String>,
        #[arg(long)]
        addr: Vec<String>,
    },
    /// Gets a file from another member's shared folder (`file.get`).
    Get {
        device: String,
        name: String,
        /// Where to save it (defaults to the same name in the current folder).
        #[arg(long)]
        to: Option<PathBuf>,
        #[arg(long)]
        addr: Vec<String>,
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
    /// Grants an AI agent a capability on this device, when relayed by a given device.
    Grant {
        /// Agent name, as the bridge announces it (e.g. `claude`).
        #[arg(long)]
        agent: String,
        /// The device that runs the MCP bridge for this agent (name or id prefix).
        #[arg(long)]
        via: String,
        /// Capability name, `prefix.*` or `*`.
        #[arg(long)]
        capability: String,
        #[arg(long, value_enum, default_value_t = DecisionArg::Ask)]
        decision: DecisionArg,
        /// Restrict to one target (an app, a folder).
        #[arg(long)]
        target: Option<String>,
    },
    /// Shows this device's permission rules.
    Policy,
    /// Runs the MCP bridge on stdio for an agent client (Claude Desktop, Claude Code).
    Mcp {
        /// The name this bridge gives the agent; devices grant capabilities to it.
        #[arg(long, default_value = "claude")]
        agent: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum DecisionArg {
    Allow,
    Ask,
    Deny,
}

impl From<DecisionArg> for Decision {
    fn from(d: DecisionArg) -> Self {
        match d {
            DecisionArg::Allow => Decision::Allow,
            DecisionArg::Ask => Decision::Ask,
            DecisionArg::Deny => Decision::Deny,
        }
    }
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
    fn policy(&self) -> PathBuf {
        self.0.join("policy.json")
    }
    fn load_policy(&self) -> anyhow::Result<Policy> {
        match std::fs::read_to_string(self.policy()) {
            Ok(text) => serde_json::from_str(&text).context("policy.json is malformed"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Policy::default()),
            Err(e) => Err(e.into()),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let home = Home::resolve(cli.home)?;
    let network: Network = network(cli.network, cli.relay.as_deref())?;
    let coord = cli
        .coord
        .as_deref()
        .map(passer_coord::parse_server)
        .transpose()?;
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
            inbox,
            share,
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
                    .module(Arc::new({
                        let mut files = passer_files::Files::new();
                        if let Some(dir) = &inbox {
                            files = files.inbox(dir);
                        }
                        if let Some(dir) = &share {
                            files = files.shared(dir);
                        }
                        files
                    }))
                    .approver(approver.clone())
                    .policy(home.load_policy()?)
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
                network: network.clone(),
                on_admitted: Some(hook),
                approver: Some(approver),
            };
            let node = Arc::new(Node::spawn(identity, group, bus, options).await?);
            if network == Network::N0Dev {
                node.endpoint().online().await;
            }
            println!("{name} is serving as {}", node.id());
            if let Some(dir) = &inbox {
                println!("  receiving files into {}", dir.display());
            }
            if let Some(dir) = &share {
                println!("  sharing files from {}", dir.display());
            }
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
            let sync_loop = coord.clone().map(|server| {
                println!("Syncing with the coordination server every 30 s.");
                passer_coord::spawn_sync_loop(node.clone(), server, Duration::from_secs(30))
            });
            println!("Ctrl+C to stop.");
            tokio::signal::ctrl_c().await?;
            if let Some(task) = sync_loop {
                task.abort();
                let _ = task.await;
            }
            match Arc::try_unwrap(node) {
                Ok(node) => node.shutdown().await?,
                Err(_) => bail!("the node is still in use"),
            }
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
            let (node, peer) =
                client(identity, &home, network, &device, &addr, coord.as_ref()).await?;
            let response = node.call(peer, Request::new(&capability, input)).await;
            node.shutdown().await?;
            match response? {
                Response::Ok { output } => println!("{}", serde_json::to_string_pretty(&output)?),
                Response::Error { code, message } => bail!("{}: {message}", code.as_str()),
            }
        }
        Command::Send {
            device,
            path,
            name,
            addr,
        } => {
            let name = match name {
                Some(n) => n,
                None => path
                    .file_name()
                    .context("the path has no file name")?
                    .to_string_lossy()
                    .into_owned(),
            };
            let size = std::fs::metadata(&path)
                .with_context(|| format!("cannot read {}", path.display()))?
                .len();
            let (node, peer) =
                client(identity, &home, network, &device, &addr, coord.as_ref()).await?;
            let opened = node
                .open_stream(
                    peer,
                    Request::stream(passer_files::DROP, serde_json::json!({ "name": name })),
                )
                .await;
            let response = async {
                let open = match opened? {
                    Ok(open) => open,
                    Err(refusal) => return Ok(refusal),
                };
                let mut file = tokio::fs::File::open(&path).await?;
                let mut buf = vec![0u8; 256 * 1024];
                let mut sent = 0u64;
                loop {
                    let n = tokio::io::AsyncReadExt::read(&mut file, &mut buf).await?;
                    if n == 0 || open.io.outgoing.send(&buf[..n]).await.is_err() {
                        break;
                    }
                    sent += n as u64;
                    eprint!("\r{} / {} MB", sent / 1_000_000, size / 1_000_000);
                }
                eprintln!();
                drop(open.io);
                open.done.await?
            }
            .await;
            node.shutdown().await?;
            match response? {
                Response::Ok { output } => println!("{}", serde_json::to_string_pretty(&output)?),
                Response::Error { code, message } => bail!("{}: {message}", code.as_str()),
            }
        }
        Command::Get {
            device,
            name,
            to,
            addr,
        } => {
            let destination = to.unwrap_or_else(|| PathBuf::from(&name));
            let mut part = destination.clone().into_os_string();
            part.push(".part");
            let part = PathBuf::from(part);
            let (node, peer) =
                client(identity, &home, network, &device, &addr, coord.as_ref()).await?;
            let opened = node
                .open_stream(
                    peer,
                    Request::stream(passer_files::GET, serde_json::json!({ "name": name })),
                )
                .await;
            let response = async {
                let mut open = match opened? {
                    Ok(open) => open,
                    Err(refusal) => return Ok((refusal, false)),
                };
                let mut file = tokio::fs::File::create(&part).await?;
                let mut got = 0u64;
                let complete = loop {
                    match open.io.incoming.next().await {
                        Ok(Some(bytes)) => {
                            tokio::io::AsyncWriteExt::write_all(&mut file, &bytes).await?;
                            got += bytes.len() as u64;
                            eprint!("\r{} MB", got / 1_000_000);
                        }
                        Ok(None) => break true,
                        Err(_) => break false,
                    }
                };
                eprintln!();
                tokio::io::AsyncWriteExt::flush(&mut file).await?;
                drop(open.io);
                anyhow::Ok((open.done.await??, complete))
            }
            .await;
            node.shutdown().await?;
            match response {
                Ok((Response::Ok { output }, true)) => {
                    std::fs::rename(&part, &destination)?;
                    println!("{}", serde_json::to_string_pretty(&output)?);
                    println!("Saved to {}", destination.display());
                }
                Ok((Response::Error { code, message }, _)) => {
                    let _ = std::fs::remove_file(&part);
                    bail!("{}: {message}", code.as_str())
                }
                Ok((Response::Ok { .. }, false)) => {
                    let _ = std::fs::remove_file(&part);
                    bail!("the transfer broke before the file was complete")
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&part);
                    return Err(e);
                }
            }
        }
        Command::Sync { device, addr } => {
            let (node, peer) =
                client(identity, &home, network, &device, &addr, coord.as_ref()).await?;
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
            let options = NodeOptions {
                network,
                ..Default::default()
            };
            let node = Node::spawn(identity, group, bus, options).await?;
            node.remove(target)?;
            if let Some(server) = coord {
                passer_coord::sync(&node, server).await?;
                println!("Removed, and published to the coordination server.");
            } else {
                println!("Removed. Other devices learn it at their next `sync`.");
            }
            node.shutdown().await?;
        }
        Command::Grant {
            agent,
            via,
            capability,
            decision,
            target,
        } => {
            let group = Group::load(home.group())?;
            let via_id = resolve(&group, &via)?;
            let mut policy = home.load_policy()?;
            policy.rules.insert(
                0,
                Rule {
                    who: Who::Agent {
                        name: agent.clone(),
                        via: Some(via_id),
                    },
                    capability: capability.clone(),
                    target,
                    decision: decision.into(),
                    lease_secs: None,
                },
            );
            std::fs::write(home.policy(), serde_json::to_string_pretty(&policy)?)?;
            println!(
                "{agent} (through {via}) may now `{capability}` on this device: {:?}. Restart `serve` to apply.",
                Decision::from(decision)
            );
        }
        Command::Policy => {
            let policy = home.load_policy()?;
            if policy.rules.is_empty() {
                println!(
                    "No rules: devices may read and write, sensitive actions ask, agents get nothing."
                );
            }
            for (i, r) in policy.rules.iter().enumerate() {
                println!("{i:>3}  {}", serde_json::to_string(r)?);
            }
        }
        Command::Mcp { agent } => {
            // stdout belongs to the MCP protocol from here on: no println!.
            let group = Arc::new(
                Group::load(home.group()).context("no group: run `init` or `join` first")?,
            );
            let bus = Arc::new(Bus::builder(group.clone()).build()?);
            let options = NodeOptions {
                network,
                ..Default::default()
            };
            let node = Arc::new(Node::spawn(Arc::new(identity), group, bus, options).await?);
            if let Some(server) = &coord {
                // Learn where the devices are before the client lists tools.
                if let Err(e) = passer_coord::sync(&node, server.clone()).await {
                    eprintln!("coordination server unreachable: {e:#}");
                }
            }
            let sync_loop = coord.map(|server| {
                passer_coord::spawn_sync_loop(node.clone(), server, Duration::from_secs(30))
            });
            let result = passer_mcp::serve_stdio(passer_mcp::Bridge::new(node, agent)).await;
            if let Some(task) = sync_loop {
                task.abort();
            }
            result?;
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
    coord: Option<&EndpointAddr>,
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
    if let Some(server) = coord {
        passer_coord::sync(&node, server.clone()).await?;
    }
    let mut peer = node.peers().addr_of(&target);
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

/// Asks the person at this terminal, one prompt at a time, through a single reader.
struct ConsolePrompter;

static CONSOLE: std::sync::LazyLock<tokio::sync::Mutex<tokio::io::BufReader<tokio::io::Stdin>>> =
    std::sync::LazyLock::new(|| {
        tokio::sync::Mutex::new(tokio::io::BufReader::new(tokio::io::stdin()))
    });

#[async_trait::async_trait]
impl Prompter for ConsolePrompter {
    async fn ask(&self, p: &ApprovalPrompt) -> bool {
        use tokio::io::AsyncBufReadExt;
        let mut stdin = CONSOLE.lock().await;
        let who = match &p.agent {
            Some(agent) => format!(
                "{agent} (through {} {})",
                p.requester_name,
                p.requester.fmt_short()
            ),
            None => format!("{} {}", p.requester_name, p.requester.fmt_short()),
        };
        let on = match &p.target {
            Some(t) => format!(" on {t}"),
            None => String::new(),
        };
        println!(
            "\n{who} asks: {} [{}]{on} on {} {}, for up to {} min. Allow? [y/N]",
            p.title,
            p.capability,
            p.target_device_name,
            p.target_device.fmt_short(),
            p.lease_secs.div_ceil(60)
        );
        let mut line = String::new();
        stdin.read_line(&mut line).await.is_ok() && line.trim().eq_ignore_ascii_case("y")
    }
}
