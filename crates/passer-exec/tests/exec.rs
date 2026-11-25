//! passer-exec through the real bus: checks, lease, indicator, then the process.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use passer_bus::stream::{self, Chunk};
use passer_bus::{
    Bus, Decision, Effect, ErrorCode, Indicator, LeaseInfo, MembershipView, Mode, Policy, Request,
    Response, Rule, Subject, Who,
};
use passer_exec::{Command, Exec};
use passer_identity::{DeviceId, Identity};

struct Everyone;
impl MembershipView for Everyone {
    fn is_member(&self, _: &DeviceId) -> bool {
        true
    }
}

#[derive(Default)]
struct Hud(Mutex<Vec<String>>);
impl Indicator for Hud {
    fn show(&self, lease: &LeaseInfo) {
        self.0
            .lock()
            .unwrap()
            .push(format!("show {}", lease.capability));
    }
    fn hide(&self, _: u64) {
        self.0.lock().unwrap().push("hide".into());
    }
}

fn helper() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_exec-test-helper"))
}

fn command(name: &str, args: &[&str], indicator: bool) -> Command {
    Command {
        name: name.into(),
        title: name.into(),
        description: name.into(),
        effect: Effect::Sensitive,
        indicator,
        program: helper(),
        args: args.iter().map(|a| (*a).to_owned()).collect(),
    }
}

/// A bus where the caller (named `name`) runs `exec.*` without being asked.
fn make_bus(
    commands: Vec<Command>,
    name: &'static str,
    hud: Option<Arc<Hud>>,
) -> (Arc<Bus>, Subject) {
    let me = Identity::generate().id();
    let exec = Exec::new(commands, Arc::new(move |_| Some(name.to_owned())));
    let policy = Policy {
        rules: vec![Rule {
            who: Who::AnyDevice,
            capability: "exec.*".into(),
            target: None,
            decision: Decision::Allow,
            lease_secs: None,
        }],
    };
    let mut builder = Bus::builder(Arc::new(Everyone))
        .module(Arc::new(exec))
        .policy(policy);
    if let Some(h) = hud {
        builder = builder.indicator(h);
    }
    (Arc::new(builder.build().unwrap()), Subject::device(me))
}

fn open(capability: &str) -> Request {
    Request::stream(capability, serde_json::json!({}))
}

#[tokio::test]
async fn stdin_and_stdout_ride_the_stream() {
    let hud = Arc::new(Hud::default());
    let (bus, me) = make_bus(
        vec![command("exec.echo", &["echo"], true)],
        "iPhone",
        Some(hud.clone()),
    );
    let (io, mut peer) = stream::pair();
    let b = bus.clone();
    let run = tokio::spawn(async move {
        let session = b
            .open(me, open("exec.echo"), Mode::Stream)
            .await
            .expect("allowed");
        session.run_stream(io).await
    });
    peer.to_module
        .send(Chunk::Data(b"hello ".to_vec()))
        .await
        .unwrap();
    peer.to_module
        .send(Chunk::Data(b"world".to_vec()))
        .await
        .unwrap();
    peer.to_module.send(Chunk::End).await.unwrap();
    let mut got = Vec::new();
    while let Some(bytes) = peer.from_module.recv().await {
        got.extend(bytes);
    }
    assert_eq!(got, b"hello world");
    let result = run.await.unwrap();
    assert_eq!(
        result,
        Response::Ok {
            output: serde_json::json!({ "exit": 0 })
        }
    );
    assert_eq!(*hud.0.lock().unwrap(), vec!["show exec.echo", "hide"]);
}

#[tokio::test]
async fn only_the_known_placeholders_are_filled() {
    let (bus, me) = make_bus(
        vec![command(
            "exec.args",
            &["args", "--viewer={caller_name}", "{caller_id}", "{input}"],
            true,
        )],
        "WALSON-HP",
        Some(Arc::default()),
    );
    let id = me.device.to_string();
    let (io, peer) = stream::pair();
    let b = bus.clone();
    let run = tokio::spawn(async move {
        let session = b
            .open(me, open("exec.args"), Mode::Stream)
            .await
            .expect("allowed");
        session.run_stream(io).await
    });
    let stream::StreamPeer {
        to_module,
        mut from_module,
    } = peer;
    // Done sending (a drop without `End` would be a broken stream).
    to_module.send(Chunk::End).await.unwrap();
    drop(to_module);
    let mut got = Vec::new();
    while let Some(bytes) = from_module.recv().await {
        got.extend(bytes);
    }
    let lines: Vec<String> = String::from_utf8(got)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        lines,
        vec!["--viewer=WALSON-HP".to_owned(), id, "{input}".to_owned()]
    );
    assert!(matches!(run.await.unwrap(), Response::Ok { .. }));
}

#[tokio::test]
async fn the_stop_button_kills_the_command() {
    let dir = tempfile::tempdir().unwrap();
    let ticks = dir.path().join("ticks");
    let path = ticks.to_string_lossy().into_owned();
    let (bus, me) = make_bus(
        vec![command("exec.tick", &["tick", &path], true)],
        "iPhone",
        Some(Arc::default()),
    );
    let (io, _peer) = stream::pair();
    let b = bus.clone();
    let run = tokio::spawn(async move {
        let session = b
            .open(me, open("exec.tick"), Mode::Stream)
            .await
            .expect("allowed");
        session.run_stream(io).await
    });
    // A freshly built helper can take a while to start (antivirus scan on Windows).
    let mut ran = false;
    for _ in 0..100 {
        if std::fs::metadata(&ticks).map(|m| m.len()).unwrap_or(0) > 0 {
            ran = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ran, "it ran");

    bus.leases().revoke_all("stopped by the user");
    let result = tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.code(), Some(ErrorCode::Interrupted));
    // Killed: the file stops growing.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after = std::fs::metadata(&ticks).unwrap().len();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        std::fs::metadata(&ticks).unwrap().len(),
        after,
        "the process is gone"
    );
}

#[tokio::test]
async fn refusals() {
    // No indicator on a device whose command requires one: it does not run.
    let (bus, me) = make_bus(vec![command("exec.echo", &["echo"], true)], "iPhone", None);
    let r = bus.open(me, open("exec.echo"), Mode::Stream).await;
    assert_eq!(r.err().and_then(|r| r.code()), Some(ErrorCode::NoIndicator));

    // A caller named like an option cannot slip it into the command line.
    let (bus, me) = make_bus(
        vec![command("exec.args", &["args", "{caller_name}"], false)],
        "--control",
        None,
    );
    let session = bus.open(me, open("exec.args"), Mode::Stream).await.unwrap();
    let (io, _peer) = stream::pair();
    assert_eq!(
        session.run_stream(io).await.code(),
        Some(ErrorCode::InvalidInput)
    );
}

/// Runs `exec.stubborn` (writes forever, ignores its input) until the caller does `leave`,
/// then returns how long the session took to end after that, and the HUD's log.
async fn stubborn_until<F, Fut>(leave: F) -> (Duration, Vec<String>)
where
    F: FnOnce(stream::StreamPeer) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let hud = Arc::new(Hud::default());
    let (bus, me) = make_bus(
        vec![command("exec.stubborn", &["stubborn"], true)],
        "iPhone",
        Some(hud.clone()),
    );
    let (io, peer) = stream::pair();
    let b = bus.clone();
    let run = tokio::spawn(async move {
        let session = b
            .open(me, open("exec.stubborn"), Mode::Stream)
            .await
            .expect("allowed");
        session.run_stream(io).await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let left = std::time::Instant::now();
    leave(peer).await;
    tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .expect("the session ended")
        .unwrap();
    let took = left.elapsed();
    let log = hud.0.lock().unwrap().clone();
    (took, log)
}

#[tokio::test]
async fn a_caller_that_vanishes_ends_the_session_at_once() {
    // The stream breaks (no `End`): the phone was closed, or the network dropped.
    let (took, hud) = stubborn_until(|peer| async move { drop(peer) }).await;
    assert!(took < Duration::from_secs(2), "took {took:?}");
    assert_eq!(hud, vec!["show exec.stubborn", "hide"]);
}

#[tokio::test]
async fn a_command_that_misses_the_end_is_killed_after_a_grace() {
    // The caller says it is done but keeps reading; the command keeps writing.
    let (took, hud) = stubborn_until(|peer| async move {
        let stream::StreamPeer {
            to_module,
            mut from_module,
        } = peer;
        to_module.send(Chunk::End).await.unwrap();
        tokio::spawn(async move {
            // Keep the sender alive (a clean end, not a break) and drain the output.
            let _keep = to_module;
            while from_module.recv().await.is_some() {}
        });
    })
    .await;
    // Killed after the 3 s grace, not before, and not never.
    assert!(
        took >= Duration::from_secs(3) && took < Duration::from_secs(8),
        "took {took:?}"
    );
    assert_eq!(hud, vec!["show exec.stubborn", "hide"]);
}
