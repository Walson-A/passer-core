use std::collections::HashSet;
use std::sync::Mutex;

use passer_identity::Identity;
use serde_json::json;

use super::*;

struct Members(HashSet<DeviceId>);

impl MembershipView for Members {
    fn is_member(&self, device: &DeviceId) -> bool {
        self.0.contains(device)
    }
}

/// A module with one capability of each kind, used to exercise the bus.
struct Toy;

#[async_trait]
impl Module for Toy {
    fn manifest(&self) -> Manifest {
        let text = json!({"type": "object", "properties": {"text": {"type": "string", "maxLength": 100}}, "required": ["text"], "additionalProperties": false});
        let empty = json!({"type": "object", "additionalProperties": false});
        let mut screen = Capability::call(
            "toy.screen",
            "Screen",
            "Acts on an app",
            Effect::Sensitive,
            empty.clone(),
        );
        screen.target_kind = Some("app".into());
        screen.indicator = IndicatorRequirement::Required;
        Manifest {
            module: "toy".into(),
            version: "0".into(),
            capabilities: vec![
                Capability::call(
                    "toy.echo",
                    "Echo",
                    "Returns the text",
                    Effect::Read,
                    text.clone(),
                ),
                Capability::call("toy.drop", "Drop", "Writes", Effect::Write, text),
                Capability::call(
                    "toy.secret",
                    "Secret",
                    "Reads a secret",
                    Effect::Sensitive,
                    empty.clone(),
                ),
                Capability::call("toy.hang", "Hang", "Never returns", Effect::Read, empty),
                screen,
            ],
        }
    }

    async fn invoke(&self, ctx: Ctx, capability: &str, input: Value) -> Result<Value, ModuleError> {
        match capability {
            "toy.echo" | "toy.drop" => Ok(json!({ "text": input["text"] })),
            "toy.secret" => Ok(json!({ "secret": 42 })),
            "toy.screen" => Ok(json!({ "app": ctx.target, "lease": ctx.lease.info().id })),
            "toy.hang" => {
                std::future::pending::<()>().await;
                unreachable!()
            }
            _ => Err(ModuleError::Unsupported(capability.into())),
        }
    }
}

struct FixedApprover(Option<ApprovalOutcome>);

#[async_trait]
impl Approver for FixedApprover {
    async fn approve(&self, _: &ApprovalRequest) -> ApprovalOutcome {
        match self.0 {
            Some(o) => o,
            None => std::future::pending().await,
        }
    }
}

#[derive(Default)]
struct RecordingIndicator(Mutex<Vec<String>>);

impl Indicator for RecordingIndicator {
    fn show(&self, lease: &LeaseInfo) {
        self.0.lock().unwrap().push(format!("show {}", lease.id));
    }
    fn hide(&self, lease_id: u64) {
        self.0.lock().unwrap().push(format!("hide {lease_id}"));
    }
}

fn setup(builder: impl FnOnce(BusBuilder) -> BusBuilder) -> (Bus, Subject) {
    let me = Identity::generate().id();
    let members = Arc::new(Members([me].into_iter().collect()));
    let bus = builder(Bus::builder(members).module(Arc::new(Toy)))
        .build()
        .unwrap();
    (bus, Subject::device(me))
}

fn req(cap: &str, input: Value) -> Request {
    Request::new(cap, input)
}

#[tokio::test]
async fn member_reads_and_writes_by_default() {
    let (bus, me) = setup(|b| b);
    let r = bus
        .handle(me.clone(), req("toy.echo", json!({"text": "hi"})))
        .await;
    assert_eq!(
        r,
        Response::Ok {
            output: json!({"text": "hi"})
        }
    );
    let r = bus.handle(me, req("toy.drop", json!({"text": "hi"}))).await;
    assert!(r.code().is_none());
}

#[tokio::test]
async fn stranger_is_refused_before_anything_else() {
    let (bus, _) = setup(|b| b);
    let stranger = Subject::device(Identity::generate().id());
    let r = bus
        .handle(stranger, req("toy.echo", json!({"text": "hi"})))
        .await;
    assert_eq!(r.code(), Some(ErrorCode::NotMember));
}

#[tokio::test]
async fn input_is_validated_against_the_schema() {
    let (bus, me) = setup(|b| b);
    for bad in [
        json!({}),
        json!({"text": 3}),
        json!({"text": "x", "extra": true}),
        json!({"text": "x".repeat(101)}),
    ] {
        let r = bus.handle(me.clone(), req("toy.echo", bad)).await;
        assert_eq!(r.code(), Some(ErrorCode::InvalidInput));
    }
    assert_eq!(
        bus.handle(me, req("toy.nope", json!({}))).await.code(),
        Some(ErrorCode::UnknownCapability)
    );
}

#[tokio::test]
async fn sensitive_asks_and_respects_the_answer() {
    let (bus, me) = setup(|b| b);
    assert_eq!(
        bus.handle(me, req("toy.secret", json!({}))).await.code(),
        Some(ErrorCode::Denied),
        "no approver = no"
    );

    let (bus, me) = setup(|b| b.approver(Arc::new(FixedApprover(Some(ApprovalOutcome::Approved)))));
    assert_eq!(
        bus.handle(me, req("toy.secret", json!({}))).await,
        Response::Ok {
            output: json!({"secret": 42})
        }
    );

    let (bus, me) = setup(|b| b.approver(Arc::new(FixedApprover(Some(ApprovalOutcome::Denied)))));
    assert_eq!(
        bus.handle(me, req("toy.secret", json!({}))).await.code(),
        Some(ErrorCode::Denied)
    );
}

#[tokio::test(start_paused = true)]
async fn unanswered_approval_times_out() {
    let (bus, me) = setup(|b| b.approver(Arc::new(FixedApprover(None))));
    let r = bus.handle(me, req("toy.secret", json!({}))).await;
    assert_eq!(r.code(), Some(ErrorCode::ApprovalTimeout));
}

#[tokio::test]
async fn agents_get_nothing_unless_granted() {
    let (bus, me) = setup(|b| b);
    let agent = Subject {
        device: me.device,
        agent: Some("claude".into()),
    };
    assert_eq!(
        bus.handle(agent.clone(), req("toy.echo", json!({"text": "hi"})))
            .await
            .code(),
        Some(ErrorCode::Denied)
    );
    bus.set_policy(Policy::new(vec![Rule {
        who: Who::Agent {
            name: "claude".into(),
            via: Some(me.device),
        },
        capability: "toy.echo".into(),
        target: None,
        decision: Decision::Allow,
        lease_secs: None,
    }]));
    assert!(
        bus.handle(agent.clone(), req("toy.echo", json!({"text": "hi"})))
            .await
            .code()
            .is_none()
    );
    let listed: Vec<String> = bus
        .capabilities_for(&agent)
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(listed, vec!["toy.echo"]);
}

#[tokio::test]
async fn indicator_is_required_shown_and_hidden() {
    let allow_screen = Policy::new(vec![Rule {
        who: Who::AnyDevice,
        capability: "toy.screen".into(),
        target: None,
        decision: Decision::Allow,
        lease_secs: Some(60),
    }]);
    let input = || Request {
        capability: "toy.screen".into(),
        target: Some("notepad.exe".into()),
        input: json!({}),
        agent: None,
        stream: false,
    };

    let (bus, me) = setup(|b| b.policy(allow_screen.clone()));
    assert_eq!(
        bus.handle(me, input()).await.code(),
        Some(ErrorCode::NoIndicator)
    );

    let indicator = Arc::new(RecordingIndicator::default());
    let (bus, me) = setup(|b| b.policy(allow_screen).indicator(indicator.clone()));
    let r = bus.handle(me.clone(), input()).await;
    assert_eq!(
        r,
        Response::Ok {
            output: json!({"app": "notepad.exe", "lease": 1})
        }
    );
    assert_eq!(*indicator.0.lock().unwrap(), vec!["show 1", "hide 1"]);

    let missing_target = Request {
        target: None,
        ..input()
    };
    assert_eq!(
        bus.handle(me, missing_target).await.code(),
        Some(ErrorCode::InvalidInput)
    );
}

#[tokio::test]
async fn stop_button_interrupts_a_running_invocation() {
    let (bus, me) = setup(|b| b);
    let bus = Arc::new(bus);
    let call = {
        let bus = bus.clone();
        tokio::spawn(async move { bus.handle(me, req("toy.hang", json!({}))).await })
    };
    // Wait until the lease exists, then press stop.
    while bus.leases().active().is_empty() {
        tokio::task::yield_now().await;
    }
    bus.leases().revoke_all("stop button");
    assert_eq!(call.await.unwrap().code(), Some(ErrorCode::Interrupted));
    assert!(bus.leases().active().is_empty());
}

#[tokio::test]
async fn journal_records_every_call_without_content() {
    let (bus, me) = setup(|b| b);
    bus.handle(
        me.clone(),
        req("toy.echo", json!({"text": "top secret words"})),
    )
    .await;
    bus.handle(me, req("toy.secret", json!({}))).await;
    let lines = bus.journal().recent();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].record.outcome, "ok");
    assert_eq!(lines[1].record.decision, "ask");
    assert_eq!(lines[1].record.approved, Some(false));
    let dump = serde_json::to_string(&lines).unwrap();
    assert!(
        !dump.contains("top secret"),
        "inputs never reach the journal"
    );
    assert_eq!(lines[1].record.prev, lines[0].hash);
}

#[test]
fn reserved_and_duplicate_names_are_refused() {
    struct Bad(&'static str);
    #[async_trait]
    impl Module for Bad {
        fn manifest(&self) -> Manifest {
            Manifest {
                module: "bad".into(),
                version: "0".into(),
                capabilities: vec![Capability::call(self.0, "x", "x", Effect::Read, json!({}))],
            }
        }
        async fn invoke(&self, _: Ctx, _: &str, _: Value) -> Result<Value, ModuleError> {
            Ok(Value::Null)
        }
    }
    let members: Arc<dyn MembershipView> = Arc::new(Members(HashSet::new()));
    assert!(matches!(
        Bus::builder(members.clone())
            .module(Arc::new(Bad("bus.capabilities")))
            .build(),
        Err(BuildError::Reserved(_))
    ));
    assert!(matches!(
        Bus::builder(members.clone())
            .module(Arc::new(Bad("Toy.Echo")))
            .build(),
        Err(BuildError::BadName(_))
    ));
    assert!(matches!(
        Bus::builder(members)
            .module(Arc::new(Toy))
            .module(Arc::new(Bad("toy.echo")))
            .build(),
        Err(BuildError::Duplicate(_))
    ));
}
