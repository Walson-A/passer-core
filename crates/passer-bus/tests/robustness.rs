//! Property tests: whatever a member sends, the bus answers with a response — no panic, no
//! module call that the checkpoint should have stopped.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use passer_bus::{
    Bus, Capability, Ctx, Effect, Manifest, MembershipView, Module, ModuleError, Request, Subject,
};
use passer_identity::{DeviceId, Identity};
use proptest::prelude::*;
use serde_json::{Value, json};

struct One(DeviceId);
impl MembershipView for One {
    fn is_member(&self, d: &DeviceId) -> bool {
        *d == self.0
    }
}

/// Counts how often it actually runs.
struct Counter(Arc<AtomicUsize>);

#[async_trait]
impl Module for Counter {
    fn manifest(&self) -> Manifest {
        let strict = json!({
            "type": "object",
            "properties": { "n": { "type": "integer", "minimum": 0, "maximum": 10 } },
            "required": ["n"],
            "additionalProperties": false
        });
        Manifest {
            module: "t".into(),
            version: "0".into(),
            capabilities: vec![
                Capability::call("t.read", "r", "r", Effect::Read, strict.clone()),
                Capability::call("t.secret", "s", "s", Effect::Sensitive, strict),
            ],
        }
    }
    async fn invoke(&self, _: Ctx, _: &str, input: Value) -> Result<Value, ModuleError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        // The schema guarantees this shape; a panic here would mean validation was skipped.
        let n = input["n"].as_i64().expect("validated");
        assert!((0..=10).contains(&n));
        Ok(json!({ "n": n }))
    }
}

/// Arbitrary JSON values, a few levels deep.
fn any_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| json!(n)),
        any::<f64>().prop_map(|f| json!(f)),
        ".{0,20}".prop_map(Value::String),
    ];
    leaf.prop_recursive(3, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::hash_map("[a-z]{0,4}", inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Any input to any capability name: a response, and the module runs only on inputs
    /// that match its schema, and never for the sensitive one (no approver here).
    #[test]
    fn any_request_gets_an_answer(
        capability in prop_oneof![Just("t.read".to_owned()), Just("t.secret".to_owned()), Just("bus.capabilities".to_owned()), ".{0,40}"],
        target in proptest::option::of(".{0,40}"),
        input in any_json(),
        agent in proptest::option::of("[a-z]{0,8}"),
    ) {
        let me = Identity::generate().id();
        let runs = Arc::new(AtomicUsize::new(0));
        let bus = Bus::builder(Arc::new(One(me))).module(Arc::new(Counter(runs.clone()))).build().unwrap();
        let req = Request { capability: capability.clone(), target, input, agent: agent.clone(), stream: false };
        let response = runtime().block_on(bus.handle(Subject { device: me, agent }, req));
        if capability == "t.secret" {
            prop_assert_eq!(runs.load(Ordering::SeqCst), 0, "sensitive ran without approval");
        }
        if response.code().is_none() && capability.starts_with("t.") {
            prop_assert_eq!(runs.load(Ordering::SeqCst), 1);
        }
        prop_assert_eq!(bus.journal().recent().len(), 1, "every request is journaled");
    }

    /// Strings that reach the journal never carry control characters (terminal injection).
    #[test]
    fn journal_fields_are_printable(capability in ".{0,120}", target in ".{0,300}") {
        let me = Identity::generate().id();
        let bus = Bus::builder(Arc::new(One(me))).build().unwrap();
        let req = Request { capability, target: Some(target), input: Value::Null, agent: None, stream: false };
        runtime().block_on(bus.handle(Subject::device(me), req));
        let line = bus.journal().recent().remove(0).record;
        prop_assert!(!line.capability.chars().any(char::is_control));
        prop_assert!(!line.target.unwrap_or_default().chars().any(char::is_control));
    }
}
