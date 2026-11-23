#![no_main]
//! Any bytes received as a request, a join request or a policy: decode, never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<passer_bus::Request>(data);
    let _ = serde_json::from_slice::<passer_bus::Response>(data);
    let _ = serde_json::from_slice::<passer_membership::pairing::JoinRequest>(data);
    if let Ok(policy) = serde_json::from_slice::<passer_bus::Policy>(data) {
        let me = passer_identity::Identity::from_secret_bytes(&[1; 32]).id();
        let _ = policy.evaluate(&passer_bus::Subject::device(me), "a.b", Some("t"), passer_bus::Effect::Sensitive);
    }
});
