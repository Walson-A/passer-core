#![no_main]
//! Any bytes received as a device log: decode, verify, compare, never panic.
use libfuzzer_sys::fuzz_target;
use passer_membership::DeviceLog;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(log) = DeviceLog::from_json(s) {
            if let Ok(m) = log.verify() {
                // A verified log prefers itself, and its prefixes lose to it.
                assert_eq!(log.prefer(&log), Ok(passer_membership::Preferred::Same));
                assert!(m.len as usize == log.entries().len());
                let half = log.prefix(log.entries().len() / 2);
                if half.verify().is_ok() && half.entries().len() < log.entries().len() {
                    assert_eq!(log.prefer(&half), Ok(passer_membership::Preferred::Ours));
                }
            }
        }
    }
});
