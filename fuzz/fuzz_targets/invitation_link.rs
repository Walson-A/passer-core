#![no_main]
//! Any string scanned from a QR code: parse or refuse, never panic.
use libfuzzer_sys::fuzz_target;
use passer_membership::pairing::Invitation;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(inv) = Invitation::parse_link(s) {
            // What parses must round-trip.
            assert_eq!(Invitation::parse_link(&inv.to_link()), Ok(inv));
        }
    }
});
