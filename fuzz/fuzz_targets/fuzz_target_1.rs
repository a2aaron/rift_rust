#![no_main]

use libfuzzer_sys::fuzz_target;

use rift_rust::packet::parse_security_envelope;

fuzz_target!(|data: &[u8]| {
    parse_security_envelope(data);
});
