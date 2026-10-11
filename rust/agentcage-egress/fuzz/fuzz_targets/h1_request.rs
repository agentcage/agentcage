//! `cargo +nightly fuzz run h1_request`: see `agentcage_egress::fuzz_api::h1_request`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| agentcage_egress::fuzz_api::h1_request(data));
