//! `cargo +nightly fuzz run h1_response`: see `agentcage_egress::fuzz_api::h1_response`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| agentcage_egress::fuzz_api::h1_response(data));
