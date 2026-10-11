//! `cargo +nightly fuzz run redact_stream`: see `agentcage_egress::fuzz_api::redact_stream`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| agentcage_egress::fuzz_api::redact_stream(data));
