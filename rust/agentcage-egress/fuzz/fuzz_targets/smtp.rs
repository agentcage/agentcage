//! `cargo +nightly fuzz run smtp`: see `agentcage_egress::fuzz_api::smtp`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| agentcage_egress::fuzz_api::smtp(data));
