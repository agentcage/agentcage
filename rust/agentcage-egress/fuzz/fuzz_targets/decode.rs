//! `cargo +nightly fuzz run decode`: see `agentcage_egress::fuzz_api::decode`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| agentcage_egress::fuzz_api::decode(data));
