//! `cargo +nightly fuzz run config`: see `agentcage_egress::fuzz_api::config`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| agentcage_egress::fuzz_api::config(data));
