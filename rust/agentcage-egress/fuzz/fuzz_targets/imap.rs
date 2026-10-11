//! `cargo +nightly fuzz run imap`: see `agentcage_egress::fuzz_api::imap`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| agentcage_egress::fuzz_api::imap(data));
