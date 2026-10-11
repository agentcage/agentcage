//! `cargo +nightly fuzz run tls_detect`: see `agentcage_egress::fuzz_api::tls_detect`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| agentcage_egress::fuzz_api::tls_detect(data));
