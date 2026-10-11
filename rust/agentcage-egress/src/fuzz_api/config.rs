//! Loading config text and handing it to every section's parser.
//!
//! The config is written by the host, so it is not hostile the way a
//! peer's bytes are; but every parser here runs on a live reload, and a
//! panic there takes the egress (and the cage's network) down instead of
//! refusing the edit. So: arbitrary text never panics the loader or any
//! consumer, and what the shared YAML emitter writes, it reads back.

use std::sync::Arc;

use agentcage_core::yaml;

use crate::config::{Config, Value};
use crate::inject::Injector;
use crate::inspect::chain::{NoPlugins, build_chain};
use crate::inspect::domain::DomainInspector;
use crate::relays::{imap::ImapConfig, smtp::SmtpConfig, validate::validate_relay_entry};
use crate::watcher::WatcherConfig;

/// Load `data` as a config and parse every section of it.
pub fn config(data: &[u8]) {
    let text = String::from_utf8_lossy(data);

    // The host's PyYAML-compatible loader and emitter: a dumped value
    // loads back to one that dumps the same.
    if let Ok(value) = yaml::load(&text) {
        if let Ok(dumped) = yaml::dump(&value) {
            let back = yaml::load(&dumped).expect("the emitter's output loads");
            let again = yaml::dump(&back).expect("a loaded dump dumps");
            assert_eq!(again, dumped, "the emitter is not stable");
        }
    }

    let Ok(cfg) = Config::parse("fuzz", &text) else {
        return;
    };
    let _ = build_chain(&cfg, &Arc::new(DomainInspector::new()), &NoPlugins);
    let _ = crate::engine::parse_rate(&cfg);
    let _ = crate::audit::log_allowed(&cfg);
    let _ = crate::policy::decider_enabled(&cfg);
    let _ = WatcherConfig::parse(&cfg, &mut |_| {});
    // Secrets resolve to a stand-in: no file or environment is read.
    Injector::new().configure_with(
        cfg.get("secret_injection"),
        &|name| format!("value-of-{name}"),
        &crate::transforms::build,
    );
    if let Some(Value::Sequence(entries)) = cfg.get("protocol_relays") {
        for entry in entries {
            if validate_relay_entry(entry).is_ok() {
                let _ = ImapConfig::parse(entry);
                let _ = SmtpConfig::parse(entry);
            }
        }
    }
}
