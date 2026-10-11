//! Building the inspector chain a config describes.
//!
//! The order, and which config each inspector gets:
//!
//! 1. built-ins enabled by their legacy top-level keys, in registry order
//!    `domain, secrets, body-size, entropy, content-type`: `domain` and
//!    `secrets` always (they check their own config), `body-size` when
//!    `max_request_body` (default 10 MiB) is truthy, `entropy` when
//!    `entropy:` is a mapping, `content-type` unless `content_type:` is
//!    literally `false`;
//! 2. then each `inspectors:` entry in turn. A built-in by name (no
//!    `path`) that is already in the chain takes this entry's `config`
//!    *wholesale* — the section wins over the legacy key; otherwise it is
//!    appended. A plugin (`path:`) whose entry name is already in the
//!    chain also just takes the config; otherwise the plugin is loaded,
//!    and if the name it declares is already in the chain that slot
//!    takes the config instead; otherwise it is appended under its
//!    declared name. An entry that is neither is skipped with a warning.
//!
//! Each slot is configured once, with the config that won.
//!
//! A reload builds the same chain a fresh start with the new config
//! would. The built-ins are rebuilt from config each time — they hold no
//! runtime state — except the domain inspector, which carries the live
//! grants: the caller passes the one long-lived instance in, and it is
//! reconfigured in place, last, by [`PendingChain::commit`]. Plugins come
//! from a [`PluginLoader`], which owns compiling and caching them.
//!
//! Everything that can fail happens in [`build_chain`], before anything
//! live is touched: a config that does not build leaves the running
//! chain (and the domain baseline) exactly as it was.

use std::sync::Arc;

use agentcage_core::python::{str_of, type_name};

use super::body_size::BodySizeInspector;
use super::content_type::ContentTypeInspector;
use super::domain::{DomainConfig, DomainInspector};
use super::entropy::EntropyInspector;
use super::secrets::{RelaySecrets, SecretsInspector};
use super::{Action, Context, Inspector, Severity, Verdict};
use crate::config::{Config, Mapping, Value, truthy};

/// The built-in inspector names, in registry (chain) order.
pub const BUILTIN_NAMES: [&str; 5] = [
    super::domain::NAME,
    super::secrets::NAME,
    super::body_size::NAME,
    super::entropy::NAME,
    super::content_type::NAME,
];

/// `max_request_body`'s default: 10 MiB.
pub const DEFAULT_MAX_REQUEST_BODY: i64 = 10_485_760;

/// Loads custom inspectors (WebAssembly plugins) for the chain.
///
/// Two steps, because the chain's precedence rules need a plugin's
/// declared name before they know which config it will get: a plugin is
/// first [`declared_name`](Self::declared_name)d, and only the ones that
/// end up with a slot of their own are
/// [`instantiate`](Self::instantiate)d, once, with the winning config.
///
/// Either step failing fails the whole build, so a plugin that cannot be
/// loaded never leaves a chain running without it (D1).
pub trait PluginLoader {
    /// Load (or fetch from the loader's cache) the plugin at `path`,
    /// listed under `entry_name`, and return the name it declares.
    ///
    /// # Errors
    ///
    /// The path is refused (outside the plugin directory, not `.wasm`),
    /// missing, or not a valid plugin.
    fn declared_name(&self, entry_name: &str, path: &str) -> Result<String, String>;

    /// An inspector for the plugin at `path`, configured with `config`
    /// (the entry's `config:` value; null when absent).
    ///
    /// # Errors
    ///
    /// The plugin cannot be instantiated or its `configure` rejects
    /// `config`.
    fn instantiate(&self, path: &str, config: &Value) -> Result<Arc<dyn Inspector>, String>;
}

/// A [`PluginLoader`] for builds without plugin support: every plugin
/// fails to load, so a config that lists one fails closed.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPlugins;

impl PluginLoader for NoPlugins {
    fn declared_name(&self, entry_name: &str, path: &str) -> Result<String, String> {
        Err(format!(
            "custom inspector {entry_name:?} ({path}): plugins are not supported by this egress"
        ))
    }

    fn instantiate(&self, path: &str, _config: &Value) -> Result<Arc<dyn Inspector>, String> {
        Err(format!(
            "custom inspector {path}: plugins are not supported by this egress"
        ))
    }
}

/// Where a slot's inspector comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotKind {
    /// A built-in.
    Builtin,
    /// A plugin loaded from this `path:`.
    Plugin(String),
}

/// One position in the chain, as planned.
#[derive(Clone, Debug, PartialEq)]
pub struct Slot {
    /// The inspector's name.
    pub name: String,
    /// Built-in or plugin.
    pub kind: SlotKind,
    /// The config it was configured with (the winning one).
    pub config: Value,
}

/// A built chain that has not yet touched the live domain inspector.
#[derive(Debug)]
#[must_use = "a pending chain does nothing until committed"]
pub struct PendingChain {
    chain: Chain,
    domain_config: DomainConfig,
}

impl PendingChain {
    /// The chain as it will be after [`Self::commit`].
    #[must_use]
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    /// Apply the new domain baseline to the shared domain inspector and
    /// hand over the chain. Infallible.
    #[must_use]
    pub fn commit(self) -> Chain {
        self.chain.domain.apply_config(self.domain_config);
        self.chain
    }
}

/// An ordered inspector chain plus typed handles on the built-ins other
/// parts of the egress need.
#[derive(Clone, Debug)]
pub struct Chain {
    inspectors: Vec<Arc<dyn Inspector>>,
    slots: Vec<Slot>,
    domain: Arc<DomainInspector>,
    secrets: Arc<SecretsInspector>,
    warnings: Vec<String>,
}

impl Chain {
    /// The inspectors, in order, for [`super::run_chain`].
    #[must_use]
    pub fn inspectors(&self) -> &[Arc<dyn Inspector>] {
        &self.inspectors
    }

    /// The plan: each slot's name, kind and winning config, in order.
    #[must_use]
    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    /// The inspector names, in order.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.slots.iter().map(|s| s.name.as_str()).collect()
    }

    /// The shared domain inspector (always in the chain).
    #[must_use]
    pub fn domain(&self) -> &Arc<DomainInspector> {
        &self.domain
    }

    /// The secrets inspector (always in the chain).
    #[must_use]
    pub fn secrets(&self) -> &Arc<SecretsInspector> {
        &self.secrets
    }

    /// Entries that were skipped, for the caller to log:
    /// `skipping unknown inspector: <name>`.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// True for the slot that must not run on reverse-proxied (inbound)
    /// traffic: the domain inspector, which judges the upstream host.
    #[must_use]
    pub fn is_domain(&self, inspector: &dyn Inspector) -> bool {
        std::ptr::addr_eq(
            std::ptr::from_ref(inspector),
            Arc::as_ptr(&self.domain).cast::<()>(),
        )
    }

    /// The chain handed to protocol relays: the domain inspector removed
    /// (it is HTTP-host shaped; SMTP has `recipient_allowlist` instead)
    /// and the secrets inspector wrapped in [`RelaySecrets`], so a leak
    /// in a mail blocks unless the operator chose the action explicitly.
    #[must_use]
    pub fn relay_inspectors(&self) -> Vec<Arc<dyn Inspector>> {
        self.inspectors
            .iter()
            .zip(&self.slots)
            .filter_map(|(inspector, slot)| match (&slot.kind, slot.name.as_str()) {
                (SlotKind::Builtin, super::domain::NAME) => None,
                (SlotKind::Builtin, super::secrets::NAME) => {
                    Some(Arc::new(RelaySecrets::new(Arc::clone(&self.secrets)))
                        as Arc<dyn Inspector>)
                }
                _ => Some(Arc::clone(inspector)),
            })
            .collect()
    }

    /// A chain that blocks every request, for when no config has ever
    /// built (a boot whose config fails): the domain inspector is kept
    /// so the Policy API still has it, and `reason` is in every 403.
    /// Relays get the same refusal through [`Self::relay_inspectors`].
    ///
    /// # Panics
    ///
    /// Never: the secrets inspector's defaults always build.
    #[must_use]
    pub fn refuse_all(domain: Arc<DomainInspector>, reason: &str) -> Self {
        let refuse: Arc<dyn Inspector> = Arc::new(RefuseAll {
            reason: format!("egress inspector chain failed to load: {reason}"),
        });
        Self {
            inspectors: vec![refuse],
            slots: vec![Slot {
                name: REFUSE_ALL.to_owned(),
                kind: SlotKind::Builtin,
                config: Value::Null,
            }],
            domain,
            secrets: Arc::new(
                SecretsInspector::from_config(&Value::Null).expect("defaults always build"),
            ),
            warnings: Vec::new(),
        }
    }
}

const REFUSE_ALL: &str = "chain";

/// The single inspector of [`Chain::refuse_all`].
#[derive(Debug)]
struct RefuseAll {
    reason: String,
}

impl Inspector for RefuseAll {
    fn name(&self) -> &str {
        REFUSE_ALL
    }

    fn inspect_request(&self, _ctx: &Context) -> Option<Verdict> {
        Some(Verdict::new(
            REFUSE_ALL,
            Action::Block,
            self.reason.clone(),
            Severity::Critical,
        ))
    }

    fn inspect_response(&self, ctx: &Context) -> Option<Verdict> {
        self.inspect_request(ctx)
    }
}

/// `_build_legacy_config`: the built-ins the legacy top-level keys
/// enable, each with its config, in registry order.
#[must_use]
pub fn legacy_sections(cfg: &Config) -> Vec<(&'static str, Value)> {
    let mut out = Vec::new();
    let get = |k| cfg.get(k).cloned();
    out.push((
        super::domain::NAME,
        get("domains").unwrap_or_else(empty_mapping),
    ));
    out.push((
        super::secrets::NAME,
        get("secrets").unwrap_or_else(empty_mapping),
    ));
    let max_body = get("max_request_body").unwrap_or_else(|| Value::from(DEFAULT_MAX_REQUEST_BODY));
    if truthy(&max_body) {
        let mut m = Mapping::new();
        m.insert(Value::from("max_bytes"), max_body);
        out.push((super::body_size::NAME, Value::Mapping(m)));
    }
    if let Some(entropy @ Value::Mapping(_)) = cfg.get("entropy") {
        out.push((super::entropy::NAME, entropy.clone()));
    }
    match cfg.get("content_type") {
        Some(Value::Bool(false)) => {}
        Some(ct @ Value::Mapping(_)) => out.push((super::content_type::NAME, ct.clone())),
        _ => out.push((super::content_type::NAME, empty_mapping())),
    }
    out
}

fn empty_mapping() -> Value {
    Value::Mapping(Mapping::new())
}

/// The planned chain: slots in order, before anything is built.
///
/// # Errors
///
/// `inspectors:` is not a list or an entry is not a mapping, or a
/// plugin's [`PluginLoader::declared_name`] fails.
pub fn plan(cfg: &Config, plugins: &dyn PluginLoader) -> Result<(Vec<Slot>, Vec<String>), String> {
    let mut slots: Vec<Slot> = legacy_sections(cfg)
        .into_iter()
        .map(|(name, config)| Slot {
            name: name.to_owned(),
            kind: SlotKind::Builtin,
            config,
        })
        .collect();
    let mut warnings = Vec::new();

    let entries: &[Value] = match cfg.get("inspectors") {
        None => &[],
        Some(v) if !truthy(v) => &[],
        Some(Value::Sequence(entries)) => entries,
        Some(v) => {
            return Err(format!("inspectors must be a list (got {})", type_name(v)));
        }
    };
    // `next(s for s in plan if name and s.name == name)`.
    let slot_named = |slots: &[Slot], name: &str| {
        if name.is_empty() {
            None
        } else {
            slots.iter().position(|s| s.name == name)
        }
    };
    for entry in entries {
        let Value::Mapping(entry) = entry else {
            return Err(format!(
                "inspectors entries must be mappings (got {})",
                type_name(entry)
            ));
        };
        let name = entry.get("name").map(str_of).unwrap_or_default();
        let path = entry.get("path").filter(|p| truthy(p)).map(str_of);
        let config = entry.get("config").cloned().unwrap_or_else(empty_mapping);

        match path {
            None if BUILTIN_NAMES.contains(&name.as_str()) => {
                if let Some(i) = slot_named(&slots, &name) {
                    slots[i].config = config;
                } else {
                    slots.push(Slot {
                        name,
                        kind: SlotKind::Builtin,
                        config,
                    });
                }
            }
            Some(path) => {
                if let Some(i) = slot_named(&slots, &name) {
                    slots[i].config = config;
                    continue;
                }
                let declared = plugins.declared_name(&name, &path)?;
                if let Some(i) = slot_named(&slots, &declared) {
                    slots[i].config = config;
                    continue;
                }
                slots.push(Slot {
                    name: declared,
                    kind: SlotKind::Plugin(path),
                    config,
                });
            }
            None => warnings.push(format!("skipping unknown inspector: {name}")),
        }
    }
    Ok((slots, warnings))
}

/// Build the chain `cfg` describes around the long-lived `domain`
/// inspector. Nothing live changes until the result is committed.
///
/// # Errors
///
/// Any inspector's config is refused, or a plugin fails to load or
/// configure. The message names the inspector.
pub fn build_chain(
    cfg: &Config,
    domain: &Arc<DomainInspector>,
    plugins: &dyn PluginLoader,
) -> Result<PendingChain, String> {
    let (slots, warnings) = plan(cfg, plugins)?;
    let mut inspectors: Vec<Arc<dyn Inspector>> = Vec::with_capacity(slots.len());
    let mut domain_config = None;
    let mut secrets = None;
    for slot in &slots {
        let built: Arc<dyn Inspector> = match (&slot.kind, slot.name.as_str()) {
            (SlotKind::Plugin(path), _) => plugins.instantiate(path, &slot.config)?,
            (SlotKind::Builtin, super::domain::NAME) => {
                domain_config = Some(DomainConfig::parse(&slot.config)?);
                Arc::clone(domain) as Arc<dyn Inspector>
            }
            (SlotKind::Builtin, super::secrets::NAME) => {
                let s = Arc::new(SecretsInspector::from_config(&slot.config)?);
                secrets = Some(Arc::clone(&s));
                s
            }
            (SlotKind::Builtin, super::body_size::NAME) => {
                Arc::new(BodySizeInspector::from_config(&slot.config)?)
            }
            (SlotKind::Builtin, super::entropy::NAME) => {
                Arc::new(EntropyInspector::from_config(&slot.config)?)
            }
            (SlotKind::Builtin, super::content_type::NAME) => {
                Arc::new(ContentTypeInspector::from_config(&slot.config)?)
            }
            (SlotKind::Builtin, other) => unreachable!("planned unknown built-in {other}"),
        };
        inspectors.push(built);
    }
    // Both are legacy-enabled unconditionally, so always planned.
    let (Some(domain_config), Some(secrets)) = (domain_config, secrets) else {
        unreachable!("domain and secrets are always in the chain");
    };
    Ok(PendingChain {
        chain: Chain {
            inspectors,
            slots,
            domain: Arc::clone(domain),
            secrets,
            warnings,
        },
        domain_config,
    })
}

#[cfg(test)]
mod tests {
    use super::super::{Phase, run_chain};
    use super::*;

    fn cfg(text: &str) -> Config {
        Config::parse("t", text).unwrap()
    }

    fn ctx(host: &str, body: &str) -> Context {
        Context {
            url: format!("https://{host}/"),
            host: host.to_owned(),
            body_text: Some(body.to_owned()),
            body_bytes: Some(body.as_bytes().to_vec()),
            body_size: body.len(),
            ..Context::default()
        }
    }

    fn build(domain: &Arc<DomainInspector>, text: &str) -> Result<PendingChain, String> {
        build_chain(&cfg(text), domain, &NoPlugins)
    }

    #[test]
    fn a_rebuild_keeps_the_domain_instance_and_its_grants() {
        let domain = Arc::new(DomainInspector::new());
        let first = build(&domain, "domains: {allow: [a.com]}\n")
            .unwrap()
            .commit();
        assert!(domain.grant("g.com", "", "", ""));
        let second = build(&domain, "domains: {allow: [b.com]}\nentropy: {}\n")
            .unwrap()
            .commit();
        assert!(Arc::ptr_eq(first.domain(), second.domain()));
        assert!(second.is_domain(second.inspectors()[0].as_ref()));
        assert!(!second.is_domain(second.inspectors()[1].as_ref()));
        assert!(domain.is_granted("g.com"));
        assert!(domain.matches_baseline("b.com"));
        assert!(!domain.matches_baseline("a.com"));
        assert_eq!(
            second.names(),
            ["domain", "secrets", "body-size", "entropy", "content-type"]
        );
    }

    #[test]
    fn a_failed_build_touches_nothing_live() {
        let domain = Arc::new(DomainInspector::new());
        drop(
            build(&domain, "domains: {allow: [a.com]}\n")
                .unwrap()
                .commit(),
        );
        // The domain section parses, the entropy one does not (Python took
        // the string and raised on every request instead): the domain
        // baseline must not move, because nothing was committed.
        let bad = "domains: {allow: [b.com]}\nentropy: {threshold: high}\n";
        assert!(build(&domain, bad).is_err());
        assert!(domain.matches_baseline("a.com"));
        // Nor does a build that is never committed.
        let pending = build(&domain, "domains: {allow: [c.com]}\n").unwrap();
        assert_eq!(pending.chain().names()[0], "domain");
        drop(pending);
        assert!(domain.matches_baseline("a.com"));
    }

    #[test]
    fn plugins_without_a_loader_fail_closed() {
        let domain = Arc::new(DomainInspector::new());
        let err = build(
            &domain,
            "inspectors:\n  - {name: x, path: /etc/agentcage/inspectors/x.wasm}\n",
        )
        .unwrap_err();
        assert!(err.contains("not supported"), "{err}");
    }

    #[test]
    fn refuse_all_blocks_everything_and_keeps_the_domain() {
        let domain = Arc::new(DomainInspector::new());
        let chain = Chain::refuse_all(Arc::clone(&domain), "bad entropy config");
        let mut c = ctx("a.com", "");
        let out = run_chain(chain.inspectors(), &mut c, Phase::Request, &|_| false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].action, Action::Block);
        assert_eq!(
            out[0].reason,
            "egress inspector chain failed to load: bad entropy config"
        );
        assert!(Arc::ptr_eq(chain.domain(), &domain));
    }

    #[test]
    fn the_relay_chain_blocks_secrets_unless_the_action_is_explicit() {
        let domain = Arc::new(DomainInspector::new());
        let leak = ctx("relay.local", "access_key=AKIAIOSFODNN7EXAMPLE");
        for (yaml, want) in [
            ("secrets: {}\n", Action::Block),
            ("secrets: {action: flag}\n", Action::Flag),
            (
                "inspectors:\n  - {name: secrets, config: {action: flag}}\n",
                Action::Flag,
            ),
        ] {
            let chain = build(&domain, yaml).unwrap().commit();
            let http = chain.secrets().inspect_request(&leak).unwrap();
            assert_eq!(http.action, Action::Flag, "{yaml}");
            let relay = chain.relay_inspectors();
            assert!(relay.iter().all(|i| i.name() != "domain"));
            let secrets = relay.iter().find(|i| i.name() == "secrets").unwrap();
            assert_eq!(
                secrets.inspect_request(&leak).unwrap().action,
                want,
                "{yaml}"
            );
        }
    }
}
