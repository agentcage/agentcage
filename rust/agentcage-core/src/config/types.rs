//! The `cage.yaml` type tree — one Rust type per `config.py` dataclass.
//!
//! Every struct here mirrors a `@dataclass` in `src/agentcage/config.py`,
//! field for field and name for name, and every [`Default`] impl is that
//! dataclass's field defaults. The comments are ported with the code:
//! where one explains a Python-specific mechanism it is rewritten rather
//! than dropped, because the *reason* usually outlives the language.
//!
//! # Where a default is not what [`Default`] says
//!
//! Four of these defaults are never the value a real config gets,
//! because `load_config` computes something else before the struct is
//! built. They are listed on the fields, and collected here because a
//! reader who trusts `Default` alone will be wrong about all four:
//!
//! | Field | `Default` | what `load_config` actually does |
//! | :-- | :-- | :-- |
//! | [`Config::isolation`] | `"container"` | the host probe — Linux `container`, macOS `vm` or `apple-container` |
//! | [`Config::dns_servers`] | empty | the host's non-loopback resolvers, read from `resolv.conf` |
//! | [`ContainerConfig::timeout_start_sec`] | `600` | **`120`** — the dataclass default is dead code |
//! | [`SecretsConfig::scope`] | `"auto"` | stays `"auto"` here; `secret_resolver` resolves it at deploy time |
//!
//! The third is not a subtlety, it is a discrepancy in `config.py`:
//! `ContainerConfig.timeout_start_sec = 600` and `load_config` writes
//! `c.get("timeout_start_sec", 120)`. Since `load_config` is the only
//! way a `Config` is ever built from a file, 120 is the number users
//! get, and the golden corpus records 120. Both are reproduced —
//! `Default` keeps 600 so the type is a faithful mirror, and the parser
//! keeps 120 so behaviour is faithful. Do not "fix" one to match the
//! other without changing `config.py` first.

use indexmap::IndexMap;

use crate::yaml::Mapping;

/// An ordered string map, standing in for a Python `dict`.
///
/// Insertion order is load-bearing: `save_raw_config` dumps with
/// `sort_keys=False`, `cage edit` shows the user their own key order,
/// and `quadlets.py` emits one `Environment=` line per entry in `dict`
/// order. A `BTreeMap` would silently re-sort all three.
pub type OrderedMap<V> = IndexMap<String, V>;

/// `SecretsConfig` — at-rest storage for the cage's secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretsConfig {
    /// At-rest storage backend: `auto` picks the best encrypting
    /// backend for the platform (Linux: systemd-creds). Explicit:
    /// `systemd-creds`, `system-keychain` (macOS), `plaintext`.
    pub backend: String,
    /// `auto` | `user` | `system` (systemd-creds only).
    pub scope: String,
    /// When no encrypting backend is available, agentcage refuses to
    /// store secrets as cleartext (fail-closed). Set this to true to
    /// explicitly opt into the unencrypted podman secret store under
    /// `backend: auto`.
    pub allow_plaintext: bool,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            backend: "auto".to_owned(),
            scope: "auto".to_owned(),
            allow_plaintext: false,
        }
    }
}

/// `SecretInjectionRule` — one placeholder-to-credential rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretInjectionRule {
    /// The environment variable name the cage sees.
    pub env: String,
    /// Empty means "not yet generated": rules may omit `placeholder:`
    /// in cage.yaml, and the CLI persists a generated token into the
    /// stored config at declare time (create/update/edit) — see
    /// `config.fill_raw_placeholders`. Consumers that render or inject
    /// placeholders skip rules whose placeholder is still empty.
    pub placeholder: String,
    /// Domains this rule's real value may be substituted into.
    pub inject_to: Vec<String>,
    /// Where the real value comes from: `env:` / `cmd:` / `podman:` /
    /// `systemd-creds:`.
    pub source: String,
    /// Optional transform applied to the resolved value.
    pub transform: String,
    /// The transform's own settings, kept raw for the proxy to read.
    pub transform_config: Mapping,
    /// Strict by default: only substitute placeholders found in a
    /// credential-bearing request header — one whose name contains
    /// "auth", "key", or "token" (Authorization, x-api-key, `*-token`,
    /// …). Set `inject_body: true` to also inject into the request URL
    /// and body (the legacy, looser behavior).
    pub inject_body: bool,
    /// Extra request headers to treat as credential-bearing under the
    /// strict default — for auth headers whose name doesn't match the
    /// keyword heuristic (e.g. `x-honeycomb-team`). Matched
    /// case-insensitively.
    pub inject_headers: Vec<String>,
}

/// `BuildConfig` — build the workload image instead of pulling it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuildConfig {
    /// Path to the Containerfile, relative to the config.
    pub containerfile: String,
    /// `--build-arg` values.
    pub args: OrderedMap<String>,
}

/// `ContainerConfig` — the workload container itself.
///
/// The six booleans are `config.py`'s six, with its names; grouping
/// them into an enum would make this type stop being a mirror of the
/// dataclass and start being an interpretation of it.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerConfig {
    /// Image reference, or the tag `build` produces.
    pub image: String,
    /// Entrypoint argv.
    pub command: Vec<String>,
    /// `host:container[:options]` bind mounts.
    pub volumes: Vec<String>,
    /// Named podman volumes, `name: /mount/point`.
    pub named_volumes: OrderedMap<String>,
    /// tmpfs mounts, `/path[:options]`.
    pub tmpfs: Vec<String>,
    /// Inbound port publishes, `[BIND:]HOST:CONTAINER`.
    pub ports: Vec<String>,
    /// podman secrets mounted into the workload.
    pub podman_secrets: Vec<String>,
    /// Environment for the workload.
    pub env: OrderedMap<String>,
    /// Default `1000:1000`; an empty string means "use the image's own
    /// user".
    pub user: String,
    /// `--memory`.
    pub memory: String,
    /// `--cpus`.
    pub cpus: String,
    /// Read-only rootfs.
    pub read_only: bool,
    /// Capabilities to drop; `["ALL"]` by default.
    pub drop_capabilities: Vec<String>,
    /// Capabilities to add back.
    pub add_capabilities: Vec<String>,
    /// `--security-opt no-new-privileges`.
    pub no_new_privileges: bool,
    /// Run podman inside the cage.
    pub nested_containers: bool,
    /// `--security-opt label=disable`.
    pub security_label_disable: bool,
    /// e.g. `keep-id` to map the host UID into the container.
    pub userns: String,
    /// Build instead of pull.
    pub build: BuildConfig,
    /// systemd `Restart=`.
    pub restart: String,
    /// systemd `RestartSec=`.
    pub restart_sec: i64,
    /// systemd `TimeoutStartSec=`. **`load_config` defaults this to
    /// 120, not to the 600 below** — see the module docs.
    pub timeout_start_sec: i64,
    /// systemd `TimeoutStopSec=`.
    pub timeout_stop_sec: i64,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            image: String::new(),
            command: Vec::new(),
            volumes: Vec::new(),
            named_volumes: OrderedMap::new(),
            tmpfs: Vec::new(),
            ports: Vec::new(),
            podman_secrets: Vec::new(),
            env: OrderedMap::new(),
            user: "1000:1000".to_owned(),
            memory: String::new(),
            cpus: String::new(),
            read_only: true,
            drop_capabilities: vec!["ALL".to_owned()],
            add_capabilities: Vec::new(),
            no_new_privileges: true,
            nested_containers: false,
            security_label_disable: true,
            userns: String::new(),
            build: BuildConfig::default(),
            restart: "on-failure".to_owned(),
            restart_sec: 10,
            timeout_start_sec: 600,
            timeout_stop_sec: 30,
        }
    }
}

/// The five `logging.level` values, in increasing severity.
pub const VALID_LOG_LEVELS: [&str; 5] = ["debug", "info", "warning", "error", "critical"];

/// `LoggingConfig` — what the egress and the cage log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoggingConfig {
    /// Log every DNS query dnsmasq answers.
    pub dns_queries: bool,
    /// Log every connection the proxy accepts.
    pub proxy_connections: bool,
    /// Log allowed requests, not only denied ones.
    pub allowed_requests: bool,
    /// Global default minimum level.
    pub level: String,
    /// Per-service override (empty = inherit from `level`).
    pub dns: String,
    /// Per-service override for the proxy.
    pub proxy: String,
    /// Per-service override for the cage.
    pub cage: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            dns_queries: false,
            proxy_connections: false,
            allowed_requests: false,
            level: "info".to_owned(),
            dns: String::new(),
            proxy: String::new(),
            cage: String::new(),
        }
    }
}

impl LoggingConfig {
    /// The effective minimum level for one service.
    ///
    /// `config.py` does this with `getattr(self, service, "")`, so an
    /// unknown service name silently inherits the global level. The
    /// three real names are spelled out here instead; an unknown one
    /// still inherits, which is the same answer without the reflection.
    #[must_use]
    pub fn level_for(&self, service: &str) -> &str {
        let override_level = match service {
            "dns" => self.dns.as_str(),
            "proxy" => self.proxy.as_str(),
            "cage" => self.cage.as_str(),
            _ => "",
        };
        if override_level.is_empty() {
            &self.level
        } else {
            override_level
        }
    }
}

/// `DomainConfig` — the cage's egress domain policy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DomainConfig {
    /// `allowlist` | `blocklist` | `""` — derived from allow/block.
    pub mode: String,
    /// Domains the cage may reach (allowlist mode).
    pub allow: Vec<String>,
    /// Domains the cage may not reach (blocklist mode).
    pub block: Vec<String>,
    /// Domains forwarded without inspection.
    pub passthrough: Vec<String>,
    /// Per-domain expiry (allowlist mode): domain → ISO-8601
    /// `expires_at`. Absent key (or empty value) = permanent. Backward
    /// compatible: an operator who never uses `--expires-in` has an
    /// empty map and zero behavior change. Enforced two ways: the L7
    /// `DomainInspector` blocks an expired domain in-process (immediate,
    /// robust regardless of any host command), and in-egress the
    /// addon's own TTL sweeper drops an expired grant and re-publishes
    /// the zone list so dnsmasq stops forwarding it. Static-baseline
    /// entries with `expires` (`domain add --expires-in`) are pruned
    /// lazily by the `cage grants sync` / `domain list` reconcile. See
    /// docs/explain/policy-api.md §expiry.
    pub expires: OrderedMap<String>,
}

impl DomainConfig {
    /// The active domain list (allow or block), for backward compat.
    #[must_use]
    pub fn list(&self) -> &[String] {
        match self.mode.as_str() {
            "allowlist" => &self.allow,
            "blocklist" => &self.block,
            _ => &[],
        }
    }
}

/// `MAX_CAPTURE_BODY_BYTES` — 10 MB.
pub const MAX_CAPTURE_BODY_BYTES: i64 = 10_485_760;

/// `MAX_CAPTURE_FILE_BYTES` — 128 MB.
///
/// Per-file cap before `capture.jsonl` rolls over to `capture.jsonl.1`,
/// so the on-disk ceiling is twice this. Unbounded growth was the
/// actual failure mode: a body-heavy cage wrote 222 MB in 20 minutes,
/// which fills the volume and leaves the watcher's byte-offset tail
/// unable to ever catch up. 0 disables rotation.
pub const MAX_CAPTURE_FILE_BYTES: i64 = 134_217_728;

/// `CaptureConfig` — full request/response capture for `cage har`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureConfig {
    /// Write `capture.jsonl` at all.
    pub enable_har: bool,
    /// Per-body truncation point.
    pub max_body_size: i64,
    /// Per-file rotation point; 0 disables rotation.
    pub max_file_size: i64,
    /// `all` | `flag` | `block` — the least severe action captured.
    pub min_action: String,
    /// Capture only these domains, when non-empty.
    pub domains: Vec<String>,
    /// Never capture these domains.
    pub exclude_domains: Vec<String>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            enable_har: false,
            max_body_size: MAX_CAPTURE_BODY_BYTES,
            max_file_size: MAX_CAPTURE_FILE_BYTES,
            min_action: "all".to_owned(),
            domains: Vec::new(),
            exclude_domains: Vec::new(),
        }
    }
}

/// Default permitted destination ports for `ports.tcp.allow`.
///
/// Catches HTTP and HTTPS on standard ports. Extend (e.g. add 8448 for
/// a Matrix homeserver) to permit non-standard services. Ports outside
/// the effective port policy are dropped by the proxy's filter:FORWARD
/// policy.
pub const DEFAULT_TCP_ALLOW_PORTS: [i64; 2] = [80, 443];

/// Ports reserved by mitmdump's own listeners.
///
/// Redirecting them would either loop (8443 is the transparent
/// listener's own port) or break the L7 `HTTP_PROXY` path (8080 is the
/// regular HTTP-proxy listener). Applied only to inspected TCP ports
/// (= `tcp.allow` - `tcp.passthrough`); passthrough entries never get a
/// REDIRECT rule and don't conflict.
pub const MITMDUMP_RESERVED_PORTS: [i64; 2] = [8080, 8443];

/// `TcpPortsConfig` — TCP egress port policy.
///
/// - `allow` — TCP destination ports the cage may reach. Anything not
///   in allow (and not in passthrough, which is implicitly allowed) is
///   dropped by the proxy's filter:FORWARD policy.
/// - `passthrough` — subset of allowed TCP ports that bypass mitmdump
///   inspection. These flow L3-forwarded to upstream without entering
///   `audit.jsonl`, the inspector chain, or the secret injector.
///
/// Inspected TCP ports = allow - passthrough.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpPortsConfig {
    /// Allowed destination ports.
    pub allow: Vec<i64>,
    /// Allowed ports that skip inspection.
    pub passthrough: Vec<i64>,
}

impl Default for TcpPortsConfig {
    fn default() -> Self {
        Self {
            allow: DEFAULT_TCP_ALLOW_PORTS.to_vec(),
            passthrough: Vec::new(),
        }
    }
}

/// `UdpPortsConfig` — UDP egress port policy.
///
/// - `allow` — UDP destination ports the cage may reach. UDP is never
///   inspected (mitmdump is HTTP-only); all entries are forwarded
///   uninspected. Ports not in allow are dropped by filter:FORWARD.
///
/// Defaults to empty. HTTP/3 (UDP/443), NTP (UDP/123), and any other
/// UDP-using protocol requires an explicit entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UdpPortsConfig {
    /// Allowed destination ports.
    pub allow: Vec<i64>,
}

/// `IcmpPortsConfig` — outbound ICMP (echo-request / `ping`) policy.
///
/// - `allow` — when true, the egress installs a `filter:FORWARD -p icmp
///   --icmp-type echo-request ACCEPT` rule so the cage can `ping` out
///   for diagnostics; replies ride the `ESTABLISHED,RELATED` rule. When
///   false (the default) no such rule is installed and the default-deny
///   FORWARD policy drops outbound echo-request — for every in-cage
///   privilege level, including `--as-root` (which holds `CAP_NET_RAW`
///   but cannot reach the egress's FORWARD chain).
///
/// Defaults to false: ICMP is OFF unless explicitly opted in. This does
/// NOT affect path-MTU discovery — the ICMP `fragmentation-needed`
/// errors arrive as `RELATED` to an existing TCP flow and ride the
/// `ESTABLISHED,RELATED` rule regardless of this knob.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IcmpPortsConfig {
    /// Permit outbound echo-request.
    pub allow: bool,
}

/// `PortsConfig` — cage egress port policy, split by protocol.
///
/// Layered on a default-deny filter:FORWARD policy (always installed,
/// no opt-out flag): every cage drops L4 traffic not explicitly allowed
/// here. Outbound ICMP echo-request is opt-in via `ports.icmp.allow`
/// (default false). A separate `ip6tables -P FORWARD DROP` failsafe
/// blocks all IPv6 forwarding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortsConfig {
    /// TCP policy.
    pub tcp: TcpPortsConfig,
    /// UDP policy.
    pub udp: UdpPortsConfig,
    /// ICMP policy.
    pub icmp: IcmpPortsConfig,
}

/// `VmConfig` — the Lima guest, for `isolation: vm`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmConfig {
    /// Guest vCPUs.
    pub vcpus: i64,
    /// Guest memory, in MiB.
    pub mem_mb: i64,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            vcpus: 4,
            mem_mb: 4096,
        }
    }
}

/// `RelayUpstream` — where a protocol relay connects out to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayUpstream {
    /// Upstream host.
    pub host: String,
    /// Upstream port.
    pub port: i64,
    /// Use TLS to the upstream.
    pub tls: bool,
    /// Path to a PEM certificate on the host, added to the proxy's
    /// system CA store for this upstream. For upstreams no public CA
    /// signs: a private-CA mail server, or a local decrypting daemon
    /// like Proton Mail Bridge that mints its own self-signed
    /// certificate. Read at deploy time and delivered to the proxy as
    /// `ca_pem`.
    pub ca_file: String,
    /// The resolved inline form `ca_file` becomes, and what the relay
    /// actually loads. Accepted directly in config too.
    pub ca_pem: String,
    /// Name presented in SNI and checked against the certificate, when
    /// it differs from `host` — required whenever `host` is an IP
    /// literal.
    pub tls_servername: String,
}

impl Default for RelayUpstream {
    fn default() -> Self {
        // `config.py` builds this one as `RelayUpstream("", 0)`, so the
        // positional defaults are an empty host and port 0.
        Self {
            host: String::new(),
            port: 0,
            tls: true,
            ca_file: String::new(),
            ca_pem: String::new(),
            tls_servername: String::new(),
        }
    }
}

/// `RelayAuth` — the relay's credentials, resolved egress-side.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayAuth {
    /// e.g. `imap-login`.
    pub r#type: String,
    /// Source scheme (`env:` / `cmd:` / `systemd-creds:`).
    pub user_source: String,
    /// Source scheme for the password.
    pub password_source: String,
}

/// `RelayRecipientAllowlist` — the SMTP recipient gate.
///
/// Empty = allow any recipient (insecure; explicit acknowledgement
/// only). When non-empty, a RCPT TO is accepted iff its address matches
/// an entry in `addresses` or its domain matches an entry in `domains`
/// (suffix-aware so `foo.example.com` matches an `example.com` domain
/// entry).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayRecipientAllowlist {
    /// Exact addresses.
    pub addresses: Vec<String>,
    /// Domains, suffix-matched.
    pub domains: Vec<String>,
}

/// `RelayPolicy` — what a relay lets through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayPolicy {
    /// Connection rate limit, common to every relay type.
    pub conn_rate_limit: String,
    /// Maximum time the relay waits between commands before
    /// disconnecting an idle session. 0 disables. Defaults differ per
    /// relay type: SMTP=300 (5 min, RFC 5321 §4.5.3.2), IMAP=1800 (30
    /// min, to permit IDLE heartbeats RFC 2177) — applied by the relay
    /// itself, not here, which is why this defaults to 0.
    pub idle_timeout_seconds: i64,
    /// IMAP: refuse everything that writes.
    pub readonly: bool,
    /// IMAP: `none` | `organise` | `full`. Empty means "derive from
    /// `readonly`", which the proxy does, so old configs are untouched.
    pub write_mode: String,
    /// IMAP: folders the cage may open.
    pub folder_allowlist: Vec<String>,
    /// IMAP: denied outright; denial wins over the allowlist.
    pub folder_denylist: Vec<String>,
    /// SMTP: permitted envelope senders.
    pub sender_allowlist: Vec<String>,
    /// SMTP: the recipient gate.
    pub recipient_allowlist: RelayRecipientAllowlist,
    /// SMTP: maximum message size.
    pub max_message_bytes: i64,
    /// SMTP: maximum recipients per message.
    pub max_recipients: i64,
    /// SMTP: message rate limit.
    pub send_rate_limit: String,
    /// Inspectors to skip when the `recipient_allowlist` is non-empty
    /// and every recipient matched it. The threat model assumes the
    /// allowlist names trusted destinations, so legitimate user content
    /// that trips `secrets`, `entropy`, or `content-type` (forwarded
    /// calendar invites, recovery codes, base64 attachments, PGP-signed
    /// plaintext, long URLs) is allowed through. `body-size` still
    /// applies as a structural cap. Set to `[]` to keep strict behavior
    /// even for trusted recipients. `content-type` is a more aggressive
    /// bypass than `secrets`/`entropy` because it catches legitimate
    /// base64-in-text/plain content email clients routinely produce;
    /// for HTTP that's an exfil signal, for email it's noise.
    pub bypass_inspectors_for_allowlisted: Vec<String>,
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self {
            conn_rate_limit: "30/min".to_owned(),
            idle_timeout_seconds: 0,
            readonly: false,
            write_mode: String::new(),
            folder_allowlist: Vec::new(),
            folder_denylist: Vec::new(),
            sender_allowlist: Vec::new(),
            recipient_allowlist: RelayRecipientAllowlist::default(),
            max_message_bytes: 5_242_880,
            max_recipients: 10,
            send_rate_limit: "20/hour".to_owned(),
            bypass_inspectors_for_allowlisted: vec![
                "secrets".to_owned(),
                "entropy".to_owned(),
                "content-type".to_owned(),
            ],
        }
    }
}

/// `ProtocolRelay` — one non-HTTP relay (IMAP, SMTP).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProtocolRelay {
    /// Operator-chosen name, used in error messages and unit names.
    pub name: String,
    /// `imap` | `smtp`.
    pub r#type: String,
    /// `host:port` the relay listens on, inside the cage network.
    pub listen: String,
    /// Where it connects out to.
    pub upstream: RelayUpstream,
    /// Its credentials.
    pub auth: RelayAuth,
    /// What it lets through.
    pub policy: RelayPolicy,
}

/// Fixed grant TTL — 0 means permanent (the grant lives until
/// `domain rm`).
pub const AUTO_TTL_SECONDS: i64 = 0;

/// Cap on concurrent live runtime grants.
pub const AUTO_MAX_GRANTS: i64 = 32;

/// Suffixes the decider may never grant.
///
/// Suffix-matched; the control host is always added. `metadata.goog` is
/// GCP's public metadata alias — the only cloud metadata NAME that does
/// not end in `.internal` (AWS and Azure address theirs by IP, which
/// the domain syntax check already rejects).
pub const AUTO_NEVER_GRANT: [&str; 4] = ["internal", "local", "localhost", "metadata.goog"];

/// Refuse to run the decider in blocklist mode (a grant is meaningless
/// there).
pub const AUTO_REQUIRE_ALLOWLIST_MODE: bool = true;

/// `LlmAgentConfig` — the flat client fields every in-egress LLM agent
/// carries.
///
/// Keys are egress-only source references (`env:`/`systemd-creds:`),
/// never injected into cage traffic. HTTPS-only overrides protect them
/// on the wire. The completion budget includes reasoning tokens: sizing
/// it for the verdict alone starves reasoning models before they can
/// emit a forced tool call.
///
/// In `config.py` this is a base dataclass the two roster entries
/// inherit from; here it is a field on each of them, and
/// [`super::json`] flattens it back out so `resolved-config.json` keeps
/// the shape Python's `dataclasses.fields` produces.
#[derive(Clone, Debug, PartialEq)]
pub struct LlmAgentConfig {
    /// `anthropic` | `openai` | `openrouter`.
    pub provider: String,
    /// Model identifier, passed through to the provider.
    pub model: String,
    /// `source:NAME` reference to the egress-only API key.
    pub api_key: String,
    /// Per-call timeout.
    pub timeout_seconds: f64,
    /// Completion budget, reasoning tokens included.
    pub max_tokens: i64,
    /// Override the provider's base URL; must be https.
    pub base_url: String,
}

impl Default for LlmAgentConfig {
    fn default() -> Self {
        Self {
            provider: String::new(),
            model: String::new(),
            api_key: String::new(),
            timeout_seconds: 15.0,
            max_tokens: 8192,
            base_url: String::new(),
        }
    }
}

/// `DeciderAgentConfig` — `agents.decider`, the policy decider.
///
/// The caged agent can request a new egress domain; the decider (a
/// senior cybersecurity expert) adjudicates it. On grant, the domain
/// takes effect immediately in-egress (L7 inspector + dnsmasq zone),
/// and the reconcile (`cage grants sync` / `domain list`) later
/// promotes it into the static baseline via the literal `domain add`
/// chain, so it's permanent. It guards the FRONT DOOR: before a grant.
/// Was `domains.auto` through 0.39.
#[derive(Clone, Debug, PartialEq)]
pub struct DeciderAgentConfig {
    /// The shared LLM client fields.
    pub llm: LlmAgentConfig,
    /// Master switch.
    pub enable: bool,
    /// Reserved synthetic control host.
    pub host: String,
    /// Operator-provided free-text describing this cage's purpose and
    /// scope. Flows verbatim into the decider's system prompt (as
    /// trusted operator context) so decisions can account for what the
    /// cage is FOR; advisory only — it never overrides `never_grant`,
    /// syntax, or rate limits. Capped at 4096 chars because it rides in
    /// every decider call's system prompt and through
    /// `proxy-config.yaml`. Empty/whitespace-only = feature off.
    pub context: String,
    /// Per-cage request rate limit, independent of the egress HTTP rate
    /// limit, to bound LLM cost / abuse of the request endpoint.
    pub rate_limit_rps: f64,
    /// Burst allowance for the same limiter.
    pub rate_limit_burst: i64,
}

impl Default for DeciderAgentConfig {
    fn default() -> Self {
        Self {
            llm: LlmAgentConfig::default(),
            enable: false,
            host: "agentcage.local".to_owned(),
            context: String::new(),
            rate_limit_rps: 1.0,
            rate_limit_burst: 5,
        }
    }
}

impl DeciderAgentConfig {
    /// The built-in never-grant set ∪ the control host.
    ///
    /// Operator `never_grant` is deferred; the fixed defaults are the
    /// hard floor the decider can't override.
    #[must_use]
    pub fn effective_never_grant(&self) -> std::collections::BTreeSet<String> {
        let mut out: std::collections::BTreeSet<String> = AUTO_NEVER_GRANT
            .iter()
            .map(|host| host.to_lowercase().trim_end_matches('.').to_owned())
            .collect();
        out.insert(self.host.to_lowercase().trim_end_matches('.').to_owned());
        out
    }
}

/// `WatcherAgentConfig` — `agents.watcher`, the traffic watcher.
///
/// An opt-in in-egress LLM agent that re-analyzes the cage's recent
/// traffic (audit stream + HAR capture) after the fact and flags
/// suspicious patterns; where its analysis damns a runtime grant it
/// revokes it (narrowing only — the egress never edits the operator's
/// baseline). Sibling of `agents.decider` under the same trust model:
/// the decider guards the front door (before a grant), the watcher
/// guards the house (after the traffic). Was top-level `watcher:`
/// through 0.39. See docs/explain/traffic-watcher.md.
#[derive(Clone, Debug, PartialEq)]
pub struct WatcherAgentConfig {
    /// The shared LLM client fields. Note the timeout default differs
    /// from the decider's: 30s, not 15s.
    pub llm: LlmAgentConfig,
    /// Master switch; an absent block = zero surface.
    pub enable: bool,
    /// Scan cadence. One LLM call per interval at most (and only when
    /// the window had traffic — a quiet cage costs nothing). 60s floor
    /// so a mis-typed value cannot turn the watcher into a hot loop.
    ///
    /// 15 minutes is chosen for the BILL, not for detection latency:
    /// with the digest budget below it keeps a frontier-priced model
    /// under ~$50/month and a fast one near $2, where a 5-minute
    /// cadence put the same frontier model near $200. This is an
    /// after-the-fact auditor by design, so trading latency for a
    /// predictable bill is the right default; lower it deliberately if
    /// you want faster detection.
    pub interval_seconds: f64,
    /// After-the-fact lookback on the FIRST scan after an egress
    /// (re)start: how far back into `capture.jsonl` the initial window
    /// reaches. The in-memory audit ring only covers since-start, so
    /// this bounds the durable capture history re-read. 24h cap.
    pub window_seconds: f64,
    /// Flows per analysis window (prompt-size cap). The digest is built
    /// from aggregates plus at most this many capture samples.
    pub max_flows: i64,
    /// Apply runtime-grant revocations autonomously. False = the
    /// watcher only records findings + recommendations; revocations
    /// then degrade to findings the operator applies with `agentcage
    /// cage grants <name> revoke` / `domain rm`.
    pub auto_revoke: bool,
    /// Collapse repeated flow shapes in the digest into one sample with
    /// a count. On by default: measured at 18.4% of the prompt payload
    /// on real traffic, and repetition becomes an explicit count rather
    /// than something the model must infer. The escape hatch exists
    /// because this changes what a security feature sees.
    pub dedup_samples: bool,
    /// Hard ceiling on the digest handed to the model, in estimated
    /// tokens. 8000 with the 15-minute cadence is ~885k tokens/day.
    /// This is the only knob that bounds spend independently of how
    /// much traffic the cage makes: `max_flows` bounds SAMPLES, and a
    /// sample's size varies with body excerpts, so flows alone cannot
    /// bound cost. Without it the validator accepted configurations
    /// costing tens of thousands of dollars a month. 0 disables the
    /// ceiling.
    pub max_digest_tokens: i64,
    /// Operator free-text describing the cage's purpose — the same
    /// trusted context channel as `agents.decider.context`, framed
    /// identically in the watcher's system prompt. 4096-char cap
    /// (validation, not parsing).
    pub context: String,
}

impl Default for WatcherAgentConfig {
    fn default() -> Self {
        Self {
            llm: LlmAgentConfig {
                timeout_seconds: 30.0,
                ..LlmAgentConfig::default()
            },
            enable: false,
            interval_seconds: 900.0,
            window_seconds: 3600.0,
            max_flows: 200,
            auto_revoke: true,
            dedup_samples: true,
            max_digest_tokens: 8000,
            context: String::new(),
        }
    }
}

/// `AgentsConfig` — the roster of in-egress LLM agents.
///
/// Both blocks are opt-in; the defaults are fully off. Every block here
/// is an LLM call the operator pays for, and each holds an egress-only
/// API key (never cage-visible, even as a placeholder). An absent block
/// adds zero surface.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AgentsConfig {
    /// The policy decider.
    pub decider: DeciderAgentConfig,
    /// The traffic watcher.
    pub watcher: WatcherAgentConfig,
}

/// The three `lifecycle` values.
pub const VALID_LIFECYCLES: [&str; 3] = ["service", "interactive", "ephemeral"];

/// The `agentcage:secret:` placeholder prefix.
///
/// Format: `agentcage:secret:<ENV>:<32 hex chars>` (128 bits of
/// entropy). Guessable placeholders like `{{GH_TOKEN}}` are an
/// accidental-substitution hazard: any file the agent sends outbound
/// that happens to contain that literal text (template files, docs)
/// would get the real secret injected. The random suffix makes a
/// collision with legitimate content vanishingly unlikely, and the
/// prefix makes a placeholder self-identifying. The proxy matches
/// placeholders as literal strings, so the token can be any stable
/// string — no delimiters required.
pub const PLACEHOLDER_PREFIX: &str = "agentcage:secret:";

/// Transform names `secret_injection` accepts.
pub const KNOWN_TRANSFORMS: [&str; 1] = ["google-jwt-bearer"];

/// Built-in inspector names recognized by both proxy backends.
///
/// Source of truth on the container side: `data/proxy/addon.py`
/// `_BUILTIN_INSPECTORS`. Mirrored here so the apple-container
/// validator can flag typos at parse time instead of letting them
/// silently no-op at runtime. Keep in sync when adding a new built-in
/// inspector.
pub const BUILTIN_INSPECTOR_NAMES: [&str; 5] =
    ["domain", "secrets", "body-size", "entropy", "content-type"];

/// The three `secrets.scope` values.
pub const VALID_SECRET_SCOPES: [&str; 3] = ["auto", "user", "system"];

/// `Config` — a parsed `cage.yaml`.
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// Cage name; also the systemd unit and network prefix.
    pub name: String,
    /// `container` | `vm` | `apple-container`. **Computed** when the
    /// key is absent — see the module docs.
    pub isolation: String,
    /// `service` | `interactive` | `ephemeral`.
    pub lifecycle: String,
    /// The workload container.
    pub container: ContainerConfig,
    /// At-rest secret storage.
    pub secrets: SecretsConfig,
    /// Placeholder-to-credential rules.
    pub secret_injection: Vec<SecretInjectionRule>,
    /// Inspector chain — the same shape the proxy addon reads from
    /// cage.yaml's top-level `inspectors:` list. Each entry is
    /// `{"name": str, "config": dict, "path": str?}`. Kept as raw
    /// mappings (not a typed struct) because the container backend's
    /// addon already reads YAML directly and the config flow has to be
    /// byte-identical across backends. See `data/proxy/addon.py`
    /// `_load_custom_inspectors` for the dispatch.
    pub inspectors: Vec<Mapping>,
    /// Non-HTTP relays (IMAP, SMTP).
    pub protocol_relays: Vec<ProtocolRelay>,
    /// Upstream resolvers dnsmasq forwards to. **Computed** from the
    /// host when the key is absent — see the module docs.
    pub dns_servers: Vec<String>,
    /// Egress domain policy.
    pub domains: DomainConfig,
    /// In-egress LLM agents (opt-in): the policy decider (adjudicates
    /// the caged agent's runtime domain requests) and the traffic
    /// watcher (after-the-fact auditor). Parsed here, plumbed into the
    /// egress's `proxy-config.yaml` via `state._PROXY_KEYS` ("agents"),
    /// enforced by the mitmproxy addon + `watcher.py` inside the
    /// egress. Absent blocks → default (disabled) configs → zero
    /// surface.
    pub agents: AgentsConfig,
    /// Logging knobs.
    pub logging: LoggingConfig,
    /// Capture knobs.
    pub capture: CaptureConfig,
    /// Egress port policy.
    pub ports: PortsConfig,
    /// Lima guest sizing, for `isolation: vm`.
    pub vm: VmConfig,
    /// Free-text shown by `cage help`.
    pub help: String,
    /// Named argv shortcuts for `cage exec`.
    pub exec_aliases: OrderedMap<Vec<String>>,
    /// Scaffold name, stored in metadata for `cage ls`.
    pub scaffold: String,
    /// apple-container only: when true, agentcage installs a per-cage
    /// launchd plist into `~/Library/LaunchAgents` so the cage
    /// re-starts automatically at user login. Opt-in because most users
    /// prefer to control which cages come back after a reboot. Other
    /// isolation backends ignore this. See
    /// docs/explain/isolation-backends.md.
    pub apple_container_autostart: bool,
}

impl Default for Config {
    /// The `Config()` a bare `@dataclass` call produces.
    ///
    /// `load_config` returns exactly this for an empty file and for one
    /// whose document is not a mapping, so it is a reachable value and
    /// not just a constructor convenience — which is why `isolation`
    /// is `"container"` here even though a real load computes it.
    fn default() -> Self {
        Self {
            name: String::new(),
            isolation: "container".to_owned(),
            lifecycle: "service".to_owned(),
            container: ContainerConfig::default(),
            secrets: SecretsConfig::default(),
            secret_injection: Vec::new(),
            inspectors: Vec::new(),
            protocol_relays: Vec::new(),
            dns_servers: Vec::new(),
            domains: DomainConfig::default(),
            agents: AgentsConfig::default(),
            logging: LoggingConfig::default(),
            capture: CaptureConfig::default(),
            ports: PortsConfig::default(),
            vm: VmConfig::default(),
            help: String::new(),
            exec_aliases: OrderedMap::new(),
            scaffold: String::new(),
            apple_container_autostart: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, ContainerConfig, DeciderAgentConfig, DomainConfig, LoggingConfig};

    /// `Default` is the dataclass default, which for `isolation` is the
    /// *annotation*, not what a real load produces.
    #[test]
    fn config_default_mirrors_the_dataclass() {
        let config = Config::default();
        assert_eq!(config.isolation, "container");
        assert_eq!(config.lifecycle, "service");
        assert_eq!(config.container.user, "1000:1000");
        assert!(config.container.read_only);
        assert_eq!(config.container.drop_capabilities, ["ALL"]);
        assert_eq!(config.vm.vcpus, 4);
        assert_eq!(config.ports.tcp.allow, [80, 443]);
    }

    /// The one field whose `Default` and whose parsed default disagree,
    /// pinned so the discrepancy cannot be quietly "tidied".
    #[test]
    fn timeout_start_sec_keeps_the_dead_dataclass_default() {
        assert_eq!(ContainerConfig::default().timeout_start_sec, 600);
    }

    #[test]
    fn domain_list_follows_mode() {
        let mut domains = DomainConfig {
            allow: vec!["a.example.com".to_owned()],
            block: vec!["b.example.com".to_owned()],
            ..DomainConfig::default()
        };
        assert!(domains.list().is_empty());
        domains.mode = "allowlist".to_owned();
        assert_eq!(domains.list(), ["a.example.com"]);
        domains.mode = "blocklist".to_owned();
        assert_eq!(domains.list(), ["b.example.com"]);
    }

    #[test]
    fn level_for_inherits_when_the_override_is_empty() {
        let logging = LoggingConfig {
            level: "warning".to_owned(),
            dns: "debug".to_owned(),
            ..LoggingConfig::default()
        };
        assert_eq!(logging.level_for("dns"), "debug");
        assert_eq!(logging.level_for("proxy"), "warning");
        assert_eq!(logging.level_for("nonsense"), "warning");
    }

    #[test]
    fn never_grant_always_holds_the_control_host() {
        let decider = DeciderAgentConfig::default();
        let never = decider.effective_never_grant();
        assert!(never.contains("agentcage.local"));
        assert!(never.contains("metadata.goog"));
        assert_eq!(never.len(), 5);
    }
}
