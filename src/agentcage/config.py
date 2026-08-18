"""Parse and validate agentcage YAML configuration."""

from __future__ import annotations

import ipaddress
import os
import platform
import re
import subprocess
from dataclasses import dataclass, field

import yaml

from agentcage.data.proxy.relays._validate import (
    validate_relay_entry,
)


KNOWN_TRANSFORMS = frozenset({"google-jwt-bearer"})

# Built-in inspector names recognized by both proxy backends. Source of
# truth on the container side: ``data/proxy/addon.py _BUILTIN_INSPECTORS``.
# We mirror it here so the apple-container validator can flag typos at
# parse time instead of letting them silently no-op at runtime. Keep in
# sync when adding a new built-in inspector.
_BUILTIN_INSPECTOR_NAMES = frozenset({
    "domain", "secrets", "body-size", "entropy", "content-type",
})

_VALID_SECRET_SCOPES = ("auto", "user", "system")


@dataclass
class SecretsConfig:
    # At-rest storage backend: "auto" picks the best encrypting backend for
    # the platform (Linux: systemd-creds). Explicit: "systemd-creds",
    # "system-keychain" (macOS), "plaintext".
    backend: str = "auto"
    scope: str = "auto"  # "auto" | "user" | "system" (systemd-creds only)
    # When no encrypting backend is available, agentcage refuses to store
    # secrets as cleartext (fail-closed). Set this to true to explicitly opt
    # into the unencrypted podman secret store under `backend: auto`.
    allow_plaintext: bool = False


PLACEHOLDER_PREFIX = "agentcage:secret:"


def generate_placeholder(env: str) -> str:
    """Return an entropic placeholder token for *env*.

    Format: ``agentcage:secret:<ENV>:<32 hex chars>`` (128 bits of entropy).
    Guessable placeholders like ``{{GH_TOKEN}}`` are an accidental-
    substitution hazard: any file the agent sends outbound that happens to
    contain that literal text (template files, docs) would get the real
    secret injected. The random suffix makes a collision with legitimate
    content vanishingly unlikely, and the ``agentcage:secret:`` prefix makes
    a placeholder self-identifying (see :func:`validate_config`). The proxy
    matches placeholders as literal strings, so the token can be any stable
    string — no delimiters required.
    """
    import secrets as _secrets
    return "%s%s:%s" % (PLACEHOLDER_PREFIX, env, _secrets.token_hex(16))


def fill_raw_placeholders(raw: dict, prev_raw: dict | None = None) -> bool:
    """Generate entropic placeholders for rules that omit ``placeholder:``.

    Mutates *raw* (a parsed cage.yaml dict) in place; returns True if any
    rule was filled. When *prev_raw* is given (``cage update -c`` / ``cage
    edit``), a placeholder already persisted for the same env is carried
    over so the token stays stable across updates — regenerating would
    desynchronize processes still holding the old token in their env.

    The filled dict is persisted into the stored cage.yaml (the single
    source of truth) so every consumer — quadlet rendering, proxy config,
    ``secret list`` — sees the same value.
    """
    def _rules(d: dict) -> list:
        si = d.get("secret_injection") or []
        rules = si.get("rules", []) if isinstance(si, dict) else si
        return rules if isinstance(rules, list) else []

    prev = {}
    if prev_raw:
        prev = {
            e.get("env"): e.get("placeholder", "")
            for e in _rules(prev_raw) if isinstance(e, dict)
        }
    changed = False
    for entry in _rules(raw):
        if not isinstance(entry, dict):
            continue
        env = entry.get("env", "")
        if not env or entry.get("placeholder"):
            continue
        entry["placeholder"] = prev.get(env) or generate_placeholder(env)
        changed = True
    return changed


@dataclass
class SecretInjectionRule:
    env: str
    # Empty means "not yet generated": rules may omit ``placeholder:`` in
    # cage.yaml, and the CLI persists a generated token into the stored
    # config at declare time (create/update/edit) — see
    # config.fill_raw_placeholders. Consumers that render or inject
    # placeholders skip rules whose placeholder is still empty.
    placeholder: str
    inject_to: list[str] = field(default_factory=list)
    source: str = ""
    transform: str = ""
    transform_config: dict = field(default_factory=dict)
    # Strict by default: only substitute placeholders found in a
    # credential-bearing request header — one whose name contains "auth",
    # "key", or "token" (Authorization, x-api-key, *-token, …). Set
    # ``inject_body: true`` to also inject into the request URL and body
    # (the legacy, looser behavior).
    inject_body: bool = False
    # Extra request headers to treat as credential-bearing under the strict
    # default — for auth headers whose name doesn't match the keyword
    # heuristic (e.g. ``x-honeycomb-team``). Matched case-insensitively.
    inject_headers: list[str] = field(default_factory=list)


def validate_transform(name: str) -> None:
    """Reject unknown transform names at config parse time."""
    if not name:
        return
    if name not in KNOWN_TRANSFORMS:
        valid = ", ".join(sorted(KNOWN_TRANSFORMS))
        raise ValueError(
            f"unknown secret_injection transform: '{name}'. Valid: {valid}"
        )


@dataclass
class BuildConfig:
    containerfile: str = ""
    args: dict[str, str] = field(default_factory=dict)


@dataclass
class ContainerConfig:
    image: str = ""
    command: list[str] = field(default_factory=list)
    volumes: list[str] = field(default_factory=list)
    named_volumes: dict[str, str] = field(default_factory=dict)
    tmpfs: list[str] = field(default_factory=list)
    ports: list[str] = field(default_factory=list)
    podman_secrets: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    user: str = "1000:1000"
    memory: str = ""
    cpus: str = ""
    read_only: bool = True
    drop_capabilities: list[str] = field(default_factory=lambda: ["ALL"])
    add_capabilities: list[str] = field(default_factory=list)
    no_new_privileges: bool = True
    nested_containers: bool = False
    security_label_disable: bool = True
    userns: str = ""  # e.g. "keep-id" to map host UID into container
    build: BuildConfig = field(default_factory=BuildConfig)
    restart: str = "on-failure"
    restart_sec: int = 10
    timeout_start_sec: int = 600
    timeout_stop_sec: int = 30


_VALID_LEVELS = ("debug", "info", "warning", "error", "critical")
_LEVEL_ORDER = {name: idx for idx, name in enumerate(_VALID_LEVELS)}


@dataclass
class LoggingConfig:
    dns_queries: bool = False
    proxy_connections: bool = False
    allowed_requests: bool = False
    level: str = "info"   # global default minimum level
    dns: str = ""         # per-service override (empty = inherit from level)
    proxy: str = ""
    cage: str = ""

    def level_for(self, service: str) -> str:
        """Return the effective minimum level for *service*."""
        override = getattr(self, service, "")
        return override if override else self.level


@dataclass
class DomainConfig:
    mode: str = ""  # "allowlist" | "blocklist" | "" — derived from allow/block
    allow: list[str] = field(default_factory=list)
    block: list[str] = field(default_factory=list)
    passthrough: list[str] = field(default_factory=list)

    @property
    def list(self) -> list[str]:
        """Return the active domain list (allow or block) for backward compat."""
        if self.mode == "allowlist":
            return self.allow
        if self.mode == "blocklist":
            return self.block
        return []


MAX_CAPTURE_BODY_BYTES = 10_485_760  # 10 MB


@dataclass
class CaptureConfig:
    enable_har: bool = False
    max_body_size: int = MAX_CAPTURE_BODY_BYTES
    min_action: str = "all"  # "all" | "flag" | "block"
    domains: list[str] = field(default_factory=list)
    exclude_domains: list[str] = field(default_factory=list)


# Default permitted destination ports for `ports.tcp.allow`. Catches
# HTTP and HTTPS on standard ports. Extend (e.g. add 8448 for a Matrix
# homeserver) to permit non-standard services. Ports outside the
# effective port policy are dropped by the proxy's filter:FORWARD policy.
DEFAULT_TCP_ALLOW_PORTS = (80, 443)

# Reserved by mitmdump's own listeners; redirecting them would either
# loop (8443 is the transparent listener's own port) or break the L7
# HTTP_PROXY path (8080 is the regular HTTP-proxy listener). Applied
# only to inspected TCP ports (= tcp.allow - tcp.passthrough);
# passthrough entries never get a REDIRECT rule and don't conflict.
_MITMDUMP_RESERVED_PORTS = (8080, 8443)


@dataclass
class TcpPortsConfig:
    """TCP egress port policy.

    - ``allow`` — TCP destination ports the cage may reach. Anything not
      in allow (and not in passthrough, which is implicitly allowed) is
      dropped by the proxy's filter:FORWARD policy.
    - ``passthrough`` — subset of allowed TCP ports that bypass mitmdump
      inspection. These flow L3-forwarded to upstream without entering
      audit.jsonl, the inspector chain, or the secret injector.

    Inspected TCP ports = allow - passthrough.
    """
    allow: list[int] = field(
        default_factory=lambda: list(DEFAULT_TCP_ALLOW_PORTS)
    )
    passthrough: list[int] = field(default_factory=list)


@dataclass
class UdpPortsConfig:
    """UDP egress port policy.

    - ``allow`` — UDP destination ports the cage may reach. UDP is never
      inspected (mitmdump is HTTP-only); all entries are forwarded
      uninspected. Ports not in allow are dropped by filter:FORWARD.

    Defaults to empty. HTTP/3 (UDP/443), NTP (UDP/123), and any other
    UDP-using protocol requires an explicit entry.
    """
    allow: list[int] = field(default_factory=list)


@dataclass
class IcmpPortsConfig:
    """Outbound ICMP (echo-request / ``ping``) egress policy.

    - ``allow`` — when true, the egress installs a ``filter:FORWARD
      -p icmp --icmp-type echo-request ACCEPT`` rule so the cage can
      ``ping`` out for diagnostics; replies ride the ``ESTABLISHED,RELATED``
      rule. When false (the default) no such rule is installed and the
      default-deny FORWARD policy drops outbound echo-request — for every
      in-cage privilege level, including ``--as-root`` (which holds
      ``CAP_NET_RAW`` but cannot reach the egress's FORWARD chain).

    Defaults to false: ICMP is OFF unless explicitly opted in. This does
    NOT affect path-MTU discovery — the ICMP ``fragmentation-needed``
    errors arrive as ``RELATED`` to an existing TCP flow and ride the
    ``ESTABLISHED,RELATED`` rule regardless of this knob.
    """
    allow: bool = False


@dataclass
class PortsConfig:
    """Cage egress port policy, split by protocol.

    Layered on a default-deny filter:FORWARD policy (always installed,
    no opt-out flag): every cage drops L4 traffic not explicitly allowed
    here. Outbound ICMP echo-request is opt-in via ``ports.icmp.allow``
    (default false). A separate ip6tables -P FORWARD DROP failsafe blocks
    all IPv6 forwarding.
    """
    tcp: TcpPortsConfig = field(default_factory=TcpPortsConfig)
    udp: UdpPortsConfig = field(default_factory=UdpPortsConfig)
    icmp: IcmpPortsConfig = field(default_factory=IcmpPortsConfig)


@dataclass
class VmConfig:
    vcpus: int = 4
    mem_mb: int = 4096


@dataclass
class RelayUpstream:
    host: str
    port: int
    tls: bool = True
    # Path to a PEM certificate on the host, added to the proxy's system
    # CA store for this upstream. For upstreams no public CA signs: a
    # private-CA mail server, or a local decrypting daemon like Proton
    # Mail Bridge that mints its own self-signed certificate. Read at
    # deploy time and delivered to the proxy as ``ca_pem``.
    ca_file: str = ""
    # The resolved inline form ``ca_file`` becomes, and what the relay
    # actually loads. Accepted directly in config too.
    ca_pem: str = ""
    # Name presented in SNI and checked against the certificate, when it
    # differs from ``host`` — required whenever ``host`` is an IP literal.
    tls_servername: str = ""


@dataclass
class RelayAuth:
    type: str = ""  # e.g. "imap-login"
    user_source: str = ""  # source scheme (env:/cmd:/systemd-creds:)
    password_source: str = ""


@dataclass
class RelayRecipientAllowlist:
    """SMTP recipient gate. Empty = allow any recipient (insecure;
    explicit acknowledgement only). When non-empty, a RCPT TO is
    accepted iff its address matches an entry in ``addresses`` or its
    domain matches an entry in ``domains`` (suffix-aware so
    ``foo.example.com`` matches an ``example.com`` domain entry).
    """

    addresses: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)


@dataclass
class RelayPolicy:
    # Common
    conn_rate_limit: str = "30/min"
    # Maximum time the relay waits between commands before disconnecting
    # an idle session. 0 disables. Defaults differ per relay type:
    # SMTP=300 (5 min, RFC 5321 §4.5.3.2), IMAP=1800 (30 min, to permit
    # IDLE heartbeats RFC 2177).
    idle_timeout_seconds: int = 0

    # IMAP
    readonly: bool = False
    # "none" | "organise" | "full". Empty means "derive from readonly",
    # which the proxy does, so old configs are untouched.
    write_mode: str = ""
    folder_allowlist: list[str] = field(default_factory=list)
    # Denied outright; denial wins over the allowlist.
    folder_denylist: list[str] = field(default_factory=list)

    # SMTP
    sender_allowlist: list[str] = field(default_factory=list)
    recipient_allowlist: RelayRecipientAllowlist = field(
        default_factory=RelayRecipientAllowlist
    )
    max_message_bytes: int = 5_242_880  # 5 MiB
    max_recipients: int = 10
    send_rate_limit: str = "20/hour"
    # Inspectors to skip when the recipient_allowlist is non-empty
    # and every recipient matched it. The threat model assumes the
    # allowlist names trusted destinations, so legitimate user
    # content that trips `secrets`, `entropy`, or `content-type`
    # (forwarded calendar invites, recovery codes, base64 attachments,
    # PGP-signed plaintext, long URLs) is allowed through. body-size
    # still applies as a structural cap. Set to ``[]`` to keep strict
    # behavior even for trusted recipients. content-type is a more
    # aggressive bypass than secrets/entropy because it catches
    # legitimate base64-in-text/plain content email clients routinely
    # produce; for HTTP that's an exfil signal, for email it's noise.
    bypass_inspectors_for_allowlisted: list[str] = field(
        default_factory=lambda: ["secrets", "entropy", "content-type"]
    )


@dataclass
class ProtocolRelay:
    name: str
    type: str  # "imap"
    listen: str  # "host:port"
    upstream: RelayUpstream = field(default_factory=lambda: RelayUpstream("", 0))
    auth: RelayAuth = field(default_factory=RelayAuth)
    policy: RelayPolicy = field(default_factory=RelayPolicy)


_VALID_LIFECYCLES = ("service", "interactive", "ephemeral")


@dataclass
class Config:
    name: str = ""
    isolation: str = "container"  # "container" | "vm" | "apple-container"
    lifecycle: str = "service"  # "service" | "interactive" | "ephemeral"
    container: ContainerConfig = field(default_factory=ContainerConfig)
    secrets: SecretsConfig = field(default_factory=SecretsConfig)
    secret_injection: list[SecretInjectionRule] = field(default_factory=list)
    # Inspector chain — same shape the proxy addon reads from cage.yaml's
    # top-level ``inspectors:`` list. Each entry is ``{"name": str,
    # "config": dict, "path": str?}``. Kept as raw dicts (not a typed
    # dataclass) because the container backend's addon already reads YAML
    # directly and we want byte-identical config flow across backends.
    # See data/proxy/addon.py ``_load_custom_inspectors`` for the dispatch.
    inspectors: list[dict] = field(default_factory=list)
    protocol_relays: list[ProtocolRelay] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)
    domains: DomainConfig = field(default_factory=DomainConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    ports: PortsConfig = field(default_factory=PortsConfig)
    vm: VmConfig = field(default_factory=VmConfig)
    help: str = ""
    exec_aliases: dict[str, list[str]] = field(default_factory=dict)
    scaffold: str = ""  # scaffold name, stored in metadata for cage ls
    # apple-container only: when True, agentcage installs a per-cage
    # launchd plist into ~/Library/LaunchAgents so the cage re-starts
    # automatically at user login. Opt-in because most users prefer to
    # control which cages come back after a reboot. Other isolation
    # backends ignore this. See docs/apple-container.md.
    apple_container_autostart: bool = False


def default_isolation() -> str:
    """Return the best isolation backend for the current host.

    Resolution order (first match wins):
      - Linux              -> "container" (rootless podman on host)
      - macOS 26+ ASi with the `container` CLI installed -> "apple-container"
      - macOS (any other)  -> "vm" (Lima)

    The probe uses ``shutil.which`` for the `container` binary (no
    subprocess) so it's safe to call on every config load. We don't probe
    whether the apiserver is *running* — validation catches "installed but
    stopped" with a clear hint.
    """
    if platform.system() != "Darwin":
        return "container"
    if platform.machine() != "arm64":
        return "vm"
    # macOS major version. mac_ver() returns ("26.3.2", ...) etc.
    try:
        major = int((platform.mac_ver()[0] or "0").split(".")[0])
    except (ValueError, IndexError):
        major = 0
    if major < 26:
        return "vm"
    # Lazy import to avoid a circular dep at module load time.
    from agentcage.apple_container import cli as _ac_cli  # noqa: PLC0415
    if _ac_cli.container_binary() is None:
        return "vm"
    return "apple-container"


def _is_loopback(addr: str) -> bool:
    """Return True if *addr* is a loopback IP (127.0.0.0/8 or ::1)."""
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def _read_nameservers(path: str) -> list[str]:
    """Parse nameserver lines from a resolv.conf file."""
    try:
        with open(path) as f:
            return [
                parts[1]
                for line in f
                if (parts := line.split()) and parts[0] == "nameserver"
            ]
    except OSError:
        return []


# systemd-resolved writes the real upstream servers here, while
# /etc/resolv.conf points at the 127.0.0.53 stub listener.
_RESOLVED_CONF = "/run/systemd/resolve/resolv.conf"

# macOS does not consult /etc/resolv.conf for resolution (the file even says
# so) — the System Configuration framework is the source of truth, exposed
# via `scutil --dns`. Its output lists upstreams as `nameserver[N] : <addr>`.
_SCUTIL_NS_RE = re.compile(r"^\s*nameserver\[\d+\]\s*:\s*(\S+)")


def _scutil_dns_servers() -> list[str]:
    """Return non-loopback upstream nameservers from `scutil --dns` (macOS).

    macOS may leave /etc/resolv.conf pointing at a loopback resolver (a local
    VPN client, dnsmasq, Cloudflare WARP, etc.), which is unreachable from
    inside containers. `scutil --dns` reports the real upstreams. Returns an
    empty list if scutil is unavailable or yields nothing usable.
    """
    try:
        out = subprocess.run(
            ["scutil", "--dns"],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    seen: dict[str, None] = {}
    for line in out.splitlines():
        m = _SCUTIL_NS_RE.match(line)
        if m and not _is_loopback(m.group(1)):
            # scutil repeats each resolver across resolver scopes; dedupe
            # while preserving first-seen order.
            seen.setdefault(m.group(1), None)
    return list(seen)


def _host_dns_servers() -> list[str]:
    """Detect the host's usable upstream DNS servers.

    Loopback addresses (e.g. 127.0.0.53 from systemd-resolved) are filtered
    out because they are unreachable from inside containers.  When all
    nameservers in /etc/resolv.conf are loopback, the real upstreams are read
    from /run/systemd/resolve/resolv.conf (systemd-resolved) on Linux, or from
    `scutil --dns` on macOS.

    Raises RuntimeError if no usable DNS servers can be found.  Set
    ``dns_servers`` explicitly in the config to avoid auto-detection.
    """
    servers = _read_nameservers("/etc/resolv.conf")
    non_loopback = [s for s in servers if not _is_loopback(s)]
    if non_loopback:
        return non_loopback
    # All servers were loopback (systemd-resolved stub) — try the real
    # upstream config that systemd-resolved maintains.
    resolved = _read_nameservers(_RESOLVED_CONF)
    resolved = [s for s in resolved if not _is_loopback(s)]
    if resolved:
        return resolved
    # On macOS /etc/resolv.conf is not authoritative; ask the System
    # Configuration framework for the real upstreams.
    if platform.system() == "Darwin":
        scutil = _scutil_dns_servers()
        if scutil:
            return scutil
        raise RuntimeError(
            "Could not detect usable DNS servers: /etc/resolv.conf contains "
            "only loopback addresses and `scutil --dns` reported no usable "
            "upstream resolvers. Set dns_servers explicitly in your agentcage "
            "config."
        )
    raise RuntimeError(
        "Could not detect usable DNS servers: /etc/resolv.conf contains only "
        "loopback addresses (e.g. 127.0.0.53 from systemd-resolved) and "
        f"{_RESOLVED_CONF} is missing or empty. "
        "Set dns_servers explicitly in your agentcage config."
    )


def load_config(path: str) -> Config:
    """Load and parse a agentcage YAML config file.

    Raises ``ValueError`` with a friendly message on YAML syntax errors or
    file-read errors. Previously a malformed cage.yaml surfaced as a raw
    ``yaml.scanner.ScannerError`` Python traceback at the CLI user; click
    catches ValueError via the cli wrapper and prints a clean error
    instead.
    """
    try:
        with open(path) as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        # mark + problem_mark give the operator file:line:column. Stripping
        # the traceback noise leaves "<file>:<line>:<col>: <message>"-ish
        # output that mirrors how compilers report syntax errors.
        loc = getattr(e, "problem_mark", None)
        where = f" at line {loc.line + 1}, column {loc.column + 1}" if loc else ""
        msg = getattr(e, "problem", None) or str(e)
        raise ValueError(
            f"{path} is not valid YAML{where}: {msg}"
        ) from e
    except OSError as e:
        raise ValueError(f"could not read {path}: {e}") from e

    if not raw or not isinstance(raw, dict):
        return Config()

    cfg = Config()
    cfg.name = raw.get("name", "")
    cfg.isolation = raw.get("isolation") or default_isolation()
    cfg.lifecycle = raw.get("lifecycle", "service")
    cfg.scaffold = raw.get("scaffold", "")

    # Silently migrate "firecracker" isolation to "vm"
    if cfg.isolation == "firecracker":
        cfg.isolation = "vm"

    # VM section — prefer explicit "vm:" key, fall back to "firecracker:" for migration
    vm_raw = raw.get("vm") or raw.get("firecracker") or {}
    vm = VmConfig()
    vm.vcpus = int(vm_raw.get("vcpus", VmConfig.vcpus))
    vm.mem_mb = int(vm_raw.get("mem_mb", VmConfig.mem_mb))
    cfg.vm = vm

    # Container section
    c = raw.get("container") or {}
    cc = ContainerConfig()
    cc.image = c.get("image", "")
    cc.command = list(c.get("command") or [])
    cc.volumes = list(c.get("volumes") or [])
    cc.named_volumes = dict(c.get("named_volumes") or {})
    cc.tmpfs = list(c.get("tmpfs") or [])
    cc.ports = list(c.get("ports") or [])
    cc.podman_secrets = list(c.get("podman_secrets") or [])
    cc.env = dict(c.get("env") or {})

    # User: default "1000:1000", empty string means use image default
    cc.user = c.get("user", "1000:1000")
    # If user explicitly sets user: "" in YAML, it comes as None or ""
    if cc.user is None:
        cc.user = ""

    cc.memory = str(c.get("memory", "") or "")
    cc.cpus = str(c.get("cpus", "") or "")

    cc.read_only = c.get("read_only", True)
    cc.no_new_privileges = c.get("no_new_privileges", True)
    cc.nested_containers = bool(c.get("nested_containers", False))
    cc.security_label_disable = c.get("security_label_disable", True)
    cc.userns = str(c.get("userns", "") or "")

    # drop_capabilities: default "ALL" (string or list)
    drop = c.get("drop_capabilities", "ALL")
    if drop:
        cc.drop_capabilities = list(drop) if isinstance(drop, list) else [drop]
    else:
        cc.drop_capabilities = []

    cc.add_capabilities = list(c.get("add_capabilities") or [])

    cc.restart = c.get("restart") or "on-failure"
    cc.restart_sec = c.get("restart_sec") if c.get("restart_sec") is not None else 10
    cc.timeout_start_sec = c.get("timeout_start_sec", 120) or 0
    cc.timeout_stop_sec = c.get("timeout_stop_sec", 30) or 0

    # Build config
    build_raw = c.get("build") or {}
    bb = BuildConfig()
    bb.containerfile = build_raw.get("containerfile", "")
    bb.args = dict(build_raw.get("args") or {})
    cc.build = bb

    cfg.container = cc

    # Secrets section — encryption scope for systemd-creds
    secrets_raw = raw.get("secrets") or {}
    scope = str(secrets_raw.get("scope", "auto"))
    if scope not in _VALID_SECRET_SCOPES:
        valid = ", ".join(_VALID_SECRET_SCOPES)
        raise ValueError(
            f"invalid secrets.scope: {scope!r}. Valid: {valid}"
        )
    backend = str(secrets_raw.get("backend", "auto"))
    from agentcage.secret_store import KNOWN_BACKENDS
    if backend not in KNOWN_BACKENDS:
        valid = ", ".join(sorted(KNOWN_BACKENDS))
        raise ValueError(
            f"invalid secrets.backend: {backend!r}. Valid: {valid}"
        )
    cfg.secrets = SecretsConfig(
        backend=backend,
        scope=scope,
        allow_plaintext=bool(secrets_raw.get("allow_plaintext", False)),
    )

    # Secret injection — accepts list or {"rules": [...]}
    si_cfg = raw.get("secret_injection") or []
    si_rules = si_cfg.get("rules", []) if isinstance(si_cfg, dict) else si_cfg
    injected_names = set()
    from agentcage.secret_resolver import validate_env_name, validate_source

    for entry in si_rules:
        env_name = entry.get("env", "")
        # placeholder is optional: an omitted/empty placeholder is filled
        # with a generated entropic token when the rule is persisted to a
        # cage's stored config (config.fill_raw_placeholders).
        placeholder = entry.get("placeholder", "") or ""
        if env_name:
            validate_env_name(env_name)
            source = entry.get("source", "")
            validate_source(source)
            transform = entry.get("transform", "") or ""
            validate_transform(transform)
            transform_config = dict(entry.get("transform_config") or {})
            injected_names.add(env_name)
            cfg.secret_injection.append(SecretInjectionRule(
                env=env_name,
                placeholder=placeholder,
                inject_to=list(entry.get("inject_to") or []),
                source=source,
                transform=transform,
                transform_config=transform_config,
                inject_body=bool(entry.get("inject_body", False)),
                inject_headers=[
                    str(h).strip() for h in (entry.get("inject_headers") or [])
                ],
            ))

    # Remove injected secrets from podman_secrets and env — they are handled
    # separately via placeholder substitution in the proxy.  Leaving them in
    # env would expose the real value inside the cage (os.path.expandvars
    # expands ${VAR} references during quadlet generation).
    cc.podman_secrets = [s for s in cc.podman_secrets if s not in injected_names]
    cc.env = {k: v for k, v in cc.env.items() if k not in injected_names}

    # Inspector chain — preserved as raw dicts so the proxy addon's
    # dispatch logic stays the single source of truth for valid keys.
    # We coerce non-list values (None, scalars) to an empty list to keep
    # the field shape consistent for downstream consumers.
    insp_raw = raw.get("inspectors") or []
    if isinstance(insp_raw, list):
        cfg.inspectors = [dict(e) for e in insp_raw if isinstance(e, dict)]

    # Protocol relays — non-HTTP secret injection (IMAP, etc.)
    pr_cfg = raw.get("protocol_relays") or []
    relay_secret_names: set[str] = set()
    for entry in pr_cfg:
        validate_relay_entry(entry, source_validator=validate_source)
        rname = entry["name"]
        rtype = entry["type"]
        listen = entry["listen"]
        up_raw = entry.get("upstream") or {}
        upstream = RelayUpstream(
            host=str(up_raw.get("host", "")),
            port=int(up_raw.get("port", 0) or 0),
            tls=bool(up_raw.get("tls", True)),
            ca_file=str(up_raw.get("ca_file", "") or ""),
            ca_pem=str(up_raw.get("ca_pem", "") or ""),
            tls_servername=str(up_raw.get("tls_servername", "") or ""),
        )
        auth_raw = entry.get("auth") or {}
        auth = RelayAuth(
            type=str(auth_raw.get("type", "") or ""),
            user_source=str(auth_raw.get("user_source", "") or ""),
            password_source=str(auth_raw.get("password_source", "") or ""),
        )
        # Collect env names (the part after "scheme:") so we strip them
        # from the cage's env/podman_secrets the same way secret_injection
        # does — these credentials must only land in the proxy.
        for src in (auth.user_source, auth.password_source):
            scheme, _, arg = (src or "").partition(":")
            if scheme and arg:
                relay_secret_names.add(arg)
        pol_raw = entry.get("policy") or {}
        rcpt_raw = pol_raw.get("recipient_allowlist") or {}
        if isinstance(rcpt_raw, list):
            # Convenience shorthand: a flat list is treated as `addresses`.
            rcpt_raw = {"addresses": rcpt_raw}
        recipient_allowlist = RelayRecipientAllowlist(
            addresses=list(rcpt_raw.get("addresses") or []),
            domains=list(rcpt_raw.get("domains") or []),
        )
        if "bypass_inspectors_for_allowlisted" in pol_raw:
            bypass = list(pol_raw.get("bypass_inspectors_for_allowlisted") or [])
        else:
            bypass = ["secrets", "entropy", "content-type"]
        policy = RelayPolicy(
            conn_rate_limit=str(
                pol_raw.get("conn_rate_limit") or "30/min"
            ),
            idle_timeout_seconds=int(pol_raw.get("idle_timeout_seconds", 0)),
            readonly=bool(pol_raw.get("readonly", False)),
            write_mode=str(pol_raw.get("write_mode", "") or ""),
            folder_allowlist=list(pol_raw.get("folder_allowlist") or []),
            folder_denylist=list(pol_raw.get("folder_denylist") or []),
            sender_allowlist=list(pol_raw.get("sender_allowlist") or []),
            recipient_allowlist=recipient_allowlist,
            max_message_bytes=int(
                pol_raw.get("max_message_bytes", 5_242_880)
            ),
            max_recipients=int(pol_raw.get("max_recipients", 10)),
            send_rate_limit=str(
                pol_raw.get("send_rate_limit") or "20/hour"
            ),
            bypass_inspectors_for_allowlisted=bypass,
        )
        cfg.protocol_relays.append(ProtocolRelay(
            name=rname,
            type=rtype,
            listen=listen,
            upstream=upstream,
            auth=auth,
            policy=policy,
        ))

    if relay_secret_names:
        cc.podman_secrets = [
            s for s in cc.podman_secrets if s not in relay_secret_names
        ]
        cc.env = {
            k: v for k, v in cc.env.items() if k not in relay_secret_names
        }

    # DNS servers (default to host resolvers if not specified)
    cfg.dns_servers = list(raw.get("dns_servers") or _host_dns_servers())

    # Domains
    dom_raw = raw.get("domains") or {}
    dc = DomainConfig()
    dc.passthrough = list(dom_raw.get("passthrough") or [])

    # New format: explicit allow/block lists
    if "allow" in dom_raw:
        dc.allow = list(dom_raw["allow"] or [])
        dc.mode = "allowlist"
        if "block" in dom_raw:
            dc.block = list(dom_raw["block"] or [])
    elif "block" in dom_raw:
        dc.block = list(dom_raw["block"] or [])
        dc.mode = "blocklist"
    elif "mode" in dom_raw:
        # Backward compat: mode + list
        dc.mode = dom_raw["mode"]
        entries = list(dom_raw.get("list") or [])
        if dc.mode == "allowlist":
            dc.allow = entries
        elif dc.mode == "blocklist":
            dc.block = entries
    cfg.domains = dc

    # Logging
    log_raw = raw.get("logging") or {}
    lc = LoggingConfig()
    lc.dns_queries = bool(log_raw.get("dns_queries", False))
    lc.proxy_connections = bool(log_raw.get("proxy_connections", False))
    if "allowed_requests" in log_raw:
        lc.allowed_requests = bool(log_raw["allowed_requests"])
    else:
        lc.allowed_requests = bool(raw.get("log_allowed", False))
    lc.level = str(log_raw.get("level", "info") or "info")
    lc.dns = str(log_raw.get("dns", "") or "")
    lc.proxy = str(log_raw.get("proxy", "") or "")
    lc.cage = str(log_raw.get("cage", "") or "")
    cfg.logging = lc

    # Capture
    cap_raw = raw.get("capture") or {}
    cap = CaptureConfig()
    cap.enable_har = bool(cap_raw.get("enable_har", False))
    cap.max_body_size = int(cap_raw.get("max_body_size", MAX_CAPTURE_BODY_BYTES))
    cap.min_action = str(cap_raw.get("min_action", "all") or "all")
    cap.domains = list(cap_raw.get("domains") or [])
    cap.exclude_domains = list(cap_raw.get("exclude_domains") or [])
    cfg.capture = cap

    # Ports — nested by protocol. Per-entry type/range validation is
    # deferred to validate_config so all bad entries are reported together.
    # The structural shape (mappings at each level) is checked here so a
    # malformed config like `ports: "yes"` or `ports.tcp: [80, 443]`
    # (operator forgot the `allow:` key) raises a clean error rather than
    # crashing with AttributeError/TypeError or silently swallowing the
    # operator's intent.
    pt_raw = raw.get("ports") or {}
    if not isinstance(pt_raw, dict):
        raise ValueError(
            f"ports must be a mapping with 'tcp', 'udp', and/or 'icmp' keys "
            f"(got: {pt_raw!r})"
        )
    pt = PortsConfig()

    tcp_raw = pt_raw.get("tcp") or {}
    if not isinstance(tcp_raw, dict):
        raise ValueError(
            f"ports.tcp must be a mapping with 'allow' and/or "
            f"'passthrough' keys (got: {tcp_raw!r}). If you meant to list "
            f"TCP ports, use 'ports.tcp.allow: [...]'"
        )
    if "allow" in tcp_raw:
        raw_tcp_allow = tcp_raw["allow"] or []
        if not isinstance(raw_tcp_allow, list):
            raise ValueError(
                f"ports.tcp.allow must be a list of integers "
                f"(got: {raw_tcp_allow!r})"
            )
        pt.tcp.allow = list(raw_tcp_allow)
    if "passthrough" in tcp_raw:
        raw_tcp_pass = tcp_raw["passthrough"] or []
        if not isinstance(raw_tcp_pass, list):
            raise ValueError(
                f"ports.tcp.passthrough must be a list of integers "
                f"(got: {raw_tcp_pass!r})"
            )
        pt.tcp.passthrough = list(raw_tcp_pass)

    udp_raw = pt_raw.get("udp") or {}
    if not isinstance(udp_raw, dict):
        raise ValueError(
            f"ports.udp must be a mapping with an 'allow' key "
            f"(got: {udp_raw!r}). If you meant to list UDP ports, "
            f"use 'ports.udp.allow: [...]'"
        )
    if "allow" in udp_raw:
        raw_udp_allow = udp_raw["allow"] or []
        if not isinstance(raw_udp_allow, list):
            raise ValueError(
                f"ports.udp.allow must be a list of integers "
                f"(got: {raw_udp_allow!r})"
            )
        pt.udp.allow = list(raw_udp_allow)

    icmp_raw = pt_raw.get("icmp") or {}
    if not isinstance(icmp_raw, dict):
        raise ValueError(
            f"ports.icmp must be a mapping with an 'allow' boolean "
            f"(got: {icmp_raw!r}). To allow outbound ping, use "
            f"'ports.icmp.allow: true'"
        )
    if "allow" in icmp_raw:
        raw_icmp_allow = icmp_raw["allow"]
        if not isinstance(raw_icmp_allow, bool):
            raise ValueError(
                f"ports.icmp.allow must be a boolean (got: {raw_icmp_allow!r})"
            )
        pt.icmp.allow = raw_icmp_allow

    cfg.ports = pt

    # apple-container only: opt-in launchd autostart at user login.
    cfg.apple_container_autostart = bool(raw.get("apple_container_autostart", False))

    # Help text
    cfg.help = str(raw.get("help", "") or "")

    # Exec aliases
    aliases_raw = raw.get("exec_aliases") or {}
    cfg.exec_aliases = {
        k: list(v) for k, v in aliases_raw.items() if isinstance(v, list)
    }

    return cfg


def validate_config(config: Config) -> list[str]:
    """Validate a config and return a list of warnings.

    Raises ValueError for fatal errors.
    """
    if not config.name:
        raise ValueError("'name' is required in config")
    if not re.match(r'^[a-z0-9][a-z0-9-]{0,62}$', config.name):
        raise ValueError(
            f"'name' must be 1-63 lowercase alphanumeric characters or hyphens, "
            f"starting with a letter or digit (got: {config.name!r})"
        )
    if not config.container.image:
        raise ValueError("container.image is required in config")
    if not re.match(
        r'^[a-zA-Z0-9][a-zA-Z0-9._/:-]*(@sha256:[a-f0-9]{64})?$',
        config.container.image,
    ):
        raise ValueError(
            f"invalid container image reference: {config.container.image!r}"
        )

    if config.isolation not in ("container", "vm", "apple-container"):
        raise ValueError(
            f"isolation must be 'container', 'vm', or 'apple-container' "
            f"(got: {config.isolation!r})"
        )

    if config.lifecycle not in _VALID_LIFECYCLES:
        raise ValueError(
            f"lifecycle must be one of {_VALID_LIFECYCLES} "
            f"(got: {config.lifecycle!r})"
        )

    if config.isolation == "container" and platform.system() == "Darwin":
        raise ValueError(
            "container isolation is not available on macOS; "
            "use vm or apple-container instead"
        )

    if config.isolation == "apple-container":
        if platform.system() != "Darwin":
            raise ValueError(
                "apple-container isolation requires macOS; "
                f"current platform is {platform.system()}"
            )
        if platform.machine() != "arm64":
            raise ValueError(
                "apple-container isolation requires Apple Silicon (arm64); "
                f"current arch is {platform.machine()}"
            )

    if config.isolation == "vm":
        vm = config.vm
        if vm.vcpus < 1:
            raise ValueError("vm.vcpus must be >= 1")
        if vm.mem_mb < 128:
            raise ValueError("vm.mem_mb must be >= 128")

    # Validate logging levels
    if config.logging.level not in _VALID_LEVELS:
        raise ValueError(
            f"logging.level must be one of {_VALID_LEVELS} "
            f"(got: {config.logging.level!r})"
        )
    for svc in ("dns", "proxy", "cage"):
        val = getattr(config.logging, svc)
        if val and val not in _VALID_LEVELS:
            raise ValueError(
                f"logging.{svc} must be one of {_VALID_LEVELS} or empty "
                f"(got: {val!r})"
            )

    # Validate port specs
    for port_spec in config.container.ports:
        parts = port_spec.split(":")
        if len(parts) == 3:
            _bind, host_port_s, container_port_s = parts
            port_strs = [host_port_s, container_port_s]
        elif len(parts) == 2:
            port_strs = list(parts)
        else:
            raise ValueError(
                f"invalid port spec {port_spec!r}: "
                f"expected HOST_PORT:CONTAINER_PORT or BIND:HOST_PORT:CONTAINER_PORT"
            )
        for ps in port_strs:
            try:
                pn = int(ps)
            except ValueError:
                raise ValueError(
                    f"invalid port number {ps!r} in port spec {port_spec!r}"
                )
            if pn < 1 or pn > 65535:
                raise ValueError(
                    f"port {pn} out of range (1-65535) in port spec {port_spec!r}"
                )

    # Validate ports.tcp.allow + ports.tcp.passthrough + ports.udp.allow.
    #
    # Per-list type/range/dedupe validation is independent. Reserved-port
    # checks apply only to the inspected TCP set (= tcp.allow -
    # tcp.passthrough): those ports become nat:PREROUTING REDIRECT rules,
    # which collide with mitmdump's own listeners and with in-process
    # listeners (relays, reverse-mode mitmdump for inbound forwards).
    # Passthrough ports never get a REDIRECT, so they don't conflict.
    # UDP entries never get REDIRECT either — mitmdump can't audit UDP —
    # so reserved-port checks don't apply to them.
    def _check_port_entry(entry: object, field_label: str) -> None:
        if isinstance(entry, bool) or not isinstance(entry, int):
            raise ValueError(
                f"{field_label} entries must be integers (got: {entry!r})"
            )
        if entry < 1 or entry > 65535:
            raise ValueError(
                f"{field_label} entry {entry} out of range (1-65535)"
            )

    def _validate_port_list(entries: list, field_label: str) -> set[int]:
        seen: set[int] = set()
        for entry in entries:
            _check_port_entry(entry, field_label)
            if entry in seen:
                raise ValueError(
                    f"{field_label} entry {entry} appears more than once"
                )
            seen.add(entry)
        return seen

    tcp_allow_set = _validate_port_list(
        config.ports.tcp.allow, "ports.tcp.allow"
    )
    tcp_passthrough_set = _validate_port_list(
        config.ports.tcp.passthrough, "ports.tcp.passthrough"
    )
    udp_allow_set = _validate_port_list(
        config.ports.udp.allow, "ports.udp.allow"
    )

    # Inspected TCP = effective allow (tcp.allow ∪ tcp.passthrough)
    # minus tcp.passthrough. Reserved-port checks apply here only.
    inspected_tcp_ports = tcp_allow_set - tcp_passthrough_set
    # Sort before iterating: set order is non-deterministic in CPython,
    # so with multiple reserved-port violations the operator would see a
    # different "first violation" on each run. Sorted ascending means the
    # smallest violating port is reported first, predictably.
    for entry in sorted(inspected_tcp_ports):
        if entry in _MITMDUMP_RESERVED_PORTS:
            raise ValueError(
                f"ports.tcp.allow entry {entry} is reserved by mitmdump "
                f"(8080 = HTTP-proxy listener, 8443 = transparent listener); "
                f"redirecting it would loop or break the L7 proxy path. "
                f"Move it to ports.tcp.passthrough if the cage needs to "
                f"reach an upstream service on this port without inspection"
            )
    # Cross-check inspected TCP ports against protocol_relays listen ports.
    for relay in config.protocol_relays:
        _, _, port_s = relay.listen.rpartition(":")
        if not port_s:
            continue
        try:
            relay_port = int(port_s)
        except ValueError:
            continue
        if relay_port in inspected_tcp_ports:
            raise ValueError(
                f"ports.tcp.allow entry {relay_port} collides with "
                f"protocol_relays[{relay.name!r}].listen={relay.listen!r}; "
                f"the REDIRECT would intercept connections meant for the "
                f"relay. Move it to ports.tcp.passthrough if the cage also "
                f"talks to an external service on this port"
            )
    # Cross-check inspected TCP ports against container.ports inbound
    # forwards — the proxy runs reverse-mode mitmdump listeners on
    # those ports, and PREROUTING REDIRECT fires before INPUT.
    for port_spec in config.container.ports:
        parts = port_spec.split(":")
        if len(parts) == 3:
            container_port_s = parts[2]
        elif len(parts) == 2:
            container_port_s = parts[1]
        else:
            continue
        try:
            container_port = int(container_port_s)
        except ValueError:
            continue
        if container_port in inspected_tcp_ports:
            raise ValueError(
                f"ports.tcp.allow entry {container_port} collides with "
                f"container.ports inbound forward {port_spec!r}; the "
                f"REDIRECT would intercept connections meant for the "
                f"cage's reverse-mode listener"
            )

    # Validate domain config
    if config.domains.allow and config.domains.block:
        raise ValueError(
            "domains: cannot specify both 'allow' and 'block' lists"
        )

    warnings = []

    def _is_scaffold_default_tmpfs(entries: list[str]) -> bool:
        """A single entry whose target is /tmp matches the stock scaffold
        default (``tmpfs: ["/tmp:rw,noexec,nosuid,size=256M"]``). On
        apple-container the cage's /tmp lives in the RW rootfs, so the
        functional outcome (writable /tmp for the workload) is the same;
        the noexec/nosuid hardening flags aren't enforced but no scaffold
        relies on them. Multiple entries OR a non-``/tmp`` target IS
        operator intent that this backend can't honor — keep warning."""
        if len(entries) != 1:
            return False
        target = entries[0].split(":", 1)[0]
        return target == "/tmp"

    # Apple-container backend: surface config knobs that the backend doesn't
    # respect today (silently dropped pre-this-warning). Tracked as the full
    # parity work in #120. Plain `validate_config` warnings so the user sees
    # them on cage create / update / show — they don't block the operation
    # because several built-in scaffolds (ubuntu, etc.) set these fields
    # unconditionally for the container backend. The right long-term fix is
    # either to make the supervisor honor them or to make the scaffold
    # cage.yaml.j2 templates omit them on apple-container; until then, this
    # tells the operator their `tmpfs:` / `volumes:` / `add_capabilities:`
    # entries are decorative on this backend.
    if config.isolation == "apple-container":
        # Each entry: (field-path, predicate-on-config-that-says-"non-default",
        # human-readable summary of what the field's effect would be elsewhere).
        _ac_silent_drops: list[tuple[str, bool, str]] = [
            # container.volumes is no longer silently dropped — it now
            # flows through `AppleContainerBackend.start()` as per-entry
            # `--volume host:cage[:mode]` argv, with the same containment
            # rule the container backend's quadlet enforces (host path
            # must live under $HOME). See backends/apple_container.py
            # `_user_volume_argv`.
            ("container.named_volumes", bool(config.container.named_volumes),
             "podman named volumes (no equivalent on apple-container)"),
            # Stock scaffold ships `tmpfs: ["/tmp:rw,noexec,nosuid,size=256M"]`
            # as defense-in-depth for the container backend. On apple-
            # container the cage's /tmp lives in the RW rootfs — the
            # workload functionally gets a writable /tmp, and the noexec
            # /nosuid hardening flags aren't enforced. A single /tmp
            # entry is the documented scaffold default; treating it as
            # "compatible enough" silences the noisiest warning on every
            # default cage. Anything else (multiple entries, non-/tmp
            # targets like /run, /var/cache) still warns because those
            # do represent operator intent that this backend can't honor.
            ("container.tmpfs",
             bool(config.container.tmpfs) and not _is_scaffold_default_tmpfs(
                 config.container.tmpfs
             ),
             "tmpfs mounts (apple-container's rootfs is RW; explicit tmpfs entries "
             "are not wired)"),
            ("container.podman_secrets", bool(config.container.podman_secrets),
             "Podman secret refs (no host Podman secret store on apple-container; "
             "use cage.yaml `secret_injection:` or env: instead)"),
            ("container.nested_containers", bool(config.container.nested_containers),
             "nested container runtime (no podman-in-podman shim available in "
             "the Apple microVM)"),
            # Inbound published ports. On the container/vm backends these
            # become egress `PublishPort=host:host_port:container_port`
            # entries plus reverse-mode mitmdump listeners, exposing a cage
            # service to the host through the inspector chain. Apple's
            # `container` runtime has no host-port-publishing equivalent —
            # it uses VMNET_SHARED_MODE NAT and reaches containers by their
            # vmnet-assigned IP, not via host port forwarding (verified
            # against apple/container; see backends/apple_container.py
            # NonisolatedInterfaceStrategy note). So a `container.ports:`
            # entry is silently dropped here. Warn so operators stop being
            # surprised by an inbound service that never becomes reachable.
            ("container.ports", bool(config.container.ports),
             "inbound published ports — Apple's runtime has no host "
             "port-publishing (no `--publish`); reach the cage by its "
             "vmnet IP instead"),
            # Scaffold default `userns: "keep-id"` exists for the container
            # backend's rootless-podman uid mapping. On apple-container,
            # the supervisor's drop-to-uid-1000 already achieves the
            # "workload isn't root" goal, so keep-id is functionally a
            # no-op rather than a missing feature. Anything else (e.g.
            # an explicit remap config) is operator intent that doesn't
            # apply here — keep warning on those.
            ("container.userns",
             bool(config.container.userns) and config.container.userns != "keep-id",
             "user namespace remap (the supervisor drops to a fixed uid 1000 — "
             "no remap layer)"),
            # container.add_capabilities is intentionally NOT warned about.
            # The cage workload always runs as uid 1000 with an empty cap
            # set (cage-init.sh Stage D capsh-drops ALL caps before exec),
            # so added caps are inert on this backend regardless. But every
            # stock package-manager scaffold (ubuntu/debian/arch/openclaw)
            # sets add_capabilities unconditionally for the container
            # backend's build/install path, so warning here fired on every
            # default apple-container cage — pure noise on the common path,
            # like the read_only / tmpfs warnings tuned down below.
            ("container.drop_capabilities",
             list(config.container.drop_capabilities) != ["ALL"],
             "custom drop list — the supervisor unconditionally drops ALL caps; "
             "your selective drop list has no effect"),
            # Only warn when the operator EXPLICITLY wants a read-only
            # rootfs and apple-container can't deliver. The False default
            # matches the backend's actual behavior — it's not a conflict,
            # just config-vs-runtime parity. Pre-0.22.7 the predicate was
            # `is False` which fired on every default cage (the scaffold
            # ships read_only: false for coding agents that write to the
            # FS), making this the single noisiest warning on every
            # `agentcage run`.
            ("container.read_only", config.container.read_only is True,
             "read-only rootfs — apple-container's rootfs is always RW, "
             "so `read_only: true` cannot be enforced"),
            ("container.security_label_disable",
             config.container.security_label_disable is False,
             "SELinux label control — apple-container's microVM has no SELinux"),
            # capture.enable_har is intentionally NOT in this list: HAR
            # body capture now works end-to-end on apple-container — the
            # in-cage mitmproxy addon stages inbound+outbound snapshots
            # under the shared CaptureWriter and writes them to
            # /var/log/agentcage/capture.jsonl (bind-mounted to the host).
            # See docs/apple-container.md → "HAR body capture".
        ]
        for field_path, non_default, summary in _ac_silent_drops:
            if non_default:
                warnings.append(
                    f"{field_path}: silently has no effect on apple-container "
                    f"({summary}). See issue #120 for the parity plan."
                )
        # secret_injection.transform now runs end-to-end on apple-container
        # — the in-cage mitmproxy addon loads the same data/proxy/transforms
        # registry the container backend uses. KNOWN_TRANSFORMS is the
        # source of truth for "what the addon can dispatch". Anything
        # outside that set is rejected at parse time by validate_transform,
        # so reaching this loop with an unknown transform is impossible.
        # We keep the loop as a hard assert so a future divergence between
        # the schema (KNOWN_TRANSFORMS) and the in-cage registry surfaces
        # as a config-time warning instead of a silent runtime drop.
        for rule in config.secret_injection:
            transform = getattr(rule, "transform", "") or ""
            if transform and transform not in KNOWN_TRANSFORMS:
                warnings.append(
                    f"secret_injection[{rule.env!r}].transform "
                    f"={transform!r}: not in KNOWN_TRANSFORMS — the "
                    f"apple-container addon will skip the rule at "
                    f"startup. See issue #120."
                )
        # Inspector chain — built-in inspectors run end-to-end on
        # apple-container as of this PR (the in-cage addon dispatches
        # through the same data/proxy/inspectors registry the container
        # backend uses). Built-in names are silently accepted. Entries
        # with ``path:`` (custom Python files) are NOT yet staged into
        # the wrapper image; warn so the operator doesn't expect those
        # to run. Unknown built-in names also warn so a typo doesn't
        # silently no-op.
        for idx, entry in enumerate(config.inspectors or []):
            if not isinstance(entry, dict):
                continue
            name = entry.get("name", "")
            path = entry.get("path")
            if path:
                warnings.append(
                    f"inspectors[{idx}] {name!r}: custom Python file "
                    f"inspectors (path: ...) are not yet staged into "
                    f"the apple-container wrapper image — the in-cage "
                    f"addon will skip this entry. Use a built-in "
                    f"inspector or stay on the container backend."
                )
            elif name and name not in _BUILTIN_INSPECTOR_NAMES:
                warnings.append(
                    f"inspectors[{idx}] {name!r}: not a known built-in "
                    f"inspector — the in-cage addon will skip this "
                    f"entry. Valid names: "
                    f"{', '.join(sorted(_BUILTIN_INSPECTOR_NAMES))}."
                )

    # Warn when a tcp.passthrough port isn't explicitly listed in
    # tcp.allow — mirrors the domains.passthrough auto-merge warning.
    for p in config.ports.tcp.passthrough:
        if (
            isinstance(p, int) and not isinstance(p, bool)
            and p not in tcp_allow_set
        ):
            warnings.append(
                f"ports.tcp.passthrough entry {p} is not in "
                f"ports.tcp.allow and will be added automatically to "
                f"the effective allow list"
            )

    # Warn when transparent TCP capture is fully disabled — only L7-aware
    # traffic (apps that honor HTTP_PROXY) will be audited. Inspected
    # TCP ports = tcp.allow - tcp.passthrough; if empty, no REDIRECT
    # rules are installed.
    if not inspected_tcp_ports:
        warnings.append(
            "ports has no inspected TCP entries (tcp.allow - "
            "tcp.passthrough is empty): transparent capture disabled, "
            "only L7 HTTP_PROXY-aware traffic will be audited"
        )

    # Warn when default-deny would leave the cage with zero outbound.
    # filter:FORWARD policy is DROP; inspected TCP ports get REDIRECTed,
    # tcp.passthrough gets explicit TCP ACCEPT, udp.allow gets UDP
    # ACCEPT, ICMP echo-request always ACCEPT. If all three port lists
    # are empty, only ICMP echo + ESTABLISHED,RELATED traffic is allowed
    # and the cage cannot initiate any new TCP/UDP outbound connection.
    effective_allow = tcp_allow_set | tcp_passthrough_set | udp_allow_set
    if not effective_allow:
        warnings.append(
            "ports.tcp.allow, ports.tcp.passthrough, and ports.udp.allow "
            "are all empty: the cage will have zero outbound TCP/UDP "
            "connectivity (the proxy's filter:FORWARD policy is DROP "
            "and no ports are allowed through)"
        )

    # Warn about placeholders that aren't in the canonical
    # ``agentcage:secret:<ENV>:<hex>`` shape. A placeholder is matched as a
    # literal string in outbound content, so a guessable value like
    # ``{{GH_TOKEN}}`` — or any string an outbound payload might legitimately
    # contain — is an accidental-substitution hazard. The canonical prefix is
    # also self-identifying: tooling can recognize an agentcage placeholder on
    # sight. Existing cages keep working (this is a warning, not a hard
    # error); `agentcage secret rotate-placeholders` mints a conforming token.
    for rule in config.secret_injection:
        if rule.placeholder and not rule.placeholder.startswith(PLACEHOLDER_PREFIX):
            warnings.append(
                f"secret_injection[{rule.env!r}]: placeholder "
                f"'{rule.placeholder}' is not in the '{PLACEHOLDER_PREFIX}*' "
                f"form — omit `placeholder:` to auto-generate an entropic "
                f"token, or run `agentcage secret rotate-placeholders` to "
                f"mint one"
            )

    # Warn about passthrough implications
    if config.domains.passthrough:
        warnings.append(
            "domains.passthrough bypasses TLS interception for listed domains "
            "(proxy inspectors will not see this traffic)"
        )
        # Warn if passthrough domain not covered by allowlist
        if config.domains.mode == "allowlist":
            allow_set = set(config.domains.allow)
            for d in config.domains.passthrough:
                if d not in allow_set:
                    warnings.append(
                        f"passthrough domain '{d}' is not in the allow list "
                        f"and will be added automatically for DNS resolution"
                    )

    # Nested containers validation
    if config.container.nested_containers:
        if config.isolation == "vm":
            raise ValueError(
                "nested_containers is not supported with vm isolation"
            )
        warnings.append(
            "nested_containers grants elevated capabilities, "
            "disables NoNewPrivileges, and disables seccomp"
        )

    # Warn about unset env var references
    for key, val in config.container.env.items():
        val_str = str(val)
        start = 0
        while True:
            idx = val_str.find("${", start)
            if idx == -1:
                break
            end = val_str.find("}", idx)
            if end == -1:
                break
            varname = val_str[idx + 2:end]
            if varname and varname not in os.environ:
                warnings.append(
                    f"env var reference ${{{varname}}} is unset (key: {key})"
                )
            start = end + 1

    return warnings
