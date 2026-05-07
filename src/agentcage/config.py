"""Parse and validate agentcage YAML configuration."""

from __future__ import annotations

import ipaddress
import os
import platform
import re
from dataclasses import dataclass, field

import yaml

from agentcage.data.proxy.relays._validate import (
    KNOWN_RELAY_TYPES,
    validate_relay_entry,
    validate_relay_type,
)


KNOWN_TRANSFORMS = frozenset({"google-jwt-bearer"})


@dataclass
class SecretInjectionRule:
    env: str
    placeholder: str
    inject_to: list[str] = field(default_factory=list)
    source: str = ""
    transform: str = ""
    transform_config: dict = field(default_factory=dict)


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


# Default permitted destination ports for `ports.allow`. Catches HTTP
# and HTTPS on standard ports. Extend (e.g. add 8448 for a Matrix
# homeserver) to permit non-standard services. Ports outside this list
# (and outside `ports.passthrough`) are dropped by the proxy's
# filter:FORWARD policy.
DEFAULT_ALLOW_PORTS = (80, 443)

# Reserved by mitmdump's own listeners; redirecting them would either
# loop (8443 is the transparent listener's own port) or break the L7
# HTTP_PROXY path (8080 is the regular HTTP-proxy listener). Applied
# only to inspected ports (= allow - passthrough); passthrough ports
# never get a REDIRECT rule, so they don't conflict.
_MITMDUMP_RESERVED_PORTS = (8080, 8443)


@dataclass
class PortsConfig:
    """Cage egress port policy.

    Mirrors the shape of ``DomainConfig``:

    - ``allow`` — TCP+UDP destination ports the cage may reach. Anything
      not in ``allow`` (and not in ``passthrough``, which is implicitly
      allowed) is dropped by the proxy's filter:FORWARD policy.
    - ``passthrough`` — subset of allowed ports that bypass mitmdump
      inspection. These flow L3-forwarded to upstream without entering
      audit.jsonl, the inspector chain, or the secret injector. UDP
      traffic to ports not in this list is blocked, so QUIC/HTTP3
      requires an explicit entry.

    Inspected ports = allow - passthrough. There is no opt-out flag for
    the default-deny FORWARD policy; every cage gets it on next
    ``cage update``.
    """
    allow: list[int] = field(
        default_factory=lambda: list(DEFAULT_ALLOW_PORTS)
    )
    passthrough: list[int] = field(default_factory=list)


@dataclass
class VmConfig:
    vcpus: int = 4
    mem_mb: int = 4096


@dataclass
class RelayUpstream:
    host: str
    port: int
    tls: bool = True


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
    folder_allowlist: list[str] = field(default_factory=list)

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
    isolation: str = "container"  # "container" | "vm"
    lifecycle: str = "service"  # "service" | "interactive" | "ephemeral"
    container: ContainerConfig = field(default_factory=ContainerConfig)
    secret_injection: list[SecretInjectionRule] = field(default_factory=list)
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


def _host_dns_servers() -> list[str]:
    """Read nameservers from /etc/resolv.conf.

    Loopback addresses (e.g. 127.0.0.53 from systemd-resolved) are filtered
    out because they are unreachable from inside containers.  When all
    nameservers are loopback, the real upstreams are read from
    /run/systemd/resolve/resolv.conf.

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
    raise RuntimeError(
        "Could not detect usable DNS servers: /etc/resolv.conf contains only "
        "loopback addresses (e.g. 127.0.0.53 from systemd-resolved) and "
        f"{_RESOLVED_CONF} is missing or empty. "
        "Set dns_servers explicitly in your agentcage config."
    )


def load_config(path: str) -> Config:
    """Load and parse a agentcage YAML config file."""
    with open(path) as f:
        raw = yaml.safe_load(f)

    if not raw or not isinstance(raw, dict):
        return Config()

    cfg = Config()
    cfg.name = raw.get("name", "")
    cfg.isolation = raw.get("isolation", "container")
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

    # Secret injection — accepts list or {"rules": [...]}
    si_cfg = raw.get("secret_injection") or []
    si_rules = si_cfg.get("rules", []) if isinstance(si_cfg, dict) else si_cfg
    injected_names = set()
    from agentcage.secret_resolver import validate_env_name, validate_source

    for entry in si_rules:
        env_name = entry.get("env", "")
        placeholder = entry.get("placeholder", "")
        if env_name and placeholder:
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
            ))

    # Remove injected secrets from podman_secrets and env — they are handled
    # separately via placeholder substitution in the proxy.  Leaving them in
    # env would expose the real value inside the cage (os.path.expandvars
    # expands ${VAR} references during quadlet generation).
    cc.podman_secrets = [s for s in cc.podman_secrets if s not in injected_names]
    cc.env = {k: v for k, v in cc.env.items() if k not in injected_names}

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
            folder_allowlist=list(pol_raw.get("folder_allowlist") or []),
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

    # Ports
    pt_raw = raw.get("ports") or {}
    pt = PortsConfig()
    if "allow" in pt_raw:
        # Preserve the operator's literal entries; defer per-entry type/range
        # validation to validate_config so all bad entries are reported
        # together instead of failing on the first one.
        raw_allow = pt_raw["allow"] or []
        if not isinstance(raw_allow, list):
            raise ValueError(
                f"ports.allow must be a list of integers "
                f"(got: {raw_allow!r})"
            )
        pt.allow = list(raw_allow)
    if "passthrough" in pt_raw:
        raw_pass = pt_raw["passthrough"] or []
        if not isinstance(raw_pass, list):
            raise ValueError(
                f"ports.passthrough must be a list of integers "
                f"(got: {raw_pass!r})"
            )
        pt.passthrough = list(raw_pass)
    cfg.ports = pt

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

    if config.isolation not in ("container", "vm"):
        raise ValueError(
            f"isolation must be 'container' or 'vm' (got: {config.isolation!r})"
        )

    if config.lifecycle not in _VALID_LIFECYCLES:
        raise ValueError(
            f"lifecycle must be one of {_VALID_LIFECYCLES} "
            f"(got: {config.lifecycle!r})"
        )

    if config.isolation == "container" and platform.system() == "Darwin":
        raise ValueError(
            "container isolation is not available on macOS; use vm instead"
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

    # Validate ports.allow + ports.passthrough.
    #
    # Mirrors the domains.allow / domains.passthrough relationship:
    # `allow` is the superset of permitted destination ports, `passthrough`
    # is the subset that bypasses inspection. A passthrough port not in
    # `allow` is auto-merged at quadlet generation (with a warning here),
    # mirroring _effective_dns_allowlist.
    #
    # Reserved-port checks apply only to the inspected set
    # (= allow - passthrough), because reserved ports collide with
    # mitmdump's REDIRECT path. Passthrough ports never get a REDIRECT
    # rule — they hit filter:FORWARD ACCEPT — so they don't conflict with
    # mitmdump's listeners or with in-process relays.
    def _check_port_entry(entry: object, field_label: str) -> None:
        if isinstance(entry, bool) or not isinstance(entry, int):
            raise ValueError(
                f"{field_label} entries must be integers (got: {entry!r})"
            )
        if entry < 1 or entry > 65535:
            raise ValueError(
                f"{field_label} entry {entry} out of range (1-65535)"
            )

    seen_allow_ports: set[int] = set()
    for entry in config.ports.allow:
        _check_port_entry(entry, "ports.allow")
        if entry in seen_allow_ports:
            raise ValueError(
                f"ports.allow entry {entry} appears more than once"
            )
        seen_allow_ports.add(entry)

    seen_passthrough_ports: set[int] = set()
    for entry in config.ports.passthrough:
        _check_port_entry(entry, "ports.passthrough")
        if entry in seen_passthrough_ports:
            raise ValueError(
                f"ports.passthrough entry {entry} appears more than once"
            )
        seen_passthrough_ports.add(entry)

    # Inspected = effective allow (allow ∪ passthrough) minus passthrough.
    # Reserved-port checks apply here: each inspected port becomes a
    # nat:PREROUTING REDIRECT rule, which collides with locally-bound
    # listeners.
    inspected_ports = (
        seen_allow_ports | seen_passthrough_ports
    ) - seen_passthrough_ports
    for entry in inspected_ports:
        if entry in _MITMDUMP_RESERVED_PORTS:
            raise ValueError(
                f"ports.allow entry {entry} is reserved by mitmdump "
                f"(8080 = HTTP-proxy listener, 8443 = transparent listener); "
                f"redirecting it would loop or break the L7 proxy path. "
                f"Move it to ports.passthrough if the cage needs to reach "
                f"an upstream service on this port without inspection"
            )
    # Cross-check inspected ports against protocol_relays listen ports —
    # those bind in the same proxy container, so a REDIRECT for the same
    # port would steal connections away from the relay before it could
    # see them.
    for relay in config.protocol_relays:
        _, _, port_s = relay.listen.rpartition(":")
        if not port_s:
            continue
        try:
            relay_port = int(port_s)
        except ValueError:
            continue
        if relay_port in inspected_ports:
            raise ValueError(
                f"ports.allow entry {relay_port} collides with "
                f"protocol_relays[{relay.name!r}].listen={relay.listen!r}; "
                f"the REDIRECT would intercept connections meant for the "
                f"relay. Move it to ports.passthrough if the cage also "
                f"talks to an external service on this port"
            )
    # Cross-check inspected ports against container.ports inbound
    # forwards — for each published port, the proxy container runs an
    # extra mitmdump reverse listener on 0.0.0.0:<container_port>.
    # PREROUTING REDIRECT fires before the netfilter INPUT decision, so
    # an overlap silently steals inbound connections from the reverse
    # listener and routes them to the transparent listener instead.
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
        if container_port in inspected_ports:
            raise ValueError(
                f"ports.allow entry {container_port} collides with "
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

    # Warn when a passthrough port isn't explicitly listed in allow.
    # Mirrors the domains.passthrough warning: the port is auto-merged
    # into the effective allow set at quadlet generation time, but the
    # operator should be aware their config relies on the merge.
    allow_set = set(config.ports.allow)
    for p in config.ports.passthrough:
        if isinstance(p, int) and not isinstance(p, bool) and p not in allow_set:
            warnings.append(
                f"ports.passthrough entry {p} is not in ports.allow "
                f"and will be added automatically to the effective "
                f"allow list"
            )

    # Warn when transparent capture is fully disabled — only L7-aware
    # traffic (apps that honor HTTP_PROXY) will be audited. Inspected
    # ports = allow - passthrough; if empty, no REDIRECT rules are
    # installed.
    inspected_set = allow_set - set(config.ports.passthrough)
    if not inspected_set:
        warnings.append(
            "ports has no inspected entries (allow - passthrough is "
            "empty): transparent capture disabled, only L7 HTTP_PROXY-"
            "aware traffic will be audited"
        )

    # Warn when default-deny would leave the cage with zero outbound.
    # filter:FORWARD policy is DROP; inspected ports get REDIRECTed (so
    # they don't traverse FORWARD), passthrough ports get an explicit
    # ACCEPT. If the effective allow set is empty, ESTABLISHED,RELATED
    # is the only allowed traffic — and the cage cannot initiate any
    # new outbound connection.
    effective_allow = allow_set | set(config.ports.passthrough)
    if not effective_allow:
        warnings.append(
            "ports.allow and ports.passthrough are both empty: "
            "the cage will have zero outbound connectivity (the proxy's "
            "filter:FORWARD policy is DROP and no ports are allowed through)"
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
