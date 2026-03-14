"""Parse and validate agentcage YAML configuration."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
from dataclasses import dataclass, field

import yaml


@dataclass
class SecretInjectionRule:
    env: str
    placeholder: str
    inject_to: list[str] = field(default_factory=list)


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


@dataclass
class CaptureConfig:
    enable_har: bool = False
    max_body_size: int = 10485760  # 10MB
    min_action: str = "all"  # "all" | "flag" | "block"
    domains: list[str] = field(default_factory=list)
    exclude_domains: list[str] = field(default_factory=list)


@dataclass
class FirecrackerConfig:
    kernel: str = ""  # path to vmlinux
    vcpus: int = 2
    mem_mb: int = 2048
    firecracker_bin: str = "firecracker"


@dataclass
class Config:
    name: str = ""
    isolation: str = "container"  # "container" | "firecracker"
    container: ContainerConfig = field(default_factory=ContainerConfig)
    secret_injection: list[SecretInjectionRule] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)
    domains: DomainConfig = field(default_factory=DomainConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    firecracker: FirecrackerConfig = field(default_factory=FirecrackerConfig)
    help: str = ""
    exec_aliases: dict[str, list[str]] = field(default_factory=dict)


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

    # Firecracker section
    fc_raw = raw.get("firecracker") or {}
    fc = FirecrackerConfig()
    fc.kernel = fc_raw.get("kernel", "")
    fc.vcpus = int(fc_raw.get("vcpus", 2))
    fc.mem_mb = int(fc_raw.get("mem_mb", 2048))
    fc.firecracker_bin = fc_raw.get("firecracker_bin", "firecracker")
    cfg.firecracker = fc

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
    for entry in si_rules:
        env_name = entry.get("env", "")
        placeholder = entry.get("placeholder", "")
        if env_name and placeholder:
            injected_names.add(env_name)
            cfg.secret_injection.append(SecretInjectionRule(
                env=env_name,
                placeholder=placeholder,
                inject_to=list(entry.get("inject_to") or []),
            ))

    # Remove injected secrets from podman_secrets and env — they are handled
    # separately via placeholder substitution in the proxy.  Leaving them in
    # env would expose the real value inside the cage (os.path.expandvars
    # expands ${VAR} references during quadlet generation).
    cc.podman_secrets = [s for s in cc.podman_secrets if s not in injected_names]
    cc.env = {k: v for k, v in cc.env.items() if k not in injected_names}

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
    cap.max_body_size = int(cap_raw.get("max_body_size", 10485760))
    cap.min_action = str(cap_raw.get("min_action", "all") or "all")
    cap.domains = list(cap_raw.get("domains") or [])
    cap.exclude_domains = list(cap_raw.get("exclude_domains") or [])
    cfg.capture = cap

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

    if config.isolation not in ("container", "firecracker"):
        raise ValueError(
            f"isolation must be 'container' or 'firecracker' (got: {config.isolation!r})"
        )

    if config.isolation == "firecracker":
        fc = config.firecracker
        if not fc.kernel:
            from agentcage.firecracker.kernel import default_kernel_path
            fc.kernel = default_kernel_path()
        if fc.firecracker_bin == "firecracker" and not shutil.which("firecracker"):
            from agentcage.firecracker.binaries import default_firecracker_path
            default_fc = default_firecracker_path()
            if os.path.isfile(default_fc):
                fc.firecracker_bin = default_fc
        if fc.vcpus < 1:
            raise ValueError("firecracker.vcpus must be >= 1")
        if fc.mem_mb < 128:
            raise ValueError("firecracker.mem_mb must be >= 128")

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

    # Validate domain config
    if config.domains.allow and config.domains.block:
        raise ValueError(
            "domains: cannot specify both 'allow' and 'block' lists"
        )

    warnings = []

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
        if config.isolation == "firecracker":
            raise ValueError(
                "nested_containers is not supported with Firecracker isolation"
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
