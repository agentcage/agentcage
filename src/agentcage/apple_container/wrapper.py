"""Per-cage wrapper image generation for the apple-container backend.

PR 3 of #196 — 2-microVM refactor. The legacy `build_wrapper` produced a
heavyweight image carrying mitmproxy + dnsmasq + iptables + supervisor.sh.
That all moved to the sibling <cage>-egress microVM (built from the
shared agentcage-egress image; PR 1). What's left here is a tiny wrapper
that adds a `cage-init.sh` entrypoint to the user's image — sets the
default route to the egress sibling, capsh-drops, then exec's the user's
original CMD via a shell-escaped one-shot script.

Helpers also exposed from this module (still used by build_artifacts +
domain add/rm):
  - `render_dnsmasq_conf(allowlist, dns_servers)` — host-side rendering
    of the dnsmasq config. Now bind-mounted into the egress microVM at
    runtime rather than baked into the wrapper image. Same template
    (dnsmasq.conf.j2) as the legacy path.
"""

from __future__ import annotations

import shlex
import shutil
from pathlib import Path
from typing import Iterable

from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment

from agentcage.apple_container import cli as ac_cli


_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "apple-container"


def _user_cmd(user_image: str) -> list[str]:
    """Resolve the user image's effective CMD (ENTRYPOINT + CMD, exec form).

    Apple's `container image inspect` returns the OCI image index plus a
    per-platform variant block; the OCI image config lives at
    ``variants[<host-platform>].config.config`` and uses OCI-style
    capitalized keys (``Cmd``, ``Entrypoint``).
    """
    data = ac_cli.image_inspect(user_image)
    if not data:
        raise ValueError(
            f"cannot inspect user cage image {user_image!r}; is it pulled/built?"
        )

    cfg: dict | None = None
    # Newer Apple schema: data["variants"][i]["config"]["config"]
    variants = data.get("variants") or data.get("Variants")
    if isinstance(variants, list):
        # Prefer the arm64 variant (we're on Apple Silicon); fall back to any.
        for v in variants:
            plat = (v.get("platform") or {})
            if plat.get("architecture") == "arm64":
                cfg = ((v.get("config") or {}).get("config")) or {}
                break
        if cfg is None and variants:
            cfg = ((variants[0].get("config") or {}).get("config")) or {}
    # Older / generic schemas:
    if cfg is None:
        cfg = (
            (data.get("config", {}) or {}).get("config")
            or data.get("config")
            or data.get("Config")
            or {}
        )

    entrypoint = cfg.get("Entrypoint") or cfg.get("entrypoint") or []
    cmd = cfg.get("Cmd") or cfg.get("cmd") or []
    if isinstance(entrypoint, str):
        entrypoint = [entrypoint]
    if isinstance(cmd, str):
        cmd = [cmd]
    combined = [*entrypoint, *cmd]
    if not combined:
        raise ValueError(
            f"user cage image {user_image!r} has neither ENTRYPOINT nor CMD; "
            "agentcage cannot determine what to run"
        )
    return combined


def _shlex_join_argv(argv: list[str]) -> str:
    """Shell-escape each argv element and join with spaces.

    The result is safe to feed straight to ``/bin/sh -c "exec <result>"``
    or as the body of an `exec ...` line in a sh script. Every shell
    metacharacter (whitespace, ``$VAR``, ``&&``, ``;``, etc.) is escaped
    by ``shlex.quote`` so the cage user's argv survives the build-time
    bake into ``cage-cmd.sh`` verbatim.
    """
    return " ".join(shlex.quote(a) for a in argv)


def render_wrapper_containerfile(
    user_image: str,
    *,
    user_cmd: list[str] | None = None,
) -> str:
    """Render the per-cage wrapper Containerfile to a string.

    The template's only dynamic inputs are the user image reference and
    the shell-escaped form of the user's CMD (baked into cage-cmd.sh by
    a RUN heredoc).
    """
    env = SandboxedEnvironment(
        loader=FileSystemLoader(str(_DATA_DIR)),
        keep_trailing_newline=True,
    )
    if user_cmd is None:
        user_cmd = _user_cmd(user_image)
    tmpl = env.get_template("Containerfile.wrapper.j2")
    return tmpl.render(
        user_image=user_image,
        user_cmd_quoted=_shlex_join_argv(user_cmd),
    )


_DEFAULT_DNS_SERVERS: list[str] = ["1.1.1.1", "8.8.8.8"]


def render_dnsmasq_conf(
    allowlist: list[str] | None,
    dns_servers: list[str] | None = None,
) -> str:
    """Render the per-cage dnsmasq.conf with allowlist-scoped recursion.

    Recursion is permitted ONLY for hostnames within an explicitly
    allowlisted apex domain — every other zone returns REFUSED regardless
    of record type. Without this scoping a blanket ``server=<upstream>``
    line would forward TXT/MX/NS/SRV/CNAME queries to upstream for any
    hostname an attacker chose, which is a fully out-of-band DNS-tunnel
    exfil channel (mitmproxy never sees DNS).

    Same template + invariants as the legacy wrapper. The semantic
    location moved (bind-mounted into the egress microVM at runtime
    instead of baked into the wrapper image at build time), but the
    rendering itself is unchanged so all the dnsmasq-shape regression
    tests still apply.
    """
    env = SandboxedEnvironment(
        loader=FileSystemLoader(str(_DATA_DIR)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    tmpl = env.get_template("dnsmasq.conf.j2")
    return tmpl.render(
        allowlist=[h.strip() for h in (allowlist or []) if h.strip()],
        dns_servers=list(dns_servers or _DEFAULT_DNS_SERVERS),
    )


def stage_build_context(
    dest: Path,
    user_cmd: list[str],
    # Kwargs kept (and ignored) for back-compat with callers that still
    # pass them — the 2-microVM refactor moved every per-cage proxy/dns
    # config out of the wrapper image, so none of these flow into the
    # cage's build context anymore. The signatures stay so existing
    # callers (build_artifacts, possibly tests) don't have to keep
    # version-gating; they'll all be cleaned up in a follow-up.
    allowlist: list[str] | None = None,  # noqa: ARG001  -- egress-side now
    secret_injection_rules: list[dict] | None = None,  # noqa: ARG001
    protocol_relays: list[dict] | None = None,  # noqa: ARG001
    capture_config: dict | None = None,  # noqa: ARG001
    inspectors: list[dict] | None = None,  # noqa: ARG001
    dns_servers: list[str] | None = None,  # noqa: ARG001
) -> None:
    """Stage cage-init.sh into the wrapper build context.

    Files written:
      - cage-init.sh — PID 1 of the cage microVM. Waits for the egress
                       sibling to be ARP-reachable, replaces the default
                       route via the egress IP, installs the proxy CA
                       into the trust store, capsh-drops + exec's the
                       user's CMD via cage-cmd.sh.

    Files no longer written (vs the legacy single-VM model):
      - supervisor.sh        — deleted; the egress image's supervisor
                                handles every stage 30-80 equivalent.
      - allowlist_addon.py   — mitmproxy addon now lives in the egress
                                container's image (PR 1 + PR 2 wire it).
      - capture.py           — same.
      - cage-cmd.json        — replaced by /opt/agentcage/cage-cmd.sh,
                                baked at build time via a RUN heredoc
                                in Containerfile.wrapper.j2 with the
                                shlex.quote'd argv. No runtime jq.
      - allowlist.txt        — egress-side now.
      - dnsmasq.conf         — egress-side; rendered host-side and
                                bind-mounted into the egress container.
      - secret_injection.json + protocol_relays.json + capture.json
        + inspectors.json    — egress-side now (PR 2 stages the addon
                                config dir on the host and bind-mounts
                                it into the egress container).
      - transforms.tar.gz / relays.tar.gz / inspectors.tar.gz
                              — egress-side.
    """
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy2(_DATA_DIR / "cage-init.sh", dest / "cage-init.sh")


def wrapped_image_name(cage_name: str) -> str:
    """Return the OCI image reference for the wrapped per-cage image.

    The per-cage tag is unchanged from the legacy single-VM model so
    `cage update` on a 0.21 cage finds the existing image and replaces
    it in place. The PR 3 image content is unrecognizable to the
    legacy supervisor, but Apple's `container build` retags freely.
    """
    return f"localhost/agentcage-apple-{cage_name}:latest"


def build_wrapper(
    cage_name: str,
    user_image: str,
    *,
    user_cmd: list[str] | None = None,
    # Back-compat kwargs — see stage_build_context's docstring. None of
    # these flow into the wrapper image anymore; the per-cage egress
    # config (dnsmasq.conf, allowlist, secret_injection.json, etc.) is
    # rendered host-side by AppleContainerBackend.build_artifacts and
    # bind-mounted into the egress sibling at runtime.
    allowlist: list[str] | None = None,  # noqa: ARG001
    secret_injection_rules: list[dict] | None = None,  # noqa: ARG001
    protocol_relays: list[dict] | None = None,  # noqa: ARG001
    capture_config: dict | None = None,  # noqa: ARG001
    inspectors: list[dict] | None = None,  # noqa: ARG001
    dns_servers: list[str] | None = None,  # noqa: ARG001
) -> str:
    """Generate Containerfile, stage build context, run `container build`.

    Returns the built image reference.
    """
    import tempfile

    image = wrapped_image_name(cage_name)

    if user_cmd is None:
        user_cmd = _user_cmd(user_image)

    containerfile = render_wrapper_containerfile(user_image, user_cmd=user_cmd)

    with tempfile.TemporaryDirectory(prefix="agentcage-apple-build-") as tmp:
        tmpdir = Path(tmp)
        (tmpdir / "Containerfile").write_text(containerfile)
        stage_build_context(tmpdir, user_cmd)
        ac_cli.run(
            ["build", "-t", image, "-f", str(tmpdir / "Containerfile"), str(tmpdir)],
            capture_output=False,  # stream output to user
        )
    return image


def collect_image_artifacts(cage_name: str) -> Iterable[str]:
    """Return image references owned by *cage_name* (for cleanup).

    The shared agentcage-egress image is NOT yielded here — destroying
    one cage must not delete an image used by sibling cages. The egress
    image is host-wide; its lifecycle is tied to the agentcage version.
    """
    yield wrapped_image_name(cage_name)
