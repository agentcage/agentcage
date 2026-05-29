"""Apple container backend — 2-microVM model (cage + egress).

PR 3 of #196: previously each cage was a single Apple microVM with a
329-line supervisor.sh booting mitmproxy + dnsmasq + iptables inside it
before capsh-dropping to uid 1000. This refactor splits the per-cage
shape into TWO sibling microVMs:

  <cage>-egress  — built from the shared `agentcage-egress` image (PR 1).
                   Carries mitmproxy + dnsmasq + iptables. Acts as a
                   router/proxy between the cage and the internet.
  <cage>         — the slimmed wrapper (FROM <user_image> + tiny
                   cage-init.sh). No mitmproxy, no dnsmasq, no iptables,
                   no jq, no acproxy/acdns users, no secrets.

Both microVMs join a per-cage Apple `container` network. cage-init.sh
inside the cage VM sets the default route to the egress VM's IP, then
capsh-drops to uid 1000 and exec's the user's CMD.

Threat model — workload (uid 1000) cannot:
  * read /home/acproxy/secrets/* (not in cage VM's namespace at all)
  * modify iptables (no binary in cage wrapper)
  * change routes (no NET_ADMIN in CapEff/CapPrm at uid 1000)
  * see other UIDs' processes (kernel namespace gives this for free —
    no need for the legacy supervisor.sh's hidepid=2 remount)

Known residual: cage VM is started with --cap-add CAP_NET_ADMIN (needed
for cage-init's `ip route replace`). `container exec --user 0 <cage>`
re-acquires NET_ADMIN per the spike on Apple's runtime; an operator with
--as-root can `ip route replace default via <host-bridge-ip>` to bypass
the egress sibling. Workload threat is unaffected. Tracked for v0.23 via
macOS pf rules.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import time
from importlib.metadata import version as _pkg_version
from pathlib import Path

import click

from agentcage.apple_container import cli as ac_cli
from agentcage.apple_container import prerequisites as ac_prereq
from agentcage.apple_container import scaffold as ac_scaffold
from agentcage.apple_container import wrapper as ac_wrapper
from agentcage.config import Config
from agentcage.quadlets import _effective_port_policy


# Shared agentcage-egress image is built once per host (tagged with the
# agentcage version so a wheel upgrade triggers a rebuild). All cages
# share this image — building per cage would burn ~30s + ~120MB on every
# `cage create`.
_EGRESS_IMAGE_REPO = "localhost/agentcage-egress"


def _agentcage_version() -> str:
    """Return the installed agentcage version (used to tag the egress image).

    Falls back to ``unknown`` if importlib.metadata can't find the
    distribution (e.g. running uninstalled from a source checkout without
    `pip install -e .`). Same fallback shape the quadlet renderer uses.
    """
    try:
        return _pkg_version("agentcage")
    except Exception:  # noqa: BLE001
        return "unknown"


def _egress_image_name() -> str:
    """Full tagged reference for the shared egress image."""
    return f"{_EGRESS_IMAGE_REPO}:{_agentcage_version()}"


def _normalize_cpus(value: str) -> str:
    """Apple's `container run --cpus` rejects fractional values; ceil to int.

    Podman accepts "0.5" / "1.5"; Apple wants "1" / "2". Round up so the
    cage gets at least the cap the user wrote. Returns the original
    string if it's already an integer or doesn't parse as a float.
    """
    try:
        f = float(value)
    except ValueError:
        return value
    return str(math.ceil(f)) if f != int(f) else str(int(f))


_MEMORY_SUFFIX_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([kKmMgGtTpP][iI]?[bB]?)?$")


def _normalize_memory(value: str) -> str:
    """Apple's `container run --memory` requires UPPERCASE K/M/G/T/P.

    Lowercase suffixes ("512m", "2g") that podman/docker accept are
    rejected. Uppercase the suffix in place; pass through unchanged if
    the value doesn't match the expected `<n><suffix>` shape so any
    operator-supplied novelty (e.g. raw byte counts) still reaches Apple
    for its own error reporting rather than being silently mangled.
    """
    m = _MEMORY_SUFFIX_RE.match(value.strip())
    if not m:
        return value
    number, suffix = m.group(1), (m.group(2) or "")
    return f"{number}{suffix.upper()}"


class AppleContainerBackend:
    """Backend using Apple's `container` CLI with a hardened supervisor."""

    # --- helpers --------------------------------------------------------------

    def _state_dir(self, name: str) -> Path:
        return Path(os.path.expanduser("~/.config/agentcage/apple-container")) / name

    def logs_dir(self, name: str) -> Path:
        """Per-cage logs dir on the host, bind-mounted into the egress microVM.

        The egress sibling writes audit.jsonl + capture.jsonl + dnsmasq.log
        + the `ready` marker into /var/log/agentcage/ inside its microVM;
        we mount this host path there so `agentcage cage audit` and
        `cage har` can read those files from the host without having to
        exec into the microVM.

        Created on demand (start), preserved on stop/restart, removed by
        destroy_resources alongside the rest of the per-cage state.
        """
        return self._state_dir(name) / "logs"

    def egress_config_dir(self, name: str) -> Path:
        """Per-cage config dir on the host, bind-mounted into the egress VM.

        Holds the bytes the egress microVM consumes at startup:
          * ``proxy-config.yaml``      → /etc/agentcage/config.yaml (mitmproxy
                                          addon reads via $AGENTCAGE_CONFIG).
          * ``dnsmasq.conf``           → /etc/agentcage/dnsmasq.conf.
          * ``dns-allowlist.conf``     → /etc/agentcage/dns-allowlist.conf.

        Host-side rendering instead of build-time bake means `domain add`
        can SIGHUP dnsmasq inside the egress VM after a host file rewrite,
        no rebuild + restart needed (parity with container/vm backends).
        """
        return self._state_dir(name) / "egress-config"

    def certs_dir(self, name: str) -> Path:
        """Per-cage CA-cert dir, bind-mounted ONLY into the egress microVM.

        This is mitmproxy's full ``~/.mitmproxy/`` working dir on the host
        — it contains the egress's CA *private* key
        (``mitmproxy-ca.pem``, ``mitmproxy-ca.p12``) which mitmproxy needs
        to mint per-host certs for transparent MITM. The private key MUST
        NEVER be exposed to the cage workload — a uid-1000 process that
        can read it can mint a trusted certificate for any allowlisted
        host and bypass the trust-store guard from cage-init.sh stage C.

        Pre-0.22.6: this dir was bind-mounted on the cage at /certs (for
        the public cert install), which silently exposed the private key
        too — caught by the CTF re-run on 0.22.5 as the headline finding.
        The cage now mounts ``public_certs_dir`` instead; the egress is
        still the only VM that sees the full mitmproxy dir.
        """
        return self._state_dir(name) / "certs"

    def public_certs_dir(self, name: str) -> Path:
        """Per-cage *public-only* cert dir, bind-mounted into BOTH microVMs.

        Egress's supervisor copies just ``mitmproxy-ca-cert.pem`` here
        after generation; cage-init.sh stage C reads it to install into
        the cage's trust store. Private key material stays in
        ``certs_dir`` which is egress-only.
        """
        return self._state_dir(name) / "public-certs"

    def secrets_dir(self, name: str) -> Path:
        """Per-cage secrets dir on the host, bind-mounted ONLY into the
        EGRESS microVM (read-only) at /home/acproxy/secrets.

        Each ``secret_injection`` rule's resolved value gets written to
        ``<secrets_dir>/<env-name>`` (mode 0600, owned by the host user)
        at ``start()`` time. The cage's ``container run`` argv carries
        only the PLACEHOLDER (``-e API_KEY={{API_KEY}}``) — the raw value
        is never on the command line (visible to host `ps`), not in
        ``container inspect`` output, and not in the cage microVM's
        namespace at all. The egress sibling reads each file and the
        mitmproxy addon substitutes the value on the wire.

        Threat-model invariant (vs the legacy single-VM model where the
        bind happened in the cage VM): `container exec --user 0 <cage>`
        cannot read injected secrets — they're in a different microVM's
        filesystem. Workload-uid-1000 already couldn't read them under
        either model, but `--as-root` operators now can't either.

        Created on demand (start), removed by destroy_resources alongside
        the rest of the per-cage state.
        """
        return self._state_dir(name) / "secrets"

    @staticmethod
    def _user_volume_argv(raw_entries: list[str]) -> list[str]:
        """Expand and validate user-supplied ``container.volumes`` entries.

        Returns a list of ``host:cage[:mode]`` strings ready to splice
        into ``container run --volume <entry>``. Mirrors the quadlet
        backend's safety rules so behavior is identical across backends:

        - Expand ``~`` and ``$VAR`` in the host portion.
        - Skip (with a warning) entries whose host path still contains an
          unresolved ``$``.
        - Reject (with a warning + skip) entries whose host path resolves
          outside the operator's home directory — prevents bind-ing
          ``/etc``, ``/var``, ``/root``, etc. by accident.
        - Reject (warning + skip) entries with no ``:`` separator (no
          target path).
        """
        out: list[str] = []
        home = os.path.realpath(os.path.expanduser("~"))
        for v in raw_entries:
            if ":" not in v:
                click.echo(
                    f"warning: skipping volume {v!r} on apple-container "
                    "(missing ':<cage-path>')",
                    err=True,
                )
                continue
            parts = v.split(":", 1)
            host_part = os.path.expandvars(os.path.expanduser(parts[0]))
            if "$" in host_part:
                click.echo(
                    f"warning: skipping volume {host_part!r} on apple-container "
                    "(unresolved variable in host path)",
                    err=True,
                )
                continue
            real = os.path.realpath(host_part)
            if not (real == home or real.startswith(home + os.sep)):
                click.echo(
                    f"warning: skipping volume {host_part!r} on apple-container "
                    f"(host path resolves outside {home!r})",
                    err=True,
                )
                continue
            out.append(f"{real}:{parts[1]}")
        return out

    def _launchd_plist_path(self, name: str) -> Path:
        """Host path of the per-cage launchd plist.

        We install into the user's LaunchAgents dir (no sudo needed; runs
        as the user at every login). The plist label and filename follow
        reverse-DNS form `io.agentcage.<cage>` so they don't collide with
        non-agentcage daemons in launchctl listings.
        """
        return Path(
            os.path.expanduser(f"~/Library/LaunchAgents/io.agentcage.{name}.plist")
        )

    def _install_launchd_plist(self, name: str) -> None:
        """Write + load the per-cage launchd plist.

        The plist re-execs `container start <cage>` at user login. Logs
        go under the per-cage state dir so `cage logs` already finds
        them. Idempotent: an existing plist is overwritten and reloaded.
        """
        binary = ac_cli.container_binary()
        if binary is None:
            click.echo(
                "warning: cannot install launchd autostart — Apple "
                "`container` CLI not found",
                err=True,
            )
            return
        plist = self._launchd_plist_path(name)
        plist.parent.mkdir(parents=True, exist_ok=True)
        state_dir = self._state_dir(name)
        state_dir.mkdir(parents=True, exist_ok=True)
        plist_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.agentcage.{name}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>start</string>
        <string>{name}</string>
    </array>
    <key>StandardOutPath</key>
    <string>{state_dir}/launchd.out.log</string>
    <key>StandardErrorPath</key>
    <string>{state_dir}/launchd.err.log</string>
</dict>
</plist>
"""
        plist.write_text(plist_xml)
        # bootstrap into the GUI user's domain (the modern macOS API).
        # `launchctl load -w` is deprecated since 10.10 and frequently
        # silently no-ops in non-TTY contexts — the symptom we hit was
        # the plist file existing but `launchctl list` showing nothing,
        # so autostart never actually ran. `bootstrap gui/<uid>` is the
        # documented replacement and the form Apple recommends for
        # ~/Library/LaunchAgents/ plists. Fall back to `load -w` if
        # `bootstrap` fails for any reason (e.g. very old macOS, no GUI
        # session) so we never get worse than the prior behavior.
        import subprocess as _sp
        label = f"io.agentcage.{name}"
        uid = os.getuid()
        domain = f"gui/{uid}"
        # bootout any prior version of the service so bootstrap doesn't
        # fail with "service is already loaded". `bootout` errors are
        # benign — they just mean the service wasn't loaded.
        _sp.run(["launchctl", "bootout", f"{domain}/{label}"],
                check=False, capture_output=True)
        result = _sp.run(["launchctl", "bootstrap", domain, str(plist)],
                         check=False, capture_output=True, text=True)
        if result.returncode != 0:
            # Fallback to legacy load -w. Worst case: same outcome as
            # before this fix.
            _sp.run(["launchctl", "unload", str(plist)],
                    check=False, capture_output=True)
            fallback = _sp.run(["launchctl", "load", "-w", str(plist)],
                               check=False, capture_output=True, text=True)
            if fallback.returncode != 0:
                click.echo(
                    f"warning: launchctl bootstrap+load both failed for "
                    f"{plist}: bootstrap='{result.stderr.strip()}' "
                    f"load='{fallback.stderr.strip()}' — autostart will "
                    f"NOT trigger at next login until resolved",
                    err=True,
                )

    def _uninstall_launchd_plist(self, name: str) -> None:
        """Unload + remove the per-cage launchd plist. No-op if absent."""
        plist = self._launchd_plist_path(name)
        if not plist.exists():
            return
        import subprocess as _sp
        label = f"io.agentcage.{name}"
        domain = f"gui/{os.getuid()}"
        # bootout for plists installed via the new path; unload for the
        # legacy fallback path. Both are best-effort: if neither
        # succeeds, the plist file is still removed and launchctl will
        # forget the service at next login.
        _sp.run(["launchctl", "bootout", f"{domain}/{label}"],
                check=False, capture_output=True)
        _sp.run(["launchctl", "unload", str(plist)],
                check=False, capture_output=True)
        plist.unlink(missing_ok=True)

    # --- Backend protocol -----------------------------------------------------

    def check_prerequisites(self, config: Config) -> list[str]:  # noqa: ARG002
        return ac_prereq.check_prerequisites()

    def build_artifacts(
        self, config: Config, deploy_name: str, *, quiet: bool = False
    ) -> None:
        """Build (or refresh) the per-cage wrapper + the shared egress image,
        and stage per-cage egress config files on the host.

        Two image builds happen here (vs the legacy single wrapper build):

          1. **agentcage-egress:<version>** — built ONCE per host
             (skipped if already present locally with the version tag).
             All cages share this image; per-cage build would burn
             ~30s + ~120MB on every `cage create`.
          2. **agentcage-apple-<cage>:latest** — per-cage wrapper, now
             slimmed to FROM <user_image> + cage-init.sh + cage-cmd.sh
             (the user's argv shell-escaped at build time via
             shlex.quote). No mitmproxy/dnsmasq/iptables/jq install.

        Three host-side renderings also happen here (vs the legacy
        baked-into-image path) so domain add / secret rotation can use
        live-reload semantics in PR 3 follow-ups:

          1. <egress_config>/proxy-config.yaml — mitmproxy addon config.
          2. <egress_config>/dnsmasq.conf      — dnsmasq main config.
          3. <egress_config>/dns-allowlist.conf — dnsmasq --servers-file.
        """
        user_image = config.container.image
        if not user_image:
            raise ValueError("cage has no container.image set")

        # 1. Build (or skip) the shared agentcage-egress image. Tagged with
        # the agentcage version so a wheel upgrade triggers a rebuild even
        # if the user already has a stale tag from an older release.
        self._build_egress_image_if_missing(quiet=quiet)

        # 2. If the cage came from a scaffold (cage.yaml has `scaffold:`),
        # build any scaffold-declared images via Apple `container build`
        # BEFORE the wrapper build. The wrapper's `FROM <user_image>`
        # references one of these tags, so it must exist first.
        scaffold_name = getattr(config, "scaffold", "") or ""
        if scaffold_name:
            ac_scaffold.build_scaffold_images(scaffold_name, quiet=quiet)

        # 3. Ensure the user image is available locally — checking the local
        # store FIRST, before any registry pull. This matters because:
        #   * The scaffold step above (and any Containerfile build) produces a
        #     `localhost/...` image that can NEVER resolve in a registry. The
        #     old code pulled unconditionally, so every scaffold cage create
        #     burned a multi-second `container image pull` that was guaranteed
        #     to fail (POSIXErrorCode 61 / "Connection refused" when offline)
        #     and only "worked" via the local fallback below — wasting time
        #     and printing an alarming error on the happy path.
        #   * A mistyped or unbuilt `localhost/` tag previously surfaced as that
        #     same cryptic pull error instead of a clear "not built" message.
        # So: use the local image if present; pull only a genuinely-remote ref
        # that is genuinely absent; never try to pull a local-only `localhost/`
        # ref (fail fast with an actionable message instead).
        if ac_cli.image_inspect(user_image):
            if not quiet:
                click.echo(f"Using local image: {user_image}")
        elif user_image.startswith("localhost/"):
            raise RuntimeError(
                f"image {user_image!r} is a local-only ('localhost/') reference "
                f"but is not present in the local image store. It is never "
                f"pulled from a registry. If it should be built from a "
                f"Containerfile, set 'container.build.containerfile' (and, for a "
                f"scaffold, ensure 'container.image' matches the tag the build "
                f"produces, e.g. 'localhost/agentcage-scaffold-<name>:latest'); "
                f"otherwise build/load it first with "
                f"'container build -t {user_image} ...'."
            )
        else:
            if not quiet:
                click.echo(f"Pulling user image: {user_image}")
            pull_result = ac_cli.run(
                ["image", "pull", user_image],
                check=False,
                capture_output=False,
            )
            if pull_result.returncode != 0 and not ac_cli.image_inspect(user_image):
                raise RuntimeError(
                    f"failed to pull user image {user_image!r} and it is not built locally"
                )

        # 4. Resolve the cage's CMD. Precedence: cage.yaml `container.command:`
        # wins (explicit intent, portable across backends); fall back to the
        # user image's OCI CMD only when unset. Without this precedence the
        # apple-container backend silently ignores cage.yaml `command:` and
        # execs the base image's CMD instead (e.g. ubuntu → `/bin/bash`,
        # which exits immediately under `run -d` with no TTY).
        if config.container.command:
            user_cmd = list(config.container.command)
        else:
            try:
                user_cmd = ac_wrapper._user_cmd(user_image)
            except ValueError as e:
                raise RuntimeError(
                    f"cannot determine cage entrypoint: {e}; "
                    "set CMD in your Containerfile or use a scaffold that provides one"
                ) from e

        # 5. Render per-cage egress config files host-side. These get
        # bind-mounted into the egress sibling at runtime.
        self._render_egress_config(config, deploy_name)

        # 6. Build the per-cage wrapper image. The slim template only
        # needs the user image ref + the shlex-quoted user CMD (baked
        # into cage-cmd.sh by a RUN heredoc in the Containerfile). All
        # the legacy kwargs are accepted but ignored by the new wrapper.
        if not quiet:
            click.echo(f"Building apple-container wrapper for {deploy_name}...")
        ac_wrapper.build_wrapper(deploy_name, user_image, user_cmd=user_cmd)
        if not quiet:
            click.echo(f"Built {ac_wrapper.wrapped_image_name(deploy_name)}")

    def _build_egress_image_if_missing(self, *, quiet: bool = False) -> None:
        """Build localhost/agentcage-egress:<version> if not already present.

        The Containerfile lives at src/agentcage/data/containers/Containerfile.egress
        (PR 1). It expects the build context to be src/agentcage/data/ so
        `COPY containers/supervisor-egress.sh ...` resolves — same context
        the smoke-test in tests/test_egress_image.py uses.
        """
        image = _egress_image_name()
        if ac_cli.image_inspect(image) is not None:
            if not quiet:
                click.echo(f"Egress image {image} already present; skipping rebuild")
            return

        if not quiet:
            click.echo(f"Building shared egress image {image}...")
        # Resolve paths relative to this file so the build works regardless
        # of cwd (tests, agentcage invoked from a sub-dir, etc.).
        data_dir = Path(__file__).resolve().parent.parent / "data"
        containerfile = data_dir / "containers" / "Containerfile.egress"
        if not containerfile.is_file():
            raise RuntimeError(
                f"egress Containerfile missing at {containerfile} — "
                f"is the agentcage install complete?"
            )
        ac_cli.run(
            ["build", "-t", image, "-f", str(containerfile), str(data_dir)],
            capture_output=False,
        )

    def _render_egress_config(self, config: Config, deploy_name: str) -> None:
        """Render proxy-config.yaml + dnsmasq.conf + dns-allowlist.conf to
        the per-cage egress config dir.

        These three files are bind-mounted read-only into the egress
        sibling at runtime; the egress supervisor (supervisor-egress.sh,
        PR 1) reads them on startup. Same shape the container/vm backends
        produce via quadlets + state.save_proxy_config / save_dns_allowlist.
        """
        import yaml as _yaml
        from agentcage import state as _state

        dest = self.egress_config_dir(deploy_name)
        dest.mkdir(parents=True, exist_ok=True)

        # proxy-config.yaml — same subset state.save_proxy_config writes
        # for container/vm. Re-use the helper directly so the on-disk
        # shape stays identical across backends. The helper reads from
        # ~/.config/agentcage/cages/<name>/cage.yaml, so save_deployment
        # must have run first (it has — `cage create` calls it before
        # build_artifacts).
        try:
            proxy_yaml_path = Path(_state.save_proxy_config(deploy_name))
            shutil.copy2(proxy_yaml_path, dest / "proxy-config.yaml")
        except FileNotFoundError:
            # Pre-create / test path — no stored cage.yaml yet. Write a
            # minimal config so the egress addon can still load.
            (dest / "proxy-config.yaml").write_text(
                _yaml.safe_dump(
                    {
                        "name": deploy_name,
                        "domains": {"allow": list(config.domains.allow or [])},
                    },
                    default_flow_style=False,
                    sort_keys=False,
                )
            )

        # dnsmasq.conf — same template as the legacy single-VM model.
        # Just write the rendered bytes to disk instead of into the
        # wrapper build context.
        (dest / "dnsmasq.conf").write_text(
            ac_wrapper.render_dnsmasq_conf(
                list(config.domains.allow or []),
                dns_servers=list(config.dns_servers or []),
            )
        )

        # dns-allowlist.conf — same shape state.save_dns_allowlist
        # produces for the container backend. Re-use the helper for
        # parity; fall back to in-line rendering if the cage.yaml isn't
        # on disk yet (pre-create path).
        try:
            allowlist_path = Path(_state.save_dns_allowlist(deploy_name))
            shutil.copy2(allowlist_path, dest / "dns-allowlist.conf")
        except FileNotFoundError:
            lines = [
                f"server=/{d}/{srv}"
                for d in (config.domains.allow or [])
                for srv in (config.dns_servers or ["1.1.1.1", "8.8.8.8"])
            ]
            (dest / "dns-allowlist.conf").write_text(
                "\n".join(lines) + ("\n" if lines else "")
            )

    def reload_domains(self, config: Config, name: str) -> None:
        """Apply a domain-allowlist change to a RUNNING egress in place —
        no cage rebuild, no cage restart.

        The egress microVM bind-mounts the three rendered config files
        read-only from the host egress-config dir (see ``start()``):
        ``dns-allowlist.conf`` / ``dnsmasq.conf`` →
        ``/etc/agentcage/{dns-allowlist,dnsmasq}.conf`` and
        ``proxy-config.yaml`` → ``/etc/agentcage/config.yaml``.
        ``_render_egress_config`` rewrites those files **in place** (same
        inode, via ``shutil.copy2`` / ``write_text`` truncate-in-place),
        so virtiofs surfaces the new bytes inside the running egress
        without re-creating the mount. We then:

          1. Validate the rewritten allowlist inside the egress
             (``dnsmasq --test``); on failure revert the file and raise,
             so a malformed allowlist can't silently break DNS.
          2. SIGHUP both dnsmasq instances so they re-read the
             ``--servers-file`` allowlist:
               * the egress dnsmasq (pidfile ``/home/acdns/dnsmasq.pid``,
                 run under ``setpriv --reuid=acdns`` — signal the pid, not
                 ``pkill``);
               * the **cage-local** dnsmasq (pidfile
                 ``/run/agentcage/dnsmasq.pid``) — the load-bearing one,
                 since the cage workload resolves via 127.0.0.1:53 served
                 by that local dnsmasq (vmnet drops inter-microVM UDP, so
                 the cage can't use the egress dnsmasq; see cage-init.sh
                 stage A'). Best-effort: skipped if the cage has no
                 dnsmasq.
          3. Leave ``proxy-config.yaml`` to the mitmproxy addon, which
             polls its mtime per request and hot-reloads in place
             (``data/proxy/addon.py``) — no signal needed.

        The cage microVM is never touched, so an interactive
        ``agentcage run`` session survives the domain change. Mirrors the
        container/vm SIGHUP fast path (see cli._update_dns_quadlet); the
        only difference is the ``container exec`` wrapper vs ``podman
        exec`` / ``limactl shell``.
        """
        egress_dir = self.egress_config_dir(name)
        allow_dest = egress_dir / "dns-allowlist.conf"
        previous = allow_dest.read_text() if allow_dest.is_file() else None

        # Rewrite the bind-mounted config files in place from the (already
        # updated) stored cage.yaml + live config object.
        self._render_egress_config(config, name)

        # If the egress isn't up, the rewrite is enough — the next start()
        # reads the new files. Nothing to signal.
        if not self.is_running(name, "egress"):
            return

        container = f"{name}-egress"

        # 1. Validate the new allowlist inside the egress before signaling.
        test = ac_cli.run(
            ["exec", container, "dnsmasq", "--test",
             "--servers-file=/etc/agentcage/dns-allowlist.conf"],
            check=False,
        )
        if test.returncode != 0:
            if previous is not None:
                allow_dest.write_text(previous)
            raise RuntimeError(
                "dnsmasq rejected the new allowlist; reverted it and left "
                "the egress serving the previous config. Details:\n"
                f"{(test.stderr or test.stdout or '').strip()}"
            )

        # 2. SIGHUP the egress dnsmasq via its pidfile so it re-reads the
        # allowlist.
        ac_cli.run(
            ["exec", container, "sh", "-c",
             'kill -HUP "$(cat /home/acdns/dnsmasq.pid)"'],
            check=False,
        )

        # 3. SIGHUP the CAGE-local dnsmasq too — this is the load-bearing
        # one. The cage workload resolves via 127.0.0.1:53 served by a
        # dnsmasq started in the cage by cage-init.sh stage A' (macOS vmnet
        # drops inter-microVM UDP, so the cage can't query the egress
        # dnsmasq). It reads the SAME bind-mounted allowlist (pidfile
        # /run/agentcage/dnsmasq.pid). Without this SIGHUP the new domain
        # lands in the file but the cage keeps resolving the old set.
        # Best-effort: the cage dnsmasq is itself best-effort (skipped on
        # bases without dnsmasq, cage-init.sh stage A'), so guard on the
        # pidfile and never fail the reload.
        if self.is_running(name, "cage"):
            ac_cli.run(
                ["exec", name, "sh", "-c",
                 'p=/run/agentcage/dnsmasq.pid; '
                 '[ -f "$p" ] && kill -HUP "$(cat "$p")" || true'],
                check=False,
            )

        # 4. proxy-config.yaml is hot-reloaded by the mitmproxy addon's
        # mtime poll — no signal required.

    def generate_units(
        self,
        config: Config,
        config_host_path: str,  # noqa: ARG002
        patches_host_dir: str,  # noqa: ARG002
        deploy_name: str,
        used_octets: set[int] | None = None,  # noqa: ARG002
        network_octet: int | None = None,  # noqa: ARG002
    ) -> dict[str, str]:
        """Generate a cage metadata JSON used by `start` to construct argv.

        ``used_octets`` and ``network_octet`` are accepted to match the
        Backend protocol but ignored. Apple `container` networks are
        per-cage with auto-allocated subnets — there is no shared 10.89.X
        pool to coordinate against, and the cage's effective network is
        Apple's default vmnet (no custom network created by this backend
        in v1; egress is locked to localhost via iptables in the
        supervisor).
        """
        # Resource resolution precedence: cage.yaml's `container.cpus` /
        # `container.memory` (the per-cage cap the user actually wrote)
        # wins over `vm.vcpus` / `vm.mem_mb` (which exist primarily for
        # the Lima backend's outer VM but used to be the only thing this
        # backend respected — silently dropping `container.cpus/memory`
        # was a real footgun on Mac, where users edit cage.yaml not a
        # separate vm section). Empty / unset on both → no --cpus or
        # --memory flag, letting Apple's defaults apply.
        cpus = config.container.cpus or (
            str(config.vm.vcpus) if getattr(config.vm, "vcpus", 0) else ""
        )
        memory = config.container.memory or (
            f"{config.vm.mem_mb}m" if getattr(config.vm, "mem_mb", 0) else ""
        )
        # Persist the secret-injection env→placeholder map so `start()` knows
        # which env vars to resolve from the host environment AND which
        # placeholder string to pass to the cage in their place. The
        # placeholder (not the real value) ends up in the cage's env via
        # `-e ENV={{ENV}}` so cage code that reads `os.environ["KEY"]`
        # gets the placeholder; the real value lives only in the
        # bind-mounted secrets file and the mitmproxy addon substitutes
        # it on the wire. ``secret_envs`` kept (list of env names) for
        # backward compat with cages last started on 0.21.0 or earlier.
        secret_envs = [r.env for r in (config.secret_injection or [])]
        secret_env_placeholders = {
            r.env: r.placeholder for r in (config.secret_injection or [])
        }
        # Protocol-relay credential env names — must reach the mitmproxy
        # process inside the cage (where the relay's _resolve_credential
        # reads them) but must NOT reach the cage workload's env. We
        # write each value into the same per-cage secrets bind mount
        # secret_injection uses; the addon reads it at relay-start time
        # and sets os.environ[<env>] before constructing the relay.
        # Critically, these env names do NOT get a `-e` flag on
        # `container run` — that's how we keep them off the cage
        # workload's environ block.
        relay_secret_envs: list[str] = []
        for relay in (config.protocol_relays or []):
            for src in (relay.auth.user_source, relay.auth.password_source):
                scheme, _, var = (src or "").partition(":")
                if scheme and var and var not in relay_secret_envs:
                    relay_secret_envs.append(var)
        # Resolve cage.yaml's nested ``ports.*`` into the three int lists the
        # egress supervisor's Step A turns into iptables rules. Computed HERE
        # (at unit-generation time, when we have a live Config) and persisted
        # into metadata.json so ``start()`` — which works only from the meta
        # dict, not a Config — can feed them to the egress argv. Reuses the
        # SAME ``_effective_port_policy`` the container/vm quadlet path uses
        # (quadlets.py:152) so the policy resolution can never diverge between
        # backends. Pre-this-fix apple-container hardcoded only ALLOW_UDP_PORTS=53
        # and silently dropped a cage.yaml's ports.tcp.* / ports.udp.* policy.
        inspected_tcp, passthrough_tcp, allow_udp = _effective_port_policy(config)
        unit_json = json.dumps(
            {
                "name": deploy_name,
                "user_image": config.container.image,
                "cpus": cpus,
                "memory": memory,
                "lifecycle": config.lifecycle,
                "secret_envs": secret_envs,
                "secret_env_placeholders": secret_env_placeholders,
                "relay_secret_envs": relay_secret_envs,
                "autostart": bool(getattr(config, "apple_container_autostart", False)),
                # User-defined host bind mounts. Apple's `container run`
                # accepts `--volume host:cage[:mode]` just like podman.
                # Expand + validate the host path HERE (at generate_units
                # / create-update time) and persist the resolved ABSOLUTE
                # path, NOT the raw cage.yaml string. This is load-bearing:
                # the scaffold workspace mount is `${PROJECT_DIR}:/workspace`
                # and PROJECT_DIR only lives in the environment of the
                # `agentcage run` process. If we persisted the literal
                # `${PROJECT_DIR}` and expanded it lazily in start() (as we
                # did pre-fix), any start() outside that process — launchd
                # autostart, reboot, `cage start`, `cage restart` — has no
                # PROJECT_DIR set, so _user_volume_argv's unresolved-`$`
                # guard silently dropped the workspace. Baking the absolute
                # path at create time (matching quadlets.py's
                # expand-at-generate semantics for container/vm) makes the
                # mount survive restarts. _user_volume_argv is idempotent on
                # already-absolute paths, so start() re-running it is a safe
                # revalidation, not a re-expansion.
                "volumes": self._user_volume_argv(config.container.volumes),
                # User-defined ``container.env:`` entries. Apple's
                # `container run` accepts `-e KEY=VAL` like podman. The
                # container backend wires these via quadlets.py:338;
                # pre-this-fix apple-container ignored them silently (the
                # cage workload's environ was just missing the keys, no
                # warning). Expand $VAR in values to match the container
                # backend's behavior. Placeholder-style values from
                # ``secret_injection:`` go through a separate `-e KEY={{PH}}`
                # path that lives in ``start()`` (using
                # ``secret_env_placeholders`` above); the two never overlap
                # because validate_config rejects a key listed in BOTH.
                "env": {
                    k: os.path.expandvars(str(v))
                    for k, v in (config.container.env or {}).items()
                },
                # Egress port policy (see _effective_port_policy above). Three
                # lists of ints; start() space-joins them onto the egress argv
                # as INSPECTED_TCP_PORTS / PASSTHROUGH_TCP_PORTS / ALLOW_UDP_PORTS.
                "inspected_tcp_ports": inspected_tcp,
                "passthrough_tcp_ports": passthrough_tcp,
                "allow_udp_ports": allow_udp,
            },
            indent=2,
            sort_keys=True,
        )
        return {f"{deploy_name}.json": unit_json}

    def unit_dir(self) -> Path:
        return Path(os.path.expanduser("~/.config/agentcage/apple-container"))

    def install_units(self, units: dict[str, str], *, quiet: bool = False) -> None:
        dest = self.unit_dir()
        dest.mkdir(parents=True, exist_ok=True)
        for filename, content in units.items():
            (dest / filename).write_text(content)
        if not quiet:
            click.echo(f"Installed apple-container unit metadata to {dest}/")

    def start(self, name: str, *, quiet: bool = False) -> None:
        """Start the cage's two sibling microVMs (egress + cage).

        Ordered:
          1. Create the per-cage network (idempotent).
          2. Run <name>-egress (the agentcage-egress image).
          3. Wait for egress readiness (file marker in the shared logs dir).
          4. Read the egress sibling's IP.
          5. Run <name> (the slim wrapper) with AGENTCAGE_EGRESS_IP env.
             cage-init.sh sets the default route via that IP and execs
             the user's CMD after capsh-drop.
        """
        unit_path = self.unit_dir() / f"{name}.json"
        if not unit_path.exists():
            raise RuntimeError(
                f"apple-container unit metadata missing at {unit_path}; "
                f"run `agentcage cage create {name}` first"
            )
        meta = json.loads(unit_path.read_text())

        wrapper_image = ac_wrapper.wrapped_image_name(name)
        if not ac_cli.image_inspect(wrapper_image):
            raise RuntimeError(
                f"wrapped image {wrapper_image!r} not found — was build_artifacts() called?"
            )
        egress_image = _egress_image_name()
        if not ac_cli.image_inspect(egress_image):
            raise RuntimeError(
                f"egress image {egress_image!r} not found — was build_artifacts() called?"
            )

        # Stop+delete any prior incarnations of either container (start
        # should be idempotent like every other backend).
        for cname in (name, f"{name}-egress"):
            if ac_cli.inspect(cname) is not None:
                ac_cli.run(["stop", cname], check=False)
                ac_cli.run(["delete", "-f", cname], check=False)

        # Per-cage state dirs created on demand. Egress writes audit
        # / capture / dnsmasq logs + the ready marker into logs_dir; the
        # CA exchange dir is mounted into BOTH VMs.
        logs_dir = self.logs_dir(name)
        logs_dir.mkdir(parents=True, exist_ok=True)
        # 1777 — virtiofs maps host owner identity-wise into the guest, so
        # uid 200/201 (mitmproxy/dnsmasq in the egress VM) can only write
        # here if the host-side perms allow it. Sticky bit prevents
        # cross-uid file deletion. Same trick the legacy single-VM model
        # used; preserved verbatim.
        os.chmod(logs_dir, 0o1777)

        certs_dir = self.certs_dir(name)
        certs_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(certs_dir, 0o1777)

        # Separate cage-visible cert dir — holds ONLY the public cert.
        # Egress's supervisor-egress.sh Step E copies
        # mitmproxy-ca-cert.pem here after generation; the cage mounts
        # THIS dir at /certs, not the full certs_dir which holds the
        # private key. See public_certs_dir() docstring for context.
        public_certs_dir = self.public_certs_dir(name)
        public_certs_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(public_certs_dir, 0o1777)

        egress_cfg_dir = self.egress_config_dir(name)
        if not egress_cfg_dir.is_dir():
            raise RuntimeError(
                f"egress config dir {egress_cfg_dir} missing — run `cage update`"
            )

        # Clear any stale readiness marker BEFORE the first container run.
        # The egress supervisor touches /var/log/agentcage/ready at end of
        # its step F; we poll for it below.
        ready_marker = logs_dir / "ready"
        try:
            ready_marker.unlink()
        except FileNotFoundError:
            pass

        # 1. Per-cage network. `network create` errors if already-present
        # (rc != 0); tolerated — the post-error inspect path would slow
        # the common case. Subnet auto-allocated by Apple's container
        # network plugin (no shared 10.89.X pool to coordinate on, unlike
        # the container backend's quadlet network shape).
        network_name = f"{name}-net"
        ac_cli.run(["network", "create", network_name], check=False)

        # 2. Egress sibling. Resolve secret values + write them into the
        # secrets dir BEFORE the egress runs (its addon reads them at
        # startup). The cage VM never sees the secrets dir — that's the
        # whole point of the refactor. ``staged_envs`` is the set of
        # secret env names that actually got a value (subset of
        # secret_envs minus the unprovided ones) — used below to decide
        # which `-e NAME={{NAME}}` flags to add to the cage VM's argv.
        staged_envs = self._stage_secrets(name, meta)

        # Cap set for the egress microVM (mirrors the container/vm
        # Quadlet — see egress.container.j2):
        #   NET_ADMIN          — iptables PREROUTING REDIRECT + FORWARD
        #                        chain (supervisor-egress.sh step A)
        #   NET_BIND_SERVICE   — dnsmasq :53 (the image setcap's the
        #                        binary, the bounding set must still
        #                        permit the file cap)
        #   SETUID + SETGID    — supervisor's ``setpriv --reuid/--regid``
        #                        drop chain for dnsmasq (acdns=201) and
        #                        mitmproxy (acproxy=200)
        #   SETPCAP            — ``setpriv --bounding-set`` to strip the
        #                        children's CapBnd
        #   KILL               — supervisor (root) ``kill -0 "$pid"``
        #                        cross-uid polls of acdns/acproxy children
        # The previous list of just NET_ADMIN + NET_BIND_SERVICE relied
        # on the runtime's default cap set including SETUID/SETGID/
        # SETPCAP/KILL; rootless podman on a hardened
        # ``default_capabilities = []`` host drops them all and the
        # supervisor crashed at the first setpriv. Apple's container
        # runtime hasn't reproduced this so far, but staying explicit
        # keeps parity with the container/vm path and survives a future
        # cap-default tightening.
        secrets_dir = self.secrets_dir(name)
        egress_argv = [
            "run", "-d", "--name", f"{name}-egress",
            "--cap-add", "CAP_NET_ADMIN",
            "--cap-add", "CAP_NET_BIND_SERVICE",
            "--cap-add", "CAP_SETUID",
            "--cap-add", "CAP_SETGID",
            "--cap-add", "CAP_SETPCAP",
            "--cap-add", "CAP_KILL",
            "--network", network_name,
            "--volume", f"{logs_dir}:/var/log/agentcage",
            "--volume", f"{certs_dir}:/home/acproxy/.mitmproxy",
            # Egress writes the public-only cert here so the cage can
            # bind-mount JUST this dir, not certs_dir (which holds the
            # CA private key — see public_certs_dir() docstring + the
            # CTF F1 finding on 0.22.5).
            "--volume", f"{public_certs_dir}:/home/acproxy/public-certs",
            "--volume", f"{egress_cfg_dir}/proxy-config.yaml:/etc/agentcage/config.yaml:ro",
            "--volume", f"{egress_cfg_dir}/dnsmasq.conf:/etc/agentcage/dnsmasq.conf:ro",
            "--volume", f"{egress_cfg_dir}/dns-allowlist.conf:/etc/agentcage/dns-allowlist.conf:ro",
        ]
        # Only mount the secrets dir if it actually has files (avoids an
        # empty-bind whose listdir would shadow the egress image's empty
        # /home/acproxy/secrets dir).
        if secrets_dir.is_dir() and any(secrets_dir.iterdir()):
            egress_argv += [
                "--volume", f"{secrets_dir}:/home/acproxy/secrets:ro",
            ]
        # Egress runs the agentcage addon — point it at the bind-mounted
        # config + capture jsonl. Same env vars data/proxy/addon.py reads.
        egress_argv += [
            "-e", "AGENTCAGE_CONFIG=/etc/agentcage/config.yaml",
            "-e", "AGENTCAGE_AUDIT_LOG=/var/log/agentcage/audit.jsonl",
            "-e", "AGENTCAGE_CAPTURE=/var/log/agentcage/capture.jsonl",
        ]
        # Egress port policy. generate_units() persisted these three int
        # lists (from cage.yaml's nested ``ports.*`` via the shared
        # _effective_port_policy). supervisor-egress.sh Step A turns them
        # into iptables rules: INSPECTED_TCP_PORTS → nat:PREROUTING REDIRECT
        # to mitmproxy, PASSTHROUGH_TCP_PORTS → FORWARD ACCEPT uninspected,
        # ALLOW_UDP_PORTS → FORWARD ACCEPT for UDP.
        inspected_tcp = [int(p) for p in (meta.get("inspected_tcp_ports") or [])]
        passthrough_tcp = [int(p) for p in (meta.get("passthrough_tcp_ports") or [])]
        allow_udp = [int(p) for p in (meta.get("allow_udp_ports") or [])]
        # INSPECTED_TCP_PORTS MUST be set explicitly: the supervisor only
        # falls back to "80 443" when the var is UNSET, so a cage that
        # narrows or widens its inspected set has to be honored here.
        egress_argv += [
            "-e", f"INSPECTED_TCP_PORTS={' '.join(str(p) for p in inspected_tcp)}",
            "-e", f"PASSTHROUGH_TCP_PORTS={' '.join(str(p) for p in passthrough_tcp)}",
        ]
        # CTF F2 (0.22.6): the cage's local dnsmasq (cage-init.sh
        # stage A') queries upstream resolvers via UDP :53. Those
        # packets route through the egress sibling (the cage's
        # default gateway). supervisor-egress.sh sets FORWARD policy
        # to DROP and only ACCEPTs ports listed in $ALLOW_UDP_PORTS,
        # which is otherwise unset. Without :53 in the list, the
        # cage's dnsmasq sees its upstream forwarders timeout and
        # returns SERVFAIL — even for allowlisted apexes. So 53 MUST
        # remain present even when the operator's config.udp.allow is
        # empty: we union it in and dedupe (preserving operator order).
        udp_with_dns = list(allow_udp)
        if 53 not in udp_with_dns:
            udp_with_dns.append(53)
        egress_argv += [
            "-e", f"ALLOW_UDP_PORTS={' '.join(str(p) for p in udp_with_dns)}",
        ]
        # Egress is small — 512M is plenty. We don't normalize here
        # because the value is internal, not operator-supplied.
        egress_argv += ["--memory", "512M"]
        egress_argv.append(egress_image)

        result = ac_cli.run(egress_argv, check=False, capture_output=False)
        if result.returncode != 0:
            raise RuntimeError(
                f"`container run` for egress sibling failed (exit {result.returncode})"
            )

        # 3. Wait for egress readiness — the supervisor's step F touches
        # /var/log/agentcage/ready which virtiofs surfaces here.
        self._wait_supervisor_ready(name, ready_marker)

        # 4. Read the egress sibling's allocated IP. The cage uses it as
        # default-route gateway via cage-init.sh. Apple's runtime populates
        # `networks[].address` asynchronously — even after the supervisor's
        # ready marker, the inspect output can briefly show `networks: []`.
        # Poll with a short timeout to absorb this race.
        egress_ip = None
        ip_deadline = time.monotonic() + 10.0
        while time.monotonic() < ip_deadline:
            egress_ip = self._container_ip(f"{name}-egress")
            if egress_ip:
                break
            time.sleep(0.2)
        if not egress_ip:
            raise RuntimeError(
                f"could not resolve IP of {name}-egress within 10s — "
                f"`container inspect` returned no address. Check "
                f"`container logs {name}-egress`."
            )

        # 5. Cage VM. CAP_NET_ADMIN is needed for cage-init's `ip route
        # replace default via <egress_ip>`. capsh drops it before the
        # workload runs, so uid 1000 has no caps — but `cage exec --user 0`
        # re-acquires NET_ADMIN per the spike (known residual; see module
        # docstring). The cage VM has NO secrets bind, NO config bind,
        # NO mitmproxy/dnsmasq/iptables.
        cage_argv = [
            "run", "-d", "--name", name,
            "--cap-add", "CAP_NET_ADMIN",
            "--network", network_name,
            # CTF F1 (0.22.5): pre-0.22.6 this bound certs_dir, which
            # holds mitmproxy-ca.pem (the CA *private* key). A uid-1000
            # cage workload could read it and mint a trusted forged
            # cert for any allowlisted host. Bind public_certs_dir
            # instead — egress's Step E copies only the public cert
            # there. The full mitmproxy dir is now egress-only.
            "--volume", f"{public_certs_dir}:/certs",
            # CTF F2 (0.22.6): the cage's local dnsmasq (cage-init stage A')
            # reads the same allowlist-scoped config the egress sibling
            # uses, bind-mounted from the host's egress-config dir. macOS
            # vmnet drops inter-microVM UDP (verified against apple/container
            # source — NonisolatedInterfaceStrategy.swift uses
            # VMNET_SHARED_MODE NAT), so the cage can't reach the egress's
            # dnsmasq on .2:53; the only fix is a local resolver scoped to
            # the same config.
            "--volume", f"{egress_cfg_dir}/dnsmasq.conf:/etc/agentcage/dnsmasq.conf:ro",
            "--volume", f"{egress_cfg_dir}/dns-allowlist.conf:/etc/agentcage/dns-allowlist.conf:ro",
            "-e", f"AGENTCAGE_EGRESS_IP={egress_ip}",
            "-e", "AGENTCAGE_DNS_SERVERS_FILE=/etc/agentcage/dns-allowlist.conf",
            # Point HTTPS clients at the proxy CA immediately, without
            # waiting for cage-init.sh stage C to finish copying it into
            # /usr/local/share/ca-certificates and running
            # update-ca-certificates. curl reads SSL_CERT_FILE, Node reads
            # NODE_EXTRA_CA_CERTS; together they cover the agents we
            # actually ship (claude-code, codex, the openclaw stack).
            # Mirrors the container backend's cage.container.j2 (lines
            # 14–15). Without this, claude-code 2.1.x silently exits 0
            # from `-p` when its HTTPS call fails verification.
            "-e", "SSL_CERT_FILE=/certs/mitmproxy-ca-cert.pem",
            "-e", "NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca-cert.pem",
        ]
        # User-defined env from cage.yaml.
        for env_k, env_v in (meta.get("env") or {}).items():
            cage_argv += ["-e", f"{env_k}={env_v}"]
        # Placeholder env (NOT real values) for each secret_injection
        # rule that actually got a value. The cage workload sees
        # `{{API_KEY}}` in its env; the egress addon substitutes the
        # real value on the wire. If --set-secret didn't provide a
        # value for an env, we skip the -e flag entirely so the
        # placeholder doesn't end up leaking through to upstream as a
        # literal string (matches legacy single-VM start() behavior).
        placeholders = meta.get("secret_env_placeholders") or {}
        for env_name in staged_envs:
            ph = placeholders.get(env_name)
            if not ph:
                continue
            cage_argv += ["-e", f"{env_name}={ph}"]
        # User-defined bind mounts. meta["volumes"] already holds ABSOLUTE,
        # expanded, $HOME-validated entries (baked by generate_units at
        # create/update time — see the "volumes" comment there). Re-running
        # _user_volume_argv here is an idempotent revalidation, NOT a
        # re-expansion: absolute paths have no `~`/`$VAR` left to resolve, so
        # this no longer depends on PROJECT_DIR being in the start() env.
        for vol_entry in self._user_volume_argv(meta.get("volumes") or []):
            cage_argv += ["--volume", vol_entry]
        # Apple's --cpus / --memory normalization (uppercase suffix, ceil
        # fractions). Backward-compat fallback to pre-0.20.6 `mem_mb` int.
        cpus_raw = meta.get("cpus")
        if cpus_raw not in (None, "", 0):
            cage_argv += ["--cpus", _normalize_cpus(str(cpus_raw))]
        memory_raw = meta.get("memory")
        if memory_raw:
            cage_argv += ["--memory", _normalize_memory(str(memory_raw))]
        elif meta.get("mem_mb"):
            cage_argv += ["--memory", f"{meta['mem_mb']}M"]
        cage_argv.append(wrapper_image)

        result = ac_cli.run(cage_argv, check=False, capture_output=False)
        if result.returncode != 0:
            # Clean up the orphaned egress sibling so a retry isn't blocked
            # by the "already exists" check at the top of start().
            ac_cli.run(["stop", f"{name}-egress"], check=False)
            ac_cli.run(["delete", "-f", f"{name}-egress"], check=False)
            raise RuntimeError(
                f"`container run` for cage failed (exit {result.returncode})"
            )

        # launchd plist refresh if the cage opted in to autostart. Same
        # logic as legacy: read from the unit metadata so flags stick
        # across reloads.
        if meta.get("autostart"):
            self._install_launchd_plist(name)
        if not quiet:
            click.echo(f"Started {name} (apple-container, 2-microVM model)")

    def _stage_secrets(self, name: str, meta: dict) -> set[str]:
        """Resolve --set-secret values into <secrets_dir>/<env-name> files.

        Returns the set of secret_injection env names that got a value
        staged — the caller uses this to decide which `-e NAME={{NAME}}`
        flags to add to the cage VM's run argv. Relay-only envs are
        NEVER returned (they're staged to the bind mount but never
        `-e`'d to the cage workload).

        The host-side resolution logic mirrors the legacy single-VM
        start(); the only difference vs the legacy model is WHERE the
        bind-mount lands: the egress sibling at /home/acproxy/secrets
        (read-only), not the cage VM. Cleartext never flows through
        ``container run`` argv on either side.
        """
        staged: set[str] = set()
        placeholders = meta.get("secret_env_placeholders") or {}
        secret_envs = meta.get("secret_envs") or list(placeholders.keys())
        relay_secret_envs = meta.get("relay_secret_envs") or []
        all_secret_envs = list(secret_envs) + [
            v for v in relay_secret_envs if v not in secret_envs
        ]
        if not all_secret_envs:
            return staged

        from agentcage import state as _state
        provided: dict[str, str] = {}
        pending_path = _state.deployment_dir(name) / "pending_secrets.json"
        if pending_path.is_file():
            try:
                provided = {k: v for k, v in json.loads(pending_path.read_text())}
            except Exception:
                click.echo(
                    f"warning: failed to parse {pending_path}; treating "
                    f"all secret_injection rules as unprovided",
                    err=True,
                )

        secrets_dir = self.secrets_dir(name)
        secrets_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(secrets_dir, 0o700)
        # Drop stale secret files so a removed rule doesn't linger in the
        # bind mount.
        for stale in secrets_dir.iterdir():
            stale.unlink()
        relay_only = set(relay_secret_envs) - set(secret_envs)
        for env_name in all_secret_envs:
            value = provided.get(env_name)
            if value is None:
                if env_name in relay_only:
                    click.echo(
                        f"warning: protocol_relays env {env_name!r} not "
                        f"provided via --set-secret; the relay will fail "
                        f"to start with empty credentials",
                        err=True,
                    )
                else:
                    click.echo(
                        f"warning: secret_injection env {env_name!r} not "
                        f"provided via --set-secret; placeholder will NOT "
                        f"be substituted in cage requests",
                        err=True,
                    )
                continue
            if env_name in relay_only:
                # Relay credential — file goes in the bind mount; no -e
                # flag added to the cage VM's run argv.
                secret_file = secrets_dir / env_name
                secret_file.write_text(value)
                os.chmod(secret_file, 0o600)
                continue
            placeholder = placeholders.get(env_name)
            if not placeholder:
                # Pre-0.21.1 unit JSON — refuse cleartext fallback.
                continue
            secret_file = secrets_dir / env_name
            secret_file.write_text(value)
            os.chmod(secret_file, 0o600)
            staged.add(env_name)
        return staged

    def _container_ip(self, name: str) -> str | None:
        """Return the IPv4 address Apple's network plugin assigned to *name*.

        Apple's `container inspect` (CLI v0.12.x) returns a list (one
        entry per container). The IP lives under
        ``networks[].ipv4Address`` (CIDR-form, e.g. ``192.168.64.5/24``);
        we strip the mask. Returns None if no address is populated yet
        (still booting — caller should poll briefly).
        """
        data = ac_cli.inspect(name)
        if not data:
            return None
        networks = data.get("networks") or data.get("Networks") or []
        if isinstance(networks, list):
            for net in networks:
                # Apple's schema (verified empirically against v0.12.3):
                # `ipv4Address` is the populated field. Defensively also
                # check `address`/`Address` for older/newer schema variants.
                addr = (
                    net.get("ipv4Address")
                    or net.get("address")
                    or net.get("Address")
                    or ""
                ).strip()
                if addr:
                    return addr.split("/", 1)[0]
        # Fallback: some schemas put the IP at `network.address`.
        n = data.get("network") or {}
        addr = (n.get("ipv4Address") or n.get("address") or n.get("Address") or "").strip()
        if addr:
            return addr.split("/", 1)[0]
        return None

    # Polling interval and total timeout for the supervisor readiness wait.
    # Module-level so tests can monkeypatch them to ~0 without subclassing.
    _READY_POLL_INTERVAL_S = 0.1
    _READY_TIMEOUT_S = 30.0

    def _wait_supervisor_ready(self, name: str, marker: Path) -> None:
        """Block until ``marker`` (the egress sibling's ready file) exists
        or the egress sibling exits.

        Raises ``RuntimeError`` if the egress exits before signaling ready
        (so the operator sees a real error, not a successful return that
        then 401s on the first request).

        ``name`` is the cage's base name; we poll ``<name>-egress`` since
        the supervisor running in the egress sibling owns the marker.
        """
        deadline = time.monotonic() + self._READY_TIMEOUT_S
        egress_name = f"{name}-egress"
        while time.monotonic() < deadline:
            if marker.exists():
                return
            data = ac_cli.inspect(egress_name)
            status = (data or {}).get("status") or (data or {}).get("Status")
            if data is not None and status not in ("running", None):
                raise RuntimeError(
                    f"egress sibling {egress_name!r} exited before becoming "
                    f"ready (status={status!r}); see `container logs {egress_name}`"
                )
            time.sleep(self._READY_POLL_INTERVAL_S)
        raise RuntimeError(
            f"egress sibling {egress_name!r} did not signal ready within "
            f"{self._READY_TIMEOUT_S:.0f}s; see `container logs {egress_name}` "
            f"for the supervisor's last step"
        )

    def stop(self, name: str) -> None:
        """Stop both microVMs (cage + egress)."""
        ac_cli.run(["stop", name], check=False)
        ac_cli.run(["stop", f"{name}-egress"], check=False)

    def restart(self, name: str) -> None:
        self.stop(name)
        self.start(name)

    def destroy_resources(self, name: str, keep_secrets: bool = False) -> list[str]:  # noqa: ARG002
        """Stop+delete both microVMs, delete the per-cage network + wrapper
        image + state dir.

        The shared egress image (agentcage-egress:<version>) is NOT
        removed — it's used by sibling cages.
        """
        removed: list[str] = []
        # launchd plist (best-effort).
        plist = self._launchd_plist_path(name)
        if plist.exists():
            self._uninstall_launchd_plist(name)
            removed.append(f"launchd:{plist}")
        # Containers — stop+delete cage first (in case start() ordered them
        # the other way, this just makes the cleanup more readable).
        for cname in (name, f"{name}-egress"):
            if ac_cli.inspect(cname) is not None:
                ac_cli.run(["stop", cname], check=False)
                r = ac_cli.run(["delete", "-f", cname], check=False)
                if r.returncode == 0:
                    removed.append(f"container:{cname}")
        # Per-cage network. `network delete` is idempotent in Apple's CLI
        # but we only care to report when it actually existed; rely on the
        # rc to decide whether to add it to `removed`.
        net_result = ac_cli.run(["network", "delete", f"{name}-net"], check=False)
        if net_result.returncode == 0:
            removed.append(f"network:{name}-net")
        # Wrapper image. The shared egress image is NOT deleted here —
        # sibling cages depend on it.
        wrapper_image = ac_wrapper.wrapped_image_name(name)
        if ac_cli.image_inspect(wrapper_image) is not None:
            r = ac_cli.run(["image", "delete", wrapper_image], check=False)
            if r.returncode == 0:
                removed.append(f"image:{wrapper_image}")
        # State dir + unit JSON.
        unit_path = self.unit_dir() / f"{name}.json"
        if unit_path.exists():
            unit_path.unlink()
            removed.append(f"unit:{unit_path}")
        state = self._state_dir(name)
        if state.exists():
            shutil.rmtree(state)
            removed.append(f"state:{state}")
        return removed

    def has_resources(self, name: str) -> bool:
        if (self.unit_dir() / f"{name}.json").exists():
            return True
        if self._state_dir(name).exists():
            return True
        return False

    def is_running(self, name: str, service: str) -> bool:
        """Dispatch on service: cage → <name>, egress → <name>-egress.

        Unknown service names get treated as "cage" for parity with the
        legacy single-VM model where every service collapsed to a single
        container — keeps existing CLI plumbing in `cage verify` /
        `cage status` from breaking when it iterates service_names().
        """
        if service == "egress":
            target = f"{name}-egress"
        else:
            target = name
        data = ac_cli.inspect(target)
        if not data:
            return False
        status = data.get("status") or data.get("Status")
        return status == "running"

    def service_names(self, name: str) -> list[str]:  # noqa: ARG002
        """The 2-microVM model has two addressable services.

        ``cage`` is the user's workload VM; ``egress`` is the sibling
        running mitmproxy + dnsmasq from the agentcage-egress image.
        ``proxy`` / ``dns`` names from the legacy single-VM model are
        gone — they collapse into ``egress``. cli.py uses these names
        for status display and ``cage exec --service``.
        """
        return ["cage", "egress"]

    # --- Backend protocol: process inspection / streaming --------------------

    def exec_argv(
        self,
        name: str,
        service: str,
        cmd: list[str],
        *,
        interactive: bool = False,
        as_root: bool = False,
    ) -> list[str]:
        """`container exec [-it] -u <spec> <target> -- <cmd>`.

        Service dispatch:
          * ``cage`` (default) → target is ``<name>``.
          * ``egress``         → target is ``<name>-egress``.

        Privilege model in the 2-microVM model — significantly simpler
        than the legacy single-VM capsh wrap because the cage VM no
        longer contains the egress filter:

          * ``as_root=False`` (default) → ``-u 1000:1000``. Cage VM has
            no iptables binary and no secrets bind-mount in its
            namespace; CAP_NET_ADMIN is the only inherited cap and
            it's stripped from uid 1000's CapEff by the uid 0→1000
            transition that `container exec -u` performs.
          * ``as_root=True``           → ``-u 0:0``. Operator debug
            path. Image USER (root on the slim wrapper) applies. Per
            the spike on Apple's runtime, --user 0 RE-acquires
            NET_ADMIN — operator with --as-root can change the cage's
            default route. Workload-uid-1000 is unaffected.

        The legacy capsh wrap is gone: with no iptables/dnsmasq inside
        the cage VM and no secrets bind-mount, there's no
        CapBnd-acquired escape path to wrap closed. ``container exec
        -u 1000:1000`` is now what `cage exec` should produce.

        Pre-PR-3 behavior — for callers that still build the legacy
        capsh-wrap argv (tests/cli.py), this method now returns the
        flat `-u 1000:1000` form. Test expectations updated alongside.
        """
        from agentcage.backend import BackendUnsupported
        if service == "egress":
            target = f"{name}-egress"
        elif service in ("cage", ""):
            target = name
        else:
            raise BackendUnsupported(
                f"'cage exec --service {service}' is not supported on the "
                f"apple-container backend; valid services are cage / egress"
            )
        binary = ac_cli.container_binary()
        if binary is None:
            raise BackendUnsupported(
                "Apple `container` CLI not found; install from "
                "https://github.com/apple/container/releases"
            )
        flags = ["-it"] if interactive else []

        # F3 from the CTF: every previous ``cage exec`` session arrived
        # at the cage workload with NoNewPrivs=0 and CapBnd=0xa80435fb
        # (the container's full --cap-add set, including NET_ADMIN,
        # SETUID, SETGID, SYS_CHROOT). cage-init.sh stage D capsh-drops
        # all of that for the WORKLOAD's PID 1, but each ``container
        # exec`` enters via Apple's runtime as a fresh process whose
        # caps are derived directly from the container's --cap-add set
        # — no inheritance from the capsh-dropped PID 1. The result was
        # that a uid-1000 process inside the cage could exploit any
        # setuid-root binary in the base image (ubuntu:24.04 ships
        # /usr/bin/su, /usr/bin/mount, /usr/bin/passwd, etc. as
        # mode-4755) to regrant CapEff = CapBnd, then F2's
        # NET_ADMIN-route-bypass chain works without --as-root.
        #
        # Wrap the exec via setpriv, running initially as the image's
        # default USER (root, set in Containerfile.wrapper.j2). setpriv
        # uses CAP_SETPCAP to clear the bounding + inheritable sets,
        # sets PR_SET_NO_NEW_PRIVS, then setresuid/setresgid to
        # 1000:1000. Once uid changes from 0 the kernel zeroes CapEff/
        # CapPrm, leaving the exec'd cmd with empty caps + NNP=1 —
        # matching the workload PID 1's posture exactly.
        #
        # ``--as-root`` keeps the previous setpriv shape but only drops
        # NET_ADMIN (so the operator still has CHOWN/SETUID/etc. for
        # debug ops like apt-get install). The egress service is left
        # untouched — egress operations may legitimately need NET_ADMIN
        # for iptables debugging.
        wrap: list[str] = []
        if service in ("cage", ""):
            if as_root:
                # uid 0:0 + NET_ADMIN-only drop (F2).
                spec = "0:0"
                wrap = [
                    "setpriv",
                    "--bounding-set=-net_admin",
                    "--inh-caps=-net_admin",
                    "--",
                ]
            else:
                # No -u flag — enter as image USER (root), let setpriv
                # do the uid drop + cap clear in one step. ``--reuid``
                # and ``--regid`` are numeric so we don't need to look
                # up the cage user's name (varies: ubuntu / node /
                # claude / cage).
                #
                # setpriv changes uid but does NOT update HOME/USER/
                # LOGNAME — the exec target inherits root's HOME=/root,
                # which is 0700 and unreadable to uid 1000. claude-
                # code 2.1.x reads/writes ~/.claude/ on startup and
                # silently exits 0 from `claude -p` on EACCES (no error
                # message, no stderr). Same EACCES surface bites npm
                # (~/.npm), pip (~/.cache/pip), and any tool that
                # touches XDG_*. Wrap setpriv in a small sh -c that
                # reads /etc/passwd for uid 1000 and re-exports HOME/
                # USER/LOGNAME before exec'ing setpriv. Matches cage-
                # init.sh stage D's behavior for the workload PID 1.
                spec = None
                wrap = [
                    "sh", "-c",
                    'CU=$(getent passwd 1000 | cut -d: -f1) && '
                    'CH=$(getent passwd 1000 | cut -d: -f6) && '
                    'exec env HOME="$CH" USER="$CU" LOGNAME="$CU" '
                    'setpriv --reuid=1000 --regid=1000 --clear-groups '
                    '--no-new-privs --bounding-set=-all --inh-caps=-all '
                    '-- "$@"',
                    "agentcage-exec-wrap",
                ]
        else:
            spec = "0:0" if as_root else "1000:1000"

        if spec is not None:
            return [binary, "exec", "-u", spec, *flags, target, *wrap, *cmd]
        return [binary, "exec", *flags, target, *wrap, *cmd]

    def logs_argv(
        self,
        name: str,
        services: list[str],
        *,
        follow: bool = False,
        lines: int = 0,  # noqa: ARG002 — Apple `container logs` has no -n
        min_level: str | None = None,  # noqa: ARG002 — Apple doesn't filter
    ) -> list[str]:
        """`container logs [-f] <target>`.

        ``services`` dispatch:
          * ``["cage"]``   (or empty / unrecognized) → tail the cage VM.
          * ``["egress"]`` → tail the egress sibling.
          * mixed list      → tail the cage (first wins; ``cage logs --service``
                              filtering happens at the CLI layer for now).

        Apple's `container logs` doesn't accept `-n`; ``lines`` is
        accepted for protocol parity but ignored.
        """
        from agentcage.backend import BackendUnsupported
        binary = ac_cli.container_binary()
        if binary is None:
            raise BackendUnsupported(
                "Apple `container` CLI not found; install from "
                "https://github.com/apple/container/releases"
            )
        # Pick the target — cage VM by default; egress only if explicitly
        # requested and no cage in the list.
        target = name
        for s in services or []:
            if s == "egress":
                target = f"{name}-egress"
                break
            if s == "cage":
                target = name
                break
        argv = [binary, "logs"]
        if follow:
            argv.append("-f")
        argv.append(target)
        return argv

    def audit_argv(
        self,
        name: str,
        *,
        since: str | None = None,  # noqa: ARG002 — no time index host-side
        follow: bool = False,
    ) -> list[str]:
        """`tail` the host-side audit.jsonl bind-mounted from the microVM.

        The mitmproxy addon writes one JSON line per request decision into
        /var/log/agentcage/audit.jsonl, which `start()` bind-mounts to
        `<state>/<cage>/logs/audit.jsonl` on the host. `since` is not yet
        respected (the host JSONL has no journalctl-style time index);
        the CLI's AuditFilter still applies time filtering post-parse.
        """
        path = self.logs_dir(name) / "audit.jsonl"
        if follow:
            return ["tail", "-n", "0", "-F", str(path)]
        return ["tail", "-n", "10000", str(path)]
