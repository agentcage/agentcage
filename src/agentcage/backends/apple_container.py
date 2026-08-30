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
  * modify iptables (no NET_ADMIN in CapEff/CapPrm at uid 1000 — the
    nft/iptables netlink ops require it)
  * change routes (no NET_ADMIN in CapEff/CapPrm at uid 1000)
  * see other UIDs' processes (kernel namespace gives this for free —
    no need for the legacy supervisor.sh's hidepid=2 remount)

--as-root is also confined: the cage VM is started with --cap-add
CAP_NET_ADMIN (needed for cage-init's stage-B `ip route replace`), but
capsh drops it before the workload runs, and a later operator
`container exec --user 0 <cage>` does NOT inherit it — Apple's
`container` 1.0.0 grants an exec session only the DEFAULT OCI capability
set (CapEff a80425fb: chown, setuid, net_bind_service, net_raw, …; no
NET_ADMIN). Verified end-to-end on a ubuntu cage (container 1.0.0): as
uid 0, `iptables -F` returns EPERM, `ip route replace/del default`
returns "Operation not permitted", and non-allowlisted egress (arbitrary
ports, direct :53, 403'd HTTP) stays blocked — even root cannot bypass
the egress sibling. The exec path's `setpriv --bounding-set=-net_admin`
wrap is defense-in-depth on top of that.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import time
from importlib.metadata import version as _pkg_version
from pathlib import Path, PurePosixPath

import click

from agentcage.apple_container import cli as ac_cli
from agentcage.apple_container import prerequisites as ac_prereq
from agentcage.apple_container import scaffold as ac_scaffold
from agentcage.apple_container import wrapper as ac_wrapper
from agentcage.config import Config
from agentcage.quadlets import _effective_port_policy
from agentcage.volume_mounts import (
    is_non_persistent_volume,
    mask_copyup_entries,
    mask_mountpoint_dirs,
    split_volume_spec,
    validate_non_persistent_volume,
)


# Shared agentcage-egress image is built once per host. All cages share
# this image — building per cage would burn ~30s + ~120MB on every
# `cage create`.
#
# The tag is `<agentcage version>-<content hash of the build inputs>`.
# The version ALONE is not enough: `_build_egress_image_if_missing()`
# short-circuits when the tag is already present locally, so a fix that
# lands in supervisor-egress.sh (or the addon, inspectors, relays, …)
# between releases would never reach a host that already holds the
# same-version tag. That is exactly how the 0640 proxy-log hardening
# (#186) failed to ship: hosts kept running the pre-fix supervisor out of
# a stale `agentcage-egress:0.32.0` and `cage create` printed "already
# present; skipping rebuild". Hashing the actual build inputs into the tag
# makes a changed input produce a different tag, which the "already
# present?" probe misses and therefore rebuilds — no flag required.
_EGRESS_IMAGE_REPO = "localhost/agentcage-egress"

# Truncated sha256 length for the tag suffix. 12 hex chars = 48 bits;
# collisions across the handful of egress builds a host ever sees are not
# a practical concern, and a short tag keeps `container images` readable.
_EGRESS_TAG_HASH_LEN = 12

# Containerfile path relative to the build context (src/agentcage/data).
_EGRESS_CONTAINERFILE_REL = "containers/Containerfile.egress"

# `COPY [--flag=…] <src>… <dest>`. Only the shell form is matched; the
# egress Containerfile does not use the JSON-array form (a JSON COPY would
# simply contribute no sources, and the Containerfile's own bytes are
# always hashed, so the tag still changes whenever it is edited).
_EGRESS_COPY_RE = re.compile(r"^COPY\s+(?P<rest>.+)$", re.IGNORECASE)

# Build-context noise that must never reach the hash: bytecode caches are
# interpreter-dependent, so hashing them would make the tag unstable
# across Python versions for byte-identical sources.
_EGRESS_HASH_EXCLUDE_DIRS = frozenset({"__pycache__"})
_EGRESS_HASH_EXCLUDE_SUFFIXES = (".pyc", ".pyo")


def _egress_data_dir() -> Path:
    """Build context for the egress image (``src/agentcage/data``).

    Resolved relative to this file so the build works regardless of cwd
    (tests, agentcage invoked from a sub-dir, etc.).
    """
    return Path(__file__).resolve().parent.parent / "data"


def _containerfile_logical_lines(text: str):
    """Yield Containerfile instructions with backslash continuations joined.

    Comment-only lines are dropped. Good enough to find COPY sources; this
    is deliberately not a general Containerfile parser.
    """
    buf = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        buf += stripped
        if buf:
            yield buf
        buf = ""
    if buf:
        yield buf


def _egress_copy_sources(containerfile_text: str) -> list[str]:
    """Source paths named by the COPY directives of the egress Containerfile.

    Deriving the list from the Containerfile (rather than hardcoding it)
    means a new `COPY proxy/<something-new>` joins the content hash
    automatically, instead of silently falling out of the rebuild decision
    the way a hand-maintained list eventually would.
    """
    sources: list[str] = []
    for line in _containerfile_logical_lines(containerfile_text):
        match = _EGRESS_COPY_RE.match(line)
        if match is None:
            continue
        try:
            parts = shlex.split(match.group("rest"))
        except ValueError:
            continue
        # Drop `--chown=`/`--from=`-style flags; the final token is the
        # destination inside the image, everything before it is a source.
        parts = [p for p in parts if not p.startswith("--")]
        if len(parts) < 2:
            continue
        sources.extend(parts[:-1])
    return sources


def _egress_build_inputs(data_dir: Path | None = None) -> list[tuple[str, Path]]:
    """Every file baked into the egress image, as sorted (relpath, path) pairs.

    The Containerfile itself plus the transitive contents of each COPY
    source (directories are walked). Returns ``[]`` when the Containerfile
    is missing — the build path reports that with an actionable error.
    """
    root = (data_dir or _egress_data_dir()).resolve()
    containerfile = root / _EGRESS_CONTAINERFILE_REL
    if not containerfile.is_file():
        return []

    inputs: dict[str, Path] = {_EGRESS_CONTAINERFILE_REL: containerfile}

    def _add(path: Path) -> None:
        if not path.is_file():
            return
        if path.suffix in _EGRESS_HASH_EXCLUDE_SUFFIXES:
            return
        try:
            rel = path.relative_to(root)
        except ValueError:
            return  # outside the build context; `container build` can't COPY it
        if _EGRESS_HASH_EXCLUDE_DIRS.intersection(rel.parts):
            return
        inputs[rel.as_posix()] = path

    for src in _egress_copy_sources(containerfile.read_text(errors="replace")):
        parts = PurePosixPath(src.strip("/")).parts
        if not parts or ".." in parts:
            continue
        target = root.joinpath(*parts)
        if target.is_dir():
            for child in target.rglob("*"):
                _add(child)
        else:
            # A missing source contributes nothing on purpose: the build
            # itself fails loudly on it and there are no bytes to hash.
            _add(target)

    return sorted(inputs.items())


def _egress_content_hash(data_dir: Path | None = None) -> str:
    """Short stable digest over the egress image's build inputs.

    Hashes the sorted (relative path, content) pairs so a rename changes
    the digest even when the bytes do not, and so the result does not
    depend on filesystem iteration order.
    """
    inputs = _egress_build_inputs(data_dir)
    if not inputs:
        return "unknown"
    digest = hashlib.sha256()
    for rel, path in inputs:
        try:
            body = path.read_bytes()
        except OSError:
            body = b""
        digest.update(rel.encode())
        digest.update(b"\0")
        # Length-prefix the body so no path+content concatenation can be
        # re-partitioned into a different input set with the same hash.
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
    return digest.hexdigest()[:_EGRESS_TAG_HASH_LEN]


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


def _egress_image_name(data_dir: Path | None = None) -> str:
    """Full tagged reference for the shared egress image.

    ``localhost/agentcage-egress:<version>-<content-hash>``. The version
    keeps the tag human-readable and greppable; the hash is what actually
    drives the rebuild decision, so editing e.g. supervisor-egress.sh
    rebuilds on the next `cage create` / `cage update` without needing
    `--no-cache` / `--pull`.
    """
    return (
        f"{_EGRESS_IMAGE_REPO}:{_agentcage_version()}"
        f"-{_egress_content_hash(data_dir)}"
    )


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

def _gui_domain_reachable(uid: int) -> bool:
    """Probe whether the ``gui/<uid>`` launchd domain is reachable now.

    ``~/Library/LaunchAgents/`` plists live in the per-user *GUI* domain,
    which is only addressable from a session that owns the Aqua console (a
    local Terminal.app window, or a GUI login). Over SSH the user session
    runs in the non-GUI ``user/<uid>`` context: ``launchctl bootstrap
    gui/<uid>`` exits 0 but silently no-ops, so the agent would appear
    "installed" and never load. Probe first and, when unavailable, leave
    the plist on disk — the FILE is the persistence; it loads at the next
    GUI login.

    Lived in ``agentcage.watcher`` while the grants watcher shared it; that
    module is gone (grants are applied inside the egress now), and the cage
    autostart plist is the only remaining caller.
    """
    try:
        result = subprocess.run(
            ["launchctl", "print", f"gui/{uid}"],
            capture_output=True, text=True,
        )
        return result.returncode == 0
    except OSError:
        return False



class AppleContainerBackend:
    """Backend using Apple's `container` CLI with a hardened supervisor."""

    # --- helpers --------------------------------------------------------------

    def _state_dir(self, name: str) -> Path:
        return Path(os.path.expanduser("~/.config/agentcage/apple-container")) / name

    def _mask_state_path(self, name: str) -> Path:
        """Bookkeeping file for tmpfs-mask mount points created on the host.

        Written by ``_record_mask_mountpoints`` immediately before
        ``container run`` and consumed by ``_cleanup_mask_mountpoints`` on
        stop / destroy. Lives inside the per-cage state dir so
        ``destroy_resources``'s ``rmtree`` disposes of any leftover.
        """
        return self._state_dir(name) / "mask-mountpoints.json"

    @staticmethod
    def _mask_mount_targets(
        volume_entries: list[str],
    ) -> list[tuple[str, str]]:
        """Return ``(container_target, host_source)`` for the user's binds.

        The shape :func:`~agentcage.volume_mounts.mask_mountpoint_dirs` and
        :func:`~agentcage.volume_mounts.mask_copyup_entries` consume. An
        ``np`` bind's target is a tmpfs seeded from a read-only lowerdir —
        writes there never reach the host — so it reports an empty source
        and a mask nested under it is never attributed to the host path.
        """
        mount_targets: list[tuple[str, str]] = []
        for entry in volume_entries:
            host_src, target, _opts = split_volume_spec(entry)
            if not target:
                continue
            mount_targets.append(
                (target, "" if is_non_persistent_volume(entry) else host_src)
            )
        return mount_targets

    def _record_mask_mountpoints(
        self, name: str, tmpfs_specs: list[str], volume_entries: list[str],
    ) -> None:
        """Record which tmpfs-mask mount points are ABSENT on the host now.

        A ``container.tmpfs`` target nested under a host bind makes the
        in-guest OCI runtime create the mount point, and a bind shares inodes
        with its source, so that ``mkdir -p`` lands in the operator's project
        directory on the host: masking ``/workspace/.git/hooks/`` on a
        non-git project leaves a stray host ``.git/hooks/`` that the
        ubiquitous ``test -d .git`` idiom misreads as a repository (#320).

        Pre-#318 apple-container never wired ``container.tmpfs`` into
        ``container run``, which is why #320's quadlet-side fix concluded
        this backend was unaffected. Wiring tmpfs through made it affected,
        so this is the same bookkeeping the quadlet backend does with an
        ``ExecStartPre``/``ExecStopPost`` pair — there is no such hook here,
        so it is Python-side. The mask itself stays unconditional: dropping
        it when ``.git`` is absent would reopen the #170 pivot for a ``.git``
        created later.

        Only paths that do not exist right now are recorded, so a
        pre-existing directory is never a removal candidate. A symlink
        counts as existing (``lexists``) — mirrors the quadlet hook's
        ``[ -e ] || [ -L ]`` skip.
        """
        mount_targets = self._mask_mount_targets(volume_entries)
        absent: dict[str, list[str]] = {}
        for root, dirs in mask_mountpoint_dirs(tmpfs_specs, mount_targets).items():
            # `dirs` is deepest-first; keep that order for teardown.
            missing = [d for d in dirs if not os.path.lexists(d)]
            if missing:
                absent[root] = missing
        state = self._mask_state_path(name)
        if not absent:
            # Nothing to clean up — drop any stale record from an earlier
            # start so teardown can't act on outdated bookkeeping.
            state.unlink(missing_ok=True)
            return
        state.parent.mkdir(parents=True, exist_ok=True)
        state.write_text(json.dumps(absent, indent=2))

    def _cleanup_mask_mountpoints(self, name: str) -> None:
        """Remove the still-empty mask mount points ``start()`` created.

        ``rmdir`` is the whole "only if empty" safety story: a mount point
        the operator (or the workload, through a persistent bind) put content
        into is kept, with a warning. Removal is additionally contained to
        the bind source recorded at start and re-checked against
        ``realpath`` here, so a symlink swapped in after start cannot
        redirect a removal out of the project directory.

        Best-effort and idempotent throughout — a missing/unreadable state
        file (start hook never ran, older cage, hand-deleted state) is a
        silent no-op, and nothing here may fail a stop or destroy.
        """
        state = self._mask_state_path(name)
        try:
            recorded = json.loads(state.read_text())
        except (OSError, ValueError):
            return
        if not isinstance(recorded, dict):
            state.unlink(missing_ok=True)
            return
        for root, dirs in sorted(recorded.items()):
            if not isinstance(root, str) or not isinstance(dirs, list):
                continue
            # `realpath` on a non-existent path resolves lexically, matching
            # the quadlet hook's `realpath -m`.
            real_root = os.path.realpath(root)
            for d in dirs:
                if not isinstance(d, str):
                    continue
                if not os.path.realpath(d).startswith(real_root + os.sep):
                    continue
                if os.path.islink(d) or not os.path.isdir(d):
                    continue
                try:
                    os.rmdir(d)
                except OSError:
                    click.echo(
                        f"warning: keeping {d} (created as a tmpfs mask "
                        f"mount point, but not empty)",
                        err=True,
                    )
        state.unlink(missing_ok=True)

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
            validate_non_persistent_volume(v)
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

    @staticmethod
    def _tmpfs_targets(raw_entries: list[str]) -> list[str]:
        """Normalize ``container.tmpfs`` specs into bare cage paths.

        Apple's ``container run --tmpfs`` takes a BARE PATH — at container
        1.0.0 the whole argument is the destination, so Docker's
        ``path:opts`` form would mount a tmpfs at a directory literally
        named ``path:opts``. (1.3.0 learned to split ``path:opts``, but we
        target the older contract too, so the option list is dropped on
        every version.) That means the scaffolds'
        ``rw,noexec,nosuid,nodev,size=64M`` is NOT forwarded: the mount
        lands with kernel-default tmpfs options — writable, exec/suid/dev
        permitted, and bounded only by the cage VM's memory. This is not
        silent: ``validate_config`` warns per cage about exactly which
        options were dropped (see config.py's apple-container block).

        Returns absolute, de-duplicated, trailing-slash-stripped targets.
        Entries that are not absolute paths, or that ask for ``/``
        (a tmpfs over the rootfs would hide the whole image), are skipped
        with a warning rather than handed to the runtime.
        """
        out: list[str] = []
        seen: set[str] = set()
        for entry in raw_entries:
            target = entry.split(":", 1)[0].strip()
            # `/workspace/.git/hooks/` -> `/workspace/.git/hooks`; Apple
            # lexically normalizes destinations too, so strip here to keep
            # our own dedupe honest.
            normalized = target.rstrip("/")
            if not target.startswith("/"):
                click.echo(
                    f"warning: skipping tmpfs {entry!r} on apple-container "
                    "(target must be an absolute path)",
                    err=True,
                )
                continue
            if not normalized:
                click.echo(
                    f"warning: skipping tmpfs {entry!r} on apple-container "
                    "(a tmpfs over `/` would hide the cage image's rootfs)",
                    err=True,
                )
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            out.append(normalized)
        return out

    @staticmethod
    def _tmpfs_copyup_seeds(
        raw_entries: list[str],
        volume_entries: list[str],
        skip_targets: set[str],
    ) -> list[tuple[str, str, str]]:
        """Return ``(host_source, lower, target)`` for emulated copy-up masks.

        Apple's ``container run --tmpfs`` takes a bare path, so the
        ``tmpcopyup`` a mask declares can never reach the runtime here
        (see :meth:`_tmpfs_targets`). Copy-up is emulated instead, exactly
        the way ``np`` binds already are: the host directory the mask covers
        is mounted READ-ONLY at *lower* under ``/run/agentcage/masks/`` and
        cage-init's stage C'' replays it into the fresh tmpfs at *target*,
        chowned to the cage user. The tmpfs itself is what the workload
        writes to, so nothing it does reaches the host — the mask's whole
        point (#170/#173) is preserved and the seeding only affects what the
        cage can *read* (#328).

        The lower must be its own mount because the mask already covers the
        path inside the bind: ``/workspace/.claude`` is the tmpfs, so the
        directory underneath it is unreachable from inside the guest.

        Skipped, silently, when the mask does not name ``tmpcopyup``, when
        the enclosing mount does not reach the host (a named volume or an
        ``np`` bind — nothing host-side to seed from), when the target is
        already an ``np`` tmpfs (*skip_targets*, #325's double-tmpfs
        avoidance; cage-init seeds it from the np lowerdir instead), or when
        the host source is not an existing directory. That last case must
        not create the directory: the mask mount point bookkeeping (#320)
        removes host dirs agentcage materialized, and inventing one here
        would put a stray ``.claude/`` in a project that has none.

        A source that resolves outside the bind it came from is refused with
        a warning. Without that check a repository containing
        ``.claude -> ../../.ssh`` would turn the mask into a fresh read-only
        window onto a host path the operator never shared — the bind alone
        does not expose it, because an in-guest symlink resolves in the
        guest.
        """
        seeds: list[tuple[str, str, str]] = []
        mount_targets = AppleContainerBackend._mask_mount_targets(volume_entries)
        for idx, (target, host_source, host_root) in enumerate(
            mask_copyup_entries(raw_entries, mount_targets)
        ):
            if not host_source or target in skip_targets:
                continue
            real_source = os.path.realpath(host_source)
            real_root = os.path.realpath(host_root)
            # Equality is legitimate: a mask covering the whole bind seeds
            # from the bind source itself.
            if real_source != real_root and not real_source.startswith(
                real_root + os.sep
            ):
                click.echo(
                    f"warning: not seeding tmpfs mask {target!r} on "
                    f"apple-container ({host_source!r} resolves to "
                    f"{real_source!r}, outside the {host_root!r} mount); the "
                    "mask comes up empty",
                    err=True,
                )
                continue
            if not os.path.isdir(real_source):
                continue
            seeds.append(
                (real_source, f"/run/agentcage/masks/mask-{idx}/lower", target)
            )
        return seeds

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

        Persistence model (#185): the plist FILE on disk in
        `~/Library/LaunchAgents/` IS the persistence — launchd auto-loads
        it at the next Aqua login. The immediate `launchctl bootstrap
        gui/<uid>` is convenience for the common local-Terminal.app case,
        NOT correctness. Over SSH the gui domain isn't reachable, so the
        bootstrap is skipped with a clear informational message rather
        than silently no-op-ing (the pre-#185 bug).
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
        # The plist file is now the persistence mechanism: launchd will
        # auto-load it at the next Aqua login regardless of anything
        # below. The remaining steps are the immediate-load convenience.
        import subprocess as _sp
        label = f"io.agentcage.{name}"
        uid = os.getuid()
        domain = f"gui/{uid}"
        # Reachability gate (#185): `launchctl bootstrap gui/<uid>` over
        # SSH exits 0 but silently no-ops because the gui domain isn't
        # reachable from the SSH/non-GUI session context (console owned
        # by another user, `who -u` empty). Probe the domain first; if it
        # isn't reachable, skip the immediate-load and emit an honest
        # informational message instead of the pre-#185 silent no-op.
        if not _gui_domain_reachable(uid):
            click.echo(
                f"note: plist written to {plist}; autostart will activate at "
                f"next GUI login (immediate-load not available from this "
                f"SSH/non-GUI context — see #185)",
                err=True,
            )
            return
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
        """Unload + remove the per-cage launchd plist. No-op if absent.

        Note: over SSH the gui domain isn't reachable, so `bootout`/`unload`
        no-op (same reachability story as ``_install_launchd_plist``'s probe,
        #185) — but that's fine: the file removal is what guarantees the
        service won't reload at next login. Uninstall therefore does NOT gate
        on reachability; the file is removed unconditionally so persistence
        can't survive a destroy by hiding behind an unreachable domain.
        """
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


    def check_prerequisites(self, config: Config) -> list[str]:  # noqa: ARG002
        return ac_prereq.check_prerequisites()

    def build_artifacts(
        self, config: Config, deploy_name: str, *, quiet: bool = False,
        no_cache: bool = False, pull: bool = False,
    ) -> None:
        """Build (or refresh) the per-cage wrapper + the shared egress image,
        and stage per-cage egress config files on the host.

        Two image builds happen here (vs the legacy single wrapper build):

          1. **agentcage-egress:<version>-<hash>** — built ONCE per host
             per distinct set of build inputs (skipped if that exact tag
             is already present locally). All cages share this image;
             per-cage build would burn ~30s + ~120MB on every
             `cage create`.
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

        ``no_cache`` / ``pull`` come from ``cage create/update
        --no-cache/--pull`` and are honored across every build step here
        (egress image, scaffold image, wrapper image) — they map to
        ``container build --no-cache`` / ``--pull`` and bypass the
        "skip if image already present" short-circuits, so a forced
        rebuild actually rebuilds. ``pull`` also forces a re-pull of a
        genuinely-remote user image even when a copy is already cached.
        """
        user_image = config.container.image
        if not user_image:
            raise ValueError("cage has no container.image set")

        # 1. Build (or skip) the shared agentcage-egress image. Tagged with
        # the agentcage version PLUS a hash of the build inputs, so any
        # change to the supervisor/addon/Containerfile triggers a rebuild
        # even within a release — not just on a wheel upgrade.
        # --no-cache/--pull force a rebuild even when the tag is present.
        self._build_egress_image_if_missing(
            quiet=quiet, no_cache=no_cache, pull=pull,
        )

        # 2. Build the cage's image from its OWN staged Containerfile (frozen
        # into the cage state dir at create) — mirroring the container/vm
        # backends. The build must precede the wrapper build, whose
        # `FROM <user_image>` references the tag produced here. A scaffold is
        # a one-shot generator, not a live dependency: we never re-read it
        # here, so an agentcage upgrade that changes a scaffold cannot leak
        # into an existing cage on `cage update`.
        bc = config.container.build
        if bc.containerfile:
            from agentcage import state
            staged_cf = state.deployment_dir(deploy_name) / bc.containerfile
            if staged_cf.is_file():
                ac_scaffold.build_image_from_staged(
                    user_image, staged_cf, staged_cf.parent, bc.args,
                    quiet=quiet, no_cache=no_cache, pull=pull,
                )
            elif not quiet:
                click.echo(
                    f"warning: no staged Containerfile at {staged_cf}; "
                    f"relying on a prebuilt or pullable {user_image}",
                    err=True,
                )

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
        #
        # --pull overrides the "use local if present" shortcut for remote
        # refs: the operator explicitly asked for the latest from the
        # registry. A `localhost/` ref is still never pulled (no registry
        # source) — its freshness comes from the --no-cache/--pull rebuild
        # of the scaffold image above, not from a pull.
        force_pull_remote = pull and not user_image.startswith("localhost/")
        if ac_cli.image_inspect(user_image) and not force_pull_remote:
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
        ac_wrapper.build_wrapper(
            deploy_name, user_image, user_cmd=user_cmd, no_cache=no_cache,
        )
        if not quiet:
            click.echo(f"Built {ac_wrapper.wrapped_image_name(deploy_name)}")

    def _build_egress_image_if_missing(
        self, *, quiet: bool = False, no_cache: bool = False, pull: bool = False,
    ) -> None:
        """Build localhost/agentcage-egress:<version>-<hash> if not present.

        The Containerfile lives at src/agentcage/data/containers/Containerfile.egress
        (PR 1). It expects the build context to be src/agentcage/data/ so
        `COPY containers/supervisor-egress.sh ...` resolves — same context
        the smoke-test in tests/test_egress_image.py uses.

        The "already present" short-circuit is safe only because the tag
        carries a hash of the build inputs (see ``_egress_image_name``):
        editing supervisor-egress.sh or any COPYed file yields a tag that
        is by definition not present, so the fix rebuilds and ships. A
        version-only tag would keep serving the stale image within a
        release, which is how the #186 log-permission fix failed to reach
        hosts that already had `agentcage-egress:0.32.0`.

        ``no_cache`` / ``pull`` still force a rebuild even when the tag IS
        present (``cage create/update --no-cache/--pull``): the operator
        asked for a clean rebuild / fresh base, so the shared egress image
        is rebuilt too rather than served from the cached tag.
        """
        image = _egress_image_name()
        if not (no_cache or pull) and ac_cli.image_inspect(image) is not None:
            if not quiet:
                click.echo(f"Egress image {image} already present; skipping rebuild")
            return

        if not quiet:
            click.echo(f"Building shared egress image {image}...")
        data_dir = _egress_data_dir()
        containerfile = data_dir / _EGRESS_CONTAINERFILE_REL
        if not containerfile.is_file():
            raise RuntimeError(
                f"egress Containerfile missing at {containerfile} — "
                f"is the agentcage install complete?"
            )
        argv = ["build", "-t", image, "-f", str(containerfile)]
        if no_cache:
            argv.append("--no-cache")
        if pull:
            argv.append("--pull")
        argv.append(str(data_dir))
        ac_cli.run(argv, capture_output=False)

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
        # wrapper build context. Use the EFFECTIVE DNS allowlist (allow +
        # passthrough + relay upstreams + domains.auto decider host) so the
        # same egress-internal hosts that must resolve on container/vm also
        # resolve here — single source of truth (quadlets._effective_dns_allowlist).
        from agentcage.quadlets import _effective_dns_allowlist
        effective_allow = _effective_dns_allowlist(config)
        (dest / "dnsmasq.conf").write_text(
            ac_wrapper.render_dnsmasq_conf(
                effective_allow,
                dns_servers=list(config.dns_servers or []),
            )
        )

        # dns-allowlist.conf — same shape state.save_dns_allowlist
        # produces for the container backend (it also uses
        # _effective_dns_allowlist, so the two files stay in sync). Re-use
        # the helper for parity; fall back to in-line rendering from the
        # effective allowlist if the cage.yaml isn't on disk yet (pre-create).
        try:
            allowlist_path = Path(_state.save_dns_allowlist(deploy_name))
            shutil.copy2(allowlist_path, dest / "dns-allowlist.conf")
        except FileNotFoundError:
            lines = [
                f"server=/{d}/{srv}"
                for d in effective_allow
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
          2. Make the egress pick up the new baseline. When the runtime
             servers-file ``/run/agentcage/dns-allowlist.egress.conf``
             exists, raise the supervisor's reload flag
             (``: > /home/acproxy/dns/reload``) instead of regenerating
             that file from the host. The supervisor (the single render
             implementation — no drift between host and guest) runs inside
             the egress microVM (same image); its 1s liveness loop sees the
             flag, re-renders BASELINE + GRANTED zones (granted zones come
             from ``/home/acproxy/dns/granted``, written by the proxy
             addon inside the egress) and SIGHUPs dnsmasq within ~1s.
             Regenerating from the host's baseline ALONE (the old ``sed`` of
             ``/etc/agentcage/dns-allowlist.conf``) would overwrite the
             served file with baseline-only lines, clobbering every
             in-flight policy-API granted zone out of dnsmasq on every
             operator domain add/rm (round-11 finding). Fallback: when
             the runtime file is absent the egress reads the bind-mounted
             file directly, so a plain SIGHUP via the pidfile
             (``/home/acdns/dnsmasq.pid``, run under ``setpriv
             --reuid=acdns`` — signal the pid, not ``pkill``) suffices.
          3. Regenerate + SIGHUP the **cage-local** dnsmasq (pidfile
             ``/run/agentcage/dnsmasq.pid``) — the load-bearing one, since
             the cage workload resolves via 127.0.0.1:53 served by that
             local dnsmasq (vmnet drops inter-microVM UDP, so the cage
             can't use the egress dnsmasq; see cage-init.sh stage A').
             This regeneration is from the BASELINE only and is
             INTENTIONAL (see the inline step-3 comment).
             Best-effort: skipped if the cage has no dnsmasq.
          4. Leave ``proxy-config.yaml`` to the mitmproxy addon, which
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

        # 2. Make the egress pick up the new baseline. When the runtime
        # servers-file /run/agentcage/dns-allowlist.egress.conf exists, raise
        # the supervisor's reload flag (`: > /home/acproxy/dns/reload`)
        # instead of regenerating that file from the host. The supervisor
        # runs inside the egress microVM (same image); its 1s liveness loop
        # sees the flag, re-renders BASELINE + GRANTED zones (granted zones
        # come from /home/acproxy/dns/granted, written by the proxy addon
        # inside the egress) and SIGHUPs dnsmasq — the supervisor is the
        # single render implementation, so there is no drift between host
        # and guest. Regenerating from the host's baseline ALONE (the old
        # `sed` of /etc/agentcage/dns-allowlist.conf > the runtime file)
        # would overwrite the served file with baseline-only lines,
        # clobbering every in-flight policy-API granted zone out of dnsmasq
        # on every operator domain add/rm (round-11 finding). Fallback: when
        # the runtime file is absent the egress reads the bind-mounted file
        # directly, so a plain SIGHUP via the pidfile (/home/acdns/dnsmasq.pid)
        # suffices.
        ac_cli.run(
            ["exec", container, "sh", "-c",
             'rt=/run/agentcage/dns-allowlist.egress.conf; '
             'if [ -f "$rt" ]; then : > /home/acproxy/dns/reload; '
             'else kill -HUP "$(cat /home/acdns/dnsmasq.pid)" 2>/dev/null || true; fi'],
            check=False,
        )

        # 3. Regenerate + SIGHUP the CAGE-local dnsmasq too — this is the
        # load-bearing one. The cage workload resolves via 127.0.0.1:53
        # served by a dnsmasq started in the cage by cage-init.sh stage A',
        # which forwards the allowlisted apexes to the egress sibling (the
        # cage's default route). It serves /run/agentcage/dns-allowlist.cage
        # .conf, so we re-point that from the updated bind-mounted allowlist
        # (same rewrite stage A' does), then SIGHUP via the pidfile. Guarded
        # on the runtime file existing (absent → cage fell back to the baked
        # config and reads the bind-mounted file). Best-effort throughout:
        # the cage dnsmasq is itself optional (bases without dnsmasq), so
        # never fail the reload.
        #
        # NOTE: unlike step 2, regenerating the cage-local servers-file from
        # the BASELINE only is INTENTIONAL and stays unchanged. The
        # cage-local servers-file is baseline-scoped by design: unknown /
        # granted zones get the TEST-NET sinkhole answer (address=/#/...) and
        # still reach the egress's transparent interception, where SNI/Host
        # is the enforcement authority; the actual upstream resolution
        # happens at the egress, which carries the granted zones (see
        # step 2). Do NOT "fix" this to raise a reload flag — the cage has
        # no supervisor and no granted-zones source of its own.
        if self.is_running(name, "cage"):
            ac_cli.run(
                ["exec", name, "sh", "-c",
                 'p=/run/agentcage/dnsmasq.pid; '
                 'up=$(ip route 2>/dev/null | awk "/^default/{print \\$3; exit}"); '
                 '[ -n "$up" ] && [ -f /run/agentcage/dns-allowlist.cage.conf ] && '
                 'sed "s#/[^/]*\\$#/$up#" /etc/agentcage/dns-allowlist.conf '
                 '> /run/agentcage/dns-allowlist.cage.conf 2>/dev/null; '
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
        # Skip rules whose placeholder hasn't been generated yet (the CLI
        # fills omitted placeholders at declare time) — an empty placeholder
        # must not become `-e ENV=` on the cage.
        secret_env_placeholders = {
            r.env: r.placeholder
            for r in (config.secret_injection or []) if r.placeholder
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
        # domains.auto decider api_key — same egress-only invariant as a relay
        # credential: staged into the secrets bind mount, never `-e`'d to the
        # cage workload. Mirrors quadlets.py's proxy_secrets staging. We carry
        # the api_key's full SOURCE scheme (``env:NAME`` / ``systemd-creds:NAME``)
        # into the unit JSON as ``decider_api_key_source`` so ``_stage_secrets``
        # can stage it scheme-appropriately — pre-this-fix only the VARIABLE
        # NAME was collected, so a ``systemd-creds:NAME`` key was staged
        # identically to an ``env:NAME`` key. On apple that happens to resolve
        # (``secret set`` is scheme-agnostic and stores the cleartext under NAME
        # in the keychain/plaintext store, which ``_stage_secrets`` reads by
        # NAME — see ``_stage_secrets``), but recording the scheme makes the
        # ``systemd-creds:`` path explicit instead of a silent same-as-env:
        # no-op, and lets the missing-value warning name the decider key
        # accurately rather than mislabeling it a relay credential. ``cmd:`` is
        # rejected at config time, so only ``env:`` / ``systemd-creds:`` reach
        # here. (The container backend's quadlet path adds a ``systemd-creds:``
        # key to ``creds_secrets`` for an ExecStartPre decrypt; apple has no
        # systemd-creds runtime, so the apple equivalent is the keychain-held
        # cleartext staged into the bind-mount file — see ``_stage_secrets``.)
        _auto = getattr(getattr(config, "domains", None), "auto", None)
        decider_api_key_source = ""
        if _auto is not None and getattr(_auto, "enable", False):
            _api_key = _auto.decider.agent.api_key or ""
            _scheme, _, _var = _api_key.partition(":")
            if _scheme and _var:
                decider_api_key_source = _api_key
                if _var not in relay_secret_envs:
                    relay_secret_envs.append(_var)
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
                # domains.auto decider api_key source scheme (``env:NAME`` /
                # ``systemd-creds:NAME``) — see the staging comment above.
                # ``_stage_secrets`` reads this to stage the decider key
                # scheme-appropriately and emit an accurate missing-value
                # warning. Empty when domains.auto is disabled.
                "decider_api_key_source": decider_api_key_source,
                # Upstream resolvers, so start() (meta-driven, no Config) can
                # hand them to the egress for policy-api granted zones.
                "dns_servers": list(config.dns_servers or []),
                # Secret backend choice, baked in so start() (which is
                # meta-driven, no Config) can resolve the right store.
                "secrets_backend": config.secrets.backend,
                "secrets_allow_plaintext": bool(config.secrets.allow_plaintext),
                "autostart": bool(getattr(config, "apple_container_autostart", False)),
                # Whether to bind-mount the grants overlay into the egress:
                # the feature is on, OR an allow entry has an expiry (the
                # addon sweeps those and re-publishes the DNS zone list).
                "domains_auto": bool(getattr(config.domains.auto, "enable", False)),
                "has_expiring_domains": bool(getattr(config.domains, "expires", None)),
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
                # User-declared ``container.tmpfs:`` targets. Persisted raw
                # (spec string, options included) so a future agentcage that
                # can forward options doesn't need a metadata migration;
                # start() normalizes to the bare paths Apple's --tmpfs
                # accepts. Pre-#318 this field was dropped entirely, which
                # silently disabled the #170 /workspace/.git/hooks/ and #173
                # /workspace/.claude/ masks on this backend.
                "tmpfs": list(config.container.tmpfs or []),
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
                # Outbound ICMP echo-request opt-in (ports.icmp.allow).
                # start() emits it as ALLOW_ICMP=0/1; the supervisor
                # installs the FORWARD accept rule only when "1".
                "allow_icmp": bool(config.ports.icmp.allow),
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

    def ensure_ready(self, *, quiet: bool = False) -> None:
        """Start the `container` apiserver if it isn't already running.

        The apiserver does not survive a reboot — it must be re-started each
        boot with `container system start`. While it's down every `container`
        subcommand fails (an XPC connection error), so a downed daemon used
        to surface as "wrapped image not found" from the image probe in
        start(). Bring it up here, mirroring the Lima backend which
        auto-starts its VM in start() rather than making the user do it by
        hand. Best-effort and idempotent: if it still won't come up,
        check_prerequisites() reports it uniformly with the other unmet
        prerequisites.
        """
        try:
            if ac_cli.system_running():
                return
            if not quiet:
                click.echo("Apple container apiserver not running — starting it…")
            ac_cli.run(["system", "start", "--enable-kernel-install"], check=False)
        except FileNotFoundError:
            # `container` CLI not installed — check_prerequisites() reports
            # this with an install hint; nothing to recover here.
            pass

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
                f"run `agentcage cage update {name}` to regenerate it "
                f"from the stored cage.yaml"
            )
        meta = json.loads(unit_path.read_text())

        # Defensive backstop for direct/programmatic callers: the CLI gates
        # build+start on ensure_ready() already, but start() may also be
        # invoked outside that path (backup/restore). ensure_ready() is
        # idempotent and best-effort; if the apiserver is still down after
        # it, fail with an actionable message rather than the misleading
        # "wrapped image not found" the image probe below would produce.
        self.ensure_ready(quiet=quiet)
        if not ac_cli.system_running():
            raise RuntimeError(
                "Apple container apiserver is not running and could not be "
                "started automatically — run "
                "'container system start --enable-kernel-install' manually "
                f"and retry (`agentcage cage start {name}`)"
            )

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

        # Re-render the bind-mounted egress config from the CURRENT host
        # state before (re)starting the microVMs.
        #
        # dnsmasq.conf / dns-allowlist.conf encode the cage's DNS upstream
        # as `server=/<apex>/<resolver-ip>`, where <resolver-ip> is the
        # host's resolver auto-detected from /etc/resolv.conf at render
        # time (config.dns_servers → _host_dns_servers()). These files are
        # only re-rendered by build_artifacts() (create/update) and
        # reload_domains() (domain add/rm) — NOT by start(). So a dev
        # laptop that changed networks (Wi-Fi switch, VPN up/down, host
        # reboot on a different LAN) since the last `cage update` comes
        # back up forwarding DNS to a resolver IP that no longer exists:
        # every uncached lookup times out and the cage "can't reach the
        # network" even though verify/status report green. The configs are
        # bind-mounted (not baked into the image), so re-rendering here
        # picks up the live resolver with no rebuild — start/restart now
        # self-heals across host network changes.
        #
        # Best-effort: if the host has no detectable resolver right now
        # (_host_dns_servers raises), keep the previously-rendered files
        # rather than failing a start that would otherwise have worked.
        try:
            from agentcage import state as _state

            cfg = _state.load_deployment_config(name)
            self._render_egress_config(cfg, name)
        except Exception as exc:  # noqa: BLE001 - never let a refresh failure block start
            if not quiet:
                click.echo(
                    f"warning: could not refresh DNS config for {name} from "
                    f"the current host resolver ({exc}); starting with the "
                    f"existing rendered config — if DNS fails inside the cage, "
                    f"run `agentcage cage update {name}`",
                    err=True,
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
            "-e", f"AGENTCAGE_VERSION={_agentcage_version()}",
            # Upstreams for policy-api granted zones — see the same env in
            # egress.container.j2 (the baseline is empty under default-deny,
            # so the supervisor cannot scrape upstreams from it).
            "-e", "AGENTCAGE_DNS_UPSTREAMS=" + " ".join(meta.get("dns_servers") or []),
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
        # domains.auto grants overlay — backing file for decided grants.
        # The host-side grants watcher (launchd plist
        # io.agentcage.<name>.grants) is DELETED; it is no longer the live
        # mechanism on apple-container. Granted DNS is now applied INSIDE
        # the egress by the supervisor, which renders BASELINE + GRANTED
        # zones into the servers-file (granted zones come from
        # /home/acproxy/dns/granted, written by the proxy addon inside the
        # egress). This bind persists the grants dir at the canonical
        # agentcage data path (state.grants_file(name), NOT this backend's
        # _state_dir) so the egress addon can write decided grants and a
        # shared legacy cleanup helper can still reach it; the source path
        # must match that canonical location exactly. RW so the addon can
        # write. Only mount when the feature is on OR any allow entry has
        # an expiry (the addon sweeps those and re-publishes the DNS zone
        # list).
        if meta.get("domains_auto") or meta.get("has_expiring_domains"):
            from agentcage import state as _state_mod
            grants_dir = _state_mod.grants_dir(name)
            grants_dir.mkdir(parents=True, exist_ok=True)
            # The egress addon (uid 200) rewrites grants.yaml via atomic
            # temp+rename, so the DIR must be writable by it. chmod 0777
            # (operator owns it; addon is "other" via the world bit). Don't
            # chown to 200 — that would block the operator's / the shared
            # cleanup helper's access.
            #
            # macOS hosts are single-user by default and the grants dir is
            # shared into the Lima VM over reverse-sshfs/virtiofs, a share
            # only traversable by the operator's account, so the host-side
            # subgid mapping the container/Linux backend uses (podman unshare
            # chgrp → 0770) does not apply the same way here. On a SHARED macOS
            # host (multiple local accounts) this 0777 is a known limitation:
            # another local user could plant grants.yaml entries that the
            # egress addon promotes into the baseline. See egress.container.j2
            # for the hardened container/Linux path.
            try:
                grants_dir.chmod(0o777)
            except OSError:
                pass
            egress_argv += [
                "--volume", f"{grants_dir}:/var/lib/agentcage",
                "-e", "AGENTCAGE_GRANTS_DIR=/var/lib/agentcage",
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
        # Outbound ICMP echo-request: off unless ports.icmp.allow opted in.
        # Legacy metadata (created before this knob) has no key → default 0,
        # matching the supervisor's locked-down default.
        allow_icmp = bool(meta.get("allow_icmp", False))
        egress_argv += [
            "-e", f"ALLOW_ICMP={1 if allow_icmp else 0}",
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

        # 3b. The egress (mitmproxy SecretInjector) has now loaded the staged
        # secrets into memory. Wipe the transiently-staged cleartext files so
        # nothing persists at rest — the durable copy lives in the cage's
        # secret backend (macOS keychain) and is re-staged on the next start().
        if staged_envs:
            self._wipe_staged_secrets(name)

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
        # workload runs, so uid 1000 has no caps. `cage exec --user 0`
        # does NOT re-acquire it either: container 1.0.0 hands exec
        # sessions only the default OCI cap set (no NET_ADMIN), so even
        # --as-root can't change routes/iptables (see module docstring).
        # The cage VM has NO secrets bind, NO config bind.
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
            #
            # CTF (#275, 0.25.4): mount :ro so the uid-1000 workload can
            # only read the public CA cert it's told to trust via
            # SSL_CERT_FILE / NODE_EXTRA_CA_CERTS — not tamper with,
            # replace, or persist host-backed files under /certs. Matches
            # the quadlet backend's `:/certs:ro,Z` (cage.container.j2).
            "--volume", f"{public_certs_dir}:/certs:ro",
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
            # Expose the running agentcage version to the cage workload so an
            # agent can detect it's sandboxed (and which version). Parity
            # with the container/vm backends' cage.container.j2.
            "-e", f"AGENTCAGE_VERSION={_agentcage_version()}",
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
        #
        # Prefer the LIVE stored config over the metadata snapshot baked
        # at create/update time, so a plain restart picks up placeholder
        # changes (parity with the container/vm backends' EnvironmentFile
        # delivery). Metadata remains the fallback for robustness.
        placeholders = dict(meta.get("secret_env_placeholders") or {})
        try:
            from agentcage import state as _state_mod
            raw = _state_mod.load_raw_config(name)
            si = raw.get("secret_injection") or []
            rules = si.get("rules", []) if isinstance(si, dict) else si
            for entry in rules if isinstance(rules, list) else []:
                if isinstance(entry, dict) and entry.get("env") \
                        and entry.get("placeholder"):
                    placeholders[entry["env"]] = entry["placeholder"]
        except FileNotFoundError:
            pass
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
        # Keeping the revalidation is load-bearing: it re-applies the
        # $HOME-containment and unresolved-$VAR guards, so hand-edited or
        # tampered unit metadata cannot mount a path that create/update time
        # would have refused. It preserves the inline ``np`` option so the
        # routing below can still see it.
        volume_entries = self._user_volume_argv(meta.get("volumes") or [])
        # A bind that carries the inline ``np`` flag is read from a lowerdir
        # and copied to a tmpfs at its requested target. Other binds are
        # passed directly through unchanged.
        copies: list[str] = []
        np_tmpfs_targets: set[str] = set()
        for idx, vol_entry in enumerate(volume_entries):
            host_src, target, _opts = split_volume_spec(vol_entry)
            if not target:
                continue
            if not is_non_persistent_volume(vol_entry):
                cage_argv += ["--volume", vol_entry]
                continue
            lower = f"/run/agentcage/mounts/vol-{idx}/lower"
            cage_argv += ["--volume", f"{host_src}:{lower}:ro"]
            if os.path.isdir(host_src):
                # Apple `container run --tmpfs` takes a bare path only;
                # Docker's `path:opts` syntax is interpreted literally.
                cage_argv += ["--tmpfs", target]
                np_tmpfs_targets.add(target.rstrip("/") or "/")
            copies.append(f"{lower}\t{target}")
        if copies:
            cage_argv += [
                "-e", "AGENTCAGE_NONPERSISTENT_COPIES=" + "\n".join(copies),
            ]
        # User-declared `container.tmpfs:` entries (#318 / the tmpfs half of
        # the #120 parity gap). Pre-0.32 these were dropped on this backend,
        # which silently disabled the claude-code scaffold's #170
        # `/workspace/.git/hooks/` and #173 `/workspace/.claude/` masks — the
        # one backend macOS picks by default was the one without them.
        #
        # Ordering: these masks overlay a path INSIDE the `/workspace` bind,
        # so the bind must be mounted first or the tmpfs is shadowed. argv
        # order does not decide that — Apple hands `--volume` and `--tmpfs`
        # to the guest in ONE `spec.mounts` array that containerization
        # sorts by destination depth before the in-guest OCI runtime applies
        # it (`cleanAndSortMounts` / `sortMountsByDestinationDepth` in
        # apple/containerization's LinuxContainer.swift, present since the
        # 0.33.x pinned by container 1.0.0). `/workspace` (depth 1) is
        # therefore always mounted before `/workspace/.git/hooks` (depth 3),
        # and the runtime creates the missing mountpoint. We still emit
        # after the volumes so the argv reads in mount order.
        for tmpfs_target in self._tmpfs_targets(meta.get("tmpfs") or []):
            # An `np` bind already owns this target with a tmpfs of its own
            # (seeded from the host lowerdir by cage-init stage C'); a second
            # --tmpfs would be a redundant destination that Apple dedupes
            # anyway. Skip it so the seeded copy is not masked by an empty
            # mount on a runtime that keeps both.
            if tmpfs_target in np_tmpfs_targets:
                continue
            cage_argv += ["--tmpfs", tmpfs_target]
        # Emulated `tmpcopyup` (#328). Apple's `--tmpfs` has no option
        # channel, so a mask that asks for copy-up gets the host directory it
        # covers mounted READ-ONLY alongside it and cage-init's stage C''
        # replays that into the tmpfs as the cage user. Same machinery as the
        # `np` seeding above; the read-only lower is the only new host-facing
        # mount and it is never written to, so the mask still blocks every
        # cage->host write.
        copyup_seeds = self._tmpfs_copyup_seeds(
            meta.get("tmpfs") or [], volume_entries, np_tmpfs_targets,
        )
        for host_source, lower, _target in copyup_seeds:
            cage_argv += ["--volume", f"{host_source}:{lower}:ro"]
        if copyup_seeds:
            cage_argv += [
                "-e",
                "AGENTCAGE_TMPFS_COPYUP=" + "\n".join(
                    f"{lower}\t{target}" for _src, lower, target in copyup_seeds
                ),
            ]
        # A mask nested under a host bind makes the in-guest OCI runtime
        # mkdir the mount point THROUGH the bind, onto the host (#320).
        # Record which of those dirs are absent right now so stop/destroy
        # can retire exactly those, and only while still empty.
        self._record_mask_mountpoints(
            name, meta.get("tmpfs") or [], volume_entries,
        )
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

    def _wipe_staged_secrets(self, name: str) -> None:
        """Delete the transiently-staged cleartext secret files.

        Called once the egress has loaded them into memory (after the
        supervisor-ready marker), so no cleartext persists in the bind-mount
        dir at rest. The durable encrypted copy lives in the cage's secret
        backend (keychain); ``start()`` re-stages from it each time.
        """
        secrets_dir = self.secrets_dir(name)
        if not secrets_dir.is_dir():
            return
        for f in secrets_dir.iterdir():
            try:
                f.unlink()
            except OSError:
                pass

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
        # domains.auto decider api_key source (``env:NAME`` /
        # ``systemd-creds:NAME``). The decider key is ALSO in
        # ``relay_secret_envs`` (added by ``generate_units``) so it is
        # staged into the bind mount like a relay credential; we parse the
        # source here only to (a) stage it scheme-appropriately and (b)
        # name it accurately in the missing-value warning instead of
        # mislabeling it a relay credential. ``cmd:`` is rejected at config
        # time, so only ``env:`` / ``systemd-creds:`` reach here.
        _decider_src = meta.get("decider_api_key_source") or ""
        _decider_name = _decider_src.partition(":")[2] if _decider_src else ""
        all_secret_envs = list(secret_envs) + [
            v for v in relay_secret_envs if v not in secret_envs
        ]
        if not all_secret_envs:
            return staged

        # Pull secret VALUES from the cage's backend (macOS keychain by
        # default, encrypted at rest; or the legacy pending_secrets.json under
        # `secrets.backend: plaintext`). The values are materialized into the
        # 0600 bind-mount dir below ONLY transiently — wiped once the egress
        # has loaded them (see _wipe_staged_secrets, called from start()).
        from types import SimpleNamespace

        from agentcage import state as _state
        from agentcage.secret_store import SecretStoreError, resolve_store
        sd = _state.deployment_dir(name)
        # start() is meta-driven (no Config); rebuild the bits resolve_store
        # needs from the unit JSON the backend baked in at generate time.
        cfg_shim = SimpleNamespace(
            isolation="apple-container",
            secrets=SimpleNamespace(
                backend=meta.get("secrets_backend", "auto"),
                allow_plaintext=bool(meta.get("secrets_allow_plaintext", False)),
                scope="auto",
            ),
        )
        # NOTE on ``systemd-creds:`` staging (apple parity with the
        # container backend). The container backend's quadlet path, for a
        # ``systemd-creds:NAME`` decider key, adds NAME to ``creds_secrets``
        # (a systemd ExecStartPre decrypts ``<state>/creds/NAME.cred``) and
        # ``proxy_secrets`` (a podman ``Secret=`` directive exposes the value
        # as env ``$NAME`` inside the proxy); the addon's ``_read_secret``
        # then finds it via ``os.environ[NAME]``. Apple's runtime has neither
        # systemd-creds nor a podman secret store, so the apple equivalent
        # is: ``secret set`` is scheme-agnostic on apple (``cli.secret_set``
        # calls ``_store_secret`` with NO source_scheme for the apple branch)
        # and stores the cleartext under NAME in the keychain (or the legacy
        # ``pending_secrets.json`` under ``secrets.backend: plaintext``).
        # ``_stage_secrets`` retrieves it by NAME from that SAME store and
        # writes it to ``secrets_dir/NAME``; the bind-mounted file is read by
        # the addon's ``_read_secret`` at ``/home/acproxy/secrets/NAME`` —
        # the apple channel that stands in for the container backend's podman
        # ``Secret=`` env. So both ``env:NAME`` and ``systemd-creds:NAME``
        # resolve identically here (by NAME from the configured store); the
        # ``systemd-creds:`` scheme is effectively decorative on apple, and
        # the value reaches the addon either way. We do NOT pass
        # ``source_scheme="systemd-creds"`` to ``resolve_store`` here — that
        # would select ``SystemdCredsStore`` (whose ``get`` raises on apple,
        # where the systemd-creds binary is absent) and break staging.
        provided: dict[str, str] = {}
        try:
            store = resolve_store(cfg_shim)
            for env_name in all_secret_envs:
                val = store.get(name, env_name, state_dir=sd)
                if val is not None:
                    provided[env_name] = val
        except SecretStoreError as exc:
            click.echo(
                f"warning: could not read secrets for {name}: {exc}", err=True,
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
                if env_name == _decider_name and _decider_name:
                    # The decider agent's api_key (egress-only). A missing
                    # value means every domain-request fails closed with
                    # 503 "llm provider not configured" — name it
                    # accurately rather than as a relay credential.
                    click.echo(
                        f"warning: domains.auto.decider.agent.api_key env "
                        f"{_decider_name!r} not provided via "
                        f"--set-secret; the decider will fail closed (503 "
                        f"'llm provider not configured') on every domain "
                        f"request",
                        err=True,
                    )
                elif env_name in relay_only:
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

        Apple's `container inspect` returns a list (one entry per
        container). The IP lives under ``networks[].ipv4Address``
        (CIDR-form, e.g. ``192.168.64.5/24``); we strip the mask. The
        ``networks`` list sat at the top level pre-1.0 and moved under the
        nested ``status`` object in v1.0.0 — ``ac_cli.container_networks``
        absorbs both. Returns None if no address is populated yet (still
        booting — caller should poll briefly).
        """
        data = ac_cli.inspect(name)
        if not data:
            return None
        for net in ac_cli.container_networks(data):
            # Apple's schema (verified empirically against v0.12.3 and
            # v1.0.0): `ipv4Address` is the populated field. Defensively
            # also check `address`/`Address` for other schema variants.
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
            state = ac_cli.container_state(data)
            if data is not None and state not in ("running", None):
                raise RuntimeError(
                    f"egress sibling {egress_name!r} exited before becoming "
                    f"ready (state={state!r}); see `container logs {egress_name}`"
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
        # Retire the host dirs the tmpfs masks materialized through the
        # workspace bind (#320). After the cage VM is down, so a still-live
        # mount can't make an empty dir look occupied.
        self._cleanup_mask_mountpoints(name)

    def restart(self, name: str) -> None:
        self.stop(name)
        self.start(name)

    def destroy_resources(self, name: str, keep_secrets: bool = False) -> list[str]:  # noqa: ARG002
        """Stop+delete both microVMs, delete the per-cage network + wrapper
        image + state dir.

        The shared egress image (agentcage-egress:<version>-<hash>) is NOT
        removed — it's used by sibling cages, which may well be pinned to
        this exact tag. Superseded egress tags are left in place for the
        same reason; `container image delete` them by hand if disk matters.
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
        # Mask mount points created through the workspace bind (#320).
        # Runs before the state rmtree below, which would otherwise take the
        # bookkeeping file with it. No-op when stop() already handled it.
        self._cleanup_mask_mountpoints(name)
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
        return ac_cli.container_state(data) == "running"

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
            path. Image USER (root on the slim wrapper) applies, but
            `container exec -u 0` on Apple `container` 1.0.0 grants only
            the DEFAULT OCI cap set (no CAP_NET_ADMIN), so even this
            session cannot change the cage's default route or touch
            iptables — `ip route replace` / `iptables -F` return EPERM.
            Verified on a ubuntu cage; see the module docstring.

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

        # Cage sessions get the current secret-injection placeholders
        # (decoy tokens) read from the stored config at exec time — same
        # behavior as the container/vm backends. Apple's `container exec`
        # has no --env flag, so chain through env(1); with the setpriv
        # wrap, "$@" receives [env, K=V, ..., cmd] and env exec's the
        # command after the uid drop.
        env_prefix: list[str] = []
        if service in ("cage", ""):
            from agentcage.services import current_placeholders
            pairs = [
                f"{env_name}={placeholder}"
                for env_name, placeholder in current_placeholders(name)
            ]
            if pairs:
                env_prefix = ["env", *pairs]
        if spec is not None:
            return [
                binary, "exec", "-u", spec, *flags, target,
                *wrap, *env_prefix, *cmd,
            ]
        return [binary, "exec", *flags, target, *wrap, *env_prefix, *cmd]

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
        `<state>/<cage>/logs/audit.jsonl` on the host. `since` is ignored
        here because the host JSONL has no journalctl-style time index —
        `tail` cannot seek by time. The CLI compensates: `cage audit`
        parses --since and applies it as `AuditFilter.since`, dropping
        records older than the cutoff after they are parsed (parity with
        the native journalctl --since on the container/vm backends).
        """
        path = self.logs_dir(name) / "audit.jsonl"
        if follow:
            return ["tail", "-n", "0", "-F", str(path)]
        return ["tail", "-n", "10000", str(path)]
