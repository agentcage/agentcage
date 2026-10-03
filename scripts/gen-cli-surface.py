#!/usr/bin/env python3
"""Generate the CLI-surface fixture under tests/fixtures/cli-surface/.

`cli.py` is the whole public surface of agentcage: 48 command nodes, every
one of them a promise to somebody's shell script. PR D5 rebuilds that
surface in clap, and clap is not click — it wraps text differently, orders
sections differently, and spells "usage" with a capital U. So the port
cannot be verified by diffing two help screens; it has to be verified
against the *contracts* inside them.

This script is the oracle. It walks the live click tree in
``agentcage.cli`` and writes two things:

``surface.json``
    The structured contract: every command, every subcommand, every alias,
    every flag with its long and short spellings, its default, its arity,
    its hidden bit and its help text. This is what the Rust side asserts
    against, field by field, in ``rust/agentcage-cli/src/cli/conformance.rs``.

``help/<path>.txt``
    The click ``--help`` output for that node, verbatim (modulo the two
    normalisations below). Nothing asserts a byte-diff against these --
    they are the human-readable record that makes a review of the JSON
    possible, and the thing to read when a contract assertion fails and
    you want to know what click actually printed.

Two normalisations, both unavoidable:

* **ANSI is stripped.** The root group's help is prefixed by
  ``output.banner_text``, which calls ``click.style``; the escape codes
  are terminal decoration, not surface.
* **The version is replaced by ``{VERSION}``.** The banner embeds it, so
  an un-normalised fixture would go stale on every release bump and teach
  everyone to re-bless it without reading the diff.

The tree is walked through the *public* entry points -- ``Group.commands``
for children, plus the alias maps -- so a command that is reachable only
via an alias (``agentcage run``, which lives at ``cage run`` and is
surfaced at the top level by ``_BannerGroup._global_aliases``) is recorded
where a naive walk would miss it.

Usage:
    uv run python scripts/gen-cli-surface.py          # write
    uv run python scripts/gen-cli-surface.py --check  # fail if stale

See tests/fixtures/cli-surface/README.md.
"""

from __future__ import annotations

import argparse
import inspect
import json
import os
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_OUT = _ROOT / "tests" / "fixtures" / "cli-surface"

sys.path.insert(0, str(_ROOT / "src"))

# Click consults these before it decides to colour or to wrap. Set them
# before the import so nothing caches a width off the developer's tty.
os.environ["TERM"] = "dumb"
os.environ["NO_COLOR"] = "1"
os.environ["COLUMNS"] = "80"

import click  # noqa: E402

from agentcage import cli as _cli  # noqa: E402

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _version() -> str:
    from importlib.metadata import version

    return version("agentcage")


def _scrub(text: str) -> str:
    """Strip ANSI and pin the version, so the fixture is release-stable."""
    return _ANSI_RE.sub("", text).replace(_version(), "{VERSION}")


# ── type description ────────────────────────────────────────────────


def _type_info(param: click.Parameter) -> dict:
    """Describe a click ParamType in the terms clap has to reproduce.

    Only the properties that reach the user matter: the name clap will
    print in a metavar, the closed set a Choice enforces, and whether a
    Path is checked for existence (``exists=True`` is a *validation*
    contract -- ``cage create nope.yaml`` must fail before anything is
    deployed, not after).
    """
    ty = param.type
    info: dict = {"name": ty.name}
    choices = getattr(ty, "choices", None)
    if choices is not None:
        info["choices"] = list(choices)
    if isinstance(ty, click.Path):
        info["path_exists"] = bool(ty.exists)
    return info


def _jsonable(value):
    """Coerce a click attribute to JSON, naming what cannot be coerced.

    Click 8.4 uses a module-private ``Sentinel`` for "no default was
    declared", which is a different statement from ``default=None`` --
    the latter is a real, user-visible default of nothing. Both reach
    here, and they must not collapse into the same JSON.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (tuple, list)):
        return [_jsonable(v) for v in value]
    if callable(value):  # click allows a default factory; none are used today.
        return {"callable": True}
    if type(value).__name__ == "Sentinel":
        return {"unset": True}
    return {"repr": repr(value)}


def _default(param: click.Parameter):
    """The declared default, as JSON.

    ``multiple`` options default to ``()``; that is click bookkeeping
    rather than a value a user can observe, so it records as an empty
    list and the Rust side treats an absent multi-value the same way.
    """
    return _jsonable(param.default)


def _param_info(param: click.Parameter) -> dict:
    info = {
        "kind": "argument" if isinstance(param, click.Argument) else "option",
        "dest": param.name,
        "opts": list(param.opts),
        "secondary_opts": list(param.secondary_opts),
        "metavar": param.metavar,
        "required": bool(param.required),
        "nargs": param.nargs,
        "multiple": bool(param.multiple),
        "default": _default(param),
        "type": _type_info(param),
    }
    if isinstance(param, click.Option):
        info.update(
            {
                "is_flag": bool(param.is_flag),
                "hidden": bool(param.hidden),
                "help": _cleandoc(param.help),
                "show_default": bool(param.show_default),
                "count": bool(param.count),
                "prompt": _jsonable(param.prompt),
                "is_eager": bool(param.is_eager),
            }
        )
    else:
        # Arguments have no help in click at all -- the docstring carries
        # it. Recorded explicitly so the Rust side does not invent one
        # and then fail to explain where it came from.
        info.update({"is_flag": False, "hidden": False, "help": None})
    return info


# ── tree walk ───────────────────────────────────────────────────────


def _aliases(cmd: click.Command) -> dict[str, str]:
    """The alias map this node publishes, alias -> the path it resolves to.

    Two shapes exist. ``AliasGroup`` maps an alias to a sibling command
    *name* (``ls`` -> ``list``). ``_BannerGroup`` maps a top-level alias
    to a (function, display-path) pair where the display path is a full
    command line (``ls`` -> ``cage list``). Both flatten to the same
    thing here: what the user types, and what it means.
    """
    banner = getattr(cmd, "_global_aliases", None)
    if banner is not None:
        return {alias: target for alias, (_, target) in sorted(banner.items())}
    plain = getattr(cmd, "_aliases", None)
    if plain:
        return dict(sorted(plain.items()))
    return {}


def _cleandoc(text):
    """``inspect.cleandoc`` a help string, or pass ``None`` through.

    **This is what makes the fixture reproducible.** `cmd.help` is the
    command's ``__doc__``, and CPython 3.13 changed what that is:
    since gh-81283 the *compiler* strips each docstring's common leading
    indentation, so the same `cli.py` yields indented help on 3.12 and
    dedented help on 3.13+. Recording it raw made `--check` pass or fail
    depending on which interpreter `uv` happened to pick — and a
    developer on 3.12 would silently rewrite every help string in the
    fixture just by regenerating it.

    ``inspect.cleandoc`` is the right normaliser rather than an
    arbitrary one: it is what click itself applies before *displaying*
    help, so this records the text a user actually sees. It is
    idempotent on the 3.13+ form apart from the trailing newline, which
    `conformance.rs`'s `normalize_help` already trims on the Rust side.
    """
    if text is None:
        return None
    return inspect.cleandoc(text)


def _node(cmd: click.Command, path: list[str]) -> dict:
    parent_ctx = None
    for name in path[:-1]:
        parent_ctx = click.Context(
            click.Command(name), info_name=name, parent=parent_ctx
        )
    ctx = click.Context(
        cmd,
        info_name=path[-1],
        parent=parent_ctx,
        terminal_width=80,
        **(cmd.context_settings or {}),
    )

    settings = cmd.context_settings or {}
    node = {
        "path": path,
        "is_group": isinstance(cmd, click.Group),
        "class": type(cmd).__name__,
        "help": _cleandoc(cmd.help),
        "short_help": cmd.get_short_help_str(limit=200) or None,
        "hidden": bool(cmd.hidden),
        "deprecated": bool(cmd.deprecated),
        "ignore_unknown_options": bool(settings.get("ignore_unknown_options", False)),
        "allow_extra_args": bool(settings.get("allow_extra_args", False)),
        "aliases": _aliases(cmd),
        "params": [_param_info(p) for p in cmd.get_params(ctx)],
        "subcommands": (
            sorted(cmd.commands) if isinstance(cmd, click.Group) else []
        ),
        "help_text": _scrub(cmd.get_help(ctx)),
    }
    return node


def _walk() -> list[dict]:
    nodes: list[dict] = []
    seen: set[tuple[str, ...]] = set()

    def visit(cmd: click.Command, path: list[str]) -> None:
        key = tuple(path)
        if key in seen:
            return
        seen.add(key)
        nodes.append(_node(cmd, path))
        if isinstance(cmd, click.Group):
            for name in sorted(cmd.commands):
                visit(cmd.commands[name], path + [name])

    visit(_cli.main, ["agentcage"])
    nodes.sort(key=lambda n: n["path"])
    return nodes


def _alias_targets(nodes: list[dict]) -> list[dict]:
    """Flatten every alias in the tree to (where typed, what it runs).

    The Rust side needs this as a flat list because clap expresses an
    alias as an attribute of the target command, not as an entry on the
    parent -- so the parent-keyed maps in the nodes are the wrong shape
    to assert against directly.
    """
    flat = []
    for node in nodes:
        for alias, target in node["aliases"].items():
            flat.append(
                {
                    "parent": node["path"],
                    "alias": alias,
                    # A `_BannerGroup` target is a full command line; an
                    # `AliasGroup` target is a bare sibling name.
                    "target": target.split(),
                }
            )
    flat.sort(key=lambda a: (a["parent"], a["alias"]))
    return flat


def _counts(nodes: list[dict], aliases: list[dict]) -> dict:
    flags = [p for n in nodes for p in n["params"] if p["kind"] == "option"]
    args = [p for n in nodes for p in n["params"] if p["kind"] == "argument"]
    return {
        "nodes": len(nodes),
        "groups": sum(1 for n in nodes if n["is_group"]),
        "commands": sum(1 for n in nodes if not n["is_group"]),
        "top_level": sum(1 for n in nodes if len(n["path"]) == 2),
        "aliases": len(aliases),
        "options": len(flags),
        "hidden_options": sum(1 for p in flags if p["hidden"]),
        "arguments": len(args),
        "variadic_arguments": sum(1 for p in args if p["nargs"] == -1),
        "passthrough_commands": sum(1 for n in nodes if n["ignore_unknown_options"]),
    }


# ── parse cases ─────────────────────────────────────────────────────
#
# The node walk above records what the tree *declares*. These record what
# it *does* with a command line -- which is a different thing, and the
# part that breaks silently. `agentcage cage exec foo -- ls -la` has to
# deliver `ls -la` to the workload rather than complaining about `-l`;
# nothing in the declared surface says so on its own.
#
# Each case is resolved through the real click tree (aliases included)
# and parsed WITHOUT invoking any callback, so the fixture can be
# generated on a machine with no podman, no cages and no state.

PARSE_CASES: list[list[str]] = [
    # ── passthrough: the two ignore_unknown_options commands ────────
    ["cage", "exec", "myapp", "--", "ls", "-la"],
    ["cage", "exec", "--as-root", "myapp", "--", "openclaw", "devices", "list"],
    ["cage", "exec", "myapp", "ls", "-la"],
    ["cage", "exec", "-s", "egress", "myapp", "--", "sh", "-c", "echo $HOME"],
    ["exec", "myapp", "--", "ls", "-la"],
    ["run", "claude-code", "--", "claude", "--help"],
    ["run", "codex", "-s", "OPENAI_API_KEY", "--", "codex", "--version"],
    ["cage", "run", "claude-code", "--no-cache", "--", "claude", "-p", "hi"],
    ["run", "claude-code", "--verbose", "--", "--not-a-flag"],
    # ── hidden back-compat options ──────────────────────────────────
    ["cage", "audit", "myapp", "--lines", "10"],
    ["cage", "audit", "myapp", "--json-lines"],
    ["cage", "har", "myapp", "--json"],
    ["cage", "logs", "myapp", "--no-follow"],
    ["cage", "logs", "myapp", "--tail", "5"],
    # ── aliases, top level and in-group ─────────────────────────────
    ["ls"],
    ["ps"],
    ["rm", "myapp", "-y"],
    ["delete", "myapp"],
    ["reload", "myapp"],
    ["config", "myapp"],
    ["describe", "myapp"],
    ["inspect", "myapp"],
    ["cage", "ls"],
    ["cage", "rm", "myapp"],
    ["cage", "config", "myapp"],
    ["domain", "ls", "myapp"],
    ["secret", "ls", "myapp"],
    ["watcher", "ls", "myapp"],
    ["cage", "grants", "myapp", "ls"],
    # ── defaults and repeatable options ─────────────────────────────
    ["cage", "audit", "myapp"],
    ["cage", "audit", "myapp", "-d", "blocked", "-d", "flagged", "--host", "a.example"],
    ["cage", "logs", "myapp"],
    ["cage", "har", "myapp"],
    ["cage", "shell", "myapp"],
    ["init"],
    ["init", "myapp", "--port", "8080"],
    ["watcher", "findings", "myapp", "-s", "high", "-s", "critical"],
    ["secret", "set", "myapp", "KEY", "--declare"],
    ["secret", "rotate-placeholders", "myapp"],
    ["secret", "rotate-placeholders", "myapp", "A", "B"],
    ["domain", "add", "myapp", "a.example", "b.example", "--passthrough"],
    ["cage", "create", "."],
    ["cage", "create", "-c", ".", "-s", "K=V", "--no-cache", "--pull", "--time"],
    ["cage", "update"],
    ["cage", "status"],
    # ── errors: arity, unknown, choice ──────────────────────────────
    [],
    ["cage"],
    ["cage", "grants"],
    ["cage", "grants", "myapp"],
    ["nosuchcommand"],
    ["cage", "nosuchcommand"],
    ["doctor", "--nope"],
    ["cage", "exec", "myapp"],
    ["cage", "show"],
    ["cage", "audit", "myapp", "-d", "nope"],
    ["cage", "logs", "myapp", "-n", "notanumber"],
    ["domain", "add", "myapp"],
    ["cage", "create", "./definitely-missing.yaml"],
]


def _parse_case(argv: list[str]) -> dict:
    """Resolve and parse one command line, recording the outcome only.

    Callbacks are never invoked: ``Command.parse_args`` fills a context's
    ``params`` and hands back what is left, and the walk down the tree is
    the same ``resolve_command`` click itself uses -- so aliases resolve
    exactly as they do in anger, but nothing touches podman or the disk.
    """
    result: dict = {"argv": argv}
    frames: list[dict] = []
    cmd: click.Command = _cli.main
    info = "agentcage"
    parent: click.Context | None = None
    args = list(argv)
    path: list[str] = []

    try:
        while True:
            # `context_settings` is applied by `Command.make_context`, not
            # by the `Context` constructor -- build one by hand without it
            # and `ignore_unknown_options` silently does not apply, which
            # is precisely the property these cases exist to pin.
            ctx = click.Context(
                cmd,
                info_name=info,
                parent=parent,
                terminal_width=80,
                **(cmd.context_settings or {}),
            )
            rest = cmd.parse_args(ctx, args)
            path = path + [info]
            frames.append(
                {
                    "command": list(path),
                    "params": {
                        key: _jsonable(value) for key, value in sorted(ctx.params.items())
                    },
                }
            )
            if not isinstance(cmd, click.Group):
                result["trailing"] = list(rest)
                break
            # `Group.parse_args` hands back `ctx.args` only; click 8.2+
            # peels the subcommand token off into `ctx._protected_args`
            # and `Group.invoke` puts the two back together. Do the same,
            # or every descent below the root silently skips a level.
            rest = list(getattr(ctx, "_protected_args", []) or []) + list(ctx.args)
            if not rest:
                if cmd.no_args_is_help:
                    result["outcome"] = "no_args_is_help"
                    result["exit_code"] = 2
                    result["frames"] = frames
                    return result
                break
            _name, sub, rest = cmd.resolve_command(ctx, rest)
            if sub is None:
                break
            parent, cmd, info, args = ctx, sub, sub.name, list(rest)
    except click.exceptions.NoSuchOption as exc:
        return _error_case(result, frames, "NoSuchOption", exc.format_message(), 2)
    except click.exceptions.UsageError as exc:
        return _error_case(result, frames, type(exc).__name__, exc.format_message(), 2)
    except SystemExit as exc:  # an eager --help / --version fired
        result["outcome"] = "exit"
        result["exit_code"] = int(exc.code or 0)
        result["frames"] = frames
        return result

    result["outcome"] = "parsed"
    result["exit_code"] = 0
    result["frames"] = frames
    return result


def _error_case(
    result: dict, frames: list[dict], kind: str, message: str, code: int
) -> dict:
    result["outcome"] = "error"
    result["error_kind"] = kind
    result["error_message"] = _scrub(message)
    result["exit_code"] = code
    result["frames"] = frames
    return result


def _slug(path: list[str]) -> str:
    return "-".join(path[1:]) or "root"


def build() -> dict[str, str]:
    """Return {relative path: file content} for the whole fixture."""
    nodes = _walk()
    aliases = _alias_targets(nodes)
    files: dict[str, str] = {}

    for node in nodes:
        files[f"help/{_slug(node['path'])}.txt"] = node["help_text"]

    surface = {
        "_generated_by": "scripts/gen-cli-surface.py",
        "click_version": _get_click_version(),
        "counts": _counts(nodes, aliases),
        "aliases": aliases,
        "nodes": [{k: v for k, v in n.items() if k != "help_text"} for n in nodes],
    }
    files["surface.json"] = json.dumps(surface, indent=2, sort_keys=True) + "\n"

    parses = {
        "_generated_by": "scripts/gen-cli-surface.py",
        "cases": [_parse_case(argv) for argv in PARSE_CASES],
    }
    files["parse-cases.json"] = json.dumps(parses, indent=2, sort_keys=True) + "\n"
    return files


def _get_click_version() -> str:
    from importlib.metadata import version

    return version("click")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the committed fixture differs from a fresh run.",
    )
    args = ap.parse_args()

    # Two cases exercise click.Path(exists=True). They pass "." rather
    # than a repo file so the recorded outcome holds in any working
    # directory -- the Rust side replays them from its own crate root.
    os.chdir(_ROOT)

    files = build()

    if args.check:
        stale = []
        for rel, content in sorted(files.items()):
            path = _OUT / rel
            if not path.exists() or path.read_text() != content:
                stale.append(rel)
        existing = {
            str(p.relative_to(_OUT))
            for p in _OUT.rglob("*")
            if p.is_file() and p.name != "README.md"
        }
        orphans = sorted(existing - set(files))
        if stale or orphans:
            print("cli-surface fixture is stale.", file=sys.stderr)
            for rel in stale:
                print(f"  changed/missing: {rel}", file=sys.stderr)
            for rel in orphans:
                print(f"  no longer generated: {rel}", file=sys.stderr)
            print(
                "Regenerate with: uv run python scripts/gen-cli-surface.py",
                file=sys.stderr,
            )
            return 1
        print(f"cli-surface fixture up to date ({len(files)} files).")
        return 0

    _OUT.mkdir(parents=True, exist_ok=True)
    (_OUT / "help").mkdir(exist_ok=True)
    generated = set(files)
    for rel, content in sorted(files.items()):
        path = _OUT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    for path in sorted(_OUT.rglob("*")):
        if path.is_file() and path.name != "README.md":
            rel = str(path.relative_to(_OUT))
            if rel not in generated:
                path.unlink()
                print(f"removed stale {rel}")
    counts = json.loads(files["surface.json"])["counts"]
    print(f"wrote {len(files)} files to {_OUT.relative_to(_ROOT)}")
    for key, value in counts.items():
        print(f"  {key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
