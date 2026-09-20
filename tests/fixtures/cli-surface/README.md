# `cli-surface` — the golden CLI surface

Generated from the live click tree in `src/agentcage/cli.py` by
`scripts/gen-cli-surface.py`. Nothing in this directory is hand-written.

```sh
uv run python scripts/gen-cli-surface.py          # rewrite
uv run python scripts/gen-cli-surface.py --check  # fail if stale (CI runs this)
```

It exists because PR D5 rebuilds `cli.py`'s command tree in clap, and
`cli.py` is the whole public surface of agentcage — 48 command nodes,
each one a promise to somebody's shell script. The Rust side asserts
against this fixture in `rust/agentcage-cli/src/cli/conformance.rs`.

## What is here

| File | What it is |
| :-- | :-- |
| `surface.json` | Every command, subcommand, alias, option, argument, default, choice set and hidden bit, as click declares them. |
| `parse-cases.json` | 58 command lines, resolved and parsed through the real click tree, with the resulting parameter values or the error that came back. |
| `help/<path>.txt` | The click `--help` output for each node, verbatim. |

`help/` is not asserted byte-for-byte against anything. It is the
human-readable record: when a contract assertion fails, it is what you
read to see what click actually printed. `surface.json` and
`parse-cases.json` are the oracles.

### Counts

`surface.json` carries them under `counts`, and the Rust side asserts
each one:

| | |
| :-- | --: |
| command nodes | 48 |
| groups | 7 |
| leaf commands | 41 |
| top-level nodes | 7 |
| aliases | 31 |
| options (incl. the `--help` click adds to every node, and `--version`) | 129 |
| options declared in `cli.py` | 80 |
| hidden options | 4 |
| arguments | 44 |
| variadic arguments | 4 |
| `ignore_unknown_options` commands | 2 |

## Two normalisations

Both are in the generator, and both are unavoidable:

* **ANSI is stripped.** The root's help is prefixed by
  `output.banner_text`, which calls `click.style`. The escape codes are
  terminal decoration, not surface — and `click.echo` strips them itself
  when the destination is not a tty.
* **The version becomes `{VERSION}`.** The banner embeds it. Without
  this, the fixture would go stale on every release bump and everyone
  would learn to re-bless it without reading the diff.

## What the Rust side asserts, and what it lets differ

clap is not click. It wraps text at a different column, orders its help
sections differently, and spells its errors in its own words. Contorting
clap into click's exact layout would mean re-implementing click's
formatter — a much larger surface to get wrong than the one it would be
protecting.

So the port asserts **contracts** and enumerates **layout**. The
authoritative list of permitted differences is `ALLOWED_DIFFERENCES` in
`rust/agentcage-cli/src/cli/conformance.rs`, which is a test-checked
constant rather than prose. In summary:

**Asserted.** Every command and subcommand, and the order they are
listed in. Every alias and what it resolves to. Every option's long
name, short name and extra spellings. Every option's help text, byte for
byte. Every hidden bit. Every default. Every `click.Choice` set. Every
argument's arity and whether it is required. Whether a variadic accepts
flag-shaped values (`ignore_unknown_options`). The `--version` string.
The exit code and parsed parameter values for all 58 recorded command
lines.

**Allowed to differ.** Usage-line brackets. Where lines wrap. Choice
metavar punctuation. clap's `[default: ]` annotation on options where
click had `show_default=False`. Section order. The wording of usage
errors — though never their exit code, which stays 2. click's `\x08`
no-rewrap marker lines, which clap neither has nor needs.

**Added.** One command, `agentcage completions <SHELL>`, hidden. click
ships completion through the `_AGENTCAGE_COMPLETE` environment protocol
with no command at all; clap has no stable equivalent. It is allowlisted
by name in `conformance.rs` rather than by loosening any assertion.

## Adding a parse case

Append the argv to `PARSE_CASES` in `scripts/gen-cli-surface.py` and
regenerate. The expectation is always *computed* by running click, never
typed — a case cannot be added with a wrong expectation, and a behaviour
change shows up as a fixture diff in review instead of as silent drift.

Keep cases independent of the working directory. Two of them exercise
`click.Path(exists=True)` and pass `.` for exactly that reason: the Rust
side replays them from its own crate root, not from the repo root.
