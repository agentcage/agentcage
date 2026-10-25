# `plan`, `lint`, config schema and imports

| | |
| :--- | :--- |
| **Issue** | [#568](https://github.com/agentcage/agentcage/issues/568) |
| **Status** | Proposed |
| **Priority** | P1 |
| **Phase** | 1 |
| **Depends on** | [#566](https://github.com/agentcage/agentcage/issues/566) |
| **Related** | [#567](https://github.com/agentcage/agentcage/issues/567) |

## Problem

`cage create` builds and starts immediately. There is no dry-run, no
pre-deploy policy report and no static security review. Configuration is only
validated at create/update time, and there is no schema for editors or
team-shared overlays.

## Proposal

### `plan`

`agentcage cage plan -c cage.yaml` (alias `plan`) prints:

- name, backend, lifecycle, image/build inputs;
- ports and host bindings;
- volumes and named volumes, including pivot masks;
- required secrets (names only);
- effective allow/block/passthrough domains and expiry;
- resource limits and timeouts;
- warnings from lint;
- the exact `cage create` command it would run.

It performs no writes, builds, pulls, port binds or secret staging.

### `lint`

`agentcage cage lint -c cage.yaml` returns non-zero only on errors; warnings
are printed with a path and a remediation. Checks include:

- bare top-level domains or wildcard-like entries;
- broad passthrough;
- `read_only: false` without a documented reason;
- `as-root` / privileged/nested settings;
- `container.env` values containing `$VAR` (see #416);
- missing `inject_to` or empty injection domains;
- unencrypted `secrets.backend: plaintext` and `allow_plaintext`;
- secrets stored in `container.env`;
- open or non-loopback published ports;
- `agents`/`watcher` enabled without a configured key;
- no allowlist in `allowlist` mode.

### Config schema

- Publish a JSON Schema for `cage.yaml` with a stable `$schema` URL/path.
- Generated configs include `# yaml-language-server: $schema=...`.
- `agentcage cage schema` writes or prints the schema for editors/CI.

### `extends` and imports

- `extends: ../base/cage.yaml` with documented merge semantics for maps and
  lists (replace by default; explicit append only where safe).
- `agentcage init --from devcontainer.json` maps image, mounts, ports, env and
  features where possible, and reports unsupported fields.
- `agentcage init --from Dockerfile` extracts image/build basics.
- `agentcage init --detect` reads `package.json`, `pyproject.toml`,
  `Cargo.toml`, `go.mod` and proposes package-registry presets.

## Implementation

- `plan` should reuse the validation, fingerprint and rendering path, with a
  hard stop before side effects.
- `lint` should be a separate library module in `agentcage-core`, reusable by
  `create` warnings.
- Generate the schema from the config types where practical; if hand-written,
  add a test that every documented key appears.
- Merge semantics must be explicit and tested; do not use YAML anchors as a
  substitute for documented overlays.
- Importers must never execute project code; parse only.

## Acceptance criteria

- [ ] `plan` produces the same effective values as `create` for the same
      config, without side effects.
- [ ] `lint` flags the listed risky patterns with remediation.
- [ ] `$schema` autocompletes the documented keys in a supported editor.
- [ ] `extends` merges deterministically and rejects cycles.
- [ ] `init --from devcontainer.json` round-trips image, mounts and ports.
- [ ] Unsupported import fields are reported, not silently dropped.

## Tests

- Golden plan output for representative configs.
- Lint unit/golden cases for every rule.
- Schema/docs key parity test.
- `extends` merge and cycle tests.
- Devcontainer import fixture.

## Risks

- Schema/config drift; generate or test.
- `extends` can hide policy in a parent file; `plan` must show the resolved
  policy, not just the leaf.
- Import support can imply more fidelity than delivered; list unsupported
  fields explicitly.
