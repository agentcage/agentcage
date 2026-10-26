# Docs conformance and the security self-test

| | |
| :--- | :--- |
| **Issue** | [#580](https://github.com/agentcage/agentcage/issues/580) |
| **Status** | Proposed |
| **Priority** | P0/P1 |
| **Phase** | 0/4 |
| **Depends on** | The phase-0 bug fixes |
| **Related** | [#560](https://github.com/agentcage/agentcage/issues/560), [#561](https://github.com/agentcage/agentcage/issues/561), [#562](https://github.com/agentcage/agentcage/issues/562) |

## Problem

Documentation is extensive but no longer a reliable contract. The README pins
an old version, scaffold READMEs name a service the CLI rejects, `cage show`
overpromises, and the `run` lifecycle is described incorrectly. There is no
test that fails when a documented promise becomes false.

The project also has a strong redteam harness but no safe, shipped way for a
user to verify that a fresh install actually enforces its boundaries.

## Proposal

### Docs conformance

`cargo xtask check-docs` with a narrow, high-value scope:

- Extract fenced `agentcage ...` commands and verify the command/option exists.
- Extract documented `--service` values and compare with the CLI’s allowed set.
- Compare `cargo install ... --tag vX.Y.Z` with `VERSION`.
- Check that every documented `cage.yaml` key appears in the schema/reference.
- Exempt `docs/history/`, `docs/roadmap/` and `CHANGELOG.md`. History pages
  describe retired commands and roadmap pages deliberately show the proposed
  interface before it exists (for example `cage prune --older-than 7d
  --dry-run` on the [#564](https://github.com/agentcage/agentcage/issues/564)
  page), so a fenced example there is not a promise. Everything under
  `docs/get-started/`, `docs/explain/`, `docs/reference/`, `docs/how-to/` and
  the top-level `README.md` is checked.
- Assert the known behavioural promises have semantic tests:
  - what `run` keeps/removes;
  - auth strategies available to a scaffold;
  - `cage show` fields;
  - `-s dns` absence;
  - `run` help’s secrets text.
- Do not pin human prose; pin commands, options, versions and a small set of
  semantic facts.

### Behaviour tests

For each scaffold promise, add a test that would fail if the promise became
false:

- auth path matrix (API key, OAuth, import, login, none);
- cleanup semantics;
- service names in `logs`;
- generated config contains the documented rules.

### `agentcage selftest`

A non-destructive, canary-only security check suitable for CI and fresh
installs:

- non-allowlisted HTTP request is blocked with a policy error;
- DNS sinkhole returns the expected TEST-NET address;
- a canary secret is not readable in the cage and is redacted from responses;
- a DNS-rebinding/private-address target is refused;
- a workspace pivot mask is present;
- the egress reports its expected version.

Each probe prints `pass/fail/skip` with a reason; `--format json` is
machine-readable. It must never send real data, scan third parties or use
destructive payloads. A failing probe exits non-zero.

### Release checklist

- Docs, changelog and migration notes updated.
- Version references updated.
- Package-manager artifacts built.
- Selftest run on a fresh supported host.
- Security-relevant egress changes called out in the release notes.

## Implementation

- Build `check-docs` in `xtask`; use the clap command tree rather than a
  second hand-written list.
- Skip `docs/history/`, `docs/roadmap/` and `CHANGELOG.md` in the extractor,
  and say so in the check’s own help so the exemption is visible rather than
  accidental.
- Start with a small allowlist of documented examples; expand as drift is
  cleaned up.
- Base `selftest` on the redteam harness, but audit the probes and replace
  anything stateful with a canary.
- `selftest` uses the e2e mock services where possible; it should not depend
  on the public internet.
- The docs check should run in CI on every PR; the selftest runs on release and
  optionally in the e2e job.

## Acceptance criteria

- [ ] CI fails when a documented command/option or pinned version is wrong.
- [ ] The known drift items are fixed and covered.
- [ ] `agentcage selftest` passes on a fresh supported host.
- [ ] Deliberately breaking an egress rule makes the relevant probe fail.
- [ ] `selftest --format json` is usable by CI.
- [ ] Release checklist includes the selftest and package-manager artifacts.

## Tests

- `xtask` unit tests for the docs parser.
- Deliberate-drift tests for each semantic promise.
- Selftest pass/fail/skip fixture.
- Fresh-host manual acceptance for each release.

## Risks

- Docs checks can become brittle; keep the scope narrow and semantic.
- Selftest can give false confidence; document what it does not cover.
- Redteam probes may be unsafe to ship; canary-only is a hard requirement.
