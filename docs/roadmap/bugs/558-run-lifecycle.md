# `run` stops and keeps state, while the documentation says it removes it

| | |
| :--- | :--- |
| **Issue** | [#558](https://github.com/agentcage/agentcage/issues/558) |
| **Status** | Confirmed |
| **Priority** | P0 |
| **Area** | Session lifecycle / documentation |
| **Affected** | v0.53.1; behaviour predates the Rust port |
| **Fix** | [#564](https://github.com/agentcage/agentcage/issues/564) plus a docs correction |

## Summary

`agentcage run` stops the cage when the session exits, but keeps the
deployment directory, quadlets, named volumes and scoped secrets. The README,
quickstart, CLI reference and every scaffold README say the cage is torn down,
removed or destroyed on exit.

The code is explicit about this:

- `rust/agentcage-cli/src/run.rs:28-34` — the module documentation states that
  `run` “stops the cage on the way out — and only stops it”, and that
  `cage destroy` “is still the only thing that removes one”.
- `rust/agentcage-cli/src/cli/run.rs:468-471` — the teardown comment calls it
  “stopped, not destroyed” and lists what survives.

The documentation says the opposite in at least:

- `README.md` — “automatically torn down when the session exits” and “destroyed
  upon process exit”.
- `docs/get-started/quickstart.md` — “the ephemeral cage and network
  namespaces are automatically destroyed”.
- `docs/reference/cli.md` — “The cage and network are automatically destroyed
  upon process exit”.
- `src/agentcage/scaffolds/claude-code/README.md`,
  `src/agentcage/scaffolds/codex/README.md`,
  `src/agentcage/scaffolds/pi/README.md` — “the cage is removed on exit”.
- `docs/reference/configuration.md` — `lifecycle: ephemeral` is described as
  “destroyed upon process exit”.

## Expected vs actual

**Expected from the docs:** exiting the agent removes the cage, its network
and its scoped resources.

**Actual:** the cage is stopped. `agentcage cage list` shows it as stopped,
its named volumes remain, its encrypted secrets remain, and its network may
continue to occupy a `10.89.x.0/24` slot until `prune` or `destroy` is run.

## Impact

- Users accumulate stopped cages, subnets, volumes and encrypted credentials.
- Users may believe a secret was destroyed when only the container was
  stopped.
- `agentcage doctor` already warns about existing `10.89.x.0/24` subnets;
  the documented ephemeral model makes that warning surprising.
- The mismatch undermines trust in every other lifecycle message.

## Proposed fix

1. Decide the product semantics:
   - **Recommended:** keep the audit-preserving default, clearly say
     “stopped; state and audit kept”, and add `--rm` for true ephemeral
     sessions.
   - Alternative: make `run` destroy by default and require `--keep`.
2. Make the chosen semantics true in one place and print the kept inventory
   from both `run` and `destroy`/`prune`.
3. Update every documentation location listed above in the same release.
4. Add a docs conformance test for the “run lifecycle” promise.

## Acceptance criteria

- [ ] The default `run` exit message names the stopped cage, the data
      directory, the named volumes/secrets that were kept, and the exact
      removal command.
- [ ] `run --rm` leaves no deployment, network, named volume or scoped secret.
- [ ] Every documentation page that mentions `run` cleanup describes the same
      semantics.
- [ ] `lifecycle: ephemeral` is either removed as a distinct promise or given
      the same explicit keep/remove semantics.
- [ ] A test fails when the code and the docs disagree on this behaviour.

## Tests

- e2e: run a trivial scaffold, exit, assert `cage list` status and that the
  data directory exists.
- e2e: `run --rm`, exit, assert deployment and scoped secret are gone.
- docs: assert the four documentation locations contain the chosen wording;
  ideally generate the lifecycle sentence from one source.

## Related

- [#564](https://github.com/agentcage/agentcage/issues/564)
- [#559](https://github.com/agentcage/agentcage/issues/559)
