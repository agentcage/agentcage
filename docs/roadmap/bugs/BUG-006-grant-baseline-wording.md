# BUG-006: the in-cage agent brief calls a runtime grant “baseline”

| | |
| :--- | :--- |
| **Status** | Confirmed |
| **Priority** | P2 |
| **Area** | Agent brief / policy documentation |
| **Affected** | v0.53.1 |
| **Fix** | Wording correction |

## Summary

`src/agentcage/scaffolds/AGENTS.md` tells the agent:

> A granted domain is promoted into the baseline and becomes reachable within
> about a second.

A Policy API grant is a runtime grant. It is stored in the grants overlay and
is not the operator’s static `domains.allow` baseline. The Policy API
reference is explicit that `baseline` and `granted` are different lists, and
that only the operator can change the baseline.

## Impact

An agent may reason incorrectly about whether it has permanent access, whether
it should clean up a grant, or whether another process will still have access
after the grant expires. This is a documentation defect, but the audience is
an autonomous agent, so precision matters.

## Proposed fix

Replace the sentence with:

> A granted domain becomes reachable at runtime for the grant’s lifetime. It
> appears under `granted`, not under `baseline`; use the removal endpoint when
> you no longer need it.

Add the same distinction to any scaffold copy of the brief.

## Acceptance criteria

- [ ] No live agent brief says a runtime grant changes the baseline.
- [ ] The brief links (or refers) to the Policy API reference for the
      `baseline` / `granted` distinction.
- [ ] A docs test searches for the incorrect phrase.

## Related

- [FEAT-004](../features/FEAT-004-policy-presets-and-suggestions.md)
