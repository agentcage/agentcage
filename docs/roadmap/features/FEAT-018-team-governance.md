# FEAT-018: Team governance, signed audit and policy bundles

| | |
| :--- | :--- |
| **Status** | Proposed |
| **Priority** | P2 |
| **Phase** | 5 |
| **Depends on** | [FEAT-013](FEAT-013-api-sdk-ci.md) |
| **Related** | [FEAT-009](FEAT-009-approvals-and-notifications.md), [FEAT-016](FEAT-016-scaffold-registry-supply-chain.md) |

## Problem

agentcage is currently a single-user local tool. Teams need shared policy,
tamper-evident audit and a way to ship an approved profile without asking every
developer to copy YAML. The audit log is structured JSONL but is not signed or
exportable to a SIEM.

## Proposal

### Signed audit

- Add a hash chain to `audit.jsonl` and optionally sign checkpoints with a
  per-install or per-team key.
- `agentcage audit verify NAME` checks the chain and signature.
- Export in JSONL, CEF/LEEF or OTLP with a documented schema.
- Redaction remains mandatory; signatures cover redacted records.

### Policy bundles

- Package a policy (domains, presets, inspectors, decider settings) as a
  signed, versioned bundle.
- `agentcage policy pull/verify/apply` or an `extends` source that records the
  digest.
- Team policy can be pinned in a project `cage.yaml`; the user can add local
  domains only through an explicit overlay.
- `plan` prints both the team policy digest and the local delta.

### Governance workflow

- Recommended policy profiles from an org repository.
- Approval/deny audit records include the approver identity when available.
- `agentcage audit export --since ...` for SIEM ingestion.
- Optional central policy sync is a separate, hosted feature; do not require
  it for local use.

## Implementation

- Hash chain: each record includes `prev_hash` and `hash`; define canonical
  serialization and test it.
- Signing: use Sigstore/cosign or a local Ed25519 key; document the trust root.
- Policy bundle: reuse the OCI/signing work from FEAT-016 where possible.
- Export: one adapter per format, with redaction before serialization.
- Do not put secrets or raw bodies in exported records.

## Acceptance criteria

- [ ] `audit verify` detects a modified or removed record.
- [ ] A signed bundle is refused when the signature or digest is wrong.
- [ ] `plan` shows team policy digest and local overlays.
- [ ] SIEM export is documented and contains no secret values.
- [ ] Existing local-only workflows do not require a server.

## Tests

- Hash-chain tamper tests.
- Signature verification negative tests.
- Policy bundle resolution/overlay tests.
- Export schema and redaction canaries.

## Risks

- Signing key management is a product decision; start with optional local keys.
- SIEM formats are easy to get subtly wrong; use a documented subset.
- Central policy can become a control plane; keep it opt-in and local-first.
EOF