# FEAT-015: Packaging, platform support and release engineering

| | |
| :--- | :--- |
| **Status** | Proposed |
| **Priority** | P1 |
| **Phase** | 0/5 (parallel) |
| **Depends on** | #413, #414 |
| **Related** | [FEAT-016](FEAT-016-scaffold-registry-supply-chain.md), [FEAT-017](FEAT-017-docs-conformance-and-selftest.md) |

## Problem

The project is pre-1.0, effectively single-maintainer, and not available
through the package managers most users rely on. There is no notarized macOS
binary and no Windows/WSL story. The README still advertises an old install
path. Installation is a project of its own.

## Proposal

### Self-update

`agentcage update [VERSION]` with:

- latest release resolution and `--check`;
- sha256 verification;
- run-the-new-binary version check before replacing;
- atomic rename;
- refusal to overwrite Homebrew, system-package or cargo-build installs;
- print `cage update` hints for existing cages.

The draft in #556 is the starting point. Revisit the removal of the `update`
alias: deprecate first, remove later.

### Package managers

- Homebrew tap (#414).
- AUR `agentcage-bin` and source package.
- Generated formulas/packages from `scripts/gen-packaging.py`; pin version and
  checksums.
- Nix flake and devcontainer feature.
- `.deb`/`.rpm` if demand exists.

### macOS notarization

- Developer ID signing and notarization (#413), gated on the Apple account.
- Release workflow signs Linux and macOS artifacts, publishes SBOMs.
- A signed, notarized pre-release must open on a clean Mac with no Gatekeeper
  prompt.

### WSL2

- Detect WSL in `doctor` and setup.
- Document/install rootless Podman inside WSL2.
- Add a CI job for WSL2 if a hosted runner can support it; otherwise a
  documented manual acceptance check.
- Native Windows remains out of scope until the WSL2 path is solid.

### Release channels

- Stable and edge channels; security fixes get a stable patch release.
- `agentcage update --check` warns when a deployed cage's egress build is
  older than the host.
- Release checklist includes README/install-guide version updates,
  package-manager artifacts, docs and migration notes.

## Acceptance criteria

- [ ] A fresh VM on each supported platform installs from the documented
      method and passes `doctor`.
- [ ] `agentcage update --check` returns a meaningful exit code and never
      replaces a managed install.
- [ ] A deployed cage warns when its egress is older than the host.
- [ ] WSL2 is a documented, tested backend path.
- [ ] Stable/edge channel policy is written and linked from the README.
- [ ] README/install-guide versions match `VERSION`.

## Tests

- Fresh-VM install tests for Ubuntu, Arch, macOS and WSL2.
- Self-update unit tests with a local release mirror and checksum failures.
- Managed-install refusal tests.
- Signature/notarization verification on a clean Mac.

## Risks

- Apple enrollment is external and long-lead.
- Package-manager policies differ; self-update cannot be the only upgrade
  path.
- Windows native support is a separate project; do not let it block WSL2.
EOF