# Scaffold registry, signed assets and prebuilt images

| | |
| :--- | :--- |
| **Issue** | [#579](https://github.com/agentcage/agentcage/issues/579) |
| **Status** | Proposed |
| **Priority** | P2 |
| **Phase** | 5 |
| **Depends on** | [#578](https://github.com/agentcage/agentcage/issues/578) |
| **Related** | [#568](https://github.com/agentcage/agentcage/issues/568), [#580](https://github.com/agentcage/agentcage/issues/580) |

## Problem

Scaffolds are local directories or built-ins. Sharing one requires copying
files or committing them to a project. There is no versioned registry, no
signature/digest policy and no prebuilt image path, so every user builds the
same agent image on first run. Supply-chain pinning is inconsistent.

## Proposal

### Scaffold registry

```text
agentcage scaffold search QUERY
agentcage scaffold pull NAME[@VERSION]
agentcage scaffold publish ./my-scaffold
agentcage scaffold verify NAME
```

- Distribution as OCI artifacts (or a simple signed tarball) with an
  immutable version/digest.
- `pull` resolves to a digest and records it in the cage.
- `publish` is opt-in and requires a signing key.
- Local/project/user/built-in resolution order remains; a registry entry is
  explicit.

### Supply chain

- Pin scaffold base images by digest where upstream permits.
- Sign published scaffolds and policy bundles with Sigstore/cosign.
- Publish SBOMs for release binaries and prebuilt images.
- Verify signatures on pull unless `--allow-unsigned` is explicit.
- Treat scaffold `COPY` sources as build inputs; `plan` shows them.

### Prebuilt images and caches

- Publish digest-pinned scaffold images for common agents.
- `agentcage image pull/list` and `agentcage image build` where needed.
- Shared toolchain caches are opt-in and per-user; document cache poisoning
  risk.
- First-run should not require compiling the agent image.

## Acceptance criteria

- [ ] `scaffold pull` records and verifies a digest.
- [ ] An unsigned or wrong-signature scaffold is refused by default.
- [ ] A prebuilt image starts a cage without a local build.
- [ ] `plan` lists the resolved image digests and build inputs.
- [ ] SBOMs are published for release artifacts.
- [ ] Cache use is explicit and documented.

## Tests

- Registry resolution and digest tests with a local fixture.
- Signature verification negative tests.
- Prebuilt image e2e on supported backends.
- SBOM presence in release artifacts.

## Risks

- A registry is a new service and moderation burden; start with OCI artifacts
  and no hosted index if possible.
- Signing key management and trust roots need documentation.
- Prebuilt images can drift from local scaffolds; use the same content hash.
EOF