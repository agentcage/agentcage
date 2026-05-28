<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Write a custom inspector

How to author, mount, and verify a custom request inspector. Read this when the built-in inspectors don't cover a check you need — for example, a domain-specific format your agent should never send.

## What you're building

A small inspector named `customer-id` that blocks any outbound request whose JSON body contains a key called `customer_id`. This is a stand-in for the real check you have in mind (a forbidden header, a specific field, a custom token shape); the lifecycle and wiring are identical.

By the end you'll have a Python file mounted into the proxy container, a `cage.yaml` entry that loads it, and an audit-log line proving it fired.

## Write the inspector

Save this as `~/agentcage/inspectors/customer_id.py` on the host:

```python
"""Block outbound requests that include a 'customer_id' key."""
from __future__ import annotations

import json

from inspectors.base import Inspector, InspectionContext, InspectionResult


class CustomerIdInspector(Inspector):
    name = "customer-id"

    def configure(self, config: dict) -> None:
        # Operators can rename the forbidden key from cage.yaml.
        self.forbidden_key = config.get("forbidden_key", "customer_id")

    def inspect_request(
        self, ctx: InspectionContext
    ) -> InspectionResult | None:
        # Abstain on anything that isn't JSON — let other inspectors handle it.
        if "application/json" not in ctx.content_type:
            return None
        if not ctx.body_text:
            return None
        try:
            payload = json.loads(ctx.body_text)
        except ValueError:
            return None
        if not isinstance(payload, dict) or self.forbidden_key not in payload:
            return None
        return InspectionResult(
            inspector=self.name,
            action="block",
            reason=f"body contains forbidden key: {self.forbidden_key!r}",
            severity="error",
            metadata={"host": ctx.host, "method": ctx.method},
        )
```

A few notes that match how the runtime actually loads inspectors:

- **Import path.** `from inspectors.base import ...` is the public API. The proxy puts `inspectors/` on `sys.path` before loading your file — that exact import works from a custom file, even though it isn't a real PyPI package.
- **Class name doesn't matter.** The loader picks the first `Inspector` subclass in the module. `name = "customer-id"` is what shows up in audit logs and in `cage audit --inspector …` filters.
- **Return `None` to abstain.** A `None` return means "this inspector has no opinion." The chain moves on. Only return an `InspectionResult` when you actually want to block or flag.
- **`severity` is independent of `action`.** A `flag` with `severity="critical"` still lets the request through but lights up the audit log. A `block` with `severity="info"` is unusual but valid.

## Mount it into the cage

Custom inspectors run inside the proxy container, not on the host. You need to get the file in there. Two options:

**Option A — bind-mount (recommended).** Add a `volumes:` entry to `cage.yaml` that maps your host path into the container's allowed inspector directory:

```yaml
container:
  volumes:
    - ~/agentcage/inspectors:/etc/agentcage/inspectors:ro
```

Use `:ro` so the proxy can read but not write. Keeping the file under `/etc/agentcage/inspectors` in the container satisfies the path allowlist (covered just under "Custom-inspector path restrictions").

**Option B — bake into a custom Containerfile.** If you ship your own proxy image, `COPY` the inspector into `/etc/agentcage/inspectors/` in `Containerfile.proxy`. This pins the inspector to a specific image version and is the right choice for immutable deployments.

For most cages the bind-mount is simpler — you edit the Python file and the next `cage update` picks it up.

## Configure it in `cage.yaml`

Add an entry under `inspectors:` referencing the in-container path and any config your `configure()` method reads:

```yaml
inspectors:
  - name: customer-id
    path: /etc/agentcage/inspectors/customer_id.py
    config:
      forbidden_key: customer_id
```

The `path:` is the path *inside the proxy container*. Order in the list is execution order — earlier inspectors see the request first, and your inspector sees their `prior_results` via `ctx.prior_results`. If you want the secret detector to run before yours, list `secrets` first.

## Apply and verify

Rebuild and reload the cage:

```bash
agentcage cage update myapp
```

Send a request from inside the cage that should trigger the block:

```bash
agentcage cage exec myapp -- curl -sS -X POST https://api.example.com/v1/foo \
  -H 'content-type: application/json' \
  -d '{"customer_id": "abc123"}'
```

You should see a 403 with a JSON body from the proxy. Now check the audit log:

```bash
agentcage cage audit myapp --since 1m --inspector customer-id
```

Look for a `"inspector": "customer-id"` entry with `"action": "block"` and your `reason`. If nothing shows up, jump to "Patterns and pitfalls".

Send a request that should *not* match (no JSON body, or no `customer_id` key) and confirm it passes. Abstaining when not applicable is what keeps the chain composable.

## Inspect responses too

Override `inspect_response(ctx)` to look at inbound responses with the same `InspectionContext` and `InspectionResult` types:

```python
def inspect_response(
    self, ctx: InspectionContext
) -> InspectionResult | None:
    if ctx.body_text and "INTERNAL-ONLY" in ctx.body_text:
        return InspectionResult(
            inspector=self.name,
            action="flag",
            reason="response contains internal marker",
        )
    return None
```

Response inspection runs *after* the upstream has already sent the response back. The right action for response-side checks is almost always `flag`, not `block` — see the pitfalls.

## Custom-inspector path restrictions

The proxy validates every `path:` against an allowed directory list before importing it. The default is `/etc/agentcage/inspectors/`. Files outside that directory raise `ImportError` at load time and the cage refuses to start, so a misconfigured `path:` is loud, not silent.

If you have a strong reason to mount inspectors elsewhere, set `AGENTCAGE_INSPECTOR_DIRS` in the proxy's environment to a colon-separated list of directories. Don't disable this check by widening the allowlist to `/`; the whole point is to prevent the cage from loading arbitrary Python from a writable bind mount.

## Patterns and pitfalls

- **Never block on `inspect_response`.** By the time the response inspector runs, the upstream has already received and processed the outbound request. A response-side `block` only suppresses the body the agent sees — the side effect at the upstream is already committed. Use `flag` for response-side checks, or move the check to `inspect_request`.
- **Abstain liberally.** Return `None` whenever the inspector has nothing to say. Returning a `flag` with empty reason on every request just adds noise to the audit log.
- **Prefer `body_bytes` to `body_text` for binary checks.** `ctx.body_text` is a best-effort UTF-8 decode and is `None` for non-text bodies. If you're matching on bytes (a magic header, a binary signature), use `ctx.body_bytes` directly and skip the decode.
- **`prior_results` is visible.** If your inspector depends on whether the `secrets` inspector already flagged the request, inspect `ctx.prior_results` for an entry with `inspector="secrets"`. List your inspector *after* the one you depend on.
- **Don't reach the network from inside an inspector.** Inspectors run synchronously in the proxy's request path. A blocking HTTP call to an external lookup service adds its latency to every request and can deadlock the chain. Pre-compute lookups in `configure()` and refresh them out of band.
- **Cage names must satisfy `^[a-z0-9][a-z0-9-]{0,62}$`.** Your inspector's `name` should follow the same convention so `cage audit --inspector …` filtering works cleanly.

## Related

- [Inspectors reference](../reference/inspectors.md) — full `InspectionContext` / `InspectionResult` field tables and the built-in inspector configs
- [Security model](../explain/security-model.md) — where custom inspectors sit in the defense layers
- [CLI reference](../reference/cli.md) — `cage update`, `cage exec`, `cage audit` flags
- [Configuration reference](../reference/configuration.md) — `inspectors:`, `volumes:`, and related `cage.yaml` keys
