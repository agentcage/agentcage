"""agentcage web interface — read-only operator dashboard.

Visibility into cages, secrets, the domain allowlist, and proxy traffic.
Every panel exposed here is also available from the CLI; the shared data
layer lives in :mod:`agentcage.web.providers`.
"""

__all__ = ["providers", "server"]
