"""agentcage apple-container egress allowlist addon for mitmproxy.

The mitmproxy `--allow-hosts` flag controls *interception scope* (which
hosts get MITMed) but does NOT block non-listed hosts. It just passes
them through unintercepted, which is the opposite of what we want.

This addon enforces a real allowlist: every request's host is checked
against /etc/agentcage/allowlist.txt (one entry per line, subdomains
auto-allowed). Non-matching requests are replied to with a 403 from
mitmproxy itself — the upstream connection is never opened.

The allowlist file is read once at startup; restart the cage to pick up
changes. Empty allowlist means "block everything" — same default as the
supervisor's `--allow-hosts` regex fallback.
"""

from __future__ import annotations

from mitmproxy import ctx, http


ALLOWLIST_PATH = "/etc/agentcage/allowlist.txt"


def _load_allowlist() -> set[str]:
    try:
        with open(ALLOWLIST_PATH) as f:
            return {line.strip() for line in f if line.strip()}
    except OSError:
        return set()


def _host_allowed(host: str, allowed: set[str]) -> bool:
    """Subdomains of allowed hosts are also allowed (matches Lima behaviour).

    e.g. allowlist {"github.com"} accepts host "api.github.com" but not
    "evil-github.com" or "githubcom.example.com".
    """
    h = host.lower()
    for d in allowed:
        d = d.lower()
        if h == d or h.endswith("." + d):
            return True
    return False


class AllowlistAddon:
    def __init__(self) -> None:
        self.allowed = _load_allowlist()
        ctx.log.info(
            f"[agentcage] allowlist loaded: {sorted(self.allowed) or '(empty — block all)'}"
        )

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        if _host_allowed(host, self.allowed):
            return
        ctx.log.info(f"[agentcage] BLOCK {flow.request.method} {host}")
        flow.response = http.Response.make(
            403,
            (
                f"agentcage: host '{host}' is not on the cage allowlist.\n"
                "Add the domain to cage.yaml under `domains.allow` and "
                "rebuild the cage.\n"
            ).encode(),
            {"Content-Type": "text/plain"},
        )


addons = [AllowlistAddon()]
