"""Secret injection — swap placeholders for real values on outbound requests,
redact real values back to placeholders on inbound responses.

This runs *before* inspectors on requests and *after* inspectors on responses,
modifying the flow in-place.  It is deliberately separate from the read-only
inspector chain.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import quote

from mitmproxy import http

from inspectors.base import InspectionResult
from secret_lookup import read_secret

log = logging.getLogger("agentcage.secret_injector")

# Values resolve through the egress's one secret lookup
# (``secret_lookup.read_secret``, shared with the Policy API, the watcher and
# the relays): the staged file ``$AGENTCAGE_SECRETS_DIR/<NAME>`` (default
# /home/acproxy/secrets) → env. The container/podman backend delivers
# secrets as env (Quadlet `Secret=type=env,target=KEY`) AND stages the file;
# the apple-container backend can't do env — apple's `container` CLI has no
# quadlet-style env-secret primitive and we deliberately don't pass
# cleartext via `-e KEY=VAL` (would show in `container inspect` and process
# listings) — so there the staged file is the only channel. The dir is read
# on every configure() (each live-apply reload), not frozen at import.

# Strict (default) injection confines secret substitution to the "auth
# channel": a placeholder is swapped for its real value only when it appears
# in a *credential-bearing request header*, never in the URL/query string,
# the request body, or a WebSocket frame (those keep the placeholder unless
# the rule sets ``inject_body: true``). Keeping secrets out of bodies is the
# PR #251 goal — bodies get logged and echoed downstream; the auth header
# does not.
#
# Rather than enumerate specific vendor header names, we recognize a header
# as credential-bearing when its name contains one of these keyword stems
# (case-insensitive substring match). Almost every API's auth header does:
#   authorization, x-api-key, api-key, apikey, x-goog-api-key, private-token,
#   x-auth-token, x-auth-key, x-subscription-token, ocp-apim-subscription-key,
#   dd-api-key, circle-token, x-algolia-api-key, fastly-key, x-figma-token,
#   x-postmark-server-token, x-shopify-access-token, … all match.
# (Surveyed against ~70 popular APIs; the only credential header found that
# lacks any of these stems is Honeycomb's ``x-honeycomb-team`` — add headers
# like that per-rule via ``inject_headers``.)
#
# This is safe because the match only ever has an effect when a rule's unique
# ``{{PLACEHOLDER}}`` literally appears in the header — the cage only puts the
# placeholder where its HTTP client sends the credential — so a broad match
# can't inject a secret somewhere the agent didn't already place it. APIs that
# carry the key in the URL query string (Google ``?key=``, SerpAPI
# ``?api_key=``, Firebase ``?auth=``) or the request body (Plaid) are outside
# the header channel and need ``inject_body: true``.
AUTH_HEADER_KEYWORDS: tuple[str, ...] = ("auth", "key", "token")


def _rewrite_basic_auth(value: str, find: str, replace: str) -> tuple[str, bool]:
    """Rewrite ``find`` → ``replace`` inside an HTTP **Basic** credential.

    A literal substring match can't reach a placeholder (or a real secret)
    carried in ``Authorization: Basic base64("user:<secret>")`` — git over
    HTTPS sends exactly this, base64-encoding the token so it never appears
    verbatim in the header value. (The ``Bearer``/``token`` channel used by
    REST clients carries the credential in cleartext, which the literal match
    already handles.)

    Decode the base64, substitute in the decoded ``user:pass`` text, and
    re-encode. Returns ``(new_value, changed)``; ``(value, False)`` when the
    header isn't Basic, isn't decodable base64/UTF-8, or doesn't contain
    ``find`` — so the caller's literal path stays authoritative for every
    other case.
    """
    parts = value.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "basic":
        return value, False
    try:
        decoded = base64.b64decode(parts[1].strip(), validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return value, False
    if find not in decoded:
        return value, False
    new_b64 = base64.b64encode(
        decoded.replace(find, replace).encode("utf-8")
    ).decode("ascii")
    return f"{parts[0]} {new_b64}", True


# ── Encoded forms of a secret ───────────────────────────
#
# A secret reaches a sink in other spellings than its literal bytes, each
# produced by an ordinary encoder: a server echoing a URL it was sent (an
# error body, a ``Location`` header) percent-encodes it; a JSON encoder
# escapes ``/`` (PHP), ``&`` ``<`` ``>`` (Go), non-ASCII (Python); an echo
# service returns the request's ``Authorization: Basic`` header in its
# body. A cage that holds a real value can spell it the same ways to slip
# it past the literal policy check. Redaction and that check therefore
# match, besides the literal, a bounded set of derived forms
# (``_SecretForms``):
#
# - escaped: every character of the value either literal or as one of its
#   escapes: ``%XX`` per UTF-8 byte (either hex case), ``+`` for a space
#   (query and form encoding), a JSON ``\uXXXX`` (either hex case, a
#   surrogate pair past the BMP) or JSON short escape (``\/``, ``\"``,
#   ``\\``, ``\n`` …). Encoders differ in which characters they leave
#   alone (Python's ``quote`` keeps ``/``, ``encodeURIComponent`` keeps
#   ``!~*'()``), so each character may be spelled either way
#   independently; letters, digits and ``-._``, which no common encoder
#   escapes, only literally. That leaves out spellings nothing produces
#   by accident (``%61`` for ``a``) and makes the value's longest run of
#   such characters an anchor every match contains, so the pattern only
#   runs on content holding it. A secret made only of those characters
#   has no escaped form beyond its literal.
# - base64: the value at any byte offset of a standard or URL-safe base64
#   blob, padded or not. Each of the three alignments gives a fixed run of
#   base64 characters (its "core") that any such blob contains; where one
#   appears, the enclosing blob is decoded, the value replaced by the
#   placeholder and the blob re-encoded the same way. Only for a value of
#   at least ``_B64_MIN_BYTES`` bytes, so a core is long enough to be
#   searched for. ``Authorization: Basic`` is also still decoded whole
#   (``_rewrite_basic_auth``), for shorter values.
#
# The placeholder takes the escaped form's encoding, so the surrounding
# syntax stays valid: percent-encoded (same hex case) where the match used
# a ``%XX`` escape or ``+`` for a space, JSON-escaped where it used a
# backslash escape, literal otherwise. Double encodings (``%252B``, a
# percent-encoded JSON escape), HTML entities, other charsets and base64
# of an already escaped value are not matched.

# Characters no common encoder escapes (RFC 3986 unreserved minus ``~``,
# which WHATWG form encoding and Java's URLEncoder do escape).
_UNESCAPED = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._"
)

_JSON_SHORT_ESCAPES: dict[str, bytes] = {
    '"': b'\\"', "\\": b"\\\\", "/": b"\\/", "\b": b"\\b",
    "\f": b"\\f", "\n": b"\\n", "\r": b"\\r", "\t": b"\\t",
}

# Shortest value whose base64 forms are matched: its cores are at least
# 10 characters, too long to turn up by chance.
_B64_MIN_BYTES = 8
_B64_STD_CHARS = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)
_B64_URL_CHARS = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_URL_TO_STD = bytes.maketrans(b"-_", b"+/")
_STD_TO_URL = bytes.maketrans(b"+/", b"-_")

_PERCENT_ESCAPE = re.compile(rb"%[0-9A-Fa-f]{2}")
_LOWER_HEX_ESCAPE = re.compile(rb"%(?:[a-f][0-9a-fA-F]|[0-9A-F][a-f])")


def _hex_class(number: int, width: int) -> bytes:
    """Regex for *number* in *width* hex digits, either case."""
    out = []
    for digit in f"{number:0{width}X}":
        if digit.isalpha():
            out.append(f"[{digit}{digit.lower()}]".encode())
        else:
            out.append(digit.encode())
    return b"".join(out)


def _char_pattern(ch: str) -> tuple[bytes, bool]:
    """Regex for one character of a secret, every way it may be spelled,
    and whether it has a spelling besides the literal."""
    raw = ch.encode("utf-8", "surrogatepass")
    if len(raw) == 1 and raw[0] in _UNESCAPED:
        return re.escape(raw), False
    alts = [re.escape(raw), b"".join(b"%" + _hex_class(b, 2) for b in raw)]
    if ch == " ":
        alts.append(rb"\+")
    cp = ord(ch)
    units = (
        (0xD800 + ((cp - 0x10000) >> 10), 0xDC00 + ((cp - 0x10000) & 0x3FF))
        if cp > 0xFFFF else (cp,)
    )
    alts.append(b"".join(rb"\\u" + _hex_class(u, 4) for u in units))
    if ch in _JSON_SHORT_ESCAPES:
        alts.append(re.escape(_JSON_SHORT_ESCAPES[ch]))
    return b"(?:" + b"|".join(alts) + b")", True


def _base64_cores(raw: bytes) -> list[bytes]:
    """The base64 characters fixed by *raw* alone at each of the three
    byte alignments, in the standard and the URL-safe alphabet."""
    cores: list[bytes] = []
    for shift in range(3):
        enc = base64.b64encode(b"\0" * shift + raw)
        start = -(-8 * shift // 6)
        end = 8 * (shift + len(raw)) // 6
        core = enc[start:end]
        for c in (core, core.translate(_STD_TO_URL)):
            if c not in cores:
                cores.append(c)
    return cores


def _replace_in_base64(
    blob: bytes, raw: bytes, ph_raw: bytes, urlsafe: bool, padded: bool,
) -> Optional[bytes]:
    """*blob* (base64 characters, no padding) re-encoded with *raw* in its
    decoded bytes replaced by *ph_raw*; None when it does not decode to
    bytes holding *raw*. Up to three leading characters that are not part
    of the blob are tolerated (kept as they are)."""
    for off in range(4):
        body = blob[off:]
        tail = b""
        if len(body) % 4 == 1:
            body, tail = body[:-1], body[-1:]
        std = body.translate(_URL_TO_STD) if urlsafe else body
        try:
            decoded = base64.b64decode(std + b"=" * (-len(std) % 4),
                                       validate=True)
        except (binascii.Error, ValueError):
            continue
        if raw not in decoded:
            continue
        enc = base64.b64encode(decoded.replace(raw, ph_raw))
        if urlsafe:
            enc = enc.translate(_STD_TO_URL)
        if not padded:
            enc = enc.rstrip(b"=")
        return blob[:off] + enc + tail
    return None


def _rewrite_base64(
    data: bytes, core: bytes, raw: bytes, ph_raw: bytes,
) -> tuple[bytes, int]:
    """*data* with every base64 blob that contains *core* and decodes to
    bytes holding *raw* re-encoded with *ph_raw* in its place. Returns
    ``(data, count)``."""
    count = 0
    pos = 0
    while True:
        i = data.find(core, pos)
        if i < 0:
            return data, count
        pos = i + 1
        for chars, urlsafe in ((_B64_STD_CHARS, False), (_B64_URL_CHARS, True)):
            start = i
            while start > 0 and data[start - 1] in chars:
                start -= 1
            end = i + len(core)
            while end < len(data) and data[end] in chars:
                end += 1
            pad_end = end
            while (pad_end < len(data) and pad_end - end < 2
                   and data[pad_end] == 0x3D):  # "="
                pad_end += 1
            # Re-encoded padded if the blob was, and when it needed no
            # padding (a multiple of four characters): standard base64 is
            # padded (``Authorization: Basic``), URL-safe usually not (JWT).
            padded = pad_end > end or (
                not urlsafe and (end - start) % 4 == 0
            )
            new = _replace_in_base64(
                data[start:end], raw, ph_raw, urlsafe, padded,
            )
            if new is not None:
                data = data[:start] + new + data[pad_end:]
                pos = start + len(new)
                count += 1
                break


class _SecretForms:
    """One secret value with what matching its derived forms needs,
    built once per value (``SecretInjector._forms_for``).

    ``redact`` / ``redact_text`` swap the literal and every derived form
    for the placeholder; ``occurs`` / ``occurs_text`` say whether any is
    present. See the comment above for the forms.
    """

    __slots__ = ("value", "placeholder", "name", "raw", "ph_raw",
                 "pattern", "anchor", "b64_cores", "_ph_percent",
                 "_ph_json")

    def __init__(self, value: str, placeholder: str, name: str) -> None:
        self.value = value
        self.placeholder = placeholder
        self.name = name
        self.raw = value.encode("utf-8", "surrogatepass")
        self.ph_raw = placeholder.encode("utf-8", "surrogatepass")
        parts = [_char_pattern(ch) for ch in value]
        self.pattern: Optional[re.Pattern[bytes]] = None
        self.anchor: Optional[bytes] = None
        if any(escapable for _, escapable in parts):
            self.pattern = re.compile(b"".join(p for p, _ in parts))
            runs = re.findall(rb"[A-Za-z0-9._-]+", self.raw)
            self.anchor = max(runs, key=len) if runs else None
        self.b64_cores: list[bytes] = (
            _base64_cores(self.raw) if len(self.raw) >= _B64_MIN_BYTES else []
        )
        self._ph_percent = quote(placeholder, safe="").encode("ascii")
        self._ph_json = json.dumps(placeholder)[1:-1].encode("ascii")

    def _placeholder_for(self, match: re.Match[bytes]) -> bytes:
        """The placeholder in the encoding of an escaped form *match*."""
        m = match.group(0)
        plus_for_space = (
            b" " in self.raw and b" " not in m and b"%20" not in m.upper()
            and b"\\u0020" not in m.lower()
        )
        if _PERCENT_ESCAPE.search(m) or plus_for_space:
            if _LOWER_HEX_ESCAPE.search(m):
                return _PERCENT_ESCAPE.sub(
                    lambda e: e.group(0).lower(), self._ph_percent)
            return self._ph_percent
        if b"\\" in m:
            return self._ph_json
        return self.ph_raw

    @property
    def _has_derived(self) -> bool:
        return self.pattern is not None or bool(self.b64_cores)

    def _redact_derived(self, data: bytes) -> tuple[bytes, bool]:
        found = False
        if self.pattern is not None and (
            self.anchor is None or self.anchor in data
        ):
            data, n = self.pattern.subn(self._placeholder_for, data)
            found = n > 0
        for core in self.b64_cores:
            if core in data:
                data, n = _rewrite_base64(data, core, self.raw, self.ph_raw)
                found = found or n > 0
        return data, found

    def redact(self, data: bytes) -> tuple[bytes, bool]:
        """*data* with the literal and every derived form replaced;
        whether anything was."""
        found = False
        if self.raw in data:
            data = data.replace(self.raw, self.ph_raw)
            found = True
        if self._has_derived:
            data, derived = self._redact_derived(data)
            found = found or derived
        return data, found

    def redact_text(self, text: str) -> tuple[str, bool]:
        """``redact`` for a string; *text* itself when nothing matched."""
        found = False
        if self.value in text:
            text = text.replace(self.value, self.placeholder)
            found = True
        if self._has_derived:
            data, derived = self._redact_derived(
                text.encode("utf-8", "surrogatepass"))
            if derived:
                text = data.decode("utf-8", "surrogatepass")
                found = True
        return text, found

    def occurs(self, data: bytes) -> bool:
        """Whether *data* holds the literal or a derived form."""
        if self.raw in data:
            return True
        return self._has_derived and self._redact_derived(data)[1]

    def occurs_text(self, text: str) -> bool:
        """``occurs`` for a string."""
        if self.value in text:
            return True
        return self._has_derived and self._redact_derived(
            text.encode("utf-8", "surrogatepass"))[1]


@dataclass
class InjectionRule:
    name: str  # e.g. "ANTHROPIC_API_KEY"
    placeholder: str  # e.g. "{{ANTHROPIC_API_KEY}}"
    real_value: str  # resolved via secret_lookup at configure()
    inject_to: list[str] = field(default_factory=list)  # domain restrictions
    # When set, ``transform_fn`` is called at substitution time to
    # produce a derived value (e.g. a freshly minted access token) in
    # place of ``real_value``. ``real_value`` still holds the underlying
    # high-privilege credential so the literal-match defense-in-depth
    # block can detect raw key bytes leaking into outbound traffic.
    transform: str = ""
    transform_fn: Optional[Callable[[], str]] = None
    # Every value the transform produced that may still be in use (its
    # ``active_values``). Those are secrets too: redaction swaps them back
    # to ``placeholder`` like ``real_value``, and the policy check blocks
    # them heading outside ``inject_to`` (see ``minted_values``).
    transform_values_fn: Optional[Callable[[], list[str]]] = None
    # The transform object, so a reload can keep it for an unchanged rule
    # and keep redacting a replaced one's live tokens.
    transform_instance: Any = field(default=None, repr=False, compare=False)
    # Strict by default: only inject into credential-bearing headers — those
    # whose name matches the ``AUTH_HEADER_KEYWORDS`` heuristic or is listed in
    # ``inject_headers``. When True, also inject into the request URL, every
    # header, the body, and WebSocket frames (the legacy, looser behavior).
    inject_body: bool = False
    # Extra request headers this rule treats as credential-bearing under the
    # strict default — for auth headers whose name doesn't match the keyword
    # heuristic (e.g. ``x-honeycomb-team``). Matched case-insensitively.
    inject_headers: list[str] = field(default_factory=list)
    # Fallback tracking for a transform without ``active_values``: the
    # last two values ``derive_value`` returned (current and previous).
    _recent: list[str] = field(default_factory=list, repr=False, compare=False)

    def is_auth_header(self, name: str) -> bool:
        """Whether ``name`` is a credential-bearing header this rule injects
        into under the strict default. True when the (case-insensitive) header
        name contains one of ``AUTH_HEADER_KEYWORDS`` or exactly matches an
        ``inject_headers`` entry."""
        n = name.lower()
        if any(kw in n for kw in AUTH_HEADER_KEYWORDS):
            return True
        return any(n == extra.lower() for extra in self.inject_headers)

    def derive_value(self) -> str:
        """Call the transform for the value to put on the wire.

        A transform without ``active_values`` has its last two values
        remembered here instead, so they are still redacted.
        """
        assert self.transform_fn is not None
        value = self.transform_fn()
        if self.transform_values_fn is None and (
            not self._recent or self._recent[0] != value
        ):
            self._recent = [value, *self._recent[:1]]
        return value

    def minted_values(self) -> list[str]:
        """Values the transform produced that may still be on the wire.

        Empty for a rule without a transform. A transform that fails to
        list them yields none rather than breaking the flow.
        """
        if self.transform_fn is None:
            return []
        if self.transform_values_fn is None:
            values = list(self._recent)
        else:
            try:
                values = list(self.transform_values_fn())
            except Exception as e:
                log.error(
                    "secret_injection: transform %s (%s) could not list "
                    "its minted values: %s", self.transform, self.name, e,
                )
                values = []
        return [v for v in values if v and v != self.real_value]


class SecretInjector:
    """Transparent secret injection / redaction for mitmproxy flows."""

    def __init__(self) -> None:
        self.rules: list[InjectionRule] = []
        self.redact_to: list[str] = []
        # Live transform objects by (env, transform, config, secret): an
        # unchanged rule keeps its transform across a reload, with its
        # cached token, its mint rate bucket and the tokens it minted.
        self._transforms: dict[tuple[str, str, str, str], Any] = {}
        # Rules dropped or replaced by a reload whose transform minted a
        # token that is still valid. The token may be on a flow still in
        # flight, or echoed back later, so it stays a secret (redacted and
        # policy-checked) until it expires; then the rule is forgotten.
        self._retired: list[InjectionRule] = []
        # The derived forms of each secret value (``_SecretForms``), by
        # (value, placeholder, name): built when a rule is configured or
        # a minted token is first redacted, dropped once the value is no
        # longer a secret (``_redaction_forms``).
        self._forms: dict[tuple[str, str, str], _SecretForms] = {}

    def configure(self, config: list[dict] | dict) -> None:
        """Build injection rules from the ``secret_injection`` config.

        Accepts either a plain list of rules (backwards compat) or a dict
        with ``rules`` and optional ``redact_to`` keys.

        Each rule entry has keys: ``env``, ``placeholder``, and optionally
        ``inject_to`` (list of domains).
        """
        if isinstance(config, dict):
            rules_list = config.get("rules", [])
            self.redact_to = [d.lower() for d in config.get("redact_to", [])]
        else:
            rules_list = config
            self.redact_to = []

        previous = self.rules + self._retired
        old_transforms = self._transforms
        self._transforms = {}
        self.rules = []
        for entry in rules_list:
            env_name = entry.get("env", "")
            placeholder = entry.get("placeholder", "")
            if not placeholder:
                # A rule whose placeholder was never generated (the CLI
                # fills omitted placeholders at declare time). An empty
                # placeholder must never reach matching: `"" in text` is
                # always True and `text.replace("", v)` corrupts content.
                log.warning(
                    "secret_injection: rule %s has no placeholder, "
                    "skipping", env_name,
                )
                continue
            inject_to = [d.lower() for d in entry.get("inject_to", [])]

            # Value resolution — secret_lookup.read_secret.
            #
            # The staged file (re-written live by `agentcage secret set`)
            # is authoritative WHEN it exists: the process env is frozen at
            # container creation, so only the file can carry a value change
            # without a container restart. An EXISTING-but-EMPTY file is a
            # tombstone (`secret rm` / failed staging of a deleted store
            # entry): the rule is skipped rather than falling back to a
            # stale env value. Only a MISSING file falls back to the env
            # channel (pre-staging cages, podman < 4.7 where --showsecret is
            # unavailable).
            real_value = read_secret(env_name)
            if not real_value:
                log.warning(
                    "secret_injection: no value for %s (unset, or staged "
                    "file empty/unreadable), skipping rule", env_name,
                )
                continue

            inject_body = bool(entry.get("inject_body", False))
            inject_headers = [
                str(h).strip() for h in (entry.get("inject_headers") or [])
            ]

            transform_name = entry.get("transform", "") or ""
            transform_fn: Optional[Callable[[], str]] = None
            values_fn: Optional[Callable[[], list[str]]] = None
            instance: Any = None
            if transform_name:
                transform_config = entry.get("transform_config") or {}
                key = (
                    env_name,
                    transform_name,
                    json.dumps(transform_config, sort_keys=True, default=str),
                    real_value,
                )
                instance = self._transforms.get(key)
                if instance is None:
                    instance = old_transforms.pop(key, None)
                if instance is None:
                    try:
                        instance = self._build_transform(
                            transform_name, real_value, transform_config
                        )
                    except Exception as e:
                        log.error(
                            "secret_injection: transform %s for %s failed to "
                            "initialize: %s — skipping rule",
                            transform_name, env_name, e,
                        )
                        continue
                self._transforms[key] = instance
                transform_fn = instance.get_value
                values_fn = getattr(instance, "active_values", None)

            self.rules.append(
                InjectionRule(
                    name=env_name,
                    placeholder=placeholder,
                    real_value=real_value,
                    inject_to=inject_to,
                    transform=transform_name,
                    transform_fn=transform_fn,
                    transform_values_fn=values_fn,
                    transform_instance=instance,
                    inject_body=inject_body,
                    inject_headers=inject_headers,
                )
            )

        # A rule whose transform was not kept (rule removed, secret
        # re-staged, config changed) retires while a token it minted is
        # still valid.
        live = {id(r.transform_instance) for r in self.rules}
        self._retired = [
            r for r in previous
            if r.transform_instance is not None
            and id(r.transform_instance) not in live
            and r.minted_values()
        ]
        # Build each value's derived forms now rather than on the first
        # flow (and drop those of values no longer configured).
        self._redaction_forms()

    @staticmethod
    def _build_transform(name: str, secret: str, config: dict[str, Any]) -> Any:
        """Look up a transform class and return an instance of it."""
        # Lazy import — keeps mitmproxy's addon load fast and avoids
        # pulling cryptography unless a transform actually uses it.
        from transforms import get as _get

        cls = _get(name)
        return cls(secret, config)

    def _live_retired(self) -> list[InjectionRule]:
        """Retired rules that still have a valid minted token; the rest
        are forgotten here."""
        if self._retired:
            self._retired = [r for r in self._retired if r.minted_values()]
        return self._retired

    def _minted(self) -> list[tuple[InjectionRule, str]]:
        """``(rule, token)`` for every valid token a transform minted,
        live rules first, then retired ones."""
        return [
            (rule, value)
            for rule in (*self.rules, *self._live_retired())
            for value in rule.minted_values()
        ]

    def _redaction_targets(self) -> list[tuple[str, str, str]]:
        """``(value, placeholder, name)`` for every value redaction swaps
        back to a placeholder: each rule's real value and each token its
        transform minted (also a retired rule's, until it expires).

        Longest value first, so a value that is a substring of another
        never splits it.
        """
        targets: list[tuple[str, str, str]] = []
        seen: set[str] = set()
        for rule in self.rules:
            if rule.real_value and rule.real_value not in seen:
                seen.add(rule.real_value)
                targets.append((rule.real_value, rule.placeholder, rule.name))
        for rule, value in self._minted():
            if value not in seen:
                seen.add(value)
                targets.append((value, rule.placeholder, rule.name))
        targets.sort(key=lambda t: len(t[0]), reverse=True)
        return targets

    def _forms_for(self, value: str, placeholder: str,
                   name: str) -> _SecretForms:
        """The cached ``_SecretForms`` of one secret value."""
        key = (value, placeholder, name)
        forms = self._forms.get(key)
        if forms is None:
            forms = self._forms[key] = _SecretForms(value, placeholder, name)
        return forms

    def _redaction_forms(self) -> list[_SecretForms]:
        """``_SecretForms`` of every value ``_redaction_targets`` lists, in
        its order (longest value first). Forms of values that are no longer
        secrets (an expired token, a removed rule) are dropped."""
        forms = [self._forms_for(value, ph, name)
                 for value, ph, name in self._redaction_targets()]
        self._forms = {(f.value, f.placeholder, f.name): f for f in forms}
        return forms

    @staticmethod
    def _minted_token_block(rule: InjectionRule, where: str) -> InspectionResult:
        return InspectionResult(
            inspector="secret-injector",
            action="block",
            reason=(
                f"literal secret value {rule.name} (a token its "
                f"{rule.transform} transform minted) found in {where}"
            ),
            severity="critical",
        )

    @staticmethod
    def _find_value(flow: http.HTTPFlow, forms: _SecretForms) -> bool:
        """Check if a secret value is present in the request: literally,
        in a derived form (percent-encoded, JSON-escaped, base64) or
        inside an ``Authorization: Basic`` credential."""
        if forms.occurs_text(flow.request.url):
            return True
        for v in flow.request.headers.values():
            if forms.occurs_text(v):
                return True
            if _rewrite_basic_auth(v, forms.value, forms.value)[1]:
                return True
        if flow.request.content and forms.occurs(flow.request.content):
            return True
        return False

    def _find_placeholder(self, flow: http.HTTPFlow, rule: InjectionRule) -> bool:
        """Check if a rule's placeholder is present in the flow.

        Also detects a placeholder carried base64-encoded inside an
        ``Authorization: Basic`` header (git over HTTPS) — otherwise the
        per-rule gate in ``inject_request`` would skip the rule before the
        Basic-aware header substitution ever runs.
        """
        ph = rule.placeholder
        if ph in flow.request.url:
            return True
        for v in flow.request.headers.values():
            if ph in v or _rewrite_basic_auth(v, ph, ph)[1]:
                return True
        if flow.request.content and ph.encode() in flow.request.content:
            return True
        return False

    def check_injection_policy(
        self, flow: http.HTTPFlow
    ) -> Optional[InspectionResult]:
        """Check domain restrictions without modifying the flow.

        Returns an ``InspectionResult`` (flag) if a placeholder is found
        heading to an unauthorized domain, (block) if a literal secret
        value is, in any of its derived forms (``_SecretForms``).
        Returns ``None`` if ok.
        """
        if not self.rules and not self._retired:
            return None

        host = flow.request.host.lower()

        if self.redact_to and self._domain_matches(host, self.redact_to):
            return None

        # Block literal real values heading to unauthorized domains.
        # If the host is in the rule's inject_to list the value will
        # legitimately appear after injection, so we allow it — UNLESS
        # the rule has a transform, in which case the cage agent should
        # never have produced the raw secret bytes in the first place
        # (the proxy mints derived values; the raw credential never
        # legitimately appears on the wire to anywhere).
        # A derived form (percent-encoded, JSON-escaped, base64) counts
        # as the value: spelling it differently must not get it past.
        for rule in self.rules:
            forms = self._forms_for(rule.real_value, rule.placeholder,
                                    rule.name)
            if self._find_value(flow, forms):
                if (
                    not rule.transform_fn
                    and rule.inject_to
                    and self._domain_matches(host, rule.inject_to)
                ):
                    continue
                return InspectionResult(
                    inspector="secret-injector",
                    action="block",
                    reason=(
                        f"literal secret value {rule.name} found in "
                        f"outbound request to {host}"
                    ),
                    severity="critical",
                )

        # A token a transform minted is the value that goes on the wire,
        # like a static rule's real value, so it is treated like one:
        # blocked unless the host is in the rule's inject_to, where it is
        # the credential the proxy puts on the request anyway. The cage
        # never receives it (responses and capture are redacted), so
        # holding one at all means it leaked.
        for rule, token in self._minted():
            if not self._find_value(
                flow, self._forms_for(token, rule.placeholder, rule.name)
            ):
                continue
            if rule.inject_to and self._domain_matches(host, rule.inject_to):
                continue
            return self._minted_token_block(rule, f"outbound request to {host}")

        # Flag placeholders heading to unauthorized domains
        for rule in self.rules:
            if not self._find_placeholder(flow, rule):
                continue
            if not rule.inject_to or not self._domain_matches(host, rule.inject_to):
                return InspectionResult(
                    inspector="secret-injector",
                    action="flag",
                    reason=(
                        f"placeholder {rule.name} sent to unauthorized "
                        f"domain {host}"
                    ),
                    severity="error",
                )
        return None

    def inject_request(self, flow: http.HTTPFlow) -> list[str]:
        """Replace placeholders with real values in the outbound request.

        If the host matches ``redact_to``, outbound redaction is performed
        instead (real values → placeholders).

        Rules whose ``inject_to`` list does not match the request host are
        skipped, leaving the placeholder in place.

        Returns a list of secret names that were injected (or redacted for
        ``redact_to`` domains).
        """
        if not self.rules and not self._retired:
            return []

        host = flow.request.host.lower()

        # Redact-to domains: replace real values with placeholders
        if self.redact_to and self._domain_matches(host, self.redact_to):
            return self._redact_request(flow)

        names: list[str] = []
        for rule in self.rules:
            if not self._find_placeholder(flow, rule):
                continue

            # Skip injection if no authorized domains or domain not authorized
            if not rule.inject_to or not self._domain_matches(host, rule.inject_to):
                continue

            # Resolve substitution value: transform produces a derived
            # value at request time; otherwise use the static real_value.
            if rule.transform_fn is not None:
                try:
                    value = rule.derive_value()
                except Exception as e:
                    log.error(
                        "secret_injection: transform %s (%s) failed: %s "
                        "— leaving placeholder in place",
                        rule.transform, rule.name, e,
                    )
                    continue
            else:
                value = rule.real_value

            ph = rule.placeholder
            ph_bytes = ph.encode()
            value_bytes = value.encode()

            injected = False

            if rule.inject_body:
                # Legacy/loose mode: inject into URL, all headers, and body.
                #
                # Setting the URL re-parses it, host included. A
                # placeholder in the host name is therefore replaced
                # after the domain inspector (and every other request
                # inspector) judged the placeholder host, and after
                # inject_to was matched against it above: the request
                # goes to the host the secret's value names. That is
                # current behaviour, pinned by a test, not a decision.
                if ph in flow.request.url:
                    flow.request.url = flow.request.url.replace(ph, value)
                    injected = True

                for k in list(flow.request.headers.keys()):
                    v = flow.request.headers[k]
                    if ph in v:
                        flow.request.headers[k] = v.replace(ph, value)
                        injected = True

                if flow.request.content and ph_bytes in flow.request.content:
                    flow.request.content = flow.request.content.replace(
                        ph_bytes, value_bytes
                    )
                    injected = True
            else:
                # Strict mode (default): only inject into credential-bearing
                # headers — those whose name contains "auth", "key", or
                # "token" (Authorization, x-api-key, *-token, …), plus any
                # explicit ``inject_headers``. Placeholders anywhere else —
                # the URL, the body, or a non-credential header — are left
                # untouched.
                for k in list(flow.request.headers.keys()):
                    if not rule.is_auth_header(k):
                        continue
                    v = flow.request.headers[k]
                    if ph in v:
                        flow.request.headers[k] = v.replace(ph, value)
                        injected = True
                        continue
                    # git-over-HTTPS sends the token base64-encoded inside
                    # `Authorization: Basic ...`, where the literal match
                    # above can't see it. Decode/substitute/re-encode.
                    new_v, changed = _rewrite_basic_auth(v, ph, value)
                    if changed:
                        flow.request.headers[k] = new_v
                        injected = True

            if injected:
                names.append(rule.name)
        return names

    def _redact_request(self, flow: http.HTTPFlow) -> list[str]:
        """Replace real secret values with placeholders in the outbound request.

        Used for ``redact_to`` domains — the inverse of injection.
        Processes values longest first (see ``_redaction_targets``) to
        prevent partial matches when one value is a substring of another.

        Returns a list of secret names that were redacted.
        """
        return self._redact_request_values(flow)

    def _redact_request_values(self, flow: http.HTTPFlow) -> list[str]:
        """Swap every secret value (``_redaction_targets``) in the request's
        URL, headers (also inside a Basic credential) and body back to its
        placeholder, literal and in its derived forms (``_SecretForms``).
        Returns the names of the rules whose values were found.
        """
        names: list[str] = []
        for forms in self._redaction_forms():
            real, ph, name = forms.value, forms.placeholder, forms.name
            found = False

            # Redact URL (rules that injected into query strings).
            url, hit = forms.redact_text(flow.request.url)
            if hit:
                flow.request.url = url
                found = True

            # Redact headers.
            for k in list(flow.request.headers.keys()):
                v = flow.request.headers[k]
                new_v, hit = forms.redact_text(v)
                if hit:
                    flow.request.headers[k] = new_v
                    found = True
                    continue
                new_v, changed = _rewrite_basic_auth(v, real, ph)
                if changed:
                    flow.request.headers[k] = new_v
                    found = True

            # Redact body — only when a form is actually present; avoid
            # touching ``flow.request.content`` otherwise so we don't
            # churn binary bodies that legitimately contain no secret
            # material.
            if flow.request.content:
                body, hit = forms.redact(flow.request.content)
                if hit:
                    flow.request.content = body
                    found = True

            if found and name not in names:
                names.append(name)
        return names

    def redact_request(self, flow: http.HTTPFlow) -> list[str]:
        """Replace real secret values with placeholders in the outbound
        REQUEST after it has been forwarded upstream — so the capture
        writer never serializes raw secret bytes to ``capture.jsonl``.

        This is the request-side mirror of ``redact_response``. It must
        run AFTER ``inject_request`` has put the real secrets on the wire
        (mitmproxy forwards on ``request`` hook return) and BEFORE any
        capture serialization reads ``flow.request.url`` /
        ``flow.request.headers`` / ``flow.request.content``. The capture
        file is bind-mounted into the cage at mode 0644; without this
        step the OUTBOUND request snapshot (by design "what went out
        on the wire") would land the raw ``ANTHROPIC_API_KEY`` on disk
        where the cage workload can read it.

        Distinct from the ``redact_to`` path: ``_redact_request`` runs
        at injection time for explicitly tagged ``redact_to`` domains
        (the cage agent shouldn't see its own secret echoed back from
        a non-trusted upstream). ``redact_request`` runs for EVERY rule
        on EVERY domain after the upstream send, purely to scrub the
        in-memory flow before disk serialization.

        Every value a transform minted counts as a real value here (and in
        every other redaction): an injected ``ya29.…`` access token is as
        much a live credential as a static key. Values are processed
        longest first to avoid partial-match issues.

        Returns the list of secret names that were redacted.
        """
        return self._redact_request_values(flow)

    def redact_record(self, record: Any) -> Any:
        """Return *record* with every secret value in its strings swapped
        for its rule's placeholder.

        For audit entries: JSON-shaped data (dicts, lists, strings and
        scalars), walked recursively; keys are left alone. The values are
        those ``redact_request`` swaps back in a request (each rule's real
        value and each token a transform minted, longest first), so a
        field read from a request after injection (its URL, path or host)
        records what ``redact_request`` would leave there: the
        placeholder. Each value is matched in its derived forms too
        (percent-encoded, JSON-escaped, base64: see ``_SecretForms``), as
        in every redaction. The record is returned as is when there is
        nothing to redact, otherwise a copy.
        """
        if not self.rules and not self._retired:
            return record
        targets = self._redaction_forms()
        if not targets:
            return record

        def walk(value: Any) -> Any:
            if isinstance(value, str):
                for forms in targets:
                    value, _hit = forms.redact_text(value)
                return value
            if isinstance(value, dict):
                return {k: walk(v) for k, v in value.items()}
            if isinstance(value, (list, tuple)):
                return [walk(v) for v in value]
            return value

        return walk(record)

    def redact_text(self, text: str) -> tuple[str, list[str]]:
        """*text* with every secret, in any form ``redact_record`` matches,
        swapped for its rule's placeholder, and the names of the rules
        whose secrets were found."""
        names: list[str] = []
        if not self.rules and not self._retired:
            return text, names
        for forms in self._redaction_forms():
            text, hit = forms.redact_text(text)
            if hit and forms.name not in names:
                names.append(forms.name)
        return text, names

    def redact_response(self, flow: http.HTTPFlow) -> list[str]:
        """Replace real secret values with placeholders in the response.

        Covers every value ``_redaction_targets`` lists (real values and
        minted tokens), literal and in its derived forms (percent-encoded,
        JSON-escaped, base64: see ``_SecretForms``), longest first to
        prevent partial matches when one value is a substring of another.

        Returns a list of secret names that were redacted.
        """
        if not flow.response:
            return []

        names: list[str] = []
        for forms in self._redaction_forms():
            found = False

            # Redact response headers
            for k in list(flow.response.headers.keys()):
                v = flow.response.headers[k]
                new_v, hit = forms.redact_text(v)
                if hit:
                    flow.response.headers[k] = new_v
                    found = True
                    continue
                new_v, changed = _rewrite_basic_auth(
                    v, forms.value, forms.placeholder)
                if changed:
                    flow.response.headers[k] = new_v
                    found = True

            # Redact response body
            if flow.response.content:
                body, hit = forms.redact(flow.response.content)
                if hit:
                    flow.response.content = body
                    found = True

            if found and forms.name not in names:
                names.append(forms.name)
        return names

    # ── WebSocket (raw bytes) methods ───────────────────────

    def check_ws_injection_policy(
        self, content: bytes, host: str
    ) -> Optional[InspectionResult]:
        """Check domain restrictions for a WebSocket frame payload.

        Like ``check_injection_policy`` but operates on raw bytes + host
        instead of an ``http.HTTPFlow``.
        """
        if not self.rules and not self._retired:
            return None

        host = host.lower()

        if self.redact_to and self._domain_matches(host, self.redact_to):
            return None

        # Block literal real values heading to unauthorized domains.
        # Transform rules block raw secret bytes everywhere — see the
        # equivalent comment in check_injection_policy.
        for rule in self.rules:
            if self._forms_for(
                rule.real_value, rule.placeholder, rule.name
            ).occurs(content):
                if (
                    not rule.transform_fn
                    and rule.inject_to
                    and self._domain_matches(host, rule.inject_to)
                ):
                    continue
                return InspectionResult(
                    inspector="secret-injector",
                    action="block",
                    reason=(
                        f"literal secret value {rule.name} found in "
                        f"outbound WebSocket frame to {host}"
                    ),
                    severity="critical",
                )

        # Minted tokens: blocked outside inject_to — see
        # check_injection_policy.
        for rule, token in self._minted():
            if not self._forms_for(token, rule.placeholder,
                                   rule.name).occurs(content):
                continue
            if rule.inject_to and self._domain_matches(host, rule.inject_to):
                continue
            return self._minted_token_block(
                rule, f"outbound WebSocket frame to {host}"
            )

        # Flag placeholders heading to unauthorized domains
        for rule in self.rules:
            if rule.placeholder.encode() not in content:
                continue
            if not rule.inject_to or not self._domain_matches(host, rule.inject_to):
                return InspectionResult(
                    inspector="secret-injector",
                    action="flag",
                    reason=(
                        f"placeholder {rule.name} sent to unauthorized "
                        f"domain {host}"
                    ),
                    severity="error",
                )
        return None

    def inject_ws_content(
        self, content: bytes, host: str
    ) -> tuple[bytes, list[str]]:
        """Replace placeholders with real values in outbound WebSocket content.

        If the host matches ``redact_to``, outbound redaction is performed
        instead (real values → placeholders).

        Returns ``(content, names)`` where *names* lists the secrets acted on.
        """
        if not self.rules and not self._retired:
            return content, []

        host = host.lower()

        if self.redact_to and self._domain_matches(host, self.redact_to):
            return self._redact_ws_content(content)

        names: list[str] = []
        for rule in self.rules:
            # Strict mode only injects into credential-bearing request
            # headers, which have no equivalent in a raw WebSocket frame —
            # leave the placeholder in place unless the rule opted into body
            # injection (inject_body).
            if not rule.inject_body:
                continue
            ph_bytes = rule.placeholder.encode()
            if ph_bytes not in content:
                continue
            if not rule.inject_to or not self._domain_matches(host, rule.inject_to):
                continue
            if rule.transform_fn is not None:
                try:
                    value = rule.derive_value()
                except Exception as e:
                    log.error(
                        "secret_injection: transform %s (%s) failed on "
                        "WebSocket content: %s — leaving placeholder",
                        rule.transform, rule.name, e,
                    )
                    continue
                content = content.replace(ph_bytes, value.encode())
            else:
                content = content.replace(ph_bytes, rule.real_value.encode())
            names.append(rule.name)

        return content, names

    def redact_ws_content(self, content: bytes) -> tuple[bytes, list[str]]:
        """Replace real secret values with placeholders in WebSocket content.

        Covers every value ``_redaction_targets`` lists (real values and
        minted tokens), literal and in its derived forms (see
        ``_SecretForms``), longest first to prevent partial matches when
        one value is a substring of another.

        Returns ``(content, names)`` where *names* lists the secrets redacted.
        """
        names: list[str] = []
        for forms in self._redaction_forms():
            content, hit = forms.redact(content)
            if hit and forms.name not in names:
                names.append(forms.name)

        return content, names

    def _redact_ws_content(
        self, content: bytes
    ) -> tuple[bytes, list[str]]:
        """Private helper — redact real values in outbound WS content.

        Used by ``inject_ws_content`` for ``redact_to`` domains.
        """
        return self.redact_ws_content(content)

    @staticmethod
    def _domain_matches(host: str, domains: list[str]) -> bool:
        """Suffix match — same logic as DomainInspector._matches."""
        parts = host.lower().split(".")
        for i in range(len(parts)):
            if ".".join(parts[i:]) in domains:
                return True
        return False
