"""Record ``tests/fixtures/egress/get_text.json``.

What the Python egress's inspectors see of a body: the Content-Encoding
removed (``get_content``) and the result decoded to text with the charset
rules of ``get_text(strict=False)``. Both are methods of the HTTP library
the Python egress runs inside, which is not installed in this test
environment, so ``get_content`` / ``get_text`` below restate them from
that library's source at the version ``Containerfile.egress`` pins
(12.2.3): its ``Message.get_content``, ``Message.get_text``,
``infer_content_encoding``, ``parse_content_type`` and the
``custom_decode`` table. Everything they lean on is the live Python
runtime: ``codecs`` (charset names, aliases and every codec table),
``zlib``, ``brotli`` and ``zstandard``.

Run with the two compression modules the egress image installs::

    uv run --with brotli --with zstandard \\
        python tests/fixtures/egress/gen/get_text.py

Without them the ``br`` / ``zstd`` cases keep the expectations already
in the file (the generator refuses to drop them).

The Rust port (``rust/agentcage-egress/src/text.rs``) maps each
undecodable byte the fallback surrogate-escapes to U+FFFD, since a Rust
``String`` cannot hold a lone surrogate; ``text`` here is recorded the
same way (``_py_text``).
"""

from __future__ import annotations

import base64
import codecs
import collections
import gzip
import json
import re
import struct
import sys
import zlib
from pathlib import Path

try:  # optional: the egress image has them, the test venv does not
    import brotli  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    brotli = None
try:
    import zstandard  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    zstandard = None

OUT = Path(__file__).resolve().parent.parent / "get_text.json"


# ── The reference behaviour ──────────────────────────────


class NeedsModule(Exception):
    """A case needs brotli/zstandard, which is not importable."""


def _decode_gzip(content: bytes) -> bytes:
    if not content:
        return b""
    d = zlib.decompressobj(47)
    return d.decompress(content) + d.flush()


def _decode_deflate(content: bytes) -> bytes:
    if not content:
        return b""
    try:
        return zlib.decompress(content)
    except zlib.error:
        return zlib.decompress(content, -15)


def _decode_br(content: bytes) -> bytes:
    if not content:
        return b""
    if brotli is None:
        raise NeedsModule("brotli")
    return brotli.decompress(content)


def _decode_zstd(content: bytes) -> bytes:
    if not content:
        return b""
    if zstandard is None:
        raise NeedsModule("zstandard")
    import io
    ctx = zstandard.ZstdDecompressor()
    return ctx.stream_reader(io.BytesIO(content), read_across_frames=True).read()


CUSTOM_DECODE = {
    "none": lambda c: c,
    "identity": lambda c: c,
    "gzip": _decode_gzip,
    "deflate": _decode_deflate,
    "deflateraw": _decode_deflate,
    "br": _decode_br,
    "zstd": _decode_zstd,
}


def _decode(content: bytes, encoding: str):
    """The library's ``encoding.decode``: the custom table, else
    ``codecs.decode``; any failure is a ``ValueError``."""
    encoding = encoding.lower()
    try:
        fn = CUSTOM_DECODE.get(encoding)
        if fn is not None:
            return fn(content)
        return codecs.decode(content, encoding, "strict")
    except (TypeError, NeedsModule):
        raise
    except Exception as e:
        raise ValueError(repr(e)) from e


def header_get(headers: list[tuple[str, str]], name: str):
    """``headers.get(name)``: every value folded with ``", "``."""
    values = [v for k, v in headers if k.lower() == name.lower()]
    return ", ".join(values) if values else None


def get_content(headers, raw: bytes, strict: bool = True) -> bytes:
    ce = header_get(headers, "content-encoding")
    if ce:
        try:
            content = _decode(raw, ce)
            if isinstance(content, str):
                raise ValueError(f"Invalid Content-Encoding: {ce}")
            return content
        except ValueError:
            if strict:
                raise
            return raw
    return raw


def parse_content_type(c: str):
    parts = c.split(";", 1)
    ts = parts[0].split("/", 1)
    if len(ts) != 2:
        return None
    d = collections.OrderedDict()
    if len(parts) == 2:
        for i in parts[1].split(";"):
            clause = i.split("=", 1)
            if len(clause) == 2:
                d[clause[0].strip()] = clause[1].strip()
    return ts[0].lower(), ts[1].lower(), d


def infer_content_encoding(content_type: str, content: bytes = b"") -> str:
    enc = None
    if content.startswith(b"\x00\x00\xfe\xff"):
        enc = "utf-32be"
    elif content.startswith(b"\xff\xfe\x00\x00"):
        enc = "utf-32le"
    elif content.startswith(b"\xfe\xff"):
        enc = "utf-16be"
    elif content.startswith(b"\xff\xfe"):
        enc = "utf-16le"
    elif content.startswith(b"\xef\xbb\xbf"):
        enc = "utf-8-sig"
    elif parsed := parse_content_type(content_type):
        enc = parsed[2].get("charset")
    if not enc and "json" in content_type:
        enc = "utf8"
    if not enc and "html" in content_type:
        m = re.search(rb"""<meta[^>]+charset=['"]?([^'">]+)""", content,
                      re.IGNORECASE)
        enc = m.group(1).decode("ascii", "ignore") if m else "utf8"
    if not enc and "xml" in content_type:
        m = re.search(rb"""<\?xml[^\?>]+encoding=['"]([^'"\?>]+)""", content,
                      re.IGNORECASE)
        enc = m.group(1).decode("ascii", "ignore") if m else "utf8"
    if not enc and ("javascript" in content_type
                    or "ecmascript" in content_type):
        enc = "utf8"
    if not enc and "text/css" in content_type:
        m = re.match(rb"""@charset "([^"]+)";""", content, re.IGNORECASE)
        enc = m.group(1).decode("ascii", "ignore") if m else "utf8"
    if not enc:
        enc = "latin-1"
    if enc.lower() in ("gb2312", "gbk"):
        enc = "gb18030"
    return enc


def get_text(headers, raw: bytes) -> str:
    """``get_text(strict=False)``."""
    content = get_content(headers, raw, strict=False)
    enc = infer_content_encoding(header_get(headers, "content-type") or "",
                                 content)
    try:
        text = _decode(content, enc)
        if not isinstance(text, str):
            raise TypeError("charset names a bytes codec")
        return text
    except ValueError:
        return content.decode("utf8", "surrogateescape")


def _py_text(text: str) -> str:
    """Surrogate-escaped bytes as U+FFFD, the Rust port's spelling."""
    return re.sub("[\udc80-\udcff]", "�", text)


# ── Encoding helpers ─────────────────────────────────────


def enc_bytes(b: bytes):
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return {"b64": base64.b64encode(b).decode("ascii")}


def dec_bytes(v) -> bytes:
    if isinstance(v, dict):
        return base64.b64decode(v["b64"])
    return v.encode("utf-8")


def _gzip(b: bytes) -> bytes:
    return gzip.compress(b, mtime=0)


def _raw_deflate(b: bytes) -> bytes:
    c = zlib.compressobj(6, zlib.DEFLATED, -15)
    return c.compress(b) + c.flush()


def _gzip_with_header(b: bytes, flags: int, extra=b"", name=b"", comment=b"",
                      hcrc=False) -> bytes:
    head = struct.pack("<BBBBIBB", 0x1F, 0x8B, 8, flags, 0, 0, 255)
    if flags & 4:
        head += struct.pack("<H", len(extra)) + extra
    if flags & 8:
        head += name + b"\0"
    if flags & 16:
        head += comment + b"\0"
    if hcrc:
        head += struct.pack("<H", zlib.crc32(head) & 0xFFFF)
    return (head + _raw_deflate(b)
            + struct.pack("<II", zlib.crc32(b), len(b) & 0xFFFFFFFF))


# ── Cases ────────────────────────────────────────────────

TEXT = "Hello, world! agentcage:secret:API_KEY:0123456789abcdef"
UTF8 = "café — naïve 🔑 日本語".encode("utf-8")

BODIES: list[tuple[str, bytes]] = [
    ("empty", b""),
    ("ascii", TEXT.encode()),
    ("utf8", UTF8),
    ("latin1", "café naïve".encode("latin-1")),
    ("cp1252-specials", b"\x80 \x93quoted\x94 \x85"),
    ("cp1252-undefined", b"a\x81b"),
    ("invalid-utf8", b"ok \xff\xfe? \xe2\x82 end \xc3"),
    ("truncated-utf8-tail", b"abc\xe2\x82"),
    ("surrogate-utf8", b"x\xed\xa0\x80y"),
    ("overlong-utf8", b"x\xc0\xafy"),
    ("utf8-bom", b"\xef\xbb\xbf" + UTF8),
    ("utf16le-bom", "hé🔑".encode("utf-16")),
    ("utf16be-bom", b"\xfe\xff" + "hé🔑".encode("utf-16-be")),
    ("utf16le-bom-odd", b"\xff\xfeh\x00i"),
    ("utf16le-lone-surrogate", b"\xff\xfe\x00\xd8a\x00"),
    ("utf32le-bom", b"\xff\xfe\x00\x00" + "hé🔑".encode("utf-32-le")),
    ("utf32be-bom", b"\x00\x00\xfe\xff" + "hé🔑".encode("utf-32-be")),
    ("utf32le-bad", b"\xff\xfe\x00\x00\x00\x00\x11\x00"),
    ("html-meta", b'<html><head><meta charset="latin-1"></head>caf\xe9</html>'),
    ("html-meta-http-equiv",
     b'<META http-equiv="Content-Type" content="text/html; CHARSET=cp1252">\x93x\x94'),
    ("html-meta-unknown", b"<meta charset=bogus>caf\xc3\xa9"),
    ("html-no-meta", b"<p>caf\xc3\xa9</p>"),
    ("xml-decl", b"<?xml version='1.0' encoding='iso-8859-1'?><a>caf\xe9</a>"),
    ("xml-decl-utf16", b'<?xml version="1.0" encoding="utf-16"?><a/>'),
    ("css-charset", b'@charset "koi8-r"; a{content:"\xc1\xc2"}'),
    ("css-charset-late", b' @charset "koi8-r"; \xc1'),
    ("gb", "中文 text".encode("gb18030")),
    ("koi8", "привет".encode("koi8-r")),
    ("json-escaped", b'{"k": "caf\\u00e9", "raw": "caf\xc3\xa9"}'),
    ("binary", bytes(range(256))),
]

CONTENT_TYPES: list[str] = [
    "",
    "text/plain",
    "text/plain; charset=utf-8",
    "text/plain; charset=UTF8",
    "text/plain;charset=ISO-8859-1",
    "text/plain; charset=latin1",
    'text/plain; charset="utf-8"',
    "text/plain; charset=windows-1252",
    "text/plain; charset=cp1252",
    "text/plain; charset=us-ascii",
    "text/plain; charset=utf-16",
    "text/plain; charset=utf-16le",
    "text/plain; charset=UTF-32",
    "text/plain; charset=gbk",
    "text/plain; charset=GB2312",
    "text/plain; charset=gb18030",
    "text/plain; charset=koi8-r",
    "text/plain; charset=iso-8859-2",
    "text/plain; charset=iso-8859-15",
    "text/plain; charset=windows-1251",
    "text/plain; charset=bogus",
    "text/plain; charset=",
    "text/plain; Charset=latin-1",
    "text/plain; charset=utf-8; charset=latin-1",
    "text/plain; charset=utf-8-sig",
    "application/json",
    "application/json; charset=latin-1",
    "application/problem+json",
    "text/html",
    "TEXT/HTML",
    "application/xhtml+xml",
    "application/xml",
    "text/xml; charset=utf-8",
    "application/javascript",
    "text/ecmascript",
    "text/css",
    "application/octet-stream",
    "multipart/form-data; boundary=xyz",
    "jsonish-without-slash",
    "application/x-www-form-urlencoded",
]


def charset_cases():
    cases = []
    for ct in CONTENT_TYPES:
        for name, body in BODIES:
            cases.append({
                "name": f"charset/{name}/{ct or '<none>'}",
                "headers": [["Content-Type", ct]] if ct else [],
                "body": body,
            })
    # Folded duplicates: the library folds with ", " before parsing.
    cases.append({
        "name": "charset/duplicate-content-type",
        "headers": [["Content-Type", "text/plain; charset=latin-1"],
                    ["content-type", "text/html"]],
        "body": b"caf\xe9 <meta charset=utf-8>",
    })
    return cases


def _zlib_header_variants(payload: bytes):
    z = zlib.compress(payload)
    return [
        ("zlib-ok", z),
        ("zlib-truncated", z[:-6]),
        ("zlib-no-adler", z[:-4]),
        ("zlib-bad-adler", z[:-1] + bytes([z[-1] ^ 1])),
        ("zlib-trailing", z + b"garbage"),
        ("zlib-bad-header", b"\x78\x9a" + z[2:]),
        ("zlib-fdict", b"\x78\xbb" + z[2:]),
        ("zlib-big-window", b"\x88\x98" + z[2:]),
    ]


def encoding_cases():
    payload = (TEXT + " ") * 20
    p = payload.encode()
    g = _gzip(p)
    raw = _raw_deflate(p)
    out: list[tuple[str, str | None, bytes]] = [
        ("identity", "identity", p),
        ("none", "none", p),
        ("empty-ce", "", p),
        ("gzip", "gzip", g),
        ("gzip-upper", "GZIP", g),
        ("gzip-empty", "gzip", b""),
        ("gzip-one-byte", "gzip", b"\x1f"),
        ("gzip-one-byte-other", "gzip", b"A"),
        ("gzip-header-only", "gzip", g[:10]),
        ("gzip-truncated-body", "gzip", g[: len(g) // 2]),
        ("gzip-no-trailer", "gzip", g[:-8]),
        ("gzip-half-trailer", "gzip", g[:-4]),
        ("gzip-bad-crc", "gzip", g[:-8] + b"\0\0\0\0" + g[-4:]),
        ("gzip-bad-isize", "gzip", g[:-4] + b"\0\0\0\0"),
        ("gzip-trailing-garbage", "gzip", g + b"trailing"),
        ("gzip-two-members", "gzip", g + _gzip(b"second member")),
        ("gzip-bad-method", "gzip", g[:2] + b"\x07" + g[3:]),
        ("gzip-reserved-flag", "gzip", g[:3] + b"\x20" + g[4:]),
        ("gzip-all-header-fields", "gzip",
         _gzip_with_header(p, 4 | 8 | 16 | 2, extra=b"XY\x02\x00ab",
                           name=b"file.txt", comment=b"hi", hcrc=True)),
        ("gzip-bad-hcrc", "gzip",
         _gzip_with_header(p, 2, hcrc=True)[:10] + b"\0\0"
         + _gzip_with_header(p, 2, hcrc=True)[12:]),
        ("gzip-truncated-name", "gzip", _gzip_with_header(p, 8, name=b"x" * 20)[:20]),
        ("gzip-garbage", "gzip", b"definitely not compressed"),
        ("gzip-carrying-zlib", "gzip", zlib.compress(p)),
        ("deflate-zlib", "deflate", zlib.compress(p)),
        ("deflate-raw", "deflate", raw),
        ("deflateraw", "deflateraw", raw),
        ("deflate-empty", "deflate", b""),
        ("deflate-raw-truncated", "deflate", raw[: len(raw) // 2]),
        ("deflate-raw-trailing", "deflate", raw + b"trailing"),
        ("deflate-garbage", "deflate", b"definitely not compressed"),
        ("deflate-gzip", "deflate", g),
        ("x-gzip", "x-gzip", g),
        ("stacked", "gzip, br", g),
        ("codec-name", "utf-8", p),
        ("unknown", "compress", p),
        ("unknown-empty", "frobnicate", b""),
    ]
    for name, data in _zlib_header_variants(p):
        out.append((f"deflate-{name}", "deflate", data))
        out.append((f"gzip-{name}", "gzip", data))
    if brotli is not None:
        b = brotli.compress(p)
        out += [
            ("br", "br", b),
            ("br-empty", "br", b""),
            ("br-truncated", "br", b[: len(b) // 2]),
            ("br-trailing", "br", b + b"x"),
            ("br-garbage", "br", b"\xff" * 16),
        ]
    if zstandard is not None:
        c = zstandard.ZstdCompressor(level=3, write_checksum=True)
        z1 = c.compress(p)
        z2 = zstandard.ZstdCompressor(level=1).compress(b"second frame")
        skippable = struct.pack("<II", 0x184D2A50, 4) + b"skip"
        bad_ck = z1[:-4] + bytes(4)
        out += [
            ("zstd", "zstd", z1),
            ("zstd-empty", "zstd", b""),
            ("zstd-two-frames", "zstd", z1 + z2),
            ("zstd-skippable", "zstd", skippable + z2),
            ("zstd-truncated", "zstd", z1[: len(z1) // 2]),
            ("zstd-trailing", "zstd", z1 + b"garbage!"),
            ("zstd-bad-checksum", "zstd", bad_ck),
            ("zstd-garbage", "zstd", b"definitely not compressed"),
        ]
    cases = []
    for name, ce, data in out:
        cases.append({
            "name": f"encoding/{name}",
            "headers": [["Content-Type", "text/plain; charset=utf-8"],
                        ["Content-Encoding", ce]],
            "body": data,
        })
    cases.append({
        "name": "encoding/duplicate-headers-fold",
        "headers": [["Content-Encoding", "gzip"], ["content-encoding", "gzip"]],
        "body": g,
    })
    cases.append({
        "name": "encoding/gzip-latin1-text",
        "headers": [["Content-Type", "text/plain"],
                    ["Content-Encoding", "gzip"]],
        "body": _gzip("café".encode("latin-1")),
    })
    return cases


def run_case(case) -> dict:
    headers = [tuple(h) for h in case["headers"]]
    body = case["body"]
    try:
        decoded = enc_bytes(get_content(headers, body, strict=True))
    except ValueError:
        decoded = None
    return {
        "name": case["name"],
        "headers": case["headers"],
        "body": enc_bytes(body),
        "decoded": decoded,
        "text": _py_text(get_text(headers, body)),
    }


# Codec names: every alias Python knows, its module names, spelling
# variants and unknowns, each with the codec ``codecs.lookup`` resolves
# it to after the lower-casing `encoding.decode` applies (None for
# unknown).
def label_cases():
    import encodings.aliases as aliases

    labels = set(aliases.aliases)
    labels |= set(aliases.aliases.values())
    labels |= {
        "UTF-8", "utf8", "Utf-8", " utf-8 ", "utf--8", "utf 8", "'utf-8'",
        '"utf-8"', "utf_8.", ".utf-8", "u.t.f.8", "utf-8-sig", "UTF8-SIG",
        "latin-1", "Latin1", "ISO-8859-1", "iso8859-1", "iso_8859-1:1987",
        "windows-1252", "WINDOWS-1252", "x-cp1252", "cp-1252", "us-ascii",
        "ASCII", "646", "utf-16", "UTF-16LE", "utf-16-be", "utf-32",
        "utf32le", "koi8-r", "KOI8_U", "gb18030", "GB18030-2000",
        "iso-8859-15", "latin9", "l9", "windows-1251", "cp1251",
        "foo", "", "-", "utf-9", "unicode-1-1-utf-7", "x-user-defined",
        "utfé-8", "utf-８", "gbk", "gb2312", "Koi8-r", "İso-8859-1",
        "utf-8\x00",
    }
    out = []
    for label in sorted(labels):
        try:
            name = codecs.lookup(label.lower()).name
        except (LookupError, ValueError):
            name = None
        out.append({"label": label, "codec": name})
    return out


# Single-byte codec tables: the code point each byte decodes to, or
# None where the codec rejects it.
SINGLE_BYTE = [
    "ascii", "latin-1", "cp1250", "cp1251", "cp1252", "cp1253", "cp1254",
    "cp1255", "cp1256", "cp1257", "cp1258", "iso8859-2", "iso8859-3",
    "iso8859-4", "iso8859-5", "iso8859-6", "iso8859-7", "iso8859-8",
    "iso8859-9",
    "iso8859-10", "iso8859-13", "iso8859-14", "iso8859-15", "iso8859-16",
    "koi8-r", "koi8-u",
]


def table_cases():
    out = []
    for codec in SINGLE_BYTE:
        table = []
        for b in range(256):
            try:
                table.append(ord(bytes([b]).decode(codec)))
            except UnicodeDecodeError:
                table.append(None)
        out.append({"codec": codecs.lookup(codec).name, "table": table})
    return out


# Multi-byte samples: (codec, bytes) → text or None (rejected).
def multibyte_cases():
    samples = {
        "gb18030": [
            "中文 text".encode("gb18030"), b"\x80", b"\xff", b"\xa3\xa0",
            b"\xa1\xa1", b"\x81\x30\x81\x30", b"\x84\x31\xa4\x39",
            b"\x84\x31\xa5\x30", b"\x90\x30\x81\x30", b"\xe3\x32\x9a\x35",
            b"\xe3\x32\x9a\x36", b"\x81", b"\x81\x30", b"\x81\x30\x81",
            b"\xfe\xfe", b"\xa6\xd9", b"\xa8\xbc", b"\xfe\x51", b"\xfe\x52",
            b"\xa2\xe3", b"\xa8\xbf", b"\xfe\x50\xfe\x54",
            "€".encode("gb18030"), b"\x81\x7f", b"\x81\xff",
        ],
        "utf-16": [b"h\x00i\x00", b"\xfe\xff\x00h", b"\xff\xfe", b"h",
                   b"\x00\xd8\x00\xdc", b"\x00\xdc"],
        "utf-16-le": [b"\xff\xfeh\x00", b"\x3d\xd8\x11\xdd", b"\x3d\xd8"],
        "utf-16-be": [b"\xfe\xff\x00h", b"\xd8\x3d\xdd\x11", b"\xdc\x00"],
        "utf-32": [b"h\x00\x00\x00", b"\x00\x00\xfe\xffh\x00\x00\x00",
                   b"\x00\x00\xfe\xff\x00\x00\x00h", b"\xff\xfe\x00\x00",
                   b"\x00\xd8\x00\x00", b"\x00\x00\x11\x00", b"h\x00\x00"],
        "utf-32-le": [b"\xff\xfe\x00\x00h\x00\x00\x00"],
        "utf-32-be": [b"\x00\x00\x00h", b"\x00\x11\x00\x00"],
        "utf-8-sig": [b"\xef\xbb\xbfx", b"x\xef\xbb\xbf", b"\xef\xbb", b""],
        "utf-8": [b"\xef\xbb\xbfx", b"\xf4\x90\x80\x80", b"\xf0\x9f\x94\x91"],
    }
    out = []
    for codec, items in samples.items():
        for data in items:
            try:
                text = data.decode(codec)
            except UnicodeDecodeError:
                text = None
            out.append({"codec": codecs.lookup(codec).name,
                        "bytes": enc_bytes(data), "text": text})
    return out


def build() -> dict:
    cases = [run_case(c) for c in charset_cases() + encoding_cases()]
    return {
        "_comment": (
            "Body decoding as inspectors see it: Content-Encoding removal "
            "(decoded: null = the strict decode fails) and get_text("
            "strict=False) (text; undecodable bytes as U+FFFD). Plus the "
            "charset label table, single-byte codec tables and multi-byte "
            "samples. Generated by gen/get_text.py; do not edit by hand."
        ),
        "cases": cases,
        "labels": label_cases(),
        "tables": table_cases(),
        "multibyte": multibyte_cases(),
    }


def main() -> int:
    data = build()
    if OUT.exists() and (brotli is None or zstandard is None):
        old = json.loads(OUT.read_text())
        have = {c["name"] for c in data["cases"]}
        kept = [c for c in old["cases"]
                if c["name"] not in have
                and c["name"].startswith(("encoding/br", "encoding/zstd"))]
        data["cases"] += kept
        print(f"kept {len(kept)} br/zstd cases (modules missing)",
              file=sys.stderr)
    OUT.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT} ({len(data['cases'])} cases)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
