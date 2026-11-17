"""Vorobey hackerpolice list loading and indexing.

Downloads the cheater list from GitHub (with fallbacks), builds a SteamID
index, and exposes it to the sync policy.

Everything in this module moves **bytes**, never decoded text, on the read
and snapshot paths: the snapshot file must end up an exact replica of the
original upstream file, and only bytes survive the round trip unchanged
(text mode would translate CRLF, re-encoding could change escaping, a BOM
could be dropped, ...). JSON parsing accepts bytes directly.
"""

from __future__ import annotations

import base64
import binascii
import http.client
import json
import logging
import re
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from playerlist import MAX_FILE_BYTES, display_path, error_reason, normalize_steamid, strict_json_loads

SOURCE_REPO_URL = "https://github.com/Nocrex/Tom/blob/main/playerlist.vorobey-hackerpolice.json"

# Tried in order until one of them answers. The first is the canonical raw
# URL of the original file -- the exact bytes the snapshot must replicate.
DEFAULT_SOURCES: tuple[str, ...] = (
    "https://raw.githubusercontent.com/Nocrex/Tom/refs/heads/main/playerlist.vorobey-hackerpolice.json",
    "https://github.com/Nocrex/Tom/raw/main/playerlist.vorobey-hackerpolice.json",
    "https://api.github.com/repos/Nocrex/Tom/contents/playerlist.vorobey-hackerpolice.json",
)

# Single source of truth for the tool version (also used for --version and the
# HTTP User-Agent). 4.3 is a minor bump: no flag was added or removed, but the
# behaviour a user sees changed (an interrupted run now exits 130 with one line
# instead of a stack trace, error messages name the file that is actually wrong,
# and the review text is inert as Markdown).
VERSION = "4.3"

USER_AGENT = (
    f"Garou3299-tf2bd-database-vorobey-hackerpolice-sync/{VERSION} (+https://github.com/Garou3299/tf2bd-database)"
)

FETCH_TIMEOUT_SECONDS = 30
FETCH_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 2

# A displayed URL is capped at 2,048 characters. Parsing an arbitrarily large
# URL first can nevertheless materialise millions of query-parameter tuples
# from a single bounded (64 MiB) upstream document. Four kilobytes is generous
# for a real URL and bounds both that work and network request-targets; longer
# URLs are refused for fetches and omitted from logs/reports before parsing.
_MAX_URL_PARSE_CHARS = 4_096
# Nested redirect/callback URLs can themselves contain URLs. Bound recursion so
# a tiny self-similar query cannot exhaust the Python call stack while logging.
_MAX_NESTED_URL_DEPTH = 8

# Sanity cap on a fetched list (the real one is ~1.9 MB): a misbehaving or
# hostile endpoint must not be able to exhaust memory by streaming forever.
# The same budget applies to the snapshot file read from disk, which used to be
# read whole however big it was.
MAX_SOURCE_BYTES = MAX_FILE_BYTES

__all__ = [
    "DEFAULT_SOURCES",
    "MAX_URL_DISPLAY_CHARS",
    "REDACTED",
    "SOURCE_REPO_URL",
    "VERSION",
    "HackerpoliceIndex",
    "SyncError",
    "added_steamids",
    "http_scheme",
    "load_first_available_raw",
    "load_snapshot",
    "removed_steamids",
]


class SyncError(Exception):
    """A user-facing failure (bad input, unreachable source) rather than a bug."""


# ``--verbose`` turns these on: without them the flag only re-printed the INFO
# lines the default run already shows, so it did nothing at all. Every message
# names a source through ``redact_url``, because a --source may carry a token.
LOGGER = logging.getLogger("vorobey_sources")


class _ShortRead(OSError):
    """A response body that ended before the length the server declared.

    Deliberately an OSError: the retry loop treats OSError as a transient
    network failure, which is exactly what a cut-short transfer is. Returning
    the partial bytes instead would either fail to parse (a confusing "not
    valid JSON" for what was really a dropped connection) or -- if the file
    happens to end in whitespace -- be snapshotted slightly cut short.
    """


def http_scheme(value: str) -> str:
    """``"http"``, ``"https"``, or ``""`` when ``value`` is not a URL at all.

    Schemes are case-insensitive (RFC 3986) and ``urllib`` lowercases them
    before fetching, so ``HTTPS://host/x`` is a perfectly usable URL. Comparing
    a lower-cased scheme keeps our own checks in step with the library's
    instead of refusing a URL the fetch itself would have handled. A local path
    has no scheme, so it answers ``""``.
    """
    if len(value) > _MAX_URL_PARSE_CHARS:
        # The scheme is at the front, so do not ask urlsplit() to scan a
        # potentially 64 MiB upstream-supplied download_url just to classify it.
        if value[:8].casefold() == "https://":
            return "https"
        if value[:7].casefold() == "http://":
            return "http"
        return ""
    try:
        scheme = urllib.parse.urlsplit(value).scheme.lower()
    except ValueError:  # e.g. a malformed IPv6 literal
        return ""
    return scheme if scheme in {"http", "https"} else ""


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never downgrade an HTTPS fetch to plain HTTP.

    ``urllib`` happily follows an ``https://`` -> ``http://`` redirect, which
    would let anything on the network path swap the list we are about to
    snapshot (and act on: promotions come from this file). Refusing the
    downgrade keeps every fetched byte HTTPS-protected end to end.
    """

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: http.client.HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        if len(newurl) > _MAX_URL_PARSE_CHARS:
            raise SyncError(f"refusing to follow a redirect longer than {_MAX_URL_PARSE_CHARS:,} characters")
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlparse(new.full_url).scheme != "https":
            raise SyncError(f"refusing to follow a non-HTTPS redirect to {redact_url(newurl)}")
        return new


# One opener for the whole process: it holds no per-request state, and it is
# what enforces the HTTPS-only redirect rule above.
_OPENER = urllib.request.build_opener(_HttpsOnlyRedirectHandler)


def _declared_length(response: object) -> int | None:
    """Usable ``Content-Length`` of a response, or ``None`` when absent/invalid."""
    response_headers = getattr(response, "headers", None)
    declared = response_headers.get("Content-Length") if response_headers is not None else None
    # ASCII digits only: isdigit() also accepts things like "²", which int()
    # then refuses -- a malformed header must not crash the fetch.
    if isinstance(declared, str) and declared.isascii() and declared.isdigit():
        return int(declared)
    return None


@dataclass(frozen=True)
class HackerpoliceIndex:
    """Vorobey entries keyed by canonical SteamID.

    The upstream list is a cheater list and nothing else: every entry has
    carried the ``cheater`` attribute for as long as the list has existed,
    and it is not expected to carry anything else. This index therefore
    reads ``steamid`` and ignores attributes entirely -- being listed is the
    whole signal, whether an entry says ``cheater``, says nothing, or says
    something unexpected. Only ``proof`` is read, and only to show evidence
    links in the pull request.
    """

    by_steamid: dict[str, dict[str, Any]]
    total: int
    skipped: int

    @classmethod
    def build(cls, document: dict[str, Any], *, what: str = "the Vorobey hackerpolice list") -> HackerpoliceIndex:
        """Index a hackerpolice-shaped document.

        ``what`` names the document in the error. This class indexes BOTH the
        live upstream list and the previous snapshot, and a snapshot with no
        'players' array used to be reported as a broken upstream list -- sending
        the operator to look at a file that was perfectly fine.
        """
        entries = document.get("players")
        if not isinstance(entries, list):
            raise SyncError(f"{what} has no 'players' array")

        index: dict[str, dict[str, Any]] = {}
        skipped = 0
        for entry in entries:
            canonical = normalize_steamid(entry.get("steamid")) if isinstance(entry, dict) else None
            if canonical is None:
                skipped += 1
                continue
            index.setdefault(canonical, entry)
        return cls(by_steamid=index, total=len(entries), skipped=skipped)


def added_steamids(previous: HackerpoliceIndex, current: HackerpoliceIndex) -> set[str]:
    """SteamIDs that are in the current list but were not in the previous snapshot."""
    return current.by_steamid.keys() - previous.by_steamid.keys()


def removed_steamids(previous: HackerpoliceIndex, current: HackerpoliceIndex) -> set[str]:
    """SteamIDs that were in the previous snapshot but are gone now.

    This set -- and only this set -- may be demoted in the Garou database.
    IDs absent from both lists (e.g. manually added cheaters) are not in it,
    and IDs added upstream since the snapshot are not either.
    """
    return previous.by_steamid.keys() - current.by_steamid.keys()


def _parse_document(raw: bytes, source: str) -> dict[str, Any]:
    """Parse raw bytes as a playerlist document, raising SyncError."""
    try:
        document = strict_json_loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
        # ValueError: e.g. a JSON number beyond Python's int-parsing limit.
        raise SyncError(f"{_redact_source(source)} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SyncError(f"{_redact_source(source)} does not contain a JSON object")
    return document


def load_snapshot(path: Path) -> tuple[HackerpoliceIndex, bytes] | None:
    """Load the previous hackerpolice snapshot, or ``None`` if there is none.

    Returns the index and the file's raw bytes. A missing snapshot is not an
    error: it just means "no baseline yet", so no removal can be proven and
    demotion must be skipped for this run. A snapshot that exists but is
    unreadable IS an error -- guessing here could demote the wrong players,
    so the run aborts instead. The file is read once, as bytes, and the index
    is parsed from exactly the bytes handed back.
    """
    try:
        # Resolve first so a self-referential symlink is not mistaken for a
        # missing baseline. Path.exists() can return False for ELOOP; treating
        # that as "no snapshot" would silently disable demotion and let the
        # writer replace the link with a file.
        # strict=False still permits a genuinely dangling link, whose final
        # target may legitimately be created by the subsequent snapshot write.
        path.resolve(strict=False)
        # An unencodable surrogate cannot name a filesystem entry at all; keep
        # the existing "no snapshot" behavior for that impossible path.
        # (Surrogate-escape code points are still representable and continue
        # through normal filesystem handling.)
        # Use stat() rather than exists(): newer pathlib versions may turn any
        # OSError into False, which would mistake a permission/IO failure for a
        # missing baseline and could let the next write replace it.
        path.stat()
    except FileNotFoundError:
        return None
    except UnicodeError:
        return None
    except RuntimeError as exc:
        raise SyncError(f"cannot read {display_path(path)}: symbolic link loop") from exc
    except (OSError, ValueError) as exc:
        raise SyncError(f"cannot read {display_path(path)}: {error_reason(exc)}") from exc
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise SyncError(f"cannot read {display_path(path)}: {error_reason(exc)}") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise SyncError(f"{display_path(path)} is larger than the {MAX_FILE_BYTES // (1024 * 1024)} MiB safety limit")
    document = _parse_document(raw, str(path))
    return HackerpoliceIndex.build(document, what=f"the previous snapshot {display_path(path)}"), raw


# Query parameters whose VALUE is a credential. GitHub's own raw URLs, S3
# presigned URLs (?X-Amz-Signature=..., ?X-Amz-Credential=...) and most token
# schemes carry the secret in the query rather than in the userinfo -- and this
# URL is printed in the report, i.e. in the pull request body and the job
# summary, which are public in a public repository. The NAME is matched, never
# the value: a parameter called "ref" keeps its value, so the line still says
# which file was fetched.
#
# These are SUBSTRING matches on purpose. An exact-name list was a leak: it
# knew "token" but not GitLab's "private_token", "refresh_token", "auth_token",
# "secret_key", "pass", "bearer" or Google's "X-Goog-Signature", so a
# credential in one of those sailed into a public pull request. Matching a
# fragment over-redacts the occasional harmless parameter (?keyword=...), which
# costs a reader nothing, while a missed secret cannot be undone.
_SECRET_QUERY_PARAM = re.compile(
    r"token|secret|passw|^pass$|pass$|auth|credential|session|sid|bearer|jwt|nonce|state|ticket|"
    r"apikey|api[_-]?key|sig|hmac|saml|key|x-amz|x-goog|code",
    re.IGNORECASE,
)
_PERCENT_ESCAPE = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE | re.ASCII)


def _normalised_query_name(name: str) -> str | None:
    """Remove invisible/control/separator characters before checking a key name.

    URL-decoding can reveal a tab, newline, zero-width character or other
    Unicode format character embedded in a sensitive name (``to%0Aken``).
    Some servers normalize these before looking up credentials; redaction must
    use at least as broad a normalization so encoding cannot bypass it.
    """
    decoded = name
    # The first parse_qsl/unquote_plus pass has already happened for URL pairs.
    # A few consumers decode keys more than once, so inspect a small bounded
    # number of additional percent-encoding layers rather than allowing
    # ``to%250Aken`` to disguise the same key as ``to\nken``.
    for _ in range(_MAX_NESTED_URL_DEPTH):
        next_decoded = urllib.parse.unquote(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    if _PERCENT_ESCAPE.search(decoded):
        # A later consumer may decode more layers. An unresolved escape in a
        # parameter name is ambiguous, so treat it as sensitive rather than
        # risking a token hidden just beyond our inspection budget.
        return None
    return "".join(char for char in decoded if unicodedata.category(char)[0] not in {"C", "Z"}).casefold()


def _has_sensitive_query_name(name: str) -> bool:
    """Fail closed if a parameter name is secret-looking or too encoded to inspect."""
    normalized = _normalised_query_name(name)
    return normalized is None or _SECRET_QUERY_PARAM.search(normalized) is not None


REDACTED = "REDACTED"

# Lone UTF-16 surrogates. ``argv`` decodes bytes that are not valid UTF-8 with
# ``surrogateescape``, so ``--source $'https://host/?token=\xff'`` arrives
# holding ``\udcff``. ``urllib.parse.urlencode`` cannot encode that (it raises
# UnicodeEncodeError, which nothing above catches -- the run would die with a
# traceback instead of refusing cleanly), and the same character cannot be
# written to the report. They become U+FFFD, exactly as the report renders
# them, so a redacted URL is always printable.
_SURROGATES = re.compile(r"[\ud800-\udfff]")


def _no_surrogates(value: str) -> str:
    """Replace lone UTF-16 surrogates so the value can always be encoded."""
    return _SURROGATES.sub("\ufffd", value)


# Line terminators, bidi overrides and invisible format characters must never
# appear raw in a URL that is printed. ``--source`` can carry any byte, and this
# URL is written to the CI log and pull request: controls can forge a line,
# bidi can reverse its apparent meaning, and invisible characters can disguise
# a different target. Percent-encoding keeps it faithful and unambiguous.
_URL_CONTROLS = re.compile(
    r"[\x00-\x1f\x7f\x85\u00ad\u061c\u180e\u200b\u200e-\u200f\u2028-\u202e"
    r"\u2060-\u2064\u2066-\u2069\ufeff\ufff9-\ufffb\U000e0000-\U000e007f]"
)
_URL_IN_TEXT = re.compile(r"(?:(?:[a-z][a-z0-9+.-]*:)?//)[^\s<>\"'`]+", re.IGNORECASE | re.ASCII)
# A malformed URL embedded in prose may be split across lines. The normal URL
# scanner stops at whitespace, so separately redact query secrets even when a
# newline split the URL just before its parameter.
_QUERY_PARAM_IN_TEXT = re.compile(
    r"(?P<separator>[?&#;])"
    r"(?P<name>(?:[^\s?&#;=<>\"'`]|[\r\n\t])+)="
    # urllib strips CR/LF/TAB from an embedded URL before parsing it. Treat
    # those same controls as invisible inside a credential name/value here, or
    # a prose URL split at that byte can expose the rest of the secret.
    r"(?P<value>[^&;#\s<>\"'`]*(?:[\r\n\t]+[^&;#\s<>\"'`]+)*)"
)
# urlsplit() ignores raw newlines while parsing, but the prose scanner treats
# them as boundaries. Catch a userinfo password split by one before scanning.
_MULTILINE_USERINFO_IN_TEXT = re.compile(
    r"(?P<prefix>(?:[a-z][a-z0-9+.-]*:)?//)[^/@?#<>\"'`]*\s+[^/@?#<>\"'`]*@",
    re.IGNORECASE | re.ASCII,
)


def _one_line(value: str) -> str:
    """Percent-encode line-breaking, bidi and invisible characters in a URL."""
    return _URL_CONTROLS.sub(lambda match: "".join(f"%{byte:02X}" for byte in match.group().encode("utf-8")), value)


# How much of a URL is ever shown. Every URL that reaches a log line or the
# report goes through redact_url(), so this is the single bound on how big that
# line can get: a presigned URL is legitimately 1-2 kB, and a 100 kB one used to
# push the report past its byte budget, which hard-truncates the body and drops
# the closing sentence the report exists to publish. 2,048 is far beyond any
# real fetch URL and still short enough that the budget cannot be reached.
MAX_URL_DISPLAY_CHARS = 2048


def _query_pairs(value: str) -> list[tuple[str, str]]:
    """Parse bounded URL parameters, treating legacy semicolons as separators too.

    Some servers still accept ``;`` as a form-query delimiter even though
    ``parse_qsl`` only splits on ``&`` by default. Treating both as separators
    prevents a value such as ``ref=main;access_token=...`` from bypassing the
    credential-name check. The URL-length guard bounds this parser's work.
    """
    if ";" in value:
        value = value.replace(";", "&")
    return urllib.parse.parse_qsl(value, keep_blank_values=True, max_num_fields=_MAX_URL_PARSE_CHARS + 1)


def _redact_nested_url(value: str, depth: int) -> str:
    """Redact credentials inside a URL nested in a query/fragment value.

    Query parsers decode one percent-encoding layer. Inspect a few more layers
    too, because an encoded nested URL can otherwise hide its delimiters until
    a downstream consumer decodes it again.
    """
    candidate = value

    def has_url_markers(text: str) -> bool:
        return any(marker in text for marker in ("://", "//", "?", "#"))

    if not has_url_markers(candidate):
        for _ in range(_MAX_NESTED_URL_DEPTH):
            decoded = urllib.parse.unquote(candidate)
            if decoded == candidate:
                break
            candidate = decoded
            if has_url_markers(candidate):
                break

    if not has_url_markers(candidate):
        if _PERCENT_ESCAPE.search(candidate):
            # A nested URL can be encoded more times than this bounded scan.
            # Do not echo the still-encoded value: a downstream decoder could
            # reveal credentials that we have not inspected.
            return "[nested URL omitted: too deep to inspect safely]"
        return value
    if depth >= _MAX_NESTED_URL_DEPTH:
        # Fail closed: never echo the nested value if its depth exceeds the
        # inspection budget, even if its secret is hidden another level down.
        return "[nested URL omitted: too deep to inspect safely]"
    return _redact_urls_in_text(candidate, depth + 1)


def _sanitised_pairs(items: list[tuple[str, str]], depth: int) -> tuple[list[tuple[str, str]], bool]:
    """Replace secret values and redact nested URLs, reporting whether anything changed.

    Shared by the query string and the fragment, which carry the same kind of
    parameter. Sanitised before ``urlencode``: one lone surrogate in a name or a
    value would raise instead of redacting. The change flag lets ordinary URLs
    keep their original spelling and encoding untouched. ``depth`` bounds
    recursive URL nesting.
    """
    safe_items: list[tuple[str, str]] = []
    changed = False
    for name, value in items:
        safe_name = _no_surrogates(name)
        safe_value = REDACTED if _has_sensitive_query_name(name) else _no_surrogates(_redact_nested_url(value, depth))
        changed |= safe_name != name or safe_value != value
        safe_items.append((safe_name, safe_value))
    return safe_items, changed


def _redact_url(url: str, depth: int) -> str:
    """Hide credentials in a URL before it is logged or published.

    A ``--source`` or upstream proof URL may carry a token, either in the
    userinfo (``https://user:token@…``) or in a query parameter
    (``…?token=…``, ``…?X-Amz-Signature=…``), and this bot's output ends up in
    logs and in a public pull request body: the scheme/host/path are enough to
    debug a fetch, the secret is not. Everything else is left exactly as it was,
    so the line still identifies what was fetched. Oversized URLs are omitted
    before parsing: even a giant path need not be scanned to display a truncated
    link, and a giant query could make ``parse_qsl`` allocate millions of pairs.
    """
    if len(url) > _MAX_URL_PARSE_CHARS:
        return "[URL omitted: too long to inspect safely]"
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        # Parsing failed before userinfo/query redaction could run. Never fall
        # back to echoing the raw input: it may hold credentials in either.
        return "[malformed URL omitted]"

    netloc = parts.netloc
    if parts.username is not None:
        host = parts.hostname or ""
        # urlsplit.hostname omits brackets around IPv6 literals; restore them
        # before rebuilding netloc or the redacted URL is malformed (and can
        # be misread as a host with a port).
        if ":" in host:
            host = f"[{host}]"
        try:
            port = parts.port
        except ValueError:  # a malformed port must not crash the error path
            port = None
        if port is not None:
            host = f"{host}:{port}"
        netloc = host

    query = parts.query
    if query:
        safe_items, changed = _sanitised_pairs(_query_pairs(query), depth)
        if changed:
            query = urllib.parse.urlencode(safe_items)

    # A FRAGMENT carries credentials too: OAuth's implicit flow puts them there
    # (``https://host/callback#access_token=...&state=...``), and this URL is
    # published in the pull request. Only query-shaped fragments are touched --
    # "#L10" and "#section-2" are not pairs and stay exactly as they were.
    fragment = parts.fragment
    if fragment and "=" in fragment:
        safe_items, changed = _sanitised_pairs(_query_pairs(fragment), depth)
        if changed:
            fragment = urllib.parse.urlencode(safe_items)

    if netloc == parts.netloc and query == parts.query and fragment == parts.fragment:
        shown = url  # nothing to hide: hand back the caller's string untouched
    else:
        shown = urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, query, fragment))
    # Always encodable and always one line, whatever the caller passed.
    shown = _one_line(_no_surrogates(shown))
    return shown if len(shown) <= MAX_URL_DISPLAY_CHARS else shown[:MAX_URL_DISPLAY_CHARS] + "…"


def redact_url(url: str) -> str:
    """Hide credentials in a URL before it is logged or published."""
    return _redact_url(url, 0)


def _redact_url_occurrence(match: re.Match[str], depth: int) -> str:
    """Redact one URL embedded in prose, preserving sentence punctuation."""
    value = match.group()
    end = len(value)
    while end and value[end - 1] in ".,;:!?":
        end -= 1
    for closer, opener in ((")", "("), ("]", "["), ("}", "{")):
        balance = value[:end].count(closer) - value[:end].count(opener)
        while end and value[end - 1] == closer and balance > 0:
            end -= 1
            balance -= 1
    return _redact_url(value[:end], depth) + value[end:]


def _redact_multiline_userinfo(match: re.Match[str]) -> str:
    """Replace userinfo that crosses a line break while embedded in prose."""
    return f"{match.group('prefix')}REDACTED@"


def _redact_text_query_parameter(match: re.Match[str]) -> str:
    """Redact secret-looking query pairs even if malformed URL text is split."""
    name = urllib.parse.unquote_plus(_no_surrogates(match.group("name")))
    if not _has_sensitive_query_name(name):
        return match.group()
    value = match.group("value")
    end = len(value)
    while end and value[end - 1] in ".,:!?":
        end -= 1
    for closer, opener in ((")", "("), ("]", "["), ("}", "{")):
        balance = value[:end].count(closer) - value[:end].count(opener)
        while end and value[end - 1] == closer and balance > 0:
            end -= 1
            balance -= 1
    return f"{match.group('separator')}{match.group('name')}=REDACTED{value[end:]}"


def _redact_urls_in_text(text: str, depth: int) -> str:
    """Redact text while carrying the current nested-URL depth."""
    if len(text) > _MAX_URL_PARSE_CHARS:
        return "[URL omitted: too long to inspect safely]"
    text = _MULTILINE_USERINFO_IN_TEXT.sub(_redact_multiline_userinfo, text)
    # Avoid parsing arbitrary prose as a URL: urlsplit can treat "Context:" as
    # a scheme and normalize its casing. A standalone query/fragment-shaped
    # value is still passed through the regular redactor; embedded URLs are
    # handled one at a time so surrounding prose stays byte-for-byte intact.
    stripped = text.strip()
    if not any(char.isspace() for char in stripped) and ("?" in stripped or "#" in stripped):
        text = _redact_url(text, depth)
    text = _URL_IN_TEXT.sub(lambda match: _redact_url_occurrence(match, depth), text)
    return _QUERY_PARAM_IN_TEXT.sub(_redact_text_query_parameter, text)


def redact_urls_in_text(text: str) -> str:
    """Redact URL credentials even when a URL is embedded in untrusted prose."""
    return _redact_urls_in_text(text, 0)


def _redact_source(value: str) -> str:
    """Redact a standalone source URL, or embedded URLs in a path/message.

    A direct URL can contain control characters that ``urlsplit`` removes
    before parsing (including a newline before a secret query parameter), so
    it must go through ``redact_url`` as a whole. Local paths and other prose
    may contain embedded URLs, for which ``redact_urls_in_text`` preserves the
    surrounding text.
    """
    if http_scheme(value) or value[:8].casefold() == "https://" or value[:7].casefold() == "http://":
        return redact_url(value)
    return _one_line(_no_surrogates(redact_urls_in_text(value)))


def _too_large(source: str) -> SyncError:
    """The one error used wherever a source exceeds the download budget."""
    return SyncError(
        f"{_redact_source(source)} is larger than the {MAX_SOURCE_BYTES // (1024 * 1024)} MiB safety limit"
    )


def _safe_fetch_error(exc: Exception) -> str:
    """Describe a fetch failure without echoing server-controlled text.

    HTTP reason phrases, protocol exceptions and malformed-URL errors can
    contain arbitrary response text or the original credential-bearing URL.
    Only show stable local facts (the HTTP status, or a short read's byte
    counts); never interpolate those exception messages into CI logs.
    """
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP status {exc.code}"
    if isinstance(exc, _ShortRead):
        return str(exc)  # generated locally from byte counts, not response text
    if isinstance(exc, http.client.IncompleteRead):
        return "incomplete HTTP response"
    if isinstance(exc, (ValueError, http.client.HTTPException)):
        return "malformed URL or HTTP response"
    if isinstance(exc, urllib.error.URLError):
        return "network error"
    if isinstance(exc, OSError):
        return "network I/O error"
    return type(exc).__name__


def _log_retry(attempt: int, exc: Exception) -> None:
    """Say, at debug level, why an attempt failed and that another follows."""
    LOGGER.debug(
        "  attempt %d of %d failed (%s); retrying in %d s.",
        attempt,
        FETCH_ATTEMPTS,
        _safe_fetch_error(exc),
        RETRY_BACKOFF_SECONDS * attempt,
    )


def _fetch_bytes(url: str) -> bytes:
    """GET an HTTPS URL and return the body bytes VERBATIM, retrying transient failures.

    Permanent client errors (4xx other than 429) are not retried -- they
    will fail identically on every attempt, and the caller falls back to
    the next source instead.

    Only ``https://`` is fetched (bytes over plain HTTP are not trustworthy,
    and this file decides promotions); a local path is the offline option.
    """
    if len(url) > _MAX_URL_PARSE_CHARS:
        raise SyncError(f"refusing to fetch a URL longer than {_MAX_URL_PARSE_CHARS:,} characters")
    if http_scheme(url) != "https":
        # Plain HTTP is refused even when the operator passes the URL
        # explicitly: this file decides who gets promoted, so its transport is
        # part of the trust model (a network attacker could otherwise inject
        # entries). Local mirrors stay supported as a path.
        raise SyncError(f"refusing to fetch a non-HTTPS URL (use https:// or a local path): {redact_url(url)}")
    last_error: Exception | None = None
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        LOGGER.debug("Fetching %s (attempt %d of %d).", redact_url(url), attempt, FETCH_ATTEMPTS)
        try:
            headers = {"User-Agent": USER_AGENT}
            # Hostname comparison, not a substring match: a look-alike URL
            # such as https://api.github.com.example.invalid/ must not be
            # treated as the GitHub API.
            parsed = urllib.parse.urlparse(url)
            if parsed.hostname == "api.github.com":
                # Blobs answer with the file itself -- exactly the bytes the
                # snapshot must replicate. Contents endpoints must answer
                # with JSON instead: "vnd.github.raw" is refused outright for
                # files over 1 MB, which would kill the fallback before the
                # sha-based blob fetch ever got a chance to run.
                headers["Accept"] = (
                    "application/vnd.github.raw" if "/git/blobs/" in parsed.path else "application/vnd.github+json"
                )
            request = urllib.request.Request(url, headers=headers)
            # Scheme is restricted to HTTP(S) above (Bandit B310); the opener
            # only adds the HTTPS-downgrade guard.
            with _OPENER.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:  # nosec B310
                # Reject an oversized body before downloading it when the
                # server says how big it is.
                declared = _declared_length(response)
                if declared is not None and declared > MAX_SOURCE_BYTES:
                    raise _too_large(url)
                body: bytes = response.read(MAX_SOURCE_BYTES + 1)
                # A chunked body has no declared length, and its own decoder
                # already raises when the stream ends early.
                chunked = bool(getattr(response, "chunked", False))
            if len(body) > MAX_SOURCE_BYTES:
                raise _too_large(url)
            if declared is not None and not chunked and len(body) != declared:
                # The connection closed before the body did; retry it.
                raise _ShortRead(f"received {len(body):,} of {declared:,} bytes")
            return body
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code != 429 and not 500 <= exc.code < 600:
                break  # permanent: don't waste attempts, fall back sooner
            if attempt < FETCH_ATTEMPTS:
                _log_retry(attempt, exc)
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
        except OSError as exc:  # URLError, socket timeouts, resets, ...
            last_error = exc
            if attempt < FETCH_ATTEMPTS:
                _log_retry(attempt, exc)
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
        except http.client.IncompleteRead as exc:
            # A CHUNKED body that ended early: transient, like a reset.
            last_error = exc
            if attempt < FETCH_ATTEMPTS:
                _log_retry(attempt, exc)
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
        except (ValueError, http.client.HTTPException) as exc:
            # A malformed URL (bad IPv6 literal, control characters, ...)
            # fails identically on every attempt and every machine: report
            # it as a fetch failure so the caller falls back / exits cleanly
            # instead of crashing with a traceback.
            raise SyncError(f"could not fetch {redact_url(url)}: {_safe_fetch_error(exc)}") from exc
    reason = _safe_fetch_error(last_error) if last_error is not None else "unknown network error"
    raise SyncError(f"could not fetch {redact_url(url)}: {reason}")


def _read_bytes(source: str) -> bytes:
    """Return the raw bytes of an HTTP(S) URL or a local path, raising SyncError.

    The size limit is enforced on the bytes ACTUALLY READ, not on the size the
    filesystem reports: a file can grow between the two calls, and a special
    file (a device, a fifo) reports 0 while yielding endless data. Reading at
    most ``MAX_SOURCE_BYTES + 1`` bytes makes the local path obey exactly the
    same budget as a download.
    """
    if http_scheme(source):
        return _fetch_bytes(source)
    LOGGER.debug("Reading %s from disk.", _redact_source(source))
    try:
        with Path(source).open("rb") as handle:
            raw = handle.read(MAX_SOURCE_BYTES + 1)
    except (OSError, ValueError) as exc:
        # ValueError: a path the OS cannot encode (embedded NUL, lone
        # surrogate) -- a refusal like any other unreadable source.
        raise SyncError(f"cannot read {_redact_source(source)}: {error_reason(exc)}") from exc
    if len(raw) > MAX_SOURCE_BYTES:
        raise _too_large(source)
    return raw


def _unwrap_github_contents_envelope(document: dict[str, Any]) -> bytes | None:
    """Decode a GitHub Contents/Blob API envelope to the file bytes it wraps.

    Blob endpoints return the file itself, but a Contents/Blob response can
    also be a JSON envelope with the file base64-encoded in ``content``.
    Unwrapping it
    keeps the API fallback usable AND keeps the snapshot an exact copy of
    the file (the envelope itself is never written anywhere).
    """
    content = document.get("content")
    if document.get("encoding") != "base64" or not isinstance(content, str):
        return None
    try:
        decoded = base64.b64decode(content, validate=False)
    except (binascii.Error, ValueError):
        return None
    # The Contents API omits the content for files over ~1 MB (this list is
    # larger): an empty decode is not a usable file, let the caller fall
    # back to download_url / the Git blob endpoint instead.
    return decoded or None


def _github_blob_url(source: str, sha: Any) -> str | None:
    """Git Blob API URL for a GitHub Contents API response, or ``None``.

    The Contents API stops returning ``content`` for files over ~1 MB (this
    list is ~1.9 MB), so the blob endpoint is the only API strategy that
    still works -- and the only one that does not depend on
    ``raw.githubusercontent.com`` being reachable, which makes it a genuinely
    independent fallback rather than a second link to the same host.
    """
    if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40,64}", sha) is None:
        return None
    parsed = urllib.parse.urlparse(source)
    if parsed.hostname != "api.github.com":
        return None
    repository, separator, _ = parsed.path.partition("/contents/")
    if not separator or not repository.startswith("/repos/"):
        return None
    return f"https://api.github.com{repository}/git/blobs/{sha}"


def _document_from(raw: bytes, source: str) -> tuple[dict[str, Any], bytes] | None:
    """Parse ``raw`` and return it only when it is a playerlist document."""
    try:
        document = _parse_document(raw, source)
    except SyncError:
        return None
    return (document, raw) if isinstance(document.get("players"), list) else None


def _resolve_indirect_document(document: dict[str, Any], source: str) -> tuple[dict[str, Any], bytes] | None:
    """Resolve a response that only points at the playerlist file.

    Tried in order: the envelope's inline base64 ``content``, its
    ``download_url``, and the Git Blob API URL built from its ``sha``. Every
    strategy yields the file's OWN bytes, so the snapshot stays an exact
    replica regardless of which one answers.
    """
    inline = _unwrap_github_contents_envelope(document)
    if inline is not None:
        resolved = _document_from(inline, source)
        if resolved is not None:
            return resolved

    candidates: list[str] = []
    download_url = document.get("download_url")
    # download_url comes from the fetched document itself, so unlike an
    # operator-supplied --source it is untrusted: HTTPS only, never a local
    # path or a plaintext URL.
    if isinstance(download_url, str) and http_scheme(download_url) == "https":
        candidates.append(download_url)
    blob_url = _github_blob_url(source, document.get("sha"))
    if blob_url is not None:
        candidates.append(blob_url)

    for candidate in candidates:
        try:
            body = _read_bytes(candidate)
            parsed = _parse_document(body, candidate)
        except SyncError:
            continue
        # A blob response may itself be a base64 envelope instead of the file.
        for payload in (body, _unwrap_github_contents_envelope(parsed)):
            if payload is None:
                continue
            resolved = _document_from(payload, source)
            if resolved is not None:
                return resolved
    return None


def _has_usable_steamids(document: dict[str, Any]) -> bool:
    """True when at least one entry carries a SteamID this tool can normalise."""
    players = document.get("players")
    if not isinstance(players, list):
        return False
    return any(isinstance(entry, dict) and normalize_steamid(entry.get("steamid")) is not None for entry in players)


def load_first_available_raw(sources: Iterable[str]) -> tuple[dict[str, Any], str, bytes]:
    """Return the parsed document, source name, and RAW bytes of the first usable source.

    The raw bytes are what gets written to the snapshot file, so the
    snapshot is an exact replica of the original upstream file -- same
    bytes, guaranteed by construction: nothing is ever decoded, parsed and
    re-serialised on the way to the snapshot.
    """
    failures: list[str] = []
    for source in sources:
        LOGGER.debug("Trying source %s.", _redact_source(source))
        try:
            raw = _read_bytes(source)
            document = _parse_document(raw, source)
        except SyncError as exc:
            LOGGER.debug("  unusable: %s", exc)
            failures.append(str(exc))
            continue
        if not isinstance(document.get("players"), list):
            resolved = _resolve_indirect_document(document, source)
            if resolved is None:
                failures.append(
                    f"{_redact_source(source)}: no 'players' array, and neither inline content, a usable HTTPS "
                    "download_url nor a Git blob could be resolved"
                )
                continue
            document, raw = resolved
        if not _has_usable_steamids(document):
            # A 200 with an empty or all-garbage list is a broken mirror, not
            # "nobody is listed": try the next source instead of stopping here,
            # where a healthy fallback could still answer.
            failures.append(f"{_redact_source(source)}: no usable SteamIDs in its 'players' array")
            continue
        return document, source, raw

    raise SyncError("cannot load the Vorobey hackerpolice list:\n  " + "\n  ".join(failures))
