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
import contextlib
import html
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

from playerlist import (
    CREDENTIAL_NAME_MARKERS,
    MAX_FILE_BYTES,
    SURROGATE_RE,
    display_path,
    error_reason,
    fold_name_for_matching,
    normalize_steamid,
    read_bounded_regular_file,
    redact_diagnostic_text,
    strict_json_loads,
)

SOURCE_REPO_URL = "https://github.com/Nocrex/Tom/blob/main/playerlist.vorobey-hackerpolice.json"

# Try sources in order; the first URL serves the original file's raw bytes.
DEFAULT_SOURCES: tuple[str, ...] = (
    "https://raw.githubusercontent.com/Nocrex/Tom/refs/heads/main/playerlist.vorobey-hackerpolice.json",
    "https://github.com/Nocrex/Tom/raw/main/playerlist.vorobey-hackerpolice.json",
    "https://api.github.com/repos/Nocrex/Tom/contents/playerlist.vorobey-hackerpolice.json",
)

USER_AGENT = "Garou3299-tf2bd-database-vorobey-hackerpolice-sync (+https://github.com/Garou3299/tf2bd-database)"

FETCH_TIMEOUT_SECONDS = 30
FETCH_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 2

# Bound URL parsing and request targets; reject oversized URLs before parsing.
_MAX_URL_PARSE_CHARS = 4_096
# Bound nested URL inspection to prevent excessive recursion.
_MAX_NESTED_URL_DEPTH = 8

# Cap fetched files and snapshots to bound memory use.
MAX_SOURCE_BYTES = MAX_FILE_BYTES

__all__ = [
    "DEFAULT_SOURCES",
    "MAX_URL_DISPLAY_CHARS",
    "REDACTED",
    "SOURCE_REPO_URL",
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


# Debug fetch details only in verbose mode; redact source URLs in every message.
LOGGER = logging.getLogger("vorobey_sources")


class _ShortReadError(OSError):
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
        # Classify oversized URLs from the prefix without scanning untrusted input.
        if value[:8].casefold() == "https://":
            return "https"
        if value[:7].casefold() == "http://":
            return "http"
        return ""
    try:
        scheme = urllib.parse.urlsplit(value).scheme.lower()
    except ValueError:  # Invalid URLs have no usable HTTP scheme.
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


# Shared opener enforces HTTPS-only redirects.
_OPENER = urllib.request.build_opener(_HttpsOnlyRedirectHandler)


def _declared_length(response: object) -> int | None:
    """Usable ``Content-Length`` of a response, or ``None`` when absent/invalid."""
    response_headers = getattr(response, "headers", None)
    declared = response_headers.get("Content-Length") if response_headers is not None else None
    # Accept only ASCII digits in Content-Length.
    if isinstance(declared, str) and declared.isascii() and declared.isdigit():
        # Bound the digits before int(): a hostile header with thousands of
        # digits would otherwise trip Python's int-conversion limit and turn a
        # malformed header into a ValueError traceback. Ten digits is ~10 GB,
        # far beyond the byte cap, so a longer value is simply "too large".
        significant = declared.lstrip("0") or "0"
        return int(significant) if len(significant) <= 10 else MAX_SOURCE_BYTES + 1
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
    """Parse raw bytes as a playerlist document, raising SyncError.

    The bytes are decoded here, once, so the error can name the actual
    problem: handing raw bytes to ``json`` reports any non-UTF-8 file as
    "not valid JSON", which sends the operator looking for a syntax error in
    a file that is actually in the wrong encoding. UTF-8 with or without a
    BOM is accepted, matching ``playerlist.load``.
    """
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SyncError(f"{_redact_source(source)} is not valid UTF-8: {exc.reason} at byte {exc.start:,}") from exc
    try:
        document = strict_json_loads(text)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        # ValueError also covers Python's integer digit limit; duplicate-key errors may include untrusted keys.
        detail = _one_line(_no_surrogates(redact_urls_in_text(str(exc))))
        raise SyncError(f"{_redact_source(source)} is not valid JSON: {detail}") from exc
    if not isinstance(document, dict):
        raise SyncError(f"{_redact_source(source)} does not contain a JSON object")
    return document


def _display_path(path: Path) -> str:
    """Redact a path before clipping it for diagnostics."""
    return display_path(path)


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
        # Resolve symlinks without requiring the final target to exist; this also detects loops.
        path.resolve(strict=False)
        # Unencodable paths cannot name a snapshot; preserve the missing-file behavior.
        # Use stat(), not exists(), so permission and I/O errors are not treated as missing.
        path.stat()
    except FileNotFoundError:
        return None
    except UnicodeError:
        return None
    except RuntimeError as exc:
        raise SyncError(f"cannot read {_display_path(path)}: symbolic link loop") from exc
    except (OSError, ValueError) as exc:
        raise SyncError(f"cannot read {_display_path(path)}: {error_reason(exc)}") from exc
    try:
        raw = read_bounded_regular_file(path, MAX_FILE_BYTES)
    except (OSError, ValueError) as exc:
        raise SyncError(f"cannot read {_display_path(path)}: {error_reason(exc)}") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise SyncError(f"{_display_path(path)} is larger than the {MAX_FILE_BYTES // (1024 * 1024)} MiB safety limit")
    document = _parse_document(raw, str(path))
    return HackerpoliceIndex.build(document, what=f"the previous snapshot {_display_path(path)}"), raw


# Match credential-like parameter names broadly; false positives are safer than
# leaks. The vocabulary is shared with the diagnostic redactor so the two cannot
# drift apart: no case-folding limit here, because a query name reaches us
# straight off the wire and ``KEY`` spelled with a Kelvin sign must still match.
_SECRET_QUERY_PARAM = re.compile(CREDENTIAL_NAME_MARKERS, re.IGNORECASE)
_PERCENT_ESCAPE = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE | re.ASCII)
_SAFE_QUERY_NAME = re.compile(r"[A-Za-z0-9_.-]+", re.ASCII)


def _normalized_query_name(name: str) -> str | None:
    """Remove invisible/control/separator characters before checking a key name.

    URL-decoding can reveal a tab, newline, zero-width character or other
    Unicode format character embedded in a sensitive name (``to%0Aken``).
    Some servers normalize these before looking up credentials; redaction must
    use at least as broad a normalization so encoding cannot bypass it.
    """
    decoded = name
    # Inspect bounded additional percent/HTML decoding layers for obfuscated keys and delimiters.
    for _ in range(_MAX_NESTED_URL_DEPTH):
        next_decoded = _html_unescape_bounded(urllib.parse.unquote(decoded))
        if next_decoded is None:
            return None
        if next_decoded == decoded:
            break
        decoded = next_decoded
    if _PERCENT_ESCAPE.search(decoded):
        # Fail closed on unresolved escapes; another decoder could expose a credential key.
        return None
    return fold_name_for_matching(decoded)


def _has_sensitive_query_name(name: str) -> bool:
    """Fail closed if a parameter name is secret-looking or too encoded to inspect."""
    normalized = _normalized_query_name(name)
    return normalized is None or _SECRET_QUERY_PARAM.search(normalized) is not None


REDACTED = "REDACTED"


def _no_surrogates(value: str) -> str:
    """Replace lone UTF-16 surrogates so the value can always be encoded."""
    return SURROGATE_RE.sub("\ufffd", value)


def _html_unescape_bounded(value: str) -> str | None:
    """Decode a bounded number of nested HTML character-reference layers."""
    for _ in range(_MAX_NESTED_URL_DEPTH):
        decoded = html.unescape(value)
        if decoded == value:
            return value
        value = decoded
    # Omit values that remain encoded after the inspection limit.
    return None if html.unescape(value) != value else value


# Neutralize control and format characters in URLs before logging or publishing.
_URL_IN_TEXT = re.compile(r"(?:(?:[a-z][a-z0-9+.-]*:)?//)[^\s<>\"'`]+", re.IGNORECASE | re.ASCII)
# A malformed HTTP URL can leave userinfo in its path instead of its authority.
_HTTP_URL_WITH_AT_IN_TEXT = re.compile(r"https?:[^\s<>\"'`]*@[^\s<>\"'`]+", re.IGNORECASE | re.ASCII)
# Find URL schemes whose colon (or colon and slashes) are percent-encoded, including repeated encoding layers.
_ENCODED_HTTP_URL_MARKER = re.compile(r"https?(?:%(?:25)*3a|:(?:%(?:25)*2f))", re.IGNORECASE | re.ASCII)
# Scan query parameters separately when malformed URLs split at whitespace or controls.
_QUERY_PARAM_IN_TEXT = re.compile(
    r"(?P<separator>[?&#;])"
    # Include separators ignored by query-key normalization.
    r"(?P<name>[^?&#;=]+)="
    # Extend values to the next delimiter so secret suffixes are not exposed.
    r"(?P<value>[^&;#]*)"
)
# Catch userinfo split by line breaks; urlsplit ignores raw newlines.
# The run before the whitespace must exclude whitespace itself. Spelling it
# ``[^/@?#<>"'`]*\s+[^/@?#<>"'`]*@`` instead lets whitespace match either the
# class or the ``\s+``, so a run of blanks with no closing ``@`` costs cubic
# time -- 2,000 characters took 42 seconds, and ``proof`` strings arrive from
# the upstream list. Anchoring on the first whitespace keeps the matched span
# identical while leaving only one way to divide the text.
_MULTILINE_USERINFO_IN_TEXT = re.compile(
    r"(?P<prefix>(?:[a-z][a-z0-9+.-]*:)?//)[^/@?#<>\"'`\s]*\s[^/@?#<>\"'`]*@",
    re.IGNORECASE | re.ASCII,
)


def _one_line(value: str) -> str:
    """Percent-encode controls, separators, and every Unicode format character.

    Format characters include zero-width joiners/non-joiners. They are kept in
    player names where they can be meaningful, but must be visible when they
    appear in a URL target. ``_no_surrogates`` runs before this function, so
    every encoded character has a valid UTF-8 representation.
    """
    pieces: list[str] = []
    for char in value:
        if unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"}:
            pieces.extend(f"%{byte:02X}" for byte in char.encode("utf-8"))
        else:
            pieces.append(char)
    return "".join(pieces)


# Bound every URL included in logs or reports.
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
        return any(marker in text for marker in ("://", "//", "?", "#")) or (
            _HTTP_URL_WITH_AT_IN_TEXT.search(text) is not None
        )

    if not has_url_markers(candidate):
        for _ in range(_MAX_NESTED_URL_DEPTH):
            decoded = _html_unescape_bounded(urllib.parse.unquote(candidate))
            if decoded is None:
                return "[nested URL omitted: too deep to inspect safely]"
            if decoded == candidate:
                break
            candidate = decoded
            if has_url_markers(candidate):
                break

    if not has_url_markers(candidate):
        if _PERCENT_ESCAPE.search(candidate):
            # Omit nested values that remain encoded after the bounded inspection.
            return "[nested URL omitted: too deep to inspect safely]"
        return value
    if depth >= _MAX_NESTED_URL_DEPTH:
        # Fail closed when nested URL depth exceeds the inspection limit.
        return "[nested URL omitted: too deep to inspect safely]"
    safe = _redact_urls_in_text(candidate, depth + 1)
    # Preserve the caller's encoding unless inspecting the nested URL changed it.
    return value if safe == candidate else safe


def _sanitized_pairs(items: list[tuple[str, str]], depth: int) -> tuple[list[tuple[str, str]], bool]:
    """Replace secret values and redact nested URLs, reporting whether anything changed.

    Shared by the query string and the fragment, which carry the same kind of
    parameter. Sanitized before ``urlencode``: one lone surrogate in a name or a
    value would raise instead of redacting. The change flag lets ordinary URLs
    keep their original spelling and encoding untouched. ``depth`` bounds
    recursive URL nesting.
    """
    safe_items: list[tuple[str, str]] = []
    changed = False
    for name, value in items:
        sensitive = _has_sensitive_query_name(name)
        # Redact the whole parameter name when it contains an encoded delimiter or value.
        safe_name = name if not sensitive or _SAFE_QUERY_NAME.fullmatch(name) else "REDACTED"
        safe_name = _no_surrogates(safe_name)
        safe_value = REDACTED if sensitive else redact_diagnostic_text(_no_surrogates(_redact_nested_url(value, depth)))
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
    original_url = url
    # Inspect a bounded HTML-decoded view, but preserve the original spelling if unchanged.
    decoded_url = _html_unescape_bounded(url)
    if decoded_url is None:
        return "[URL omitted: too deeply encoded to inspect safely]"
    url = decoded_url
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        # Omit unparseable URLs rather than risk echoing credentials.
        return "[malformed URL omitted]"
    is_http_without_authority = parts.scheme.lower() in {"http", "https"} and not parts.netloc
    if is_http_without_authority and (
        "@" in parts.path
        or (_PERCENT_ESCAPE.search(parts.path) and _ENCODED_HTTP_URL_MARKER.search(parts.path) is None)
    ):
        # urllib leaves userinfo-looking text in the path of malformed URLs such as ``https:user@host``.
        if "@" in parts.path:
            return "[malformed URL omitted]"
        candidate = parts.path
        for _ in range(_MAX_NESTED_URL_DEPTH):
            decoded = urllib.parse.unquote(candidate)
            if decoded == candidate:
                break
            candidate = decoded
            if "@" in candidate:
                return "[malformed URL omitted]"
        if _PERCENT_ESCAPE.search(candidate):
            return "[malformed URL omitted]"

    netloc = parts.netloc
    if parts.username is None and _PERCENT_ESCAPE.search(netloc):
        # Encoded reserved characters are not delimiters to urlsplit(), but a later consumer may decode them.
        candidate = netloc
        found_encoded_userinfo = False
        for _ in range(_MAX_NESTED_URL_DEPTH):
            decoded = urllib.parse.unquote(candidate)
            if decoded == candidate:
                break
            candidate = decoded
            at = candidate.rfind("@")
            if at >= 0:
                if any(char in candidate[:at] for char in "/?#"):
                    return "[malformed URL omitted]"
                netloc = candidate[at + 1 :]
                found_encoded_userinfo = True
                break
        if not found_encoded_userinfo and _PERCENT_ESCAPE.search(candidate):
            return "[malformed URL omitted]"

    if parts.username is not None:
        host = parts.hostname or ""
        # Restore IPv6 brackets when rebuilding the authority.
        if ":" in host:
            host = f"[{host}]"
        try:
            port = parts.port
        except ValueError:  # Ignore malformed ports rather than failing during redaction.
            port = None
        if port is not None:
            host = f"{host}:{port}"
        netloc = host

    path = parts.path
    safe_path = _redact_nested_url(path, depth)
    if safe_path != path:
        # Keep nested URL separators inside the path; never let a decoded ? or # escape its component.
        path = urllib.parse.quote(_no_surrogates(safe_path), safe="/:@!$&'()*+,;=-._~")

    query = parts.query
    if query:
        safe_items, changed = _sanitized_pairs(_query_pairs(query), depth)
        if changed:
            query = urllib.parse.urlencode(safe_items)

    # Redact query-shaped fragments (for example, OAuth tokens) and nested URLs in ordinary anchors.
    fragment = parts.fragment
    if fragment and "=" in fragment:
        safe_items, changed = _sanitized_pairs(_query_pairs(fragment), depth)
        if changed:
            fragment = urllib.parse.urlencode(safe_items)
    if fragment:
        fragment = _redact_nested_url(fragment, depth)

    if netloc == parts.netloc and path == parts.path and query == parts.query and fragment == parts.fragment:
        shown = original_url  # Preserve the caller's original spelling when nothing needs redaction.
    else:
        shown = urllib.parse.urlunsplit((parts.scheme, netloc, path, query, fragment))
    # Keep output encodable and on one line.
    shown = redact_diagnostic_text(_one_line(_no_surrogates(shown)))
    return shown if len(shown) <= MAX_URL_DISPLAY_CHARS else shown[:MAX_URL_DISPLAY_CHARS] + "…"


def redact_url(url: str) -> str:
    """Hide credentials in a URL before it is logged or published."""
    return _redact_url(url, 0)


def _prose_tail_start(value: str, punctuation: str) -> int:
    """Return where the trailing prose begins, so a URL is not redacted with it.

    Trailing sentence punctuation, and closing brackets that were never opened
    inside the match, belong to the surrounding sentence rather than the URL.
    ``punctuation`` differs by caller: a semicolon ends a sentence in prose but
    separates parameters inside a query string, so only the prose caller trims it.
    """
    end = len(value)
    while end and value[end - 1] in punctuation:
        end -= 1
    for closer, opener in ((")", "("), ("]", "["), ("}", "{")):
        balance = value[:end].count(closer) - value[:end].count(opener)
        while end and value[end - 1] == closer and balance > 0:
            end -= 1
            balance -= 1
    return end


def _redact_url_occurrence(match: re.Match[str], depth: int) -> str:
    """Redact one URL embedded in prose, preserving sentence punctuation."""
    value = match.group()
    end = _prose_tail_start(value, ".,;:!?")
    return _redact_url(value[:end], depth) + value[end:]


def _redact_multiline_userinfo(match: re.Match[str]) -> str:
    """Replace userinfo that crosses a line break while embedded in prose."""
    return f"{match.group('prefix')}REDACTED@"


def _redact_text_query_parameter(match: re.Match[str], depth: int) -> str:
    """Redact sensitive pairs and inspect nested URLs in malformed prose queries."""
    raw_name = match.group("name")
    name = urllib.parse.unquote_plus(_no_surrogates(raw_name))
    value = match.group("value")
    if not _has_sensitive_query_name(name):
        safe_value = _redact_nested_url(value, depth)
        return match.group() if safe_value == value else f"{match.group('separator')}{raw_name}={safe_value}"

    # Redact parameter names that contain an encoded delimiter or secret.
    safe_name = raw_name if _SAFE_QUERY_NAME.fullmatch(raw_name) else "REDACTED"
    # A semicolon separates parameters here, so it stays with the value. No test
    # can show the difference -- _QUERY_PARAM_IN_TEXT's value excludes ';', so one
    # never reaches this trim -- but the lists are kept apart to match the regex.
    end = _prose_tail_start(value, ".,:!?")
    return f"{match.group('separator')}{safe_name}=REDACTED{value[end:]}"


def _redact_urls_in_text(
    text: str,
    depth: int,
    *,
    decode_entities: bool = True,
    inspect_encoded_urls: bool = True,
) -> str:
    """Redact text while carrying the current nested-URL depth."""
    if len(text) > _MAX_URL_PARSE_CHARS:
        # Prose is bounded for the same reason a URL is, but say so: "URL omitted"
        # for a long paragraph sent the reader looking for a link that was never there.
        return "[text omitted: too long to inspect safely]"
    if decode_entities:
        decoded = _html_unescape_bounded(text)
        if decoded is None:
            return "[URL omitted: too deeply encoded to inspect safely]"
        if decoded != text:
            # Inspect a decoded view for entity-hidden delimiters; preserve original prose if unchanged.
            safe_decoded = _redact_urls_in_text(decoded, depth, decode_entities=False)
            if safe_decoded != decoded:
                return safe_decoded
    text = _MULTILINE_USERINFO_IN_TEXT.sub(_redact_multiline_userinfo, text)
    # Inspect HTTP strings containing @ even when malformed syntax left userinfo in the path.
    text = _HTTP_URL_WITH_AT_IN_TEXT.sub(lambda match: _redact_url_occurrence(match, depth), text)
    # Do not parse prose colons as schemes; redact standalone queries and embedded URLs separately.
    stripped = text.strip()
    has_html_reference = html.unescape(stripped) != stripped
    looks_like_http_url = stripped[:5].casefold() == "http:" or stripped[:6].casefold() == "https:"
    if not any(char.isspace() for char in stripped) and (
        looks_like_http_url or "?" in stripped or ("#" in stripped and not has_html_reference)
    ):
        text = _redact_url(text, depth)
    text = _URL_IN_TEXT.sub(lambda match: _redact_url_occurrence(match, depth), text)
    text = _QUERY_PARAM_IN_TEXT.sub(lambda match: _redact_text_query_parameter(match, depth), text)

    # Inspect percent-encoded URL schemes anywhere in prose or path text, not only in parsed query values.
    if inspect_encoded_urls and _ENCODED_HTTP_URL_MARKER.search(text):
        if depth >= _MAX_NESTED_URL_DEPTH:
            return "[nested URL omitted: too deep to inspect safely]"
        candidate = text
        safe_candidate: str | None = None
        inspected_url = False
        for _ in range(_MAX_NESTED_URL_DEPTH):
            decoded = urllib.parse.unquote(candidate)
            if decoded == candidate:
                break
            candidate = decoded
            if _URL_IN_TEXT.search(candidate) or _HTTP_URL_WITH_AT_IN_TEXT.search(candidate):
                inspected_url = True
                safe = _redact_urls_in_text(
                    candidate,
                    depth + 1,
                    decode_entities=False,
                    inspect_encoded_urls=False,
                )
                if safe != candidate:
                    # Keep decoding the original view: another layer may reveal userinfo hidden beside a redacted query.
                    safe_candidate = safe
        if _ENCODED_HTTP_URL_MARKER.search(candidate) or (inspected_url and _PERCENT_ESCAPE.search(candidate)):
            return "[nested URL omitted: too deep to inspect safely]"
        if safe_candidate is not None:
            return safe_candidate
    return text


def redact_urls_in_text(text: str) -> str:
    """Redact URL credentials and common bare secrets in untrusted prose.

    Apply this once per value. It rewrites rather than deletes -- a bare
    ``?token`` becomes ``?token=REDACTED`` -- so its output is a different
    document that a second pass may legitimately parse differently, and the
    function is not a fixed point. One pass is what every caller does and is
    what the guarantee covers: no secret value survives it.
    """
    return redact_diagnostic_text(_redact_urls_in_text(text, 0))


def _redact_source(value: str) -> str:
    """Redact a standalone source URL, or embedded URLs in a path/message.

    A direct URL can contain control characters that ``urlsplit`` removes
    before parsing (including a newline before a secret query parameter), so
    it must go through ``redact_url`` as a whole. Local paths and other prose
    may contain embedded URLs, for which ``redact_urls_in_text`` preserves the
    surrounding text.
    """
    if http_scheme(value):
        # ``http_scheme`` recognizes the http/https prefixes itself, including for a
        # URL too long to parse, so no separate prefix test is needed here.
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
    if isinstance(exc, _ShortReadError):
        return str(exc)  # Generated locally from byte counts; safe to display.
    if isinstance(exc, http.client.IncompleteRead):
        return "incomplete HTTP response"
    if isinstance(exc, (ValueError, http.client.HTTPException)):
        return "malformed URL or HTTP response"
    if isinstance(exc, urllib.error.URLError):
        return "network error"
    if isinstance(exc, OSError):
        return "network I/O error"
    return type(exc).__name__


def _pause_before_retry(attempt: int, exc: Exception) -> None:
    """Back off before the next attempt, or return at once after the last one.

    Every transient branch of the fetch loop needs the same three steps, and
    the "is there another attempt?" guard is the one that matters: without it
    the final failure still sleeps, delaying the fallback to the next source
    for no reason.
    """
    if attempt >= FETCH_ATTEMPTS:
        return
    LOGGER.debug(
        "  attempt %d of %d failed (%s); retrying in %d s.",
        attempt,
        FETCH_ATTEMPTS,
        _safe_fetch_error(exc),
        RETRY_BACKOFF_SECONDS * attempt,
    )
    time.sleep(RETRY_BACKOFF_SECONDS * attempt)


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
        # Reject HTTP because the list controls promotions; local paths remain supported.
        raise SyncError(f"refusing to fetch a non-HTTPS URL (use https:// or a local path): {redact_url(url)}")
    last_error: Exception | None = None
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        LOGGER.debug("Fetching %s (attempt %d of %d).", redact_url(url), attempt, FETCH_ATTEMPTS)
        try:
            headers = {"User-Agent": USER_AGENT}
            # Compare hostnames exactly to reject lookalike API domains.
            parsed = urllib.parse.urlparse(url)
            if parsed.hostname == "api.github.com":
                # Request raw Git Blob bytes; keep Contents API JSON for its large-file fallback.
                headers["Accept"] = (
                    "application/vnd.github.raw" if "/git/blobs/" in parsed.path else "application/vnd.github+json"
                )
            request = urllib.request.Request(url, headers=headers)
            # HTTPS is enforced above; this handler prevents redirect downgrades.
            with _OPENER.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:  # nosec B310
                # Reject oversized responses before reading when Content-Length is available.
                declared = _declared_length(response)
                if declared is not None and declared > MAX_SOURCE_BYTES:
                    raise _too_large(url)
                body: bytes = response.read(MAX_SOURCE_BYTES + 1)
                # The HTTP decoder detects incomplete chunked responses.
                chunked = bool(getattr(response, "chunked", False))
            if len(body) > MAX_SOURCE_BYTES:
                raise _too_large(url)
            if declared is not None and not chunked and len(body) != declared:
                # Retry if a declared response body ends early.
                raise _ShortReadError(f"received {len(body):,} of {declared:,} bytes")
            return body
        except urllib.error.HTTPError as exc:
            # Close HTTPError bodies before retrying or falling back.
            if exc.fp is not None:
                with contextlib.suppress(OSError, ValueError):
                    exc.close()
            last_error = exc
            if exc.code != 429 and not 500 <= exc.code < 600:
                break  # Non-retryable client error; try the next source.
            _pause_before_retry(attempt, exc)
        except (OSError, http.client.IncompleteRead) as exc:
            # Transient: network and socket errors, a cut-short transfer
            # (_ShortReadError is an OSError for this reason), and a response
            # the HTTP decoder found incomplete. IncompleteRead is caught here
            # rather than falling through to the HTTPException clause below.
            last_error = exc
            _pause_before_retry(attempt, exc)
        except (ValueError, http.client.HTTPException) as exc:
            # Report invalid URL or HTTP syntax as a fetch failure so the next source can be tried.
            raise SyncError(f"could not fetch {redact_url(url)}: {_safe_fetch_error(exc)}") from exc
    reason = _safe_fetch_error(last_error) if last_error is not None else "unknown network error"
    raise SyncError(f"could not fetch {redact_url(url)}: {reason}")


# ``scheme:`` prefixes that name a URL rather than a Windows drive letter.
_RESERVED_URL_SCHEMES = frozenset(
    {"http", "https", "ftp", "ftps", "file", "data", "ssh", "git", "sftp", "gopher", "ws", "wss"}
)


def _looks_like_url(value: str) -> bool:
    """True when ``value`` uses a real URL scheme instead of naming a local file.

    Only ``http(s)`` is ever fetched, but anything carrying a scheme must be
    REPORTED as a URL: ``ftp://host/list.json`` used to fall through to the
    local-file path and fail with "cannot read ftp://...: No such file or
    directory", which sent the operator looking for a missing file. A Windows
    drive path (``C:\\list.json``) is a single character before the colon, and
    the schemes above are never drive letters, so neither is misclassified.
    """
    scheme = value.partition(":")[0]
    if not scheme or len(scheme) == 1 or http_scheme(value):
        return False
    return scheme.casefold() in _RESERVED_URL_SCHEMES


def _read_bytes(source: str) -> bytes:
    """Return the raw bytes of an HTTP(S) URL or a local path, raising SyncError.

    The size limit is enforced on the bytes ACTUALLY READ, not on the size the
    filesystem reports: a file can grow between calls. Only regular files are
    accepted, opened non-blocking, so a FIFO cannot hang the sync and a device
    cannot yield an endless stream. Reading at most ``MAX_SOURCE_BYTES + 1``
    bytes makes the local path obey the same budget as a download.
    """
    if _looks_like_url(source):
        # Name the unsupported scheme instead of reporting a missing local file.
        scheme = source.partition(":")[0].casefold()
        raise SyncError(f"unsupported source URL scheme {scheme!r} (use https:// or a local path)")
    if http_scheme(source):
        return _fetch_bytes(source)
    LOGGER.debug("Reading %s from disk.", _redact_source(source))
    try:
        raw = read_bounded_regular_file(Path(source), MAX_SOURCE_BYTES)
    except (OSError, ValueError) as exc:
        # ValueError also covers paths the OS cannot encode (for example, NUL).
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
        # Accept GitHub's MIME-style wrapping, but reject every non-Base64 character.
        compact = content.translate(str.maketrans("", "", " \t\r\n"))
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    # The Contents API omits large file content; try download_url or the Git Blob endpoint.
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


def _allowed_download_url(source: str, candidate: str) -> bool:
    """Only follow same-origin HTTPS downloads, plus GitHub's raw-content host.

    Contents API responses are untrusted data. HTTPS alone is not an origin
    boundary: following an arbitrary ``download_url`` would let a remote list
    make a write-capable CI job issue requests to unrelated hosts. The GitHub
    Contents API legitimately points from ``api.github.com`` to
    ``raw.githubusercontent.com``; all other follow-ups must stay on the
    source's own HTTPS origin. Userinfo is rejected so a response cannot make
    the client send Basic credentials.
    """
    if len(candidate) > _MAX_URL_PARSE_CHARS or http_scheme(candidate) != "https":
        return False
    try:
        source_parts = urllib.parse.urlsplit(source)
        candidate_parts = urllib.parse.urlsplit(candidate)
        source_port = source_parts.port
        candidate_port = candidate_parts.port
    except ValueError:
        return False

    if candidate_parts.username is not None:
        return False

    source_origin = (source_parts.scheme.lower(), source_parts.hostname, 443 if source_port is None else source_port)
    candidate_origin = (
        candidate_parts.scheme.lower(),
        candidate_parts.hostname,
        443 if candidate_port is None else candidate_port,
    )
    if source_origin == candidate_origin:
        return True
    return source_origin == ("https", "api.github.com", 443) and candidate_origin == (
        "https",
        "raw.githubusercontent.com",
        443,
    )


def _document_from(raw: bytes, source: str) -> tuple[dict[str, Any], bytes] | None:
    """Parse ``raw`` and return it only when it has a usable SteamID.

    An empty or all-malformed inline playerlist is not a successful resolution:
    the Contents API envelope may still offer a valid download URL or blob.
    """
    try:
        document = _parse_document(raw, source)
    except SyncError:
        return None
    if not isinstance(document.get("players"), list) or not _has_usable_steamids(document):
        return None
    return document, raw


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
    if isinstance(download_url, str) and _allowed_download_url(source, download_url):
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
        # A blob response may itself be a base64 envelope.
        for payload in (body, _unwrap_github_contents_envelope(parsed)):
            if payload is None:
                continue
            resolved = _document_from(payload, source)
            if resolved is not None:
                return resolved
    return None


def _has_usable_steamids(document: dict[str, Any]) -> bool:
    """True when at least one entry carries a SteamID this tool can normalize."""
    players = document.get("players")
    if not isinstance(players, list):
        return False
    return any(isinstance(entry, dict) and normalize_steamid(entry.get("steamid")) is not None for entry in players)


def load_first_available_raw(sources: Iterable[str]) -> tuple[dict[str, Any], str, bytes]:
    """Return the parsed document, source name, and RAW bytes of the first usable source.

    The raw bytes are what gets written to the snapshot file, so the
    snapshot is an exact replica of the original upstream file -- same
    bytes, guaranteed by construction: nothing is ever decoded, parsed and
    re-serialized on the way to the snapshot.
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
                    f"{_redact_source(source)}: no 'players' array, and neither inline content, an allowed HTTPS "
                    "download_url nor a Git blob could be resolved"
                )
                continue
            document, raw = resolved
        if not _has_usable_steamids(document):
            # Treat empty or unusable results as broken mirrors and try the next source.
            failures.append(f"{_redact_source(source)}: no usable SteamIDs in its 'players' array")
            continue
        return document, source, raw

    raise SyncError("cannot load the Vorobey hackerpolice list:\n  " + "\n  ".join(failures))
