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
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from playerlist import normalize_steamid, strict_json_loads

SOURCE_REPO_URL = "https://github.com/Nocrex/Tom/blob/main/playerlist.vorobey-hackerpolice.json"

# Marks the proof line this tool owns, so it is never added twice.
PROOF_MARKER = "[auto] cheater: matched Vorobey hackerpolice list"

# Tried in order until one of them answers. The first is the canonical raw
# URL of the original file -- the exact bytes the snapshot must replicate.
DEFAULT_SOURCES: tuple[str, ...] = (
    "https://raw.githubusercontent.com/Nocrex/Tom/refs/heads/main/playerlist.vorobey-hackerpolice.json",
    "https://github.com/Nocrex/Tom/raw/main/playerlist.vorobey-hackerpolice.json",
    "https://api.github.com/repos/Nocrex/Tom/contents/playerlist.vorobey-hackerpolice.json",
)

# Single source of truth for the tool version (also used for --version).
VERSION = "4.0"

USER_AGENT = (
    f"Garou3299-tf2bd-database-vorobey-hackerpolice-sync/{VERSION} (+https://github.com/Garou3299/tf2bd-database)"
)

FETCH_TIMEOUT_SECONDS = 30
FETCH_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 2

# Sanity cap on a fetched list (the real one is ~1.9 MB): a misbehaving or
# hostile endpoint must not be able to exhaust memory by streaming forever.
MAX_SOURCE_BYTES = 64 * 1024 * 1024

__all__ = [
    "DEFAULT_SOURCES",
    "PROOF_MARKER",
    "SOURCE_REPO_URL",
    "VERSION",
    "HackerpoliceIndex",
    "SyncError",
    "added_steamids",
    "load_first_available_raw",
    "load_snapshot",
    "removed_steamids",
]


class SyncError(Exception):
    """A user-facing failure (bad input, unreachable source) rather than a bug."""


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
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlparse(new.full_url).scheme != "https":
            raise SyncError(f"refusing to follow a non-HTTPS redirect to {newurl}")
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
    """Vorobey entries keyed by canonical SteamID."""

    by_steamid: dict[str, dict[str, Any]]
    total: int
    skipped: int

    @classmethod
    def build(cls, document: dict[str, Any]) -> HackerpoliceIndex:
        entries = document.get("players")
        if not isinstance(entries, list):
            raise SyncError("the Vorobey hackerpolice list has no 'players' array")

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
        raise SyncError(f"{redact_url(source)} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SyncError(f"{redact_url(source)} does not contain a JSON object")
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
    if not path.exists():
        return None
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SyncError(f"cannot read {path}: {exc}") from exc
    return HackerpoliceIndex.build(_parse_document(raw, str(path))), raw


def redact_url(url: str) -> str:
    """Hide credentials embedded in a URL before it is logged or published.

    A ``--source`` may legitimately carry a token (``https://user:token@…``)
    and this bot's output ends up in logs and in a pull request body: the
    scheme/host/path are enough to debug a fetch, the secret is not.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    if parts.username is None:
        return url
    host = parts.hostname or ""
    if parts.port is not None:
        host = f"{host}:{parts.port}"
    return urllib.parse.urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


def _too_large(source: str) -> SyncError:
    """The one error used wherever a source exceeds the download budget."""
    return SyncError(f"{redact_url(source)} is larger than the {MAX_SOURCE_BYTES // (1024 * 1024)} MiB safety limit")


def _fetch_bytes(url: str) -> bytes:
    """GET a URL and return the body bytes VERBATIM, retrying transient failures.

    Permanent client errors (4xx other than 429) are not retried -- they
    will fail identically on every attempt, and the caller falls back to
    the next source instead.
    """
    if not url.startswith(("https://", "http://")):
        raise SyncError(f"refusing to fetch non-HTTP(S) URL: {redact_url(url)}")
    last_error: Exception | None = None
    for attempt in range(1, FETCH_ATTEMPTS + 1):
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
            if len(body) > MAX_SOURCE_BYTES:
                raise _too_large(url)
            return body
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code != 429 and not 500 <= exc.code < 600:
                break  # permanent: don't waste attempts, fall back sooner
            if attempt < FETCH_ATTEMPTS:
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
        except OSError as exc:  # URLError, socket timeouts, resets, ...
            last_error = exc
            if attempt < FETCH_ATTEMPTS:
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
        except (ValueError, http.client.HTTPException) as exc:
            # A malformed URL (bad IPv6 literal, control characters, ...)
            # fails identically on every attempt and every machine: report
            # it as a fetch failure so the caller falls back / exits cleanly
            # instead of crashing with a traceback.
            raise SyncError(f"could not fetch {redact_url(url)}: {exc}") from exc
    raise SyncError(f"could not fetch {redact_url(url)}: {last_error}")


def _read_bytes(source: str) -> bytes:
    """Return the raw bytes of an HTTP(S) URL or a local path, raising SyncError.

    The size limit is enforced on the bytes ACTUALLY READ, not on the size the
    filesystem reports: a file can grow between the two calls, and a special
    file (a device, a fifo) reports 0 while yielding endless data. Reading at
    most ``MAX_SOURCE_BYTES + 1`` bytes makes the local path obey exactly the
    same budget as a download.
    """
    if source.startswith(("http://", "https://")):
        return _fetch_bytes(source)
    try:
        with Path(source).open("rb") as handle:
            raw = handle.read(MAX_SOURCE_BYTES + 1)
    except OSError as exc:
        raise SyncError(f"cannot read {redact_url(source)}: {exc}") from exc
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
    if isinstance(download_url, str) and download_url.startswith("https://"):
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


def load_first_available_raw(sources: Iterable[str]) -> tuple[dict[str, Any], str, bytes]:
    """Return the parsed document, source name, and RAW bytes of the first usable source.

    The raw bytes are what gets written to the snapshot file, so the
    snapshot is an exact replica of the original upstream file -- same
    bytes, guaranteed by construction: nothing is ever decoded, parsed and
    re-serialised on the way to the snapshot.
    """
    failures: list[str] = []
    for source in sources:
        try:
            raw = _read_bytes(source)
            document = _parse_document(raw, source)
        except SyncError as exc:
            failures.append(str(exc))
            continue
        if not isinstance(document.get("players"), list):
            resolved = _resolve_indirect_document(document, source)
            if resolved is None:
                failures.append(
                    f"{redact_url(source)}: no 'players' array, and neither inline content, a usable HTTPS "
                    "download_url nor a Git blob could be resolved"
                )
                continue
            document, raw = resolved
        return document, source, raw

    raise SyncError("cannot load the Vorobey hackerpolice list:\n  " + "\n  ".join(failures))
