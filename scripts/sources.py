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
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from playerlist import normalize_steamid

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
VERSION = "3.4"

USER_AGENT = (
    f"Garou3299-tf2bd-database-vorobey-hackerpolice-sync/{VERSION} (+https://github.com/Garou3299/tf2bd-database)"
)

FETCH_TIMEOUT_SECONDS = 30
FETCH_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 2

# Sanity cap on a fetched list (currently ~2 MB): a misbehaving or hostile
# endpoint must not be able to exhaust memory by streaming forever.
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
    return set(current.by_steamid) - set(previous.by_steamid)


def removed_steamids(previous: HackerpoliceIndex, current: HackerpoliceIndex) -> set[str]:
    """SteamIDs that were in the previous snapshot but are gone now.

    This set -- and only this set -- may be demoted in the Garou database.
    IDs absent from both lists (e.g. manually added cheaters) are not in it,
    and IDs added upstream since the snapshot are not either.
    """
    return set(previous.by_steamid) - set(current.by_steamid)


def _parse_document(raw: bytes, source: str) -> dict[str, Any]:
    """Parse raw bytes as a playerlist document, raising SyncError."""
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
        # ValueError: e.g. a JSON number beyond Python's int-parsing limit.
        raise SyncError(f"{source} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SyncError(f"{source} does not contain a JSON object")
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


def _fetch_bytes(
    url: str,
    *,
    timeout: int = FETCH_TIMEOUT_SECONDS,
    attempts: int = FETCH_ATTEMPTS,
) -> bytes:
    """GET a URL and return the body bytes VERBATIM, retrying transient failures.

    Permanent client errors (4xx other than 429) are not retried -- they
    will fail identically on every attempt, and the caller falls back to
    the next source instead.
    """
    if not url.startswith(("https://", "http://")):
        raise SyncError(f"refusing to fetch non-HTTP(S) URL: {url}")
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            headers = {"User-Agent": USER_AGENT}
            # Hostname comparison, not a substring match: a look-alike URL
            # such as https://api.github.com.example.invalid/ must not be
            # treated as the GitHub API.
            if urllib.parse.urlparse(url).hostname == "api.github.com":
                headers["Accept"] = "application/vnd.github.raw"
            request = urllib.request.Request(url, headers=headers)
            # Scheme is restricted to HTTP(S) above (Bandit B310).
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
                body = response.read(MAX_SOURCE_BYTES + 1)
            if len(body) > MAX_SOURCE_BYTES:
                raise SyncError(f"{url} is larger than the {MAX_SOURCE_BYTES // (1024 * 1024)} MiB safety limit")
            return body
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code != 429 and not 500 <= exc.code < 600:
                break  # permanent: don't waste attempts, fall back sooner
            if attempt < attempts:
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last_error = exc
            if attempt < attempts:
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
        except (ValueError, http.client.HTTPException) as exc:
            # A malformed URL (bad IPv6 literal, control characters, ...)
            # fails identically on every attempt and every machine: report
            # it as a fetch failure so the caller falls back / exits cleanly
            # instead of crashing with a traceback.
            raise SyncError(f"could not fetch {url}: {exc}") from exc
    raise SyncError(f"could not fetch {url}: {last_error}")


def _read_bytes(source: str) -> bytes:
    """Return the raw bytes of an HTTP(S) URL or a local path, raising SyncError."""
    if source.startswith(("http://", "https://")):
        return _fetch_bytes(source)
    try:
        return Path(source).read_bytes()
    except OSError as exc:
        raise SyncError(f"cannot read {source}: {exc}") from exc


def _unwrap_github_contents_envelope(document: dict[str, Any], raw: bytes) -> bytes | None:
    """Decode a GitHub Contents API envelope to the file bytes it wraps.

    Normally the ``Accept: application/vnd.github.raw`` header makes the API
    return the file itself, but if that is ever ignored the response is a
    JSON envelope with the file base64-encoded in ``content``. Unwrapping it
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
    # back to the envelope's download_url instead.
    return decoded or None


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
            unwrapped = _unwrap_github_contents_envelope(document, raw)
            if unwrapped is None:
                # Large-file envelopes carry no inline content, only a
                # download_url pointing at the raw file: follow it, and the
                # bytes downloaded there become the (exact) snapshot bytes.
                download_url = document.get("download_url")
                # download_url comes from the fetched document itself, so
                # unlike an operator-supplied --source it is untrusted:
                # HTTPS only -- never a local path or a plaintext URL.
                if isinstance(download_url, str) and download_url.startswith("https://"):
                    try:
                        unwrapped = _read_bytes(download_url)
                    except SyncError as exc:
                        failures.append(str(exc))
                        continue
                else:
                    failures.append(f"{source}: no 'players' array and no usable HTTPS download_url in response")
                    continue
            try:
                document = _parse_document(unwrapped, source)
            except SyncError as exc:
                failures.append(str(exc))
                continue
            if not isinstance(document.get("players"), list):
                failures.append(f"{source}: no 'players' array in response")
                continue
            raw = unwrapped
        return document, source, raw

    raise SyncError("cannot load the Vorobey hackerpolice list:\n  " + "\n  ".join(failures))
