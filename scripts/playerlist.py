"""TF2BD playerlist file format helpers.

Handles SteamID normalisation, reading/writing playerlist JSON, validation,
sorting and attribute ordering. Nothing here knows about the Vorobey
hackerpolice list.
"""

from __future__ import annotations

import errno
import html
import json
import math
import os
import re
import stat
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypedDict, cast

STEAMID64_BASE = 76561197960265728
MAX_ACCOUNT_ID = 2**32
MAX_STEAMID_INSTANCE = 2**20

# Bound local reads; the fetch path uses the same limit.
MAX_FILE_BYTES = 64 * 1024 * 1024

CANONICAL_PREFIX = "[U:1:"
CANONICAL_SUFFIX = "]"

# TF2BD v3 attributes, ordered as written.
ATTRIBUTE_ORDER: tuple[str, ...] = ("cheater", "suspicious", "exploiter", "racist")
KNOWN_ATTRIBUTES = frozenset(ATTRIBUTE_ORDER)

# SteamID digits are ASCII-only; Unicode digit checks accept extra characters.
_ACCOUNT_ID_RE = re.compile(r"[0-9]+")
# Accept case variants and canonicalize them for duplicate detection.
_U_RE = re.compile(rf"^\[U:1:({_ACCOUNT_ID_RE.pattern})\]$", re.IGNORECASE | re.ASCII)
_U_BARE_RE = re.compile(rf"^U:1:({_ACCOUNT_ID_RE.pattern})$", re.IGNORECASE | re.ASCII)
_U_INSTANCE_RE = re.compile(
    rf"^\[U:1:({_ACCOUNT_ID_RE.pattern}):({_ACCOUNT_ID_RE.pattern})\]$", re.IGNORECASE | re.ASCII
)
# Reject non-public Steam2 universes; dropping the universe could alias another account.
_STEAM2_RE = re.compile(rf"^STEAM_[01]:([01]):({_ACCOUNT_ID_RE.pattern})$", re.IGNORECASE | re.ASCII)
_STEAMID64_RE = re.compile(r"^[0-9]{17}$")
# Require a complete Steam Community profile URL, not embedded text or a lookalike host.
_PROFILE_URL_RE = re.compile(
    r"(?:https?://)?(?:www\.)?steamcommunity\.com/profiles/([0-9]{17})/?", re.IGNORECASE | re.ASCII
)


# Bound untrusted values included in validation messages.
MAX_SHOWN_VALUE_CHARS = 120
# Bound integer formatting before building diagnostic previews.
_MAX_SHOWN_INT_BITS = MAX_SHOWN_VALUE_CHARS * 4
MAX_VALIDATION_MESSAGES = 100

# Diagnostics can contain free-form values, not just URLs. Redact common
# credential fields and authorization headers even when they appear in prose.
_DIAGNOSTIC_SECRET_MARKER = re.compile(
    r"token|secret|password|passwd|pwd|auth|credential|session|sid|cookie|csrf|xsrf|code|sig|"
    r"api[_-]?key|private[_-]?key|access[_-]?key|jwt|bearer|signature|hmac|nonce|state|ticket|otp|mfa",
    re.IGNORECASE | re.ASCII,
)
_DIAGNOSTIC_FIELD_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_DIAGNOSTIC_VALUE_DELIMITERS = frozenset(",;&\r\n\t ")
_AUTHORIZATION_HEADER = re.compile(r"(?i)(?P<header>\b(?:proxy-)?authorization\s*:\s*)[^\r\n]*", re.ASCII)
# ``Bearer <token>``, also written ``Bearer = <token>`` or ``Bearer: <token>``.
# The separator is captured because it separates a credential from English: nobody
# writes "Bearer = of", so an explicit separator always means a credential, while a
# bare space has to be judged on the word that follows.
_BEARER_CREDENTIAL = re.compile(
    r"(?i)\b(?P<scheme>Bearer|Basic)(?P<separator>\s*[:=]\s*|\s+)(?P<credential>[^\s,;&]+)", re.ASCII
)
# Characters that practically never appear inside an ordinary English word.
_CREDENTIAL_CHARS = re.compile(r"[0-9_\-./+=:~]", re.ASCII)
# Also sanitize URL userinfo when the generic path formatter is used directly.
_URL_USERINFO_PREFIX = re.compile(r"(?:https?:/{0,4}|//)", re.IGNORECASE | re.ASCII)
_URL_USERINFO_IN_TEXT = re.compile(
    r"(?P<prefix>(?:https?:/{0,4}|//))[^/\s?#<>\"'`@]*@",
    re.IGNORECASE | re.ASCII,
)
# Identify nested percent-encoded URL schemes before they are clipped out of view.
_ENCODED_HTTP_SCHEME = re.compile(r"https?(?:%(?:25)*3a|:(?:%(?:25)*2f))", re.IGNORECASE | re.ASCII)
_PERCENT_ESCAPE_IN_TEXT = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE | re.ASCII)
_PERCENT_ESCAPE = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE | re.ASCII)
# Field names keep plain characters plus percent escapes and HTML references.
_FIELD_NAME_CHARS = re.compile(r"[A-Za-z0-9_.%-]+", re.ASCII)
# Control and zero-width characters that servers ignore when matching a name.
_INVISIBLE_IN_FIELD_NAME = re.compile("[\x00-\x20\x7f-\x9f\u200b-\u200f\u2028-\u202f\u2060\ufeff]", re.ASCII)
# A query-style pair anywhere in free text: find the name, then its value.
_QUERY_PAIR_IN_TEXT = re.compile(r"[?&#;](?P<name>[^\s=&?#;]+)=(?P<value>[^\s&;#]*)", re.ASCII)
_MAX_DIAGNOSTIC_DECODE_DEPTH = 8
# Lone surrogates: JSON can encode them, UTF-8 cannot. Replace before output.
SURROGATE_RE = re.compile(r"[\ud800-\udfff]")


def _normalised_field_name(name: str) -> str | None:
    """Decode an obfuscated field name, or ``None`` if it is not a plain name.

    A query key can percent-encode its separator (``to%0Aken``), use HTML
    character references, or carry invisible characters a server strips before
    looking the credential up. Redaction has to be at least as permissive as
    that normalisation, or the encoded spelling quietly walks past it.
    """
    decoded = name
    for _ in range(_MAX_DIAGNOSTIC_DECODE_DEPTH):
        next_decoded = html.unescape(urllib.parse.unquote(decoded))
        if next_decoded == decoded:
            break
        decoded = next_decoded
    else:
        # Still decoding at the depth limit. Fail closed rather than match on a
        # spelling that is not the one a server would end up with.
        return None
    decoded = _INVISIBLE_IN_FIELD_NAME.sub("", decoded)
    if not _FIELD_NAME_CHARS.fullmatch(decoded):
        # It decodes to something that is not a field name any more (an embedded
        # URL, say). Fail closed instead of guessing what a server would do.
        return None
    return decoded


def _is_secret_field_name(name: str) -> bool:
    """True when a credential-looking field name is present in any spelling."""
    if not name:
        return False
    if _DIAGNOSTIC_SECRET_MARKER.search(name) is not None:
        return True
    normalised = _normalised_field_name(name)
    return normalised is not None and _DIAGNOSTIC_SECRET_MARKER.search(normalised) is not None


def _redact_diagnostic_secret_pairs(value: str) -> str:
    """Redact sensitive fields with a linear scan instead of a backtracking regex."""
    parts: list[str] = []
    copied_through = 0
    separator = 0
    while separator < len(value):
        if value[separator] not in "=:":
            separator += 1
            continue

        key_end = separator
        while key_end and value[key_end - 1].isspace():
            key_end -= 1
        quote = value[key_end - 1] if key_end and value[key_end - 1] in "'\"" else ""
        if quote:
            key_end -= 1
        key_start = key_end
        while key_start and value[key_start - 1] in _DIAGNOSTIC_FIELD_CHARS:
            key_start -= 1
        if not _is_secret_field_name(value[key_start:key_end]):
            separator += 1
            continue
        value_start = separator + 1
        while value_start < len(value) and value[value_start].isspace():
            value_start += 1
        if value_start == len(value) or value[value_start] in _DIAGNOSTIC_VALUE_DELIMITERS:
            separator += 1
            continue

        value_end = value_start
        value_quote = value[value_start] if value[value_start] in "'\"" else ""
        if value_quote:
            value_end += 1
            escaped = False
            while value_end < len(value):
                char = value[value_end]
                value_end += 1
                if char == value_quote and not escaped:
                    break
                escaped = char == "\\" and not escaped
                if char != "\\":
                    escaped = False
            if value_end - value_start == 2:
                # An empty quoted body, as in ``password=''SECRET``. Redacting the
                # empty body would leave the secret itself in the message, so treat
                # the pair as unquoted and take everything up to the delimiter.
                value_quote = ""
                value_end = value_start
                while value_end < len(value) and value[value_end] not in _DIAGNOSTIC_VALUE_DELIMITERS:
                    value_end += 1
        else:
            while value_end < len(value) and value[value_end] not in _DIAGNOSTIC_VALUE_DELIMITERS:
                value_end += 1

        raw_value = value[value_start:value_end]
        trailing = ""
        if not value_quote:
            unpunctuated = raw_value.rstrip(".,:!?)]}>")
            if unpunctuated:
                trailing = raw_value[len(unpunctuated) :]

        parts.extend((value[copied_through:value_start], "REDACTED", trailing))
        copied_through = value_end
        separator = value_end

    if not parts:
        return value
    parts.append(value[copied_through:])
    return "".join(parts)


def _redact_encoded_query_pairs(value: str) -> str:
    """Redact the value of a query pair whose NAME only looks sensitive when decoded.

    ``_redact_diagnostic_secret_pairs`` finds a name by reading backwards over
    plain field characters, so ``?to%0Aken=SECRET`` does not look like a pair
    at all. This pass decodes each name and follows its ``=`` to the value.
    """
    parts: list[str] = []
    copied_through = 0
    for match in _QUERY_PAIR_IN_TEXT.finditer(value):
        name = match.group("name")
        if _DIAGNOSTIC_SECRET_MARKER.search(name) is not None:
            continue  # Plain names were already redacted by the scanner above.
        if not _is_secret_field_name(name):
            continue
        parts.extend((value[copied_through : match.start("value")], "REDACTED"))
        copied_through = match.end("value")
    if not parts:
        return value
    parts.append(value[copied_through:])
    return "".join(parts)


def _looks_like_credential(token: str, separator: str) -> bool:
    """True when the word after ``Bearer``/``Basic`` is a token, not English.

    Both words are ordinary English (``Bearer of bad news``, ``Basic
    Instinct``), and this redactor runs over player names on their way into the
    published report, so redacting unconditionally would rename innocent
    players in the output. A credential is recognised by its shape instead:

    - an explicit separator (``Bearer = ...``, ``Bearer: ...``) always wins,
      because prose does not write one there;
    - otherwise the token must carry a character an English word does not
      (a digit, an underscore, a dot, a slash...) or be a long mixed-case blob.
    """
    if separator.strip():
        return True
    token = token.rstrip(".,;:!?)]}>\"'")
    if _CREDENTIAL_CHARS.search(token):
        return True
    # No digits or punctuation: only a long mixed-case blob is a credential. An
    # ordinary word ("of", "Instinct", "King") has neither.
    return len(token) >= 12 and any(c.isupper() for c in token) and any(c.islower() for c in token)


def _redact_bearer_match(match: re.Match[str]) -> str:
    """Redact a bearer/basic match only when its credential looks like one."""
    token = match.group("credential")
    if not _looks_like_credential(token, match.group("separator")):
        return match.group(0)
    return f"{match.group('scheme')} REDACTED"


def redact_diagnostic_text(value: str) -> str:
    """Redact common bare secrets, authorization headers, and URL userinfo."""
    value = _AUTHORIZATION_HEADER.sub(r"\g<header>REDACTED", value)
    value = _BEARER_CREDENTIAL.sub(_redact_bearer_match, value)
    value = _URL_USERINFO_IN_TEXT.sub(r"\g<prefix>REDACTED@", value)
    return _redact_encoded_query_pairs(_redact_diagnostic_secret_pairs(value))


def _redact_diagnostic_preview(value: str, limit: int) -> str:
    """Sanitize a bounded preview without clipping credentials before inspection."""
    preview = value[: limit + 1]
    if len(value) > len(preview):
        url_prefix = _URL_USERINFO_PREFIX.search(preview)
        if url_prefix is not None and value.find("@", url_prefix.start()) >= len(preview):
            return "[credential-bearing URL omitted: too long to inspect safely]"

    encoded_scheme = _ENCODED_HTTP_SCHEME.search(preview)
    encoded_component = _PERCENT_ESCAPE_IN_TEXT.search(preview)
    has_url_prefix = _URL_USERINFO_PREFIX.search(preview) is not None
    inspect_encoded_url = encoded_scheme is not None or (encoded_component is not None and has_url_prefix)
    if inspect_encoded_url:
        if len(value) > len(preview):
            return "[nested URL omitted: too long to inspect safely]"
        # Redact at every level before decoding the next one. A key can hide its
        # separator behind an escape (``?to%0Aken=SECRET``), and the decoded form
        # of that key is no longer a matchable field name, so a single pass over
        # the deepest level would drop the raw-level redaction.
        candidate = preview
        shown = redact_diagnostic_text(candidate)
        redacted = shown != candidate
        for _ in range(_MAX_DIAGNOSTIC_DECODE_DEPTH):
            if _PERCENT_ESCAPE_IN_TEXT.search(candidate) is None:
                break
            candidate = urllib.parse.unquote(shown)
            shown = redact_diagnostic_text(candidate)
            redacted = redacted or shown != candidate
        if _PERCENT_ESCAPE_IN_TEXT.search(candidate):
            return "[nested URL omitted: too deep to inspect safely]"
        if redacted:
            # Only prefer the decoded spelling when it is what hid the credential;
            # a benign encoded path is shown exactly as the operator wrote it.
            return shown

    return redact_diagnostic_text(preview)


def _shown(value: Any) -> str:
    """A bounded, quoted preview so one bad entry cannot flood the log or RAM.

    Strings are sliced before ``repr``: clipping its result afterwards still
    allocated an escaped copy of an attacker-supplied 64 MiB value. JSON
    arrays/objects are summarized by shape rather than fully rendered for the
    same reason. ``repr`` rather than ``str`` keeps short scalar values safe: a
    newline cannot start a fake log line and an ESC cannot repaint the terminal.
    """
    if isinstance(value, str):
        preview = _redact_diagnostic_preview(value, MAX_SHOWN_VALUE_CHARS - 1)
        text = repr(preview)
    elif isinstance(value, dict):
        count = len(value)
        text = f"<object with {count:,} {'key' if count == 1 else 'keys'}>"
    elif isinstance(value, list):
        count = len(value)
        text = f"<array with {count:,} {'item' if count == 1 else 'items'}>"
    elif isinstance(value, int) and not isinstance(value, bool) and value.bit_length() > _MAX_SHOWN_INT_BITS:
        text = "<integer too large to display>"
    else:
        text = repr(value)
    return text if len(text) <= MAX_SHOWN_VALUE_CHARS else text[:MAX_SHOWN_VALUE_CHARS] + "…"


# Bound paths included in diagnostics.
MAX_SHOWN_PATH_CHARS = 200


def display_raw(value: Any) -> str:
    """One line, printable, bounded text that names an operator-supplied value.

    Paths are operator input, so they can hold a newline (which would start a
    second, operator-chosen log line) or an ESC sequence (which would repaint
    the terminal that runs ``cat`` on the log). Control characters are shown as
    escapes rather than dropped, so the value still names the file exactly.
    Build only the preview: escaping an arbitrarily long input before clipping
    it would allocate an arbitrarily long second string. This does NOT redact
    credentials -- callers that print untrusted path text go through
    ``display_path`` instead.
    """
    raw = str(value)
    preview = raw[: MAX_SHOWN_PATH_CHARS + 1]
    parts: list[str] = []
    length = 0
    for char in preview:
        if char.isprintable() and char not in "\u2028\u2029":
            piece = char
        else:
            piece = char.encode("unicode_escape").decode("ascii")
        if length + len(piece) > MAX_SHOWN_PATH_CHARS:
            return "".join(parts) + "…"
        parts.append(piece)
        length += len(piece)
    return "".join(parts) + ("…" if len(raw) > MAX_SHOWN_PATH_CHARS else "")


def display_path(path: Any) -> str:
    """A path as it should appear in a message: one line, printable, bounded.

    Same rules as ``display_raw``, with one addition: URL userinfo and common
    bare credential fields are redacted before the preview is clipped, because
    a path (or a ``--source`` value) can carry a token. Every module that shows
    a path uses this, so the escaping rules cannot drift per call site.

    ``display_raw`` is the escape-only half. It exists for text a caller has
    ALREADY redacted (a finished error message): re-running the redactor over
    it would inspect every ``key=value`` pair it mentions and, on a very long
    message, report it as an uninspectable URL.
    """
    return display_raw(_redact_diagnostic_preview(str(path), MAX_SHOWN_PATH_CHARS))


def error_reason(exc: BaseException) -> str:
    """The human half of an OS error, without it repeating the path we just named.

    ``str(OSError)`` is ``[Errno 2] No such file or directory: '<the whole
    path>'``, so a 100,000-character path would land in the message twice --
    once clipped by ``display_path`` and once at full length here. ``strerror``
    is the part that explains what went wrong; anything without one (a
    ``ValueError`` from an unencodable path, say) falls back to ``str``.
    """
    return getattr(exc, "strerror", None) or str(exc)


def read_bounded_regular_file(path: Path, max_bytes: int) -> bytes:
    """Read at most ``max_bytes + 1`` from a regular file, without blocking on a FIFO.

    Refuse known special files before opening them, then open non-blocking and
    inspect the descriptor too: the path could be replaced after ``stat()``,
    and a FIFO must never block the open. A device or FIFO is not a
    database/source file; refusing it avoids a hang or side effect.
    """
    try:
        path_status = path.stat()
    except FileNotFoundError:
        # Let os.open report missing paths consistently, including broken symlinks.
        pass
    else:
        if not stat.S_ISREG(path_status.st_mode):
            raise OSError(errno.EINVAL, "not a regular file", os.fspath(path))

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", os.fspath(path))
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            return handle.read(max_bytes + 1)
    finally:
        if fd >= 0:
            os.close(fd)


class PlayerListError(Exception):
    """Raised when a playerlist cannot be read or is structurally invalid."""


class Player(TypedDict, total=False):
    """One entry of a TF2BD playerlist."""

    steamid: str | int
    attributes: list[str]
    proof: list[str]
    last_seen: dict[str, Any]


PlayerList = TypedDict(
    "PlayerList",
    {"$schema": str, "file_info": dict[str, Any], "players": list[Player]},
    total=False,
)


def _account_from_steamid64(value: int) -> int | None:
    """Convert a SteamID64 to its 32-bit account id.

    Purely arithmetic (no ``str(value)``), so absurdly large integers --
    e.g. a JSON number with thousands of digits -- are rejected instead of
    tripping Python's int-to-string digit limit.
    """
    account = value - STEAMID64_BASE
    return account if 0 < account < MAX_ACCOUNT_ID else None


def _bounded_int(digits: str) -> int | None:
    """Parse an ASCII decimal string, or return ``None`` if it is unusable.

    Rejects anything that is not plain ASCII digits (``int()`` would raise on
    "²" and would happily accept "١٢٣"), and rejects more than 10 significant
    digits: that also guards Python's int-parsing digit limit, which a SteamID
    of thousands of digits (hostile or corrupted input) would otherwise hit.
    Account ids fit in 10 digits, so anything longer is out of range anyway;
    leading zeros are ignored.
    """
    if not (digits.isascii() and digits.isdigit()):
        return None
    significant = digits.lstrip("0") or "0"
    if len(significant) > 10:
        return None
    return int(significant)


def normalize_steamid(value: Any) -> str | None:
    """Return canonical ``[U:1:<account id>]`` form, or ``None`` if unusable.

    Accepts canonical ``[U:1:x]``, bare ``U:1:x``, ``[U:1:x:instance]``,
    public/legacy ``STEAM_0:y:z`` or ``STEAM_1:y:z``, SteamID64 integers/strings,
    and complete Steam Community
    ``/profiles/<SteamID64>`` permalinks (optionally with scheme/``www``/slash).
    """
    if isinstance(value, bool):  # bool is an int subclass, but not a SteamID
        return None

    if isinstance(value, int):
        account = value if 0 < value < MAX_ACCOUNT_ID else _account_from_steamid64(value)
        return f"{CANONICAL_PREFIX}{account}{CANONICAL_SUFFIX}" if account else None

    if not isinstance(value, str):
        return None

    text = value.strip()
    for pattern in (_U_RE, _U_BARE_RE):
        match = pattern.match(text)
        if match:
            account = _bounded_int(match.group(1))
            # Reject zero and values outside the 32-bit account-ID range.
            if account is None or not 0 < account < MAX_ACCOUNT_ID:
                return None
            return f"{CANONICAL_PREFIX}{account}{CANONICAL_SUFFIX}"

    match = _U_INSTANCE_RE.match(text)
    if match:
        account = _bounded_int(match.group(1))
        instance = _bounded_int(match.group(2))
        # The instance field is 20 bits; reject out-of-range values before canonicalizing.
        if account is None or not 0 < account < MAX_ACCOUNT_ID or instance is None or instance >= MAX_STEAMID_INSTANCE:
            return None
        return f"{CANONICAL_PREFIX}{account}{CANONICAL_SUFFIX}"

    match = _STEAM2_RE.match(text)
    if match:
        # STEAM_X:Y:Z encodes the account ID as 2 * Z + Y.
        auth_server, account_half = match.groups()
        half = _bounded_int(account_half)
        if half is None:
            return None
        account = half * 2 + int(auth_server)
        return f"{CANONICAL_PREFIX}{account}{CANONICAL_SUFFIX}" if 0 < account < MAX_ACCOUNT_ID else None

    if _STEAMID64_RE.match(text):
        account = _account_from_steamid64(int(text))
        if account is not None:
            return f"{CANONICAL_PREFIX}{account}{CANONICAL_SUFFIX}"
        # A 17-digit string below the SteamID64 base may be a zero-padded account ID.

    if text.isascii() and text.isdigit():
        # Accept bare account IDs as strings as well as integers.
        account = _bounded_int(text)
        if account is None or not 0 < account < MAX_ACCOUNT_ID:
            return None
        return f"{CANONICAL_PREFIX}{account}{CANONICAL_SUFFIX}"

    match = _PROFILE_URL_RE.fullmatch(text)
    if match:
        account = _account_from_steamid64(int(match.group(1)))
        return f"{CANONICAL_PREFIX}{account}{CANONICAL_SUFFIX}" if account else None

    return None


def account_id(steamid: Any) -> int | None:
    """Numeric account id of a SteamID in any accepted notation."""
    canonical = normalize_steamid(steamid)
    if canonical is None:
        return None
    return int(canonical[len(CANONICAL_PREFIX) : -len(CANONICAL_SUFFIX)])


def steamid64(steamid: Any) -> int | None:
    """SteamID64 form of a SteamID, or ``None`` if the SteamID is unusable.

    ``[U:1:269327660]`` -> ``76561198229593388`` (``STEAMID64_BASE`` + account id).
    Shared by every permalink below, so all of them agree on what is usable.
    """
    account = account_id(steamid)
    return None if account is None else STEAMID64_BASE + account


def steam_profile_url(steamid: Any) -> str | None:
    """Steam Community profile permalink for a SteamID, or ``None`` if unusable.

    The permalink is the SteamID64 form, e.g. ``[U:1:269327660]`` ->
    ``https://steamcommunity.com/profiles/76561198229593388``.
    """
    id64 = steamid64(steamid)
    return None if id64 is None else f"https://steamcommunity.com/profiles/{id64}"


def steam_history_url(steamid: Any) -> str | None:
    """SteamHistory profile page for a SteamID, or ``None`` if unusable.

    SteamHistory archives a profile's past names, avatars and bans, so it keeps
    working after the player renames themselves: ``[U:1:269327660]`` ->
    ``https://steamhistory.net/id/76561198229593388`` (same SteamID64 as the
    Steam Community permalink).
    """
    id64 = steamid64(steamid)
    return None if id64 is None else f"https://steamhistory.net/id/{id64}"


def player_name(player: Player) -> str:
    """Last known player name, or an empty string when the entry has none.

    Only a string or an integer counts as a name. TF2BD writes a string, so a
    JSON object or array in that position is malformed -- and ``str()`` of one
    would put Python syntax (``{'a': 1}``) in the review table, where the
    UNKNOWN placeholder is the honest answer.
    """
    last_seen = player.get("last_seen")
    if not isinstance(last_seen, dict):
        return ""
    value = last_seen.get("player_name")
    if isinstance(value, bool) or not isinstance(value, (str, int)):  # bool is an int subclass, but not a player name
        return ""
    return value if isinstance(value, str) else _shown(value)


def _player_sort_key(player: Player) -> tuple[bool, int]:
    # Invalid entries sort last; stable sorting preserves their input order.
    account = account_id(player.get("steamid")) if isinstance(player, dict) else None
    return (account is None, account or 0)


def sort_players(players: Iterable[Player]) -> list[Player]:
    """Sort by numeric SteamID; entries with an unusable SteamID go last, stably."""
    return sorted(players, key=_player_sort_key)


_ATTRIBUTE_RANK = {attribute: rank for rank, attribute in enumerate(ATTRIBUTE_ORDER)}


def _attribute_rank(attribute: str) -> tuple[int, str]:
    """Sort known attributes by schema order, unknown ones last and alphabetically."""
    return (_ATTRIBUTE_RANK.get(attribute, len(ATTRIBUTE_ORDER)), attribute)


def order_attributes(attributes: Iterable[str]) -> list[str]:
    """De-duplicate attributes and order them like the rest of the file."""
    return sorted(dict.fromkeys(attributes), key=_attribute_rank)


def dumps(database: PlayerList) -> str:
    """Serialise a playerlist exactly like the committed file.

    Tab indentation, alphabetically sorted keys, ASCII escapes and a trailing
    newline: re-serialising an untouched file produces byte-identical output.
    """
    return json.dumps(database, indent="\t", sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"


class _StrictJSONError(ValueError):
    """Input the standard library accepts but standard JSON does not."""


def _reject_constant(name: str) -> Any:
    """Refuse ``NaN``/``Infinity``/``-Infinity``, which are NOT JSON."""
    raise _StrictJSONError(f"{name} is not valid JSON (only standard JSON numbers are accepted)")


def _reject_out_of_range_float(text: str) -> float:
    """Refuse a number that overflows a double into infinity.

    ``1e999`` is valid JSON *syntax* and ``json`` quietly turns it into ``inf``
    -- which is not a number this tool can write back out (``dumps`` refuses
    it, exactly as TF2BD's strict parser would). Such a file could never be
    round-tripped, and the failure surfaced as an uncaught ``ValueError`` deep
    inside the writer, i.e. as a traceback. Refusing it here names the file
    instead. The literal is quoted through ``_shown``: it can be as long as the
    file, and this message goes to a terminal.
    """
    value = float(text)
    if not math.isfinite(value):
        raise _StrictJSONError(f"{_shown(text)} is out of range for a JSON number")
    return value


def _parse_json_int(text: str) -> int:
    """Parse a JSON integer with a fixed digit cap across supported Python versions."""
    digits = text[1:] if text.startswith("-") else text
    if len(digits) > 4_300:
        raise _StrictJSONError(f"{_shown(text)} is out of range for a JSON integer")
    return int(text)


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse an object that defines the same key twice.

    ``json`` silently keeps the last one: a file with two ``attributes`` keys
    would half-disappear on the next write, and two ``players`` keys would
    turn a full database into whatever the second one says.
    """
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise _StrictJSONError(f"duplicate key {_shown(key)} in the same object")
        seen[key] = value
    return seen


def strict_json_loads(raw: str | bytes) -> Any:
    """Parse JSON while rejecting non-standard, lossy, or unbounded numbers.

    The standard library accepts ``NaN``/``Infinity``, turns overflowing floats
    into infinity, and permits integer parsing limits to vary by Python version;
    duplicate keys silently discard data. These cases could otherwise crash,
    lose information, or consume excessive resources before the tool can name
    the file. Everything else behaves like ``json.loads``.
    """
    return json.loads(
        raw,
        parse_constant=_reject_constant,
        parse_float=_reject_out_of_range_float,
        parse_int=_parse_json_int,
        object_pairs_hook=_reject_duplicates,
    )


def load(path: Path) -> tuple[PlayerList, str]:
    """Read a playerlist, returning the parsed document and its original text.

    The file must be UTF-8: that is what ``dumps()`` writes, so accepting any
    other encoding here would guarantee a spurious rewrite of a file the run
    did not otherwise change. A leading byte-order mark IS accepted, because
    it is still UTF-8 (some editors add one) and because the upstream list is
    read through the same lenient-decoding path -- refusing it in one place
    and allowing it in the other would be a trap. A rewrite drops the mark,
    matching what ``dumps()`` writes.
    """
    try:
        # Bound reads to regular files and enforce the limit on actual bytes read.
        raw = read_bounded_regular_file(path, MAX_FILE_BYTES)
    except (OSError, ValueError) as exc:
        # ValueError also covers paths the OS cannot encode (for example, NUL).
        raise PlayerListError(f"cannot read {display_path(path)}: {error_reason(exc)}") from exc
    if len(raw) > MAX_FILE_BYTES:
        limit = MAX_FILE_BYTES // (1024 * 1024)
        raise PlayerListError(f"{display_path(path)} is larger than the {limit} MiB safety limit")
    try:
        # utf-8-sig accepts UTF-8 files with or without a BOM.
        original = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PlayerListError(f"cannot read {display_path(path)}: {error_reason(exc)}") from exc
    try:
        database = strict_json_loads(original)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        # ValueError also covers Python's integer digit limit.
        raise PlayerListError(f"{display_path(path)} is not valid JSON: {exc}") from exc
    if not isinstance(database, dict):
        raise PlayerListError(f"{display_path(path)} does not contain a JSON object")
    return cast("PlayerList", database), original


@dataclass
class ValidationResult:
    """Problems found in a playerlist: errors block writing, warnings do not.

    Keep only a bounded number of details. A syntactically small file can
    contain hundreds of thousands of malformed entries; retaining and logging
    one message per issue would turn validation into a memory and log flood.
    Counts remain exact even when details are omitted.
    """

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors_omitted: int = 0
    warnings_omitted: int = 0

    def add_error(self, message: str) -> None:
        if len(self.errors) < MAX_VALIDATION_MESSAGES:
            self.errors.append(message)
        else:
            self.errors_omitted += 1

    def add_warning(self, message: str) -> None:
        if len(self.warnings) < MAX_VALIDATION_MESSAGES:
            self.warnings.append(message)
        else:
            self.warnings_omitted += 1

    @property
    def error_count(self) -> int:
        return len(self.errors) + self.errors_omitted

    @property
    def warning_count(self) -> int:
        return len(self.warnings) + self.warnings_omitted

    def __bool__(self) -> bool:
        return not self.errors and self.errors_omitted == 0


def validate(database: PlayerList) -> ValidationResult:
    """Check the invariants this tool relies on (unique, usable SteamIDs)."""
    result = ValidationResult()

    players = database.get("players")
    if not isinstance(players, list):
        result.add_error("'players' is not an array")
        return result

    seen: set[str] = set()
    for position, player in enumerate(players):
        if not isinstance(player, dict):
            result.add_error(f"players[{position}] is not an object")
            continue

        steamid = player.get("steamid")
        canonical = normalize_steamid(steamid)
        if canonical is None:
            # Quote and bound untrusted values before logging.
            result.add_error(f"players[{position}] has an unusable steamid: {_shown(steamid)}")
            shown = _shown(steamid)
        else:
            shown = canonical
            if canonical in seen:
                result.add_error(f"duplicate steamid {canonical}")
            else:
                seen.add(canonical)

        attributes = player.get("attributes")
        if not isinstance(attributes, list) or not attributes:
            result.add_error(f"players[{position}] ({shown}) has no attributes")
            continue
        if not all(isinstance(attribute, str) for attribute in attributes):
            # Keep unhashable values out of set().
            result.add_error(f"players[{position}] ({shown}) has a non-string attribute")
            continue
        if len(set(attributes)) != len(attributes):
            result.add_error(f"players[{position}] ({shown}) has duplicate attributes")
        for attribute in attributes:
            if attribute not in KNOWN_ATTRIBUTES:
                result.add_warning(f"players[{position}] ({shown}) uses unknown attribute {_shown(attribute)}")

        # Demotion filters proof values, so present entries must be lists of strings.
        proof = player.get("proof")
        if "proof" in player and (not isinstance(proof, list) or not all(isinstance(item, str) for item in proof)):
            result.add_error(f"players[{position}] ({shown}) has a malformed 'proof' (must be an array of strings)")

    return result
