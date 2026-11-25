"""TF2BD playerlist file format helpers.

Handles SteamID normalization, reading/writing playerlist JSON, validation,
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
import unicodedata
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

# CPython refuses to build an int from more than 4,300 digits by default; cap
# the text before ``int()`` so the limit is ours and not a version-dependent
# ValueError. See sys.set_int_max_str_digits.
MAX_JSON_INT_DIGITS = 4_300
# A Steam account id is a 32-bit value, so it never needs more than 10 digits.
MAX_ACCOUNT_ID_DIGITS = 10
# Below this length a mixed-case blob is an ordinary word, not a credential.
MIN_OPAQUE_CREDENTIAL_CHARS = 12

# The playerlist files declare the TF2BD v3 schema, and that schema is stricter
# about shape than this tool needs to be about meaning. normalize_steamid
# deliberately reads legacy and SteamID64 spellings so an upstream list in any
# format can be matched, but a file that *stores* one of those spellings is
# rejected by the editor validating against the declared schema. Warn, never
# fail: the sync itself works fine either way.
SCHEMA_STEAMID = re.compile(r"\[[A-Za-z]:\d:\d+(?::\d+)?\]")
SCHEMA_LAST_SEEN_KEYS = frozenset({"player_name", "time"})
SCHEMA_ENTRY_KEYS = frozenset({"attributes", "last_seen", "proof", "steamid"})

# Substrings that make a field or query-parameter name look like a credential.
#
# This is the single vocabulary both redactors share: ``sources`` applies it to
# URL query names and this module applies it to free-form diagnostic text. Two
# hand-maintained copies drifted apart once already (``key``, ``pass`` and
# ``passphrase`` were redacted in URLs but printed in diagnostics), so the list
# lives here, in the module both importers depend on.
#
# Matching is deliberately by substring, so ``pass`` also covers ``password``,
# ``passwd`` and ``passphrase``, and ``key`` covers ``api_key``, ``ssh-key`` and
# ``appkey``. That over-matches ordinary words such as ``monkey``: a redundant
# ``REDACTED`` costs nothing, while a missed credential cannot be recalled once
# it is in a public log.
CREDENTIAL_NAME_MARKERS = (
    r"token|secret|pass|pwd|auth|credential|session|sid|cookie|csrf|xsrf|code|sig|key|"
    r"jwt|bearer|hmac|nonce|state|ticket|otp|mfa|assertion|saml|x-amz|x-goog"
)

# Diagnostics can contain free-form values, not just URLs. Redact common
# credential fields and authorization headers even when they appear in prose.
_DIAGNOSTIC_SECRET_MARKER = re.compile(CREDENTIAL_NAME_MARKERS, re.IGNORECASE | re.ASCII)
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
    r"(?P<prefix>(?:https?:/{0,4}|//))[^/\s?#<>\"'`@]*(?:@|%(?:25)*40)",
    re.IGNORECASE | re.ASCII,
)
# The pattern above reads a URL as one token, so a blank inside the userinfo
# ends the run before the ``@`` and the credential survives -- the same hole
# ``sources._SPLIT_USERINFO_IN_TEXT`` closes for prose, reached here through
# the diagnostic preview of an unusable database value (which lands in a
# public job log). The run before the break character must itself exclude
# break characters: letting a blank match either the class or the repeat
# costs cubic time on a long run with no closing ``@``.
_SPLIT_USERINFO_IN_DIAGNOSTIC = re.compile(
    r"(?P<prefix>(?:https?:/{0,4}|//))[^/@?#<>\"'`\s]*[<>\"'`\s][^/@?#]*(?:@|%(?:25)*40)",
    re.IGNORECASE | re.ASCII,
)
# Identify nested percent-encoded URL schemes before they are clipped out of view.
_ENCODED_HTTP_SCHEME = re.compile(r"https?(?:%(?:25)*3a|:(?:%(?:25)*2f))", re.IGNORECASE | re.ASCII)
_PERCENT_ESCAPE_IN_TEXT = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE | re.ASCII)
_PERCENT_ESCAPE = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE | re.ASCII)
# Field names keep plain characters plus percent escapes and HTML references.
_FIELD_NAME_CHARS = re.compile(r"[A-Za-z0-9_.%-]+", re.ASCII)
# Characters a server ignores when matching a name are stripped by Unicode
# category rather than by an enumerated list: the hand-written list used to
# omit U+00AD SOFT HYPHEN, so ``to<shy>ken=`` walked straight past the
# redactor while the same name was caught inside a URL.
# A query-style pair anywhere in free text: find the name, then its value.
_QUERY_PAIR_IN_TEXT = re.compile(r"[?&#;](?P<name>[^\s=&?#;]+)=(?P<value>[^\s&;#]*)", re.ASCII)
_MAX_DIAGNOSTIC_DECODE_DEPTH = 8
# Lone surrogates: JSON can encode them, UTF-8 cannot. Replace before output.
SURROGATE_RE = re.compile(r"[\ud800-\udfff]")


def fold_name_for_matching(name: str) -> str:
    """Fold a field or query-parameter name to the spelling a matcher should see.

    Compatibility normalization first, so full-width and look-alike spellings
    (``\uff54oken``, ``\u212aey``, ``\u017fecret``) collapse onto the ASCII letters they
    imitate, then every control, format and separator character is dropped -
    by Unicode category, so a newly assigned invisible character is covered
    the day it exists rather than whenever the list is next updated.

    Shared with ``sources`` so a name cannot be sensitive in a URL and
    harmless in a diagnostic.
    """
    folded = unicodedata.normalize("NFKC", name)
    return "".join(char for char in folded if unicodedata.category(char)[0] not in {"C", "Z"}).casefold()


def _normalized_field_name(name: str) -> str | None:
    """Decode an obfuscated field name, or ``None`` if it is not a plain name.

    A query key can percent-encode its separator (``to%0Aken``), use HTML
    character references, or carry invisible characters a server strips before
    looking the credential up. Redaction has to be at least as permissive as
    that normalization, or the encoded spelling quietly walks past it.
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
    decoded = fold_name_for_matching(decoded)
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
    normalized = _normalized_field_name(name)
    return normalized is not None and _DIAGNOSTIC_SECRET_MARKER.search(normalized) is not None


def _names_a_secret_before(value: str, separator: int) -> bool:
    """True when the field name ending at ``separator`` is a credential name.

    Reads backwards over any blanks, one optional quote, then the run of
    characters a field name may use, so ``"api_key" : x`` is recognised as
    readily as ``api_key=x``.
    """
    key_end = separator
    while key_end and value[key_end - 1].isspace():
        key_end -= 1
    if key_end and value[key_end - 1] in "'\"":
        key_end -= 1
    key_start = key_end
    while key_start and value[key_start - 1] in _DIAGNOSTIC_FIELD_CHARS:
        key_start -= 1
    return _is_secret_field_name(value[key_start:key_end])


def _unquoted_value_end(value: str, start: int) -> int:
    """Index just past a bare value: everything up to the next delimiter."""
    end = start
    while end < len(value) and value[end] not in _DIAGNOSTIC_VALUE_DELIMITERS:
        end += 1
    return end


def _quoted_value_end(value: str, start: int, quote: str) -> int:
    """Index just past a quoted value, honouring backslash escapes."""
    end = start + 1
    escaped = False
    while end < len(value):
        char = value[end]
        end += 1
        if char == quote and not escaped:
            break
        escaped = char == "\\" and not escaped
        if char != "\\":
            escaped = False
    return end


def _secret_value_span(value: str, separator: int) -> tuple[int, int, bool] | None:
    """Locate the value after ``separator`` as ``(start, end, quoted)``.

    ``None`` means there is no value to redact -- the text ended, or the next
    character already delimits the next field.
    """
    start = separator + 1
    while start < len(value) and value[start].isspace():
        start += 1
    if start == len(value) or value[start] in _DIAGNOSTIC_VALUE_DELIMITERS:
        return None
    quote = value[start] if value[start] in "'\"" else ""
    if not quote:
        return start, _unquoted_value_end(value, start), False
    end = _quoted_value_end(value, start, quote)
    if end - start == 2:
        # An empty quoted body, as in ``password=''SECRET``. Redacting the
        # empty body would leave the secret itself in the message, so treat
        # the pair as unquoted and take everything up to the delimiter.
        return start, _unquoted_value_end(value, start), False
    return start, end, True


def _redact_diagnostic_secret_pairs(value: str) -> str:
    """Redact sensitive fields with a linear scan instead of a backtracking regex."""
    parts: list[str] = []
    copied_through = 0
    separator = 0
    while separator < len(value):
        if value[separator] not in "=:" or not _names_a_secret_before(value, separator):
            separator += 1
            continue
        span = _secret_value_span(value, separator)
        if span is None:
            separator += 1
            continue
        value_start, value_end, quoted = span

        trailing = ""
        if not quoted:
            raw_value = value[value_start:value_end]
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
    players in the output. A credential is recognized by its shape instead:

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
    return (
        len(token) >= MIN_OPAQUE_CREDENTIAL_CHARS
        and any(c.isupper() for c in token)
        and any(c.islower() for c in token)
    )


def _redact_bearer_match(match: re.Match[str]) -> str:
    """Redact a bearer/basic match only when its credential looks like one."""
    token = match.group("credential")
    if not _looks_like_credential(token, match.group("separator")):
        return match.group(0)
    return f"{match.group('scheme')} REDACTED"


def _redact_literal_diagnostic_text(value: str) -> str:
    """Redact the text exactly as written, without decoding any spelling of it."""
    value = _AUTHORIZATION_HEADER.sub(r"\g<header>REDACTED", value)
    value = _BEARER_CREDENTIAL.sub(_redact_bearer_match, value)
    # Drop a blank-split userinfo span whole before the single-token pattern runs.
    value = _SPLIT_USERINFO_IN_DIAGNOSTIC.sub(r"\g<prefix>REDACTED@", value)
    value = _URL_USERINFO_IN_TEXT.sub(r"\g<prefix>REDACTED@", value)
    return _redact_encoded_query_pairs(_redact_diagnostic_secret_pairs(value))


def redact_diagnostic_text(value: str) -> str:
    """Redact common bare secrets, authorization headers, and URL userinfo.

    A credential's *field name* can be spelled with HTML character references
    (``&#116;&#111;&#107;&#101;&#110;=SECRET``), which matches no field name
    this module knows -- so the secret was printed verbatim into diagnostics,
    and from there into a public job log. Percent-encoding of the same trick
    was already decoded before matching; character references now are too.

    Each decoded layer is inspected in turn and the first one that reveals a
    credential wins, because decoding can expose a different secret at each
    level. Text whose decoded view needs no redaction keeps the spelling the
    caller wrote: a benign ``&amp;`` in a player name is not rewritten.
    """
    shown = _redact_literal_diagnostic_text(value)
    decoded = value
    for _ in range(_MAX_DIAGNOSTIC_DECODE_DEPTH):
        step = html.unescape(decoded)
        if step == decoded:
            break
        decoded = step
        from_entities = _redact_literal_diagnostic_text(decoded)
        if from_entities != decoded:
            return from_entities
    return shown


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
    if len(significant) > MAX_ACCOUNT_ID_DIGITS:
        return None
    return int(significant)


def _canonical_account(account: int | None) -> str | None:
    """Format an account id, rejecting zero and anything outside the 32-bit range."""
    if account is None or not 0 < account < MAX_ACCOUNT_ID:
        return None
    return f"{CANONICAL_PREFIX}{account}{CANONICAL_SUFFIX}"


def _canonical_from_int(value: int) -> str | None:
    """A bare integer is an account id when it is in range, and a SteamID64 otherwise."""
    account = value if 0 < value < MAX_ACCOUNT_ID else _account_from_steamid64(value)
    return _canonical_account(account)


def _canonical_from_instance(match: re.Match[str]) -> str | None:
    """``[U:1:account:instance]`` -- the instance field is 20 bits wide."""
    instance = _bounded_int(match.group(2))
    if instance is None or instance >= MAX_STEAMID_INSTANCE:
        return None
    return _canonical_account(_bounded_int(match.group(1)))


def _canonical_from_steam2(match: re.Match[str]) -> str | None:
    """``STEAM_X:Y:Z`` encodes the account id as ``2 * Z + Y``."""
    auth_server, account_half = match.groups()
    half = _bounded_int(account_half)
    if half is None:
        return None
    return _canonical_account(half * 2 + int(auth_server))


def normalize_steamid(value: Any) -> str | None:
    """Return canonical ``[U:1:<account id>]`` form, or ``None`` if unusable.

    Accepts canonical ``[U:1:x]``, bare ``U:1:x``, ``[U:1:x:instance]``,
    public/legacy ``STEAM_0:y:z`` or ``STEAM_1:y:z``, SteamID64 integers/strings,
    and complete Steam Community
    ``/profiles/<SteamID64>`` permalinks (optionally with scheme/``www``/slash).
    """
    if isinstance(value, bool):  # bool is an int subclass, but not a SteamID.
        return None
    if isinstance(value, int):
        return _canonical_from_int(value)
    if not isinstance(value, str):
        return None

    text = value.strip()
    for pattern in (_U_RE, _U_BARE_RE):
        match = pattern.match(text)
        if match:
            return _canonical_account(_bounded_int(match.group(1)))

    match = _U_INSTANCE_RE.match(text)
    if match:
        return _canonical_from_instance(match)

    match = _STEAM2_RE.match(text)
    if match:
        return _canonical_from_steam2(match)

    if _STEAMID64_RE.match(text):
        canonical = _canonical_account(_account_from_steamid64(int(text)))
        # Not a return: a 17-digit string below the SteamID64 base is not a
        # SteamID64 at all, and may still be a zero-padded account id below.
        if canonical is not None:
            return canonical

    if text.isascii() and text.isdigit():
        # Accept bare account IDs as strings as well as integers.
        return _canonical_account(_bounded_int(text))

    match = _PROFILE_URL_RE.fullmatch(text)
    if match:
        return _canonical_account(_account_from_steamid64(int(match.group(1))))

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
    # bool is an int subclass, but not a player name.
    if isinstance(value, bool) or not isinstance(value, (str, int)):
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
    """Serialize a playerlist exactly like the committed file.

    Tab indentation, alphabetically sorted keys, ASCII escapes and a trailing
    newline: re-serializing an untouched file produces byte-identical output.
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
    digits = text.removeprefix("-")
    if len(digits) > MAX_JSON_INT_DIGITS:
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
        """Record an error, counting rather than keeping it past the cap."""
        if len(self.errors) < MAX_VALIDATION_MESSAGES:
            self.errors.append(message)
        else:
            self.errors_omitted += 1

    def add_warning(self, message: str) -> None:
        """Record a warning, counting rather than keeping it past the cap."""
        if len(self.warnings) < MAX_VALIDATION_MESSAGES:
            self.warnings.append(message)
        else:
            self.warnings_omitted += 1

    @property
    def error_count(self) -> int:
        """Every error seen, including those dropped at the cap."""
        return len(self.errors) + self.errors_omitted

    @property
    def warning_count(self) -> int:
        """Every warning seen, including those dropped at the cap."""
        return len(self.warnings) + self.warnings_omitted

    def __bool__(self) -> bool:
        """True when nothing blocked the file from being used."""
        return not self.errors and self.errors_omitted == 0


def _check_declared_schema(result: ValidationResult, position: int, shown: str, player: Player) -> None:
    """Warn about shapes the declared TF2BD schema rejects but this tool tolerates.

    These are warnings on purpose. None of them stops a sync - the tool reads a
    legacy SteamID spelling perfectly well, and a missing ``last_seen.time``
    only costs a player name in the report - but each one makes the file fail
    validation in an editor, and the file names that schema itself.
    """
    steamid = player.get("steamid")
    canonical = normalize_steamid(steamid)
    # Only a *resolvable* id stored in the wrong spelling is worth saying. An
    # unresolvable one already produced an error naming the same field, and one
    # problem per field is the rule everywhere else in here.
    if canonical is not None and isinstance(steamid, str) and not SCHEMA_STEAMID.fullmatch(steamid):
        result.add_warning(
            f"players[{position}] ({shown}) stores a steamid the declared schema rejects, expected {canonical}"
        )

    unexpected_entry = sorted(set(player) - SCHEMA_ENTRY_KEYS)
    if unexpected_entry:
        shown_keys = ", ".join(_shown(key) for key in unexpected_entry[:3])
        label = "key" if len(unexpected_entry) == 1 else "keys"
        result.add_warning(f"players[{position}] ({shown}) has unexpected {label}: {shown_keys}")

    if "last_seen" not in player:
        return
    last_seen = player.get("last_seen")
    if not isinstance(last_seen, dict):
        result.add_warning(f"players[{position}] ({shown}) has a 'last_seen' that is not an object")
        return
    moment = last_seen.get("time")
    # bool is an int subclass; "time": true is not a timestamp.
    if isinstance(moment, bool) or not isinstance(moment, int):
        result.add_warning(
            f"players[{position}] ({shown}) has a 'last_seen' without an integer 'time', which the schema requires"
        )
    name = last_seen.get("player_name")
    if "player_name" in last_seen and not isinstance(name, str):
        result.add_warning(f"players[{position}] ({shown}) has a non-string 'last_seen.player_name'")
    unexpected = sorted(set(last_seen) - SCHEMA_LAST_SEEN_KEYS)
    if unexpected:
        shown_keys = ", ".join(_shown(key) for key in unexpected[:3])
        label = "key" if len(unexpected) == 1 else "keys"
        result.add_warning(f"players[{position}] ({shown}) has unexpected 'last_seen' {label}: {shown_keys}")


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
            # Quote and bound untrusted values before logging. Build the preview once:
            # it redacts and escapes a value that can be as long as the file allows.
            shown = _shown(steamid)
            result.add_error(f"players[{position}] has an unusable steamid: {shown}")
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

        _check_declared_schema(result, position, shown, player)

    return result
