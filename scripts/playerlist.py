"""TF2BD playerlist file format helpers.

Handles SteamID normalisation, reading/writing playerlist JSON, validation,
sorting and attribute ordering. Nothing here knows about the Vorobey
hackerpolice list.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypedDict, cast

STEAMID64_BASE = 76561197960265728
MAX_ACCOUNT_ID = 2**32
MAX_STEAMID_INSTANCE = 2**20

# Sanity cap on a playerlist file this tool reads. The real database is ~110 kB
# and the upstream list ~1.9 MB, so this is far beyond anything legitimate --
# but without it a 4 GB file (or a device that never ends) would be read
# straight into memory and the run would die with a MemoryError traceback
# instead of a clean refusal. The download path has always had this limit
# (``sources.MAX_SOURCE_BYTES``); the local reads did not.
MAX_FILE_BYTES = 64 * 1024 * 1024

CANONICAL_PREFIX = "[U:1:"
CANONICAL_SUFFIX = "]"

# Attributes recognised by the TF2BD v3 schema, in the order used when writing.
ATTRIBUTE_ORDER: tuple[str, ...] = ("cheater", "suspicious", "exploiter", "racist")
KNOWN_ATTRIBUTES = frozenset(ATTRIBUTE_ORDER)

# ASCII digits only: \d also matches Arabic-Indic/Devanagari digits and
# str.isdigit() also accepts things like "²" that int() then refuses, so a
# corrupted or hostile SteamID could crash the run (or silently mint an id
# from "١٢٣"). Every pattern and parser below is ASCII-strict.
_ACCOUNT_ID_RE = re.compile(r"[0-9]+")
# The canonical form is written upper-case by TF2BD, but matching is
# case-insensitive on every notation so a hand-edited "[u:1:…]" still maps to
# the same player (and is caught as a duplicate by validate()).
_U_RE = re.compile(rf"^\[U:1:({_ACCOUNT_ID_RE.pattern})\]$", re.IGNORECASE | re.ASCII)
_U_BARE_RE = re.compile(rf"^U:1:({_ACCOUNT_ID_RE.pattern})$", re.IGNORECASE | re.ASCII)
_U_INSTANCE_RE = re.compile(
    rf"^\[U:1:({_ACCOUNT_ID_RE.pattern}):({_ACCOUNT_ID_RE.pattern})\]$", re.IGNORECASE | re.ASCII
)
_STEAM2_RE = re.compile(rf"^STEAM_[0-5]:([01]):({_ACCOUNT_ID_RE.pattern})$", re.IGNORECASE | re.ASCII)
_STEAMID64_RE = re.compile(r"^[0-9]{17}$")
# An entire Steam Community permalink, not a matching substring in arbitrary
# text or a lookalike host (either could silently alias a victim's SteamID).
_PROFILE_URL_RE = re.compile(
    r"(?:https?://)?(?:www\.)?steamcommunity\.com/profiles/([0-9]{17})/?", re.IGNORECASE | re.ASCII
)


# How much of an arbitrary value a validation message quotes. These messages go
# to a terminal and to the CI log, and the value comes from the file, so it can
# be anything the file contains: an entry whose "steamid" is a 3 MB string used
# to print a single 3,000,038-character line, which buries the error it is meant
# to explain (and every other error after it, once GitHub truncates the log).
MAX_SHOWN_VALUE_CHARS = 120
# Bound decimal conversion as well as the final message length: repr(10**100000)
# allocates the entire number before the preview can be clipped.
_MAX_SHOWN_INT_BITS = MAX_SHOWN_VALUE_CHARS * 4
MAX_VALIDATION_MESSAGES = 100


def _shown(value: Any) -> str:
    """A bounded, quoted preview so one bad entry cannot flood the log or RAM.

    Strings are sliced before ``repr``: clipping its result afterwards still
    allocated an escaped copy of an attacker-supplied 64 MiB value. JSON
    arrays/objects are summarized by shape rather than fully rendered for the
    same reason. ``repr`` rather than ``str`` keeps short scalar values safe: a
    newline cannot start a fake log line and an ESC cannot repaint the terminal.
    """
    if isinstance(value, str):
        text = repr(value if len(value) <= MAX_SHOWN_VALUE_CHARS else value[:MAX_SHOWN_VALUE_CHARS])
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


# How much of a path is ever printed. A path comes from the command line or a
# workflow variable, and a very long one would push the actual reason off the
# end of the message.
MAX_SHOWN_PATH_CHARS = 200


def display_path(path: Any) -> str:
    """A path as it should appear in a message: one line, printable, bounded.

    The path is operator input, so it can hold a newline (which would start a
    second, operator-chosen log line) or an ESC sequence (which would repaint
    the terminal that runs ``cat`` on the log). Control characters are shown as
    escapes rather than dropped, so the message still names the file exactly;
    ``str`` keeps it readable where ``repr`` would add quotes as well. Build
    only the preview: escaping an arbitrarily long input before clipping it
    would allocate an arbitrarily long second string.
    """
    parts: list[str] = []
    length = 0
    for char in str(path):
        if char.isprintable() and char not in "\u2028\u2029":
            piece = char
        else:
            piece = char.encode("unicode_escape").decode("ascii")
        if length + len(piece) > MAX_SHOWN_PATH_CHARS:
            return "".join(parts) + "…"
        parts.append(piece)
        length += len(piece)
    return "".join(parts)


def error_reason(exc: BaseException) -> str:
    """The human half of an OS error, without it repeating the path we just named.

    ``str(OSError)`` is ``[Errno 2] No such file or directory: '<the whole
    path>'``, so a 100,000-character path would land in the message twice --
    once clipped by ``display_path`` and once at full length here. ``strerror``
    is the part that explains what went wrong; anything without one (a
    ``ValueError`` from an unencodable path, say) falls back to ``str``.
    """
    return getattr(exc, "strerror", None) or str(exc)


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
    ``STEAM_0:y:z``, SteamID64 integers/strings, and complete Steam Community
    ``/profiles/<SteamID64>`` permalinks (optionally with scheme/``www``/slash).
    """
    if isinstance(value, bool):  # bool is an int subclass; not a SteamID
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
            # Account ids are 32-bit and never 0; reject out-of-range input
            # instead of minting a canonical ID no real account can have.
            if account is None or not 0 < account < MAX_ACCOUNT_ID:
                return None
            return f"{CANONICAL_PREFIX}{account}{CANONICAL_SUFFIX}"

    match = _U_INSTANCE_RE.match(text)
    if match:
        account = _bounded_int(match.group(1))
        instance = _bounded_int(match.group(2))
        # The instance occupies 20 bits in the SteamID layout. It does not
        # change the individual account, but an impossible instance must not
        # let arbitrary suffixes alias a valid SteamID.
        if account is None or not 0 < account < MAX_ACCOUNT_ID or instance is None or instance >= MAX_STEAMID_INSTANCE:
            return None
        return f"{CANONICAL_PREFIX}{account}{CANONICAL_SUFFIX}"

    match = _STEAM2_RE.match(text)
    if match:
        # STEAM_X:Y:Z -> account id is Z * 2 + Y (Y is the auth-server bit).
        # Same range rule as every other form: 32-bit and never 0.
        auth_server, account_half = match.groups()
        half = _bounded_int(account_half)
        if half is None:
            return None
        account = half * 2 + int(auth_server)
        return f"{CANONICAL_PREFIX}{account}{CANONICAL_SUFFIX}" if 0 < account < MAX_ACCOUNT_ID else None

    if _STEAMID64_RE.match(text):
        account = _account_from_steamid64(int(text))
        return f"{CANONICAL_PREFIX}{account}{CANONICAL_SUFFIX}" if account else None

    if text.isascii() and text.isdigit():
        # Bare account id given as a string, e.g. "1730017" (the int form of
        # this is accepted above, so accept the string form too).
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
    if isinstance(value, bool) or not isinstance(value, (str, int)):  # bool is an int subclass
        return ""
    return value if isinstance(value, str) else _shown(value)


def _player_sort_key(player: Player) -> tuple[bool, int]:
    # Non-object entries (malformed input the validator reports) sort last,
    # stably, instead of crashing the sort.
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
        # Read at most one byte past the limit: a special file (a device, a
        # fifo) reports no size at all, so the budget is enforced on the bytes
        # actually read, exactly like the download path.
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except (OSError, ValueError) as exc:
        # ValueError covers a path the operating system cannot even encode (an
        # embedded NUL, a lone surrogate): "this file cannot be read",
        # reported like any other unreadable file instead of a traceback.
        raise PlayerListError(f"cannot read {display_path(path)}: {error_reason(exc)}") from exc
    if len(raw) > MAX_FILE_BYTES:
        limit = MAX_FILE_BYTES // (1024 * 1024)
        raise PlayerListError(f"{display_path(path)} is larger than the {limit} MiB safety limit")
    try:
        # utf-8-sig == utf-8 for files without a mark, and strips it when present.
        original = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        # The file is not valid UTF-8. Report it like any other unreadable
        # file instead of crashing with a traceback.
        raise PlayerListError(f"cannot read {display_path(path)}: {error_reason(exc)}") from exc
    try:
        database = strict_json_loads(original)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        # ValueError: e.g. a JSON number with more digits than Python's
        # int-parsing limit -- invalid input, not a crash.
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
            # A value that reached this point is arbitrary input, and these
            # messages are printed to a terminal and to the CI log: str() would
            # let a newline start a fake log line and an ESC sequence repaint
            # the screen, so it is quoted with repr -- and clipped, because it
            # can be as large as the file. Every later message about this entry
            # reuses `shown`, so they are all bounded too.
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
            # Also guards the set() below against unhashable attribute values.
            result.add_error(f"players[{position}] ({shown}) has a non-string attribute")
            continue
        if len(set(attributes)) != len(attributes):
            result.add_error(f"players[{position}] ({shown}) has duplicate attributes")
        for attribute in attributes:
            if attribute not in KNOWN_ATTRIBUTES:
                result.add_warning(f"players[{position}] ({shown}) uses unknown attribute {_shown(attribute)}")

        # The sync policy rewrites `proof` when demoting, so its shape is an
        # invariant this tool relies on: an array of strings, if present.
        proof = player.get("proof")
        if "proof" in player and (not isinstance(proof, list) or not all(isinstance(item, str) for item in proof)):
            result.add_error(f"players[{position}] ({shown}) has a malformed 'proof' (must be an array of strings)")

    return result
