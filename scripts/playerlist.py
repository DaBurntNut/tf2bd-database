"""TF2BD playerlist file format helpers.

Handles SteamID normalisation, reading/writing playerlist JSON, validation,
sorting and attribute ordering. Nothing here knows about the Vorobey
hackerpolice list.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypedDict, cast

STEAMID64_BASE = 76561197960265728
MAX_ACCOUNT_ID = 2**32

CANONICAL_PREFIX = "[U:1:"
CANONICAL_SUFFIX = "]"

# Attributes recognised by the TF2BD v3 schema, in the order used when writing.
ATTRIBUTE_ORDER: tuple[str, ...] = ("cheater", "suspicious", "exploiter", "racist")
KNOWN_ATTRIBUTES = frozenset(ATTRIBUTE_ORDER)

# re.ASCII: \d must only ever match 0-9. Without it "\d" also matches
# non-ASCII decimal digits (e.g. Arabic-Indic "١٢٣"), which int() happily
# accepts -- that would silently turn garbage into a valid-looking SteamID.
_ASCII = re.ASCII
_ACCOUNT_ID_RE = re.compile(r"\d+", _ASCII)
_U_RE = re.compile(rf"^\[U:1:({_ACCOUNT_ID_RE.pattern})\]$", _ASCII)
_U_BARE_RE = re.compile(rf"^U:1:({_ACCOUNT_ID_RE.pattern})$", re.IGNORECASE | _ASCII)
_U_INSTANCE_RE = re.compile(rf"^\[U:1:({_ACCOUNT_ID_RE.pattern}):{_ACCOUNT_ID_RE.pattern}\]$", _ASCII)
_STEAM2_RE = re.compile(r"^STEAM_[0-5]:([01]):(\d+)$", re.IGNORECASE | _ASCII)
_STEAMID64_RE = re.compile(r"^\d{17}$", _ASCII)
_PROFILE_URL_RE = re.compile(r"steamcommunity\.com/profiles/(\d{17})", re.IGNORECASE | _ASCII)


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
    """Parse a decimal string, or return ``None`` if it has >10 significant digits.

    Guards ``int()`` against Python's int-parsing digit limit: a SteamID
    string with thousands of digits (hostile or corrupted input) must be
    rejected, not crash the sync. Account ids fit in 10 digits, so anything
    longer is out of range anyway; leading zeros are ignored.
    """
    significant = digits.lstrip("0") or "0"
    if len(significant) > 10:
        return None
    return int(significant)


def _canonical(account: int | None) -> str | None:
    """Wrap an account id in canonical ``[U:1:<id>]`` form, or reject it.

    Account ids are 32-bit and never 0: out-of-range input is rejected
    instead of minting a canonical ID no real account can have.
    """
    if account is None or not 0 < account < MAX_ACCOUNT_ID:
        return None
    return f"{CANONICAL_PREFIX}{account}{CANONICAL_SUFFIX}"


def _account_from_text(text: str) -> int | None:
    """Account id from any accepted textual SteamID notation, or ``None``."""
    for pattern in (_U_RE, _U_BARE_RE, _U_INSTANCE_RE):
        match = pattern.match(text)
        if match:
            return _bounded_int(match.group(1))

    match = _STEAM2_RE.match(text)
    if match:
        # STEAM_X:Y:Z -> account id is Z * 2 + Y (Y is the auth-server bit).
        auth_server, account_half = match.groups()
        half = _bounded_int(account_half)
        return None if half is None else half * 2 + int(auth_server)

    if _STEAMID64_RE.match(text):
        return _account_from_steamid64(int(text))

    if text.isascii() and text.isdigit():
        # Bare account id given as a string, e.g. "1730017" (the int form of
        # this is accepted below, so accept the string form too). isascii()
        # keeps non-ASCII digits from being parsed as an account id.
        return _bounded_int(text)

    match = _PROFILE_URL_RE.search(text)
    if match:
        return _account_from_steamid64(int(match.group(1)))

    return None


def normalize_steamid(value: Any) -> str | None:
    """Return canonical ``[U:1:<account id>]`` form, or ``None`` if unusable.

    Accepts canonical ``[U:1:x]``, bare ``U:1:x``, ``[U:1:x:instance]``,
    ``STEAM_0:y:z``, SteamID64 integers/strings, and profile URLs.
    """
    if isinstance(value, bool):  # bool is an int subclass; not a SteamID
        return None

    if isinstance(value, int):
        # A bare account id, or a full SteamID64.
        account = value if 0 < value < MAX_ACCOUNT_ID else _account_from_steamid64(value)
        return _canonical(account)

    if not isinstance(value, str):
        return None

    return _canonical(_account_from_text(value.strip()))


def account_id(steamid: Any) -> int | None:
    """Numeric account id of a SteamID in any accepted notation."""
    canonical = normalize_steamid(steamid)
    if canonical is None:
        return None
    return int(canonical[len(CANONICAL_PREFIX) : -len(CANONICAL_SUFFIX)])


def steam_profile_url(steamid: Any) -> str | None:
    """Steam Community profile permalink for a SteamID, or ``None`` if unusable.

    The permalink is the SteamID64 form: ``STEAMID64_BASE`` + account id,
    e.g. ``[U:1:269327660]`` -> ``https://steamcommunity.com/profiles/76561198229593388``.
    """
    account = account_id(steamid)
    if account is None:
        return None
    return f"https://steamcommunity.com/profiles/{STEAMID64_BASE + account}"


def player_name(player: Player) -> str:
    """Last known player name, or an empty string when the entry has none."""
    last_seen = player.get("last_seen")
    if not isinstance(last_seen, dict):
        return ""
    return str(last_seen.get("player_name") or "")


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
    return json.dumps(database, indent="\t", sort_keys=True, ensure_ascii=True) + "\n"


def load(path: Path, *, encoding: str = "utf-8") -> tuple[PlayerList, str]:
    """Read a playerlist, returning the parsed document and its original text."""
    try:
        original = path.read_text(encoding=encoding)
    except (OSError, UnicodeDecodeError) as exc:
        # UnicodeDecodeError: the file is not valid UTF-8 -- report it like
        # any other unreadable file instead of crashing with a traceback.
        raise PlayerListError(f"cannot read {path}: {exc}") from exc
    try:
        database = json.loads(original)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        # ValueError: e.g. a JSON number with more digits than Python's
        # int-parsing limit -- invalid input, not a crash.
        raise PlayerListError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(database, dict):
        raise PlayerListError(f"{path} does not contain a JSON object")
    return cast("PlayerList", database), original


@dataclass
class ValidationResult:
    """Problems found in a playerlist: errors block writing, warnings do not."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return not self.errors


def validate(database: PlayerList) -> ValidationResult:
    """Check the invariants this tool relies on (unique, usable SteamIDs)."""
    result = ValidationResult()

    players = database.get("players")
    if not isinstance(players, list):
        result.errors.append("'players' is not an array")
        return result

    seen: set[str] = set()
    for position, player in enumerate(players):
        _validate_player(position, player, seen, result)
    return result


def _validate_player(position: int, player: Any, seen: set[str], result: ValidationResult) -> None:
    """Validate one entry, appending every problem found to ``result``.

    All checks run even when an earlier one failed, so a run reports the
    complete list of problems instead of one per entry per attempt.
    """
    if not isinstance(player, dict):
        result.errors.append(f"players[{position}] is not an object")
        return

    steamid = player.get("steamid")
    canonical = normalize_steamid(steamid)
    if canonical is None:
        result.errors.append(f"players[{position}] has an unusable steamid: {steamid!r}")
    elif canonical in seen:
        result.errors.append(f"duplicate steamid {canonical}")
    else:
        seen.add(canonical)

    _validate_attributes(position, steamid, player, result)
    _validate_proof(position, steamid, player, result)


def _validate_attributes(position: int, steamid: Any, player: dict[str, Any], result: ValidationResult) -> None:
    attributes = player.get("attributes")
    if not isinstance(attributes, list) or not attributes:
        result.errors.append(f"players[{position}] ({steamid}) has no attributes")
        return
    if not all(isinstance(attribute, str) for attribute in attributes):
        # Also guards the set() below against unhashable attribute values.
        result.errors.append(f"players[{position}] ({steamid}) has a non-string attribute")
        return
    if len(set(attributes)) != len(attributes):
        result.errors.append(f"players[{position}] ({steamid}) has duplicate attributes")
    for attribute in attributes:
        if attribute not in KNOWN_ATTRIBUTES:
            result.warnings.append(f"players[{position}] ({steamid}) uses unknown attribute {attribute!r}")


def _validate_proof(position: int, steamid: Any, player: dict[str, Any], result: ValidationResult) -> None:
    # The sync policy rewrites `proof` when demoting, so its shape is an
    # invariant this tool relies on: an array of strings, if present.
    proof = player.get("proof")
    if proof is not None and (not isinstance(proof, list) or not all(isinstance(item, str) for item in proof)):
        result.errors.append(f"players[{position}] ({steamid}) has a malformed 'proof' (must be an array of strings)")
