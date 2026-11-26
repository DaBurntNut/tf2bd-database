"""Sync policy: promote and demote entries against the hackerpolice list.

The six rules this bot is held to, in plain words:

1. A SteamID marked ``suspicious`` here that IS on the hackerpolice list
   becomes ``cheater``. No proof line is added.
2. A SteamID marked ``suspicious`` + ``racist`` that IS on the list becomes
   ``cheater`` + ``racist``. No proof line is added.
3. A SteamID marked ONLY ``cheater`` that is later dropped from the
   hackerpolice list has its WHOLE entry deleted from the database. This is
   deliberate, not an oversight: the entry is there because the list vouched
   for it, so when the list withdraws, the entry goes -- hand-written notes
   and all.
4. A SteamID marked ``cheater`` + ``racist`` that is later dropped from the
   list keeps ``racist``, loses ``cheater``, and loses every proof line that
   is not an ``[auto] ... Racist`` record (see :func:`is_racist_proof`).
5. ``snapshot/playerlist.vorobey-hackerpolice.json`` stays an exact 1-to-1
   copy of upstream -- the raw bytes, never re-serialised. (Written by
   ``write_snapshot`` in ``sync_vorobey_hackerpolice.py``.)
6. The pull request names every SteamID that disappeared upstream, including
   ones this database never carried. (``render_removed_table`` in
   ``report.py``.)

All six are pinned by the test suite: break any one of them and the tests go
red before the change can reach the database.

Promotion: entries matching the Vorobey hackerpolice list gain ``cheater``.
Demotion (opt-in via ``--demote``): entries carrying ``cheater`` lose it, or
are removed entirely -- but ONLY for SteamIDs explicitly handed to
:func:`demote` as "removed upstream" (present in the previous hackerpolice
snapshot, gone from the current one). A SteamID that was never on the
hackerpolice list is never demoted: most ``cheater`` entries in this
database were added manually and must survive every sync.

No proof text is ever authored by this module. The evidence links the
hackerpolice list records are carried in the ``Change`` records and published
in the pull request only, so a promotion can never add a proof line to an
entry. Demotion is the one place the field is touched at all, and only ever to
REMOVE lines: it keeps the trusted ``[auto] ... Racist`` records that justify
the surviving ``racist`` tag, and deletes the key outright when none survive.
"""

from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

from playerlist import (
    Player,
    PlayerList,
    normalize_steamid,
    order_attributes,
    player_name,
    sort_players,
)
from sources import HackerpoliceIndex

PROMOTABLE_ATTRIBUTES = frozenset({"suspicious", "racist"})
DROPPED_ATTRIBUTE = "suspicious"
PROMOTED_TO = "cheater"

__all__ = [
    "MAX_EVIDENCE_LINKS",
    "MAX_EVIDENCE_LINK_CHARS",
    "RACIST_PROOF_PREFIX",
    "Change",
    "demote",
    "is_racist_proof",
    "promote",
    "sync",
]

# The report's display cap for a single evidence link. ``_evidence_links``
# clips to one character beyond it, so a link sitting exactly at the cap stays
# distinguishable from one that was cut short.
MAX_EVIDENCE_LINK_CHARS = 500
MAX_EVIDENCE_LINKS = 10


# Prefix for TF2BD automatic racist records, including the opening reason quote.
RACIST_PROOF_PREFIX = '[auto] automatically marked: Racist | reason: "'
# Proof records are single-line; reject embedded separators.
_LINE_BREAKS = re.compile(r"[\r\n\v\f\x1c-\x1e\x85\u2028\u2029]")


def is_racist_proof(proof: str) -> bool:
    """True if a proof line is one of the automatic ``Racist`` chat-log lines.

    The line must start with the full ``RACIST_PROOF_PREFIX`` -- including the
    opening quote of the reason -- which is how TF2BD writes it::

        [auto] automatically marked: Racist | reason: "<the chat line>"

    Matching is forgiving about the ends only: leading/trailing whitespace and
    ASCII letter case are ignored, so a future tool that writes ``[AUTO]
    Automatically marked: RACIST`` still protects the line. Non-ASCII lookalikes
    in the trusted prefix are rejected. Embedded line breaks are rejected so
    another proof cannot be appended under that prefix. Anything else -- a
    video link, "Silent Aim & ESP", a hand-written "Racist behavior..." note,
    or an auto line whose reason is missing/unquoted -- is NOT a racist proof
    and is dropped when the cheater tag goes away.
    """
    text = proof.strip()
    if _LINE_BREAKS.search(text):
        return False
    prefix_length = len(RACIST_PROOF_PREFIX)
    prefix = text[:prefix_length]
    if not prefix.isascii() or prefix.lower() != RACIST_PROOF_PREFIX.lower():
        return False
    # Require the closing quote of a complete record.
    return len(text) > prefix_length and text.endswith('"')


def _filter_racist_proofs(proofs: Any) -> list[str]:
    """Keep only the ``[auto] ... Racist`` proof lines, dropping all others.

    When demoting ``cheater`` + ``racist`` -> ``racist``, the cheater tag was
    a false positive, so its evidence (video links, "Silent Aim & ESP", a
    hand-written "Racist behavior..." note, anything) is removed too. Only
    proofs that :func:`is_racist_proof` accepts -- the automatically recorded
    chat-log lines that justify ``racist`` -- are kept, in order.
    A malformed (non-list) proof yields an empty list: it cannot contain a
    valid racist line, so nothing of it may survive the demotion either.
    """
    if not isinstance(proofs, list):
        return []
    return [p for p in proofs if isinstance(p, str) and is_racist_proof(p)]


@dataclass(frozen=True)
class Change:
    """One changed player, as reported in the Markdown summary.

    ``kind`` is ``"promote"`` when ``cheater`` was added, ``"demote"`` when
    ``cheater`` was removed (or the whole entry was dropped).
    """

    steamid: str
    name: str
    before: tuple[str, ...]
    after: tuple[str, ...]
    evidence: tuple[str, ...] = ()
    kind: str = "promote"
    evidence_omitted: int = 0


def _evidence_links(entry: dict[str, Any]) -> tuple[tuple[str, ...], int]:
    """Return bounded, de-duplicated evidence links and the omitted-entry count."""
    proofs = entry.get("proof")
    if not isinstance(proofs, list):
        return (), 0

    links: list[str] = []
    shown: set[str] = set()
    omitted = 0
    for item in proofs:
        if not isinstance(item, str):
            continue
        link = item.strip()
        if not link:
            continue
        if len(link) > MAX_EVIDENCE_LINK_CHARS + 1:
            link = link[: MAX_EVIDENCE_LINK_CHARS + 1]
        if link in shown:
            continue
        if len(links) < MAX_EVIDENCE_LINKS:
            shown.add(link)
            links.append(link)
        else:
            # Count omitted entries without retaining additional URLs.
            omitted += 1
    return tuple(links), omitted


def promote(database: PlayerList, index: HackerpoliceIndex) -> list[Change]:
    """Apply the promotion policy in place and return what changed.

    ``suspicious`` and/or ``racist`` entries with a hackerpolice match gain
    ``cheater``: ``suspicious`` is removed (a cheater list settles it) while
    ``racist`` is kept. Everything else is left untouched.

    Membership is the entire test. The upstream list is cheater-only by
    definition, so its attributes are never read: an ID that is listed is a
    cheater even if its upstream entry said nothing at all.

    The database is NOT sorted here; call ``sync()`` to sort once after all
    changes are applied.
    """
    changes: list[Change] = []
    players = database.get("players")
    if not isinstance(players, list):
        return changes

    for player in players:
        if not isinstance(player, dict):
            continue

        canonical = normalize_steamid(player.get("steamid"))
        if canonical is None:
            continue

        entry = index.by_steamid.get(canonical)
        if entry is None:
            continue

        attributes = player.get("attributes")
        if not isinstance(attributes, list) or not attributes:
            continue
        if not all(isinstance(attribute, str) for attribute in attributes):
            continue

        before = tuple(attributes)
        if PROMOTED_TO in before:
            continue
        if not PROMOTABLE_ATTRIBUTES.intersection(before):
            continue

        after = tuple(order_attributes({*before, PROMOTED_TO} - {DROPPED_ATTRIBUTE}))
        player["attributes"] = list(after)

        evidence, evidence_omitted = _evidence_links(entry)

        changes.append(
            Change(
                steamid=canonical,
                name=player_name(player),
                before=before,
                after=after,
                evidence=evidence,
                evidence_omitted=evidence_omitted,
            )
        )

    return changes


def _demoted_entry(player: Player, removed: frozenset[str]) -> tuple[bool, Change | None]:
    """Apply the demotion rule to ONE entry, in place.

    Returns ``(keep_entry, change)``: ``change`` is ``None`` when the rule does
    not apply to this entry, and ``keep_entry`` says whether the entry survives
    (a ``cheater``+``racist`` entry keeps ``racist``; a ``cheater``-only entry
    is dropped). Entries with an unusable SteamID or malformed attributes are
    left untouched -- ``validate()`` reports those before a run ever writes
    anything. A malformed proof on a racist entry is discarded by the proof
    filter because it cannot be trusted to justify the remaining tag.
    """
    if not isinstance(player, dict):
        return True, None

    canonical = normalize_steamid(player.get("steamid"))
    if canonical is None:
        return True, None

    if canonical not in removed:
        return True, None

    attributes = player.get("attributes")
    if not isinstance(attributes, list) or not attributes:
        return True, None
    if not all(isinstance(attribute, str) for attribute in attributes):
        return True, None

    before = tuple(attributes)
    if PROMOTED_TO not in before:
        return True, None

    if "racist" not in before:
        return False, Change(
            steamid=canonical,
            name=player_name(player),
            before=before,
            after=(),
            kind="demote",
        )

    after = tuple(order_attributes({*before} - {PROMOTED_TO}))
    player["attributes"] = list(after)

    # Keep trusted racist records and omit the proof key if none remain.
    if "proof" in player:
        kept_proofs = _filter_racist_proofs(player.get("proof"))
        if kept_proofs:
            player["proof"] = kept_proofs
        else:
            del player["proof"]

    return True, Change(
        steamid=canonical,
        name=player_name(player),
        before=before,
        after=after,
        kind="demote",
    )


def demote(database: PlayerList, removed_ids: Collection[str]) -> list[Change]:
    """Remove ``cheater`` (or the whole entry) for IDs removed upstream.

    ``removed_ids`` must be exactly ``previous_snapshot - current_list``
    (canonical SteamIDs), computed by the caller -- deliberately NOT "every
    cheater missing from the current list", which would also delete cheaters
    this database added manually and that Vorobey never listed.

    * ``cheater`` + ``racist``       -> only ``cheater`` is removed (``racist`` kept)
    * ``cheater`` alone (or with any other attribute but ``racist``) -> whole entry removed

    Entries whose SteamID is not in ``removed_ids``, or without ``cheater``,
    are untouched.

    The database is NOT sorted here; call ``sync()`` to sort once after all
    changes are applied.
    """
    removed = frozenset(removed_ids)
    changes: list[Change] = []
    players = database.get("players")
    if not isinstance(players, list):
        return changes

    kept: list[Player] = []
    for player in players:
        keep, change = _demoted_entry(player, removed)
        if change is not None:
            changes.append(change)
        if keep:
            kept.append(player)

    database["players"] = kept
    return changes


def sync(
    database: PlayerList,
    index: HackerpoliceIndex,
    *,
    enable_demote: bool = False,
    removed_ids: Collection[str] = (),
) -> list[Change]:
    """Apply promotion and optionally demotion in one pass, sorting once.

    Demotion only runs when ``enable_demote`` is set AND the caller supplies
    ``removed_ids`` (previous snapshot minus current list). With the default
    empty ``removed_ids`` demotion is a safe no-op, so forgetting the
    snapshot can never fall back to deleting every unlisted cheater.

    Both ``promote`` and ``demote`` are applied, then the playerlist is
    sorted once. This avoids redundant sorting when both operations run.

    An ID that is listed in ``index`` (i.e. upstream lists it RIGHT NOW) is
    dropped from ``removed_ids`` before demotion. The caller already derives
    the set as "previous snapshot minus current list", so real runs never
    overlap -- but enforcing it here makes the operation idempotent no matter
    what a future caller passes, instead of promoting and demoting the same
    entry in one run.
    """
    changes: list[Change] = []
    changes.extend(promote(database, index))

    if enable_demote:
        still_listed = index.by_steamid
        changes.extend(demote(database, [steamid for steamid in removed_ids if steamid not in still_listed]))

    players = database.get("players")
    if isinstance(players, list):
        database["players"] = sort_players(players)
    return changes
