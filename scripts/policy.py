"""Sync policy: promote and demote entries against the hackerpolice list.

Promotion: entries matching the Vorobey hackerpolice list gain ``cheater``.
Demotion (opt-in via ``--demote``): entries carrying ``cheater`` lose it, or
are removed entirely -- but ONLY for SteamIDs explicitly handed to
:func:`demote` as "removed upstream" (present in the previous hackerpolice
snapshot, gone from the current one). A SteamID that was never on the
hackerpolice list is never demoted: most ``cheater`` entries in this
database were added manually and must survive every sync.

No proof is ever written by this module. The evidence links the hackerpolice
list records are carried in the ``Change`` records and published in the pull
request only, so a promotion can never add a proof line to an entry.
"""

from __future__ import annotations

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
    "RACIST_PROOF_PREFIX",
    "Change",
    "demote",
    "is_racist_proof",
    "promote",
    "sync",
]


# The ONLY proof lines that justify the ``racist`` tag on their own. When a
# ``cheater`` + ``racist`` entry is demoted (player removed from the Vorobey
# list as a false positive), every proof that does not start with this exact
# prefix belonged to the cheating accusation and must go with the tag.
#
# The trailing quote is part of the prefix on purpose: TF2BD writes the reason
# as a quoted string ("[auto] automatically marked: Racist | reason: \"...\""),
# so requiring it keeps only a complete, canonical auto line -- a truncated or
# hand-mangled one ("... | reason:" with nothing after it) is not the machine
# record that justifies a racist tag, and it goes with the rest.
RACIST_PROOF_PREFIX = '[auto] automatically marked: Racist | reason: "'


def is_racist_proof(proof: str) -> bool:
    """True if a proof line is one of the automatic ``Racist`` chat-log lines.

    The line must start with the full ``RACIST_PROOF_PREFIX`` -- including the
    opening quote of the reason -- which is how TF2BD writes it::

        [auto] automatically marked: Racist | reason: "<the chat line>"

    Matching is forgiving about the ends only: leading/trailing whitespace and
    letter case are ignored, so a future tool that writes ``[AUTO]
    Automatically marked: RACIST`` still protects the line. Anything else -- a
    video link, "Silent Aim & ESP", a hand-written "Racist behavior..." note, or
    an auto line whose reason is missing/unquoted -- is NOT a racist proof and
    is dropped when the cheater tag goes away.
    """
    text = proof.strip().casefold()
    prefix = RACIST_PROOF_PREFIX.casefold()
    if not text.startswith(prefix):
        return False
    # The prefix already consumed the OPENING quote, so a complete line still
    # has its closing quote after it. Requiring one is what makes the sentence
    # above true: a line that stops at the opening quote has no reason at all,
    # and used to be accepted as a machine record anyway.
    return '"' in text[len(prefix) :]


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


def _evidence_links(entry: dict[str, Any]) -> tuple[str, ...]:
    """Proof links the Vorobey hackerpolice list recorded for one player (de-duplicated)."""
    proofs = entry.get("proof")
    if not isinstance(proofs, list):
        return ()
    links = (item.strip() for item in proofs if isinstance(item, str) and item.strip())
    return tuple(dict.fromkeys(links))


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
            continue  # malformed entry; the caller's validation reports it

        before = tuple(attributes)
        if PROMOTED_TO in before:
            continue  # already a cheater, nothing to add
        if not PROMOTABLE_ATTRIBUTES.intersection(before):
            continue  # exploiter / unknown attribute only - out of scope

        after = tuple(order_attributes({*before, PROMOTED_TO} - {DROPPED_ATTRIBUTE}))
        player["attributes"] = list(after)

        evidence = _evidence_links(entry)

        changes.append(
            Change(
                steamid=canonical,
                name=player_name(player),
                before=before,
                after=after,
                evidence=evidence,
            )
        )

    return changes


def _demoted_entry(player: Player, removed: frozenset[str]) -> tuple[bool, Change | None]:
    """Apply the demotion rule to ONE entry, in place.

    Returns ``(keep_entry, change)``: ``change`` is ``None`` when the rule does
    not apply to this entry, and ``keep_entry`` says whether the entry survives
    (a ``cheater``+``racist`` entry keeps ``racist``; a ``cheater``-only entry
    is dropped). Every malformed case is left untouched -- ``validate()``
    reports those before a run ever writes anything.
    """
    if not isinstance(player, dict):
        return True, None

    canonical = normalize_steamid(player.get("steamid"))
    if canonical is None:
        return True, None

    # Not proven to have been removed upstream (never listed, or still
    # listed) - nothing to demote, however the entry got its cheater tag.
    if canonical not in removed:
        return True, None

    attributes = player.get("attributes")
    if not isinstance(attributes, list) or not attributes:
        return True, None
    if not all(isinstance(attribute, str) for attribute in attributes):
        return True, None  # malformed entry; validation reports it

    before = tuple(attributes)
    if PROMOTED_TO not in before:
        return True, None  # not a cheater - nothing to demote

    if "racist" not in before:
        # Remove the whole entry (cheater without racist)
        return False, Change(
            steamid=canonical,
            name=player_name(player),
            before=before,
            after=(),
            kind="demote",
        )

    # Remove only cheater, keep racist
    after = tuple(order_attributes({*before} - {PROMOTED_TO}))
    player["attributes"] = list(after)

    # Drop every proof except the "[auto] ... Racist" lines: the cheater tag
    # was a false positive, so its evidence must not stay behind pretending to
    # justify the remaining racist tag. When nothing survives the filter the
    # KEY goes too: this database (and TF2BD) spells "no proof" as an absent
    # key -- not one of the 456 entries carries an empty array -- so leaving
    # ``"proof": []`` behind would put a shape in the file that nothing else
    # in it has.
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
