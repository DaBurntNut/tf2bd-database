"""Sync policy: promote and demote entries against the hackerpolice list.

Promotion: entries matching the Vorobey hackerpolice list gain ``cheater``.
Demotion (opt-in via ``--demote``): entries carrying ``cheater`` lose it, or
are removed entirely -- but ONLY for SteamIDs explicitly handed to
:func:`demote` as "removed upstream" (present in the previous hackerpolice
snapshot, gone from the current one). A SteamID that was never on the
hackerpolice list is never demoted: most ``cheater`` entries in this
database were added manually and must survive every sync.
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
from sources import PROOF_MARKER, SOURCE_REPO_URL, HackerpoliceIndex

PROMOTABLE_ATTRIBUTES = frozenset({"suspicious", "racist"})
DROPPED_ATTRIBUTE = "suspicious"
PROMOTED_TO = "cheater"

__all__ = [
    "RACIST_PROOF_PREFIX",
    "Change",
    "demote",
    "promote",
    "sync",
]


# The ONLY proof lines that justify the ``racist`` tag on their own. When a
# ``cheater`` + ``racist`` entry is demoted (player removed from the Vorobey
# list as a false positive), every proof that does not start with this exact
# prefix belonged to the cheating accusation and must go with the tag.
RACIST_PROOF_PREFIX = "[auto] automatically marked: Racist | reason:"


def _filter_racist_proofs(proofs: Any) -> list[str]:
    """Keep only the ``[auto] ... Racist`` proof lines, dropping all others.

    When demoting ``cheater`` + ``racist`` -> ``racist``, the cheater tag was
    a false positive, so its evidence (video links, "Silent Aim & ESP", a
    hand-written "Racist behavior..." note, anything) is removed too. Only
    proofs starting with :data:`RACIST_PROOF_PREFIX` -- the automatically
    recorded chat-log lines that justify ``racist`` -- are kept, in order.
    A malformed (non-list) proof yields an empty list: it cannot contain a
    valid racist line, so nothing of it may survive the demotion either.
    """
    if not isinstance(proofs, list):
        return []
    return [p for p in proofs if isinstance(p, str) and p.startswith(RACIST_PROOF_PREFIX)]


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


def _write_proof(player: Player, evidence: tuple[str, ...]) -> None:
    """Write the ``[auto]`` proof line into a player entry (idempotent)."""
    proof = player.get("proof")
    proof = list(proof) if isinstance(proof, list) else ([] if proof is None else [str(proof)])
    if not any(isinstance(item, str) and PROOF_MARKER in item for item in proof):
        line = f"{PROOF_MARKER} ({SOURCE_REPO_URL})"
        if evidence:
            line += " | hackerpolice evidence: " + " ; ".join(evidence)
        proof.append(line)
    player["proof"] = proof


def promote(database: PlayerList, index: HackerpoliceIndex, *, include_proof: bool = False) -> list[Change]:
    """Apply the promotion policy in place and return what changed.

    ``suspicious`` and/or ``racist`` entries with a hackerpolice match gain
    ``cheater``: ``suspicious`` is removed (a cheater list settles it) while
    ``racist`` is kept. Everything else is left untouched.

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
        if include_proof:
            _write_proof(player, evidence)

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
        if not isinstance(player, dict):
            kept.append(player)
            continue

        canonical = normalize_steamid(player.get("steamid"))
        if canonical is None:
            kept.append(player)
            continue

        # Not proven to have been removed upstream (never listed, or still
        # listed) - nothing to demote, however the entry got its cheater tag.
        if canonical not in removed:
            kept.append(player)
            continue

        attributes = player.get("attributes")
        if not isinstance(attributes, list) or not attributes:
            kept.append(player)
            continue
        if not all(isinstance(attribute, str) for attribute in attributes):
            kept.append(player)  # malformed entry; validation reports it
            continue

        before = tuple(attributes)
        if PROMOTED_TO not in before:
            # Not a cheater - nothing to demote
            kept.append(player)
            continue

        if "racist" in before:
            # Remove only cheater, keep racist
            after = tuple(order_attributes({*before} - {PROMOTED_TO}))
            player["attributes"] = list(after)

            # Drop every proof except the "[auto] ... Racist" lines: the
            # cheater tag was a false positive, so its evidence must not
            # stay behind pretending to justify the remaining racist tag.
            if "proof" in player:
                player["proof"] = _filter_racist_proofs(player.get("proof"))

            changes.append(
                Change(
                    steamid=canonical,
                    name=player_name(player),
                    before=before,
                    after=after,
                    kind="demote",
                )
            )
            kept.append(player)
        else:
            # Remove the whole entry (cheater without racist)
            changes.append(
                Change(
                    steamid=canonical,
                    name=player_name(player),
                    before=before,
                    after=(),
                    kind="demote",
                )
            )
            # Entry is dropped - not added to kept

    database["players"] = kept
    return changes


def sync(
    database: PlayerList,
    index: HackerpoliceIndex,
    *,
    include_proof: bool = False,
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
    """
    changes: list[Change] = []
    changes.extend(promote(database, index, include_proof=include_proof))

    if enable_demote:
        changes.extend(demote(database, removed_ids))

    players = database.get("players")
    if isinstance(players, list):
        database["players"] = sort_players(players)
    return changes
