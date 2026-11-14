"""Markdown report rendering for sync results.

Produces the pull request body and job summary from a :class:`RunInfo`.

Besides the Garou database changes, the report lists every SteamID that
disappeared from the Vorobey hackerpolice list since the previous snapshot.
The Vorobey list stores no player names, so that table has just two columns:
the SteamID and its Steam Community profile permalink.
"""

from __future__ import annotations

import re
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from playerlist import account_id, steam_profile_url
from policy import Change
from sources import SOURCE_REPO_URL

__all__ = [
    "MAX_REMOVED_TABLE_ROWS",
    "RunInfo",
    "plural",
    "render_closing",
    "render_removed_table",
    "render_report",
]

# Upper bound on rows in the "removed from Vorobey" table. A single run can
# legitimately see hundreds of removals, and GitHub rejects pull request
# bodies over 65,536 characters: cap the table so the report always fits,
# and say how many rows were left out instead of silently dropping them.
MAX_REMOVED_TABLE_ROWS = 100

# Characters that would break a Markdown link target.
_LINK_ESCAPES = str.maketrans({"(": "%28", ")": "%29", " ": "%20", "<": "%3C", ">": "%3E", "\n": "%0A", "\r": "%0D"})

# Lone UTF-16 surrogates: legal in JSON input (e.g. "\ud800" in a player
# name) and loadable by Python, but impossible to encode as UTF-8 -- one in
# a name or proof would crash writing/printing the report. They are rendered
# as the replacement character instead; the database itself is unaffected
# (it is serialised with ensure_ascii, which re-escapes them losslessly).
_SURROGATES_RE = re.compile(r"[\ud800-\udfff]")


def _safe(text: str) -> str:
    """Replace lone surrogates so the report is always UTF-8 encodable."""
    return _SURROGATES_RE.sub("\ufffd", text)


def _cell(value: str) -> str:
    """Make a string safe inside a Markdown table cell."""
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ").strip() or "-"


def _name_cell(change: Change) -> str:
    """Last-known-name cell, linked to the player's Steam profile permalink.

    Clicking the name in the pull request opens the profile directly.
    A player with no recorded name shows as ``UNKNOWN`` -- still linked,
    since the SteamID (and therefore the profile) is known even when the
    name is not. Brackets in the name are escaped so they cannot break
    the link text; only an unusable SteamID renders as plain text.
    """
    # UNKNOWN only when there is genuinely no recorded name; a player
    # actually named "-" (or similar) keeps their name.
    label = "UNKNOWN" if not change.name.strip() else _cell(change.name)
    label = label.replace("[", "\\[").replace("]", "\\]")
    url = steam_profile_url(change.steamid)
    if url is None:
        return label
    return f"[{label}]({url})"


def _is_url(text: str) -> bool:
    return text.startswith(("http://", "https://"))


def _markdown_link(url: str, label: str) -> str:
    """Render a link, escaping the characters that would end the target early."""
    return f"[{label}]({url.translate(_LINK_ESCAPES)})"


def _evidence_cell(links: Sequence[str]) -> str:
    """Proof column: real links where possible, escaped text otherwise."""
    if not links:
        return "-"
    rendered = [
        _markdown_link(link, "link" if len(links) == 1 else str(position)) if _is_url(link) else _cell(link)
        for position, link in enumerate(links, start=1)
    ]
    return "<br>".join(rendered)


def plural(count: int, singular: str, plural_form: str) -> str:
    """Return ``singular`` when count is 1, otherwise ``plural_form``."""
    return singular if count == 1 else plural_form


def _sorted_steamids(steamids: Sequence[str]) -> list[str]:
    """Order SteamIDs numerically (unusable ones last, stably) for a stable diff."""
    return sorted(steamids, key=lambda steamid: (account_id(steamid) is None, account_id(steamid) or 0))


def _profile_cell(steamid: str) -> str:
    """Steam profile permalink for one SteamID, or ``-`` if it cannot be built."""
    url = steam_profile_url(steamid)
    if url is None:
        return "-"
    return _markdown_link(url, "Profile")


def render_removed_table(steamids: Sequence[str]) -> list[str]:
    """Render the "removed from the Vorobey list" table as Markdown lines.

    Vorobey's list records no player names, so the table is exactly
    ``| SteamID | Profile Link |``: the SteamID in canonical ``[U:1:x]``
    form and the Steam Community profile *permalink* (the SteamID64 URL),
    which keeps working even when the player renames themselves.

    Rows are capped at :data:`MAX_REMOVED_TABLE_ROWS` so the report always
    fits in a pull request body; the overflow is counted, never hidden.
    """
    if not steamids:
        return []

    ordered = _sorted_steamids(steamids)
    count = len(ordered)
    shown = ordered[:MAX_REMOVED_TABLE_ROWS]
    lines = [
        f"**{count} {plural(count, 'SteamID', 'SteamIDs')} removed from the Vorobey hackerpolice list "
        "since the previous snapshot.**",
        "",
        "The Vorobey list stores no player names, so each SteamID is listed with its Steam profile permalink.",
        "",
        "| SteamID | Profile Link |",
        "| --- | --- |",
    ]
    lines += [f"| `{steamid}` | {_profile_cell(steamid)} |" for steamid in shown]
    if len(ordered) > len(shown):
        lines += [
            "",
            f"… and {len(ordered) - len(shown)} more {plural(len(ordered) - len(shown), 'SteamID', 'SteamIDs')} "
            "not shown here (the list is too long for a pull request body).",
        ]
    lines.append("")
    return lines


def _with_removed_table(lines: list[str], steamids: Sequence[str]) -> list[str]:
    """Append the removed table to an already rendered report body."""
    table = render_removed_table(steamids)
    if not table:
        return lines
    while lines and not lines[-1].strip():
        lines.pop()  # exactly one blank line before the new section
    return [*lines, "", *table]


def render_closing(changes: Sequence[Change]) -> str:
    """Build the present-tense closing sentence describing what changed.

    Uses singular/plural-aware phrasing per attribute or entry, followed by
    "; nothing else is modified."
    """
    changed_steamids = [change.steamid for change in changes if (change.kind == "promote") or change.after]
    removed_steamids = [change.steamid for change in changes if (change.kind == "demote") and not change.after]

    parts: list[str] = []
    if changed_steamids:
        if len(changed_steamids) == 1:
            parts.append("Attribute is changed for this SteamID: " + changed_steamids[0])
        else:
            parts.append("Attributes are changed for these SteamIDs: " + ", ".join(changed_steamids))
    if removed_steamids:
        if len(removed_steamids) == 1:
            parts.append("Entry is removed from the database for this SteamID: " + removed_steamids[0])
        else:
            parts.append("Entries are removed from the database for these SteamIDs: " + ", ".join(removed_steamids))

    return "; ".join(parts) + "; nothing else is modified."


@dataclass(frozen=True)
class RunInfo:
    """Facts about a run, used to render the Markdown summary."""

    database_path: Path
    source: str
    source_total: int
    source_skipped: int
    dry_run: bool
    include_proof: bool = False
    changes: tuple[Change, ...] = ()
    # Demotion provenance: how many IDs disappeared upstream vs. the snapshot,
    # and (when demotion was skipped despite --demote) the reason why.
    previous_source_total: int | None = None
    added_to_source: int = 0
    removed_from_source: int = 0
    # SteamIDs that were in the previous snapshot but are gone from the
    # current list. Reported whether or not demotion ran (and even when the
    # mass-demotion guard skipped demotion), because it is the raw fact the
    # pull request exists to communicate.
    removed_upstream: tuple[str, ...] = ()
    demotion_note: str | None = None
    # True when the snapshot file itself was refreshed this run, so a
    # snapshot-only PR does not misleadingly report "No changes."
    snapshot_changed: bool = False


def render_report(info: RunInfo) -> str:
    """Render the PR body / job summary as Markdown."""
    source_note = f"{info.source_total} entries"
    if info.source_skipped:
        source_note += f", {info.source_skipped} unusable"

    lines = [
        "## Vorobey hackerpolice sync",
        "",
        f"- Database: `{info.database_path}`",
        f"- Vorobey hackerpolice list ({source_note}): {SOURCE_REPO_URL}",
        f"- Fetched from: {info.source}",
        f"- Run at: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}",
    ]
    if info.dry_run:
        lines.append("- Mode: **dry run** (no files written)")
    if info.previous_source_total is not None:
        current_total = info.previous_source_total + info.added_to_source - info.removed_from_source
        net = info.added_to_source - info.removed_from_source
        lines.append(
            f"- Previous snapshot: {info.previous_source_total} entries; "
            f"{info.removed_from_source} {plural(info.removed_from_source, 'SteamID', 'SteamIDs')} "
            "removed upstream since then (only those are demotion candidates)"
        )
        lines.append(
            f"- Snapshot diff: **{info.added_to_source} new "
            f"{plural(info.added_to_source, 'SteamID', 'SteamIDs')} added**, "
            f"**{info.removed_from_source} {plural(info.removed_from_source, 'SteamID', 'SteamIDs')} removed** "
            f"({info.previous_source_total} → {current_total} entries; net {net:+d})"
        )
    elif info.snapshot_changed:
        # No baseline existed: every current ID is new in the initial snapshot.
        lines.append(
            f"- Snapshot diff: **{info.added_to_source} new "
            f"{plural(info.added_to_source, 'SteamID', 'SteamIDs')} added**, "
            "**0 SteamIDs removed** (no previous snapshot; initial snapshot)"
        )
    if info.demotion_note:
        lines.append(f"- Demotion: **{info.demotion_note}**")
    if info.snapshot_changed:
        verb = "would be updated" if info.dry_run else "updated"
        lines.append(
            f"- Snapshot: `snapshot/playerlist.vorobey-hackerpolice.json` {verb} "
            "to an exact copy of the current upstream file"
        )
    lines.append("")

    promotions = [c for c in info.changes if c.kind == "promote"]
    demotions = [c for c in info.changes if c.kind == "demote"]

    if not promotions and not demotions:
        if info.snapshot_changed:
            lines += ["**No database changes** (snapshot refresh only).", ""]
        else:
            lines += ["**No changes.**", ""]
        return _safe("\n".join(_with_removed_table(lines, info.removed_upstream)))

    if promotions:
        count = len(promotions)
        lines += [
            f"**{count} {plural(count, 'entry', 'entries')} promoted to `cheater`.**",
            "",
            "| SteamID | Last known name | Before | After | Hackerpolice proof |",
            "| --- | --- | --- | --- | --- |",
        ]
        lines += [
            "| `{steamid}` | {name} | {before} | {after} | {evidence} |".format(
                steamid=change.steamid,
                name=_name_cell(change),
                before=", ".join(f"`{attribute}`" for attribute in change.before),
                after=", ".join(f"`{attribute}`" for attribute in change.after),
                evidence=_evidence_cell(change.evidence),
            )
            for change in promotions
        ]
        lines.append("")

    if demotions:
        count = len(demotions)
        lines += [
            f"**{count} {plural(count, 'entry', 'entries')} demoted (in the previous snapshot, "
            "removed from the hackerpolice list since).**",
            "",
            "| SteamID | Last known name | Before | After |",
            "| --- | --- | --- | --- |",
        ]
        lines += [
            "| `{steamid}` | {name} | {before} | {after} |".format(
                steamid=change.steamid,
                name=_name_cell(change),
                before=", ".join(f"`{attribute}`" for attribute in change.before),
                after=", ".join(f"`{attribute}`" for attribute in change.after) or "entry removed",
            )
            for change in demotions
        ]
        lines.append("")

    closing = render_closing(info.changes)

    while lines and not lines[-1].strip():
        lines.pop()  # exactly one blank line before the closing sentence
    lines += ["", closing]
    if promotions:
        total_links = sum(len(change.evidence) for change in promotions)
        if total_links == 1:
            lines.append("Proof link comes from the Vorobey hackerpolice list and is shown for review only.")
        else:
            lines.append("Proof links come from the Vorobey hackerpolice list and are shown for review only.")
        lines.append("")
    else:
        lines.append("")
    if info.include_proof:
        lines += [
            "**Note:** `--include-proof` was enabled, so an `[auto]` proof line citing the",
            "hackerpolice list was also written into each entry above.",
            "",
        ]
    # Always last: the raw upstream removals, whatever the database did with them.
    return _safe("\n".join(_with_removed_table(lines, info.removed_upstream)))
