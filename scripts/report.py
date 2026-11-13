"""Markdown report rendering for sync results.

Produces the pull request body and job summary from a :class:`RunInfo`.
"""

from __future__ import annotations

import re
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from playerlist import account_id, steam_profile_url
from policy import Change
from sources import DEFAULT_SNAPSHOT, SOURCE_REPO_URL, is_url

__all__ = [
    "MAX_CLOSING_STEAMIDS",
    "MAX_DEMOTION_CHARS",
    "MAX_PROMOTION_CHARS",
    "MAX_REMOVED_CHARS",
    "RunInfo",
    "plural",
    "render_closing",
    "render_report",
]

# This report IS the pull request body, and GitHub refuses a body above
# 65536 characters. Rows are long (SteamID, name, profile link, attribute
# lists, proof links -- ~240 characters with real data), so a mass promotion
# would otherwise produce a body the API rejects, taking the whole report
# with it. Each table gets a character budget; whatever does not fit is
# summarised with a pointer to the diff, which always lists every row.
MAX_PROMOTION_CHARS = 24_000
MAX_DEMOTION_CHARS = 20_000
MAX_REMOVED_CHARS = 12_000

# The closing sentence repeats the changed SteamIDs, which is handy for a
# handful of changes. On a mass run it used to be a second, uncapped copy of
# the tables (1600 IDs alone added ~17 KB to a body limited to 65536).
MAX_CLOSING_STEAMIDS = 10

# Characters that would break a Markdown link target -- or let an
# untrusted proof string (the Vorobey list is outside our control) break out
# of it and inject arbitrary Markdown. Percent-encoded rather than
# backslash-escaped so the URL stays valid.
_LINK_ESCAPES = str.maketrans(
    {
        "\\": "%5C",
        "(": "%28",
        ")": "%29",
        " ": "%20",
        "[": "%5B",
        "]": "%5D",
        "<": "%3C",
        ">": "%3E",
        "\n": "%0A",
        "\r": "%0D",
    }
)

# Lone UTF-16 surrogates: legal in JSON input (e.g. "\ud800" in a player
# name) and loadable by Python, but impossible to encode as UTF-8 -- one in
# a name or proof would crash writing/printing the report. They are rendered
# as the replacement character instead; the database itself is unaffected
# (it is serialised with ensure_ascii, which re-escapes them losslessly).
_SURROGATES_RE = re.compile(r"[\ud800-\udfff]")


def _safe(text: str) -> str:
    """Replace lone surrogates so the report is always UTF-8 encodable."""
    return _SURROGATES_RE.sub("\ufffd", text)


# Markdown table cells still allow raw HTML, so an untrusted string -- an
# upstream proof line, or a player name from a list we did not write -- could
# render as a real clickable <a href="..."> inside this repository's pull
# request. HTML-escaping makes it display literally instead; the renderer
# turns the entities back into the original characters, so legitimate names
# ("Tom & Jerry") look unchanged.
_HTML_ESCAPES = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;"})


def _cell(value: str) -> str:
    """Make an untrusted string safe inside a Markdown table cell.

    HTML first (so ``&lt;`` never becomes ``&amp;lt;``), then the Markdown
    escaping, then whitespace tidy-up.
    """
    return (
        value.translate(_HTML_ESCAPES)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", " ")
        .replace("\r", " ")
        .strip()
        or "-"
    )


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
    return label if url is None else _markdown_link(url, label)


def _markdown_link(url: str, label: str) -> str:
    """Render a link, escaping the characters that would end the target early."""
    return f"[{label}]({url.translate(_LINK_ESCAPES)})"


def _evidence_cell(links: Sequence[str]) -> str:
    """Proof column: real links where possible, escaped text otherwise."""
    if not links:
        return "-"
    rendered = [
        _markdown_link(link, "link" if len(links) == 1 else str(position))
        if is_url(link)  # anything else (javascript:, ...) stays escaped text
        else _cell(link)
        for position, link in enumerate(links, start=1)
    ]
    return "<br>".join(rendered)


def plural(count: int, singular: str, plural_form: str) -> str:
    """Return ``singular`` when count is 1, otherwise ``plural_form``."""
    return singular if count == 1 else plural_form


def _take_rows(rows: Sequence[str], budget: int) -> tuple[list[str], int]:
    """As many rows as fit in ``budget`` characters, plus how many did not."""
    kept: list[str] = []
    used = 0
    for row in rows:
        if used + len(row) + 1 > budget:  # +1 for the newline
            break
        kept.append(row)
        used += len(row) + 1
    return kept, len(rows) - len(kept)


def _truncation_note(hidden: int, singular: str, plural_form: str, where: str) -> str:
    """One line explaining that a table was cut short, and where to look."""
    return f"…and {hidden} more {plural(hidden, singular, plural_form)} ({where} in this pull request lists every one)."


def _sorted_steamids(steamids: Sequence[str]) -> list[str]:
    """Canonical SteamIDs in numeric order, unusable ones last and stable.

    Plain string sorting would order ``[U:1:100]`` before ``[U:1:99]``.
    """

    def key(steamid: str) -> tuple[bool, int]:
        account = account_id(steamid)
        return (account is None, account or 0)

    return sorted(steamids, key=key)


def _removed_section(removed: Sequence[str]) -> list[str]:
    """Table of SteamIDs the Vorobey list dropped since the previous snapshot.

    The Vorobey list stores no player names (only ``steamid``/``proof``/
    ``last_seen``), so a SteamID cannot be labelled with a name -- the Steam
    profile permalink is the only human-readable identifier available. This
    is the raw snapshot diff, independent of ``--demote``: every ID listed
    here disappeared upstream, whether or not this database contained it.
    """
    if not removed:
        return []
    ordered = _sorted_steamids(removed)
    count = len(ordered)
    lines = [
        f"**{count} {plural(count, 'SteamID', 'SteamIDs')} removed from the Vorobey list "
        "since the previous snapshot.**",
        "",
        "The Vorobey list records no player names, so these are SteamIDs only.",
        "",
        "| SteamID | Profile Link |",
        "| --- | --- |",
    ]
    rows = []
    for steamid in ordered:
        url = steam_profile_url(steamid)
        rows.append(f"| `{_cell(steamid)}` | {_markdown_link(url, 'profile') if url else '-'} |")
    shown, hidden = _take_rows(rows, MAX_REMOVED_CHARS)
    lines += shown
    lines.append("")
    if hidden:
        lines += [_truncation_note(hidden, "SteamID", "SteamIDs", "the snapshot diff"), ""]
    return lines


def _steamid_list(steamids: Sequence[str]) -> str:
    """Comma-separated SteamIDs, truncated once the list gets long."""
    shown = list(steamids[:MAX_CLOSING_STEAMIDS])
    hidden = len(steamids) - len(shown)
    text = ", ".join(shown)
    return text if hidden <= 0 else f"{text} and {hidden} more"


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
            parts.append("Attributes are changed for these SteamIDs: " + _steamid_list(changed_steamids))
    if removed_steamids:
        if len(removed_steamids) == 1:
            parts.append("Entry is removed from the database for this SteamID: " + removed_steamids[0])
        else:
            parts.append("Entries are removed from the database for these SteamIDs: " + _steamid_list(removed_steamids))

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
    # The SteamIDs behind removed_from_source, listed in a table so reviewers
    # can open the profile of every player Vorobey dropped.
    removed_upstream: tuple[str, ...] = ()
    demotion_note: str | None = None
    # True when the snapshot file itself was refreshed this run, so a
    # snapshot-only PR does not misleadingly report "No changes."
    snapshot_changed: bool = False
    # The baseline file this run actually used. Reported verbatim: --snapshot
    # can point anywhere, so a hardcoded path would lie in the PR.
    snapshot_path: Path = Path(DEFAULT_SNAPSHOT)


def _summary_lines(info: RunInfo) -> list[str]:
    """Header and bullet list: what was compared, and the snapshot diff."""
    source_note = f"{info.source_total} {plural(info.source_total, 'entry', 'entries')}"
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
        removed = info.removed_from_source
        previous_total = info.previous_source_total
        lines.append(
            f"- Previous snapshot: {previous_total} {plural(previous_total, 'entry', 'entries')}; "
            f"{removed} {plural(removed, 'SteamID', 'SteamIDs')} removed upstream since then "
            "(the only IDs that may be demoted)"
        )
        lines.append(
            f"- Snapshot diff: **{info.added_to_source} new "
            f"{plural(info.added_to_source, 'SteamID', 'SteamIDs')} added**, "
            f"**{removed} {plural(removed, 'SteamID', 'SteamIDs')} removed** "
            f"({info.previous_source_total} → {current_total} "
            f"{plural(current_total, 'entry', 'entries')}; net {net:+d})"
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
        lines.append(f"- Snapshot: `{info.snapshot_path}` {verb} to an exact copy of the current upstream file")
    lines.append("")
    return lines


def _promotion_section(promotions: Sequence[Change]) -> list[str]:
    count = len(promotions)
    lines = [
        f"**{count} {plural(count, 'entry', 'entries')} promoted to `cheater`.**",
        "",
        "| SteamID | Last known name | Before | After | Hackerpolice proof |",
        "| --- | --- | --- | --- | --- |",
    ]
    rows = [
        "| `{steamid}` | {name} | {before} | {after} | {evidence} |".format(
            steamid=change.steamid,
            name=_name_cell(change),
            before=", ".join(f"`{attribute}`" for attribute in change.before),
            after=", ".join(f"`{attribute}`" for attribute in change.after),
            evidence=_evidence_cell(change.evidence),
        )
        for change in promotions
    ]
    shown, hidden = _take_rows(rows, MAX_PROMOTION_CHARS)
    lines += shown
    lines.append("")
    if hidden:
        lines += [_truncation_note(hidden, "entry", "entries", "the database diff"), ""]
    return lines


def _demotion_section(demotions: Sequence[Change]) -> list[str]:
    count = len(demotions)
    lines = [
        f"**{count} {plural(count, 'entry', 'entries')} demoted (in the previous snapshot, "
        "removed from the hackerpolice list since).**",
        "",
        "| SteamID | Last known name | Before | After |",
        "| --- | --- | --- | --- |",
    ]
    rows = [
        "| `{steamid}` | {name} | {before} | {after} |".format(
            steamid=change.steamid,
            name=_name_cell(change),
            before=", ".join(f"`{attribute}`" for attribute in change.before),
            after=", ".join(f"`{attribute}`" for attribute in change.after) or "entry removed",
        )
        for change in demotions
    ]
    shown, hidden = _take_rows(rows, MAX_DEMOTION_CHARS)
    lines += shown
    lines.append("")
    if hidden:
        lines += [_truncation_note(hidden, "entry", "entries", "the database diff"), ""]
    return lines


def _footnotes(info: RunInfo, promotions: Sequence[Change]) -> list[str]:
    """Closing sentence plus the notes that explain where the data came from."""
    lines = [render_closing(info.changes)]
    total_links = sum(len(change.evidence) for change in promotions)
    if total_links == 1:
        lines += ["Proof link comes from the Vorobey hackerpolice list and is shown for review only.", ""]
    elif total_links > 1:
        lines += ["Proof links come from the Vorobey hackerpolice list and are shown for review only.", ""]
    else:
        lines.append("")
    if info.include_proof:
        lines += [
            "**Note:** `--include-proof` was enabled, so an `[auto]` proof line citing the",
            "hackerpolice list was also written into each entry above.",
            "",
        ]
    return lines


def render_report(info: RunInfo) -> str:
    """Render the PR body / job summary as Markdown."""
    lines = _summary_lines(info)

    promotions = [c for c in info.changes if c.kind == "promote"]
    demotions = [c for c in info.changes if c.kind == "demote"]
    removed_lines = _removed_section(info.removed_upstream)

    if not promotions and not demotions:
        if info.snapshot_changed:
            lines += ["**No database changes** (snapshot refresh only).", ""]
        else:
            lines += ["**No changes.**", ""]
        # Still worth reporting: removals upstream that this database never
        # listed produce no demotion but are part of the snapshot diff.
        lines += removed_lines
        return _safe("\n".join(lines))

    if promotions:
        lines += _promotion_section(promotions)
    if demotions:
        lines += _demotion_section(demotions)

    # Removed-upstream IDs come last, right before the closing sentence: they
    # describe the Vorobey list rather than this database's changes.
    if removed_lines:
        lines += removed_lines
    # Every section above ends with exactly one blank line, so the closing
    # sentence and its notes follow directly.
    lines += _footnotes(info, promotions)
    return _safe("\n".join(lines))
