"""Markdown report rendering for sync results.

Produces the pull request body / job summary from a :class:`RunInfo`.

The report is the bot's only human-facing output, so it is treated as
untrusted-output as well as untrusted-input territory:

* every value that comes from the database or from the upstream Vorobey
  list (names, proofs, SteamIDs) is escaped for a Markdown table cell --
  pipes and newlines cannot break the table, brackets cannot forge a link,
  angle brackets cannot inject HTML, and ``@`` cannot trigger a mention;
* every table is row-capped, and the whole body has a hard length guard,
  because GitHub rejects pull request bodies over 65,536 characters;
* the closing sentence names the database that changed exactly once.

Order of the body: header bullets, promotions, demotions, the SteamIDs
removed from the upstream list (``| SteamID | Profile Link |``), and
finally the closing sentence + proof note.
"""

from __future__ import annotations

import re
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from playerlist import account_id, steam_profile_url
from policy import Change
from sources import SOURCE_REPO_URL, redact_url

__all__ = [
    "MAX_CHANGE_TABLE_ROWS",
    "MAX_REMOVED_TABLE_ROWS",
    "MAX_REPORT_BYTES",
    "RunInfo",
    "plural",
    "render_closing",
    "render_removed_table",
    "render_report",
]

# GitHub rejects a pull request body longer than 65,536 characters. Change
# tables are capped, the removed table is capped, and the finished body is
# hard-truncated as a last resort, so publishing the PR can never fail on
# size -- however big a single run turns out to be.
MAX_CHANGE_TABLE_ROWS = 150
MAX_REMOVED_TABLE_ROWS = 100
# GitHub rejects a pull request body over 65,536 BYTES, and the body doubles
# as the job summary, so the budget is measured in bytes with room to spare.
# Characters would be the wrong unit: 30,000 Cyrillic player names are half the
# character budget and twice the byte budget.
MAX_REPORT_BYTES = 60_000

# Characters that would break a Markdown link target.
# "|" is percent-encoded too: a raw pipe inside a table cell ends the cell, so a
# proof URL like .../a|b would split the row in the rendered pull request.
_LINK_ESCAPES = str.maketrans(
    {"(": "%28", ")": "%29", " ": "%20", "<": "%3C", ">": "%3E", "|": "%7C", "\n": "%0A", "\r": "%0D"}
)

# Characters that would break out of a Markdown table cell.
_CELL_ESCAPES = str.maketrans(
    {
        "\\": "\\\\",
        "|": "\\|",
        "[": "\\[",
        "]": "\\]",
        "<": "&lt;",
        ">": "&gt;",
        "@": "&#64;",  # renders as "@" but cannot ping a user/team
        "\n": " ",
        "\r": " ",
    }
)

# Characters that would break out of an inline code span.
_CODE_ESCAPES = str.maketrans({"\\": "\\\\", "|": "\\|", "`": "\\`"})

# Lone UTF-16 surrogates: legal in JSON input (e.g. "\ud800" in a player
# name) and loadable by Python, but impossible to encode as UTF-8 -- one in
# a name or proof would crash writing/printing the report. They are rendered
# as the replacement character instead; the database itself is unaffected
# (it is serialised with ensure_ascii, which re-escapes them losslessly).
_SURROGATES_RE = re.compile(r"[\ud800-\udfff]")

PROMOTION_HEADER = ("SteamID", "Last known name", "Before", "After", "Hackerpolice proof")
DEMOTION_HEADER = ("SteamID", "Last known name", "Before", "After")
REMOVED_HEADER = ("SteamID", "Profile Link")

# Display default only: the CLI always passes the real --snapshot path in
# RunInfo, so a custom path is reported correctly instead of the default.
DEFAULT_SNAPSHOT_LABEL = "snapshot/playerlist.vorobey-hackerpolice.json"


def _safe(text: str) -> str:
    """Replace lone surrogates so the report is always UTF-8 encodable."""
    return _SURROGATES_RE.sub("\ufffd", text)


def _cell(value: str) -> str:
    """Make a string safe inside a Markdown table cell."""
    return value.translate(_CELL_ESCAPES).strip() or "-"


# Control characters (including newlines) inside running text. The fetch URL
# can be an upstream-supplied download_url, so a newline in it would otherwise
# start a new Markdown line -- e.g. an extra bullet in the report header.
_TEXT_CONTROLS = re.compile(r"[\x00-\x1f\x7f]")


def _text(value: str) -> str:
    """Make a value safe as running text (the fetch URL line).

    ``<``/``>`` become entities, so they render identically but cannot open a
    tag; control characters become spaces, so they cannot start a new line.
    """
    return _TEXT_CONTROLS.sub(" ", value).replace("<", "&lt;").replace(">", "&gt;")


def _code(value: str) -> str:
    """Make a string safe inside an inline code span (``…``)."""
    return value.translate(_CODE_ESCAPES)


def _attributes_cell(attributes: Sequence[str]) -> str:
    """Render an attribute list as code spans: ``cheater``, ``racist``."""
    return ", ".join(f"`{_code(attribute)}`" for attribute in attributes)


def _steamid_cell(steamid: str) -> str:
    """Render a SteamID as a code span (canonical IDs need no escaping)."""
    return f"`{_code(steamid)}`"


def _name_cell(change: Change) -> str:
    """Last-known-name cell, linked to the player's Steam profile permalink.

    Clicking the name in the pull request opens the profile directly.
    A player with no recorded name shows as ``UNKNOWN`` -- still linked,
    since the SteamID (and therefore the profile) is known even when the
    name is not; only an unusable SteamID renders as plain text.
    """
    # UNKNOWN only when there is genuinely no recorded name; a player
    # actually named "-" (or similar) keeps their name. _cell() escapes the
    # brackets that would otherwise break the link text.
    label = "UNKNOWN" if not change.name.strip() else _cell(change.name)
    url = steam_profile_url(change.steamid)
    if url is None:
        return label
    return _markdown_link(url, label)


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


def _count(value: int) -> str:
    """Render a count with thousands separators (``123456`` -> ``123,456``).

    The Vorobey list is thousands of entries long, so an unseparated
    "5798 entries" is needlessly hard to read and misread at a glance.
    """
    return f"{value:,}"


def _capped(rows: Sequence[str], limit: int, singular: str, plural_form: str) -> tuple[list[str], str | None]:
    """Trim a table body to ``limit`` rows, returning an overflow note if needed."""
    if len(rows) <= limit:
        return list(rows), None
    hidden = len(rows) - limit
    note = (
        f"… and {_count(hidden)} more {plural(hidden, singular, plural_form)} not shown here "
        "(the table would make the pull request body too long)."
    )
    return list(rows[:limit]), note


def _table(header: Sequence[str], rows: Sequence[str], overflow_note: str | None = None) -> list[str]:
    """Render a Markdown table, plus an optional overflow note underneath."""
    lines = [
        "| " + " | ".join(header) + " |",
        "| " + " | ".join("---" for _ in header) + " |",
        *rows,
    ]
    if overflow_note:
        lines += ["", overflow_note]
    return lines


def _steamid_sort_key(steamid: str) -> tuple[bool, int]:
    """Numeric order; unusable SteamIDs sort last (stably). Key computed once."""
    account = account_id(steamid)
    return (account is None, account or 0)


def _sorted_steamids(steamids: Sequence[str]) -> list[str]:
    """Order SteamIDs numerically (unusable ones last, stably) for a stable diff."""
    return sorted(steamids, key=_steamid_sort_key)


def _change_sort_key(change: Change) -> tuple[bool, int]:
    """Order report rows by numeric SteamID."""
    return _steamid_sort_key(change.steamid)


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
    """
    if not steamids:
        return []

    ordered = _sorted_steamids(steamids)
    count = len(ordered)
    rows = [f"| {_steamid_cell(steamid)} | {_profile_cell(steamid)} |" for steamid in ordered]
    rows, overflow = _capped(rows, MAX_REMOVED_TABLE_ROWS, "SteamID", "SteamIDs")
    headline = (
        f"**{_count(count)} {plural(count, 'SteamID', 'SteamIDs')} removed from the Vorobey hackerpolice list "
        "since the previous snapshot.**"
    )
    return [
        headline,
        "",
        *_table(REMOVED_HEADER, rows, overflow),
        "",
    ]


def _with_removed_table(lines: list[str], steamids: Sequence[str]) -> list[str]:
    """Append the removed table to an already rendered report body."""
    table = render_removed_table(steamids)
    if not table:
        return lines
    while lines and not lines[-1].strip():
        lines.pop()  # exactly one blank line before the new section
    return [*lines, "", *table]


def render_closing(changes: Sequence[Change], database: str | None = None) -> str:
    """Build the present-tense closing sentence describing what changed.

    With a database name the file scopes the whole sentence and is named
    exactly once, up front::

        In `playerlist.garou3299.json`: attributes are changed for these
        SteamIDs: ...; entry is removed for this SteamID: ...; nothing else
        is modified.

    Without one (callers that only have the changes) it falls back to the
    standalone phrasing: "Attribute is changed for this SteamID: ...; Entry
    is removed from the database for this SteamID: ...; nothing else is
    modified."
    """
    # Same numeric order as the tables above, so the sentence reads the way
    # the report does regardless of the order the changes were discovered in.
    changed_steamids = _sorted_steamids(
        [change.steamid for change in changes if (change.kind == "promote") or change.after]
    )
    removed_steamids = _sorted_steamids(
        [change.steamid for change in changes if (change.kind == "demote") and not change.after]
    )

    def clause(head: str, target: str, steamids: list[str]) -> str:
        if database is None:
            head = head[:1].upper() + head[1:]  # standalone sentence starts capitalised
        return f"{head} for {target}: " + ", ".join(steamids)

    parts: list[str] = []
    if changed_steamids:
        one = len(changed_steamids) == 1
        parts.append(
            clause(
                "attribute is changed" if one else "attributes are changed",
                "this SteamID" if one else "these SteamIDs",
                changed_steamids,
            )
        )
    if removed_steamids:
        one = len(removed_steamids) == 1
        head = "entry is removed" if one else "entries are removed"
        if database is None:
            head += " from the database"
        parts.append(clause(head, "this SteamID" if one else "these SteamIDs", removed_steamids))

    body = "; ".join(parts)
    if database is not None:
        body = f"In `{_code(database)}`: {body}"
    return body + "; nothing else is modified."


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
    # Why the snapshot was left alone (--no-update-snapshot, or a run that
    # could not apply the removals it found).
    snapshot_note: str | None = None
    # True when the snapshot file itself was refreshed this run, so a
    # snapshot-only PR does not misleadingly report "No changes."
    snapshot_changed: bool = False
    # The snapshot file this run used (--snapshot), so the report never names
    # a path the run did not actually touch.
    snapshot_path: Path | None = None

    @property
    def database_name(self) -> str:
        """File name of the database the changes are written to.

        Only the file name, never the full (possibly temporary) path, so the
        closing sentence reads the same on every machine.
        """
        return Path(self.database_path).name


def _header_lines(info: RunInfo) -> list[str]:
    """The ``- Key: value`` bullet block at the top of the report."""
    source_note = f"{_count(info.source_total)} entries"
    if info.source_skipped:
        source_note += f", {_count(info.source_skipped)} unusable"

    lines = [
        "## Vorobey hackerpolice sync",
        "",
        f"- Database: `{_code(str(info.database_path))}`",
        f"- Vorobey hackerpolice list ({source_note}): {SOURCE_REPO_URL}",
        f"- Fetched from: {_text(redact_url(info.source))}",
        f"- Run at: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}",
    ]
    if info.dry_run:
        lines.append("- Mode: **dry run** (no database or snapshot written)")
    if info.previous_source_total is not None:
        current_total = info.previous_source_total + info.added_to_source - info.removed_from_source
        net = info.added_to_source - info.removed_from_source
        lines.append(
            f"- Previous snapshot: {_count(info.previous_source_total)} entries; "
            f"{_count(info.removed_from_source)} {plural(info.removed_from_source, 'SteamID', 'SteamIDs')} "
            "removed upstream since then (only those are demotion candidates)"
        )
        lines.append(
            f"- Snapshot diff: **{_count(info.added_to_source)} new "
            f"{plural(info.added_to_source, 'SteamID', 'SteamIDs')} added**, "
            f"**{_count(info.removed_from_source)} {plural(info.removed_from_source, 'SteamID', 'SteamIDs')} removed** "
            f"({_count(info.previous_source_total)} → {_count(current_total)} entries; net {net:+,d})"
        )
    elif info.snapshot_changed:
        # No baseline existed: every current ID is new in the initial snapshot.
        lines.append(
            f"- Snapshot diff: **{_count(info.added_to_source)} new "
            f"{plural(info.added_to_source, 'SteamID', 'SteamIDs')} added**, "
            "**0 SteamIDs removed** (no previous snapshot; initial snapshot)"
        )
    if info.demotion_note:
        lines.append(f"- Demotion: **{info.demotion_note}**")
    if info.snapshot_note:
        lines.append(f"- Snapshot: {info.snapshot_note}")
    elif info.snapshot_changed:
        verb = "would be updated" if info.dry_run else "updated"
        label = _code(str(info.snapshot_path) if info.snapshot_path is not None else DEFAULT_SNAPSHOT_LABEL)
        lines.append(f"- Snapshot: `{label}` {verb} to an exact copy of the current upstream file")
    lines.append("")
    return lines


def _promotion_lines(promotions: Sequence[Change]) -> list[str]:
    """Render the "promoted to cheater" table block."""
    rows = [
        f"| {_steamid_cell(change.steamid)} | {_name_cell(change)} | {_attributes_cell(change.before)} "
        f"| {_attributes_cell(change.after)} | {_evidence_cell(change.evidence)} |"
        for change in promotions
    ]
    rows, overflow = _capped(rows, MAX_CHANGE_TABLE_ROWS, "entry", "entries")
    count = len(promotions)
    return [
        f"**{_count(count)} {plural(count, 'entry', 'entries')} promoted to `cheater`.**",
        "",
        *_table(PROMOTION_HEADER, rows, overflow),
        "",
    ]


def _demotion_lines(demotions: Sequence[Change]) -> list[str]:
    """Render the "demoted" table block."""
    rows = [
        f"| {_steamid_cell(change.steamid)} | {_name_cell(change)} | {_attributes_cell(change.before)} "
        f"| {_attributes_cell(change.after) or 'entry removed'} |"
        for change in demotions
    ]
    rows, overflow = _capped(rows, MAX_CHANGE_TABLE_ROWS, "entry", "entries")
    count = len(demotions)
    headline = (
        f"**{_count(count)} {plural(count, 'entry', 'entries')} demoted (in the previous snapshot, "
        "removed from the hackerpolice list since).**"
    )
    return [
        headline,
        "",
        *_table(DEMOTION_HEADER, rows, overflow),
        "",
    ]


def _utf8_len(text: str) -> int:
    """UTF-8 length of the text, counting (never raising on) lone surrogates.

    ``_fit_body`` runs before ``_safe`` replaces lone surrogates, so the
    measurement must not choke on them; "surrogatepass" gives each one the 3
    bytes it will occupy once replaced by U+FFFD.
    """
    return len(text.encode("utf-8", "surrogatepass"))


def _truncate_to_bytes(text: str, limit: int) -> str:
    """Longest prefix of ``text`` whose UTF-8 encoding fits in ``limit`` bytes."""
    if limit <= 0:
        return ""
    return text.encode("utf-8", "surrogatepass")[:limit].decode("utf-8", "ignore")  # never a half character


def _fit_body(text: str) -> str:
    """Hard-limit the body so publishing the pull request can never fail.

    The tables are already capped; this is the last-resort guard for a run
    with pathological input (very long names/proofs). The budget is measured
    in BYTES because that is what GitHub enforces -- measuring characters
    would let a body of non-Latin names overflow the limit. It cuts on a line
    boundary and says so, instead of silently losing the tail.
    """
    if _utf8_len(text) <= MAX_REPORT_BYTES:
        return text
    note = "\n\n… report truncated to fit the pull request body limit."
    keep = _truncate_to_bytes(text, MAX_REPORT_BYTES - _utf8_len(note))
    cut = keep.rfind("\n")
    return (keep[:cut] if cut > 0 else keep) + note


def render_report(info: RunInfo) -> str:
    """Render the PR body / job summary as Markdown."""
    lines = _header_lines(info)

    # Numeric SteamID order: the same run always renders the same table, and
    # the reader can find an ID at a glance (changes arrive in database order).
    promotions = sorted((change for change in info.changes if change.kind == "promote"), key=_change_sort_key)
    demotions = sorted((change for change in info.changes if change.kind == "demote"), key=_change_sort_key)

    if not promotions and not demotions:
        if info.snapshot_changed:
            lines += ["**No database changes** (snapshot refresh only).", ""]
        else:
            lines += ["**No changes.**", ""]
        return _safe(_fit_body("\n".join(_with_removed_table(lines, info.removed_upstream))))

    if promotions:
        lines += _promotion_lines(promotions)
    if demotions:
        lines += _demotion_lines(demotions)

    # Upstream removals first: the closing sentence and the proof note that
    # follow are always the last thing in the report.
    lines = _with_removed_table(lines, info.removed_upstream)

    closing = render_closing(info.changes, database=info.database_name)

    while lines and not lines[-1].strip():
        lines.pop()  # exactly one blank line before the closing sentence
    lines += ["", closing]

    total_links = sum(len(change.evidence) for change in promotions)
    if info.include_proof:
        lines += [
            "",
            "**Note:** `--include-proof` was enabled, so an `[auto]` proof line citing the",
            "hackerpolice list was also written into each entry above.",
        ]
        if total_links:
            lines.append("")
    if total_links:
        # Deliberately the last line of the report.
        note = (
            "Proof link comes from the Vorobey hackerpolice list and is shown for review only."
            if total_links == 1
            else "Proof links come from the Vorobey hackerpolice list and are shown for review only."
        )
        lines.append(note)
    lines.append("")
    return _safe(_fit_body("\n".join(lines)))
