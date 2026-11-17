"""Markdown report rendering for sync results.

Produces the pull request body / job summary from a :class:`RunInfo`.

The report is the bot's only human-facing output, so it is treated as
untrusted-output as well as untrusted-input territory:

* every value that comes from the database or from the upstream Vorobey
  list (names, proofs, SteamIDs) is escaped for a Markdown table cell --
  pipes and newlines cannot break the table, brackets cannot forge a link,
  angle brackets cannot inject HTML, and ``@`` cannot trigger a mention;
* credentials in URLs embedded anywhere in upstream proof text are redacted
  before they reach the report; changed text is not shown as a misleading link;
* every table is row-capped, and the whole body has a hard length guard,
  because GitHub rejects pull request bodies over 65,536 characters. A report
  that would exceed the budget drops more rows (announced with an "and N more"
  note) instead of being cut off, so the closing sentence and the removed
  SteamIDs always survive;
* the closing sentence names the database that changed exactly once.

Order of the body: header bullets, promotions, demotions, the SteamIDs
removed from the upstream list (``| SteamID | Profile Link | SteamHistory |``), and
finally the closing sentence + proof note.
"""

from __future__ import annotations

import re
import time
import urllib.parse
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from playerlist import account_id, display_path, steam_history_url, steam_profile_url
from policy import Change
from sources import SOURCE_REPO_URL, redact_urls_in_text

__all__ = [
    "MAX_ATTRIBUTE_CELLS",
    "MAX_ATTRIBUTE_CHARS",
    "MAX_CHANGE_TABLE_ROWS",
    "MAX_CLOSING_STEAMIDS",
    "MAX_EVIDENCE_LINKS",
    "MAX_EVIDENCE_LINK_CHARS",
    "MAX_NAME_CHARS",
    "MAX_REMOVED_TABLE_ROWS",
    "MAX_REPORT_BYTES",
    "RunInfo",
    "plural",
    "render_closing",
    "render_removed_table",
    "render_report",
]

# GitHub rejects a pull request body longer than 65,536 characters. Change
# tables are capped, the removed table is capped, an oversized body is
# re-rendered with smaller caps (see _SHRINK_STEPS), and a hard truncation is
# the last resort, so publishing the PR can never fail on size -- however big a
# single run turns out to be.
MAX_CHANGE_TABLE_ROWS = 150
MAX_REMOVED_TABLE_ROWS = 100
# The closing sentence names the changed SteamIDs too. A run with thousands of
# changes would spend the whole byte budget there (and stop being readable), so
# each clause names at most this many and says how many follow.
MAX_CLOSING_STEAMIDS = 150
# GitHub rejects a pull request body over 65,536 BYTES, and the body doubles
# as the job summary, so the budget is measured in bytes with room to spare.
# Characters would be the wrong unit: 30,000 Cyrillic player names are half the
# character budget and twice the byte budget.
MAX_REPORT_BYTES = 60_000
# One cell can be as big as the data behind it, and a single enormous row
# defeats every row cap: the body then gets hard-truncated, which loses the
# closing sentence and the removed-SteamID list the report exists to publish
# (measured: ten 6,000-character proof links collapsed the whole body to 494
# bytes). Every cell that carries data from the database or the upstream file
# therefore has a bound on BOTH how many items it lists and how long each item
# may be:
#   * proof links per row (the pull request is a review list, not an archive;
#     the list is only ever read a few links at a time) and their length (a
#     Discord proof link is ~60 characters, so 500 is already ~8x a real one),
#   * player-name characters (Steam names are at most 32 characters, so a much
#     longer one is abnormal -- the profile link still carries the identity),
#   * attributes per row (the TF2BD schema has four; anything beyond a handful
#     is malformed) and their length (the longest known one is 10 characters).
MAX_EVIDENCE_LINKS = 10
MAX_EVIDENCE_LINK_CHARS = 500
MAX_NAME_CHARS = 80
MAX_ATTRIBUTE_CHARS = 40
MAX_ATTRIBUTE_CELLS = 8

# Characters that would break a Markdown link target.
# "|" is percent-encoded too: a raw pipe inside a table cell ends the cell, so a
# proof URL like .../a|b would split the row in the rendered pull request.
_LINK_ESCAPES = str.maketrans(
    {
        "(": "%28",
        ")": "%29",
        " ": "%20",
        "<": "%3C",
        ">": "%3E",
        "|": "%7C",
        # A raw backtick in a URL starts a code span before the link is even
        # recognised, so the rest of the row was parsed as code.
        "`": "%60",
        "\n": "%0A",
        "\r": "%0D",
    }
)

# Characters that would break out of Markdown text. ONE policy, two tables:
# a value is escaped the same way in a table cell and in running text, and the
# only difference is the pipe (which ends a cell). Keeping one map is the point
# -- while the two lists were maintained apart, the entity spelling of a
# character got past both of them.
_ESCAPES = {
    # A literal "&" must not be able to spell an entity the guards do not see:
    # "&#x202E;" rendered a real right-to-left override, "&#8203;" a zero-width
    # space (both defeating the bidi/invisible scrubbing below), and "&#64;admin"
    # rendered "@admin" (a mention ping, which the "@" escape exists to stop).
    "&": "&amp;",
    # A backslash must be escaped first or it swallows the escape of whatever
    # follows it; ``translate`` is a single pass, so order cannot be got wrong.
    "\\": "\\\\",
    "<": "&lt;",
    ">": "&gt;",
    # A link or an image: a name holding "[click](https://elsewhere.example)"
    # would otherwise render as a live link in a bot-authored pull request.
    "[": "\\[",
    "]": "\\]",
    # A backtick OPENS a code span everywhere outside one. A name such as
    # "tick` here" used to leave the report with an odd number of them, so the
    # span swallowed the rest of the row -- the profile link stopped being a
    # link and later rows were re-rendered as code.
    "`": "\\`",
    # Renders as "@" but cannot ping a user or a team.
    "@": "&#64;",
    # Emphasis/strikethrough: "**Approved by admin**" rendered as BOLD inside
    # the bot's own pull request, which reviewers approve.
    "*": "\\*",
    "_": "\\_",
    "~": "\\~",
    # A line break would start a second line (in a table: a second row).
    "\n": " ",
    "\r": " ",
}

# Inside a table a raw pipe ends the cell, so it is escaped as well.
_CELL_ESCAPES = str.maketrans({**_ESCAPES, "|": "\\|"})
_TEXT_ESCAPES = str.maketrans(_ESCAPES)

# Characters that would break out of an inline code span INSIDE A TABLE.
# A pipe has to be escaped there because GFM splits a row into cells before it
# parses code spans; the backslash that escapes it needs escaping in turn, or
# a value like "a\|b" would leave a bare pipe behind. Outside a table neither
# is needed (and escaping them would visibly double a Windows path).
_TABLE_CODE_ESCAPES = str.maketrans({"\\": "\\\\", "|": "\\|"})

# Lone UTF-16 surrogates: legal in JSON input (e.g. "\ud800" in a player
# name) and loadable by Python, but impossible to encode as UTF-8 -- one in
# a name or proof would crash writing/printing the report. They are rendered
# as the replacement character instead; the database itself is unaffected
# (it is serialised with ensure_ascii, which re-escapes them losslessly).
_SURROGATES_RE = re.compile(r"[\ud800-\udfff]")

PROMOTION_HEADER = ("SteamID", "Last known name", "Before", "After", "Hackerpolice proof", "SteamHistory")
DEMOTION_HEADER = ("SteamID", "Last known name", "Before", "After", "SteamHistory")
REMOVED_HEADER = ("SteamID", "Profile Link", "SteamHistory")

# Display default only: the CLI always passes the real --snapshot path in
# RunInfo, so a custom path is reported correctly instead of the default.
DEFAULT_SNAPSHOT_LABEL = "snapshot/playerlist.vorobey-hackerpolice.json"


# Control characters (including newlines) in anything that reaches the page or
# the job log. The fetch URL can be an upstream-supplied download_url, so a
# newline in it would otherwise start a new Markdown line (e.g. an extra bullet
# in the report header), and an ESC would repaint the terminal that `cat`s it.
#
# U+0085 (NEL) and U+2028/U+2029 are line terminators too -- ``str.splitlines``
# and CSS both treat them as a line break -- so a player name containing one
# would split a table row in the rendered pull request. They are neutralised
# with the ASCII control characters, not left to the renderer.
_TEXT_CONTROLS = re.compile(r"[\x00-\x1f\x7f\x85\u2028\u2029]")

# Bidirectional overrides flip how the rest of the line is displayed, so a name
# like "abc\u202eDEF" shows as "abcFED" and can make the NEXT table cell read
# as something else. They have no legitimate use in a player name; a zero-width
# joiner does (emoji, Indic scripts), so only the bidi controls are replaced.
_BIDI_CONTROLS = re.compile(r"[\u200e\u200f\u202a-\u202e\u2066-\u2069]")

# The rest of Unicode's FORMAT characters are invisible rather than
# line-flipping: a zero-width space, a word joiner, a BOM, a soft hyphen or a
# Unicode tag character makes two different names render identically in the
# review table, and tag characters are a known way to hide text outright. They
# become the same visible placeholder as a bidi override, so a reader can see
# that the value holds something. ZWNJ/ZWJ stay (U+200C/U+200D): invisible but
# meaningful -- Persian and Indic orthography, and emoji sequences.
_INVISIBLE_CONTROLS = re.compile("[\u00ad\u061c\u180e\u200b\u2060-\u2064\ufeff\ufff9-\ufffb\U000e0000-\U000e007f]")


def _neutralise(value: str) -> str:
    """Make a value safe to put in front of a human or a terminal."""
    value = redact_urls_in_text(value)
    value = _TEXT_CONTROLS.sub(" ", value)
    value = _BIDI_CONTROLS.sub("\ufffd", value)
    return _INVISIBLE_CONTROLS.sub("\ufffd", value)


def _safe(text: str) -> str:
    """Replace lone surrogates so the report is always UTF-8 encodable."""
    return _SURROGATES_RE.sub("\ufffd", text)


def _shorten(value: str, limit: int) -> str:
    """Cut ``value`` to ``limit`` characters, marking the cut with an ellipsis.

    Truncation happens BEFORE escaping (a cut through an escape sequence would
    otherwise leave a half-written entity), and only ever applies to values far
    longer than the format allows.
    """
    return value if len(value) <= limit else value[:limit].rstrip() + "…"


def _cell(value: str) -> str:
    """Make a string safe inside a Markdown table cell."""
    return _neutralise(value).translate(_CELL_ESCAPES).strip() or "-"


def _text(value: str) -> str:
    """Make a value safe as running text (the fetch URL line).

    ``<``/``>`` become entities, so they render identically but cannot open a
    tag; control characters become spaces, so they cannot start a new line.
    ``[``/``]`` are escaped as well: this line carries a URL, and a URL holding
    ``[click](https://elsewhere.example)`` would otherwise render as a live
    link inside a bot-authored pull request. ``@`` becomes an entity for the
    same reason it does in a table cell: ``@handle`` is a real mention, so a
    URL (which can come from a document's ``download_url``, i.e. from someone
    else) must not be able to ping a stranger from the bot's pull request.
    Every character in ``_ESCAPES`` is escaped here too -- the same single map
    the table cells use, so a value cannot be safe in one place and not the
    other.
    """
    return _neutralise(value).translate(_TEXT_ESCAPES)


def _code(value: str, *, in_table: bool = False) -> str:
    """Make a string safe inside an inline code span (``…``).

    A code span is delimited by a run of backticks and can never contain a run
    that long, so the fence is grown past the longest run in the value: a value
    holding one backtick is wrapped in ``` ``…`` ``` instead of ending the span
    early. A backslash does NOT escape a backtick inside a code span, so the
    escape this used to write was not protection at all -- a value such as
    ``x` and **bold** ` `` closed the span and rendered its tail as Markdown.

    ``in_table`` additionally escapes the characters GFM's cell splitter cares
    about (see ``_TABLE_CODE_ESCAPES``); running text does not need that, and
    escaping it there would display a Windows path as ``C:\\x``.
    """
    text = _neutralise(value)
    if in_table:
        text = text.translate(_TABLE_CODE_ESCAPES)
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    if text.startswith("`") or text.endswith("`"):
        # CommonMark strips one space from each end; the padding keeps a value
        # that begins or ends with a backtick from merging into the fence.
        text = f" {text} "
    return f"{fence}{text}{fence}"


def _attributes_cell(attributes: Sequence[str]) -> str:
    """Render an attribute list as code spans: ``cheater``, ``racist``.

    Bounded in both directions (see ``MAX_ATTRIBUTE_CELLS`` and
    ``MAX_ATTRIBUTE_CHARS``): these strings come from the database, and an
    entry carrying a pathological attribute list must not be able to push the
    closing sentence out of the report.
    """
    shown = attributes[:MAX_ATTRIBUTE_CELLS]
    cell = ", ".join(_code(_shorten(attribute, MAX_ATTRIBUTE_CHARS), in_table=True) for attribute in shown)
    hidden = len(attributes) - len(shown)
    if hidden:
        cell += f", and {_count(hidden)} more"
    return cell


def _steamid_cell(steamid: str) -> str:
    """Render a SteamID as a code span (canonical IDs need no escaping)."""
    return _code(steamid, in_table=True)


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
    name = _shorten(change.name, MAX_NAME_CHARS)  # cut BEFORE escaping
    label = "UNKNOWN" if not name.strip() else _cell(name)
    url = steam_profile_url(change.steamid)
    if url is None:
        return label
    return _markdown_link(url, label)


_HTTP_SCHEME_IN_TEXT = re.compile(r"https?:", re.IGNORECASE)
_SECOND_HTTP_URL = re.compile(r"\s+https?://", re.IGNORECASE)
_MALFORMED_PERCENT_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")


def _is_url(text: str) -> bool:
    """True only for an unambiguous absolute HTTP(S) URL.

    ``urlsplit`` is intentionally permissive: it accepts ``https:relative``,
    empty authorities and invalid ports. Markdown/browser URL parsers also
    disagree about backslashes and whitespace in authorities. Reject those
    ambiguous forms rather than making untrusted evidence clickable. Spaces
    in a path remain supported and are percent-encoded by ``_markdown_link``.
    """
    if not text or text != text.strip() or "\\" in text or any(char in text for char in "\r\n\t"):
        return False
    if any(char.isspace() and char != " " for char in text):
        return False
    if _SECOND_HTTP_URL.search(text) or _MALFORMED_PERCENT_ESCAPE.search(text):
        return False
    try:
        parts = urllib.parse.urlsplit(text)
        hostname = parts.hostname
        # Accessing .port performs the validation urlsplit defers, including
        # rejecting non-numeric and out-of-range ports.
        _ = parts.port
    except ValueError:
        return False
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc or not hostname:
        return False
    if any(char.isspace() for char in parts.netloc) or "%" in hostname:
        return False
    authority = parts.netloc.rsplit("@", 1)[-1]
    return not authority.endswith(":")


def _markdown_link(url: str, label: str) -> str:
    """Render a link, escaping the characters that would end the target early.

    Control, bidi and invisible characters cannot appear in a URL, so they are
    percent-encoded rather than dropped: the link stays faithful and nothing
    lands raw in a terminal or in front of a reader (an ESC would repaint it, a
    bidi override would reverse the rest of the line, and a zero-width space
    would make two different targets look identical).
    """
    encoded = url.translate(_LINK_ESCAPES)
    for pattern in (_TEXT_CONTROLS, _BIDI_CONTROLS, _INVISIBLE_CONTROLS):
        encoded = pattern.sub(lambda match: "".join(f"%{byte:02X}" for byte in match.group().encode("utf-8")), encoded)
    return f"[{label}]({encoded})"


def _evidence_link_status(link: str) -> tuple[str, bool]:
    """Return safe display text and whether the value is a rendered link."""
    safe_link = redact_urls_in_text(link)
    clickable = len(link) <= MAX_EVIDENCE_LINK_CHARS and safe_link == link and _is_url(link)
    return safe_link, clickable


def _evidence_cell(links: Sequence[str]) -> str:
    """Proof column: real links where possible, escaped text otherwise.

    Each link is labelled "proof" (or "proof 1", "proof 2" when there are
    several) so it is obvious what clicking it opens; several are listed side
    by side rather than separated by an HTML ``<br>``, because the report never
    emits raw HTML -- a cell then renders the same in a pull request, in a job
    summary and in any plain Markdown preview, where a tag would show as text.
    Untrusted values that are redacted, malformed or merely prose are kept out
    of Markdown's automatic-link parser too: a code span is literal, not a
    second chance for GitHub to turn a supposedly non-clickable URL into one.
    """
    if not links:
        return "-"
    shown = links[:MAX_EVIDENCE_LINKS]
    single = len(shown) == 1
    rendered: list[str] = []
    for position, link in enumerate(shown, start=1):
        safe_link, clickable = _evidence_link_status(link)
        if clickable:
            rendered.append(_markdown_link(link, "proof" if single else f"proof {position}"))
        else:
            preview = _shorten(safe_link, MAX_EVIDENCE_LINK_CHARS)
            if safe_link != link or _HTTP_SCHEME_IN_TEXT.search(link):
                rendered.append(_code(preview, in_table=True))
            else:
                rendered.append(_cell(preview))
    cell = ", ".join(rendered)
    hidden = len(links) - len(shown)
    if hidden:
        # Plain text, not a link: it must never look clickable.
        cell += f", and {_count(hidden)} more"
    return cell


def plural(count: int, singular: str, plural_form: str) -> str:
    """Return ``singular`` when count is 1, otherwise ``plural_form``."""
    return singular if count == 1 else plural_form


def _count(value: int) -> str:
    """Render a count with thousands separators (``123456`` -> ``123,456``).

    The Vorobey list is thousands of entries long, so an unseparated
    "5798 entries" is needlessly hard to read and misread at a glance.
    """
    return f"{value:,}"


def _overflow_note(total: int, limit: int, singular: str, plural_form: str) -> str | None:
    """The "and N more" note for a table whose body was cut to ``limit`` rows.

    Callers cut the SEQUENCE first and render only ``limit`` rows: building
    every row and throwing all but a hundred away cost 2.3 s for a 50,000-row
    run, to produce a 46 kB report either way.
    """
    if total <= limit:
        return None
    hidden = total - limit
    return (
        f"… and {_count(hidden)} more {plural(hidden, singular, plural_form)} not shown here "
        "(the table would make the pull request body too long)."
    )


def _row(cells: Sequence[str]) -> str:
    """Render one table row from already-escaped cells (one string per column)."""
    return "| " + " | ".join(cells) + " |"


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


def _steamid_list(steamids: Sequence[str], limit: int = MAX_CLOSING_STEAMIDS) -> str:
    """Comma-separated SteamIDs, shortened with ``and N more`` past ``limit``."""
    if len(steamids) <= limit:
        return ", ".join(steamids)
    return ", ".join(steamids[:limit]) + f" and {_count(len(steamids) - limit)} more"


def _change_sort_key(change: Change) -> tuple[bool, int]:
    """Order report rows by numeric SteamID."""
    return _steamid_sort_key(change.steamid)


def _permalink_cell(url: str | None, label: str) -> str:
    """A Markdown link to ``url``, or ``-`` when it cannot be built."""
    return "-" if url is None else _markdown_link(url, label)


def _profile_cell(steamid: str) -> str:
    """Steam profile permalink for one SteamID, or ``-`` if it cannot be built."""
    return _permalink_cell(steam_profile_url(steamid), "Profile")


def _steam_history_cell(steamid: str) -> str:
    """SteamHistory page for one SteamID, or ``-`` if it cannot be built.

    SteamHistory keeps a profile's history (past names, avatars, bans), so the
    reviewer can see who a demoted or promoted player is even after a rename.
    """
    return _permalink_cell(steam_history_url(steamid), "SteamHistory")


def render_removed_table(steamids: Sequence[str], limit: int = MAX_REMOVED_TABLE_ROWS) -> list[str]:
    """Render the "removed from the Vorobey list" table as Markdown lines.

    Vorobey's list records no player names, so the table is
    ``| SteamID | Profile Link | SteamHistory |``: the SteamID in canonical
    ``[U:1:x]`` form, the Steam Community profile *permalink* and the
    SteamHistory page (both SteamID64 URLs, so they keep working even when the
    player renames themselves).
    """
    if not steamids:
        return []

    ordered = _sorted_steamids(steamids)
    count = len(ordered)
    rows = [
        _row((_steamid_cell(steamid), _profile_cell(steamid), _steam_history_cell(steamid)))
        for steamid in ordered[:limit]
    ]
    overflow = _overflow_note(count, limit, "SteamID", "SteamIDs")
    headline = (
        f"**{_count(count)} {plural(count, 'SteamID', 'SteamIDs')} removed from the Vorobey hackerpolice list "
        "since the previous snapshot:**"
    )
    return [
        headline,
        "",
        *_table(REMOVED_HEADER, rows, overflow),
        "",
    ]


def _with_removed_table(lines: list[str], steamids: Sequence[str], limit: int = MAX_REMOVED_TABLE_ROWS) -> list[str]:
    """Append the removed table to an already rendered report body."""
    table = render_removed_table(steamids, limit)
    if not table:
        return lines
    while lines and not lines[-1].strip():
        lines.pop()  # exactly one blank line before the new section
    return [*lines, "", *table]


def render_closing(changes: Sequence[Change], database: str | None = None) -> str:
    """Build the present-tense closing sentence describing what changed.

    With a database name the friendly label scopes the whole sentence and is
    named exactly once, up front::

        In the Garou3299 database: attributes are changed for these SteamIDs:
        ...; entry is removed for this SteamID: ...; nothing else is modified.

    The label rather than the file name, because the table headlines use it too
    and the exact path is already named in the header bullet -- repeating a
    code-span path here made the summary the clumsiest line in the report.

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
        return f"{head} for {target}: " + _steamid_list(steamids)

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

    if not parts:
        # No changes at all. Without this guard the sentence reads
        # "In the X database: ; nothing else is modified." -- an empty clause.
        return f"In the {_text(database)} database: nothing has changed." if database else "Nothing has changed."
    body = "; ".join(parts)
    if database:
        body = f"In the {_text(database)} database: {body}"
    return body + "; nothing else is modified."


@dataclass(frozen=True)
class RunInfo:
    """Facts about a run, used to render the Markdown summary."""

    database_path: Path
    source: str
    source_total: int
    source_skipped: int
    dry_run: bool
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
    # True when the DATABASE FILE changes even though no tag does: the sync
    # always writes entries back in canonical form (sorted by SteamID), so a
    # hand-appended entry is re-sorted without any attribute changing. Without
    # this flag the body used to claim "No database changes" over a visible
    # diff in the pull request.
    database_changed: bool = False
    # The snapshot file this run used (--snapshot), so the report never names
    # a path the run did not actually touch.
    snapshot_path: Path | None = None

    @property
    def database_label(self) -> str:
        """Friendly name of the database, derived from its file name.

        ``playerlist.garou3299.json`` becomes ``Garou3299``: the owner part of
        the usual ``playerlist.<owner>.json`` shape, capitalised. Any other
        file name is used as it is (``mylist.json`` becomes ``Mylist``), so
        the headline always names the file the run actually writes and no
        repository name is hardcoded here.
        """
        stem = Path(display_path(self.database_path)).stem
        head, _, owner = stem.partition(".")
        name = owner if head == "playerlist" and owner else stem
        return name[:1].upper() + name[1:]


def _header_lines(info: RunInfo) -> list[str]:
    """The ``- Key: value`` bullet block at the top of the report."""
    source_note = f"{_count(info.source_total)} entries"
    if info.source_skipped:
        source_note += f", {_count(info.source_skipped)} unusable"

    lines = [
        "## Vorobey hackerpolice sync",
        "",
        f"- Database: {_code(display_path(info.database_path))}",
        f"- Vorobey hackerpolice list ({source_note}): {SOURCE_REPO_URL}",
        f"- Fetched from: {_text(redact_urls_in_text(info.source))}",
        f"- Run at: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}",
    ]
    if info.dry_run:
        lines.append("- Mode: **dry run** (no database or snapshot written)")
    if info.previous_source_total is not None:
        current_total = info.previous_source_total + info.added_to_source - info.removed_from_source
        delta = info.added_to_source - info.removed_from_source
        # "+0" reads like a change was made; name the no-change case instead.
        net = "no net change" if delta == 0 else f"net {delta:+,d}"
        lines.append(
            f"- Previous snapshot: {_count(info.previous_source_total)} entries; "
            f"{_count(info.removed_from_source)} {plural(info.removed_from_source, 'SteamID', 'SteamIDs')} "
            "removed upstream since then (only those are demotion candidates)"
        )
        lines.append(
            f"- Snapshot diff: **{_count(info.added_to_source)} new "
            f"{plural(info.added_to_source, 'SteamID', 'SteamIDs')} added**, "
            f"**{_count(info.removed_from_source)} {plural(info.removed_from_source, 'SteamID', 'SteamIDs')} removed** "
            f"({_count(info.previous_source_total)} → {_count(current_total)} entries; {net})"
        )
    elif info.snapshot_changed:
        # No baseline existed: every current ID is new in the initial snapshot.
        lines.append(
            f"- Snapshot diff: **{_count(info.added_to_source)} new "
            f"{plural(info.added_to_source, 'SteamID', 'SteamIDs')} added**, "
            "**0 SteamIDs removed** (no previous snapshot; initial snapshot)"
        )
    if info.demotion_note:
        # _text(): this note embeds the snapshot PATH, which is data like any
        # other. A directory called "a[x](https://evil.example)" used to render
        # as a live link inside the bot's own pull request.
        lines.append(f"- Demotion: **{_text(info.demotion_note)}**")
    if info.snapshot_note:
        # Deliberately NOT escaped: unlike the demotion note, this one is
        # authored in code (bold markers and a `--demote` code span) and carries
        # no data -- escaping it would print the markers instead of applying them.
        lines.append(f"- Snapshot: {info.snapshot_note}")
    elif info.snapshot_changed:
        verb = "would be updated" if info.dry_run else "updated"
        label = _code(display_path(info.snapshot_path) if info.snapshot_path is not None else DEFAULT_SNAPSHOT_LABEL)
        lines.append(f"- Snapshot: {label} {verb} to an exact copy of the current upstream file")
    lines.append("")
    return lines


def _promotion_lines(promotions: Sequence[Change], limit: int = MAX_CHANGE_TABLE_ROWS, *, database: str) -> list[str]:
    """Render the "promoted to cheater" table block.

    ``database`` is escaped here: it is derived from a file name, which is
    data like any other -- a database called ``<b>x.json`` must not open a tag
    in the report.
    """
    count = len(promotions)
    rows = [
        _row(
            (
                _steamid_cell(change.steamid),
                _name_cell(change),
                _attributes_cell(change.before),
                _attributes_cell(change.after),
                _evidence_cell(change.evidence),
                _steam_history_cell(change.steamid),
            )
        )
        for change in promotions[:limit]
    ]
    overflow = _overflow_note(count, limit, "entry", "entries")
    entries = plural(count, "entry", "entries")
    headline = f"**{_count(count)} {entries} promoted to `cheater` in the {_text(database)} database:**"
    return [headline, "", *_table(PROMOTION_HEADER, rows, overflow), ""]


def _demotion_lines(demotions: Sequence[Change], limit: int = MAX_CHANGE_TABLE_ROWS, *, database: str) -> list[str]:
    """Render the "demoted" table block."""
    count = len(demotions)
    rows = [
        _row(
            (
                _steamid_cell(change.steamid),
                _name_cell(change),
                _attributes_cell(change.before),
                _attributes_cell(change.after) or "entry removed",
                _steam_history_cell(change.steamid),
            )
        )
        for change in demotions[:limit]
    ]
    overflow = _overflow_note(count, limit, "entry", "entries")
    headline = (
        f"**{_count(count)} {plural(count, 'entry', 'entries')} demoted (present in the previous snapshot, "
        f"absent from the current Vorobey hackerpolice list) in the {_text(database)} database:**"
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
    # Fast path: encoding a multi-megabyte body only to slice off all of it
    # would cost more than the whole shrink step. Both branches return "".
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


def _prepare_changes(info: RunInfo) -> tuple[list[Change], list[Change]]:
    """Split the changes into promotions and demotions, in numeric SteamID order.

    Numeric order means the same run always renders the same table, and the
    reader can find an ID at a glance (changes arrive in database order).
    Computed once per report: the body is rendered up to ten times while it
    shrinks to fit, and re-sorting every change each time cost 1.6 s on a
    100,000-change run.
    """
    return (
        sorted((change for change in info.changes if change.kind == "promote"), key=_change_sort_key),
        sorted((change for change in info.changes if change.kind == "demote"), key=_change_sort_key),
    )


def _render_body(
    info: RunInfo,
    change_limit: int,
    removed_limit: int,
    promotions: Sequence[Change] | None = None,
    demotions: Sequence[Change] | None = None,
    closing_sentence: str | None = None,
) -> str:
    """Render the body with at most ``change_limit``/``removed_limit`` rows per table.

    ``render_report`` passes the prepared (sorted) sequences and the closing
    sentence in, because it renders the body repeatedly; the defaults keep the
    function usable on its own.
    """
    lines = _header_lines(info)
    if promotions is None or demotions is None:
        promotions, demotions = _prepare_changes(info)

    if not promotions and not demotions:
        if info.database_changed:
            # The file changes without any tag changing (re-sorted entries,
            # restored formatting). Say exactly that: "No changes" over a diff
            # the reviewer can see is the one thing this sentence must not say.
            verb = "would be normalised" if info.dry_run else "was normalised"
            detail = "entries re-sorted, formatting restored"
            if info.snapshot_changed:
                refreshed = "would be refreshed" if info.dry_run else "was refreshed"
                detail += f"; the snapshot {refreshed} too"
            lines += [f"**No player changes** (the database file {verb}: {detail}).", ""]
        elif info.snapshot_changed:
            lines += ["**No database changes** (snapshot refresh only).", ""]
        else:
            lines += ["**No changes.**", ""]
        return "\n".join(_with_removed_table(lines, info.removed_upstream, removed_limit))

    if promotions:
        lines += _promotion_lines(promotions, change_limit, database=info.database_label)
    if demotions:
        lines += _demotion_lines(demotions, change_limit, database=info.database_label)

    # Upstream removals first: the closing sentence and the proof note that
    # follow are always the last thing in the report.
    lines = _with_removed_table(lines, info.removed_upstream, removed_limit)

    if closing_sentence is None:
        closing_sentence = render_closing(info.changes, database=info.database_label)

    while lines and not lines[-1].strip():
        lines.pop()  # exactly one blank line before the closing sentence
    lines += ["", closing_sentence]

    # Counted over the rows that are actually rendered: with a capped table the
    # evidence of row 200 is not on the page, and a note about "the proof link"
    # above no link at all is worse than no note.
    total_links = sum(
        _evidence_link_status(link)[1]
        for change in promotions[:change_limit]
        for link in change.evidence[:MAX_EVIDENCE_LINKS]
    )
    if total_links:
        # Deliberately the last line of the report.
        note = (
            "Proof link comes from the Vorobey hackerpolice list and is shown for review only."
            if total_links == 1
            else "Proof links come from the Vorobey hackerpolice list and are shown for review only."
        )
        lines.append(note)
    lines.append("")
    return "\n".join(lines)


# Tried in order when a report would exceed MAX_REPORT_BYTES. Rows are dropped
# (each drop is announced with an "and N more" note) instead of the body being
# cut off, because the closing sentence and the removed-SteamID list are what
# the pull request exists to communicate. The change tables shrink first --
# the same changes are visible in the PR's own diff -- and the removed list
# only after them; the last resort is one row per table, and _fit_body() after
# that for a single row that is itself enormous.
_SHRINK_STEPS: tuple[tuple[int, int], ...] = (
    (100, MAX_REMOVED_TABLE_ROWS),
    (50, MAX_REMOVED_TABLE_ROWS),
    (25, MAX_REMOVED_TABLE_ROWS),
    (10, MAX_REMOVED_TABLE_ROWS),
    (5, MAX_REMOVED_TABLE_ROWS),
    (1, MAX_REMOVED_TABLE_ROWS),
    (1, 50),
    (1, 10),
    (1, 1),
)


def render_report(info: RunInfo) -> str:
    """Render the PR body / job summary as Markdown.

    Tables are capped, and a report that would still exceed the byte budget is
    re-rendered with fewer rows rather than truncated, so it always ends with
    its closing sentence.
    """
    promotions, demotions = _prepare_changes(info)
    closing_sentence = render_closing(info.changes, database=info.database_label)
    text = _render_body(info, MAX_CHANGE_TABLE_ROWS, MAX_REMOVED_TABLE_ROWS, promotions, demotions, closing_sentence)
    for change_limit, removed_limit in _SHRINK_STEPS:
        if _utf8_len(text) <= MAX_REPORT_BYTES:
            break
        text = _render_body(info, change_limit, removed_limit, promotions, demotions, closing_sentence)
    return _safe(_fit_body(text))
