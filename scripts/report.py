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

import html
import re
import time
import unicodedata
import urllib.parse
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from playerlist import SURROGATE_RE, account_id, display_path, steam_history_url, steam_profile_url
from policy import MAX_EVIDENCE_LINK_CHARS, MAX_EVIDENCE_LINKS, Change
from sources import SOURCE_REPO_URL, redact_urls_in_text

__all__ = [
    "MAX_ATTRIBUTE_CELLS",
    "MAX_ATTRIBUTE_CHARS",
    "MAX_CHANGE_TABLE_ROWS",
    "MAX_CLOSING_STEAMIDS",
    "MAX_DATABASE_LABEL_CHARS",
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

# Limit report size below GitHub's body cap; reduce row limits before hard truncation.
MAX_CHANGE_TABLE_ROWS = 150
MAX_REMOVED_TABLE_ROWS = 300
# Bound closing-sentence SteamID lists to keep the summary readable.
MAX_CLOSING_STEAMIDS = 150
# Measure the shared report budget in UTF-8 bytes.
MAX_REPORT_BYTES = 60_000
# Cap row counts and cell lengths so large values cannot crowd out closing details.
MAX_NAME_CHARS = 80
MAX_DATABASE_LABEL_CHARS = 80
MAX_ATTRIBUTE_CHARS = 40
MAX_ATTRIBUTE_CELLS = 8

# Percent-encode characters that can break a Markdown link target.
# Escape pipes because GFM treats them as table separators.
_LINK_ESCAPES = str.maketrans(
    {
        "(": "%28",
        ")": "%29",
        " ": "%20",
        "<": "%3C",
        ">": "%3E",
        "|": "%7C",
        # Percent-encode backticks to prevent code spans in link URLs.
        "`": "%60",
        "\n": "%0A",
        "\r": "%0D",
    }
)

# Use one text-escaping policy for table cells and running text.
_ESCAPES = {
    # Escape entity introducers so HTML references cannot bypass sanitization.
    "&": "&amp;",
    # Escape backslashes so they cannot suppress Markdown escapes.
    "\\": "\\\\",
    "<": "&lt;",
    ">": "&gt;",
    # Escape brackets to prevent user-supplied links and images.
    "[": "\\[",
    "]": "\\]",
    # Escape backticks to prevent unterminated code spans.
    "`": "\\`",
    # Encode @ to prevent mention notifications.
    "@": "&#64;",
    # Escape emphasis and strikethrough markers.
    "*": "\\*",
    "_": "\\_",
    "~": "\\~",
    # Replace line breaks to prevent extra Markdown lines or table rows.
    "\n": " ",
    "\r": " ",
}

# Escape pipes because they terminate table cells.
_CELL_ESCAPES = str.maketrans(_ESCAPES | {"|": "\\|"})
_TEXT_ESCAPES = str.maketrans(_ESCAPES)

# Escape backslashes and pipes inside table code spans.
_TABLE_CODE_ESCAPES = str.maketrans({"\\": "\\\\", "|": "\\|"})


PROMOTION_HEADER = ("SteamID", "Last known name", "Before", "After", "Hackerpolice proof", "SteamHistory")
DEMOTION_HEADER = ("SteamID", "Last known name", "Before", "After", "SteamHistory")
REMOVED_HEADER = ("SteamID", "Profile Link", "SteamHistory")

# Fallback display label; callers should pass the actual snapshot path.
DEFAULT_SNAPSHOT_LABEL = "snapshot/playerlist.vorobey-hackerpolice.json"


# Neutralize controls and line separators before displaying untrusted text.
_TEXT_CONTROLS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")

# Replace bidi controls so displayed text cannot reorder adjacent content.
_BIDI_CONTROLS = re.compile(r"[\u200e\u200f\u202a-\u202e\u2066-\u2069]")

# Replace invisible format characters, preserving ZWNJ/ZWJ; encode URL joiners.
_MEANINGFUL_JOINERS = frozenset(("\u200c", "\u200d"))


def _neutralize(value: str) -> str:
    """Make a value safe to put in front of a human or a terminal."""
    value = redact_urls_in_text(value)
    value = _TEXT_CONTROLS.sub(" ", value)
    value = _BIDI_CONTROLS.sub("\ufffd", value)
    return "".join(
        "\ufffd" if unicodedata.category(char) == "Cf" and char not in _MEANINGFUL_JOINERS else char for char in value
    )


def _safe(text: str) -> str:
    """Replace lone surrogates so the report is always UTF-8 encodable."""
    return SURROGATE_RE.sub("\ufffd", text)


def _safe_display_path(path: Path) -> str:
    """A path for the report: redaction and clipping live in one shared helper."""
    return display_path(path)


def _shorten(value: str, limit: int) -> str:
    """Cut ``value`` to ``limit`` characters, marking the cut with an ellipsis.

    Truncation happens BEFORE escaping (a cut through an escape sequence would
    otherwise leave a half-written entity), and only ever applies to values far
    longer than the format allows.
    """
    return value if len(value) <= limit else value[:limit].rstrip() + "…"


def _cell(value: str) -> str:
    """Make a string safe inside a Markdown table cell."""
    return _data_text(value, in_table=True).strip() or "-"


def _text(value: str, *, allow_autolinks: bool = False) -> str:
    """Make a value safe as running text, with autolinks opt-in for the fetch URL.

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
    other. Autolinks are disabled for data (database labels and demotion notes)
    by default; only the explicitly selected fetch URL is allowed to remain a
    clickable URI.
    """
    if allow_autolinks:
        return _neutralize(value).translate(_TEXT_ESCAPES)
    return _data_text(value, in_table=False)


def _code(value: str, *, in_table: bool = False) -> str:
    r"""Make a string safe inside an inline code span (``…``).

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
    text = _neutralize(value)
    if in_table:
        text = text.translate(_TABLE_CODE_ESCAPES)
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    if text.startswith("`") or text.endswith("`"):
        # Pad boundary backticks so CommonMark does not merge them with the fence.
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
    name = _shorten(change.name, MAX_NAME_CHARS)
    label = "UNKNOWN" if not name.strip() else _cell(name)
    url = steam_profile_url(change.steamid)
    if url is None:
        return label
    return _markdown_link(url, label)


# Fence URI-like text and bare www. values to prevent GitHub auto-linking.
# Require text after ':' so prose such as 'Reason: ' remains plain text.
_AUTOLINK_IN_TEXT = re.compile(r"(?:[a-z][a-z0-9+.-]*:[^\s]+|www\.[^\s]+)", re.IGNORECASE | re.ASCII)
_SECOND_HTTP_URL = re.compile(r"\s+https?://", re.IGNORECASE)
_MALFORMED_PERCENT_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")


def _data_text(value: str, *, in_table: bool) -> str:
    """Escape untrusted Markdown text and fence URI literals against autolinking.

    GitHub auto-links URI schemes and bare ``www.`` text even when ordinary
    Markdown punctuation is escaped. Fence those substrings as code rather than
    weakening the visible text: a database label or player name can contain a
    URL without becoming a link of its own. The intentional fetch URL uses
    ``_text(..., allow_autolinks=True)`` instead.
    """
    escaped = _CELL_ESCAPES if in_table else _TEXT_ESCAPES
    value = _neutralize(value)
    parts: list[str] = []
    position = 0
    for match in _AUTOLINK_IN_TEXT.finditer(value):
        parts.append(value[position : match.start()].translate(escaped))
        parts.append(_code(match.group(), in_table=in_table))
        position = match.end()
    parts.append(value[position:].translate(escaped))
    return "".join(parts)


def _is_url(text: str) -> bool:
    """True only for an unambiguous absolute HTTP(S) URL.

    ``urlsplit`` is intentionally permissive: it accepts ``https:relative``,
    empty authorities and invalid ports. Markdown/browser URL parsers also
    disagree about backslashes and whitespace in authorities. Reject those
    ambiguous forms rather than making untrusted evidence clickable. Spaces
    in a path remain supported and are percent-encoded by ``_markdown_link``.
    """
    if (
        not text
        or text != text.strip()
        or "\\" in text
        or html.unescape(text) != text
        or any(char in text for char in "\r\n\t")
    ):
        return False
    if any(char.isspace() and char != " " for char in text):
        return False
    if _SECOND_HTTP_URL.search(text) or _MALFORMED_PERCENT_ESCAPE.search(text):
        return False
    try:
        parts = urllib.parse.urlsplit(text)
        hostname = parts.hostname
        # Access .port to trigger urlsplit's deferred port validation.
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
    encoded = "".join(
        "".join(f"%{byte:02X}" for byte in char.encode("utf-8"))
        if unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"}
        else char
        for char in encoded
    )
    return f"[{label}]({encoded})"


# YouTube hosts that serve video pages, and the path forms carrying the video id.
_YOUTUBE_HOSTS = frozenset(
    {"youtube.com", "www.youtube.com", "m.youtube.com", "youtube-nocookie.com", "www.youtube-nocookie.com"}
)
# ``/shorts/<id>``, ``/embed/<id>``, ``/live/<id>`` and the legacy ``/v/<id>``.
_YOUTUBE_ID_PATH = re.compile(r"^/(?:shorts|embed|live|v)/(?P<id>[A-Za-z0-9_-]+)$", re.ASCII)
# The already-short host. Its query is filtered like any other, so a share tag
# cannot survive just because the citation happened to use the short spelling.
_YOUTUBE_SHORT = re.compile(r"^https?://youtu\.be/(?P<id>[A-Za-z0-9_-]+)(?:\?(?P<query>[^#]*))?(?:#.*)?$", re.ASCII)
_VIDEO_ID = re.compile(r"^[A-Za-z0-9_-]+$", re.ASCII)
# Query keys that name a position in the video, and the forms YouTube accepts
# for one: bare seconds ("42"), any of the hour/minute/second units in that
# order ("42s", "5m", "2h", "1h30m", "1m30s", "1h2m3s"), and a trailing count
# with the "s" left off ("1h30"). At least one digit is required, so an empty
# or unit-only value is not a timestamp; the colon form ("1:30") is not one
# either, because YouTube does not accept it. Anything else is dropped rather
# than pasted into the link.
_YOUTUBE_TIMESTAMP_KEYS = frozenset({"t", "start"})
_YOUTUBE_TIME = re.compile(r"^(?=\d)(?:\d+h)?(?:\d+m)?(?:\d+s?)?$", re.ASCII)


def _youtube_short_url(link: str) -> str | None:
    """The ``youtu.be`` spelling of a YouTube video link, or ``None``.

    YouTube's own short domain is how a video is normally shared, and this is a
    PURE TEXT REWRITE: no request is made and no third-party shortener is
    involved, so the report stays offline, verifiable and free of extra
    secrets. Only the exact YouTube hosts are rewritten -- a lookalike such as
    ``youtube.com.evil.invalid`` is not a YouTube link and keeps its label.

    ONE rule for every YouTube spelling, short or long: the result is
    ``youtu.be/<id>`` plus a timestamp if -- and only if -- the input carried a
    real one (``t`` or ``start`` on the way in, any form YouTube accepts,
    always written back as ``t``). Every other query
    parameter is dropped, including the ``si=`` share tag, so
    ``youtu.be/ID?si=abc`` and ``youtube.com/watch?v=ID&si=abc`` both become
    ``youtu.be/ID`` while ``youtu.be/ID?si=abc&t=326`` becomes
    ``youtu.be/ID?t=326``. A timestamp is a position in the video that a proof
    usually relies on, so it survives; a share tag identifies nothing and is
    noise. No timestamp is ever invented. A link without exactly one usable id
    is left alone rather than guessed at.
    """
    pairs: list[tuple[str, str]]
    video_id: str | None = None
    short = _YOUTUBE_SHORT.match(link)
    if short is not None:
        video_id = short.group("id")
        pairs = urllib.parse.parse_qsl(short.group("query") or "", keep_blank_values=True)
    else:
        if not link.startswith(("https://", "http://")):
            return None
        try:
            parts = urllib.parse.urlsplit(link)
        except ValueError:
            return None
        if parts.netloc.lower() not in _YOUTUBE_HOSTS:
            return None
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if parts.path == "/watch":
            ids = [value for key, value in pairs if key == "v"]
            if len(ids) == 1:
                video_id = ids[0]
        else:
            by_path = _YOUTUBE_ID_PATH.match(parts.path)
            if by_path is not None:
                video_id = by_path.group("id")
    if video_id is None or not _VIDEO_ID.match(video_id):
        return None
    # Keep the FIRST real timestamp and drop everything else, including any
    # later one: two positions cannot both be the moment a proof means, and
    # repeating the key would only make the reader guess which one counts.
    #
    # Always write it back as "t", whichever key it arrived under. The result
    # is a youtu.be link, and "t" is the parameter that domain reads; "start"
    # belongs to the embed player, so copying that spelling onto a short link
    # would hand the reviewer a link that silently opens at 0:00. Rewriting
    # the key is safe in the other direction too, because "t" is understood
    # everywhere this function can emit.
    moment = next(
        (value for key, value in pairs if key in _YOUTUBE_TIMESTAMP_KEYS and _YOUTUBE_TIME.match(value)), None
    )
    timestamp = "?" + urllib.parse.urlencode([("t", moment)]) if moment is not None else ""
    return f"https://youtu.be/{video_id}{timestamp}"


def _evidence_link_status(link: str) -> tuple[str, bool]:
    """Return safe display text and whether the value is a rendered link.

    Both answers come from the same pass, so a caller never has to re-redact a
    link just to learn whether it may be clicked.
    """
    safe_link = redact_urls_in_text(link)
    clickable = len(link) <= MAX_EVIDENCE_LINK_CHARS and safe_link == link and _is_url(link)
    return safe_link, clickable


# Per-run memo for ``_evidence_link_status``.
#
# Why it is worth a module global: a report is rendered up to ten times while it
# shrinks to fit, and each render redacts every proof link shown plus every proof
# link counted for the closing note. Redaction is the most expensive work in the
# renderer (it parses and re-encodes URLs, decodes entities and walks nested
# layers), and it is a pure function of the link text -- so the same handful of
# links was being redacted over a hundred times. The cache is cleared by
# ``render_report``; a caller that uses the renderers directly still gets correct
# output, it just does not benefit from the memo.
_EVIDENCE_STATUS_CACHE: dict[str, tuple[str, bool]] = {}
# Bounds the memo: a hostile list cannot grow it without limit during one report.
_MAX_EVIDENCE_STATUS_CACHE = 20_000


def _evidence_link_status_cached(link: str) -> tuple[str, bool]:
    """``_evidence_link_status`` with a bounded per-run memo."""
    cached = _EVIDENCE_STATUS_CACHE.get(link)
    if cached is not None:
        return cached
    status = _evidence_link_status(link)
    if len(_EVIDENCE_STATUS_CACHE) < _MAX_EVIDENCE_STATUS_CACHE:
        _EVIDENCE_STATUS_CACHE[link] = status
    return status


def _evidence_cell(links: Sequence[str], omitted: int = 0) -> str:
    """Proof column: real links where possible, escaped text otherwise.

    Each link is labeled "proof" (or "proof 1", "proof 2" when there are
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
        safe_link, clickable = _evidence_link_status_cached(link)
        if clickable:
            # One uniform label scheme: "proof" for a lone link, "proof N" when
            # there are several. A single label shape for every target is what
            # lets a reader tell the entries apart in a mixed row: naming each
            # target instead ("YouTube", "Discord") would make the same row read
            # differently per host for no gain, since both are one click away.
            label = "proof" if single else f"proof {position}"
            # A YouTube target is shortened to YouTube's own domain, a faithful
            # alias of the same video, so the Markdown stays short. The label is
            # already uniform, so this only shortens the target, not the name.
            target = _youtube_short_url(link) or link
            rendered.append(_markdown_link(target, label))
        else:
            preview = _shorten(safe_link, MAX_EVIDENCE_LINK_CHARS)
            if safe_link != link or _AUTOLINK_IN_TEXT.search(link):
                rendered.append(_code(preview, in_table=True))
            else:
                rendered.append(_cell(preview))
    cell = ", ".join(rendered)
    hidden = max(0, len(links) - len(shown)) + max(0, omitted)
    if hidden:
        # Keep the overflow note plain; it counts evidence links not shown.
        cell += f", and {_count(hidden)} more evidence {plural(hidden, 'entry', 'entries')}"
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
        lines.pop()
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
    # Use the same numeric SteamID order as the tables above.
    changed_steamids = _sorted_steamids(
        [change.steamid for change in changes if (change.kind == "promote") or change.after]
    )
    removed_steamids = _sorted_steamids(
        [change.steamid for change in changes if (change.kind == "demote") and not change.after]
    )

    def clause(head: str, target: str, steamids: list[str]) -> str:
        if database is None:
            # Capitalize standalone clauses only.
            head = head[:1].upper() + head[1:]
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
        # Avoid an empty clause when there are no changes.
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
    source_total: int  # Raw entries, including duplicates.
    source_skipped: int  # Rows without usable SteamIDs.
    dry_run: bool
    changes: tuple[Change, ...] = ()
    # Snapshot provenance and reasons a requested demotion was skipped.
    previous_source_total: int | None = None  # Raw entries in the previous snapshot.
    # Distinct usable IDs either side of the diff. The snapshot-diff arrow counts
    # these, not the raw entry totals, so its subtraction always matches the net.
    source_ids: int = 0
    previous_source_ids: int = 0
    added_to_source: int = 0  # Distinct usable IDs added upstream.
    removed_from_source: int = 0  # Distinct usable IDs removed upstream.
    # IDs missing upstream since the previous snapshot, even when demotion is skipped.
    removed_upstream: tuple[str, ...] = ()
    demotion_note: str | None = None
    # Explain why the snapshot was not refreshed.
    snapshot_note: str | None = None
    # Include snapshot-only changes in the report status.
    snapshot_changed: bool = False
    # Distinguish file-only normalization from no database changes.
    database_changed: bool = False
    # Report the snapshot path actually used.
    snapshot_path: Path | None = None

    @property
    def database_label(self) -> str:
        """Friendly name of the database, derived from its file name.

        ``playerlist.garou3299.json`` becomes ``Garou3299``: the owner part of
        the usual ``playerlist.<owner>.json`` shape, capitalized. Any other
        file name is used as it is (``mylist.json`` becomes ``Mylist``), so
        the headline always names the file the run actually writes and no
        repository name is hardcoded here.
        """
        stem = self.database_path.stem
        head, _, owner = stem.partition(".")
        name = owner if head == "playerlist" and owner else stem
        name = _shorten(name, MAX_DATABASE_LABEL_CHARS)
        return name[:1].upper() + name[1:]


def _net_change_text(added: int, removed: int) -> str:
    """Describe the net change in distinct SteamIDs.

    The totals printed beside this count distinct usable SteamIDs on both sides,
    so the subtraction a reader performs always matches this net: for sets,
    ``len(current) - len(previous)`` is exactly ``added - removed``.
    """
    delta = added - removed
    if delta == 0:
        return "no net change"
    # Agree with the singular/plural of the counts beside it: "net +1 distinct SteamID".
    return f"net {delta:+,d} distinct {plural(abs(delta), 'SteamID', 'SteamIDs')}"


def _header_lines(info: RunInfo) -> list[str]:
    """The ``- Key: value`` bullet block at the top of the report."""
    source_note = f"{_count(info.source_total)} {plural(info.source_total, 'entry', 'entries')}"
    if info.source_skipped:
        source_note += f", {_count(info.source_skipped)} unusable"
    source = redact_urls_in_text(info.source)
    source_display = _text(source, allow_autolinks=True) if _is_url(source) else _code(source)

    lines = [
        "## Vorobey hackerpolice sync",
        "",
        f"- Database: {_code(_safe_display_path(info.database_path))}",
        f"- Vorobey hackerpolice list ({source_note}): {SOURCE_REPO_URL}",
        f"- Fetched from: {source_display}",
        f"- Run at: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}",
    ]
    if info.dry_run:
        lines.append("- Mode: **dry run** (no database or snapshot written)")
    if info.previous_source_total is not None:
        # The entry total below is raw rows (duplicates included) and is
        # provenance only: a duplicated upstream row stays visible there.
        # Everything in the diff line after it -- added, removed, BOTH sides
        # of the arrow, and the net -- counts distinct usable SteamIDs, so the
        # subtraction a reader performs on the arrow always matches the net.
        lines.append(
            f"- Previous snapshot: {_count(info.previous_source_total)} "
            f"{plural(info.previous_source_total, 'entry', 'entries')}; "
            f"{_count(info.removed_from_source)} {plural(info.removed_from_source, 'SteamID', 'SteamIDs')} "
            "removed upstream since then (only those are demotion candidates)"
        )
        lines.append(
            f"- Snapshot diff: **{_count(info.added_to_source)} new "
            f"{plural(info.added_to_source, 'SteamID', 'SteamIDs')} added**, "
            f"**{_count(info.removed_from_source)} {plural(info.removed_from_source, 'SteamID', 'SteamIDs')} removed** "
            f"({_count(info.previous_source_ids)} → {_count(info.source_ids)} "
            f"{plural(info.source_ids, 'SteamID', 'SteamIDs')}; "
            f"{_net_change_text(info.added_to_source, info.removed_from_source)})"
        )
    elif info.snapshot_changed:
        # With no baseline, every usable ID is new.
        lines.append(
            f"- Snapshot diff: **{_count(info.added_to_source)} new "
            f"{plural(info.added_to_source, 'SteamID', 'SteamIDs')} added**, "
            "**0 SteamIDs removed** (no previous snapshot; initial snapshot)"
        )
    if info.demotion_note:
        # Escape data-derived paths included in the demotion note.
        lines.append(f"- Demotion: **{_text(info.demotion_note)}**")
    if info.snapshot_note:
        # Snapshot notes contain code-authored Markdown; preserve their formatting.
        #
        # Deliberately NOT escaped through _text() the way the demotion note above
        # is, and that asymmetry is intentional: a demotion note interpolates a
        # filesystem path (data), while every snapshot note is assembled from fixed
        # wording plus integers in _plan_demotion -- it never carries upstream text,
        # so there is nothing here to neutralize. Escaping it would publish a
        # literal "\*\*not refreshed\*\*" and "\`--demote\`" instead of bold text
        # and a code span. If a snapshot note ever starts embedding a value that
        # came from the network, escape that value at the point it is built.
        lines.append(f"- Snapshot: {info.snapshot_note}")
    elif info.snapshot_changed:
        verb = "would be updated" if info.dry_run else "updated"
        snapshot_label = (
            _safe_display_path(info.snapshot_path) if info.snapshot_path is not None else DEFAULT_SNAPSHOT_LABEL
        )
        label = _code(snapshot_label)
        lines.append(f"- Snapshot: {label} {verb} to an exact copy of the current upstream file")
    lines.append("")
    return lines


def _promotion_row(change: Change) -> str:
    """Render one promotion row, escaping every untrusted value it carries."""
    return _row(
        (
            _steamid_cell(change.steamid),
            _name_cell(change),
            _attributes_cell(change.before),
            _attributes_cell(change.after),
            _evidence_cell(change.evidence, change.evidence_omitted),
            _steam_history_cell(change.steamid),
        )
    )


def _demotion_row(change: Change) -> str:
    """Render one demotion row; ``after`` is empty when the entry is removed."""
    return _row(
        (
            _steamid_cell(change.steamid),
            _name_cell(change),
            _attributes_cell(change.before),
            _attributes_cell(change.after) or "entry removed",
            _steam_history_cell(change.steamid),
        )
    )


def _promotion_lines(promotions: Sequence[Change], limit: int = MAX_CHANGE_TABLE_ROWS, *, database: str) -> list[str]:
    """Render the "promoted to cheater" table block.

    ``database`` is escaped here: it is derived from a file name, which is
    data like any other -- a database called ``<b>x.json`` must not open a tag
    in the report.
    """
    count = len(promotions)
    rows = [_promotion_row(change) for change in promotions[:limit]]
    overflow = _overflow_note(count, limit, "entry", "entries")
    entries = plural(count, "entry", "entries")
    headline = f"**{_count(count)} {entries} promoted to `cheater` in the {_text(database)} database:**"
    return [headline, "", *_table(PROMOTION_HEADER, rows, overflow), ""]


def _demotion_lines(demotions: Sequence[Change], limit: int = MAX_CHANGE_TABLE_ROWS, *, database: str) -> list[str]:
    """Render the "demoted" table block."""
    count = len(demotions)
    rows = [_demotion_row(change) for change in demotions[:limit]]
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
    if limit <= 0:
        return ""
    return text.encode("utf-8", "surrogatepass")[:limit].decode("utf-8", "ignore")


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
            # Describe file-only normalization accurately instead of claiming no changes.
            verb = "would be normalized" if info.dry_run else "was normalized"
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

    # Place the removed-ID table before the closing summary and proof note.
    lines = _with_removed_table(lines, info.removed_upstream, removed_limit)

    if closing_sentence is None:
        closing_sentence = render_closing(info.changes, database=info.database_label)

    while lines and not lines[-1].strip():
        lines.pop()
    lines += ["", closing_sentence]

    # Count visible rows only; do not reference evidence omitted from the table.
    total_links = sum(
        _evidence_link_status_cached(link)[1]
        for change in promotions[:change_limit]
        for link in change.evidence[:MAX_EVIDENCE_LINKS]
    )
    if total_links:
        # Keep attribution as the report's final content line.
        note = (
            "Proof link comes from the Vorobey hackerpolice list and is shown for review only."
            if total_links == 1
            else "Proof links come from the Vorobey hackerpolice list and are shown for review only."
        )
        lines.append(note)
    lines.append("")
    return "\n".join(lines)


# Row caps tried in order when the body is over budget.
#
# The removed-ID list gives ground first, but only down to _REMOVED_TABLE_FLOOR.
# A long list of bare SteamIDs is the cheapest thing to shorten -- every row
# costs the same and says the same kind of thing -- whereas the change table is
# the review record of what happened to THIS database, so it is kept whole for
# as long as possible. Once the removed list is down to its floor, change rows
# shrink, and only then does the removed list give up the rest; the last resort
# (``_fit_body``) cuts text the tables could not give up.
#
# Shrinking the change table first would be the wrong trade: it would answer "we
# removed 300 IDs upstream" in full while hiding which of your own entries were
# deleted for it.
#
# The removed-list rungs descend in even steps rather than halving. Coarse rungs
# make a SMALLER cap print MORE names: with a 200 -> 100 jump, a run of 200
# removals and 150 changes overflows at 200 rows and lands on 100, while a cap of
# 150 renders all 150 first time. Even steps keep a larger cap from ever losing
# to a smaller one.
_REMOVED_TABLE_FLOOR = 100
_SHRINK_STEPS: tuple[tuple[int, int], ...] = (
    (MAX_CHANGE_TABLE_ROWS, 250),
    (MAX_CHANGE_TABLE_ROWS, 200),
    (MAX_CHANGE_TABLE_ROWS, 150),
    (MAX_CHANGE_TABLE_ROWS, _REMOVED_TABLE_FLOOR),
    (100, _REMOVED_TABLE_FLOOR),
    (50, _REMOVED_TABLE_FLOOR),
    (25, _REMOVED_TABLE_FLOOR),
    (10, _REMOVED_TABLE_FLOOR),
    (5, _REMOVED_TABLE_FLOOR),
    (1, _REMOVED_TABLE_FLOOR),
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
    try:
        text = _render_body(
            info, MAX_CHANGE_TABLE_ROWS, MAX_REMOVED_TABLE_ROWS, promotions, demotions, closing_sentence
        )
        for change_limit, removed_limit in _SHRINK_STEPS:
            if _utf8_len(text) <= MAX_REPORT_BYTES:
                break
            text = _render_body(info, change_limit, removed_limit, promotions, demotions, closing_sentence)
    finally:
        # The memo only has to live as long as this report; dropping it here keeps a
        # long-lived caller (or the test suite) from holding onto proof text. In a
        # ``finally`` because a render that does not finish is exactly when that
        # matters: Ctrl-C between the two renders above used to leave every proof
        # link of a half-built report sitting in a module global.
        _EVIDENCE_STATUS_CACHE.clear()
    return _safe(_fit_body(text))
