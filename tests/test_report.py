#!/usr/bin/env python3
"""Tests for the Vorobey hackerpolice sync tool."""

from __future__ import annotations

import re
import string
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _support import (
    HACKERPOLICE_PROOF,
    player,
)

import playerlist as playerlist_module
import report as report_module
import sources
from playerlist import (
    MAX_SHOWN_PATH_CHARS,
    MAX_SHOWN_VALUE_CHARS,
    PlayerListError,
    display_path,
    load,
)
from policy import Change, demote
from report import (
    MAX_ATTRIBUTE_CELLS,
    MAX_ATTRIBUTE_CHARS,
    MAX_CHANGE_TABLE_ROWS,
    MAX_EVIDENCE_LINK_CHARS,
    MAX_EVIDENCE_LINKS,
    MAX_REMOVED_TABLE_ROWS,
    MAX_REPORT_BYTES,
    RunInfo,
    _demotion_lines,
    _promotion_lines,
    _shorten,
    plural,
    render_closing,
    render_report,
)
from sources import (
    SyncError,
)

_UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")


class PluralTests(unittest.TestCase):
    def test_only_one_is_singular(self):
        self.assertEqual(plural(1, "entry", "entries"), "entry")
        self.assertEqual(plural(2, "entry", "entries"), "entries")
        self.assertEqual(plural(0, "entry", "entries"), "entries")


def _code_span_ranges(text):
    """(start, end) of every Markdown code span, delimited by a run of exactly N.

    A proper scan (not a regex): a two-backtick fence may contain single
    backticks, which is exactly what a naive non-greedy pattern gets wrong.
    """
    ranges = []
    position = 0
    while position < len(text):
        if text[position] != "`":
            position += 1
            continue
        start = position
        while position < len(text) and text[position] == "`":
            position += 1
        fence = position - start
        search_from = position
        while True:
            match = re.compile(r"`+").search(text, search_from)
            if match is None or len(match.group()) == fence:
                break
            search_from = match.end()
        if match is None:
            continue
        ranges.append((start, match.end()))
        position = match.end()
    return ranges


class ReportTests(unittest.TestCase):
    def info(self, changes=(), *, source="https://example.invalid/list.json", **kwargs):
        values = {
            "source_total": 10,
            "source_skipped": 0,
            "dry_run": False,
            "changes": tuple(changes),
            **kwargs,
        }
        return RunInfo(database_path=Path("playerlist.garou3299.json"), source=source, **values)

    def test_ansi_escapes_cannot_repaint_the_job_log(self):
        """The workflow `cat`s this report into the job log: ESC must not survive."""
        change = Change("[U:1:100]", "\x1b[31mRED\x1b[0m", ("suspicious",), ("cheater",))
        report = render_report(self.info([change]))
        self.assertNotIn("\x1b", report)
        self.assertIn("RED", report)  # The name remains readable.

    def test_a_directory_name_cannot_forge_a_link_in_the_demotion_note(self):
        """The demotion note embeds the snapshot PATH -- data, not code.

        A directory called "a[x](https://evil.example)" used to render as a live,
        clickable link inside the bot's own pull request: the escaping applied to
        the tables never reached the header notes, which are built in another
        module and carry a path.
        """
        note = "skipped - no snapshot at /tmp/a[x](https://evil.example)/s.json yet"
        report = render_report(self.info(demotion_note=note))
        line = next(line for line in report.splitlines() if line.startswith("- Demotion:"))
        self.assertIn("\\[x\\]", line)  # Escaped text renders literally.
        self.assertNotIn("[x](https://evil.example)", line)  # It must not become a link.

    def test_the_snapshot_note_keeps_its_own_markdown(self):
        """Unlike the demotion note, this one is authored in code.

        It says "**not refreshed**" and names `--demote` in a code span; those
        markers must render, so the note must NOT be escaped as data.
        """
        note = "**not refreshed** - demotion is disabled (`--demote`) so removals stay candidates"
        report = render_report(self.info(snapshot_note=note))
        line = next(line for line in report.splitlines() if line.startswith("- Snapshot: **"))
        self.assertIn("**not refreshed**", line)
        self.assertIn("`--demote`", line)

    def test_bidi_overrides_cannot_reverse_the_rest_of_the_line(self):
        """U+202E would display "abcDEF" as "abcFED" and flip the next column."""
        change = Change("[U:1:100]", "abc\u202eDEF", ("suspicious",), ("cheater",))
        report = render_report(self.info([change]))
        for character in ("\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"):
            self.assertNotIn(character, report)
        self.assertIn("\ufffd", report)

    def test_invisible_format_characters_cannot_make_two_names_look_alike(self):
        """A zero-width space, a word joiner or a tag character hides itself.

        Two different names would then render identically in the review table,
        and Unicode tag characters are a known way to hide text outright. Only
        the bidi set was neutralized, so these sailed into the pull request body.
        """
        for character in (
            "\u200b",  # Zero-width space.
            "\u2060",  # Word joiner.
            "\ufeff",  # Zero-width no-break space / BOM.
            "\u00ad",  # Soft hyphen.
            "\u061c",  # Arabic letter mark.
            "\u180e",  # Mongolian vowel separator.
            "\u206a",  # Deprecated invisible format control.
            "\u070f",  # Syriac abbreviation mark.
            "\U000e0041",  # Unicode tag character.
            "\ufff9",  # Interlinear annotation anchor.
        ):
            with self.subTest(character=f"U+{ord(character):04X}"):
                change = Change("[U:1:100]", f"Pla{character}yer", ("suspicious",), ("cheater",))
                report = render_report(self.info([change]))
                self.assertNotIn(character, report)
                self.assertIn("\ufffd", report)

    def test_joiners_that_carry_meaning_are_kept(self):
        """ZWNJ and ZWJ are invisible but real: Persian/Indic text, emoji family."""
        change = Change("[U:1:100]", "می\u200cخواهم", ("suspicious",), ("cheater",))
        report = render_report(self.info([change]))
        self.assertIn("\u200c", report)
        self.assertNotIn("\ufffd", report)

    def test_bell_and_backspace_cannot_hide_what_was_written(self):
        change = Change("[U:1:100]", "good\x07\x08BAD", ("suspicious",), ("cheater",))
        report = render_report(self.info([change]))
        self.assertNotIn("\x07", report)
        self.assertNotIn("\x08", report)

    def test_c1_controls_in_names_are_neutralized(self):
        """U+009B is the 8-bit CSI control, not a printable name character."""
        change = Change("[U:1:100]", "Good\u009b31mBAD", ("suspicious",), ("cheater",))
        report = render_report(self.info([change]))
        self.assertNotIn("\u009b", report)
        self.assertIn("Good 31mBAD", report)

    def test_legitimate_unicode_is_left_alone(self):
        """Hardening must not mangle real names: Cyrillic, emoji, ZWJ sequences."""
        names = ["Игрок", "名前", "\U0001f468\u200d\U0001f469\u200d\U0001f467", "Ünïcode"]
        changes = [Change(f"[U:1:{200 + n}]", name, ("suspicious",), ("cheater",)) for n, name in enumerate(names)]
        report = render_report(self.info(changes))
        for name in names:
            self.assertIn(name, report)
            self.assertNotIn("\ufffd", name)

    def test_control_and_bidi_characters_in_a_proof_link_are_percent_encoded(self):
        change = Change(
            "[U:1:100]",
            "p",
            ("suspicious",),
            ("cheater",),
            evidence=(
                "https://example.invalid/\x1b[31mx",
                "https://example.invalid/a\u202eb",
                "https://example.invalid/csi\u009b31m",
            ),
        )
        report = render_report(self.info([change]))
        self.assertNotIn("\x1b", report)
        self.assertNotIn("\u202e", report)
        self.assertNotIn("\u009b", report)
        self.assertIn("%1B", report)  # ESC control.
        self.assertIn("%E2%80%AE", report)  # U+202E encoded as UTF-8.
        self.assertIn("%C2%9B", report)  # U+009B encoded as UTF-8.

    def test_attributes_cannot_carry_control_characters_into_the_report(self):
        change = Change("[U:1:100]", "p", ("suspicious\x1b",), ("cheater",))
        report = render_report(self.info([change]))
        self.assertNotIn("\x1b", report)

    def test_an_enormous_proof_link_cannot_collapse_the_report(self):
        """Regression: ten 6,000-character links used to hard-truncate the body.

        The body collapsed to 494 bytes -- header, table header and "report
        truncated" -- losing the closing sentence and the removed-SteamID table
        the report exists to publish.
        """
        long_url = "https://example.invalid/" + "a" * 6000
        change = Change("[U:1:100]", "n", ("suspicious",), ("cheater",), evidence=tuple([long_url] * 10))
        report = render_report(self.info([change], removed_upstream=("[U:1:300]",)))
        self.assertNotIn("report truncated", report)
        self.assertIn("nothing else is modified.", report)
        self.assertIn("| SteamID | Profile Link | SteamHistory |", report)
        self.assertLessEqual(len(report.encode()), MAX_REPORT_BYTES)

    def test_an_enormous_attribute_list_cannot_collapse_the_report(self):
        """Same regression through the database side of the report."""
        attributes = tuple(f"attr{position}-" + "z" * 5900 for position in range(20))
        report = render_report(
            self.info([Change("[U:1:100]", "n", attributes, ("cheater",))], removed_upstream=("[U:1:300]",))
        )
        self.assertNotIn("report truncated", report)
        self.assertIn("nothing else is modified.", report)

    def test_a_proof_link_too_long_to_show_is_text_not_a_broken_link(self):
        """A cut link would look clickable and go somewhere else."""
        long_url = "https://example.invalid/" + "a" * 6000
        report = render_report(
            self.info([Change("[U:1:100]", "n", ("suspicious",), ("cheater",), evidence=(long_url,))])
        )
        self.assertIn("text omitted: too long to inspect safely", report)
        self.assertNotIn(f"]({long_url})", report)
        self.assertNotIn("Proof link comes from", report)
        self.assertNotIn("a" * (MAX_EVIDENCE_LINK_CHARS + 10), report)

    def test_an_attribute_list_is_capped_and_counts_what_it_hides(self):
        hidden = 3
        attributes = tuple(f"attribute{position}" for position in range(MAX_ATTRIBUTE_CELLS + hidden))
        report = render_report(self.info([Change("[U:1:100]", "n", attributes, ("cheater",))]))
        self.assertIn(f"and {hidden} more", report)

    def test_an_absurdly_long_attribute_is_shortened(self):
        report = render_report(self.info([Change("[U:1:100]", "n", ("x" * 5000,), ("cheater",))]))
        self.assertIn("…", report)
        self.assertNotIn("x" * (MAX_ATTRIBUTE_CHARS + 10), report)

    def test_no_changes_message(self):
        report = render_report(self.info())
        self.assertIn("**No changes.**", report)
        self.assertIn("10 entries", report)
        self.assertNotIn("| SteamID |", report)

    def test_report_links_the_human_friendly_blob_page_and_names_the_fetch_source(self):
        report = render_report(self.info())
        # Link to the human-readable GitHub blob page, not a raw/API URL.
        self.assertIn(
            "Vorobey hackerpolice list (10 entries): "
            "https://github.com/Nocrex/Tom/blob/main/playerlist.vorobey-hackerpolice.json",
            report,
        )
        # Keep the actual fetch URL visible for troubleshooting.
        self.assertIn("- Fetched from: https://example.invalid/list.json", report)

    def test_the_fetch_line_never_publishes_a_credential(self):
        """The same line is the public pull request body's fetch record."""
        report = render_report(
            self.info(source="https://user:secret@example.invalid/list.json?token=ghp_SECRET&ref=main")
        )
        # Escape '&' and '_' so URL data cannot introduce Markdown formatting.
        self.assertIn("- Fetched from: https://example.invalid/list.json?token=REDACTED&amp;ref=main", report)
        self.assertNotIn("secret", report)
        self.assertNotIn("ghp_SECRET", report)

    def test_every_change_row_links_the_player_to_steamhistory(self):
        """Reviewers can open the archived profile (past names, bans) in one click."""
        promote = Change("[U:1:100]", "a", ("suspicious",), ("cheater",))
        demote = Change("[U:1:200]", "b", ("cheater",), ("racist",), kind="demote")
        report = render_report(self.info([promote, demote]))
        self.assertIn("| SteamHistory |", report)  # Header used by both tables.
        rows = [line for line in report.splitlines() if line.startswith("| `[U:1:")]
        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[0].endswith("| [SteamHistory](https://steamhistory.net/id/76561197960265828) |"))
        self.assertTrue(rows[1].endswith("| [SteamHistory](https://steamhistory.net/id/76561197960265928) |"))

    def test_steamhistory_column_is_dash_when_the_steamid_is_unusable(self):
        change = Change(steamid="nope", name="someone", before=("suspicious",), after=("cheater",))
        report = render_report(self.info([change]))
        row = next(line for line in report.splitlines() if line.startswith("| `nope`"))
        self.assertTrue(row.endswith("| - |"))
        self.assertNotIn("steamhistory.net/id/None", report)

    def test_every_row_has_exactly_as_many_cells_as_its_header(self):
        """Adding a column later cannot silently produce a ragged table."""
        promote = Change("[U:1:100]", "a|b", ("suspicious",), ("cheater",), ("https://example.invalid/x|y",))
        demote = Change("[U:1:200]", "b", ("cheater",), ("racist",), kind="demote")
        report = render_report(self.info([promote, demote], removed_upstream=("[U:1:5]",)))

        def cells(line: str) -> int:
            # An escaped pipe remains part of a cell.
            return len(_UNESCAPED_PIPE.findall(line)) - 1

        header_cells = None
        for line in report.splitlines():
            if line.startswith("| SteamID |"):
                header_cells = cells(line)
            elif line.startswith("| `["):
                self.assertEqual(cells(line), header_cells, line)

    def test_unusable_steamid_renders_name_without_a_link(self):
        changes = (Change(steamid="nope", name="someone", before=("suspicious",), after=("cheater",)),)
        report = render_report(self.info(changes))
        self.assertIn("someone", report)
        self.assertNotIn("steamcommunity.com/profiles/None", report)

    def test_unusable_source_entries_are_reported_in_the_header(self):
        report = render_report(self.info(source_skipped=7))
        self.assertIn("(10 entries, 7 unusable)", report)

    def test_change_rows_are_sorted_by_steamid(self):
        unsorted_changes = (
            Change(steamid="[U:1:900]", name="c", before=("suspicious",), after=("cheater",)),
            Change(steamid="[U:1:100]", name="a", before=("suspicious",), after=("cheater",)),
            Change(steamid="[U:1:500]", name="b", before=("suspicious",), after=("cheater",)),
        )
        report = render_report(self.info(unsorted_changes))
        rows = [line for line in report.splitlines() if line.startswith("| `[U:1:")]
        self.assertEqual(
            [row.split("`")[1] for row in rows],
            ["[U:1:100]", "[U:1:500]", "[U:1:900]"],
        )

    def test_dry_run_says_the_database_and_snapshot_are_untouched(self):
        report = render_report(self.info(dry_run=True))
        self.assertIn("**dry run** (no database or snapshot written)", report)

    def test_custom_snapshot_path_is_reported_verbatim(self):
        report = render_report(self.info(snapshot_changed=True, snapshot_path=Path("mirror/vorobey.json")))
        self.assertIn("- Snapshot: `mirror/vorobey.json` updated to an exact copy", report)
        self.assertNotIn("snapshot/playerlist.vorobey-hackerpolice.json", report)

    def test_proof_note_is_the_last_line(self):
        changes = (
            Change(
                steamid="[U:1:100]",
                name="a",
                before=("suspicious",),
                after=("cheater",),
                evidence=("https://example.invalid/p",),
            ),
        )
        report = render_report(self.info(changes))
        lines = [line for line in report.splitlines() if line.strip()]
        self.assertEqual(
            lines[-1],
            "Proof link comes from the Vorobey hackerpolice list and is shown for review only.",
        )

    def test_normalized_file_is_reported_instead_of_no_changes(self):
        """The sync always writes entries in canonical form.

        A hand-appended entry is re-sorted without any tag changing: the file
        in the pull request differs, so the body must not claim "No changes".
        """
        report = render_report(self.info(database_changed=True))
        self.assertIn("**No player changes** (the database file was normalized:", report)
        self.assertNotIn("**No changes.**", report)
        self.assertNotIn("**No database changes**", report)

        both = render_report(self.info(database_changed=True, snapshot_changed=True))
        self.assertIn("the snapshot was refreshed too", both)

        # Dry-run wording must be conditional.
        dry = render_report(self.info(database_changed=True, snapshot_changed=True, dry_run=True))
        self.assertIn("would be normalized", dry)
        self.assertIn("the snapshot would be refreshed too", dry)
        self.assertNotIn("was normalized", dry)

        # Snapshot-only runs retain their existing wording.
        snapshot_only = render_report(self.info(snapshot_changed=True))
        self.assertIn("**No database changes** (snapshot refresh only).", snapshot_only)

    def test_snapshot_diff_shows_added_removed_and_net(self):
        report = render_report(
            self.info(
                source_total=109,
                previous_source_total=100,
                source_ids=109,
                previous_source_ids=100,
                added_to_source=12,
                removed_from_source=3,
                snapshot_changed=True,
            )
        )
        self.assertIn(
            "- Snapshot diff: **12 new SteamIDs added**, **3 SteamIDs removed** (100 → 109 SteamIDs; net +9 distinct SteamIDs)",
            report,
        )

    def test_snapshot_diff_singular_and_negative_net(self):
        report = render_report(
            self.info(
                source_total=99,
                previous_source_total=100,
                source_ids=99,
                previous_source_ids=100,
                added_to_source=1,
                removed_from_source=2,
            )
        )
        self.assertIn(
            "**1 new SteamID added**, **2 SteamIDs removed** (100 → 99 SteamIDs; net -1 distinct SteamID)", report
        )

    def test_the_net_change_agrees_with_the_distinct_ids_beside_it(self):
        """The diff arrow counts distinct SteamIDs, so its subtraction holds.

        Raw row totals stay in the provenance lines. Printing them inside the
        diff made the line contradict itself whenever a row was a duplicate or
        unusable: "1 added, 1 removed" beside "3 -> 2 entries" reads as net -1.
        """
        report = render_report(
            self.info(
                source_total=2,
                previous_source_total=3,
                source_ids=2,
                previous_source_ids=2,
                added_to_source=1,
                removed_from_source=1,
            )
        )
        self.assertIn("**1 new SteamID added**, **1 SteamID removed**", report)
        self.assertIn("(2 → 2 SteamIDs; no net change)", report)
        # The raw row total is still reported, just not inside the subtraction.
        self.assertIn("- Previous snapshot: 3 entries", report)

    def test_a_net_of_one_reads_as_a_singular_steamid(self):
        """The net agrees with the singular/plural of the counts beside it."""
        report = render_report(
            self.info(
                source_total=101,
                previous_source_total=100,
                source_ids=101,
                previous_source_ids=100,
                added_to_source=1,
                removed_from_source=0,
            )
        )
        self.assertIn("(100 → 101 SteamIDs; net +1 distinct SteamID)", report)
        self.assertNotIn("net +1 distinct SteamIDs", report)

    def test_every_count_in_the_header_agrees_with_its_own_noun(self):
        """Randomized invariant testing found four counts bolted to a fixed noun.

        Each one is a number the upstream file decides, so each one can be 1 on
        a real day: a list that still holds a single row, a baseline captured
        when it did, a list that collapsed to one usable SteamID, and a row
        whose evidence overflowed by exactly one. All four published "1 ...s"
        in the pull request body. They are checked together because they are
        one defect in four places, and a test per site would have let the next
        site be added without one.
        """
        singular = render_report(
            self.info(
                source_total=1,
                previous_source_total=1,
                previous_source_ids=33,
                source_ids=1,
                added_to_source=0,
                removed_from_source=32,
            )
        )
        self.assertIn("- Vorobey hackerpolice list (1 entry)", singular)
        self.assertIn("- Previous snapshot: 1 entry;", singular)
        self.assertIn("(33 → 1 SteamID; net -32 distinct SteamIDs)", singular)

        plural_report = render_report(
            self.info(
                source_total=2,
                previous_source_total=2,
                previous_source_ids=33,
                source_ids=2,
                added_to_source=0,
                removed_from_source=31,
            )
        )
        self.assertIn("- Vorobey hackerpolice list (2 entries)", plural_report)
        self.assertIn("- Previous snapshot: 2 entries;", plural_report)
        self.assertIn("(33 → 2 SteamIDs; net -31 distinct SteamIDs)", plural_report)

        # Zero takes the plural, as English does ("0 entries").
        self.assertIn("- Vorobey hackerpolice list (0 entries)", render_report(self.info(source_total=0)))

    def test_a_single_omitted_evidence_link_reads_as_one_entry(self):
        links = tuple(f"https://discord.com/channels/1/2/{n}" for n in range(MAX_EVIDENCE_LINKS))
        for omitted, expected in ((1, "and 1 more evidence entry"), (2, "and 2 more evidence entries")):
            with self.subTest(omitted=omitted):
                change = Change("[U:1:5]", "n", ("suspicious",), ("cheater",), links, evidence_omitted=omitted)
                self.assertIn(expected, render_report(self.info([change])))

    def test_snapshot_diff_initial_snapshot_without_previous(self):
        report = render_report(self.info(added_to_source=10, snapshot_changed=True))
        self.assertIn("**10 new SteamIDs added**, **0 SteamIDs removed** (no previous snapshot", report)

    def test_counts_use_thousands_separators(self):
        report = render_report(
            self.info(
                source_total=13542,
                previous_source_total=12345,
                source_ids=13542,
                previous_source_ids=12345,
                added_to_source=1200,
                removed_from_source=3,
                removed_upstream=("[U:1:1]",),
                snapshot_changed=True,
            )
        )
        self.assertIn("Vorobey hackerpolice list (13,542 entries)", report)  # Raw row totals remain exact.
        self.assertIn("- Previous snapshot: 12,345 entries", report)
        self.assertIn("**1,200 new SteamIDs added**", report)
        self.assertIn("(12,345 → 13,542 SteamIDs; net +1,197 distinct SteamIDs)", report)  # 1,200 added - 3 removed
        self.assertIn("**1 SteamID removed from the Vorobey hackerpolice list", report)

    def test_fetch_url_cannot_smuggle_html_into_the_report(self):
        info = RunInfo(
            database_path=Path("playerlist.garou3299.json"),
            source="https://example.invalid/<script>alert(1)</script>",
            source_total=1,
            source_skipped=0,
            dry_run=False,
        )
        report = render_report(info)
        self.assertNotIn("<script", report)
        self.assertIn("&lt;script&gt;", report)

    def test_a_url_cannot_ping_a_user_from_the_report(self):
        """``@handle`` in the body is a mention: it notifies a stranger.

        The fetch line carries a URL from --source, or from a document's
        download_url -- which comes from someone else's server.
        """
        report = render_report(self.info(source="https://example.invalid/@octocat/playerlist.json"))
        self.assertIn("&#64;octocat", report)
        self.assertNotIn("@octocat", report)

    def test_fetch_url_credentials_are_redacted(self):
        """A --source may carry a token; the PR body is public to the repo."""
        info = RunInfo(
            database_path=Path("playerlist.garou3299.json"),
            source="https://bot:ghp_secret@example.invalid/list.json?x=1",
            source_total=1,
            source_skipped=0,
            dry_run=False,
        )
        report = render_report(info)
        self.assertIn("- Fetched from: https://example.invalid/list.json?x=1", report)
        self.assertNotIn("ghp_secret", report)

    def test_html_entities_cannot_hide_fetch_url_credentials(self):
        report = render_report(
            self.info(source="https://example.invalid/list.json?token&#x3d;HTML_QUERY_SECRET&amp;ref&#x3d;main")
        )
        self.assertNotIn("HTML_QUERY_SECRET", report)
        self.assertIn("token=REDACTED", report)
        self.assertIn("ref=main", report)

    def test_snapshot_only_change_is_reported_as_such(self):
        report = render_report(self.info(snapshot_changed=True))
        self.assertIn("snapshot refresh only", report)
        self.assertIn("Snapshot:", report)
        self.assertNotIn("**No changes.**", report)

    def test_table_lists_changes_and_evidence(self):
        change = Change(
            steamid="[U:1:1]",
            name="cheater | with pipe",
            before=("suspicious",),
            after=("cheater",),
            evidence=(HACKERPOLICE_PROOF,),
        )
        report = render_report(self.info([change]))
        self.assertIn("**1 entry promoted to `cheater` in the Garou3299 database:**", report)
        self.assertIn(
            "| `[U:1:1]` | [cheater \\| with pipe](https://steamcommunity.com/profiles/76561197960265729) |",
            report,
        )
        self.assertIn(f"[proof]({HACKERPOLICE_PROOF})", report)
        self.assertIn("Proof link comes from the Vorobey hackerpolice list", report)

    def test_name_links_to_the_steam_profile_permalink(self):
        # SteamID64 = base + account ID.
        change = Change("[U:1:269327660]", "KNNU", ("suspicious",), ("cheater",), (HACKERPOLICE_PROOF,))
        report = render_report(self.info([change]))
        self.assertIn("[KNNU](https://steamcommunity.com/profiles/76561198229593388)", report)

    def test_demoted_names_link_too_and_missing_names_become_unknown(self):
        demoted = Change("[U:1:269327660]", "KNNU", ("cheater",), (), kind="demote")
        unnamed = Change("[U:1:2]", "", ("suspicious",), ("cheater",))
        report = render_report(self.info([demoted, unnamed]))
        self.assertIn("[KNNU](https://steamcommunity.com/profiles/76561198229593388)", report)
        # An unnamed player remains linked as UNKNOWN.
        self.assertIn("| `[U:1:2]` | [UNKNOWN](https://steamcommunity.com/profiles/76561197960265730) |", report)

    def test_a_player_literally_named_dash_keeps_their_name(self):
        change = Change("[U:1:1]", "-", ("suspicious",), ("cheater",))
        report = render_report(self.info([change]))
        self.assertIn("[-](https://steamcommunity.com/profiles/76561197960265729)", report)
        self.assertNotIn("[UNKNOWN]", report)

    def test_brackets_in_names_cannot_break_the_profile_link(self):
        change = Change("[U:1:1]", "a [b] c", ("suspicious",), ("cheater",))
        report = render_report(self.info([change]))
        self.assertIn("[a \\[b\\] c](https://steamcommunity.com/profiles/76561197960265729)", report)

    def test_lone_surrogates_in_names_and_proofs_cannot_crash_the_report(self):
        # JSON permits lone surrogates, but UTF-8 cannot encode them.
        # Replace them to keep report output encodable.
        change = Change("[U:1:1]", "bad\ud800name", ("suspicious",), ("cheater",), ("https://x/\udfff",))
        report = render_report(self.info([change]))
        self.assertIn("bad\ufffdname", report)
        report.encode("utf-8")  # The rendered report must remain UTF-8 encodable.

    def test_carriage_returns_in_names_cannot_break_the_table(self):
        change = Change("[U:1:1]", "a\rb", ("suspicious",), ("cheater",), (HACKERPOLICE_PROOF,))
        report = render_report(self.info([change]))
        self.assertIn("| [a b](https://steamcommunity.com/profiles/76561197960265729) |", report)
        self.assertNotIn("\r", report)

    def test_multiple_evidence_links_and_missing_links(self):
        with_links = Change("[U:1:1]", "a", ("suspicious",), ("cheater",), ("https://x/1", "https://x/2"))
        without_links = Change("[U:1:2]", "b", ("suspicious",), ("cheater",))
        report = render_report(self.info([with_links, without_links]))
        self.assertIn("[proof 1](https://x/1), [proof 2](https://x/2)", report)
        self.assertIn("**2 entries promoted to `cheater` in the Garou3299 database:**", report)

    def test_database_proofs_are_never_published_in_the_report(self):
        """The report is public; the proofs in the database are not printable.

        A ``racist`` entry's proof is the chat line TF2BD auto-marked it with --
        ``[auto] automatically marked: Racist | reason: "..."`` -- i.e. actual
        slur text. The report shows SteamIDs, names, attributes and the UPSTREAM
        evidence links only, so it must never echo a database proof: that is
        what keeps the pull request body publishable.
        """
        marker = "SLUR-MARKER-DO-NOT-PUBLISH"
        line = f'[auto] automatically marked: Racist | reason: "{marker}"'
        database = {
            "$schema": "x",
            "file_info": {},
            "players": [player("[U:1:200]", ["cheater", "racist"], proof=[line])],
        }
        changes = demote(database, ["[U:1:200]"])
        report = render_report(self.info(changes, removed_upstream=("[U:1:200]",)))
        # The proof remains in the database.
        self.assertEqual(database["players"][0]["proof"], [line])
        # The report must not expose it.
        self.assertNotIn(marker, report)
        self.assertNotIn("[auto] automatically marked", report)

    def test_line_terminators_cannot_split_a_table_row(self):
        """U+2028/U+2029/U+0085 break lines in CSS and in str.splitlines().

        A player name is attacker-controlled, so one containing a line
        terminator must not be able to end a table row early and start a new
        one. Everything that ends a line is neutralized, not just \n and \r.
        """
        name = "evil\u2028name\u2029other\x85nel\nlf\rcr\x0bvt\x0cff"
        change = Change("[U:1:1]", name, ("suspicious",), ("cheater",))
        report = render_report(self.info([change]))
        for terminator in ("\u2028", "\u2029", "\x85", "\x0b", "\x0c"):
            self.assertNotIn(terminator, report)
        # No unneutralized line terminator may add a split line.
        self.assertEqual(len(report.rstrip("\n").split("\n")), len(report.splitlines()))
        row = next(line for line in report.split("\n") if line.startswith("| `[U:1:1]`"))
        self.assertIn("evil name other nel lf cr vt ff", row)

    def test_a_backslash_cannot_neutralize_the_escape_that_follows_it(self):
        """``_text`` must escape the backslash before anything else.

        "a\\`b" used to become "a\\\\`b": the doubled backslash is a literal
        backslash, so the backtick after it opened a code span that ran on
        into the next line of the report.
        """
        report = render_report(self.info(source="https://host/a\\`b"))
        spans = _code_span_ranges(report)
        for start, end in spans:
            self.assertNotIn("\n", report[start:end])
        outside = "".join(
            character for index, character in enumerate(report) if not any(start <= index < end for start, end in spans)
        )
        # No unescaped backtick may remain outside a code span.
        stripped = re.sub(r"\\" + "[" + re.escape(string.punctuation) + "]", "", outside)
        self.assertNotIn("`", stripped)

    def test_a_backtick_in_a_proof_url_cannot_start_a_code_span(self):
        """A raw backtick in a link target opens a span before the link exists."""
        change = Change("[U:1:1]", "n", ("suspicious",), ("cheater",), ("https://e/x`y",))
        report = render_report(self.info([change]))
        for start, end in _code_span_ranges(report):
            self.assertNotIn("\n", report[start:end])
        self.assertIn("https://e/x%60y", report)

    def test_a_stray_backtick_cannot_swallow_the_rest_of_a_row(self):
        """Outside a code span a backtick OPENS one.

        A player name such as "tick` here" left the report with an odd number
        of backticks: the span opened inside the name cell ran on to the next
        backtick, so the profile link stopped being a link and the rest of the
        row was rendered as code.
        """
        change = Change("[U:1:1]", "tick` here", ("suspicious",), ("cheater",), ("proof`text",))
        report = render_report(self.info([change]))
        spans = _code_span_ranges(report)
        self.assertTrue(spans)
        for start, end in spans:
            self.assertNotIn("\n", report[start:end], "a code span ran past the end of its line")
        row = next(line for line in report.split("\n") if line.startswith("| `[U:1:1]`"))
        self.assertEqual(row.count("|"), 7)  # The row still has six cells.
        self.assertIn("[SteamHistory](", row)
        self.assertIn("tick\\` here", row)

    def test_a_backtick_cannot_break_out_of_a_code_span(self):
        """A backslash does not escape a backtick inside a code span.

        So the fence has to grow past the longest backtick run in the value.
        Escaping it the old way closed the span early, and the tail of the
        value was then parsed as Markdown (``x` and **bold** ` `` rendered its
        "bold" as bold in the page, outside the code).
        """
        for value in ("plain", "a`b", "`start", "end`", "a``b", "x` and **bold** `", "`"):
            rendered = report_module._code(value)
            fence = len(rendered) - len(rendered.lstrip("`"))
            self.assertGreaterEqual(fence, 1)
            self.assertTrue(rendered.endswith("`" * fence))
            content = rendered[fence:-fence]
            inner = max((len(run) for run in re.findall(r"`+", content)), default=0)
            self.assertLess(inner, fence, f"{value!r} -> {rendered!r} closes its own span")
            self.assertIn(value, content)

    def test_the_database_label_cannot_inject_markup(self):
        """The headline names the database file, so it is data too.

        A database called ``<b>x.json`` (or one holding ``[c](https://evil)``)
        must not open an HTML tag or a link in the pull request.
        """
        for name in ("<b>x.json", "[c](https://elsewhere.example).json", "a|b.json"):
            change = Change("[U:1:1]", "n", ("suspicious",), ("cheater",))
            info = report_module.RunInfo(
                database_path=Path("/tmp") / name,
                source="https://example.invalid/list.json",
                source_total=10,
                source_skipped=0,
                dry_run=False,
                changes=(change,),
            )
            report = render_report(info)
            # Only Markdown outside code spans is parsed.
            outside_code = re.sub(r"`+[^`]*`+", "", report)
            self.assertNotIn("<", outside_code)
            self.assertNotIn("](https://elsewhere.example)", outside_code)
            headline = next(line for line in report.split("\n") if "promoted to" in line)
            self.assertIn("database:**", headline)

    def test_untrusted_labels_and_notes_cannot_autolink(self):
        """Names, file labels, and path-bearing notes are data, not links."""
        for name in ("https://evil.example", "www.evil.example"):
            with self.subTest(name=name):
                change = Change("[U:1:1]", name, ("suspicious",), ("cheater",))
                row = next(
                    line for line in render_report(self.info([change])).splitlines() if line.startswith("| `[U:1:1]`")
                )
                self.assertIn(f"[`{name}`](https://steamcommunity.com/", row)

        for path, label in (
            ("playerlist.https:evil.example.json", "Https:evil.example"),
            ("playerlist.www.evil.example.json", "Www.evil.example"),
        ):
            with self.subTest(path=path):
                info = RunInfo(
                    database_path=Path("/tmp") / path,
                    source="https://example.invalid/list.json",
                    source_total=1,
                    source_skipped=0,
                    dry_run=False,
                    changes=(Change("[U:1:1]", "player", ("suspicious",), ("cheater",)),),
                    demotion_note="skipped because of https://evil.example and www.evil.example",
                )
                report = render_report(info)
                headline = next(line for line in report.splitlines() if "promoted to" in line)
                note = next(line for line in report.splitlines() if "Demotion:" in line)
                self.assertIn(f"`{label}`", headline)
                self.assertIn("`https://evil.example`", note)
                self.assertIn("`www.evil.example`", note)

    def test_a_url_cannot_inject_a_link_into_the_fetch_line(self):
        """The "Fetched from" line carries a URL, which can come from upstream.

        A URL holding "[click](https://elsewhere.example)" must render as
        literal text, not as a clickable link in a bot-authored pull request.
        """
        report = render_report(self.info(source="https://host/[click](https://elsewhere.example)/x"))
        line = next(line for line in report.split("\n") if "Fetched from" in line)
        self.assertIn("\\[click\\]", line)
        self.assertNotIn("[click](https://elsewhere.example)", report)

    def test_a_local_source_that_looks_like_a_url_is_not_autolinked(self):
        source = "www.evil.example/playerlist.json"
        report = render_report(self.info(source=source))
        line = next(line for line in report.splitlines() if "Fetched from" in line)
        self.assertIn(f"Fetched from: `{source}`", line)

    def test_report_never_emits_raw_html(self):
        """Markdown previews that escape HTML would show the tag as literal text."""
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",), ("https://x/1", "https://x/2"))
        report = render_report(self.info([change], removed_upstream=("[U:1:2]",)))
        self.assertNotIn("<br>", report)
        self.assertNotIn("<br/>", report)
        self.assertNotIn("<br />", report)

    def test_prose_evidence_is_not_turned_into_a_link_or_unnecessarily_fenced(self):
        for proof in ("seen spinbotting", "Reason: watched in-game"):
            with self.subTest(proof=proof):
                change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",), (proof,))
                report = render_report(self.info([change]))
                self.assertIn(f"| {proof} |", report)
                self.assertNotIn(f"[proof]({proof})", report)

    def test_autolink_literals_cannot_make_invalid_evidence_clickable(self):
        """GFM can link URI schemes and bare www.*; invalid proof stays inert."""
        for proof in ("www.evil.example/tracker", "ftp://evil.example/tracker", "mailto:evil@example.com"):
            with self.subTest(proof=proof):
                report = render_report(self.info([Change("[U:1:1]", "a", ("suspicious",), ("cheater",), (proof,))]))
                row = next(line for line in report.splitlines() if line.startswith("| `[U:1:1]`"))
                self.assertIn(f"`{proof}`", row)
                self.assertNotIn(f"]({proof})", report)
                self.assertNotIn("Proof link", report)

    def test_invisible_format_characters_are_encoded_in_link_targets(self):
        """Even meaningful joiners must be visible when they alter a URL."""
        for character in ("\u200b", "\u200c", "\u200d", "\u206a", "\u070f"):
            with self.subTest(character=f"U+{ord(character):04X}"):
                url = f"https://youtu.be/{character}abc"
                change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",), (url,))
                report = render_report(self.info([change]))
                encoded = "".join(f"%{byte:02X}" for byte in character.encode("utf-8"))
                self.assertIn(encoded, report)
                self.assertNotIn(character, report)

                # Direct link rendering must also encode format characters.
                self.assertIn(encoded, report_module._markdown_link(url, "proof"))

    def test_link_targets_are_escaped(self):
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",), ("https://example.invalid/a (b)",))
        report = render_report(self.info([change]))
        self.assertIn("https://example.invalid/a%20%28b%29", report)

    def test_url_classification_requires_a_valid_absolute_http_url(self):
        for url in (
            "https://example.invalid/a (b)",  # Path spaces are percent-encoded before Markdown parsing
            "HTTP://example.invalid/path",
        ):
            with self.subTest(valid=url):
                self.assertTrue(report_module._is_url(url))

        for url in (
            "",
            " https://example.invalid/path",
            "https://example.invalid/path ",
            "https:relative",
            "https:///missing-host/path",
            "https://:443/path",
            "https://example.invalid:bogus/path",
            "https://example.invalid:/path",
            "https://example.invalid bad/path",
            "https://example.invalid/a https://evil.invalid/x",
            "https://example.invalid/a" + chr(92) + "b",
            "https://example.invalid/a" + chr(9) + "b",
            "https://example.invalid/a" + chr(10) + "b",
            "https://example.invalid/\u00a0b",
            "https://bad%host.invalid/path",
            "https://example.invalid/%GG",
            "https://example.invalid/?ref&#x3d;main",
            "https://[::1/path",
            "//example.invalid/path",
        ):
            with self.subTest(invalid=url):
                self.assertFalse(report_module._is_url(url))

    def test_malformed_or_ambiguous_proof_urls_are_literal_and_do_not_raise_a_link_note(self):
        probes = (
            "seen spinbotting",
            "https:relative",
            "https:///missing-host/path",
            "https://example.invalid:bogus/path",
            "https://example.invalid:/path",
            "https://example.invalid bad/path",
            "https://example.invalid/a https://evil.invalid/x",
            "https://example.invalid/a\\\\b",
            "https://example.invalid/%GG",
        )
        for url in probes:
            with self.subTest(url=url):
                report = render_report(self.info([Change("[U:1:1]", "a", ("suspicious",), ("cheater",), (url,))]))
                self.assertNotIn("[proof]", report)
                self.assertNotIn("Proof link", report)
                row = next(line for line in report.splitlines() if line.startswith("| `[U:1:1]`"))
                self.assertEqual(row.count("|"), 7)

    def test_a_redacted_proof_url_cannot_become_an_automatic_markdown_link(self):
        url = "https://example.invalid/x?access_token=SECRET&cookie=COOKIE_SECRET&csrf=CSRF_SECRET"
        report = render_report(self.info([Change("[U:1:1]", "a", ("suspicious",), ("cheater",), (url,))]))
        for secret in ("SECRET", "COOKIE_SECRET", "CSRF_SECRET"):
            self.assertNotIn(secret, report)
        self.assertNotIn("[proof]", report)
        self.assertNotIn("Proof link", report)
        row = next(line for line in report.splitlines() if line.startswith("| `[U:1:1]`"))
        self.assertIn("access_token=REDACTED", row)
        self.assertIn("cookie=REDACTED", row)
        self.assertIn("csrf=REDACTED", row)

    def test_html_entities_cannot_hide_credentials_in_a_proof_link(self):
        links = (
            "https://user&#x3a;HTML_USERINFO_PASSWORD&#x40;example.invalid/watch",
            "https://example.invalid/watch?token&#x3d;HTML_QUERY_SECRET",
            "https://example.invalid/watch?ref&#x3d;main",
        )
        report = render_report(self.info([Change("[U:1:1]", "a", ("suspicious",), ("cheater",), links)]))
        self.assertNotIn("HTML_USERINFO_PASSWORD", report)
        self.assertNotIn("HTML_QUERY_SECRET", report)
        self.assertNotIn("[proof 1]", report)
        self.assertNotIn("[proof 2]", report)
        self.assertNotIn("[proof 3]", report)
        self.assertIn("https://example.invalid/watch", report)
        self.assertIn("token=REDACTED", report)

    def test_newline_in_the_fetch_url_cannot_inject_a_report_line(self):
        # Newlines in upstream URLs must not create extra report lines.
        report = render_report(self.info(source="https://example.invalid/a\n- **injected**\r\n- second"))
        self.assertFalse(any(line.startswith("- **injected**") for line in report.splitlines()))
        self.assertIn("injected", report)  # Flatten the newline rather than dropping the URL

    def test_pipe_in_a_proof_url_cannot_split_the_table_row(self):
        # Percent-encode raw pipes; they split table cells, while %7C preserves the URL.
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",), ("https://example.invalid/a|b",))
        report = render_report(self.info([change]))
        self.assertIn("https://example.invalid/a%7Cb", report)
        rows = [line for line in report.splitlines() if line.startswith("| `[U:1:1]`")]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].count("|"), 7)  # The row still has six cells.

    def test_no_proof_note_without_evidence_links(self):
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",))  # No evidence links.
        report = render_report(self.info([change]))
        self.assertNotIn("Proof links come from", report)

    def test_a_demotions_proof_never_raises_the_note(self):
        """Only the promotion table has a proof column, so only it needs the note.

        A demoted entry can still carry the ``[auto] ... Racist`` proof it kept,
        but the demotion table never renders it -- annotating a link that is not
        on the page would be the same defect as the capped-table case.
        """
        change = Change(
            "[U:1:1]",
            "a",
            ("cheater", "racist"),
            ("racist",),
            ("https://proof.example/1",),
            kind="demote",
        )
        # This case has no promotion table, only demotion and removal tables.
        report = render_report(self.info([change], removed_upstream=("[U:1:2]",)))
        self.assertNotIn("promoted to", report)
        self.assertIn("demoted", report)
        self.assertIn("removed from the Vorobey hackerpolice list", report)
        self.assertNotIn("Hackerpolice proof", report)
        self.assertNotIn("Proof link", report)

    def test_name_and_proof_cells_cannot_inject_html_or_mentions(self):
        change = Change(
            "[U:1:1]",
            "<img src=x>@here",
            ("suspicious",),
            ("cheater",),
            ("@everyone see <b>this</b>",),
        )
        report = render_report(self.info([change]))
        self.assertNotIn("<img", report)
        self.assertNotIn("@here", report)
        self.assertNotIn("@everyone", report)
        self.assertNotIn("<b>", report)
        self.assertIn("&lt;b&gt;this&lt;/b&gt;", report)  # Render it literally, not as HTML.

    def test_the_table_and_the_running_text_share_one_escape_policy(self):
        """Two hand-maintained lists is how a hole gets missed.

        The entity spelling of a character got past BOTH the table escaping and
        the running-text escaping, because each was a separate list; the fix
        needed two edits, and missing either would have left the hole open.
        They are now derived from one map, and this pins that they stay so.
        """
        for character, replacement in report_module._ESCAPES.items():
            with self.subTest(character=character):
                if character.isspace():
                    # Both breaks become spaces, then trimming yields the '-' placeholder.
                    self.assertEqual(report_module._text(character), " ")
                    self.assertEqual(report_module._cell(character), "-")
                    continue
                self.assertNotEqual(replacement, character)  # The output is an escape sequence.
                self.assertEqual(report_module._text(character), replacement)
                self.assertEqual(report_module._cell(character), replacement)
        # Pipes are the only intentional difference between the maps.
        self.assertNotIn("|", report_module._ESCAPES)
        self.assertNotEqual(report_module._cell("|"), report_module._text("|"))

    def test_a_name_cannot_render_emphasis_in_the_pull_request(self):
        """The report is markdown that a human APPROVES.

        A player name is data from the database (and, upstream, from whoever
        wrote it). Unescaped, "**Approved by admin**" rendered as bold text, and
        "~~cheater~~ trusted" as struck-through text, inside the bot's own pull
        request -- formatting the reviewer never asked for, in the one column a
        reader takes at face value.
        """
        for name, marker in (
            ("**Approved by admin**", "\\*\\*Approved by admin\\*\\*"),
            ("__under__", "\\_\\_under\\_\\_"),
            ("~~cheater~~ trusted", "\\~\\~cheater\\~\\~ trusted"),
        ):
            with self.subTest(name=name):
                cell = report_module._cell(name)
                self.assertEqual(cell, marker)
                # Ordinary underscores remain readable after escaping.
                self.assertEqual(report_module._cell("a_b_c"), "a\\_b\\_c")

    def test_a_name_cannot_smuggle_an_html_entity_past_the_guards(self):
        """The entity SPELLING defeated every character-level defence.

        ``&#x202E;`` is not a bidi character, so the bidi scrub let it through,
        and the renderer turned it into U+202E -- a right-to-left override in
        the review table. ``&#8203;`` did the same with a zero-width space, and
        ``&#64;admin`` rendered ``@admin``: a mention ping from the bot's own
        pull request, which the ``@`` -> ``&#64;`` escape exists to prevent.
        """
        for name in ("&#x202E;evil", "&#8203;hidden", "&#64;admin"):
            with self.subTest(name=name):
                cell = report_module._cell(name)
                self.assertNotIn("&#", cell.replace("&#64;", "").replace("&amp;", ""))
                self.assertIn("&amp;#", cell)  # Entity syntax is now inert text.

    def test_change_tables_are_capped(self):
        changes = [
            Change(f"[U:1:{1000 + n}]", f"n{n}", ("suspicious",), ("cheater",))
            for n in range(MAX_CHANGE_TABLE_ROWS + 3)
        ]
        report = render_report(self.info(changes))
        rows = [line for line in report.splitlines() if line.startswith("| `[U:1:")]
        self.assertEqual(len(rows), MAX_CHANGE_TABLE_ROWS)
        self.assertIn("… and 3 more entries not shown here", report)

    def test_a_huge_report_shrinks_its_tables_instead_of_losing_its_tail(self):
        """Pathological input must not cut off the closing sentence or the removed list."""
        changes = [Change(f"[U:1:{1000 + n}]", "x" * 900, ("suspicious",), ("cheater",)) for n in range(200)]
        report = render_report(self.info(changes, removed_upstream=tuple(f"[U:1:{5000 + n}]" for n in range(100))))
        self.assertLessEqual(len(report.encode("utf-8")), MAX_REPORT_BYTES)
        self.assertNotIn("report truncated to fit the pull request body limit", report)
        # Preserve the closing sentence and removed-ID table.
        self.assertIn("; nothing else is modified.", report)
        self.assertIn("100 SteamIDs removed from the Vorobey hackerpolice list", report)
        self.assertIn("| SteamID | Profile Link | SteamHistory |", report)
        # Reduced change-table rows are announced; the removed-ID list is preserved.
        self.assertIn("more entries not shown here", report)
        self.assertEqual(report.count("| [Profile]("), 100)
        report.encode("utf-8")

    def test_the_report_drops_the_fewest_rows_that_fit(self):
        """Shrinking must not throw away more rows than the budget requires."""
        changes = [Change(f"[U:1:{1000 + n}]", "x" * 900, ("suspicious",), ("cheater",)) for n in range(200)]
        info = self.info(changes, removed_upstream=tuple(f"[U:1:{5000 + n}]" for n in range(100)))
        report = render_report(info)
        shown = sum(1 for line in report.splitlines() if line.startswith("| `[U:1:1"))
        caps = (MAX_CHANGE_TABLE_ROWS, 100, 50, 25, 10, 5, 1)
        largest_that_fits = next(
            cap
            for cap in caps
            if len(report_module._render_body(info, cap, MAX_REMOVED_TABLE_ROWS).encode("utf-8")) <= MAX_REPORT_BYTES
        )
        self.assertEqual(shown, largest_that_fits)

    def test_a_huge_demotion_table_shrinks_like_the_promotion_one(self):
        changes = [Change(f"[U:1:{2000 + n}]", "y" * 900, ("cheater",), (), kind="demote") for n in range(200)]
        report = render_report(self.info(changes))
        shown = sum(1 for line in report.splitlines() if line.startswith("| `[U:1:2"))
        self.assertLess(shown, len(changes))
        self.assertIn("more entries not shown here", report)
        self.assertIn("; nothing else is modified.", report)
        self.assertLessEqual(len(report.encode("utf-8")), MAX_REPORT_BYTES)

    def test_a_single_enormous_row_is_shortened_instead_of_truncated(self):
        """An absurd URL is shortened, so the body never needs the last resort.

        This used to be the ONE unshortenable cell: a URL had to stay whole to
        remain clickable, so the whole body was hard-truncated -- header, table
        header and a truncation note, with the closing sentence and the removed
        SteamIDs gone. A link that long is not usable anyway, so it is now
        shown as shortened text and everything else survives.
        """
        change = Change("[U:1:1]", "x", ("suspicious",), ("cheater",), ("https://example.invalid/" + "y" * 70_000,))
        report = render_report(self.info([change], removed_upstream=("[U:1:2]",)))
        self.assertLessEqual(len(report.encode("utf-8")), MAX_REPORT_BYTES)
        self.assertNotIn("report truncated", report)
        self.assertIn("nothing else is modified.", report)
        self.assertIn("| SteamID | Profile Link | SteamHistory |", report)
        report.encode("utf-8")  # Confirm that UTF-8 encoding succeeds.

    def test_a_body_that_would_be_too_long_shrinks_its_tables_instead(self):
        """150 rows of maximal cells overflow the budget: drop rows, never cut.

        Row caps alone are not enough when every cell is at its own limit
        (10 proof links of 500 characters each), so the report is re-rendered
        with smaller tables. What must survive is the closing sentence, the
        removed-SteamID list, and an honest "and N more" note.
        """
        link = "https://example.invalid/" + "x" * 476
        changes = tuple(
            Change(f"[U:1:{number}]", "名" * 80, ("suspicious",), ("cheater",), tuple(link for _ in range(10)))
            for number in range(1, 151)
        )
        report = render_report(
            self.info(changes=changes, removed_upstream=tuple(f"[U:1:{number}]" for number in range(151, 251)))
        )
        self.assertLessEqual(len(report.encode("utf-8")), MAX_REPORT_BYTES)
        self.assertNotIn("report truncated to fit the pull request body limit", report)
        self.assertIn("; nothing else is modified.", report)
        self.assertIn("not shown here", report)
        self.assertIn("removed from the Vorobey hackerpolice list", report)

    def test_the_last_resort_cut_still_works_when_the_budget_is_tiny(self):
        """Every cell is bounded, so the nine shrink steps always fit in practice.

        This forces the budget below a single row to prove the tenth step -- a
        hard cut on a line boundary -- is still in working order for the day a
        future change adds a cell without a bound.
        """
        changes = tuple(
            Change(f"[U:1:{number}]", "name", ("suspicious",), ("cheater",), ("https://example.invalid/p",))
            for number in range(1, 6)
        )
        budget = 700  # Set the budget below the header plus one reduced row.
        with mock.patch.object(report_module, "MAX_REPORT_BYTES", budget):
            report = report_module.render_report(self.info(changes=changes))
        self.assertLessEqual(len(report.encode("utf-8")), budget)
        self.assertTrue(report.endswith("… report truncated to fit the pull request body limit."))
        self.assertTrue(report.startswith("## Vorobey hackerpolice sync"))
        self.assertNotIn("\ufffd", report)

    def test_a_demoted_entry_that_loses_every_tag_says_entry_removed(self):
        """With no attributes left the After cell must not be blank."""
        change = Change("[U:1:1]", "name", ("cheater",), (), kind="demote")
        report = render_report(self.info(changes=(change,)))
        self.assertIn("entry removed", report)
        self.assertIn("| `cheater` | entry removed |", report)

    def test_an_unusable_steamid_sorts_last_in_the_removed_table(self):
        """Numeric order, with anything unusable trailing (stably)."""
        table = report_module.render_removed_table(["[U:1:20]", "nope", "[U:1:3]"])
        rows = [line for line in table if line.startswith("| `")]
        self.assertEqual(len(rows), 3)
        self.assertIn("[U:1:3]", rows[0])
        self.assertIn("[U:1:20]", rows[1])
        self.assertIn("nope", rows[2])

    def test_database_and_snapshot_paths_redact_url_like_credentials(self):
        database_secret = "DATABASE_PATH_SECRET"
        snapshot_secret = "SNAPSHOT_PATH_SECRET"
        source_secret = "SOURCE_PATH_SECRET"
        info = RunInfo(
            database_path=Path("https:/user:" + database_secret + "x" * 180 + "@example.invalid/db.json"),
            source=("https:/example.invalid/https%3A%2F%2Fuser%3A" + source_secret + "%40client.invalid%2Flist.json"),
            source_total=1,
            source_skipped=0,
            dry_run=False,
            snapshot_changed=True,
            snapshot_path=Path("https:user:" + snapshot_secret + "@example.invalid/snapshot.json"),
        )
        report = render_report(info)
        self.assertNotIn(database_secret, report)
        self.assertNotIn(snapshot_secret, report)
        self.assertNotIn(source_secret, report)
        self.assertIn("example.invalid", report)
        self.assertIn("[malformed URL omitted]", report)

    def test_encoded_nested_credentials_in_database_path_are_redacted(self):
        secret = "ENCODED_DATABASE_PATH_SECRET"
        path = Path("/tmp/https%3A%2F%2Fuser%3A" + secret + "%40client.invalid%2Fdb.json")
        info = RunInfo(
            database_path=path,
            source="https://example.invalid/list.json",
            source_total=1,
            source_skipped=0,
            dry_run=False,
        )
        report = render_report(info)
        self.assertNotIn(secret, report)

    def test_an_absurd_database_path_is_clipped_instead_of_truncating_the_report(self):
        """A 100,000-character path can no longer blow the body budget.

        The path is operator input and used to be the last way to overflow the
        body from inside the header. It is clipped now, so the header -- and
        every line of it -- stays readable; ``_fit_body`` remains as defence in
        depth and is tested directly (ReportBoundaryTests).
        """
        absurd = Path("/tmp/" + "d" * 100_000 + ".json")
        info = RunInfo(
            database_path=absurd,
            source="https://example.invalid/list.json",
            source_total=10,
            source_skipped=0,
            dry_run=False,
            # Include a promotion because the path also appears in its headline.
            changes=(Change("[U:1:1]", "name", ("suspicious",), ("cheater",)),),
        )
        report = render_report(info)
        self.assertLessEqual(len(report.encode("utf-8")), MAX_REPORT_BYTES)
        self.assertNotIn("report truncated to fit the pull request body limit", report)
        self.assertIn("; nothing else is modified.", report)
        self.assertIn("…", report)  # The path itself is clipped.
        self.assertTrue(report.startswith("## Vorobey hackerpolice sync"))
        database_line = next(line for line in report.splitlines() if line.startswith("- Database:"))
        self.assertLessEqual(len(database_line), 300)
        self.assertLessEqual(max(len(line) for line in report.splitlines()), 400)
        self.assertNotIn("\ufffd", report)

    def test_an_enormous_name_is_shortened_instead_of_truncating_the_report(self):
        """A name is data, not a link: cap it and keep the tables and sentence."""
        changes = [Change(f"[U:1:{1000 + n}]", "名" * 5_000, ("suspicious",), ("cheater",)) for n in range(3)]
        report = render_report(self.info(changes, removed_upstream=("[U:1:9]",)))
        self.assertLessEqual(len(report.encode("utf-8")), MAX_REPORT_BYTES)
        self.assertNotIn("report truncated to fit the pull request body limit", report)
        self.assertIn("; nothing else is modified.", report)
        self.assertIn("…", report)
        longest = max(len(line) for line in report.splitlines())
        self.assertLess(longest, 1_000, "a single row is still enormous")
        # Apply the cap before Markdown escaping to avoid cutting an escape sequence.
        self.assertEqual(report.count("| `[U:1:1"), 3)

    def test_the_number_of_proof_links_in_a_row_is_capped(self):
        """One row may not carry thousands of links: the tables must survive."""
        links = tuple(f"https://discord.com/channels/1/2/{n}" for n in range(2_000))
        changes = [Change(f"[U:1:{1000 + n}]", "name", ("suspicious",), ("cheater",), links) for n in range(3)]
        report = render_report(self.info(changes, removed_upstream=("[U:1:9]",)))
        self.assertLessEqual(len(report.encode("utf-8")), MAX_REPORT_BYTES)
        self.assertNotIn("report truncated to fit the pull request body limit", report)
        self.assertIn("; nothing else is modified.", report)
        # Pin the cap directly; a test derived from it would miss policy changes.
        self.assertEqual(report_module.MAX_EVIDENCE_LINKS, 10)
        row = next(line for line in report.splitlines() if line.startswith("| `[U:1:1000]`"))
        self.assertEqual(row.count("https://discord.com/channels/1/2/"), 10)
        self.assertIn("and 1,990 more", row)
        self.assertNotIn("[and", row, "the overflow note must not look like a link")

    def test_many_huge_proof_lists_still_show_most_of_the_rows(self):
        """A row must not eat the byte budget: hundreds of changes stay visible."""
        links = tuple(f"https://discord.com/channels/1/2/{n}" for n in range(2_000))
        changes = [Change(f"[U:1:{1000 + n}]", "name", ("suspicious",), ("cheater",), links) for n in range(200)]
        report = render_report(self.info(changes, removed_upstream=tuple(f"[U:1:{9000 + n}]" for n in range(100))))
        self.assertLessEqual(len(report.encode("utf-8")), MAX_REPORT_BYTES)
        rows = sum(1 for line in report.splitlines() if line.startswith("| `[U:1:1"))
        self.assertGreaterEqual(rows, 50, f"only {rows} change rows survived the byte budget")
        self.assertIn("; nothing else is modified.", report)

    def test_ten_or_fewer_proof_links_get_no_overflow_note(self):
        for count in (0, 1, 10):
            links = tuple(f"https://discord.com/channels/1/2/{n}" for n in range(count))
            change = Change("[U:1:1000]", "name", ("suspicious",), ("cheater",), links)
            report = render_report(self.info([change]))
            self.assertNotIn(" more", report)
            self.assertEqual(report.count("https://discord.com/channels/1/2/"), count)

    def test_omitted_upstream_evidence_is_counted_after_policy_caps_storage(self):
        links = tuple(f"https://discord.com/channels/1/2/{n}" for n in range(MAX_EVIDENCE_LINKS))
        change = Change(
            "[U:1:1000]",
            "name",
            ("suspicious",),
            ("cheater",),
            evidence=links,
            evidence_omitted=3,
        )

        report = render_report(self.info([change]))
        row = next(line for line in report.splitlines() if line.startswith("| `[U:1:1000]`"))

        self.assertEqual(row.count("https://discord.com/channels/1/2/"), MAX_EVIDENCE_LINKS)
        self.assertIn("and 3 more evidence entries", row)

    def test_a_report_that_already_fits_is_never_shrunk(self):
        """The reduced caps only kick in when the body really is too big."""
        changes = [Change(f"[U:1:{1000 + n}]", f"n{n}", ("suspicious",), ("cheater",)) for n in range(5)]
        info = self.info(changes, removed_upstream=("[U:1:9]",))
        self.assertEqual(
            render_report(info),
            report_module._render_body(info, MAX_CHANGE_TABLE_ROWS, MAX_REMOVED_TABLE_ROWS),
        )
        self.assertNotIn("more entries not shown here", render_report(info))

    def test_dry_run_note(self):
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",))
        report = render_report(self.info([change], dry_run=True))
        self.assertIn("**dry run**", report)

    def test_the_report_never_has_a_double_blank_line(self):
        """Markdown quality: blocks are separated by exactly one blank line."""
        changes = (
            Change("[U:1:1]", "a", ("suspicious",), ("cheater",)),
            Change("[U:1:2]", "b", ("cheater", "racist"), ("racist",), kind="demote"),
            Change("[U:1:3]", "c", ("cheater",), (), kind="demote"),
        )
        report = render_report(self.info(changes=changes, removed_upstream=("[U:1:9]",)))
        self.assertNotIn("\n\n\n", report)
        self.assertIn("; nothing else is modified.", report)
        last_block = report.rstrip("\n").split("\n\n")[-1]
        self.assertTrue(last_block.startswith("In the Garou3299 database:"), last_block)


class RemovedFromVorobeyTableTests(unittest.TestCase):
    """A capped report table makes removed IDs reviewable without bloating the PR.

    The Vorobey list stores no player names, so the table is exactly
    ``| SteamID | Profile Link | SteamHistory |`` and every displayed link is a
    SteamID64 permalink, never a vanity URL or a last-seen name. The overflow
    note accounts for any IDs beyond the row cap.
    """

    def info(self, **kwargs):
        return RunInfo(
            database_path=Path("playerlist.garou3299.json"),
            source="https://example.invalid/list.json",
            source_total=10,
            source_skipped=0,
            **{"dry_run": False, **kwargs},
        )

    def test_table_lists_the_steamid_and_its_permalink(self):
        report = render_report(self.info(removed_upstream=("[U:1:269327660]",)))
        self.assertIn(
            "**1 SteamID removed from the Vorobey hackerpolice list since the previous snapshot:**",
            report,
        )
        self.assertIn("| SteamID | Profile Link | SteamHistory |", report)
        self.assertIn("| --- | --- | --- |", report)
        self.assertIn(
            "| `[U:1:269327660]` | [Profile](https://steamcommunity.com/profiles/76561198229593388) "
            "| [SteamHistory](https://steamhistory.net/id/76561198229593388) |",
            report,
        )

    def test_no_names_are_used_because_vorobey_stores_none(self):
        report = render_report(self.info(removed_upstream=("[U:1:2]",)))
        self.assertNotIn("Last known name", report)
        self.assertNotIn("UNKNOWN", report)
        # No filler appears between the heading and table.
        self.assertNotIn("stores no player names", report)
        self.assertLess(
            report.index("removed from the Vorobey hackerpolice list"),
            report.index("| SteamID | Profile Link | SteamHistory |"),
        )

    def test_plural_count_and_numeric_order(self):
        report = render_report(self.info(removed_upstream=("[U:1:20]", "[U:1:3]")))
        self.assertIn("**2 SteamIDs removed from the Vorobey hackerpolice list", report)
        rows = [line for line in report.splitlines() if line.startswith("| `[U:1:")]
        self.assertEqual(
            rows,
            [
                (
                    "| `[U:1:3]` | [Profile](https://steamcommunity.com/profiles/76561197960265731) "
                    "| [SteamHistory](https://steamhistory.net/id/76561197960265731) |"
                ),
                (
                    "| `[U:1:20]` | [Profile](https://steamcommunity.com/profiles/76561197960265748) "
                    "| [SteamHistory](https://steamhistory.net/id/76561197960265748) |"
                ),
            ],
        )

    def test_table_is_shown_even_when_the_database_changed_nothing(self):
        # Snapshot-only run with no affected database entries.
        report = render_report(self.info(snapshot_changed=True, removed_upstream=("[U:1:5]",)))
        self.assertIn("snapshot refresh only", report)
        self.assertIn("| `[U:1:5]` | [Profile](", report)

    def test_table_is_shown_after_the_change_tables(self):
        change = Change("[U:1:400]", "a", ("suspicious",), ("cheater",))
        report = render_report(self.info(changes=(change,), removed_upstream=("[U:1:5]",)))
        self.assertLess(
            report.index("promoted to `cheater`"), report.index("removed from the Vorobey hackerpolice list")
        )

    def test_the_three_tables_always_come_in_promote_demote_removed_order(self):
        """The body never reorders the tables, whether one, two or three are present."""
        promote = Change("[U:1:400]", "a", ("suspicious",), ("cheater",), kind="promote")
        demote = Change("[U:1:300]", "b", ("cheater", "racist"), ("racist",), kind="demote")
        markers = (
            "promoted to `cheater`",
            "demoted (present in the previous snapshot",
            "removed from the Vorobey hackerpolice list since the previous snapshot",
        )
        cases = {
            "all three": {"changes": (demote, promote), "removed_upstream": ("[U:1:300]", "[U:1:500]")},
            "promote + removed": {"changes": (promote,), "removed_upstream": ("[U:1:500]",)},
            "demote + removed": {"changes": (demote,), "removed_upstream": ("[U:1:300]",)},
            "promote only": {"changes": (promote,), "removed_upstream": ()},
            "removed only": {"changes": (), "removed_upstream": ("[U:1:500]",)},
        }
        for title, kwargs in cases.items():
            with self.subTest(title):
                report = render_report(self.info(**kwargs))
                present = [marker for marker in markers if marker in report]
                self.assertEqual(
                    [report.index(marker) for marker in present],
                    sorted(report.index(marker) for marker in present),
                    f"{title}: {present}",
                )
                # Demotions retain the raw upstream-removal table in the report.
                if "demoted (present" in report:
                    self.assertIn(markers[2], report)

    def test_closing_sentence_and_proof_note_are_always_last(self):
        change = Change("[U:1:400]", "a", ("suspicious",), ("cheater",), ("https://x/1",))
        report = render_report(self.info(changes=(change,), removed_upstream=("[U:1:5]",)))
        lines = [line for line in report.splitlines() if line.strip()]
        self.assertIn("Proof link", lines[-1])
        self.assertIn("nothing else is modified.", lines[-2])
        # The removed table precedes the closing sentence.
        self.assertLess(report.index("| Profile Link | SteamHistory |"), report.index("nothing else is modified."))

    def test_closing_sentence_names_the_database_that_changed(self):
        change = Change("[U:1:400]", "a", ("suspicious",), ("cheater",))
        other = Change("[U:1:401]", "c", ("suspicious",), ("cheater",))
        removed_entry = Change("[U:1:500]", "b", ("cheater",), (), kind="demote")
        report = render_report(self.info(changes=(change, other, removed_entry)))
        self.assertIn("In the Garou3299 database: attributes are changed for these SteamIDs", report)
        self.assertIn("entry is removed for this SteamID: [U:1:500]", report)
        # The closing sentence names the database exactly once.
        closing = next(line for line in report.splitlines() if "nothing else is modified" in line)
        self.assertEqual(closing.count("Garou3299"), 1)
        # Report the basename, not an absolute or temporary path.
        self.assertNotIn(str(Path("playerlist.garou3299.json").resolve()), report)

    def test_no_table_without_removals(self):
        for kwargs in ({}, {"previous_source_total": 100, "added_to_source": 2, "removed_from_source": 0}):
            report = render_report(self.info(**kwargs))
            self.assertNotIn("Profile Link", report)
            self.assertNotIn("| SteamID |", report)

    def test_long_lists_are_capped_but_the_overflow_is_counted(self):
        steamids = [f"[U:1:{1000 + n}]" for n in range(MAX_REMOVED_TABLE_ROWS + 25)]
        report = render_report(self.info(removed_upstream=tuple(steamids)))
        rows = [line for line in report.splitlines() if line.startswith("| `[U:1:")]
        self.assertEqual(len(rows), MAX_REMOVED_TABLE_ROWS)
        self.assertIn("… and 25 more SteamIDs not shown here", report)

    def test_cap_message_is_singular_for_one_left_over(self):
        steamids = [f"[U:1:{1000 + n}]" for n in range(MAX_REMOVED_TABLE_ROWS + 1)]
        report = render_report(self.info(removed_upstream=tuple(steamids)))
        self.assertIn("… and 1 more SteamID not shown here", report)

    def test_an_unusable_steamid_never_crashes_the_table(self):
        report = render_report(self.info(removed_upstream=("nonsense",)))
        self.assertIn("| `nonsense` | - |", report)

    def test_report_stays_utf8_encodable(self):
        """A report must always encode: the CLI writes it with UTF-8.

        Lone surrogates are legal in a JSON database and impossible to encode,
        so this asserts the bytes really are produced -- not merely that no
        exception escaped.
        """
        report = render_report(self.info(removed_upstream=("[U:1:1]",), previous_source_total=10))
        encoded = report.encode("utf-8")
        self.assertTrue(encoded)
        self.assertIn(b"removed from the Vorobey hackerpolice list", encoded)


class ClosingMessageTests(unittest.TestCase):
    def test_promote_singular(self):
        change = Change("[U:1:400]", "a", ("suspicious",), ("cheater",), kind="promote")
        self.assertEqual(
            render_closing([change]),
            "Attribute is changed for this SteamID: [U:1:400]; nothing else is modified.",
        )

    def test_promote_plural(self):
        changes = [
            Change("[U:1:100]", "a", ("suspicious",), ("cheater",), kind="promote"),
            Change("[U:1:200]", "b", ("racist",), ("cheater", "racist"), kind="promote"),
        ]
        self.assertEqual(
            render_closing(changes),
            "Attributes are changed for these SteamIDs: [U:1:100], [U:1:200]; nothing else is modified.",
        )

    def test_demote_remove_entry_singular(self):
        change = Change("[U:1:300]", "a", ("cheater",), (), kind="demote")
        self.assertEqual(
            render_closing([change]),
            "Entry is removed from the database for this SteamID: [U:1:300]; nothing else is modified.",
        )

    def test_demote_remove_entry_plural(self):
        changes = [
            Change("[U:1:100]", "a", ("cheater",), (), kind="demote"),
            Change("[U:1:200]", "b", ("cheater",), (), kind="demote"),
        ]
        self.assertEqual(
            render_closing(changes),
            "Entries are removed from the database for these SteamIDs: [U:1:100], [U:1:200]; nothing else is modified.",
        )

    def test_demote_cheater_racist_keeps_racist(self):
        change = Change("[U:1:200]", "a", ("cheater", "racist"), ("racist",), kind="demote")
        self.assertEqual(
            render_closing([change]),
            "Attribute is changed for this SteamID: [U:1:200]; nothing else is modified.",
        )

    def test_database_label_scopes_the_sentence(self):
        promote_change = Change("[U:1:400]", "a", ("suspicious",), ("cheater",), kind="promote")
        demote_change = Change("[U:1:300]", "b", ("cheater",), (), kind="demote")
        # The label scopes the sentence and appears exactly once.
        self.assertEqual(
            render_closing([promote_change], database="Garou3299"),
            "In the Garou3299 database: attribute is changed for this SteamID: [U:1:400]; nothing else is modified.",
        )
        self.assertEqual(
            render_closing([demote_change], database="Garou3299"),
            "In the Garou3299 database: entry is removed for this SteamID: [U:1:300]; nothing else is modified.",
        )
        self.assertEqual(
            render_closing([promote_change, demote_change], database="Garou3299"),
            "In the Garou3299 database: attribute is changed for this SteamID: [U:1:400]; "
            "entry is removed for this SteamID: [U:1:300]; nothing else is modified.",
        )
        self.assertEqual(
            render_closing([promote_change, demote_change], database="Garou3299").count("Garou3299"),
            1,
        )

    def test_plural_and_two_removals_with_database(self):
        changes = [
            Change("[U:1:400]", "a", ("suspicious",), ("cheater",), kind="promote"),
            Change("[U:1:401]", "b", ("suspicious",), ("cheater",), kind="promote"),
            Change("[U:1:300]", "c", ("cheater",), (), kind="demote"),
            Change("[U:1:301]", "d", ("cheater",), (), kind="demote"),
        ]
        self.assertEqual(
            render_closing(changes, database="Garou3299"),
            "In the Garou3299 database: attributes are changed for these SteamIDs: [U:1:400], [U:1:401]; "
            "entries are removed for these SteamIDs: [U:1:300], [U:1:301]; nothing else is modified.",
        )

    def test_database_label_is_derived_from_the_file_name(self):
        cases = {
            "playerlist.garou3299.json": "Garou3299",
            "/tmp/some/dir/playerlist.garou3299.json": "Garou3299",
            f"/{'a' * 220}/playerlist.garou3299.json": "Garou3299",
            "mylist.json": "Mylist",
            "playerlist.json": "Playerlist",
            # Numeric owner names are accepted as labels.
            "playerlist.2024.json": "2024",
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                info = RunInfo(
                    database_path=Path(path),
                    source="https://example.invalid/list.json",
                    source_total=1,
                    source_skipped=0,
                    dry_run=False,
                )
                self.assertEqual(info.database_label, expected)

        info = RunInfo(
            database_path=Path("x" * (report_module.MAX_DATABASE_LABEL_CHARS + 10) + ".json"),
            source="https://example.invalid/list.json",
            source_total=1,
            source_skipped=0,
            dry_run=False,
        )
        self.assertEqual(
            info.database_label,
            "X" + "x" * (report_module.MAX_DATABASE_LABEL_CHARS - 1) + "…",
        )

    def test_headlines_name_the_database_and_read_as_sentences(self):
        promote = Change("[U:1:400]", "a", ("suspicious",), ("cheater",), kind="promote")
        demote = Change("[U:1:300]", "b", ("cheater", "racist"), ("racist",), kind="demote")
        rendered = render_report(
            RunInfo(
                database_path=Path("playerlist.garou3299.json"),
                source="https://example.invalid/list.json",
                source_total=1,
                source_skipped=0,
                dry_run=False,
                changes=(promote, demote),
            )
        )
        self.assertIn("**1 entry promoted to `cheater` in the Garou3299 database:**", rendered)
        self.assertIn(
            "**1 entry demoted (present in the previous snapshot, absent from the current "
            "Vorobey hackerpolice list) in the Garou3299 database:**",
            rendered,
        )

    def test_headlines_take_the_database_label(self):
        promote = Change("[U:1:400]", "a", ("suspicious",), ("cheater",), kind="promote")
        demote = Change("[U:1:300]", "b", ("cheater",), (), kind="demote")
        self.assertEqual(
            _promotion_lines([promote], database="Garou3299")[0],
            "**1 entry promoted to `cheater` in the Garou3299 database:**",
        )
        self.assertEqual(
            _demotion_lines([demote], database="Garou3299")[0],
            "**1 entry demoted (present in the previous snapshot, absent from the current "
            "Vorobey hackerpolice list) in the Garou3299 database:**",
        )

    def test_combined_promote_and_demote(self):
        changes = [
            Change("[U:1:400]", "a", ("suspicious",), ("cheater",), kind="promote"),
            Change("[U:1:300]", "b", ("cheater",), (), kind="demote"),
        ]
        self.assertEqual(
            render_closing(changes),
            "Attribute is changed for this SteamID: [U:1:400]; Entry is removed from the database for this SteamID: [U:1:300]; nothing else is modified.",
        )

    def test_no_changes(self):
        self.assertEqual(render_closing([]), "Nothing has changed.")
        self.assertEqual(render_closing([], database="Garou3299"), "In the Garou3299 database: nothing has changed.")

    def test_closing_sentence_is_bounded_for_a_huge_run(self):
        limit = report_module.MAX_CLOSING_STEAMIDS
        at_limit = [Change(f"[U+{n}]", "n", ("suspicious",), ("cheater",)) for n in range(limit)]
        over = [Change(f"[U+{n}]", "n", ("suspicious",), ("cheater",)) for n in range(limit + 25)]
        # At the cap, list every ID without an overflow suffix.
        at_cap = render_closing(at_limit, database="db.json")
        self.assertNotIn("more", at_cap)
        self.assertIn(f"[U+{limit - 1}]", at_cap)  # The final ID is included.
        closing = render_closing(over, database="db.json")
        self.assertIn(" and 25 more", closing)
        self.assertIn(f"[U+{limit - 1}]", closing)  # IDs up to the cap are listed.
        self.assertNotIn(f"[U+{limit}]", closing)  # IDs above the cap are omitted.
        self.assertLess(len(closing), 4_000)

    def test_closing_sentence_counts_hidden_ids_with_thousands_separators(self):
        changes = [Change(f"[U+{n}]", "n", ("cheater",), (), kind="demote") for n in range(1_200)]
        closing = render_closing(changes, database="db.json")
        self.assertIn("and 1,050 more", closing)


class ReportBoundaryTests(unittest.TestCase):
    def _info(self, **kwargs):
        return RunInfo(
            database_path=Path("playerlist.garou3299.json"),
            source="https://example.invalid/list.json",
            source_total=1,
            source_skipped=0,
            dry_run=False,
            **kwargs,
        )

    def test_exactly_the_row_limit_gets_no_overflow_note(self):
        limit = MAX_CHANGE_TABLE_ROWS
        changes = tuple(
            Change(steamid=f"[U:1:{n}]", name="n", before=("suspicious",), after=("cheater",)) for n in range(limit)
        )
        rendered = render_report(self._info(changes=changes))
        self.assertNotIn("more entries not shown", rendered)
        one_more = (*changes, Change(steamid="[U:1:999999]", name="x", before=("suspicious",), after=("cheater",)))
        self.assertIn("1 more entry not shown", render_report(self._info(changes=one_more)))

    def test_body_exactly_at_the_byte_limit_is_untouched(self):
        text = "a" * MAX_REPORT_BYTES
        self.assertEqual(report_module._fit_body(text), text)

    def test_multi_byte_names_cannot_overflow_the_byte_budget(self):
        """GitHub's limit is bytes: 30,000 Cyrillic characters are 60,000 bytes.

        Measuring characters (the old behaviour) would have shipped a body
        twice the allowed size for any database full of non-Latin names.
        """
        text = "\u044b" * (MAX_REPORT_BYTES + 1)
        fitted = report_module._fit_body(text)
        self.assertLessEqual(len(fitted.encode("utf-8")), MAX_REPORT_BYTES)
        self.assertIn("report truncated to fit the pull request body limit", fitted)
        # An exact byte-budget fit must remain unchanged.
        exact = "\u044b" * (MAX_REPORT_BYTES // 2)
        self.assertEqual(report_module._fit_body(exact), exact)

    def test_truncation_helper_handles_a_zero_or_negative_budget(self):
        self.assertEqual(report_module._truncate_to_bytes("abc", 0), "")
        self.assertEqual(report_module._truncate_to_bytes("abc", -5), "")
        # A negative limit means no output, not a slice from the end.
        self.assertEqual(report_module._truncate_to_bytes("abcdefghij", -1), "")
        self.assertEqual(report_module._truncate_to_bytes("abc", 3), "abc")
        self.assertEqual(report_module._truncate_to_bytes("\u044b\u044b", 1), "")  # Do not split a multibyte character.

    def test_truncation_survives_lone_surrogates(self):
        """Measured before the surrogates are replaced, so it must not encode and crash."""
        text = ("\ud800" + "a" * 50) * 2_000
        fitted = report_module._fit_body(text)
        self.assertLessEqual(len(fitted.encode("utf-8", "surrogatepass")), MAX_REPORT_BYTES)

    def test_truncation_keeps_content_when_the_cut_lands_on_the_first_newline(self):
        text = "\n" + "b" * (MAX_REPORT_BYTES + 100)
        fitted = report_module._fit_body(text)
        self.assertLessEqual(len(fitted.encode("utf-8")), MAX_REPORT_BYTES)
        self.assertTrue(fitted.lstrip("\n").startswith("b"), fitted[:20])

    def test_promotions_and_demotions_land_in_their_own_tables(self):
        changes = (
            Change(steamid="[U:1:100]", name="p", before=("suspicious",), after=("cheater",)),
            Change(steamid="[U:1:200]", name="d", before=("cheater", "racist"), after=("racist",), kind="demote"),
        )
        rendered = render_report(self._info(changes=changes))
        promotion_block, demotion_block = rendered.split(" demoted (present in the previous snapshot", 1)
        self.assertIn("[U:1:100]", promotion_block)
        self.assertNotIn("[U:1:200]", promotion_block)
        self.assertIn("[U:1:200]", demotion_block)

    def test_proof_note_only_appears_when_a_link_exists(self):
        with_link = (
            Change(steamid="[U:1:1]", name="n", before=("suspicious",), after=("cheater",), evidence=("https://x",)),
        )
        without = (Change(steamid="[U:1:1]", name="n", before=("suspicious",), after=("cheater",)),)
        self.assertIn("Proof link comes from", render_report(self._info(changes=with_link)))
        self.assertNotIn("Proof link", render_report(self._info(changes=without)))

    def test_proof_note_needs_a_link_in_the_rendered_rows(self):
        """A capped table can hide every link: then there is nothing to annotate.

        The note sits directly under the tables, so a note about a link the
        reader cannot see -- the only proof riding on the row the row cap drops
        -- reads as a promise the report does not keep.
        """
        limit = MAX_CHANGE_TABLE_ROWS

        def promotions(proof_on: int) -> tuple[Change, ...]:
            return tuple(
                Change(
                    steamid=f"[U:1:{n}]",
                    name="n",
                    before=("suspicious",),
                    after=("cheater",),
                    evidence=("https://proof.example/1",) if n == proof_on else (),
                )
                # The range starts at 1; proof_on=0 means no entry has evidence.
                for n in range(1, limit + 2)
            )

        def account_id(steamid: str) -> int:
            return int(steamid.rsplit(":", 1)[1].rstrip("]"))

        bare = render_report(self._info(changes=promotions(0)))
        self.assertNotIn("Proof link", bare)
        shown = [line.split("`")[1] for line in bare.splitlines() if line.startswith("| `[")]
        self.assertEqual(len(shown), limit)
        hidden = next(f"[U:1:{n}]" for n in range(1, limit + 2) if f"[U:1:{n}]" not in shown)

        # This link belongs only to the entry omitted by the row cap.
        dropped = render_report(self._info(changes=promotions(account_id(hidden))))
        self.assertIn("1 more entry not shown", dropped)
        self.assertNotIn("Proof link", dropped)
        # A visible copy of the entry should restore the attribution note.
        kept = render_report(self._info(changes=promotions(account_id(shown[0]))))
        self.assertIn("Proof link comes from", kept)

    def test_multiple_links_use_the_plural_note(self):
        changes = (
            Change(
                steamid="[U:1:1]",
                name="n",
                before=("suspicious",),
                after=("cheater",),
                evidence=("https://x", "https://y"),
            ),
        )
        self.assertIn("Proof links come from", render_report(self._info(changes=changes)))


class ClosingOrderTests(unittest.TestCase):
    def test_closing_sentence_lists_steamids_numerically(self):
        changes = (
            Change(steamid="[U:1:900]", name="c", before=("suspicious",), after=("cheater",)),
            Change(steamid="[U:1:100]", name="a", before=("suspicious",), after=("cheater",)),
        )
        closing = render_closing(changes, database="db.json")
        self.assertIn("these SteamIDs: [U:1:100], [U:1:900];", closing)


class CapBoundaryTests(unittest.TestCase):
    """Every cap is an exact boundary: at the limit unchanged, one over clipped.

    Mutation testing found all of these untested: flipping ``<=`` to ``<`` in
    each of them left the suite green, which is how an off-by-one would ship.
    """

    def test_shown_values_are_exact_at_the_limit(self):
        """The limit applies to the quoted text, i.e. the repr including quotes."""
        at_limit = "x" * (MAX_SHOWN_VALUE_CHARS - 2)
        self.assertEqual(len(repr(at_limit)), MAX_SHOWN_VALUE_CHARS)
        self.assertEqual(playerlist_module._shown(at_limit), repr(at_limit))
        self.assertTrue(playerlist_module._shown(at_limit + "x").endswith("…"))

    def test_shown_large_strings_are_sliced_before_repr(self):
        value = "\n" * (MAX_SHOWN_VALUE_CHARS * 100_000)
        builtin_repr = repr
        seen = []

        def record_repr(argument):
            seen.append(argument)
            return builtin_repr(argument)

        with mock.patch("builtins.repr", side_effect=record_repr):
            shown = playerlist_module._shown(value)
        self.assertLessEqual(len(seen[0]), MAX_SHOWN_VALUE_CHARS)
        self.assertLessEqual(len(shown), MAX_SHOWN_VALUE_CHARS + 1)
        self.assertTrue(shown.endswith("…"))

    def test_shown_json_containers_are_summarized_without_rendering_values(self):
        secret = "DO_NOT_ECHO" * MAX_SHOWN_VALUE_CHARS
        self.assertEqual(playerlist_module._shown({"secret": secret}), "<object with 1 key>")
        self.assertEqual(playerlist_module._shown([secret]), "<array with 1 item>")
        self.assertEqual(playerlist_module._shown(None), "None")

    def test_paths_are_exact_at_the_limit(self):
        at_limit = "/tmp/" + "d" * (MAX_SHOWN_PATH_CHARS - 5)
        self.assertEqual(display_path(at_limit), at_limit)
        self.assertTrue(display_path(at_limit + "d").endswith("…"))

    def test_a_printable_non_ascii_path_stays_readable(self):
        """Only control characters are escaped; ü is a character, not junk."""
        self.assertEqual(display_path("/tmp/über.json"), "/tmp/über.json")
        self.assertEqual(display_path("a\u2028b"), "a\\u2028b")

    def test_a_youtube_link_targets_its_short_form(self):
        """YouTube's own short domain is a faithful alias of the same video.

        The LABEL stays uniform (see below); the TARGET uses the short form, so
        the raw markdown is no longer than it was before and nothing raw sits in
        the visible text.
        """
        for link, expected in (
            ("https://www.youtube.com/watch?v=DXQ5gEDIhzE", "https://youtu.be/DXQ5gEDIhzE"),
            ("https://youtube.com/watch?v=DXQ5gEDIhzE", "https://youtu.be/DXQ5gEDIhzE"),
            ("https://m.youtube.com/watch?v=DXQ5gEDIhzE", "https://youtu.be/DXQ5gEDIhzE"),
            ("http://www.youtube.com/watch?v=DXQ5gEDIhzE&t=42s", "https://youtu.be/DXQ5gEDIhzE?t=42s"),
            ("https://www.youtube.com/watch?v=DXQ5gEDIhzE&list=PLabc&index=3", "https://youtu.be/DXQ5gEDIhzE"),
            ("https://youtu.be/DXQ5gEDIhzE", "https://youtu.be/DXQ5gEDIhzE"),
            ("https://www.youtube.com/shorts/DXQ5gEDIhzE", "https://youtu.be/DXQ5gEDIhzE"),
            ("https://www.youtube.com/embed/DXQ5gEDIhzE", "https://youtu.be/DXQ5gEDIhzE"),
            ("https://www.youtube.com/live/DXQ5gEDIhzE", "https://youtu.be/DXQ5gEDIhzE"),
            ("https://www.youtube.com/v/DXQ5gEDIhzE", "https://youtu.be/DXQ5gEDIhzE"),
        ):
            with self.subTest(link=link):
                self.assertEqual(report_module._youtube_short_url(link), expected)

    def test_a_timestamp_in_the_long_form_is_carried_over(self):
        """A proof is often a specific MOMENT in a long video.

        Dropping the timestamp makes the reviewer hunt for the evidence, so it
        survives the rewrite in every long form (watch, shorts, embed, live, v).
        """
        for link, expected in (
            ("https://www.youtube.com/watch?v=DXQ5gEDIhzE&t=42s", "https://youtu.be/DXQ5gEDIhzE?t=42s"),
            ("https://www.youtube.com/watch?t=42s&v=DXQ5gEDIhzE", "https://youtu.be/DXQ5gEDIhzE?t=42s"),
            ("https://www.youtube.com/watch?v=DXQ5gEDIhzE&t=1m30s", "https://youtu.be/DXQ5gEDIhzE?t=1m30s"),
            ("https://www.youtube.com/watch?v=DXQ5gEDIhzE&t=1h2m3s", "https://youtu.be/DXQ5gEDIhzE?t=1h2m3s"),
            ("https://www.youtube.com/watch?v=DXQ5gEDIhzE&t=90", "https://youtu.be/DXQ5gEDIhzE?t=90"),
            ("https://www.youtube.com/watch?v=DXQ5gEDIhzE&start=90", "https://youtu.be/DXQ5gEDIhzE?start=90"),
            ("https://www.youtube.com/shorts/DXQ5gEDIhzE?t=42s", "https://youtu.be/DXQ5gEDIhzE?t=42s"),
            ("https://www.youtube.com/embed/DXQ5gEDIhzE?t=42s", "https://youtu.be/DXQ5gEDIhzE?t=42s"),
        ):
            with self.subTest(link=link):
                self.assertEqual(report_module._youtube_short_url(link), expected)

    def test_no_timestamp_is_ever_invented(self):
        # The rule is "carry it only if the long form had one".
        for link in (
            "https://www.youtube.com/watch?v=DXQ5gEDIhzE",
            "https://www.youtube.com/watch?v=DXQ5gEDIhzE&si=share-tag",
            "https://www.youtube.com/watch?v=DXQ5gEDIhzE&list=PLabc",
            "https://www.youtube.com/shorts/DXQ5gEDIhzE",
        ):
            with self.subTest(link=link):
                self.assertEqual(report_module._youtube_short_url(link), "https://youtu.be/DXQ5gEDIhzE")

    def test_only_a_real_timestamp_survives_the_rewrite(self):
        # Junk in t=/start= must not be pasted into the rewritten link, and no
        # other query key may ride along with a real timestamp.
        for link in (
            "https://www.youtube.com/watch?v=DXQ5gEDIhzE&t=abc",
            "https://www.youtube.com/watch?v=DXQ5gEDIhzE&t=",
            "https://www.youtube.com/watch?v=DXQ5gEDIhzE&t=42s%20evil",
        ):
            with self.subTest(link=link):
                self.assertEqual(report_module._youtube_short_url(link), "https://youtu.be/DXQ5gEDIhzE")
        mixed = "https://www.youtube.com/watch?v=DXQ5gEDIhzE&t=42s&si=vZ4JnwKUJCx6a1dk&list=PLabc"
        self.assertEqual(report_module._youtube_short_url(mixed), "https://youtu.be/DXQ5gEDIhzE?t=42s")

    def test_a_share_tag_is_dropped_from_every_youtube_spelling(self):
        """``si=`` identifies a share, not evidence, so it never survives.

        The rule is one rule for short and long spellings alike, so the result
        cannot depend on which form the upstream list happened to use.
        """
        for link, expected in (
            ("https://youtu.be/DXQ5gEDIhzE?si=vZ4JnwKUJCx6a1dk", "https://youtu.be/DXQ5gEDIhzE"),
            ("https://www.youtube.com/watch?v=DXQ5gEDIhzE&si=abc", "https://youtu.be/DXQ5gEDIhzE"),
            ("https://youtu.be/DXQ5gEDIhzE?list=PLabc", "https://youtu.be/DXQ5gEDIhzE"),
            ("https://youtu.be/DXQ5gEDIhzE?si=abc&t=abc", "https://youtu.be/DXQ5gEDIhzE"),
        ):
            with self.subTest(link=link):
                self.assertEqual(report_module._youtube_short_url(link), expected)

    def test_a_timestamp_survives_with_or_without_a_share_tag(self):
        # The two examples this rule was written for.
        for link, expected in (
            ("https://youtu.be/DXQ5gEDIhzE?si=oqg7fzNwpk9ivsOm&t=326", "https://youtu.be/DXQ5gEDIhzE?t=326"),
            ("https://youtu.be/DXQ5gEDIhzE?t=326&si=oqg7fzNwpk9ivsOm", "https://youtu.be/DXQ5gEDIhzE?t=326"),
            ("https://youtu.be/DXQ5gEDIhzE?t=326", "https://youtu.be/DXQ5gEDIhzE?t=326"),
            ("https://youtu.be/DXQ5gEDIhzE", "https://youtu.be/DXQ5gEDIhzE"),
            ("https://youtu.be/DXQ5gEDIhzE?t=326#t=326", "https://youtu.be/DXQ5gEDIhzE?t=326"),
        ):
            with self.subTest(link=link):
                self.assertEqual(report_module._youtube_short_url(link), expected)

    def test_the_proof_label_is_proof_when_there_is_exactly_one(self):
        # The rule: one link shows "proof", several show "proof 1", "proof 2", ...
        # regardless of what the link points at.
        for link in (
            "https://discord.com/channels/354/1526",
            "https://www.youtube.com/watch?v=DXQ5gEDIhzE",
            "https://steamcommunity.com/profiles/76561197960265729",
            "https://youtu.be/DXQ5gEDIhzE",
        ):
            with self.subTest(link=link):
                self.assertTrue(report_module._evidence_cell([link]).startswith("[proof]("))

    def test_the_proof_label_is_numbered_when_there_are_several(self):
        discord = "https://discord.com/channels/354/1526"
        youtube = "https://www.youtube.com/watch?v=DXQ5gEDIhzE"
        steam = "https://steamcommunity.com/profiles/76561197960265729"
        for links in (
            [discord, steam],
            [youtube, discord],
            [youtube, discord, steam],
            [youtube, "https://www.youtube.com/watch?v=AAAAAAAAAAA"],
        ):
            with self.subTest(links=links):
                cell = report_module._evidence_cell(links)
                for position in range(1, len(links) + 1):
                    self.assertIn(f"[proof {position}](", cell)
                self.assertNotIn("[proof](", cell)

    def test_every_proof_link_uses_the_same_label_scheme(self):
        """A YouTube link must not carry a different label from a Discord one.

        A per-target label made a YouTube row look different from a Discord row
        even though both are one click away, which is what the uniform rule
        replaced.
        """
        cell = report_module._evidence_cell(
            ["https://www.youtube.com/watch?v=DXQ5gEDIhzE", "https://discord.com/channels/354/1526"]
        )
        self.assertEqual(
            cell,
            "[proof 1](https://youtu.be/DXQ5gEDIhzE), [proof 2](https://discord.com/channels/354/1526)",
        )

    def test_the_visible_text_never_carries_the_raw_url(self):
        cell = report_module._evidence_cell(["https://www.youtube.com/watch?v=DXQ5gEDIhzE&list=SECRETLIST"])
        self.assertNotIn("SECRETLIST", cell)
        self.assertNotIn("youtube.com/watch", cell)

    def test_a_youtube_link_without_one_usable_id_keeps_its_own_target(self):
        for link in (
            "https://www.youtube.com/watch?v=",
            "https://www.youtube.com/watch?list=PLabc",
            "https://www.youtube.com/watch?v=A&v=B",
            "https://www.youtube.com/watch?v=bad!id",
            "https://www.youtube.com/playlist?list=PLabc",
            "https://www.youtube.com/",
            "https://www.youtube.com/watch",
        ):
            with self.subTest(link=link):
                self.assertIsNone(report_module._youtube_short_url(link))
                self.assertEqual(report_module._evidence_cell([link]), f"[proof]({link})")

    def test_a_lookalike_host_keeps_its_own_target(self):
        for link in (
            "https://www.youtube.com.evil.invalid/watch?v=X",
            "https://evil.invalid/youtube.com/watch?v=X",
            "https://notyoutube.com/watch?v=X",
        ):
            with self.subTest(link=link):
                self.assertIsNone(report_module._youtube_short_url(link))

    def test_a_non_http_youtube_value_is_not_rewritten(self):
        for link in ("youtu.be/DXQ5gEDIhzE", "ftp://www.youtube.com/watch?v=X", ""):
            with self.subTest(link=link):
                self.assertIsNone(report_module._youtube_short_url(link))

    def test_an_unparsable_youtube_url_is_left_alone(self):
        # urlsplit raises on a malformed IPv6 authority; the target must not.
        self.assertIsNone(report_module._youtube_short_url("http://[::1youtube.com/watch?v=X"))

    def test_shorten_is_exact_at_the_limit(self):
        self.assertEqual(_shorten("abc", 3), "abc")
        self.assertEqual(_shorten("abcd", 3), "abc…")

    def test_evidence_links_are_exact_at_the_limit(self):
        prefix = "https://example.invalid/"
        link = prefix + "x" * (MAX_EVIDENCE_LINK_CHARS - len(prefix))
        self.assertEqual(len(link), MAX_EVIDENCE_LINK_CHARS)
        self.assertIn("](", report_module._evidence_cell([link]))  # A valid link.
        longer = link + "x"
        self.assertNotIn("](", report_module._evidence_cell([longer]))  # Plain text, not a link.

    def test_redact_url_is_exact_at_the_display_limit(self):
        prefix = "https://example.invalid/"
        url = prefix + "x" * (sources.MAX_URL_DISPLAY_CHARS - len(prefix))
        self.assertEqual(sources.redact_url(url), url)
        self.assertTrue(sources.redact_url(url + "x").endswith("…"))

    def test_the_database_file_limit_is_exact(self):
        body = b'{"players": []}'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "list.json"
            path.write_bytes(body + b" " * (200 - len(body)))
            with mock.patch.object(playerlist_module, "MAX_FILE_BYTES", 200):
                database, _ = load(path)
                self.assertEqual(database["players"], [])
                path.write_bytes(body + b" " * (201 - len(body)))
                with self.assertRaises(PlayerListError):
                    load(path)

    def test_the_snapshot_file_limit_is_exact(self):
        body = b'{"players": [{"steamid": "[U:1:1]"}]}'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snap.json"
            path.write_bytes(body + b" " * (200 - len(body)))
            with mock.patch.object(sources, "MAX_FILE_BYTES", 200):
                index, raw = sources.load_snapshot(path)
                self.assertEqual(len(index.by_steamid), 1)
                self.assertEqual(raw, body + b" " * (200 - len(body)))
                path.write_bytes(body + b" " * (201 - len(body)))
                with self.assertRaises(SyncError):
                    sources.load_snapshot(path)

    def test_a_body_of_exactly_the_budget_is_not_touched(self):
        """Exactly at the limit is a fit, not an overflow.

        Enough rows that shrinking would visibly change the report, so an
        off-by-one here cannot hide behind a table that was short anyway.
        """
        changes = tuple(Change(f"[U:1:{number}]", "name", ("suspicious",), ("cheater",)) for number in range(1, 151))
        info = RunInfo(
            database_path=Path("playerlist.garou3299.json"),
            source="https://example.invalid/list.json",
            source_total=10,
            source_skipped=0,
            dry_run=False,
            changes=changes,
        )
        full = render_report(info)
        self.assertEqual(full.count("| `[U:1:"), 150)  # No entries were dropped.
        budget = len(full.encode("utf-8"))
        with mock.patch.object(report_module, "MAX_REPORT_BYTES", budget):
            self.assertEqual(render_report(info), full)  # Exact fit: no shrink or truncation.


class RenderMemoTests(unittest.TestCase):
    """The per-run proof-link memo must never change what the report says."""

    def test_a_link_is_redacted_once_across_repeated_renders(self):
        """Redacting a proof link twice for the same report is wasted work.

        Redaction is the most expensive step in the renderer (it parses and
        re-encodes URLs, decodes entities and walks nested layers) and it is a
        pure function of the link text, so a second sighting must reuse the first
        answer rather than recompute it.
        """
        change = Change(
            "[U:1:1]",
            "name",
            ("suspicious",),
            ("cheater",),
            evidence=("https://example.invalid/watch?t=1",),
        )
        report_module._EVIDENCE_STATUS_CACHE.clear()
        with mock.patch.object(
            report_module, "_evidence_link_status", wraps=report_module._evidence_link_status
        ) as redaction:
            for _ in range(3):
                report_module._evidence_cell(change.evidence)
        report_module._EVIDENCE_STATUS_CACHE.clear()
        self.assertEqual(redaction.call_count, 1)

    def test_the_memo_stops_growing_at_its_bound(self):
        """A list full of distinct links cannot grow the memo without limit.

        Past the bound, lookups still answer correctly -- they are simply not
        retained -- so a report larger than the bound loses speed, never accuracy.
        """
        link_a, link_b = "https://a.invalid/1", "https://b.invalid/2"
        with mock.patch.object(report_module, "_MAX_EVIDENCE_STATUS_CACHE", 1):
            report_module._EVIDENCE_STATUS_CACHE.clear()
            first = report_module._evidence_link_status_cached(link_a)
            overflow = report_module._evidence_link_status_cached(link_b)
            self.assertEqual(len(report_module._EVIDENCE_STATUS_CACHE), 1)
        report_module._EVIDENCE_STATUS_CACHE.clear()

        self.assertEqual(first, report_module._evidence_link_status(link_a))
        self.assertEqual(overflow, report_module._evidence_link_status(link_b))

    def test_render_report_leaves_no_proof_text_in_the_memo(self):
        """The memo is per-report state, not a cache that outlives the run."""
        info = RunInfo(
            database_path=Path("playerlist.garou3299.json"),
            source="https://example.invalid/list.json",
            source_total=1,
            source_skipped=0,
            dry_run=False,
            changes=(Change("[U:1:1]", "name", ("suspicious",), ("cheater",), evidence=("https://e.invalid/1",)),),
        )
        render_report(info)
        self.assertEqual(report_module._EVIDENCE_STATUS_CACHE, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
