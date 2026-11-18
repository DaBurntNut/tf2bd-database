#!/usr/bin/env python3
"""Tests for the Vorobey hackerpolice sync tool."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import random
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from _support import (
    HACKERPOLICE_PROOF,
    hackerpolice_entry,
    index_of,
    player,
)

import policy
import sync_vorobey_hackerpolice as sync_module
from playerlist import (
    dumps,
    normalize_steamid,
    order_attributes,
    validate,
)
from policy import demote, is_racist_proof, promote, sync
from sources import (
    HackerpoliceIndex,
    added_steamids,
    removed_steamids,
)
from sync_vorobey_hackerpolice import main


class MassDemotionGuardTests(unittest.TestCase):
    """The two thresholds that stop a broken upstream list from un-banning everyone.

    Both operands matter: the absolute floor (more than 50 IDs) and the
    fraction (more than 20% of the snapshot). An inverted comparison in either
    one would either let a mass unban through or block every ordinary removal.
    """

    @staticmethod
    @contextlib.contextmanager
    def quiet():
        """Silence the policy's logging; these tests assert on what it returns."""
        with mock.patch.object(sync_module.LOGGER, "info"), mock.patch.object(sync_module.LOGGER, "warning"):
            yield

    def plan(self, removed_count, snapshot_entries, *, demote=True, allow=False, no_update=False, impact=(0, 0)):
        args = SimpleNamespace(demote=demote, allow_mass_demotion=allow, no_update_snapshot=no_update)
        previous = index_of(*[hackerpolice_entry(f"[U:1:{1000 + n}]") for n in range(snapshot_entries)])
        removed = {f"[U:1:{1000 + n}]" for n in range(removed_count)}
        with self.quiet():
            return sync_module._plan_demotion(args, previous, removed, Path("snapshot.json"), demotion_impact=impact)

    def test_a_purge_of_the_databases_own_cheaters_is_vetoed(self):
        # Modelled on the real baseline: 108 demotable cheaters against 5,574
        # snapshot entries. The snapshot-relative rule alone let a purge of every
        # tracked cheater look harmless -- 108/5,574 is 1.9%, well under the 20%
        # threshold -- so the database-relative rule exists to catch it.
        removed, update_snapshot, note, snapshot_note = self.plan(108, 5574, impact=(108, 108))
        self.assertEqual(removed, set())
        self.assertFalse(update_snapshot)
        self.assertIn("looks like an upstream problem", note)
        self.assertIn("not refreshed", snapshot_note)

    def test_the_smallest_purge_that_matters_is_still_caught(self):
        # 25% of 108 tracked cheaters is 27, so the guard trips once past it.
        for removed_count, expected_veto in ((27, False), (28, True)):
            with self.subTest(removed=removed_count):
                removed, _, note, _ = self.plan(removed_count, 5574, impact=(removed_count, 108))
                self.assertEqual(bool(note), expected_veto)
                self.assertEqual(len(removed), 0 if expected_veto else removed_count)

    def test_a_tiny_purge_does_not_trip_the_database_guard(self):
        # A handful of real removals is ordinary news, not an upstream accident.
        removed, update_snapshot, note, _ = self.plan(4, 5574, impact=(4, 108))
        self.assertEqual(len(removed), 4)
        self.assertTrue(update_snapshot)
        self.assertIsNone(note)

    def test_the_database_guard_needs_something_to_guard(self):
        # With no demotable entries there is nothing to protect, so the
        # database-relative rule stays quiet and only the snapshot rule applies.
        self.assertFalse(sync_module._looks_like_mass_removal(40, 5574, 0, 0))
        self.assertTrue(sync_module._looks_like_mass_removal(2000, 5574, 0, 0))

    def test_the_guard_reports_how_much_of_the_database_is_at_stake(self):
        self.assertIn("26% of the 108 cheater(s)", sync_module._demotion_scale(28, 108))
        self.assertIn("no tracked cheaters", sync_module._demotion_scale(9, 0))
        # Never claim more than the whole database.
        self.assertIn("100%", sync_module._demotion_scale(500, 108))

    def test_removals_beyond_the_demotable_count_are_still_measured(self):
        # More removals than demotable entries cannot happen in a real run (sync
        # drops IDs upstream still lists), but the guard must not under-report.
        self.assertTrue(sync_module._looks_like_mass_removal(60, 5574, 60, 20))

    def test_the_demotion_impact_counts_only_entries_upstream_could_ever_demote(self):
        """A hand-added cheater upstream never listed is never demoted.

        Counting those would overstate the blast radius and veto harmless runs.
        """
        database = {
            "players": [
                player("[U:1:1]", ["cheater"]),  # in previous snapshot -> at risk
                player("[U:1:2]", ["cheater"]),  # never known to upstream -> exonerated
                player("[U:1:3]", ["racist"]),  # no cheater tag -> untouched
                player("[U:1:4]", ["cheater", "racist"]),  # in snapshot -> at risk
                {"attributes": ["cheater"]},  # unusable SteamID -> skipped
                {"steamid": "[U:1:5]", "attributes": "cheater"},  # malformed attributes
                "not an entry",
            ]
        }
        previous = index_of(hackerpolice_entry("[U:1:1]"), hackerpolice_entry("[U:1:4]"), hackerpolice_entry("[U:1:9]"))
        # 1 and 4 are at risk; only 1 is actually removed this run.
        self.assertEqual(sync_module._demotion_impact(database, {"[U:1:1]"}, previous), (1, 2))

    def test_the_impact_uses_the_previous_snapshot_not_the_current_list(self):
        """Demotion targets are by definition MISSING from the current list.

        Measuring against the current index collapsed the denominator to zero
        exactly when a purge was largest -- the guard went blind on the only
        case it exists to catch. This pins the fix.
        """
        database = {"players": [player(f"[U:1:{n}]", ["cheater"]) for n in range(1, 11)]}
        previous = index_of(*[hackerpolice_entry(f"[U:1:{n}]") for n in range(1, 11)])
        removed = {f"[U:1:{n}]" for n in range(1, 11)}
        to_demote, at_risk = sync_module._demotion_impact(database, removed, previous)
        self.assertEqual((to_demote, at_risk), (10, 10))
        # Every tracked cheater gone at once is still caught.
        self.assertTrue(sync_module._looks_like_mass_removal(to_demote, 5574, to_demote, at_risk))

    def test_the_impact_tolerates_a_malformed_database(self):
        self.assertEqual(sync_module._demotion_impact({"players": "nope"}, {"[U:1:1]"}, index_of()), (0, 0))

    def test_exactly_fifty_removals_are_not_a_mass_removal(self):
        # Exactly 50 stays below the guard; the count must exceed 50.
        removed, update_snapshot, note, _ = self.plan(50, 100)
        self.assertEqual(len(removed), 50)
        self.assertTrue(update_snapshot)
        self.assertIsNone(note)

    def test_fifty_one_removals_trip_the_guard(self):
        removed, update_snapshot, note, snapshot_note = self.plan(51, 100)
        self.assertEqual(removed, set())
        self.assertFalse(update_snapshot)
        self.assertIn("disappeared upstream at once", note)
        self.assertIn("not refreshed", snapshot_note)

    def test_many_removals_from_a_large_snapshot_are_normal(self):
        # 100 exceeds the count floor but is only 10% of this snapshot.
        removed, update_snapshot, note, _ = self.plan(100, 1000)
        self.assertEqual(len(removed), 100)
        self.assertTrue(update_snapshot)
        self.assertIsNone(note)

    def test_the_fraction_threshold_alone_can_trip_the_guard(self):
        # 201 of 1,000 exceeds the 20% threshold.
        removed, update_snapshot, note, _ = self.plan(201, 1000)
        self.assertEqual(removed, set())
        self.assertFalse(update_snapshot)
        self.assertIn("disappeared upstream at once", note)

    def test_exactly_twenty_percent_does_not_trip_the_guard(self):
        removed, update_snapshot, _, note = self.plan(200, 1000)
        self.assertEqual(len(removed), 200)
        self.assertTrue(update_snapshot)
        self.assertIsNone(note)

    def test_the_override_forces_a_mass_removal_through(self):
        removed, update_snapshot, note, _ = self.plan(51, 100, allow=True)
        self.assertEqual(len(removed), 51)
        self.assertTrue(update_snapshot)
        self.assertIsNone(note)

    def test_demotion_without_a_snapshot_cannot_prove_anything(self):
        args = SimpleNamespace(demote=True, allow_mass_demotion=False, no_update_snapshot=False)
        with self.quiet():
            removed, update_snapshot, note, _ = sync_module._plan_demotion(
                args, None, {"[U:1:1]"}, Path("snapshot.json")
            )
        self.assertEqual(removed, set())
        self.assertTrue(update_snapshot)
        self.assertIn("no snapshot at snapshot.json", note)

    def test_unusable_current_entries_hold_back_demotions_and_the_snapshot(self):
        args = SimpleNamespace(demote=True, allow_mass_demotion=False, no_update_snapshot=False)
        previous = index_of(*[hackerpolice_entry(f"[U:1:{1000 + n}]") for n in range(10)])
        with self.quiet():
            removed, update_snapshot, note, snapshot_note = sync_module._plan_demotion(
                args,
                previous,
                {"[U:1:1000]"},
                Path("snapshot.json"),
                source_skipped=1,
            )
        self.assertEqual(removed, set())
        self.assertFalse(update_snapshot)
        self.assertIn("1 unusable SteamID entry", note)
        self.assertIn("cannot be confirmed safely", note)
        self.assertIn("demotion candidates", snapshot_note)

        # Skipped input matters only when removals need confirmation.
        with self.quiet():
            _, update_snapshot, note, _ = sync_module._plan_demotion(
                args, previous, set(), Path("snapshot.json"), source_skipped=1
            )
        self.assertTrue(update_snapshot)
        self.assertIsNone(note)

    def test_demotion_disabled_keeps_the_baseline(self):
        removed, update_snapshot, note, snapshot_note = self.plan(3, 10, demote=False)
        self.assertEqual(removed, set())
        self.assertFalse(update_snapshot)
        self.assertIsNone(note)
        self.assertIn("demotion is disabled", snapshot_note)

    def test_no_update_snapshot_is_reported(self):
        _, update_snapshot, _, snapshot_note = self.plan(0, 10, demote=False, no_update=True)
        self.assertFalse(update_snapshot)
        self.assertIn("--no-update-snapshot", snapshot_note)

    def test_pending_removals_are_the_more_useful_reason_to_show(self):
        # Prefer reporting pending removals over the no-update flag; reviewers need the reason.
        _, update_snapshot, _, snapshot_note = self.plan(1, 10, demote=False, no_update=True)
        self.assertFalse(update_snapshot)
        self.assertIn("could not be applied", snapshot_note)


class PromoteTests(unittest.TestCase):
    def setUp(self):
        self.index = index_of(
            hackerpolice_entry("[U:1:100]", [HACKERPOLICE_PROOF]),
            hackerpolice_entry("[U:1:200]"),
            hackerpolice_entry("[U:1:300]"),
            hackerpolice_entry("[U:1:400]"),
            hackerpolice_entry("STEAM_0:0:250"),
        )

    def promote(self, players, **kwargs):
        database = {"$schema": "x", "file_info": {"title": "t"}, "players": players}
        return database, promote(database, self.index, **kwargs)

    def test_suspicious_becomes_cheater_without_touching_proof(self):
        database, changes = self.promote([player("[U:1:100]", ["suspicious"])])
        self.assertEqual(database["players"][0]["attributes"], ["cheater"])
        self.assertNotIn("proof", database["players"][0])
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].evidence, (HACKERPOLICE_PROOF,))
        self.assertEqual(changes[0].before, ("suspicious",))
        self.assertEqual(changes[0].after, ("cheater",))

    def test_the_three_rules(self):
        """The policy, exactly as specified:

        suspicious              -> cheater
        racist                  -> cheater + racist
        suspicious + racist     -> cheater + racist
        """
        cases = [
            (["suspicious"], ["cheater"]),
            (["racist"], ["cheater", "racist"]),
            (["suspicious", "racist"], ["cheater", "racist"]),
        ]
        for before, expected in cases:
            with self.subTest(before=before):
                database, changes = self.promote([player("[U:1:200]", before)])
                self.assertEqual(database["players"][0]["attributes"], expected)
                self.assertEqual(len(changes), 1)
                self.assertNotIn("proof", database["players"][0])

    def test_attribute_order_is_normalised(self):
        database, _ = self.promote([player("[U:1:300]", ["racist", "suspicious"])])
        self.assertEqual(database["players"][0]["attributes"], ["cheater", "racist"])

    def test_promotion_cannot_write_a_proof_at_all(self):
        """The capability is gone, not merely switched off.

        ``--include-proof`` was removed so a promotion can never add a proof
        line: the parameter does not exist, and passing it is a TypeError.
        """
        with self.assertRaises(TypeError):
            policy.promote({"players": []}, index_of(), include_proof=True)
        self.assertFalse(hasattr(policy, "_write_proof"))
        self.assertFalse(hasattr(policy, "MAX_EMBEDDED_PROOFS"))

    def test_membership_alone_decides_regardless_of_upstream_attributes(self):
        """The Vorobey list is cheater-only and always will be.

        Because of that, the policy never reads an upstream entry's
        attributes: being listed is the whole signal. A missing, empty or
        unexpected attribute list changes nothing -- the ID is promoted.
        """
        for attributes in (["cheater"], [], ["cheater", "racist"], None, ["something-unexpected"]):
            entry = {"steamid": "[U:1:100]", "last_seen": {"time": 1}}
            if attributes is not None:
                entry["attributes"] = attributes
            database = {"players": [player("[U:1:100]", ["suspicious"])]}
            promote(database, index_of(entry))
            self.assertEqual(
                database["players"][0]["attributes"],
                ["cheater"],
                f"upstream attributes {attributes!r} changed the verdict",
            )

    def test_already_cheater_is_untouched(self):
        database, changes = self.promote([player("[U:1:400]", ["cheater", "racist"], proof=["keep me"])])
        self.assertEqual(database["players"][0]["attributes"], ["cheater", "racist"])
        self.assertEqual(database["players"][0]["proof"], ["keep me"])
        self.assertEqual(changes, [])

    def test_other_attributes_and_non_matches_are_untouched(self):
        database, changes = self.promote([player("[U:1:100]", ["exploiter"]), player("[U:1:999]", ["suspicious"])])
        self.assertEqual(database["players"][0]["attributes"], ["exploiter"])
        self.assertEqual(database["players"][1]["attributes"], ["suspicious"])
        self.assertEqual(changes, [])

    def test_malformed_entries_are_skipped_not_fatal(self):
        broken_attributes = {"attributes": "suspicious", "steamid": "[U:1:300]"}
        broken_last_seen = {"attributes": ["suspicious"], "last_seen": "never", "steamid": "[U:1:100]"}
        database, changes = self.promote([broken_attributes, broken_last_seen])
        players = {entry["steamid"]: entry for entry in database["players"]}

        self.assertEqual(players["[U:1:300]"]["attributes"], "suspicious")
        self.assertEqual(players["[U:1:100]"]["attributes"], ["cheater"])
        self.assertEqual(changes[0].name, "")

    def test_alternate_steamid_notation_matches(self):
        database, changes = self.promote([player("STEAM_0:0:250", ["suspicious"])])
        self.assertEqual(database["players"][0]["attributes"], ["cheater"])
        self.assertEqual(len(changes), 1)

    def test_players_end_up_in_steamid_order(self):
        database = {
            "$schema": "x",
            "file_info": {"title": "t"},
            "players": [
                player("[U:1:20]", ["cheater"]),
                player("[U:1:3]", ["cheater"]),
            ],
        }
        sync(database, self.index)
        self.assertEqual([p["steamid"] for p in database["players"]], ["[U:1:3]", "[U:1:20]"])


class RemovedSteamIdsTests(unittest.TestCase):
    def test_removed_is_previous_minus_current(self):
        previous = index_of(hackerpolice_entry("[U:1:100]"), hackerpolice_entry("[U:1:200]"))
        current = index_of(hackerpolice_entry("[U:1:200]"), hackerpolice_entry("[U:1:300]"))
        # Only previous-minus-current IDs qualify; new and never-listed IDs do not.
        self.assertEqual(removed_steamids(previous, current), {"[U:1:100]"})

    def test_added_is_current_minus_previous(self):
        previous = index_of(hackerpolice_entry("[U:1:100]"), hackerpolice_entry("[U:1:200]"))
        current = index_of(hackerpolice_entry("[U:1:200]"), hackerpolice_entry("[U:1:300]"))
        self.assertEqual(added_steamids(previous, current), {"[U:1:300]"})
        self.assertEqual(added_steamids(current, current), set())


class DemoteTests(unittest.TestCase):
    """Demotion applies ONLY to IDs handed in as removed upstream."""

    # [U:1:200] disappeared upstream; [U:1:100] remains listed.
    REMOVED = frozenset({"[U:1:200]"})

    def setUp(self):
        self.index = index_of(hackerpolice_entry("[U:1:100]", [HACKERPOLICE_PROOF]))

    def demote(self, players):
        database = {"$schema": "x", "file_info": {"title": "t"}, "players": players}
        return database, demote(database, self.REMOVED)

    def test_cheater_and_racist_removes_cheater_keeps_racist(self):
        database, changes = self.demote([player("[U:1:200]", ["cheater", "racist"])])
        self.assertEqual(database["players"][0]["attributes"], ["racist"])
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].kind, "demote")
        self.assertEqual(changes[0].before, ("cheater", "racist"))
        self.assertEqual(changes[0].after, ("racist",))

    def test_cheater_and_racist_drops_cheater_proof_keeps_racist_proof(self):
        database, _ = self.demote(
            [
                player(
                    "[U:1:200]",
                    ["cheater", "racist"],
                    proof=[
                        "Silent Aim & ESP. Cheating proof.",
                        '[auto] automatically marked: Racist | reason: "nigga stop afk"',
                    ],
                )
            ]
        )
        proofs = database["players"][0]["proof"]
        self.assertEqual(len(proofs), 1)
        self.assertIn("Racist", proofs[0])
        self.assertNotIn("Silent Aim", proofs[0])
        self.assertNotIn("ESP", proofs[0])

    def test_cheater_and_racist_drops_all_proofs_when_none_are_racist(self):
        database, _ = self.demote(
            [
                player(
                    "[U:1:200]",
                    ["cheater", "racist"],
                    proof=["Silent Aim & ESP.", "Some other cheating evidence"],
                )
            ]
        )
        # Omit the key when no proofs survive; absence represents no proof in this database.
        self.assertNotIn("proof", database["players"][0])

    def test_cheater_and_racist_keeps_only_auto_racist_prefixed_proofs(self):
        """Multiple proofs: ONLY lines starting with the exact
        '[auto] automatically marked: Racist | reason:' prefix survive.
        A proof merely mentioning racism, a video link, or a cheating
        description is dropped along with the false-positive cheater tag."""
        kept = [
            '[auto] automatically marked: Racist | reason: "slur one"',
            '[auto] automatically marked: Racist | reason: "slur two"',
        ]
        database, _ = self.demote(
            [
                player(
                    "[U:1:200]",
                    ["cheater", "racist"],
                    proof=[
                        "https://youtu.be/cheating-video",
                        kept[0],
                        "Racist behavior in voice chat",
                        "Silent Aim & ESP",
                        kept[1],
                        '[auto] automatically marked: Cheater | reason: "aimbot"',
                    ],
                )
            ]
        )
        self.assertEqual(database["players"][0]["proof"], kept)

    def test_racist_proof_matching_ignores_case_and_padding(self):
        """A future tool writing "[AUTO] Automatically marked: RACIST ..."
        must not lose the line that justifies the surviving racist tag."""
        kept = '  [AUTO] Automatically marked: RACIST | reason: "slur"  '
        database, _ = self.demote([player("[U:1:200]", ["cheater", "racist"], proof=[kept, "Silent Aim & ESP"])])
        self.assertEqual(database["players"][0]["proof"], [kept])

    def test_a_truncated_auto_line_is_not_a_machine_record(self):
        """The reason must end with its closing quote, not merely contain one."""
        prefix = '[auto] automatically marked: Racist | reason: "'
        self.assertFalse(is_racist_proof(prefix))
        self.assertFalse(is_racist_proof("[auto] automatically marked: Racist | reason:"))
        self.assertFalse(is_racist_proof(prefix + 'a "quoted" word but no final delimiter'))
        for separator in ("\n", "\r", "\u2028", "\u0085"):
            with self.subTest(separator=repr(separator)):
                self.assertFalse(is_racist_proof(prefix + 'legitimate reason"' + separator + 'appended proof "'))
        # A closed empty reason still matches the stored format.
        self.assertTrue(is_racist_proof(prefix + '"'))

    def test_is_racist_proof(self):
        self.assertTrue(is_racist_proof('[auto] automatically marked: Racist | reason: "x"'))
        # Matching trims surrounding whitespace and ignores case.
        self.assertTrue(is_racist_proof('  [AUTO] Automatically marked: RACIST | reason: "x"  '))
        for value in (
            '[auto] automatically marked: Cheater | reason: "aimbot"',
            # Unicode long-s casefolds to ASCII "s", but is not part of the machine format.
            '[auto] automatically marked: Raciſt | reason: "spoofed prefix"',
            "https://youtu.be/x",
            "Racist behavior in voice chat",
            "[auto] automatically marked: Racist",
            "",
            # The opening quote is part of the prefix; incomplete or unquoted reasons are rejected.
            "[auto] automatically marked: Racist | reason:",
            "[auto] automatically marked: Racist | reason: no quotes here",
            '[auto] automatically marked: Racist | reason:"x"',
        ):
            self.assertFalse(is_racist_proof(value), value)

    def test_demotion_keeps_only_proofs_starting_with_the_full_racist_prefix(self):
        """Owner's rule: the tag goes, and so does every proof that is not a
        complete ``[auto] automatically marked: Racist | reason: "..."`` line."""
        kept = '[auto] automatically marked: Racist | reason: "slur in chat"'
        database, changes = self.demote(
            [
                player(
                    "[U:1:200]",
                    ["cheater", "racist"],
                    proof=[
                        kept,
                        "https://youtu.be/cheating-video",
                        "Silent Aim & ESP",
                        "Racist behavior in voice chat",
                        '[auto] automatically marked: Racist | reason: "legitimate chat"\n[manual] cheating proof "',
                        "[auto] automatically marked: Racist | reason:",  # Missing closing quote.
                        "[auto] automatically marked: Racist | reason: no quotes",
                    ],
                )
            ]
        )
        self.assertEqual(database["players"][0]["attributes"], ["racist"])
        self.assertEqual(database["players"][0]["proof"], [kept])
        self.assertEqual([change.kind for change in changes], ["demote"])

    def test_cheater_and_racist_with_non_list_proof_drops_the_proof(self):
        database, _ = self.demote([player("[U:1:200]", ["cheater", "racist"], proof="Silent Aim & ESP")])
        self.assertEqual(database["players"][0]["attributes"], ["racist"])
        self.assertNotIn("proof", database["players"][0])

    def test_cheater_only_removes_whole_entry(self):
        database, changes = self.demote([player("[U:1:200]", ["cheater"])])
        self.assertEqual(database["players"], [])
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].kind, "demote")
        self.assertEqual(changes[0].before, ("cheater",))
        self.assertEqual(changes[0].after, ())

    def test_cheater_and_exploiter_removes_whole_entry(self):
        database, changes = self.demote([player("[U:1:200]", ["cheater", "exploiter"])])
        self.assertEqual(database["players"], [])
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].kind, "demote")

    def test_still_on_hackerpolice_list_is_untouched(self):
        database, changes = self.demote([player("[U:1:100]", ["cheater", "racist"])])
        self.assertEqual(database["players"][0]["attributes"], ["cheater", "racist"])
        self.assertEqual(changes, [])

    def test_cheater_never_listed_upstream_is_untouched(self):
        """The original bug: a manually added cheater absent from BOTH the
        snapshot and the current list must survive demotion."""
        database, changes = self.demote([player("[U:1:999]", ["cheater"]), player("[U:1:998]", ["cheater", "racist"])])
        self.assertEqual(len(database["players"]), 2)
        self.assertEqual(changes, [])

    def test_empty_removed_set_demotes_nobody(self):
        database = {"$schema": "x", "file_info": {"title": "t"}, "players": [player("[U:1:200]", ["cheater"])]}
        self.assertEqual(sync(database, self.index, enable_demote=True), [])
        self.assertEqual(len(database["players"]), 1)

    def test_sync_never_demotes_when_the_caller_forgets_enable_demote(self):
        """Defence in depth: removals without the flag demote nobody.

        The CLI never gets here (it empties the set when --demote is off), but a
        future caller that hands over removed_ids and forgets the flag must not
        be able to delete entries by accident.
        """
        database = {"$schema": "x", "file_info": {"title": "t"}, "players": [player("[U:1:200]", ["cheater"])]}
        self.assertEqual(sync(database, self.index, removed_ids={"[U:1:200]"}), [])
        self.assertEqual(database["players"][0]["attributes"], ["cheater"])

    def test_not_a_cheater_is_untouched(self):
        database, changes = self.demote([player("[U:1:200]", ["suspicious"])])
        self.assertEqual(database["players"][0]["attributes"], ["suspicious"])
        self.assertEqual(changes, [])

    def test_racist_without_cheater_is_untouched(self):
        database, changes = self.demote([player("[U:1:200]", ["racist"])])
        self.assertEqual(database["players"][0]["attributes"], ["racist"])
        self.assertEqual(changes, [])

    def test_players_end_up_in_steamid_order(self):
        database = {
            "$schema": "x",
            "file_info": {"title": "t"},
            "players": [
                player("[U:1:200]", ["cheater"]),
                player("[U:1:20]", ["cheater", "racist"]),
                player("[U:1:100]", ["cheater", "racist"]),
            ],
        }
        sync(database, self.index, enable_demote=True, removed_ids={"[U:1:20]", "[U:1:200]"})
        steamids = [p["steamid"] for p in database["players"]]
        self.assertEqual(steamids, ["[U:1:20]", "[U:1:100]"])


class MalformedProofTests(unittest.TestCase):
    """``_filter_racist_proofs`` promises an empty list for a non-list proof."""

    def test_a_malformed_proof_is_dropped_rather_than_iterated(self):
        """A public entry point keeps its documented contract.

        ``validate()`` refuses such a file before a real run reaches here, but
        ``demote`` is exported and the docstring promises this: without the
        guard an int proof raised TypeError and a dict proof iterated its keys.
        """
        for proof in (5, 5.5, {"a": 1}, "a string", None, True):
            with self.subTest(proof=proof):
                player = {"steamid": "[U:1:1]", "attributes": ["cheater", "racist"], "proof": proof}
                changes = policy.demote({"players": [player]}, ["[U:1:1]"])
                self.assertEqual(player["attributes"], ["racist"])
                self.assertNotIn("proof", player)  # No proofs remain; remove the key.
                self.assertEqual([change.kind for change in changes], ["demote"])


class PolicyPropertyTests(unittest.TestCase):
    """Seeded property test over arbitrary databases and upstream states.

    The rules are re-derived here from the spec (not from the implementation),
    and a second run must always be a no-op: that is what keeps the daily bot
    from churning the file.
    """

    RACIST_LINE = '[auto] automatically marked: Racist | reason: "whatever"'

    def test_random_databases_satisfy_the_rules(self):
        rng = random.Random(20261114)
        tags = ("cheater", "suspicious", "exploiter", "racist")
        for _ in range(250):
            accounts = rng.sample(range(2, 300), rng.randint(0, 20))
            players: list = []
            listed: set = set()
            removed: set = set()
            for account in accounts:
                steamid = f"[U:1:{account}]"
                entry = player(steamid, rng.sample(tags, rng.randint(0, 3)), last_seen={"time": 1})
                if rng.random() < 0.4:
                    entry["proof"] = rng.choice(
                        [[self.RACIST_LINE], ["https://y"], [self.RACIST_LINE, "https://y"], []]
                    )
                players.append(entry)
                if rng.random() < 0.4:
                    listed.add(steamid)
                if rng.random() < 0.3:
                    removed.add(steamid)

            index = index_of(*[hackerpolice_entry(steamid) for steamid in listed])
            database = {"players": copy.deepcopy(players)}
            sync(database, index, enable_demote=True, removed_ids=removed)

            after = {normalize_steamid(entry["steamid"]): entry for entry in database["players"]}
            self.assertEqual(len(after), len(database["players"]), "duplicated entry after sync")
            for original in players:
                steamid = original["steamid"]
                was, has = set(original["attributes"]), "cheater" in original["attributes"]
                entry = after.get(steamid)
                if not was:
                    # Malformed entries stay unchanged; the CLI rejects them before writing.
                    self.assertEqual(entry, original)
                    continue
                if steamid in listed and has:
                    # Still listed upstream: never demote, even if also in removed_ids.
                    self.assertEqual(entry, original)
                elif steamid in listed and was & {"suspicious", "racist"}:
                    # Promotion adds cheater, removes suspicious, and preserves other fields.
                    # Existing proofs are not added or rewritten.
                    self.assertEqual(entry["attributes"], order_attributes((was | {"cheater"}) - {"suspicious"}))
                    self.assertEqual(entry["last_seen"], original["last_seen"])
                    self.assertEqual(entry.get("proof"), original.get("proof"), "promotion changed the proofs")
                elif steamid in removed and has and "racist" not in was:
                    # Removed upstream without racist: remove the full entry.
                    self.assertIsNone(entry)
                elif steamid in removed and has:
                    # Remove cheater, retain other attributes, and keep only automatic racist proofs.
                    self.assertEqual(entry["attributes"], order_attributes(was - {"cheater"}))
                    if "proof" in original:
                        kept = [line for line in original["proof"] if isinstance(line, str) and is_racist_proof(line)]
                        if kept:
                            self.assertEqual(entry["proof"], kept)
                        else:
                            self.assertNotIn(
                                "proof", entry, "an empty proof array is not how this file says 'no proof'"
                            )
                else:
                    self.assertEqual(entry, original, "an unrelated entry was modified")

            settled = dumps(database)
            self.assertEqual(sync(database, index, enable_demote=True, removed_ids=removed), [])
            self.assertEqual(dumps(database), settled, "a second run changed the database")


class EvidenceTests(unittest.TestCase):
    def test_evidence_ignores_non_strings_and_blank_entries(self):
        index = index_of(hackerpolice_entry("[U:1:100]", [1, "  ", None, "https://x", "https://x"]))
        database = {"players": [player("[U:1:100]", ["suspicious"])]}
        changes = promote(database, index)
        self.assertEqual(changes[0].evidence, ("https://x",))  # Deduplicate links; ignore invalid proof values.
        self.assertEqual(changes[0].evidence_omitted, 0)

    def test_a_change_retains_only_the_evidence_the_report_can_show(self):
        links = [f"https://example.invalid/{number}" for number in range(policy.MAX_EVIDENCE_LINKS + 2)]
        # Ignore duplicates among displayed links; count overflow entries without retaining them.
        proofs = [*links, links[0], links[-1]]
        index = index_of(hackerpolice_entry("[U:1:100]", proofs))
        database = {"players": [player("[U:1:100]", ["suspicious"])]}

        change = promote(database, index)[0]

        self.assertEqual(change.evidence, tuple(links[: policy.MAX_EVIDENCE_LINKS]))
        self.assertEqual(change.evidence_omitted, 3)
        self.assertNotIn(links[-1], change.evidence)

    def test_an_oversized_evidence_value_is_bounded_before_it_is_retained(self):
        link = "https://example.invalid/" + "x" * 100_000
        index = index_of(hackerpolice_entry("[U:1:100]", [link]))
        database = {"players": [player("[U:1:100]", ["suspicious"])]}

        change = promote(database, index)[0]

        self.assertEqual(len(change.evidence[0]), policy.MAX_EVIDENCE_LINK_CHARS + 1)
        self.assertEqual(change.evidence_omitted, 0)


class SyncInvariantTests(unittest.TestCase):
    def test_an_id_listed_upstream_is_never_demoted(self):
        """`removed_ids` should never contain a still-listed ID; even if a
        caller passes one, sync must not promote and demote it in one run."""
        index = index_of(hackerpolice_entry("[U:1:100]"))
        database = {"players": [player("[U:1:100]", ["racist"])]}
        changes = sync(database, index, enable_demote=True, removed_ids={"[U:1:100]"})
        self.assertEqual(
            [(c.steamid, c.kind, c.after) for c in changes], [("[U:1:100]", "promote", ("cheater", "racist"))]
        )
        self.assertEqual(database["players"][0]["attributes"], ["cheater", "racist"])
        # A second sync must be a no-op.
        self.assertEqual(sync(database, index, enable_demote=True, removed_ids={"[U:1:100]"}), [])


class MalformedEntryTests(unittest.TestCase):
    """Malformed or unrelated entries must be skipped, never crash or be lost."""

    def test_demote_keeps_entries_it_cannot_interpret(self):
        players = [
            "not a dict",
            {"attributes": ["cheater"]},  # Missing SteamID.
            player("nope", ["cheater"]),  # Unusable SteamID.
            player("[U:1:400]", []),  # Missing attributes.
            player("[U:1:401]", [1]),  # Non-string attribute.
            player("[U:1:402]", ["suspicious"]),  # Not a cheater.
            player("[U:1:100]", ["cheater"]),  # Only this entry is demoted.
        ]
        database = {"players": list(players)}
        changes = demote(database, {"[U:1:100]", "[U:1:999]"})
        self.assertEqual(len(changes), 1)
        # Removed upstream but absent locally: nothing to remove.
        self.assertEqual(len(database["players"]), 6)  # Only [U:1:100] is removed.
        self.assertEqual(database["players"][0], "not a dict")

    def test_promote_skips_entries_it_cannot_interpret(self):
        index = index_of(*[hackerpolice_entry(f"[U:1:{n}]") for n in (200, 201, 202, 203)])
        database = {
            "players": [
                "not a dict",
                {"attributes": ["suspicious"]},
                player("nope", ["suspicious"]),
                player("[U:1:200]", []),
                player("[U:1:201]", [1]),
                player("[U:1:202]", ["cheater"]),  # Already a cheater.
                player("[U:1:203]", ["suspicious"]),
                player("[U:1:999]", ["suspicious"]),  # Not listed upstream.
            ]
        }
        changes = promote(database, index)
        promoted = [change.steamid for change in changes]
        self.assertEqual(promoted, ["[U:1:203]"])

    def test_sync_tolerates_a_missing_players_array(self):
        self.assertEqual(promote({}, index_of()), [])
        self.assertEqual(demote({}, {"[U:1:1]"}), [])

    def test_promotion_never_touches_an_existing_proof(self):
        index = index_of(hackerpolice_entry("[U:1:100]", [HACKERPOLICE_PROOF, "  "]))
        database = {"players": [player("[U:1:100]", ["suspicious"], proof=["manual note"])]}
        promote(database, index)
        self.assertEqual(database["players"][0]["attributes"], ["cheater"])
        self.assertEqual(database["players"][0]["proof"], ["manual note"])


class PolicyFuzzTests(unittest.TestCase):
    def test_sync_invariants_hold(self):
        rng = random.Random(42)
        attributes_pool = ["cheater", "suspicious", "racist", "exploiter"]
        proof_pool = ["cheat proof", '[auto] automatically marked: Racist | reason: "x"', "notes"]
        for _ in range(2000):
            players = []
            for i in range(rng.randint(0, 12)):
                entry = {
                    "steamid": f"[U:1:{1000 + i}]",
                    "attributes": rng.sample(attributes_pool, rng.randint(1, 3)),
                }
                if rng.random() < 0.5:
                    entry["proof"] = rng.sample(proof_pool, rng.randint(0, 3))
                players.append(entry)
            current_ids = {p["steamid"] for p in players if rng.random() < 0.5}
            index = HackerpoliceIndex.build({"players": [{"steamid": s} for s in current_ids]})
            removed = {f"[U:1:{1000 + i}]" for i in range(len(players)) if rng.random() < 0.3} - current_ids

            database = {"$schema": "x", "file_info": {}, "players": copy.deepcopy(players)}
            original = {p["steamid"]: p for p in players}
            sync(database, index, enable_demote=True, removed_ids=removed)
            after = {p["steamid"]: p for p in database["players"]}

            ids = [int(p["steamid"][5:-1]) for p in database["players"]]
            self.assertEqual(ids, sorted(ids))  # Entries remain sorted, regardless of the changes.
            self.assertFalse(validate(database).errors)
            for steamid, before in original.items():
                demoted = steamid in removed and "cheater" in before["attributes"]
                if demoted and "racist" not in before["attributes"]:
                    self.assertNotIn(steamid, after)  # Remove a cheater-only entry.
                    continue
                self.assertIn(steamid, after)  # Preserve unrelated entries.
                got = after[steamid]
                if demoted:  # Remove cheater; retain racist and only the automatic racist proofs.
                    self.assertNotIn("cheater", got["attributes"])
                    self.assertIn("racist", got["attributes"])
                    for proof in got.get("proof", []):
                        self.assertTrue(proof.startswith('[auto] automatically marked: Racist | reason: "'))
                elif (
                    steamid in current_ids
                    and "cheater" not in before["attributes"]
                    and ({"suspicious", "racist"} & set(before["attributes"]))
                ):
                    self.assertIn("cheater", got["attributes"])
                    self.assertNotIn("suspicious", got["attributes"])
                    self.assertEqual("racist" in got["attributes"], "racist" in before["attributes"])
                else:
                    self.assertEqual(got, before)  # Unchanged entries remain identical


class OwnerAcceptanceTests(unittest.TestCase):
    """The five rules the database owner stated, each executed end to end.

    Every test below runs the real entry point over real files, so a regression
    anywhere in the chain -- parsing, policy, report, database write, snapshot
    write -- fails here, not only in a unit test of a single function.
    """

    RACIST_LINE = '[auto] automatically marked: Racist | reason: "slur"'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.database = self.root / "playerlist.garou3299.json"
        self.upstream = self.root / "upstream.json"
        self.snapshot = self.root / "snapshot" / "playerlist.vorobey-hackerpolice.json"
        self.snapshot.parent.mkdir(parents=True, exist_ok=True)  # The CLI must not create missing parent directories.

    def write(self, path, players):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dumps({"$schema": "s", "file_info": {}, "players": players}), encoding="utf-8")

    def run_sync(self, *flags):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(
                [
                    "--database",
                    str(self.database),
                    "--snapshot",
                    str(self.snapshot),
                    "--source",
                    str(self.upstream),
                    "--report",
                    str(self.root / "report.md"),
                    "--quiet",
                    *flags,
                ]
            )
        self.assertEqual(code, 0, stderr.getvalue())
        return json.loads(self.database.read_text(encoding="utf-8"))

    def entry(self, database, steamid):
        matches = [player for player in database["players"] if player["steamid"] == steamid]
        self.assertLessEqual(len(matches), 1)
        return matches[0] if matches else None

    def test_rule_1_suspicious_is_promoted_without_adding_any_proof(self):
        """suspicious -> cheater, no proof added, existing proofs untouched."""
        existing = "https://youtu.be/already-there"
        self.write(self.database, [player("[U:1:100]", ["suspicious"], proof=[existing])])
        self.write(self.upstream, [hackerpolice_entry("[U:1:100]", [HACKERPOLICE_PROOF])])

        after = self.run_sync("--demote")

        entry = self.entry(after, "[U:1:100]")
        self.assertEqual(entry["attributes"], ["cheater"])
        self.assertEqual(entry["proof"], [existing])

    def test_rule_1_promotion_adds_no_proof_at_all_when_there_is_none(self):
        self.write(self.database, [player("[U:1:101]", ["suspicious"])])
        self.write(self.upstream, [hackerpolice_entry("[U:1:101]", [HACKERPOLICE_PROOF])])

        after = self.run_sync()

        entry = self.entry(after, "[U:1:101]")
        self.assertEqual(entry["attributes"], ["cheater"])
        self.assertNotIn("proof", entry)  # Promotion must not invent proof.

    def test_rule_2_suspicious_and_racist_becomes_cheater_and_racist_without_new_proofs(self):
        self.write(self.database, [player("[U:1:200]", ["suspicious", "racist"], proof=[self.RACIST_LINE])])
        self.write(self.upstream, [hackerpolice_entry("[U:1:200]", [HACKERPOLICE_PROOF])])

        after = self.run_sync()

        entry = self.entry(after, "[U:1:200]")
        self.assertEqual(entry["attributes"], ["cheater", "racist"])
        self.assertEqual(entry["proof"], [self.RACIST_LINE])

    def test_rule_3_cheater_only_removed_upstream_drops_the_whole_entry(self):
        self.write(self.database, [player("[U:1:300]", ["cheater"], proof=["Silent Aim & ESP"])])
        self.write(self.snapshot, [player("[U:1:300]", ["cheater"])])
        self.write(self.upstream, [hackerpolice_entry("[U:1:399]")])  # [U:1:300] is absent upstream.

        after = self.run_sync("--demote")

        self.assertIsNone(self.entry(after, "[U:1:300]"))
        self.assertEqual(after["players"], [])

    def test_rule_4_cheater_and_racist_removed_upstream_keeps_only_the_auto_racist_proofs(self):
        """The cheater tag goes, and so does every proof that is not a
        ``[auto] automatically marked: Racist | reason: "..."`` line -- including
        gibberish that never pointed at cheating in the first place."""
        self.write(
            self.database,
            [
                player(
                    "[U:1:400]",
                    ["cheater", "racist"],
                    proof=[
                        self.RACIST_LINE,
                        "Silent Aim & ESP",
                        "asdf gibberish n0t a proof",
                        "https://youtu.be/cheat-video",
                    ],
                )
            ],
        )
        self.write(self.snapshot, [player("[U:1:400]", ["cheater", "racist"])])
        self.write(self.upstream, [hackerpolice_entry("[U:1:499]")])  # [U:1:400] is absent upstream.

        after = self.run_sync("--demote")

        entry = self.entry(after, "[U:1:400]")
        self.assertEqual(entry["attributes"], ["racist"])
        self.assertEqual(entry["proof"], [self.RACIST_LINE])

    def test_rule_5_snapshot_is_a_byte_for_byte_copy_of_the_upstream_file(self):
        """CRLF, tabs, unsorted keys and no trailing newline: all preserved."""
        raw = b'{\r\n\t"players": [ {"attributes": ["cheater"], "steamid": "[U:1:500]" } ],\r\n\t"$schema": "s"\r\n}'
        self.write(self.database, [player("[U:1:500]", ["suspicious"])])
        self.upstream.parent.mkdir(parents=True, exist_ok=True)
        self.upstream.write_bytes(raw)

        after = self.run_sync()

        self.assertEqual(self.entry(after, "[U:1:500]")["attributes"], ["cheater"])  # The sync promoted the entry.
        self.assertEqual(self.snapshot.read_bytes(), raw)  # The snapshot remains an exact byte copy.

    def test_rule_5_snapshot_keeps_being_updated_when_the_database_does_not_change(self):
        """A run that changes no entry must still advance the baseline."""
        self.write(self.database, [player("[U:1:600]", ["cheater"])])
        first = json.dumps({"$schema": "s", "file_info": {}, "players": [hackerpolice_entry("[U:1:600]")]}).encode()
        self.upstream.write_bytes(first)
        self.run_sync("--demote")
        self.assertEqual(self.snapshot.read_bytes(), first)

        second = json.dumps(
            {
                "$schema": "s",
                "file_info": {},
                "players": [hackerpolice_entry("[U:1:600]"), hackerpolice_entry("[U:1:601]")],
            }
        ).encode()
        self.upstream.write_bytes(second)
        after = self.run_sync("--demote")

        self.assertEqual(after["players"][0]["attributes"], ["cheater"])  # The database is unchanged.
        self.assertEqual(self.snapshot.read_bytes(), second)  # The snapshot baseline still advances.


if __name__ == "__main__":
    unittest.main(verbosity=2)
