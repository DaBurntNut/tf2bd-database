#!/usr/bin/env python3
"""Tests for the Vorobey hackerpolice sync tool (stdlib only).

Modules under test:
  playerlist   - SteamID norms, load/dumps/validate/sort
  sources      - Vorobey list download + indexing
  policy       - promote / demote / sync
  report       - Markdown report rendering
"""

from __future__ import annotations

import base64
import contextlib
import copy
import io
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from playerlist import (
    PlayerListError,
    account_id,
    dumps,
    load,
    normalize_steamid,
    order_attributes,
    sort_players,
    steam_profile_url,
    validate,
)
from policy import Change, demote, promote, sync
from report import MAX_REMOVED_ROWS, RunInfo, plural, render_closing, render_report
from sources import (
    PROOF_MARKER,
    HackerpoliceIndex,
    SyncError,
    added_steamids,
    load_first_available_raw,
    removed_steamids,
)
from sync_vorobey_hackerpolice import DEFAULT_SNAPSHOT, build_parser, main

HACKERPOLICE_PROOF = "https://discord.com/channels/1/2"


def player(steamid, attributes, **extra):
    entry = {"attributes": list(attributes), "steamid": steamid}
    entry.update(extra)
    return entry


def hackerpolice_entry(steamid, proof=None):
    entry = {"attributes": ["cheater"], "steamid": steamid, "last_seen": {"time": 1}}
    if proof is not None:
        entry["proof"] = proof
    return entry


def index_of(*entries):
    return HackerpoliceIndex.build({"players": list(entries)})


# --------------------------------------------------------------------------- #
# HackerpoliceIndex
# --------------------------------------------------------------------------- #
class HackerpoliceIndexTests(unittest.TestCase):
    def test_build_indexes_canonical_steamids(self):
        index = index_of(hackerpolice_entry("[U:1:100]"), hackerpolice_entry("STEAM_0:0:250"))
        self.assertEqual(len(index.by_steamid), 2)
        self.assertEqual(index.total, 2)
        self.assertEqual(index.skipped, 0)
        self.assertIsNotNone(index.by_steamid.get("[U:1:500]"))
        self.assertIsNone(index.by_steamid.get("[U:1:999]"))

    def test_unusable_entries_are_skipped(self):
        index = index_of(hackerpolice_entry("nope"), "not a dict", hackerpolice_entry("[U:1:100]"))
        self.assertEqual(len(index.by_steamid), 1)
        self.assertEqual(index.skipped, 2)

    def test_duplicates_keep_the_first_entry(self):
        index = index_of(hackerpolice_entry("[U:1:100]", ["first"]), hackerpolice_entry("[U:1:100]", ["second"]))
        self.assertEqual(index.by_steamid["[U:1:100]"]["proof"], ["first"])

    def test_missing_players_array_is_an_error(self):
        with self.assertRaises(SyncError):
            HackerpoliceIndex.build({})


# --------------------------------------------------------------------------- #
# Source fetching (network layer, mocked)
# --------------------------------------------------------------------------- #
class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        return self._body if size is None or size < 0 else self._body[:size]


class SourceFetchTests(unittest.TestCase):
    URL = "https://example.invalid/list.json"
    BODY = b'\xef\xbb\xbf{"players": [{"steamid": "[U:1:100]", "attributes": ["cheater"]}]}'

    def fetch(self, side_effect):
        with (
            mock.patch("sources.urllib.request.urlopen", side_effect=side_effect) as urlopen,
            mock.patch("sources.time.sleep"),
        ):
            result = load_first_available_raw([self.URL])
        return result, urlopen.call_count

    def test_fetch_returns_body_bytes_verbatim(self):
        (document, source, raw), _ = self.fetch([_FakeResponse(self.BODY)])
        self.assertEqual(raw, self.BODY)  # BOM and all: nothing decoded/re-encoded
        self.assertEqual(source, self.URL)
        self.assertIn("[U:1:100]", [p["steamid"] for p in document["players"]])

    def test_github_contents_envelope_is_unwrapped_to_the_file_bytes(self):
        inner = b'{"players": [{"steamid": "[U:1:100]", "attributes": ["cheater"]}]}'
        envelope = json.dumps({"encoding": "base64", "content": base64.b64encode(inner).decode("ascii")}).encode(
            "utf-8"
        )
        (document, _, raw), _ = self.fetch([_FakeResponse(envelope)])
        self.assertEqual(raw, inner)  # the envelope itself is never snapshotted
        self.assertEqual(len(document["players"]), 1)

    def test_non_https_download_url_is_never_followed(self):
        # download_url is untrusted response data: a plaintext or local
        # target must be rejected, not fetched.
        for bad_url in ("http://example.invalid/raw.json", "/etc/passwd"):
            envelope = json.dumps({"encoding": "none", "content": "", "download_url": bad_url}).encode("utf-8")
            with (
                mock.patch("sources.urllib.request.urlopen", side_effect=[_FakeResponse(envelope)]) as urlopen,
                mock.patch("sources.time.sleep"),
                self.assertRaises(SyncError),
            ):
                load_first_available_raw([self.URL])
            self.assertEqual(urlopen.call_count, 1)  # only the envelope itself was fetched

    def test_large_file_envelope_falls_back_to_download_url(self):
        envelope = json.dumps(
            {"encoding": "none", "content": "", "download_url": "https://example.invalid/raw.json"}
        ).encode("utf-8")
        (document, _, raw), calls = self.fetch([_FakeResponse(envelope), _FakeResponse(self.BODY)])
        self.assertEqual(raw, self.BODY)
        self.assertEqual(len(document["players"]), 1)
        self.assertEqual(calls, 2)

    def test_malformed_urls_are_clean_errors_not_crashes(self):
        # Bad IPv6 literals / control characters make urllib raise
        # ValueError/InvalidURL: that must surface as SyncError (fallback
        # or exit 2), never as a traceback. No network is touched.
        for url in ("https://[::1", "https://exa\nmple.invalid/"):
            with mock.patch("sources.time.sleep"), self.assertRaises(SyncError):
                load_first_available_raw([url])

    def test_oversized_response_is_rejected(self):
        with (
            mock.patch("sources.urllib.request.urlopen", return_value=_FakeResponse(self.BODY)),
            mock.patch("sources.MAX_SOURCE_BYTES", 10),
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError),
        ):
            load_first_available_raw([self.URL])

    def test_permanent_http_error_is_not_retried(self):
        error = urllib.error.HTTPError(self.URL, 404, "not found", Message(), None)
        with (
            mock.patch("sources.urllib.request.urlopen", side_effect=[error]) as urlopen,
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError),
        ):
            load_first_available_raw([self.URL])
        self.assertEqual(urlopen.call_count, 1)

    def test_transient_http_error_is_retried_until_success(self):
        error = urllib.error.HTTPError(self.URL, 503, "unavailable", Message(), None)
        (_, _, raw), calls = self.fetch([error, error, _FakeResponse(self.BODY)])
        self.assertEqual(raw, self.BODY)
        self.assertEqual(calls, 3)


# --------------------------------------------------------------------------- #
# Promotion policy
# --------------------------------------------------------------------------- #
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

    def test_suspicious_and_racist_becomes_cheater_and_racist(self):
        database, _ = self.promote([player("[U:1:300]", ["suspicious", "racist"])])
        self.assertEqual(database["players"][0]["attributes"], ["cheater", "racist"])

    def test_attribute_order_is_normalised(self):
        database, _ = self.promote([player("[U:1:300]", ["racist", "suspicious"])])
        self.assertEqual(database["players"][0]["attributes"], ["cheater", "racist"])

    def test_include_proof_is_opt_in_and_idempotent(self):
        database, _ = self.promote([player("[U:1:100]", ["suspicious"])], include_proof=True)
        proof = database["players"][0]["proof"]
        self.assertEqual(len(proof), 1)
        self.assertIn(PROOF_MARKER, proof[0])
        self.assertIn(HACKERPOLICE_PROOF, proof[0])

        _, changes = self.promote(database["players"], include_proof=True)
        self.assertEqual(changes, [])
        self.assertEqual(len(database["players"][0]["proof"]), 1)

    def test_existing_proof_is_kept_and_extended_once(self):
        database, _ = self.promote([player("[U:1:100]", ["suspicious"], proof=["manual note"])], include_proof=True)
        self.assertEqual(database["players"][0]["proof"][0], "manual note")
        self.assertEqual(len(database["players"][0]["proof"]), 2)

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


# --------------------------------------------------------------------------- #
# Demotion policy
# --------------------------------------------------------------------------- #
class RemovedSteamIdsTests(unittest.TestCase):
    def test_removed_is_previous_minus_current(self):
        previous = index_of(hackerpolice_entry("[U:1:100]"), hackerpolice_entry("[U:1:200]"))
        current = index_of(hackerpolice_entry("[U:1:200]"), hackerpolice_entry("[U:1:300]"))
        # 100 disappeared upstream; 300 is new upstream (not a removal);
        # an ID in neither list can never appear here.
        self.assertEqual(removed_steamids(previous, current), {"[U:1:100]"})

    def test_added_is_current_minus_previous(self):
        previous = index_of(hackerpolice_entry("[U:1:100]"), hackerpolice_entry("[U:1:200]"))
        current = index_of(hackerpolice_entry("[U:1:200]"), hackerpolice_entry("[U:1:300]"))
        self.assertEqual(added_steamids(previous, current), {"[U:1:300]"})
        self.assertEqual(added_steamids(current, current), set())


class DemoteTests(unittest.TestCase):
    """Demotion applies ONLY to IDs handed in as removed upstream."""

    # [U:1:200] was in the snapshot and is gone now; [U:1:100] is still listed.
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
        self.assertEqual(database["players"][0]["proof"], [])

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

    def test_cheater_and_racist_with_non_list_proof_drops_the_proof(self):
        database, _ = self.demote([player("[U:1:200]", ["cheater", "racist"], proof="Silent Aim & ESP")])
        self.assertEqual(database["players"][0]["attributes"], ["racist"])
        self.assertEqual(database["players"][0]["proof"], [])

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


# --------------------------------------------------------------------------- #
# Policy invariants over randomised inputs (seeded: fully deterministic)
# --------------------------------------------------------------------------- #
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
            self.assertEqual(ids, sorted(ids))  # always sorted, whatever happened
            self.assertFalse(validate(database).errors)
            for steamid, before in original.items():
                demoted = steamid in removed and "cheater" in before["attributes"]
                if demoted and "racist" not in before["attributes"]:
                    self.assertNotIn(steamid, after)  # cheater-only: entry gone
                    continue
                self.assertIn(steamid, after)  # nothing else may ever vanish
                got = after[steamid]
                if demoted:  # cheater+racist: racist kept, only auto-racist proofs survive
                    self.assertNotIn("cheater", got["attributes"])
                    self.assertIn("racist", got["attributes"])
                    for proof in got.get("proof", []):
                        self.assertTrue(proof.startswith("[auto] automatically marked: Racist | reason:"))
                elif (
                    steamid in current_ids
                    and "cheater" not in before["attributes"]
                    and ({"suspicious", "racist"} & set(before["attributes"]))
                ):
                    self.assertIn("cheater", got["attributes"])
                    self.assertNotIn("suspicious", got["attributes"])
                    self.assertEqual("racist" in got["attributes"], "racist" in before["attributes"])
                else:
                    self.assertEqual(got, before)  # untouched means byte-identical


# --------------------------------------------------------------------------- #
# Report rendering
# --------------------------------------------------------------------------- #
class ReportTests(unittest.TestCase):
    def info(self, changes=(), **kwargs):
        return RunInfo(
            database_path=Path("playerlist.garou3299.json"),
            source="https://example.invalid/list.json",
            source_total=10,
            source_skipped=0,
            changes=tuple(changes),
            **{"dry_run": False, **kwargs},
        )

    def test_no_changes_message(self):
        report = render_report(self.info())
        self.assertIn("**No changes.**", report)
        self.assertIn("10 entries", report)
        self.assertNotIn("| SteamID |", report)

    def test_report_links_the_human_friendly_blob_page_and_names_the_fetch_source(self):
        report = render_report(self.info())
        # Main reference: the readable GitHub blob page, not a raw/API URL.
        self.assertIn(
            "Vorobey hackerpolice list (10 entries): "
            "https://github.com/Nocrex/Tom/blob/main/playerlist.vorobey-hackerpolice.json",
            report,
        )
        # The actual URL the bytes were fetched from stays visible for debugging.
        self.assertIn("- Fetched from: https://example.invalid/list.json", report)

    def test_snapshot_diff_shows_added_removed_and_net(self):
        report = render_report(
            self.info(previous_source_total=100, added_to_source=12, removed_from_source=3, snapshot_changed=True)
        )
        self.assertIn(
            "- Snapshot diff: **12 new SteamIDs added**, **3 SteamIDs removed** (100 → 109 entries; net +9)",
            report,
        )

    def test_snapshot_diff_singular_and_negative_net(self):
        report = render_report(self.info(previous_source_total=100, added_to_source=1, removed_from_source=2))
        self.assertIn("**1 new SteamID added**, **2 SteamIDs removed** (100 → 99 entries; net -1)", report)

    def test_snapshot_diff_initial_snapshot_without_previous(self):
        report = render_report(self.info(added_to_source=10, snapshot_changed=True))
        self.assertIn("**10 new SteamIDs added**, **0 SteamIDs removed** (no previous snapshot", report)

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
        self.assertIn("**1 entry promoted to `cheater`.**", report)
        self.assertIn(
            "| `[U:1:1]` | [cheater \\| with pipe](https://steamcommunity.com/profiles/76561197960265729) |",
            report,
        )
        self.assertIn(f"[link]({HACKERPOLICE_PROOF})", report)
        self.assertIn("Proof link comes from the Vorobey hackerpolice list", report)

    def test_name_links_to_the_steam_profile_permalink(self):
        # [U:1:269327660] -> SteamID64 76561198229593388 (base + account id).
        change = Change("[U:1:269327660]", "KNNU", ("suspicious",), ("cheater",), (HACKERPOLICE_PROOF,))
        report = render_report(self.info([change]))
        self.assertIn("[KNNU](https://steamcommunity.com/profiles/76561198229593388)", report)

    def test_demoted_names_link_too_and_missing_names_become_unknown(self):
        demoted = Change("[U:1:269327660]", "KNNU", ("cheater",), (), kind="demote")
        unnamed = Change("[U:1:2]", "", ("suspicious",), ("cheater",))
        report = render_report(self.info([demoted, unnamed]))
        self.assertIn("[KNNU](https://steamcommunity.com/profiles/76561198229593388)", report)
        # No recorded name -> UNKNOWN, still linked to the profile permalink.
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
        # "\ud800" is legal JSON and loads fine, but cannot be encoded as
        # UTF-8: it must be replaced, not crash writing/printing the report.
        change = Change("[U:1:1]", "bad\ud800name", ("suspicious",), ("cheater",), ("https://x/\udfff",))
        report = render_report(self.info([change]))
        self.assertIn("bad\ufffdname", report)
        report.encode("utf-8")  # must not raise

    def test_carriage_returns_in_names_cannot_break_the_table(self):
        change = Change("[U:1:1]", "a\rb", ("suspicious",), ("cheater",), (HACKERPOLICE_PROOF,))
        report = render_report(self.info([change]))
        self.assertIn("| [a b](https://steamcommunity.com/profiles/76561197960265729) |", report)
        self.assertNotIn("\r", report)

    def test_multiple_evidence_links_and_missing_links(self):
        with_links = Change("[U:1:1]", "a", ("suspicious",), ("cheater",), ("https://x/1", "https://x/2"))
        without_links = Change("[U:1:2]", "b", ("suspicious",), ("cheater",))
        report = render_report(self.info([with_links, without_links]))
        self.assertIn("[1](https://x/1)<br>[2](https://x/2)", report)
        self.assertIn("**2 entries promoted to `cheater`.**", report)

    def test_prose_evidence_is_not_turned_into_a_link(self):
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",), ("seen spinbotting",))
        report = render_report(self.info([change]))
        self.assertIn("| seen spinbotting |", report)
        self.assertNotIn("[link](seen spinbotting)", report)

    def test_link_targets_are_escaped(self):
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",), ("https://example.invalid/a (b)",))
        report = render_report(self.info([change]))
        self.assertIn("https://example.invalid/a%20%28b%29", report)

    def test_dry_run_and_include_proof_notes(self):
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",))
        report = render_report(self.info([change], dry_run=True, include_proof=True))
        self.assertIn("**dry run**", report)
        self.assertIn("`--include-proof` was enabled", report)

    def test_removed_steamids_are_tabulated_with_profile_links(self):
        # The Vorobey list stores no names, so the table only has the SteamID
        # and a link to the profile permalink -- sorted numerically, not
        # lexicographically ([U:1:99] must come before [U:1:100]).
        report = render_report(self.info(removed_upstream=("[U:1:100]", "[U:1:269327660]", "[U:1:99]")))
        self.assertIn("**3 SteamIDs removed from the Vorobey list since the previous snapshot.**", report)
        self.assertIn("records no player names", report)
        self.assertIn(
            "| SteamID | Profile Link |\n| --- | --- |\n"
            "| `[U:1:99]` | [profile](https://steamcommunity.com/profiles/76561197960265827) |\n"
            "| `[U:1:100]` | [profile](https://steamcommunity.com/profiles/76561197960265828) |\n"
            "| `[U:1:269327660]` | [profile](https://steamcommunity.com/profiles/76561198229593388) |\n",
            report,
        )
        self.assertNotIn("Last known name", report)

    def test_removed_steamid_singular_and_absent_when_empty(self):
        self.assertIn(
            "**1 SteamID removed from the Vorobey list since the previous snapshot.**",
            render_report(self.info(removed_upstream=("[U:1:1]",))),
        )
        # Nothing removed -> no table at all (not an empty one).
        for kwargs in ({}, {"previous_source_total": 100, "removed_from_source": 0}):
            self.assertNotIn("Profile Link", render_report(self.info(**kwargs)))

    def test_removed_steamids_are_reported_even_without_database_changes(self):
        # Removals of IDs this database never listed cause no demotion, but
        # they are still part of the snapshot diff and must be visible.
        report = render_report(
            self.info(
                previous_source_total=100, removed_from_source=1, removed_upstream=("[U:1:7]",), snapshot_changed=True
            )
        )
        self.assertIn("**No database changes** (snapshot refresh only).", report)
        self.assertIn("| `[U:1:7]` | [profile](https://steamcommunity.com/profiles/76561197960265735) |", report)

    def test_removed_table_is_capped_so_the_pr_body_cannot_explode(self):
        removed = tuple(f"[U:1:{account}]" for account in range(1, MAX_REMOVED_ROWS + 6))
        report = render_report(
            self.info(previous_source_total=10000, removed_from_source=len(removed), removed_upstream=removed)
        )
        self.assertEqual(report.count("| [profile]("), MAX_REMOVED_ROWS)
        self.assertIn("…and 5 more SteamIDs (the snapshot diff in this pull request lists every one).", report)


# --------------------------------------------------------------------------- #
# Closing message rendering
# --------------------------------------------------------------------------- #
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
        self.assertEqual(render_closing([]), "; nothing else is modified.")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.database = self.root / "list.json"
        self.database.write_text(
            dumps(
                {
                    "$schema": "x",
                    "file_info": {},
                    "players": [
                        player("[U:1:100]", ["suspicious"]),
                        player("[U:1:200]", ["racist"]),
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.source = self.root / "hackerpolice.json"
        self.source.write_text(
            dumps(
                {
                    "$schema": "x",
                    "file_info": {},
                    "players": [
                        hackerpolice_entry("[U:1:100]", [HACKERPOLICE_PROOF]),
                        hackerpolice_entry("[U:1:200]"),
                    ],
                }
            ),
            encoding="utf-8",
        )

    def write_snapshot_fixture(self, *entries):
        snapshot_file = self.root / "snapshot.json"
        snapshot_file.write_text(dumps({"$schema": "x", "file_info": {}, "players": list(entries)}), encoding="utf-8")
        return snapshot_file

    def test_snapshot_default_path_and_flags(self):
        self.assertEqual(DEFAULT_SNAPSHOT, "snapshot/playerlist.vorobey-hackerpolice.json")
        self.assertEqual(build_parser().parse_args([]).snapshot, DEFAULT_SNAPSHOT)
        args = build_parser().parse_args(["--snapshot", "some/path.json", "--no-update-snapshot"])
        self.assertEqual(args.snapshot, "some/path.json")
        self.assertTrue(args.no_update_snapshot)
        # The pre-rename --backup flags no longer exist.
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            build_parser().parse_args(["--backup", "old/path.json"])

    def run_cli(self, *extra, env=None):
        # Always point --snapshot at the temp dir so tests never touch the
        # repository's real snapshot.
        argv = ["--database", str(self.database), "--snapshot", str(self.root / "snapshot.json"), *extra]
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            mock.patch.dict(os.environ, env or {}, clear=False),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_dry_run_does_not_write(self):
        original = self.database.read_text(encoding="utf-8")
        code, stdout, _ = self.run_cli("--source", str(self.source), "--dry-run", "--report", str(self.root / "r.md"))
        self.assertEqual(code, 0)
        self.assertEqual(self.database.read_text(encoding="utf-8"), original)
        self.assertIn("dry run", stdout)
        self.assertIn("dry run", (self.root / "r.md").read_text(encoding="utf-8"))

    def test_suspicious_and_racist_are_written(self):
        code, _, _ = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 0)
        players = {
            p["steamid"]: p["attributes"] for p in json.loads(self.database.read_text(encoding="utf-8"))["players"]
        }
        self.assertEqual(players["[U:1:100]"], ["cheater"])
        self.assertEqual(players["[U:1:200]"], ["cheater", "racist"])

    def test_second_run_reports_no_changes(self):
        self.run_cli("--source", str(self.source))
        code, stdout, _ = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 0)
        self.assertIn("No changes", stdout)

    def test_demote_only_ids_removed_from_snapshot(self):
        """End-to-end regression test for the reported bug.

        [U:1:300] cheater+racist and [U:1:400] cheater-only were in the
        snapshot but are gone from the current list -> demote them.
        [U:1:500] is a manually added cheater in NEITHER list -> untouched,
        even though it is 'not present in the Vorobey database'.
        """
        self.database.write_text(
            dumps(
                {
                    "$schema": "x",
                    "file_info": {},
                    "players": [
                        player(
                            "[U:1:300]",
                            ["cheater", "racist"],
                            proof=["cheating proof", '[auto] automatically marked: Racist | reason: "slur"'],
                        ),
                        player("[U:1:400]", ["cheater"]),
                        player("[U:1:500]", ["cheater"]),
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.write_snapshot_fixture(hackerpolice_entry("[U:1:300]"), hackerpolice_entry("[U:1:400]"))
        code, stdout, _ = self.run_cli("--source", str(self.source), "--demote")
        self.assertEqual(code, 0)
        players = {p["steamid"]: p for p in json.loads(self.database.read_text(encoding="utf-8"))["players"]}
        self.assertEqual(players["[U:1:300]"]["attributes"], ["racist"])
        self.assertEqual(players["[U:1:300]"]["proof"], ['[auto] automatically marked: Racist | reason: "slur"'])
        self.assertNotIn("[U:1:400]", players)
        self.assertEqual(players["[U:1:500]"]["attributes"], ["cheater"])
        self.assertIn("Previous snapshot: 2 entries; 2 SteamIDs removed upstream", stdout)
        self.assertIn(
            "- Snapshot diff: **2 new SteamIDs added**, **2 SteamIDs removed** (2 → 2 entries; net +0)",
            stdout,
        )

    def test_removed_ids_are_tabulated_in_the_report_even_without_demote(self):
        """The PR must show WHO Vorobey dropped, not just how many.

        The Vorobey list has no names, so each removed SteamID is listed with
        a profile link. This is the snapshot diff and is shown whether or not
        --demote was requested (here it was not).
        """
        self.write_snapshot_fixture(hackerpolice_entry("[U:1:300]"), hackerpolice_entry("[U:1:400]"))
        report_file = self.root / "r.md"
        code, stdout, _ = self.run_cli("--source", str(self.source), "--report", str(report_file))
        self.assertEqual(code, 0)
        report = report_file.read_text(encoding="utf-8")
        self.assertIn("removed from the Vorobey list", stdout)  # job summary gets it too
        self.assertIn("**2 SteamIDs removed from the Vorobey list since the previous snapshot.**", report)
        self.assertIn("| `[U:1:300]` | [profile](https://steamcommunity.com/profiles/76561197960266028) |", report)
        self.assertIn("| `[U:1:400]` | [profile](https://steamcommunity.com/profiles/76561197960266128) |", report)
        self.assertNotIn("demoted", report)

    def test_demote_without_snapshot_demotes_nobody_and_creates_baseline(self):
        self.database.write_text(
            dumps({"$schema": "x", "file_info": {}, "players": [player("[U:1:500]", ["cheater"])]}),
            encoding="utf-8",
        )
        code, stdout, _ = self.run_cli("--source", str(self.source), "--demote")
        self.assertEqual(code, 0)
        players = json.loads(self.database.read_text(encoding="utf-8"))["players"]
        self.assertEqual(players[0]["attributes"], ["cheater"])
        self.assertIn("Demotion: **skipped", stdout)
        # The run still writes the snapshot, establishing the baseline; the
        # second run can then prove removals against it.
        snapshot = json.loads((self.root / "snapshot.json").read_text(encoding="utf-8"))
        self.assertEqual(len(snapshot["players"]), 2)

    def test_mass_disappearance_upstream_skips_demotion(self):
        self.database.write_text(
            dumps({"$schema": "x", "file_info": {}, "players": [player("[U:1:400]", ["cheater"])]}),
            encoding="utf-8",
        )
        snapshot_fixture = self.write_snapshot_fixture(*[hackerpolice_entry(f"[U:1:{n}]") for n in range(400, 461)])
        snapshot_before = snapshot_fixture.read_bytes()
        code, stdout, _ = self.run_cli("--source", str(self.source), "--demote")
        self.assertEqual(code, 0)
        players = json.loads(self.database.read_text(encoding="utf-8"))["players"]
        self.assertEqual(players[0]["attributes"], ["cheater"])
        self.assertIn("looks like an upstream problem", stdout)
        # The snapshot must NOT advance past removals we refused to apply,
        # or they could never be demoted later.
        self.assertEqual(snapshot_fixture.read_bytes(), snapshot_before)

    def test_empty_upstream_list_is_an_error_and_writes_nothing(self):
        empty = self.root / "empty.json"
        empty.write_text(dumps({"$schema": "x", "file_info": {}, "players": []}), encoding="utf-8")
        snapshot_fixture = self.write_snapshot_fixture(hackerpolice_entry("[U:1:100]"))
        snapshot_before, database_before = snapshot_fixture.read_bytes(), self.database.read_bytes()
        code, _, stderr = self.run_cli("--source", str(empty), "--demote")
        self.assertEqual(code, 2)
        self.assertIn("no usable SteamIDs", stderr)
        self.assertEqual(snapshot_fixture.read_bytes(), snapshot_before)
        self.assertEqual(self.database.read_bytes(), database_before)

    def test_snapshot_is_refreshed_in_the_same_run_as_a_demotion(self):
        self.database.write_text(
            dumps({"$schema": "x", "file_info": {}, "players": [player("[U:1:400]", ["cheater"])]}),
            encoding="utf-8",
        )
        self.write_snapshot_fixture(hackerpolice_entry("[U:1:400]"))
        code, _, _ = self.run_cli("--source", str(self.source), "--demote")
        self.assertEqual(code, 0)
        snapshot_ids = {
            p["steamid"] for p in json.loads((self.root / "snapshot.json").read_text(encoding="utf-8"))["players"]
        }
        self.assertEqual(snapshot_ids, {"[U:1:100]", "[U:1:200]"})
        # Next run: baseline == current list, so nothing is re-demoted.
        code, stdout, _ = self.run_cli("--source", str(self.source), "--demote")
        self.assertEqual(code, 0)
        self.assertIn("No changes", stdout)

    def test_snapshot_is_an_exact_byte_for_byte_copy_of_the_source(self):
        """The snapshot must be the original file verbatim, not a
        re-serialisation: this source deliberately uses odd key order,
        spacing, unescaped Unicode and no trailing newline, and the snapshot
        must come out identical byte for byte."""
        raw = (
            '{ "players": [ { "steamid": "[U:1:100]", "attributes": ["cheater"],'
            ' "last_seen": {"player_name": "німий", "time": 1} } ],'
            ' "file_info": {"title": "t"}, "$schema": "x" }'
        )
        weird_source = self.root / "weird.json"
        weird_source.write_bytes(raw.encode("utf-8"))
        code, _, _ = self.run_cli("--source", str(weird_source), "--demote")
        self.assertEqual(code, 0)
        self.assertEqual((self.root / "snapshot.json").read_bytes(), raw.encode("utf-8"))

    def test_snapshot_replica_survives_crlf_bom_and_unicode_bytes(self):
        """Byte-level replica guarantee: CRLF line endings, a UTF-8 BOM and
        raw (unescaped) Unicode in the source must all survive untouched --
        any decode/re-encode or text-mode round trip would alter them."""
        document = {
            "$schema": "x",
            "file_info": {},
            "players": [hackerpolice_entry("[U:1:100]")],
        }
        raw = b"\xef\xbb\xbf" + json.dumps(document, ensure_ascii=False, indent=2).replace("\n", "\r\n").encode("utf-8")
        weird_source = self.root / "crlf.json"
        weird_source.write_bytes(raw)
        code, _, _ = self.run_cli("--source", str(weird_source), "--demote")
        self.assertEqual(code, 0)
        self.assertEqual((self.root / "snapshot.json").read_bytes(), raw)

    def test_include_proof_writes_the_citation(self):
        code, _, _ = self.run_cli("--source", str(self.source), "--include-proof")
        self.assertEqual(code, 0)
        players = {p["steamid"]: p for p in json.loads(self.database.read_text(encoding="utf-8"))["players"]}
        proof = players["[U:1:100]"]["proof"]
        self.assertEqual(len(proof), 1)
        self.assertIn(PROOF_MARKER, proof[0])
        self.assertIn(HACKERPOLICE_PROOF, proof[0])

    def test_github_outputs(self):
        output_file = self.root / "github_output"
        output_file.write_text("", encoding="utf-8")
        code, _, _ = self.run_cli("--source", str(self.source), env={"GITHUB_OUTPUT": str(output_file)})
        self.assertEqual(code, 0)
        lines = output_file.read_text(encoding="utf-8").splitlines()
        self.assertIn("changed=true", lines)
        self.assertIn("count=2", lines)
        self.assertIn("modified=true", lines)
        self.assertIn("snapshot_added=2", lines)
        self.assertIn("snapshot_removed=0", lines)

    def test_concurrent_runs_never_corrupt_the_files(self):
        # Four processes sync the SAME database/snapshot at the same time:
        # unique temp files + atomic replace must leave complete, valid
        # files behind (last writer wins, never an interleaved mixture).
        script = Path(__file__).resolve().parents[1] / "scripts" / "sync_vorobey_hackerpolice.py"
        argv = [
            sys.executable,
            str(script),
            "--database",
            str(self.database),
            "--snapshot",
            str(self.root / "snapshot.json"),
            "--source",
            str(self.source),
        ]
        processes = [subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for _ in range(4)]
        for process in processes:
            self.assertEqual(process.wait(), 0)
        players = {
            p["steamid"]: p["attributes"] for p in json.loads(self.database.read_text(encoding="utf-8"))["players"]
        }
        self.assertEqual(players["[U:1:100]"], ["cheater"])
        # The snapshot is still an exact byte replica, and no temp files leaked.
        self.assertEqual((self.root / "snapshot.json").read_bytes(), self.source.read_bytes())
        self.assertEqual(list(self.root.glob(".*.tmp")), [])

    def test_corrupted_files_never_crash(self):
        # Random byte corruption of database/source/snapshot must always end
        # in exit 0 or the clean exit 2 -- never an uncaught exception.
        rng = random.Random(99)
        db_bytes = self.database.read_bytes()
        src_bytes = self.source.read_bytes()

        def mutate(data):
            blob = bytearray(data)
            for _ in range(rng.randint(1, 40)):
                blob[rng.randrange(len(blob))] = rng.randrange(256)
            if rng.random() < 0.5:
                blob = blob[: rng.randrange(len(blob))]
            return bytes(blob)

        for _ in range(60):
            self.database.write_bytes(mutate(db_bytes))
            self.source.write_bytes(mutate(src_bytes))
            (self.root / "snapshot.json").write_bytes(mutate(src_bytes))
            code, _, _ = self.run_cli("--source", str(self.source), "--demote", "--dry-run")
            self.assertIn(code, (0, 2))

    def test_ascii_stdout_cannot_crash_the_report(self):
        # Regression: on an ASCII/legacy-codepage stdout (Windows cp1252,
        # PYTHONIOENCODING=ascii) printing the report -- which contains
        # arrows and non-ASCII names -- used to die with UnicodeEncodeError.
        self.write_snapshot_fixture(hackerpolice_entry("[U:1:100]"))
        raw = io.BytesIO()
        stdout = io.TextIOWrapper(raw, encoding="ascii")
        argv = [
            "--database",
            str(self.database),
            "--snapshot",
            str(self.root / "snapshot.json"),
            "--source",
            str(self.source),
        ]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            code = main(argv)
        stdout.flush()
        self.assertEqual(code, 0)
        self.assertIn("→", raw.getvalue().decode("utf-8"))

    def test_missing_database_is_an_error(self):
        self.database.unlink()
        code, _, stderr = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 2)
        self.assertIn("cannot read", stderr)

    def test_invalid_json_is_an_error(self):
        self.database.write_text("{nope", encoding="utf-8")
        code, _, stderr = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 2)
        self.assertIn("not valid JSON", stderr)

    def test_report_path_must_not_alias_the_database(self):
        # Regression: the report is written before the database, so an
        # aliased --report destroyed the database (even in dry-run mode).
        original = self.database.read_text(encoding="utf-8")
        for extra in (("--report", str(self.database)), ("--report", str(self.database), "--dry-run")):
            code, _, stderr = self.run_cli("--source", str(self.source), *extra)
            self.assertEqual(code, 2)
            self.assertIn("--report must not be the same file", stderr)
            self.assertEqual(self.database.read_text(encoding="utf-8"), original)

    def test_report_path_must_not_alias_the_snapshot_or_a_local_source(self):
        snapshot_fixture = self.write_snapshot_fixture(hackerpolice_entry("[U:1:100]"))
        for target in (snapshot_fixture, self.source):
            code, _, stderr = self.run_cli("--source", str(self.source), "--report", str(target))
            self.assertEqual(code, 2)
            self.assertIn("--report must not be the same file", stderr)

    def test_non_utf8_database_is_a_clean_error_not_a_traceback(self):
        self.database.write_bytes(b"\xff\xfe{")
        code, _, stderr = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 2)
        self.assertIn("cannot read", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_all_sources_failing_is_an_error(self):
        code, _, stderr = self.run_cli("--source", str(self.root / "missing.json"), "--dry-run")
        self.assertEqual(code, 2)
        self.assertIn("cannot load the Vorobey hackerpolice list", stderr)

    def test_source_fallback_uses_the_next_candidate(self):
        code, stdout, _ = self.run_cli(
            "--source", str(self.root / "missing.json"), "--source", str(self.source), "--dry-run"
        )
        self.assertEqual(code, 0)
        self.assertIn("2 entries promoted", stdout)


# --------------------------------------------------------------------------- #
# Full PR lifecycle in a real Git repo
# --------------------------------------------------------------------------- #
@unittest.skipUnless(shutil.which("git"), "git is required for the lifecycle test")
class LifecycleTests(unittest.TestCase):
    """Run -> merge -> upstream moves -> run -> idle, plus closed-PR re-proposal."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "snapshot").mkdir()
        self.db = self.root / "db.json"
        self.bak = self.root / "snapshot" / "snap.json"
        self.up = self.root / "upstream.json"

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True, text=True)

    def write(self, path, players):
        path.write_text(dumps({"$schema": "x", "file_info": {}, "players": players}), encoding="utf-8")

    def run_bot(self):
        argv = ["--database", str(self.db), "--snapshot", str(self.bak), "--source", str(self.up), "--demote"]
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = main(argv)
        self.assertEqual(code, 0)
        return out.getvalue()

    def players(self):
        return {p["steamid"]: p for p in json.loads(self.db.read_text(encoding="utf-8"))["players"]}

    def test_full_lifecycle(self):
        auto = '[auto] automatically marked: Racist | reason: "slur"'
        self.write(
            self.db,
            [
                player("[U:1:100]", ["suspicious"]),
                player("[U:1:200]", ["cheater", "racist"], proof=["Silent Aim & ESP", auto]),
                player("[U:1:300]", ["cheater"]),
                player("[U:1:999]", ["cheater"]),  # manual cheater, never upstream
            ],
        )
        self.write(
            self.up, [hackerpolice_entry("[U:1:100]"), hackerpolice_entry("[U:1:200]"), hackerpolice_entry("[U:1:300]")]
        )
        self.bak.write_bytes(self.up.read_bytes())
        self.git("init", "-q")
        self.git("config", "user.email", "t@t")
        self.git("config", "user.name", "t")
        self.git("add", "-A")
        self.git("commit", "-qm", "baseline")

        # Run 1 + "merge": promotion lands, baseline committed.
        self.run_bot()
        self.assertEqual(self.players()["[U:1:100]"]["attributes"], ["cheater"])
        self.git("add", "-A")
        self.git("commit", "-qm", "sync 1")

        # Upstream drops 200+300; run, DISCARD the changes (closed PR), re-run:
        # the identical demotions must be proposed again from the old baseline.
        self.write(self.up, [hackerpolice_entry("[U:1:100]")])
        out1 = self.run_bot()
        self.git("checkout", "--", "db.json", "snapshot/snap.json")
        out2 = self.run_bot()
        self.assertIn("2 entries demoted", out1)
        self.assertIn("2 entries demoted", out2)
        players = self.players()
        self.assertEqual(players["[U:1:200]"]["attributes"], ["racist"])
        self.assertEqual(players["[U:1:200]"]["proof"], [auto])
        self.assertNotIn("[U:1:300]", players)
        self.assertEqual(players["[U:1:999]"]["attributes"], ["cheater"])
        self.assertEqual(self.bak.read_bytes(), self.up.read_bytes())
        self.git("add", "-A")
        self.git("commit", "-qm", "sync 2")

        # Run 3: fully converged - no changes, clean working tree.
        self.assertIn("No changes", self.run_bot())
        status = subprocess.run(
            ["git", "status", "--porcelain"], cwd=self.root, capture_output=True, text=True, check=True
        ).stdout
        self.assertEqual(status, "")


# --------------------------------------------------------------------------- #
# TF2BD playerlist helpers
# --------------------------------------------------------------------------- #
class NormalizeSteamIdTests(unittest.TestCase):
    def test_canonical(self):
        self.assertEqual(normalize_steamid("[U:1:1730017]"), "[U:1:1730017]")

    def test_bare_and_instance_forms(self):
        self.assertEqual(normalize_steamid("U:1:1730017"), "[U:1:1730017]")
        self.assertEqual(normalize_steamid("[U:1:1730017:1]"), "[U:1:1730017]")
        self.assertEqual(normalize_steamid("  [U:1:1730017]  "), "[U:1:1730017]")

    def test_space_warrior_and_steam64(self):
        self.assertEqual(normalize_steamid("STEAM_0:1:865008"), "[U:1:1730017]")
        self.assertEqual(normalize_steamid("steam_0:1:865008"), "[U:1:1730017]")
        self.assertEqual(normalize_steamid("76561197961995745"), "[U:1:1730017]")
        self.assertEqual(normalize_steamid(76561197961995745), "[U:1:1730017]")
        self.assertEqual(normalize_steamid("https://steamcommunity.com/profiles/76561197961995745"), "[U:1:1730017]")

    def test_bare_account_id(self):
        self.assertEqual(normalize_steamid(1730017), "[U:1:1730017]")

    def test_bare_account_id_as_string(self):
        self.assertEqual(normalize_steamid("1730017"), "[U:1:1730017]")
        self.assertIsNone(normalize_steamid("0"))

    def test_out_of_range_account_ids_are_rejected(self):
        for value in ("[U:1:0]", "[U:1:4294967296]", "U:1:0", "[U:1:0:1]"):
            self.assertIsNone(normalize_steamid(value), value)
        self.assertEqual(normalize_steamid("[U:1:4294967295]"), "[U:1:4294967295]")

    def test_steam2_ids_are_range_checked_too(self):
        # Regression: the STEAM_X:Y:Z branch used to mint [U:1:0] and
        # account ids far beyond 32 bits.
        self.assertIsNone(normalize_steamid("STEAM_0:0:0"))
        self.assertIsNone(normalize_steamid("STEAM_0:1:99999999999"))
        self.assertEqual(normalize_steamid("STEAM_0:1:2147483647"), "[U:1:4294967295]")

    def test_absurdly_large_int_is_rejected_without_crashing(self):
        self.assertIsNone(normalize_steamid(10**5000))

    def test_absurdly_long_digit_strings_are_rejected_without_crashing(self):
        # Beyond Python's int-parsing digit limit: hostile/corrupt input
        # must be rejected, not crash the sync.
        huge = "9" * 5000
        for value in (f"[U:1:{huge}]", huge, f"STEAM_0:1:{huge}"):
            self.assertIsNone(normalize_steamid(value), value[:20])
        # Leading zeros do not count towards the limit.
        self.assertEqual(normalize_steamid("0" * 5000 + "1730017"), "[U:1:1730017]")

    def test_rejects_garbage(self):
        for value in (
            None,
            "",
            "unknown",
            "[U:1:abc]",
            "https://steamcommunity.com/id/garou",
            True,
            123456789012345678,
        ):
            self.assertIsNone(normalize_steamid(value), value)

    def test_account_id(self):
        self.assertEqual(account_id("[U:1:1730017]"), 1730017)
        self.assertEqual(account_id("STEAM_0:1:865008"), 1730017)
        self.assertIsNone(account_id("nope"))

    def test_steam_profile_url(self):
        self.assertEqual(steam_profile_url("[U:1:269327660]"), "https://steamcommunity.com/profiles/76561198229593388")
        self.assertEqual(steam_profile_url("STEAM_0:1:865008"), "https://steamcommunity.com/profiles/76561197961995745")
        self.assertIsNone(steam_profile_url("nope"))
        self.assertIsNone(steam_profile_url(None))


class PluralTests(unittest.TestCase):
    def test_singular(self):
        self.assertEqual(plural(1, "entry", "entries"), "entry")

    def test_plural(self):
        self.assertEqual(plural(2, "entry", "entries"), "entries")
        self.assertEqual(plural(0, "entry", "entries"), "entries")


class AttributeTests(unittest.TestCase):
    def test_order_and_dedupe(self):
        self.assertEqual(order_attributes(["racist", "cheater", "racist"]), ["cheater", "racist"])
        self.assertEqual(order_attributes(["suspicious"]), ["suspicious"])

    def test_unknown_attributes_sort_last(self):
        self.assertEqual(order_attributes(["zeta", "racist", "cheater"]), ["cheater", "racist", "zeta"])


class SortPlayersTests(unittest.TestCase):
    def test_numeric_order(self):
        players = [
            {"steamid": "[U:1:20]", "attributes": ["cheater"]},
            {"steamid": "[U:1:3]", "attributes": ["cheater"]},
        ]
        self.assertEqual([player["steamid"] for player in sort_players(players)], ["[U:1:3]", "[U:1:20]"])

    def test_non_object_entries_do_not_crash_the_sort(self):
        players = ["not an object", {"steamid": "[U:1:7]", "attributes": []}, 42]
        self.assertEqual(sort_players(players)[0]["steamid"], "[U:1:7]")

    def test_unusable_steamids_go_last_and_keep_their_order(self):
        players = [
            {"steamid": "bad", "attributes": []},
            {"steamid": "[U:1:7]", "attributes": []},
            {"steamid": "worse", "attributes": []},
        ]
        self.assertEqual([player["steamid"] for player in sort_players(players)], ["[U:1:7]", "bad", "worse"])


class SerialisationTests(unittest.TestCase):
    def test_round_trip_is_byte_identical(self):
        database = {
            "$schema": "https://example.invalid/schema.json",
            "file_info": {"authors": ["A"], "title": "T", "description": "D"},
            "players": [
                {"attributes": ["racist"], "last_seen": {"player_name": "німий", "time": 5}, "steamid": "[U:1:1]"}
            ],
        }
        rendered = dumps(database)
        self.assertTrue(rendered.endswith("}\n"))
        self.assertIn('\n\t"players"', rendered)
        self.assertNotIn("н", rendered)
        self.assertEqual(json.loads(rendered), database)
        self.assertEqual(dumps(json.loads(rendered)), rendered)

    def test_load_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "list.json"
            text = dumps({"$schema": "x", "file_info": {}, "players": []})
            path.write_text(text, encoding="utf-8")

            database, original = load(path)
            self.assertEqual(original, text)
            self.assertEqual(database["players"], [])
            self.assertEqual(dumps(database), text)

    def test_load_reports_broken_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / "broken.json"
            broken.write_text("{not json", encoding="utf-8")
            with self.assertRaises(PlayerListError):
                load(broken)

            with self.assertRaises(PlayerListError):
                load(Path(tmp) / "missing.json")


class ValidateTests(unittest.TestCase):
    def test_valid_database(self):
        result = validate({"players": [{"steamid": "[U:1:1]", "attributes": ["cheater"]}]})
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])

    def test_players_must_be_a_list(self):
        result = validate({"players": {}})
        self.assertEqual(result.errors, ["'players' is not an array"])

    def test_duplicate_steamid_is_an_error(self):
        result = validate(
            {
                "players": [
                    {"steamid": "[U:1:1]", "attributes": ["cheater"]},
                    {"steamid": "STEAM_0:1:0", "attributes": ["cheater"]},
                ]
            }
        )
        self.assertTrue(any("duplicate steamid" in error for error in result.errors))

    def test_unusable_steamid_and_missing_attributes_are_errors(self):
        result = validate({"players": [{"steamid": "nope", "attributes": []}]})
        self.assertEqual(len(result.errors), 2)

    def test_duplicate_attributes_are_an_error(self):
        result = validate({"players": [{"steamid": "[U:1:1]", "attributes": ["cheater", "cheater"]}]})
        self.assertTrue(any("duplicate attributes" in error for error in result.errors))

    def test_malformed_proof_is_an_error(self):
        result = validate({"players": [{"steamid": "[U:1:1]", "attributes": ["cheater"], "proof": "a link"}]})
        self.assertTrue(any("malformed 'proof'" in error for error in result.errors))

    def test_non_string_attribute_is_an_error_not_a_crash(self):
        result = validate({"players": [{"steamid": "[U:1:1]", "attributes": ["cheater", ["racist"]]}]})
        self.assertTrue(any("non-string attribute" in error for error in result.errors))

    def test_unknown_attribute_is_only_a_warning(self):
        result = validate({"players": [{"steamid": "[U:1:1]", "attributes": ["scammer"]}]})
        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.warnings), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
