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
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import sources
import sync_vorobey_hackerpolice as cli
from playerlist import (
    PlayerListError,
    ValidationResult,
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
from report import (
    MAX_CLOSING_STEAMIDS,
    MAX_DEMOTION_CHARS,
    MAX_PROMOTION_CHARS,
    MAX_REMOVED_CHARS,
    RunInfo,
    plural,
    render_closing,
    render_report,
)
from sources import (
    PROOF_MARKER,
    HackerpoliceIndex,
    SyncError,
    added_steamids,
    is_url,
    load_first_available_raw,
    load_snapshot,
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


class IndexDuplicateTests(unittest.TestCase):
    def test_duplicate_upstream_entries_collapse_onto_the_first(self):
        first = hackerpolice_entry("[U:1:100]", ["https://first.test/1"])
        second = hackerpolice_entry("[U:1:100]", ["https://second.test/2"])
        index = HackerpoliceIndex.build({"players": [first, second, hackerpolice_entry("not a steamid")]})
        self.assertEqual(len(index.by_steamid), 1)
        self.assertEqual(index.by_steamid["[U:1:100]"]["proof"], ["https://first.test/1"])
        self.assertEqual(index.total, 3)
        self.assertEqual(index.skipped, 1)  # the unusable one
        self.assertEqual(index.duplicates, 1)  # the repeated one

    def test_no_duplicates_in_a_clean_list(self):
        self.assertEqual(HackerpoliceIndex.build({"players": [hackerpolice_entry("[U:1:1]")]}).duplicates, 0)


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
        # download_url is untrusted response data: a plaintext, local or
        # third-party target must be rejected, not fetched (SSRF).
        for bad_url in (
            "http://example.invalid/raw.json",
            "/etc/passwd",
            "https://example.invalid/raw.json",
            "https://internal-metadata.example/latest",
            "https://github.com.evil.example/raw.json",  # look-alike host
        ):
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
            {
                "encoding": "none",
                "content": "",
                "download_url": "https://raw.githubusercontent.com/Nocrex/Tom/main/playerlist.vorobey-hackerpolice.json",
            }
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

    def test_oversized_local_source_is_rejected(self):
        # A local --source is operator-chosen, but pointing it at a huge file
        # must be a clean error, not an out-of-memory kill mid-run.
        big = Path(tempfile.mkdtemp()) / "big.json"
        self.addCleanup(shutil.rmtree, big.parent)
        big.write_bytes(b'{"players": []}' + b" " * 5_000_000)
        with mock.patch("sources.MAX_SOURCE_BYTES", 1024), self.assertRaises(SyncError) as caught:
            load_first_available_raw([str(big)])
        self.assertIn("safety limit", str(caught.exception))

    def test_oversized_snapshot_is_rejected(self):
        path = Path(tempfile.mkdtemp()) / "snap.json"
        self.addCleanup(shutil.rmtree, path.parent)
        path.write_bytes(b'{"players": []}' + b" " * 5_000_000)
        with mock.patch("sources.MAX_SOURCE_BYTES", 1024), self.assertRaises(SyncError):
            load_snapshot(path)

    def test_an_unparseable_source_is_a_clean_error(self):
        with (
            mock.patch("sources.urllib.request.urlopen", side_effect=[_FakeResponse(b"{not json")]),
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError) as caught,
        ):
            load_first_available_raw([self.URL])
        self.assertIn("is not valid JSON", str(caught.exception))

    def test_a_source_that_is_not_an_object_is_a_clean_error(self):
        with (
            mock.patch("sources.urllib.request.urlopen", side_effect=[_FakeResponse(b"[1, 2, 3]")]),
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError) as caught,
        ):
            load_first_available_raw([self.URL])
        self.assertIn("does not contain a JSON object", str(caught.exception))

    def test_an_envelope_that_unwraps_to_the_wrong_shape_is_a_clean_error(self):
        envelope = json.dumps({"encoding": "base64", "content": base64.b64encode(b'{"not": "a playerlist"}').decode()})
        with (
            mock.patch("sources.urllib.request.urlopen", side_effect=[_FakeResponse(envelope.encode("utf-8"))]),
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError) as caught,
        ):
            load_first_available_raw([self.URL])
        self.assertIn("no 'players' array in response", str(caught.exception))

    def test_the_github_api_request_asks_for_the_raw_media_type(self):
        """Without this header the API answers with a JSON envelope, not the file."""
        with (
            mock.patch("sources.urllib.request.urlopen", return_value=_FakeResponse(self.BODY)) as urlopen,
            mock.patch("sources.time.sleep"),
        ):
            load_first_available_raw(["https://api.github.com/repos/Nocrex/Tom/contents/list.json"])
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_header("Accept"), "application/vnd.github.raw")

    def test_http_get_refuses_anything_but_http(self):
        # Defence in depth: even if a caller slips through, no other scheme
        # (file:, data:, ftp:, ...) may ever reach urlopen.
        for url in ("file:///etc/passwd", "data:text/plain,x", "ftp://example.invalid/x", "javascript:alert(1)"):
            with self.assertRaises(SyncError):
                sources._http_get(url, timeout=1)

    def test_a_connection_failure_is_retried_then_reported_cleanly(self):
        error = urllib.error.URLError("connection refused")
        with (
            mock.patch("sources.urllib.request.urlopen", side_effect=error) as urlopen,
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError) as caught,
        ):
            load_first_available_raw([self.URL])
        self.assertEqual(urlopen.call_count, sources.FETCH_ATTEMPTS)
        self.assertIn("could not fetch", str(caught.exception))

    def test_a_malformed_base64_envelope_is_a_clean_error(self):
        envelope = json.dumps({"encoding": "base64", "content": "AAAAA"}).encode("utf-8")
        with (
            mock.patch("sources.urllib.request.urlopen", side_effect=[_FakeResponse(envelope)]),
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

    def test_suspicious_and_racist_keeps_its_existing_proofs(self):
        """Promotion adds no proof: the entry's own proofs stay as they were."""
        proofs = ['[auto] automatically marked: Racist | reason: "chat log"', "https://existing.test/1"]
        database, _ = self.promote([player("[U:1:300]", ["suspicious", "racist"], proof=list(proofs))])
        self.assertEqual(database["players"][0]["attributes"], ["cheater", "racist"])
        self.assertEqual(database["players"][0]["proof"], proofs)

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

    def test_include_proof_sanitises_and_caps_upstream_evidence(self):
        """Upstream proof text ends up in OUR database with --include-proof.

        So it must not be able to smuggle a newline/control character into
        the JSON, and one hostile entry must not add a huge proof line.
        """
        proofs = [
            "https://x/1\nDROP TABLE",
            "https://x/1\nDROP TABLE",  # duplicate once normalised
            "\x00\x07",  # control characters only -> empty after cleaning
            None,
            42,
        ] + [f"https://x/{n}" for n in range(50)]
        index = index_of(hackerpolice_entry("[U:1:100]", proofs))
        database = {"$schema": "x", "file_info": {"title": "t"}, "players": [player("[U:1:100]", ["suspicious"])]}
        promote(database, index, include_proof=True)
        line = database["players"][0]["proof"][0]
        self.assertNotIn("\n", line)
        self.assertNotIn("\x00", line)
        self.assertEqual(line.count("https://x/1 DROP TABLE"), 1)
        self.assertEqual(line.count("https://x/"), 10)  # capped

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

    def test_cheater_and_another_tag_keeps_the_entry(self):
        """Only the cheater tag is Vorobey's business; delete nothing else.

        Demoting used to delete any entry that was not ``cheater``+``racist``
        outright, silently dropping an ``exploiter`` / ``suspicious`` tag (and
        the player) that the hackerpolice list had nothing to do with.
        """
        database, changes = self.demote(
            [player("[U:1:200]", ["cheater", "exploiter"], proof=["https://video.test/exploit"])]
        )
        self.assertEqual(database["players"][0]["attributes"], ["exploiter"])
        self.assertEqual(database["players"][0]["proof"], [])  # the cheater evidence went with it
        self.assertEqual(changes[0].after, ("exploiter",))

    def test_cheater_and_an_unknown_tag_keeps_the_entry(self):
        database, changes = self.demote([player("[U:1:200]", ["cheater", "scammer"])])
        self.assertEqual(database["players"][0]["attributes"], ["scammer"])
        self.assertEqual(changes[0].after, ("scammer",))

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

    def test_only_the_exact_racist_prefix_survives_a_demotion(self):
        proofs = [
            '[auto] automatically marked: Racist | reason: "keep me"',
            "[auto] automatically marked: Racist | reason:",  # bare, but exactly the prefix
            "[auto] automatically marked: Racist | reason",  # no colon -> cheater evidence
            "[auto] automatically marked: Racist",  # no reason at all -> cheater evidence
            '[auto] automatically marked: racist | reason: "x"',  # wrong case
            f"{PROOF_MARKER} (https://github.com/Nocrex/Tom)",  # our own promotion line
            "https://video.test/1",
        ]
        database, _ = self.demote([player("[U:1:200]", ["cheater", "racist"], proof=list(proofs))])
        self.assertEqual(
            database["players"][0]["proof"],
            [
                '[auto] automatically marked: Racist | reason: "keep me"',
                "[auto] automatically marked: Racist | reason:",
            ],
        )

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
                remaining = set(before["attributes"]) - {"cheater"}
                if demoted and not remaining:
                    self.assertNotIn(steamid, after)  # cheater-only: entry gone
                    continue
                self.assertIn(steamid, after)  # nothing else may ever vanish
                got = after[steamid]
                if demoted:  # only the cheater tag goes, proofs with it
                    self.assertEqual(set(got["attributes"]), remaining)
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


class PolicyRobustnessTests(unittest.TestCase):
    """``promote``/``demote`` never trust their input: bad entries are skipped.

    The CLI validates before calling them, so these branches only run if a
    caller forgets to -- which must still not crash or corrupt anything.
    """

    def test_promote_skips_a_malformed_document(self):
        self.assertEqual(promote({"players": None}, index_of()), [])
        self.assertEqual(
            promote(
                {
                    "players": [
                        None,
                        "not an entry",
                        {"steamid": "[U:1:1]", "attributes": "cheater"},
                        {"steamid": "[U:1:2]", "attributes": [1]},
                        {"steamid": "not a steamid", "attributes": ["suspicious"]},
                    ]
                },
                index_of(hackerpolice_entry("[U:1:1]"), hackerpolice_entry("[U:1:2]")),
            ),
            [],
        )

    def test_demote_skips_a_malformed_document(self):
        self.assertEqual(demote({"players": None}, ["[U:1:1]"]), [])
        database = {
            "players": [
                None,
                {"steamid": "not a steamid", "attributes": ["cheater"]},
                {"steamid": "[U:1:1]", "attributes": "cheater"},
                {"steamid": "[U:1:2]", "attributes": [1]},
                {"steamid": "[U:1:3]", "attributes": ["racist"]},
            ]
        }
        self.assertEqual(demote(database, ["[U:1:1]", "[U:1:2]", "[U:1:3]"]), [])
        self.assertEqual(len(database["players"]), 5)  # nothing was dropped
        self.assertIsNone(database["players"][0])


# --------------------------------------------------------------------------- #
# Report rendering
# --------------------------------------------------------------------------- #
class ReportTests(unittest.TestCase):
    def info(self, changes=(), **kwargs):
        defaults = {"source_total": 10, "source_skipped": 0, "dry_run": False}
        return RunInfo(
            database_path=Path("playerlist.garou3299.json"),
            source="https://example.invalid/list.json",
            changes=tuple(changes),
            **{**defaults, **kwargs},
        )

    def test_a_demoted_entry_that_keeps_another_tag_is_not_shown_as_removed(self):
        """Demotion only removes the cheater tag: the row must say so."""
        change = Change("[U:1:100]", "a", ("cheater", "exploiter"), ("exploiter",), kind="demote")
        report = render_report(self.info([change]))
        self.assertIn("| `[U:1:100]` | [a](https://steamcommunity.com/profiles/76561197960265828)", report)
        self.assertIn("`cheater`, `exploiter` | `exploiter` |", report)
        self.assertNotIn("entry removed", report)
        self.assertIn("Attribute is changed for this SteamID: [U:1:100]", report)

    def test_an_entry_that_loses_its_last_tag_is_shown_as_removed(self):
        change = Change("[U:1:100]", "a", ("cheater",), (), kind="demote")
        report = render_report(self.info([change]))
        self.assertIn("| `cheater` | entry removed |", report)
        self.assertIn("Entry is removed from the database for this SteamID: [U:1:100]", report)

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

    def test_the_removed_table_ignores_the_order_the_ids_arrive_in(self):
        # run() hands over tuple(frozenset), whose order varies with the
        # process: the rendered table must not, or every PR body would churn.
        ids = ["[U:1:300]", "[U:1:100]", "[U:1:42]", "[U:1:200]"]
        with mock.patch("report.time.strftime", return_value="frozen"):
            forward = render_report(self.info(removed_upstream=tuple(ids), removed_from_source=len(ids)))
            backward = render_report(self.info(removed_upstream=tuple(reversed(ids)), removed_from_source=len(ids)))
        self.assertEqual(forward, backward)
        rows = [line for line in forward.splitlines() if line.startswith("| `[U:1:")]
        self.assertEqual(
            rows,
            [
                "| `[U:1:42]` | [profile](https://steamcommunity.com/profiles/76561197960265770) |",
                "| `[U:1:100]` | [profile](https://steamcommunity.com/profiles/76561197960265828) |",
                "| `[U:1:200]` | [profile](https://steamcommunity.com/profiles/76561197960265928) |",
                "| `[U:1:300]` | [profile](https://steamcommunity.com/profiles/76561197960266028) |",
            ],
        )

    def test_duplicate_upstream_entries_are_reported(self):
        # "10 entries" next to a "8 -> 8 entries" diff would look like a bug.
        report = render_report(self.info(source_duplicates=2))
        self.assertIn("Vorobey hackerpolice list (10 entries, 2 duplicates)", report)

    def test_a_single_duplicate_is_singular(self):
        self.assertIn("1 duplicate", render_report(self.info(source_duplicates=1)))

    def test_unusable_upstream_entries_are_reported(self):
        report = render_report(self.info(source_skipped=3))
        self.assertIn("Vorobey hackerpolice list (10 entries, 3 unusable)", report)

    def test_blank_text_renders_as_a_dash_cell(self):
        from report import _cell

        self.assertEqual(_cell("   "), "-")
        self.assertEqual(_cell("a|b"), "a\\|b")  # a pipe can never split the row
        self.assertEqual(_cell("<b>x</b>"), "&lt;b&gt;x&lt;/b&gt;")

    def test_sections_are_separated_by_exactly_one_blank_line(self):
        changes = [
            Change("[U:1:100]", "a", ("suspicious",), ("cheater",), ("https://p/1",)),
            Change("[U:1:200]", "b", ("cheater", "racist"), ("racist",), kind="demote"),
        ]
        report = render_report(
            self.info(changes, previous_source_total=10, removed_from_source=1, removed_upstream=("[U:1:200]",))
        )
        self.assertNotIn("\n\n\n", report)
        self.assertIn("|\n\nAttributes are changed", report)

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

    def test_untrusted_cell_text_cannot_inject_html(self):
        # The Vorobey list is outside our control: markup in a proof line (or
        # in a name) must render as text, not as a live <a href> phishing
        # link inside this repository's pull request.
        name = '<img src=x onerror=alert(1)> & "Tom & Jerry"'
        proof = '<a href="https://evil.example">Free items</a>'
        report = render_report(self.info([Change("[U:1:1]", name, ("suspicious",), ("cheater",), (proof,))]))
        self.assertNotIn("<img", report)
        self.assertNotIn("<a href", report)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", report)
        # No tag can be formed at all once < and > are escaped; the visible
        # text (entities render back to the original characters) is intact.
        self.assertIn('&lt;a href="https://evil.example"&gt;Free items&lt;/a&gt;', report)
        self.assertIn('&amp; "Tom &amp; Jerry"', report)

    def test_link_targets_escape_backslashes_and_brackets(self):
        # The Vorobey list is outside our control: a proof string must not be
        # able to close the link target early and inject Markdown.
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",), ("https://x/\\[a](b) ",))
        report = render_report(self.info([change]))
        self.assertIn("https://x/%5C%5Ba%5D%28b%29%20", report)
        self.assertNotIn("](b)", report)

    def test_dry_run_and_include_proof_notes(self):
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",))
        report = render_report(self.info([change], dry_run=True, include_proof=True))
        self.assertIn("**dry run**", report)
        self.assertIn("`--include-proof` was enabled", report)

    def test_report_names_the_snapshot_file_actually_used(self):
        # Regression: the summary used to print a hardcoded snapshot path, so
        # a run with --snapshot somewhere else described a file it never
        # touched.
        report = render_report(self.info(snapshot_changed=True, snapshot_path=Path("custom/baseline.json")))
        self.assertIn("- Snapshot: `custom/baseline.json` updated to an exact copy", report)
        self.assertNotIn("snapshot/playerlist.vorobey-hackerpolice.json` updated", report)

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
        accounts = range(1, 5000)
        removed = tuple(f"[U:1:{account}]" for account in accounts)
        report = render_report(
            self.info(previous_source_total=10000, removed_from_source=len(removed), removed_upstream=removed)
        )
        rows = report.count("| [profile](")
        self.assertLess(rows, len(removed))
        self.assertGreater(rows, 100)  # a normal day is never truncated
        self.assertIn(f"…and {len(removed) - rows} more SteamIDs (the snapshot diff", report)
        self.assertLess(len(report), 65536)

    def test_table_budgets_always_leave_room_under_the_github_body_limit(self):
        # GitHub rejects a pull request body above 65536 characters and this
        # report IS that body: the three table budgets plus the prose around
        # them must never add up to it.
        tables = MAX_PROMOTION_CHARS + MAX_DEMOTION_CHARS + MAX_REMOVED_CHARS
        self.assertLess(tables, 65536 - 4000)

    def test_a_massive_run_still_produces_a_deliverable_pull_request_body(self):
        """GitHub rejects a body over 65536 characters: the report IS the body.

        A run where upstream suddenly matches (or drops) the whole database
        used to render ~108k characters, so the API call failed and the report
        was lost. Every table is budgeted, with a pointer to the diff.
        """
        names = ["x" * 31] * 800
        promotions = tuple(
            Change(
                f"[U:1:{n}]",
                names[n],
                ("suspicious", "racist"),
                ("cheater", "racist"),
                ("https://discord.com/channels/1/" + "9" * 40,),
            )
            for n in range(800)
        )
        demotions = tuple(
            Change(f"[U:1:{n}]", names[n], ("cheater", "racist"), ("racist",), kind="demote") for n in range(800)
        )
        removed = tuple(f"[U:1:{n}]" for n in range(1, 3000))
        report = render_report(
            self.info(
                [*promotions, *demotions],
                previous_source_total=5800,
                added_to_source=0,
                removed_from_source=len(removed),
                removed_upstream=removed,
                snapshot_changed=True,
            )
        )
        self.assertLess(len(report), 65536, "the PR body would be rejected by GitHub")
        self.assertIn("promoted to `cheater`", report)
        self.assertIn("…and", report)
        self.assertIn("the database diff", report)
        self.assertIn("the snapshot diff", report)
        # The counts in the headings stay truthful even when rows are hidden.
        self.assertIn("**800 entries promoted", report)
        self.assertIn("**800 entries demoted", report)
        self.assertIn("**2999 SteamIDs removed", report)


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

    def test_a_long_list_of_steamids_is_truncated(self):
        # The closing sentence must not become a second, uncapped copy of the
        # tables: on a mass run that alone blew past the PR body limit.
        changes = [
            Change(f"[U:1:{account}]", "a", ("suspicious",), ("cheater",))
            for account in range(MAX_CLOSING_STEAMIDS + 5)
        ]
        closing = render_closing(changes)
        self.assertIn(f"and {len(changes) - MAX_CLOSING_STEAMIDS} more", closing)
        self.assertNotIn(f"[U:1:{MAX_CLOSING_STEAMIDS + 1}]", closing)
        self.assertIn(f"[U:1:{MAX_CLOSING_STEAMIDS - 1}]", closing)  # the last shown one
        self.assertLess(len(closing), 400)


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

    def test_a_symlinked_database_is_updated_through_the_link(self):
        """Replacing the link instead would silently stop TF2BD's updates.

        ``cfg/playerlist.json`` pointing at this repository is the usual way
        people wire the file into the game, so the link must survive and the
        real file must be the one that changes.
        """
        real = self.root / "real-list.json"
        real.write_bytes(self.database.read_bytes())
        try:
            self.database.unlink()
            self.database.symlink_to(real)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are not available here")

        code, _, _ = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 0)
        self.assertTrue(self.database.is_symlink())  # the link survived
        players = {p["steamid"]: p for p in json.loads(real.read_text(encoding="utf-8"))["players"]}
        self.assertEqual(players["[U:1:100]"]["attributes"], ["cheater"])  # target updated
        self.assertEqual(players["[U:1:200]"]["attributes"], ["cheater", "racist"])

    def test_a_symlinked_snapshot_is_updated_through_the_link(self):
        real = self.root / "real-snapshot.json"
        real.write_text(
            dumps({"$schema": "x", "file_info": {}, "players": [hackerpolice_entry("[U:1:100]")]}), encoding="utf-8"
        )
        snapshot = self.root / "snapshot.json"
        try:
            snapshot.symlink_to(real)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are not available here")

        code, _, _ = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 0)
        self.assertTrue(snapshot.is_symlink())
        self.assertEqual(real.read_bytes(), self.source.read_bytes())  # verbatim copy of upstream

    def test_a_snapshot_symlink_loop_is_a_clean_error(self):
        """Path.exists() is False for a looping link, so the write is where it surfaces."""
        loop = self.root / "loop-snapshot"
        try:
            loop.symlink_to(loop)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are not available here")

        code, _, stderr = self.run_cli("--source", str(self.source), "--snapshot", str(loop))
        self.assertEqual(code, 2)
        self.assertIn("cannot be resolved", stderr)
        self.assertNotIn("Traceback", stderr)
        self.assertIn("players", json.loads(self.database.read_text(encoding="utf-8")))  # never corrupted

    def test_a_dangling_snapshot_symlink_creates_its_target(self):
        target = self.root / "not-created-yet.json"
        snapshot = self.root / "snapshot.json"
        try:
            snapshot.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are not available here")

        code, _, stderr = self.run_cli("--source", str(self.source), "--demote")
        self.assertEqual(code, 0)
        self.assertIn("no snapshot", stderr)  # nothing can be demoted without a baseline
        self.assertTrue(snapshot.is_symlink())
        self.assertEqual(target.read_bytes(), self.source.read_bytes())  # the baseline was created

    def test_a_write_failure_names_the_file_not_a_temp_file(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("running as root: permissions do not restrict writes")
        locked = self.root / "locked"
        locked.mkdir()
        database = locked / "list.json"
        database.write_bytes(self.database.read_bytes())
        os.chmod(locked, 0o500)
        self.addCleanup(os.chmod, locked, 0o700)
        script = Path(__file__).resolve().parents[1] / "scripts" / "sync_vorobey_hackerpolice.py"
        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "--database",
                str(database),
                "--snapshot",
                str(self.root / "snapshot.json"),
                "--source",
                str(self.source),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(f"cannot write {database}", result.stderr)
        self.assertNotIn(".tmp", result.stderr)  # no temp-file name leaked to the user

    def test_the_database_file_mode_is_preserved(self):
        # mkstemp creates 0600 files: the replacement must not silently make
        # a shared/read-only playerlist unreadable to everyone else.
        os.chmod(self.database, 0o444)
        code, _, _ = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 0)
        self.assertEqual(stat.S_IMODE(self.database.stat().st_mode), 0o444)

    def test_a_failed_write_leaves_no_temp_file_and_no_half_written_file(self):
        original = self.database.read_text(encoding="utf-8")
        with mock.patch("pathlib.Path.replace", side_effect=OSError("disk full")):
            code, _, stderr = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 2)
        self.assertIn("disk full", stderr)
        self.assertEqual(self.database.read_text(encoding="utf-8"), original)  # untouched
        self.assertEqual(list(self.root.glob(".*.tmp")), [])  # no debris left behind

    def test_a_directory_that_cannot_be_fsynced_is_not_an_error(self):
        # A missing/unfsyncable directory (Windows, some network mounts) must
        # not fail the run: the rename itself is already atomic.
        cli._fsync_directory(self.root / "does-not-exist")  # must not raise

    def test_a_samefile_error_does_not_block_the_run(self):
        with mock.patch("os.path.samefile", side_effect=OSError("no such device")):
            code, _, _ = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 0)

    def test_an_invalid_sync_result_is_never_written(self):
        """Safety net behind the policy: an invalid result must not reach disk."""
        original = self.database.read_text(encoding="utf-8")
        broken = ValidationResult()
        broken.errors.append("boom")
        with mock.patch("sync_vorobey_hackerpolice.validate", side_effect=[ValidationResult(), broken]):
            code, _, stderr = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 2)
        self.assertIn("the synced playerlist is invalid", stderr)
        self.assertEqual(self.database.read_text(encoding="utf-8"), original)

    def test_the_entry_point_runs_as_a_command(self):
        """Exactly how the workflow calls it: ``python3 scripts/<tool>.py``."""
        script = Path(__file__).resolve().parents[1] / "scripts" / "sync_vorobey_hackerpolice.py"
        result = subprocess.run(
            [sys.executable, str(script), "--version"], capture_output=True, text=True, timeout=60, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sync_vorobey_hackerpolice.py", result.stdout)

    def test_snapshot_must_not_be_the_database(self):
        code, _, stderr = self.run_cli("--source", str(self.source), "--snapshot", str(self.database))
        self.assertEqual(code, 2)
        self.assertIn("must be different files", stderr)

    def test_quiet_keeps_the_progress_log_off_the_console(self):
        code, stdout, stderr = self.run_cli("--source", str(self.source), "-q")
        self.assertEqual(code, 0)
        self.assertEqual(stderr.strip(), "")  # no "Indexed ..."/"Updated ..." noise
        self.assertIn("Vorobey hackerpolice sync", stdout)  # the report is still printed

    def test_an_interrupted_run_exits_130(self):
        with mock.patch("sync_vorobey_hackerpolice.run", side_effect=KeyboardInterrupt):
            code, _, stderr = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 130)
        self.assertIn("interrupted", stderr)

    def test_an_invalid_database_is_refused_with_the_reason(self):
        self.database.write_text(
            dumps({"$schema": "x", "file_info": {}, "players": [player("[U:1:100]", ["cheater"])] * 2}),
            encoding="utf-8",
        )
        code, _, stderr = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 2)
        self.assertIn("duplicate steamid", stderr)

    def test_unknown_attributes_are_kept_and_only_warned_about(self):
        self.database.write_text(
            dumps({"$schema": "x", "file_info": {}, "players": [player("[U:1:999]", ["scammer"])]}),
            encoding="utf-8",
        )
        code, _, stderr = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 0)  # a warning must not block the run
        self.assertIn("unknown attribute 'scammer'", stderr)
        self.assertEqual(json.loads(self.database.read_text(encoding="utf-8"))["players"][0]["attributes"], ["scammer"])

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

    def test_no_update_snapshot_demotes_but_leaves_the_baseline_alone(self):
        """Documented trade-off: untouched baseline => the same IDs are re-reported."""
        self.database.write_text(
            dumps({"$schema": "x", "file_info": {}, "players": [player("[U:1:300]", ["cheater"])]}),
            encoding="utf-8",
        )
        snapshot = self.write_snapshot_fixture(hackerpolice_entry("[U:1:300]"))
        baseline = snapshot.read_bytes()
        code, _, _ = self.run_cli(
            "--source", str(self.source), "--snapshot", str(snapshot), "--demote", "--no-update-snapshot"
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(self.database.read_text(encoding="utf-8"))["players"], [])  # demoted
        self.assertEqual(snapshot.read_bytes(), baseline)  # baseline never advanced

    def test_demote_keeps_an_entry_that_still_has_another_tag(self):
        """End-to-end: only the cheater tag goes, the player stays listed."""
        self.database.write_text(
            dumps(
                {
                    "$schema": "x",
                    "file_info": {},
                    "players": [
                        player("[U:1:300]", ["cheater", "exploiter"], proof=["https://video.test/1"]),
                    ],
                }
            ),
            encoding="utf-8",
        )
        snapshot = self.write_snapshot_fixture(hackerpolice_entry("[U:1:300]"))
        report_path = self.root / "r.md"
        code, _, _ = self.run_cli(
            "--source", str(self.source), "--snapshot", str(snapshot), "--demote", "--report", str(report_path)
        )
        self.assertEqual(code, 0)
        players = json.loads(self.database.read_text(encoding="utf-8"))["players"]
        self.assertEqual([p["attributes"] for p in players], [["exploiter"]])
        report = report_path.read_text(encoding="utf-8")
        self.assertIn("`cheater`, `exploiter` | `exploiter` |", report)
        self.assertNotIn("entry removed", report)

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
        self.assertNotIn("demoted (in the previous snapshot", report)  # no demotion table

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

    def test_verbose_really_logs_fetch_attempts(self):
        # Regression: -v used to change nothing at all (there were no debug
        # messages), while --help promised "log fetch attempts".
        code, _, stderr = self.run_cli("--source", str(self.source), "--dry-run", "-v")
        self.assertEqual(code, 0)
        self.assertIn("Source 1/1: trying", stderr)
        self.assertIn("Reading local file", stderr)
        self.assertIn("Source", stderr)

    def test_skipped_demotion_is_annotated_and_exposed(self):
        # A skip changes no file, so it would otherwise be a silent green run:
        # emit an Actions warning annotation and a step output.
        output_file = self.root / "github_output"
        output_file.write_text("", encoding="utf-8")
        code, stdout, _ = self.run_cli(
            "--source",
            str(self.source),
            "--demote",
            env={"GITHUB_OUTPUT": str(output_file), "GITHUB_ACTIONS": "true"},
        )
        self.assertEqual(code, 0)
        self.assertIn("::warning::Demotion skipped - no snapshot at", stdout)
        self.assertIn("demotion_skipped=true", output_file.read_text(encoding="utf-8").splitlines())

    def test_no_annotation_outside_github_actions(self):
        code, stdout, _ = self.run_cli("--source", str(self.source), "--demote")
        self.assertEqual(code, 0)
        self.assertNotIn("::warning::", stdout)

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
        self.assertIn("demotion_skipped=false", lines)

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

    def test_source_must_not_be_the_database_or_the_snapshot(self):
        # Syncing our own files against themselves would overwrite the
        # snapshot with the database (or vice versa) and silently disable
        # demotion forever, so it is refused outright.
        snapshot_fixture = self.write_snapshot_fixture(hackerpolice_entry("[U:1:100]"))
        for target, expected in (
            (self.database, "must not be the same file as --database"),
            (snapshot_fixture, "must not be the same file as --snapshot"),
        ):
            code, _, stderr = self.run_cli("--source", str(target))
            self.assertEqual(code, 2)
            self.assertIn(expected, stderr)
        # The database and the snapshot are intact.
        self.assertIn("[U:1:100]", self.database.read_text(encoding="utf-8"))
        self.assertEqual(
            snapshot_fixture.read_text(encoding="utf-8"),
            dumps(
                {
                    "$schema": "x",
                    "file_info": {},
                    "players": [hackerpolice_entry("[U:1:100]")],
                }
            ),
        )

    def test_report_path_must_not_alias_the_database(self):
        # Regression: the report is written before the database, so an
        # aliased --report destroyed the database (even in dry-run mode).
        original = self.database.read_text(encoding="utf-8")
        for extra in (("--report", str(self.database)), ("--report", str(self.database), "--dry-run")):
            code, _, stderr = self.run_cli("--source", str(self.source), *extra)
            self.assertEqual(code, 2)
            self.assertIn("--report must not be the same file", stderr)
            self.assertEqual(self.database.read_text(encoding="utf-8"), original)

    def test_report_names_the_snapshot_path_the_run_used(self):
        self.write_snapshot_fixture(hackerpolice_entry("[U:1:100]"))
        report_file = self.root / "r.md"
        code, _, _ = self.run_cli("--source", str(self.source), "--report", str(report_file))
        self.assertEqual(code, 0)
        report = report_file.read_text(encoding="utf-8")
        self.assertIn(f"- Snapshot: `{self.root / 'snapshot.json'}` updated to an exact copy", report)

    def test_symlink_loops_are_clean_errors_not_crashes(self):
        # Path.resolve() raises RuntimeError on a symlink loop: every path
        # comparison must survive that instead of crashing with a traceback.
        loop = self.root / "loop"
        try:
            loop.symlink_to(loop)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are not available here")
        # The report is unwritable -> clean "cannot write report", no traceback.
        code, _, stderr = self.run_cli("--source", str(self.source), "--report", str(loop))
        self.assertEqual(code, 2)
        self.assertIn("cannot write report", stderr)
        self.assertNotIn("Traceback", stderr)
        # ... and an unreadable --source is just a source failure.
        code, _, stderr = self.run_cli("--source", str(loop))
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", stderr)

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
# The five behaviours the database owner requires, end to end
# --------------------------------------------------------------------------- #
class AcceptedRequirementsTests(unittest.TestCase):
    """One test per required rule, run exactly like the workflow runs the bot.

    The same flags the workflow passes (``--demote --report``, never
    ``--include-proof``) against a database and an upstream list that cover
    all five cases at once.
    """

    RACIST_LINE = '[auto] automatically marked: Racist | reason: "sample chat log"'
    OTHER_LINE = "https://video.test/1"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.database = self.root / "list.json"
        self.snapshot = self.root / "snapshot.json"
        self.upstream = self.root / "upstream.json"
        self.report = self.root / "report.md"

        # [U:1:100]/[U:1:200] are on the upstream list; [U:1:300]/[U:1:400]
        # were in the previous snapshot and have since disappeared from it.
        self.database.write_text(
            dumps(
                {
                    "$schema": "x",
                    "file_info": {},
                    "players": [
                        player("[U:1:100]", ["suspicious"], proof=["https://existing.test/1"]),
                        player(
                            "[U:1:200]",
                            ["suspicious", "racist"],
                            proof=[self.RACIST_LINE, "https://existing.test/2"],
                        ),
                        player("[U:1:300]", ["cheater"], proof=[self.OTHER_LINE]),
                        player("[U:1:400]", ["cheater", "racist"], proof=[self.OTHER_LINE, self.RACIST_LINE, "note"]),
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.snapshot.write_text(
            dumps(
                {
                    "$schema": "x",
                    "file_info": {},
                    "players": [
                        hackerpolice_entry("[U:1:100]"),
                        hackerpolice_entry("[U:1:200]"),
                        hackerpolice_entry("[U:1:300]"),
                        hackerpolice_entry("[U:1:400]"),
                    ],
                }
            ),
            encoding="utf-8",
        )
        live = {
            "$schema": "x",
            "file_info": {},
            "players": [hackerpolice_entry("[U:1:100]"), hackerpolice_entry("[U:1:200]")],
        }
        # Deliberately NOT in the shape dumps() produces (two-space indent, no
        # trailing newline): the snapshot must be a byte copy of whatever
        # upstream served, never a re-render of it.
        self.upstream_bytes = json.dumps(live, indent="  ", ensure_ascii=False).encode("utf-8")
        self.upstream.write_bytes(self.upstream_bytes)

    def run_bot(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = [
            "--database",
            str(self.database),
            "--snapshot",
            str(self.snapshot),
            "--source",
            str(self.upstream),
            "--demote",
            "--report",
            str(self.report),
        ]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(argv)
        self.assertEqual(code, 0, stderr.getvalue())
        return {p["steamid"]: p for p in json.loads(self.database.read_text(encoding="utf-8"))["players"]}

    def test_1_suspicious_becomes_cheater_with_no_proof_added(self):
        players = self.run_bot()
        self.assertEqual(players["[U:1:100]"]["attributes"], ["cheater"])
        self.assertEqual(players["[U:1:100]"]["proof"], ["https://existing.test/1"])

    def test_2_suspicious_and_racist_becomes_cheater_and_racist_with_no_new_proof(self):
        players = self.run_bot()
        self.assertEqual(players["[U:1:200]"]["attributes"], ["cheater", "racist"])
        self.assertEqual(players["[U:1:200]"]["proof"], [self.RACIST_LINE, "https://existing.test/2"])

    def test_3_cheater_only_entry_is_deleted_when_it_leaves_the_upstream_list(self):
        players = self.run_bot()
        self.assertNotIn("[U:1:300]", players)

    def test_4_cheater_and_racist_keeps_racist_and_only_auto_racist_proofs(self):
        players = self.run_bot()
        self.assertEqual(players["[U:1:400]"]["attributes"], ["racist"])
        self.assertEqual(players["[U:1:400]"]["proof"], [self.RACIST_LINE])

    def test_5_snapshot_is_a_byte_for_byte_copy_of_the_upstream_file(self):
        self.run_bot()
        self.assertEqual(self.snapshot.read_bytes(), self.upstream_bytes)


# --------------------------------------------------------------------------- #
# The committed data files and the workflow glue
# --------------------------------------------------------------------------- #
REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"


class RepositoryDataTests(unittest.TestCase):
    """The data files ARE the product: they must stay canonical and usable."""

    def test_the_database_is_valid_and_round_trips_byte_for_byte(self):
        database, original = load(REPO_ROOT / "playerlist.garou3299.json")
        result = validate(database)
        self.assertFalse(result.errors, result.errors[:3])
        players = database["players"]
        self.assertTrue(players)
        # If this ever fails, someone hand-edited the formatting: the next bot
        # run would rewrite the whole file and hide the real change in a huge
        # diff no reviewer can read.
        self.assertEqual(dumps(database), original)
        ids = [p["steamid"] for p in players]
        self.assertEqual(ids, sorted(ids, key=account_id))  # numeric order, not lexical
        self.assertEqual(len(ids), len(set(ids)))

    def test_the_snapshot_is_a_usable_baseline(self):
        snapshot = load_snapshot(REPO_ROOT / DEFAULT_SNAPSHOT)
        self.assertIsNotNone(snapshot, "the demotion baseline is missing from the repository")
        index, raw = snapshot
        self.assertEqual(raw, (REPO_ROOT / DEFAULT_SNAPSHOT).read_bytes())
        self.assertGreater(len(index.by_steamid), 0)
        for steamid in index.by_steamid:
            self.assertEqual(normalize_steamid(steamid), steamid)  # canonical keys only

    def test_the_other_published_files_are_valid_json(self):
        for name in ("rules.garou3299.json", "playerlist.scammers.json"):
            document = json.loads((REPO_ROOT / name).read_text(encoding="utf-8"))
            self.assertIsInstance(document, dict, name)
            self.assertIn("file_info", document, name)


@unittest.skipUnless(WORKFLOWS.is_dir(), "workflow files are not present")
class WorkflowTests(unittest.TestCase):
    """Guards the glue no Python test would otherwise cover."""

    def read(self, name):
        return (WORKFLOWS / name).read_text(encoding="utf-8")

    def test_sync_workflow_still_demotes_and_uses_the_real_paths(self):
        text = self.read("sync-vorobey-hackerpolice.yml")
        # Dropping --demote would silently make the bot promote-only; a
        # renamed data file would point it at nothing.
        self.assertIn("--demote", text)
        self.assertIn("playerlist.garou3299.json", text)
        self.assertIn(DEFAULT_SNAPSHOT, text)
        # The PR body must come from the report the run wrote.
        self.assertIn("--report", text)
        self.assertIn("body-path:", text)

    def test_ci_runs_the_same_checks_on_pull_requests(self):
        text = self.read("ci.yml")
        self.assertIn("pull_request:", text)
        for check in ("ruff check", "ruff format --check", "mypy scripts", "unittest discover"):
            self.assertIn(check, text)

    def test_both_workflows_pin_the_same_tool_versions(self):
        sync, ci = self.read("sync-vorobey-hackerpolice.yml"), self.read("ci.yml")
        for tool in ("ruff", "mypy"):
            pinned = set(re.findall(rf"\b{tool}==([\w.]+)", sync))
            self.assertTrue(pinned, f"{tool} is not pinned in the sync workflow")
            self.assertEqual(pinned, set(re.findall(rf"\b{tool}==([\w.]+)", ci)), f"{tool} pins drifted")


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

    def test_non_ascii_digits_are_not_steamids(self):
        # "١٢٣" is Arabic-Indic for 123 and int() parses it: it used to be
        # silently accepted as [U:1:123]. Only ASCII digits are SteamIDs.
        for value in ("١٢٣", "[U:1:١٢٣]", "U:1:١٢٣", "١٢٣٤٥٦٧٨٩٠١٢٣٤٥٦٧٨"):
            self.assertIsNone(normalize_steamid(value), value)

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


class IsUrlTests(unittest.TestCase):
    """One predicate (sources.is_url) decides URL-vs-path everywhere."""

    def test_http_and_https_are_urls_whatever_the_case(self):
        for url in ("http://x/y", "https://x/y", "HTTPS://raw.githubusercontent.com/a/b"):
            self.assertTrue(is_url(url), url)

    def test_paths_are_not_urls(self):
        for path in ("playerlist.json", "/opt/db/x.json", "snapshot/x.json", "httpdocs/x.json", "", "ftp://x/y"):
            self.assertFalse(is_url(path), path)


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


class LoadTests(unittest.TestCase):
    def test_a_utf8_bom_is_tolerated(self):
        # Editors on Windows happily add a BOM; that must not make every run
        # fail with "not valid JSON" until a human fixes the file by hand.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "list.json"
            text = dumps({"$schema": "x", "file_info": {}, "players": []})
            path.write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))
            database, original = load(path)
            self.assertEqual(database["players"], [])
            self.assertEqual(original, text)  # BOM stripped, not carried into the output
            self.assertEqual(dumps(database), original)


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


class PlayerlistEdgeCaseTests(unittest.TestCase):
    def test_a_json_array_is_not_a_playerlist(self):
        path = Path(tempfile.mkdtemp()) / "list.json"
        self.addCleanup(shutil.rmtree, path.parent)
        path.write_text("[1, 2, 3]", encoding="utf-8")
        with self.assertRaises(PlayerListError) as caught:
            load(path)
        self.assertIn("does not contain a JSON object", str(caught.exception))

    def test_a_non_object_player_is_an_error(self):
        result = validate({"players": [1, "x", None]})
        self.assertEqual(len(result.errors), 3)
        self.assertIn("players[0] is not an object", result.errors[0])
        self.assertFalse(result)  # errors make the result falsy

    def test_a_clean_result_is_truthy(self):
        self.assertTrue(validate({"players": [player("[U:1:100]", ["cheater"])]}))

    def test_a_bare_integer_is_an_account_id_or_a_steamid64(self):
        self.assertEqual(account_id(1730017), 1730017)
        self.assertEqual(account_id(76561198229593388), 269327660)
        self.assertIsNone(account_id(True))

    def test_a_player_without_last_seen_has_no_name(self):
        from playerlist import player_name

        self.assertEqual(player_name({"steamid": "[U:1:100]"}), "")
        self.assertEqual(player_name({"last_seen": {"player_name": "a"}}), "a")


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
