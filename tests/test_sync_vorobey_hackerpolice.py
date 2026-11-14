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
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import playerlist as playerlist_module
import report as report_module
import sources
import sync_vorobey_hackerpolice as sync_module
from playerlist import (
    PlayerListError,
    ValidationResult,
    account_id,
    dumps,
    load,
    normalize_steamid,
    order_attributes,
    player_name,
    sort_players,
    steam_profile_url,
    validate,
)
from policy import Change, demote, is_racist_proof, promote, sync
from report import (
    MAX_CHANGE_TABLE_ROWS,
    MAX_REMOVED_TABLE_ROWS,
    MAX_REPORT_CHARS,
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
    load_first_available_raw,
    load_snapshot,
    removed_steamids,
)
from sync_vorobey_hackerpolice import DEFAULT_SNAPSHOT, build_parser, main, write_database

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
    def __init__(self, body: bytes, headers: dict[str, str] | None = None):
        self._body = body
        self.headers = headers or {}
        self.read_count = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        self.read_count += 1
        return self._body if size is None or size < 0 else self._body[:size]


class SourceFetchTests(unittest.TestCase):
    URL = "https://example.invalid/list.json"
    API_URL = "https://api.github.com/repos/Nocrex/Tom/contents/playerlist.vorobey-hackerpolice.json"
    BODY = b'\xef\xbb\xbf{"players": [{"steamid": "[U:1:100]", "attributes": ["cheater"]}]}'

    def fetch(self, side_effect):
        with (
            mock.patch("sources._OPENER.open", side_effect=side_effect) as urlopen,
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
                mock.patch("sources._OPENER.open", side_effect=[_FakeResponse(envelope)]) as urlopen,
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

    def test_redact_url_strips_credentials_only(self):
        self.assertEqual(sources.redact_url("https://u:secret@h.example/x?y=1"), "https://h.example/x?y=1")
        self.assertEqual(sources.redact_url("https://h.example:8443/x"), "https://h.example:8443/x")
        self.assertEqual(sources.redact_url("playerlist.garou3299.json"), "playerlist.garou3299.json")

    def test_fetch_errors_redact_credentials(self):
        """Failures are printed to a public Actions log: no tokens there."""
        url = "https://bot:ghp_secret@example.invalid/list.json"
        with (
            mock.patch("sources._OPENER.open", side_effect=urllib.error.URLError("boom")),
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError) as raised,
        ):
            load_first_available_raw([url])
        self.assertNotIn("ghp_secret", str(raised.exception))
        self.assertIn("https://example.invalid/list.json", str(raised.exception))

    def test_large_file_envelope_falls_back_to_the_git_blob_api(self):
        """Raw.githubusercontent unreachable + Contents API > 1 MB: the blob
        endpoint by sha is the only remaining way to get the file."""
        sha = "a" * 40
        envelope = json.dumps({"encoding": "none", "content": "", "sha": sha}).encode("utf-8")
        with (
            mock.patch(
                "sources._OPENER.open", side_effect=[_FakeResponse(envelope), _FakeResponse(self.BODY)]
            ) as opener,
            mock.patch("sources.time.sleep"),
        ):
            document, source, raw = load_first_available_raw([self.API_URL])
        self.assertEqual(raw, self.BODY)
        self.assertEqual(source, self.API_URL)
        self.assertEqual(len(document["players"]), 1)
        urls = [call.args[0].full_url for call in opener.call_args_list]
        self.assertEqual(urls[0], self.API_URL)
        self.assertEqual(urls[1], f"https://api.github.com/repos/Nocrex/Tom/git/blobs/{sha}")

    def test_git_blob_envelope_is_decoded_to_the_file_bytes(self):
        inner = b'{"players": [{"steamid": "[U:1:100]"}]}'
        sha = "b" * 40
        contents = json.dumps({"encoding": "none", "content": "", "sha": sha}).encode("utf-8")
        blob = json.dumps({"encoding": "base64", "content": base64.b64encode(inner).decode("ascii")}).encode("utf-8")
        with (
            mock.patch("sources._OPENER.open", side_effect=[_FakeResponse(contents), _FakeResponse(blob)]),
            mock.patch("sources.time.sleep"),
        ):
            document, _, raw = load_first_available_raw([self.API_URL])
        self.assertEqual(raw, inner)  # the envelope is never what gets snapshotted
        self.assertEqual(len(document["players"]), 1)

    def test_accept_header_matches_the_endpoint(self):
        """Contents endpoints must answer in JSON (raw is refused > 1 MB);
        blob endpoints return the file itself."""
        with (
            mock.patch("sources._OPENER.open", side_effect=[_FakeResponse(self.BODY)]) as opener,
            mock.patch("sources.time.sleep"),
        ):
            load_first_available_raw([self.API_URL])
        self.assertEqual(opener.call_args_list[0].args[0].get_header("Accept"), "application/vnd.github+json")

        blob_url = "https://api.github.com/repos/Nocrex/Tom/git/blobs/" + "a" * 40
        with (
            mock.patch("sources._OPENER.open", side_effect=[_FakeResponse(self.BODY)]) as opener,
            mock.patch("sources.time.sleep"),
        ):
            load_first_available_raw([blob_url])
        self.assertEqual(opener.call_args_list[0].args[0].get_header("Accept"), "application/vnd.github.raw")

    def test_blob_url_requires_the_github_api_and_a_valid_sha(self):
        self.assertIsNone(sources._github_blob_url(self.URL, "a" * 40))  # not the API host
        self.assertIsNone(sources._github_blob_url(self.API_URL, "not-a-sha"))
        self.assertIsNone(sources._github_blob_url(self.API_URL, None))
        self.assertEqual(
            sources._github_blob_url(self.API_URL, "c" * 64),
            "https://api.github.com/repos/Nocrex/Tom/git/blobs/" + "c" * 64,
        )

    def test_unparsable_source_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / "broken.json"
            broken.write_text("{not json", encoding="utf-8")
            array = Path(tmp) / "array.json"
            array.write_text("[]", encoding="utf-8")
            for path in (broken, array):
                with self.assertRaises(SyncError):
                    load_first_available_raw([str(path)])

    def test_non_http_scheme_is_refused(self):
        with self.assertRaises(SyncError):
            load_first_available_raw(["ftp://example.invalid/list.json"])

    def test_unreadable_snapshot_is_an_error_but_missing_one_is_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(load_snapshot(Path(tmp) / "absent.json"))
            with self.assertRaises(SyncError):
                load_snapshot(Path(tmp))  # a directory, not a file

    def test_bad_base64_envelope_falls_through_to_the_next_strategy(self):
        envelope = json.dumps({"encoding": "base64", "content": "!!!not base64!!!", "download_url": self.URL}).encode(
            "utf-8"
        )
        with (
            mock.patch("sources._OPENER.open", side_effect=[_FakeResponse(envelope), _FakeResponse(self.BODY)]),
            mock.patch("sources.time.sleep"),
        ):
            _, _, raw = load_first_available_raw([self.API_URL])
        self.assertEqual(raw, self.BODY)

    def test_inline_content_that_is_not_a_playerlist_falls_through(self):
        inner = base64.b64encode(b"[]").decode("ascii")
        envelope = json.dumps({"encoding": "base64", "content": inner, "download_url": self.URL}).encode("utf-8")
        with (
            mock.patch("sources._OPENER.open", side_effect=[_FakeResponse(envelope), _FakeResponse(self.BODY)]),
            mock.patch("sources.time.sleep"),
        ):
            document, _, raw = load_first_available_raw([self.API_URL])
        self.assertEqual(raw, self.BODY)
        self.assertEqual(len(document["players"]), 1)

    def test_a_failing_candidate_is_skipped_for_the_next_one(self):
        sha = "d" * 40
        # download_url (3 failed attempts) is tried before the blob endpoint.
        envelope = json.dumps(
            {"encoding": "none", "content": "", "sha": sha, "download_url": "https://raw.invalid/list.json"}
        ).encode("utf-8")
        with (
            mock.patch(
                "sources._OPENER.open",
                side_effect=[
                    _FakeResponse(envelope),
                    urllib.error.URLError("raw host down"),
                    urllib.error.URLError("raw host down"),
                    urllib.error.URLError("raw host down"),
                    _FakeResponse(self.BODY),
                ],
            ),
            mock.patch("sources.time.sleep"),
        ):
            _, _, raw = load_first_available_raw([self.API_URL])
        self.assertEqual(raw, self.BODY)

    def test_oversized_local_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "big.json"
            path.write_bytes(b"x" * 4096)
            with mock.patch("sources.MAX_SOURCE_BYTES", 1024), self.assertRaises(SyncError):
                load_first_available_raw([str(path)])

    def test_malformed_urls_are_clean_errors_not_crashes(self):
        # Bad IPv6 literals / control characters make urllib raise
        # ValueError/InvalidURL: that must surface as SyncError (fallback
        # or exit 2), never as a traceback. No network is touched.
        for url in ("https://[::1", "https://exa\nmple.invalid/"):
            with mock.patch("sources.time.sleep"), self.assertRaises(SyncError):
                load_first_available_raw([url])

    def test_oversized_response_is_rejected(self):
        with (
            mock.patch("sources._OPENER.open", return_value=_FakeResponse(self.BODY)),
            mock.patch("sources.MAX_SOURCE_BYTES", 10),
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError),
        ):
            load_first_available_raw([self.URL])

    def test_permanent_http_error_is_not_retried(self):
        error = urllib.error.HTTPError(self.URL, 404, "not found", Message(), None)
        with (
            mock.patch("sources._OPENER.open", side_effect=[error]) as urlopen,
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError),
        ):
            load_first_available_raw([self.URL])
        self.assertEqual(urlopen.call_count, 1)

    def test_https_downgrade_redirect_is_refused(self):
        """A redirect from HTTPS to plain HTTP must never be followed: the
        fetched bytes become the snapshot and drive promotions."""
        handler = sources._HttpsOnlyRedirectHandler()
        request = urllib.request.Request("https://example.invalid/list.json")
        with self.assertRaises(SyncError):
            handler.redirect_request(request, None, 302, "Found", Message(), "http://example.invalid/list.json")
        upgraded = handler.redirect_request(request, None, 302, "Found", Message(), "https://cdn.invalid/list.json")
        self.assertEqual(upgraded.full_url, "https://cdn.invalid/list.json")

    def test_body_exactly_at_the_size_limit_is_accepted(self):
        with (
            mock.patch("sources._OPENER.open", return_value=_FakeResponse(self.BODY)),
            mock.patch("sources.MAX_SOURCE_BYTES", len(self.BODY)),
            mock.patch("sources.time.sleep"),
        ):
            _, _, raw = load_first_available_raw([self.URL])
        self.assertEqual(raw, self.BODY)
        with (
            mock.patch("sources._OPENER.open", return_value=_FakeResponse(self.BODY)),
            mock.patch("sources.MAX_SOURCE_BYTES", len(self.BODY) - 1),
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError),
        ):
            load_first_available_raw([self.URL])

    def test_network_errors_are_retried_with_backoff(self):
        with (
            mock.patch("sources._OPENER.open", side_effect=urllib.error.URLError("down")) as opener,
            mock.patch("sources.time.sleep") as sleep,
            self.assertRaises(SyncError),
        ):
            load_first_available_raw([self.URL])
        self.assertEqual(opener.call_count, sources.FETCH_ATTEMPTS)
        self.assertEqual(sleep.call_count, sources.FETCH_ATTEMPTS - 1)

    def test_local_source_exactly_at_the_limit_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "exact.json"
            path.write_bytes(self.BODY)
            with mock.patch("sources.MAX_SOURCE_BYTES", len(self.BODY)):
                _, _, raw = load_first_available_raw([str(path)])
        self.assertEqual(raw, self.BODY)

    def test_declared_length_boundary_is_exact(self):
        for declared, accepted in ((len(self.BODY), True), (len(self.BODY) + 1, False)):
            response = _FakeResponse(self.BODY, {"Content-Length": str(declared)})
            with (
                mock.patch("sources._OPENER.open", return_value=response),
                mock.patch("sources.MAX_SOURCE_BYTES", len(self.BODY)),
                mock.patch("sources.time.sleep"),
            ):
                if accepted:
                    _, _, raw = load_first_available_raw([self.URL])
                    self.assertEqual(raw, self.BODY)
                else:
                    with self.assertRaises(SyncError):
                        load_first_available_raw([self.URL])
                    self.assertEqual(response.read_count, 0)  # rejected before download

    def test_server_errors_are_retried_and_client_errors_are_not(self):
        for code, expected_attempts in (
            (500, sources.FETCH_ATTEMPTS),
            (599, sources.FETCH_ATTEMPTS),
            (600, 1),
            (404, 1),
        ):
            error = urllib.error.HTTPError(self.URL, code, "boom", Message(), None)
            with (
                mock.patch("sources._OPENER.open", side_effect=error) as opener,
                mock.patch("sources.time.sleep") as sleep,
                self.assertRaises(SyncError),
            ):
                load_first_available_raw([self.URL])
            self.assertEqual(opener.call_count, expected_attempts, f"HTTP {code}")
            # never sleep after the final attempt
            self.assertEqual(sleep.call_count, expected_attempts - 1, f"HTTP {code}")

    def test_backoff_grows_linearly_between_attempts(self):
        error = urllib.error.HTTPError(self.URL, 503, "boom", Message(), None)
        with (
            mock.patch("sources._OPENER.open", side_effect=error),
            mock.patch("sources.time.sleep") as sleep,
            self.assertRaises(SyncError),
        ):
            load_first_available_raw([self.URL])
        self.assertEqual(
            [call.args[0] for call in sleep.call_args_list],
            [sources.RETRY_BACKOFF_SECONDS * attempt for attempt in range(1, sources.FETCH_ATTEMPTS)],
        )

    def test_non_ascii_content_length_is_ignored_instead_of_crashing(self):
        """isdigit() accepts "²", int() does not: a malformed header must be
        ignored (download, then the byte cap applies) rather than raise."""
        response = _FakeResponse(self.BODY, {"Content-Length": "²"})
        with mock.patch("sources._OPENER.open", return_value=response), mock.patch("sources.time.sleep"):
            _, _, raw = load_first_available_raw([self.URL])
        self.assertEqual(raw, self.BODY)
        self.assertEqual(response.read_count, 1)

    def test_oversized_declared_length_is_rejected_without_downloading(self):
        response = _FakeResponse(self.BODY, {"Content-Length": str(10 * 1024 * 1024)})
        with (
            mock.patch("sources._OPENER.open", return_value=response),
            mock.patch("sources.MAX_SOURCE_BYTES", 1024),
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError),
        ):
            load_first_available_raw([self.URL])
        self.assertEqual(response.read_count, 0)  # never downloaded the body

    def test_transient_http_error_is_retried_until_success(self):
        error = urllib.error.HTTPError(self.URL, 503, "unavailable", Message(), None)
        (_, _, raw), calls = self.fetch([error, error, _FakeResponse(self.BODY)])
        self.assertEqual(raw, self.BODY)
        self.assertEqual(calls, 3)


# --------------------------------------------------------------------------- #
# Promotion policy
# --------------------------------------------------------------------------- #
class WriteSnapshotTests(unittest.TestCase):
    """write_snapshot()'s return value becomes the workflow's step output."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "snapshot.json"

    def test_returns_true_and_writes_when_the_bytes_differ(self):
        changed = sync_module.write_snapshot(self.path, b"new\n", b"old\n", dry_run=False)
        self.assertTrue(changed)
        self.assertEqual(self.path.read_bytes(), b"new\n")

    def test_returns_false_and_leaves_the_file_alone_when_identical(self):
        changed = sync_module.write_snapshot(self.path, b"same\n", b"same\n", dry_run=False)
        self.assertFalse(changed)
        self.assertFalse(self.path.exists())  # nothing written

    def test_dry_run_reports_the_change_without_writing(self):
        changed = sync_module.write_snapshot(self.path, b"new\n", b"old\n", dry_run=True)
        self.assertTrue(changed)
        self.assertFalse(self.path.exists())

    def test_a_first_snapshot_counts_as_a_change(self):
        self.assertTrue(sync_module.write_snapshot(self.path, b"first\n", None, dry_run=False))
        self.assertEqual(self.path.read_bytes(), b"first\n")


class UntouchedPathTests(unittest.TestCase):
    """The branches nothing reached yet: error handling that protects the files.

    Each of these is a guard that only fires when something goes wrong, which
    is exactly the kind of code that rots silently without a test.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_oversize_body_is_rejected_then_the_next_source_is_used(self):
        # A body past the download budget must be refused, not written to disk.
        with (
            mock.patch.object(sources, "MAX_SOURCE_BYTES", 100),
            mock.patch(
                "sources._OPENER.open",
                side_effect=[_FakeResponse(b"x" * 101), _FakeResponse(SourceFetchTests.BODY)],
            ),
            mock.patch("sources.time.sleep"),
        ):
            document, source, raw = load_first_available_raw(["https://example.invalid/big.json", SourceFetchTests.URL])
        self.assertEqual(source, SourceFetchTests.URL)
        self.assertEqual(raw, SourceFetchTests.BODY)
        self.assertEqual(document["players"][0]["steamid"], "[U:1:100]")

    def test_non_http_url_is_refused_before_any_request(self):
        with mock.patch("sources._OPENER.open") as urlopen, self.assertRaises(SyncError):
            sources._fetch_bytes("file:///etc/passwd")
        urlopen.assert_not_called()

    def test_unreadable_local_source_falls_through_to_the_next_one(self):
        local = self.root / "present.json"
        local.write_text("{}", encoding="utf-8")
        with (
            mock.patch("sources._OPENER.open", side_effect=[_FakeResponse(SourceFetchTests.BODY)]),
            mock.patch.object(Path, "read_bytes", side_effect=OSError("input/output error")),
            mock.patch("sources.time.sleep"),
        ):
            _, source, _ = load_first_available_raw([str(local), SourceFetchTests.URL])
        self.assertEqual(source, SourceFetchTests.URL)  # the I/O error became a clean skip

    def test_blob_url_is_only_derived_from_a_contents_api_url(self):
        sha = "a" * 40
        self.assertIsNone(sources._github_blob_url("https://api.github.com/repos/x/y/git/refs/main", sha))
        self.assertIsNone(sources._github_blob_url("https://example.invalid/repos/x/y/contents/f.json", sha))
        self.assertIsNone(sources._github_blob_url(SourceFetchTests.API_URL, "not-a-sha"))
        self.assertEqual(
            sources._github_blob_url(SourceFetchTests.API_URL, sha),
            f"https://api.github.com/repos/Nocrex/Tom/git/blobs/{sha}",
        )

    def test_running_the_module_as_a_script_uses_main(self):
        # Exactly what the workflow does: python3 scripts/sync_vorobey_hackerpolice.py
        output = io.StringIO()
        with (
            mock.patch.object(sys, "argv", ["sync_vorobey_hackerpolice.py", "--help"]),
            contextlib.redirect_stdout(output),
            self.assertRaises(SystemExit) as caught,
        ):
            runpy.run_module("sync_vorobey_hackerpolice", run_name="__main__")
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("--include-proof", output.getvalue())

    def test_envelope_with_non_string_content_is_not_unwrapped(self):
        # encoding says base64 but content is not text: b64decode would raise,
        # so the envelope must be rejected before it is tried.
        self.assertIsNone(sources._unwrap_github_contents_envelope({"encoding": "base64", "content": 123}))
        self.assertIsNone(sources._unwrap_github_contents_envelope({"content": "e30="}))
        self.assertIsNone(sources._unwrap_github_contents_envelope({"encoding": "base64"}))
        self.assertIsNone(sources._unwrap_github_contents_envelope({"encoding": "base64", "content": ""}))

    def test_envelope_content_with_line_breaks_still_decodes(self):
        # The API may wrap long base64 in newlines; strict validation would
        # reject that and silently lose the fallback.
        encoded = base64.encodebytes(b'{"players": []}').decode("ascii")
        self.assertIn("\n", encoded)
        self.assertEqual(
            sources._unwrap_github_contents_envelope({"encoding": "base64", "content": encoded}), b'{"players": []}'
        )

    def test_redact_url_tolerates_a_url_it_cannot_parse(self):
        # urlsplit raises on a malformed IPv6 literal; logging must not crash.
        broken = "https://user:secret@[::1/list.json"
        self.assertEqual(sources.redact_url(broken), broken)

    def test_indirect_document_skips_a_candidate_that_is_not_a_playerlist(self):
        # A follow-up URL that answers with JSON which is neither a playerlist
        # nor a base64 envelope: it must be skipped, not accepted.
        envelope = json.dumps(
            {
                "encoding": "base64",
                "content": base64.b64encode(b"{}").decode("ascii"),
                "sha": "a" * 40,
                "download_url": "https://example.invalid/download.json",
            }
        ).encode("utf-8")

        def read(url):
            if url == SourceFetchTests.API_URL:
                return envelope
            if url == "https://example.invalid/download.json":
                return b'{"$schema": "x"}'  # JSON, but not a playerlist
            raise SyncError("blocked")

        with (
            mock.patch("sources._read_bytes", side_effect=read),
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError),
        ):
            load_first_available_raw([SourceFetchTests.API_URL])

    def test_redact_url_keeps_the_port_and_drops_the_credentials(self):
        self.assertEqual(
            sources.redact_url("https://user:secret@example.invalid:8443/list.json"),
            "https://example.invalid:8443/list.json",
        )
        self.assertNotIn("secret", sources.redact_url("https://user:secret@example.invalid/x"))

    def test_a_directory_that_cannot_be_fsynced_does_not_fail_the_write(self):
        # Some platforms cannot fsync a directory; the rename is already done,
        # so failing to make it durable must not turn the write into an error.
        target = self.root / "list.json"
        real_fsync = os.fsync

        def fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("cannot fsync a directory on this platform")
            return real_fsync(fd)

        with mock.patch("os.fsync", side_effect=fsync):
            sync_module._atomic_write_bytes(target, b"{}\n")
        self.assertEqual(target.read_bytes(), b"{}\n")

    def test_indirect_document_with_no_usable_candidate_is_a_fetch_error(self):
        # A GitHub API envelope that decodes to nothing usable, and every
        # follow-up URL for it is blocked: the source must fail with a clear
        # SyncError, not a traceback and not a half-parsed document.
        envelope = json.dumps(
            {"encoding": "base64", "content": base64.b64encode(b"{}").decode("ascii"), "sha": "a" * 40}
        ).encode("utf-8")

        def read(url):
            if url == SourceFetchTests.API_URL:
                return envelope
            raise SyncError("blocked")

        with (
            mock.patch("sources._read_bytes", side_effect=read),
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError) as caught,
        ):
            load_first_available_raw([SourceFetchTests.API_URL])
        self.assertIn("cannot load the Vorobey hackerpolice list", str(caught.exception))

    def test_failed_write_leaves_no_temp_file_behind(self):
        target = self.root / "list.json"
        with mock.patch.object(Path, "replace", side_effect=OSError("disk full")), self.assertRaises(OSError):
            sync_module._atomic_write_bytes(target, b"{}\n")
        self.assertEqual(list(self.root.iterdir()), [])  # no stale .tmp file

    def test_write_creates_a_missing_parent_directory(self):
        nested = self.root / "a" / "b" / "list.json"
        sync_module._atomic_write_bytes(nested, b"{}\n")
        self.assertEqual(nested.read_bytes(), b"{}\n")

    def test_write_into_an_existing_directory_keeps_the_existing_mode(self):
        target = self.root / "list.json"
        target.write_bytes(b"old\n")
        target.chmod(0o640)
        sync_module._atomic_write_bytes(target, b"new\n")
        self.assertEqual(target.read_bytes(), b"new\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)  # mode preserved

    def test_same_file_sees_two_hard_links_to_one_file(self):
        first = self.root / "a.json"
        first.write_text("{}", encoding="utf-8")
        second = self.root / "b.json"
        os.link(first, second)
        self.assertTrue(sync_module._same_file(first, second))

    def test_same_file_treats_a_stat_error_as_different_files(self):
        first, second = self.root / "a.json", self.root / "b.json"
        first.write_text("{}", encoding="utf-8")
        second.write_text("{}", encoding="utf-8")
        with mock.patch("os.path.samefile", side_effect=OSError("no such file")):
            self.assertFalse(sync_module._same_file(first, second))
        self.assertTrue(sync_module._same_file(first, first))

    def test_database_that_fails_validation_after_sync_is_not_written(self):
        database = self.root / "list.json"
        database.write_text(dumps({"players": [player("[U:1:100]", ["suspicious"])]}), encoding="utf-8")
        source = self.root / "upstream.json"
        source.write_text(dumps({"players": [hackerpolice_entry("[U:1:100]")]}), encoding="utf-8")
        before = database.read_bytes()
        clean = playerlist_module.ValidationResult()
        broken = playerlist_module.ValidationResult(errors=["simulated problem"])
        # load_database() validates too: let that one pass, fail the post-sync one.
        with mock.patch.object(sync_module, "validate", side_effect=[clean, broken]):
            code = main(
                ["--database", str(database), "--source", str(source), "--snapshot", str(self.root / "snapshot.json")]
            )
        self.assertEqual(code, 2)
        self.assertEqual(database.read_bytes(), before)  # nothing written

    def test_policy_keeps_an_entry_whose_attributes_are_not_a_list(self):
        # A bare string is iterable, so an unguarded loop would treat it as a
        # list of one-character tags and mangle the entry.
        # A tuple/set/dict of real tag names is the dangerous case: unlike a
        # bare string it survives the "looks like attributes" checks, so an
        # unguarded policy would rewrite (or crash on) a hand-edited entry.
        for attributes in (
            "cheater",
            "suspicious",
            "",
            None,
            {"cheater": True},
            ("suspicious",),
            ("cheater",),
            frozenset({"racist"}),
        ):
            database = {"players": [{"steamid": "[U:1:100]", "attributes": attributes}]}
            self.assertEqual(demote(database, ["[U:1:100]"]), [])
            self.assertEqual(database["players"][0]["attributes"], attributes)
            changes = promote(database, index_of(hackerpolice_entry("[U:1:100]")))
            self.assertEqual(changes, [])
            self.assertEqual(database["players"][0]["attributes"], attributes)

    def test_demote_leaves_an_entry_with_non_string_attributes_alone(self):
        # validate() rejects this before the run starts; the policy still keeps
        # the entry rather than crashing if it ever reaches here.
        database = {"players": [{"steamid": "[U:1:100]", "attributes": [1, "cheater"]}]}
        changes = demote(database, ["[U:1:100]"])  # type: ignore[arg-type]
        self.assertEqual(changes, [])
        self.assertEqual(len(database["players"]), 1)

    def test_sync_without_a_players_array_is_a_no_op(self):
        database = {"players": None}
        self.assertEqual(sync(database, index_of(), enable_demote=True, removed_ids={"[U:1:100]"}), [])  # type: ignore[arg-type]


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

    def test_racist_proof_matching_ignores_case_and_padding(self):
        """A future tool writing "[AUTO] Automatically marked: RACIST ..."
        must not lose the line that justifies the surviving racist tag."""
        kept = '  [AUTO] Automatically marked: RACIST | reason: "slur"  '
        database, _ = self.demote([player("[U:1:200]", ["cheater", "racist"], proof=[kept, "Silent Aim & ESP"])])
        self.assertEqual(database["players"][0]["proof"], [kept])

    def test_is_racist_proof(self):
        self.assertTrue(is_racist_proof('[auto] automatically marked: Racist | reason: "x"'))
        self.assertTrue(is_racist_proof("  [AUTO] automatically marked: RACIST | reason:"))
        for value in (
            '[auto] automatically marked: Cheater | reason: "aimbot"',
            "https://youtu.be/x",
            "Racist behavior in voice chat",
            "[auto] automatically marked: Racist",
            "",
        ):
            self.assertFalse(is_racist_proof(value), value)

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
class PolicyPropertyTests(unittest.TestCase):
    """Seeded property test over arbitrary databases and upstream states.

    The rules are re-derived here from the spec (not from the implementation),
    and a second run must always be a no-op: that is what keeps the daily bot
    from churning the file.
    """

    RACIST_LINE = "[auto] automatically marked: Racist | reason: whatever"

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
                    # No attributes at all: malformed, left alone by the policy
                    # (the CLI refuses such a database before writing anything).
                    self.assertEqual(entry, original)
                    continue
                if steamid in listed and has:
                    # Still listed: never demoted, even if also in removed_ids.
                    self.assertEqual(entry, original)
                elif steamid in listed and was & {"suspicious", "racist"}:
                    # Promoted: cheater added, suspicious settled, everything else kept.
                    self.assertEqual(entry["attributes"], order_attributes((was | {"cheater"}) - {"suspicious"}))
                    self.assertEqual(entry["last_seen"], original["last_seen"])
                elif steamid in removed and has and "racist" not in was:
                    # Removed upstream without a racist tag: the entry is gone.
                    self.assertIsNone(entry)
                elif steamid in removed and has:
                    # Only the cheater tag goes (other tags survive); every proof
                    # that is not an [auto] racist line is dropped with it.
                    self.assertEqual(entry["attributes"], order_attributes(was - {"cheater"}))
                    if "proof" in original:
                        self.assertTrue(all(is_racist_proof(line) for line in entry["proof"]))
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
        self.assertEqual(changes[0].evidence, ("https://x",))  # de-duplicated, junk dropped


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
        # ... and a second run must be a no-op.
        self.assertEqual(sync(database, index, enable_demote=True, removed_ids={"[U:1:100]"}), [])


class MalformedEntryTests(unittest.TestCase):
    """Malformed or unrelated entries must be skipped, never crash or be lost."""

    def test_demote_keeps_entries_it_cannot_interpret(self):
        players = [
            "not a dict",
            {"attributes": ["cheater"]},  # no steamid
            player("nope", ["cheater"]),  # unusable steamid
            player("[U:1:400]", []),  # no attributes
            player("[U:1:401]", [1]),  # non-string attribute
            player("[U:1:402]", ["suspicious"]),  # not a cheater
            player("[U:1:100]", ["cheater"]),  # the only real demotion
        ]
        database = {"players": list(players)}
        changes = demote(database, {"[U:1:100]", "[U:1:999]"})
        self.assertEqual(len(changes), 1)
        # [U:1:999] is "removed upstream" but absent locally: nothing to do.
        self.assertEqual(len(database["players"]), 6)  # only [U:1:100] dropped
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
                player("[U:1:202]", ["cheater"]),  # already a cheater
                player("[U:1:203]", ["suspicious"]),
                player("[U:1:999]", ["suspicious"]),  # not on the list
            ]
        }
        changes = promote(database, index)
        promoted = [change.steamid for change in changes]
        self.assertEqual(promoted, ["[U:1:203]"])

    def test_sync_tolerates_a_missing_players_array(self):
        self.assertEqual(promote({}, index_of()), [])
        self.assertEqual(demote({}, {"[U:1:1]"}), [])

    def test_include_proof_is_idempotent_and_keeps_evidence(self):
        index = index_of(hackerpolice_entry("[U:1:100]", [HACKERPOLICE_PROOF, "  "]))
        database = {"players": [player("[U:1:100]", ["suspicious"])]}
        promote(database, index, include_proof=True)
        first = list(database["players"][0]["proof"])
        self.assertEqual(len(first), 1)
        self.assertIn(PROOF_MARKER, first[0])
        self.assertIn(HACKERPOLICE_PROOF, first[0])
        # Re-running (e.g. a second sync, or the same player promoted again)
        # must never duplicate the line this tool owns.
        database["players"][0]["attributes"] = ["suspicious"]
        promote(database, index, include_proof=True)
        self.assertEqual(database["players"][0]["proof"], first)


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
    def info(self, changes=(), *, source="https://example.invalid/list.json", **kwargs):
        return RunInfo(
            database_path=Path("playerlist.garou3299.json"),
            source=source,
            source_total=10,
            changes=tuple(changes),
            **{"source_skipped": 0, "dry_run": False, **kwargs},
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

    def test_proof_note_is_the_last_line_even_with_include_proof(self):
        changes = (
            Change(
                steamid="[U:1:100]",
                name="a",
                before=("suspicious",),
                after=("cheater",),
                evidence=("https://example.invalid/p",),
            ),
        )
        report = render_report(self.info(changes, include_proof=True))
        lines = [line for line in report.splitlines() if line.strip()]
        self.assertEqual(
            lines[-1],
            "Proof link comes from the Vorobey hackerpolice list and is shown for review only.",
        )
        self.assertIn("`--include-proof` was enabled", report)

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

    def test_counts_use_thousands_separators(self):
        report = render_report(
            self.info(
                previous_source_total=12345,
                added_to_source=1200,
                removed_from_source=3,
                removed_upstream=("[U:1:1]",),
                snapshot_changed=True,
            )
        )
        self.assertIn("Vorobey hackerpolice list (10 entries)", report)  # source_total stays exact
        self.assertIn("- Previous snapshot: 12,345 entries", report)
        self.assertIn("**1,200 new SteamIDs added**", report)
        self.assertIn("(12,345 → 13,542 entries; net +1,197)", report)
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

    def test_newline_in_the_fetch_url_cannot_inject_a_report_line(self):
        # The fetch URL can be an upstream-supplied download_url, so a newline
        # in it must not start a new Markdown line in the pull request body.
        report = render_report(self.info(source="https://example.invalid/a\n- **injected**\r\n- second"))
        self.assertFalse(any(line.startswith("- **injected**") for line in report.splitlines()))
        self.assertIn("injected", report)  # flattened onto one line, not dropped

    def test_pipe_in_a_proof_url_cannot_split_the_table_row(self):
        # Upstream proof links are third-party data; a raw "|" inside a table
        # cell ends the cell, so GitHub would render a truncated row with an
        # extra column. The URL keeps working because %7C decodes to "|".
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",), ("https://example.invalid/a|b",))
        report = render_report(self.info([change]))
        self.assertIn("https://example.invalid/a%7Cb", report)
        rows = [line for line in report.splitlines() if line.startswith("| `[U:1:1]`")]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].count("|"), 6)  # five cells, no stray separator

    def test_no_proof_note_without_evidence_links(self):
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",))  # no evidence links
        report = render_report(self.info([change]))
        self.assertNotIn("Proof links come from", report)

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
        self.assertIn("&lt;b&gt;this&lt;/b&gt;", report)  # rendered literally, not as HTML

    def test_change_tables_are_capped(self):
        changes = [
            Change(f"[U:1:{1000 + n}]", f"n{n}", ("suspicious",), ("cheater",))
            for n in range(MAX_CHANGE_TABLE_ROWS + 3)
        ]
        report = render_report(self.info(changes))
        rows = [line for line in report.splitlines() if line.startswith("| `[U:1:")]
        self.assertEqual(len(rows), MAX_CHANGE_TABLE_ROWS)
        self.assertIn("… and 3 more entries not shown here", report)

    def test_report_body_is_hard_capped(self):
        """Pathological input (very long names) can never break PR creation."""
        changes = [Change(f"[U:1:{1000 + n}]", "x" * 900, ("suspicious",), ("cheater",)) for n in range(200)]
        report = render_report(self.info(changes, removed_upstream=tuple(f"[U:1:{5000 + n}]" for n in range(100))))
        self.assertLessEqual(len(report), MAX_REPORT_CHARS)
        self.assertIn("report truncated to fit the pull request body limit", report)
        report.encode("utf-8")

    def test_dry_run_and_include_proof_notes(self):
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",))
        report = render_report(self.info([change], dry_run=True, include_proof=True))
        self.assertIn("**dry run**", report)
        self.assertIn("`--include-proof` was enabled", report)


# --------------------------------------------------------------------------- #
# "Removed from the Vorobey list" table
# --------------------------------------------------------------------------- #
class RemovedFromVorobeyTableTests(unittest.TestCase):
    """The PR body lists EVERY SteamID that disappeared from the Vorobey list.

    The Vorobey list stores no player names, so the table is exactly
    ``| SteamID | Profile Link |`` and every link is the Steam profile
    permalink (SteamID64 URL), never a vanity URL or a last-seen name.
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
            "**1 SteamID removed from the Vorobey hackerpolice list since the previous snapshot.**",
            report,
        )
        self.assertIn("| SteamID | Profile Link |", report)
        self.assertIn("| --- | --- |", report)
        self.assertIn(
            "| `[U:1:269327660]` | [Profile](https://steamcommunity.com/profiles/76561198229593388) |",
            report,
        )

    def test_no_names_are_used_because_vorobey_stores_none(self):
        report = render_report(self.info(removed_upstream=("[U:1:2]",)))
        self.assertNotIn("Last known name", report)
        self.assertNotIn("UNKNOWN", report)
        # No explanatory filler above the table either: heading, then the table.
        self.assertNotIn("stores no player names", report)
        self.assertLess(
            report.index("removed from the Vorobey hackerpolice list"), report.index("| SteamID | Profile Link |")
        )

    def test_plural_count_and_numeric_order(self):
        report = render_report(self.info(removed_upstream=("[U:1:20]", "[U:1:3]")))
        self.assertIn("**2 SteamIDs removed from the Vorobey hackerpolice list", report)
        rows = [line for line in report.splitlines() if line.startswith("| `[U:1:")]
        self.assertEqual(
            rows,
            [
                "| `[U:1:3]` | [Profile](https://steamcommunity.com/profiles/76561197960265731) |",
                "| `[U:1:20]` | [Profile](https://steamcommunity.com/profiles/76561197960265748) |",
            ],
        )

    def test_table_is_shown_even_when_the_database_changed_nothing(self):
        # Snapshot-only PR (e.g. none of the removed IDs was a cheater here).
        report = render_report(self.info(snapshot_changed=True, removed_upstream=("[U:1:5]",)))
        self.assertIn("snapshot refresh only", report)
        self.assertIn("| `[U:1:5]` | [Profile](", report)

    def test_table_is_shown_after_the_change_tables(self):
        change = Change("[U:1:400]", "a", ("suspicious",), ("cheater",))
        report = render_report(self.info(changes=(change,), removed_upstream=("[U:1:5]",)))
        self.assertLess(
            report.index("promoted to `cheater`"), report.index("removed from the Vorobey hackerpolice list")
        )

    def test_closing_sentence_and_proof_note_are_always_last(self):
        change = Change("[U:1:400]", "a", ("suspicious",), ("cheater",), ("https://x/1",))
        report = render_report(self.info(changes=(change,), removed_upstream=("[U:1:5]",)))
        lines = [line for line in report.splitlines() if line.strip()]
        self.assertIn("Proof link", lines[-1])
        self.assertIn("nothing else is modified.", lines[-2])
        # The removed table sits above the closing sentence, not below it.
        self.assertLess(report.index("| Profile Link |"), report.index("nothing else is modified."))

    def test_closing_sentence_names_the_database_that_changed(self):
        change = Change("[U:1:400]", "a", ("suspicious",), ("cheater",))
        other = Change("[U:1:401]", "c", ("suspicious",), ("cheater",))
        removed_entry = Change("[U:1:500]", "b", ("cheater",), (), kind="demote")
        report = render_report(self.info(changes=(change, other, removed_entry)))
        self.assertIn("In `playerlist.garou3299.json`: attributes are changed for these SteamIDs", report)
        self.assertIn("entry is removed for this SteamID: [U:1:500]", report)
        # ... and only that once (the header bullet is a separate line):
        closing = next(line for line in report.splitlines() if "nothing else is modified" in line)
        self.assertEqual(closing.count("`playerlist.garou3299.json`"), 1)
        # Only the file name -- never an absolute/temporary path.
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
        report = render_report(self.info(removed_upstream=("[U:1:1]",), previous_source_total=10))
        report.encode("utf-8")


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

    def test_database_name_is_included_when_given(self):
        promote_change = Change("[U:1:400]", "a", ("suspicious",), ("cheater",), kind="promote")
        demote_change = Change("[U:1:300]", "b", ("cheater",), (), kind="demote")
        # The file scopes the whole sentence and is named exactly once.
        self.assertEqual(
            render_closing([promote_change], database="playerlist.garou3299.json"),
            "In `playerlist.garou3299.json`: attribute is changed for this SteamID: [U:1:400]; "
            "nothing else is modified.",
        )
        self.assertEqual(
            render_closing([demote_change], database="playerlist.garou3299.json"),
            "In `playerlist.garou3299.json`: entry is removed for this SteamID: [U:1:300]; nothing else is modified.",
        )
        self.assertEqual(
            render_closing([promote_change, demote_change], database="playerlist.garou3299.json"),
            "In `playerlist.garou3299.json`: attribute is changed for this SteamID: [U:1:400]; "
            "entry is removed for this SteamID: [U:1:300]; nothing else is modified.",
        )
        self.assertEqual(
            render_closing([promote_change, demote_change], database="playerlist.garou3299.json").count(
                "playerlist.garou3299.json"
            ),
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
            render_closing(changes, database="playerlist.garou3299.json"),
            "In `playerlist.garou3299.json`: attributes are changed for these SteamIDs: [U:1:400], [U:1:401]; "
            "entries are removed for these SteamIDs: [U:1:300], [U:1:301]; nothing else is modified.",
        )

    def test_database_name_is_the_file_name_only(self):
        info = RunInfo(
            database_path=Path("/tmp/some/dir/playerlist.garou3299.json"),
            source="https://example.invalid/list.json",
            source_total=1,
            source_skipped=0,
            dry_run=False,
        )
        self.assertEqual(info.database_name, "playerlist.garou3299.json")

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

    def test_body_exactly_at_the_character_limit_is_untouched(self):
        text = "a" * MAX_REPORT_CHARS
        self.assertEqual(report_module._fit_body(text), text)

    def test_truncation_keeps_content_when_the_cut_lands_on_the_first_newline(self):
        text = "\n" + "b" * (MAX_REPORT_CHARS + 100)
        fitted = report_module._fit_body(text)
        self.assertLessEqual(len(fitted), MAX_REPORT_CHARS)
        self.assertTrue(fitted.lstrip("\n").startswith("b"), fitted[:20])

    def test_promotions_and_demotions_land_in_their_own_tables(self):
        changes = (
            Change(steamid="[U:1:100]", name="p", before=("suspicious",), after=("cheater",)),
            Change(steamid="[U:1:200]", name="d", before=("cheater", "racist"), after=("racist",), kind="demote"),
        )
        rendered = render_report(self._info(changes=changes))
        promotion_block, demotion_block = rendered.split("demoted (in the previous snapshot", 1)
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


class WriteDatabaseCompatibilityTests(unittest.TestCase):
    def test_accepts_the_pre_4_0_parsed_playerlist(self):
        """The signature used to take the parsed document, not the text."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "list.json"
            database = {"players": [player("[U:1:1]", ["cheater"])]}
            original = dumps(database)
            path.write_text(original, encoding="utf-8")
            self.assertFalse(write_database(path, database, original, dry_run=False))
            self.assertEqual(path.read_text(encoding="utf-8"), original)
            database["players"].append(player("[U:1:2]", ["cheater"]))
            self.assertTrue(write_database(path, database, original, dry_run=False))
            self.assertEqual(path.read_text(encoding="utf-8"), dumps(database))
            # a dry run still refuses to write, whichever form is passed
            self.assertTrue(write_database(path, {"players": []}, original, dry_run=True))
            self.assertEqual(path.read_text(encoding="utf-8"), dumps(database))


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

    def test_version_flag(self):
        with contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit) as exit_:
            build_parser().parse_args(["--version"])
        self.assertEqual(exit_.exception.code, 0)
        self.assertIn(sources.VERSION, out.getvalue())

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

    def test_report_lists_every_removed_steamid_with_its_permalink(self):
        """Every ID gone from the list since the snapshot appears in the
        ``| SteamID | Profile Link |`` table -- including ones that were not
        demoted because they were never cheaters here, and ones that were
        never in this database at all."""
        self.database.write_text(
            dumps(
                {
                    "$schema": "x",
                    "file_info": {},
                    "players": [
                        player("[U:1:400]", ["cheater"]),  # removed upstream -> demoted
                        player("[U:1:300]", ["suspicious"]),  # removed upstream, not a cheater
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.write_snapshot_fixture(
            hackerpolice_entry("[U:1:300]"),
            hackerpolice_entry("[U:1:400]"),
            hackerpolice_entry("[U:1:500]"),  # not in this database at all
        )
        report_file = self.root / "report.md"
        code, stdout, _ = self.run_cli("--source", str(self.source), "--demote", "--report", str(report_file))
        self.assertEqual(code, 0)
        report = report_file.read_text(encoding="utf-8")
        self.assertEqual(report, stdout)
        self.assertIn("**3 SteamIDs removed from the Vorobey hackerpolice list since the previous snapshot.**", report)
        self.assertIn("| SteamID | Profile Link |", report)
        for account in (300, 400, 500):
            steamid64 = 76561197960265728 + account
            self.assertIn(
                f"| `[U:1:{account}]` | [Profile](https://steamcommunity.com/profiles/{steamid64}) |",
                report,
            )
        # The still-current upstream IDs are not "removed".
        for account in (100, 200):
            self.assertNotIn(f"| `[U:1:{account}]` | [Profile]", report)

    def test_removed_table_is_absent_when_nothing_was_removed(self):
        code, stdout, _ = self.run_cli("--source", str(self.source), "--demote")
        self.assertEqual(code, 0)
        self.assertNotIn("Profile Link", stdout)

    def test_mass_disappearance_still_reports_the_removals(self):
        snapshot_fixture = self.write_snapshot_fixture(*[hackerpolice_entry(f"[U:1:{n}]") for n in range(400, 461)])
        code, stdout, _ = self.run_cli("--source", str(self.source), "--demote")
        self.assertEqual(code, 0)
        self.assertIn("looks like an upstream problem", stdout)
        self.assertIn("**61 SteamIDs removed from the Vorobey hackerpolice list", stdout)
        self.assertIn("**not refreshed**", stdout)
        # ... while demotion was skipped, so the baseline did not advance.
        self.assertEqual(
            {p["steamid"] for p in json.loads(snapshot_fixture.read_text(encoding="utf-8"))["players"]},
            {f"[U:1:{n}]" for n in range(400, 461)},
        )

    def test_snapshot_is_frozen_when_demotion_is_disabled(self):
        """A run without --demote must not advance the baseline past removals
        it could not apply -- that would forget them forever."""
        self.database.write_text(
            dumps({"$schema": "x", "file_info": {}, "players": [player("[U:1:400]", ["cheater"])]}),
            encoding="utf-8",
        )
        snapshot_fixture = self.write_snapshot_fixture(hackerpolice_entry("[U:1:300]"), hackerpolice_entry("[U:1:400]"))
        before = snapshot_fixture.read_bytes()

        code, stdout, _ = self.run_cli("--source", str(self.source))  # no --demote
        self.assertEqual(code, 0)
        self.assertEqual(snapshot_fixture.read_bytes(), before)  # baseline held back
        self.assertIn("**not refreshed**", stdout)
        self.assertIn("demotion is disabled", stdout)

        # ... and the very same removals are applied once --demote is passed.
        code, stdout, _ = self.run_cli("--source", str(self.source), "--demote")
        self.assertEqual(code, 0)
        players = json.loads(self.database.read_text(encoding="utf-8"))["players"]
        self.assertEqual(players, [])
        self.assertEqual(snapshot_fixture.read_bytes(), self.source.read_bytes())

    def test_no_update_snapshot_is_reported(self):
        self.write_snapshot_fixture(hackerpolice_entry("[U:1:100]"))
        before = (self.root / "snapshot.json").read_bytes()
        code, stdout, _ = self.run_cli("--source", str(self.source), "--demote", "--no-update-snapshot")
        self.assertEqual(code, 0)
        self.assertIn("`--no-update-snapshot`", stdout)
        self.assertEqual((self.root / "snapshot.json").read_bytes(), before)

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

    def test_allow_mass_demotion_forces_the_demotion(self):
        self.database.write_text(
            dumps({"$schema": "x", "file_info": {}, "players": [player("[U:1:400]", ["cheater"])]}),
            encoding="utf-8",
        )
        self.write_snapshot_fixture(*[hackerpolice_entry(f"[U:1:{n}]") for n in range(400, 461)])
        code, stdout, _ = self.run_cli("--source", str(self.source), "--demote", "--allow-mass-demotion")
        self.assertEqual(code, 0)
        self.assertNotIn("looks like an upstream problem", stdout)
        self.assertEqual(json.loads(self.database.read_text(encoding="utf-8"))["players"], [])

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

    def test_dry_run_never_writes_the_snapshot(self):
        """A dry run must leave BOTH files alone, not just the database."""
        snapshot = self.write_snapshot_fixture(hackerpolice_entry("[U:1:999]"))
        before = snapshot.read_bytes()
        code, _, stderr = self.run_cli(
            "--source", str(self.source), "--snapshot", str(snapshot), "--demote", "--dry-run"
        )
        self.assertEqual(code, 0)
        self.assertEqual(snapshot.read_bytes(), before)
        self.assertIn(f"Would update snapshot {snapshot}", stderr)

    def test_log_reports_no_changes_and_snapshot_updates_exactly_once(self):
        snapshot = self.write_snapshot_fixture(hackerpolice_entry("[U:1:999]"))
        first = self.run_cli("--source", str(self.source), "--snapshot", str(snapshot), "--demote")
        self.assertEqual(first[0], 0)
        self.assertIn(f"Updated snapshot {snapshot}", first[2])
        second = self.run_cli("--source", str(self.source), "--snapshot", str(snapshot), "--demote")
        self.assertEqual(second[0], 0)
        self.assertIn("No changes: nothing to update.", second[2])
        self.assertNotIn("Updated snapshot", second[2])

    def test_quiet_prints_only_the_report(self):
        code, stdout, stderr = self.run_cli("--source", str(self.source), "--dry-run", "-q")
        self.assertEqual(code, 0)
        self.assertIn("## Vorobey hackerpolice sync", stdout)
        self.assertEqual(stderr.strip(), "")

    def test_verbose_logs_the_index_and_the_diff(self):
        code, _, stderr = self.run_cli("--source", str(self.source), "--dry-run", "-v")
        self.assertEqual(code, 0)
        self.assertIn("Indexed 2 Vorobey hackerpolice SteamIDs", stderr)

    def test_snapshot_must_not_be_the_database(self):
        code, _, stderr = self.run_cli("--snapshot", str(self.database))
        self.assertEqual(code, 2)
        self.assertIn("--snapshot and --database must be different files", stderr)

    def test_unwritable_report_path_is_a_clean_error(self):
        report_dir = self.root / "report-dir"
        report_dir.mkdir()
        code, _, stderr = self.run_cli("--source", str(self.source), "--report", str(report_dir))
        self.assertEqual(code, 2)
        self.assertIn("cannot write report", stderr)
        # Nothing was written before the report failed.
        self.assertNotIn("cheater", self.database.read_text(encoding="utf-8"))

    def test_invalid_database_is_refused_before_anything_is_written(self):
        self.database.write_text(
            dumps({"players": [player("[U:1:100]", ["cheater"]), player("[U:1:100]", ["cheater"])]}),
            encoding="utf-8",
        )
        before = self.database.read_text(encoding="utf-8")
        code, _, stderr = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 2)
        self.assertIn("not a usable playerlist", stderr)
        self.assertIn("duplicate steamid", stderr)
        self.assertEqual(self.database.read_text(encoding="utf-8"), before)

    def test_unknown_attribute_warns_but_does_not_block(self):
        self.database.write_text(
            dumps({"players": [player("[U:1:100]", ["suspicious", "futuretag"])]}), encoding="utf-8"
        )
        code, _, stderr = self.run_cli("--source", str(self.source), "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("unknown attribute", stderr)

    def test_unexpected_os_error_is_reported_as_exit_code_two(self):
        with mock.patch("sync_vorobey_hackerpolice.run", side_effect=OSError("disk full")):
            code = main(["--source", str(self.source)])
        self.assertEqual(code, 2)

    def test_source_must_not_be_the_database(self):
        code, _, stderr = self.run_cli("--source", str(self.database))
        self.assertEqual(code, 2)
        self.assertIn("--source must not be the same file as --database", stderr)

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
# Repository data integrity
# --------------------------------------------------------------------------- #
class RepositoryDataTests(unittest.TestCase):
    """The data files this repository ships must be exactly what the bot expects."""

    ROOT = Path(__file__).resolve().parents[1]

    def test_shipped_database_is_valid_and_canonically_formatted(self):
        database, original = load(self.ROOT / "playerlist.garou3299.json")
        self.assertEqual(validate(database).errors, [])
        # Canonical formatting means a bot run never rewrites the whole file:
        # a hand-reformatted list would show up as a thousands-line diff.
        self.assertEqual(dumps(database), original)

    @staticmethod
    def job_block(text, name):
        """The lines of one job, without needing a YAML parser in CI."""
        lines = text.splitlines()
        start = next(index for index, line in enumerate(lines) if line.rstrip() == f"  {name}:")
        end = len(lines)
        for index in range(start + 1, len(lines)):
            line = lines[index]
            if line.strip() and not line.startswith("    "):
                end = index
                break
        return "\n".join(lines[start:end])

    def test_the_pull_request_job_cannot_write_to_the_repository(self):
        # The checks job runs for contributions: its token must stay read-only.
        workflow = (self.ROOT / ".github/workflows/sync-vorobey-hackerpolice.yml").read_text(encoding="utf-8")
        block = self.job_block(workflow, "checks")
        self.assertIn("contents: read", block)
        self.assertNotIn("contents: write", block)
        self.assertNotIn("pull-requests: write", block)

    def test_a_running_sync_is_never_cancelled_and_cannot_hang_forever(self):
        workflow = (self.ROOT / ".github/workflows/sync-vorobey-hackerpolice.yml").read_text(encoding="utf-8")
        sync_block = self.job_block(workflow, "sync")
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("timeout-minutes:", sync_block)  # a stuck fetch cannot hold the job

    def test_publishing_steps_stage_only_the_two_data_files(self):
        """`git add -A` would publish whatever else happens to be in the workspace.

        Verified by executing both steps against a local remote; this keeps the
        property pinned without needing git in the test environment.
        """
        workflow = (self.ROOT / ".github/workflows/sync-vorobey-hackerpolice.yml").read_text(encoding="utf-8")
        self.assertNotIn("git add -A", workflow)
        self.assertNotIn("git add .", workflow)
        self.assertEqual(workflow.count('git add -- "$DATABASE" "$SNAPSHOT"'), 2)
        self.assertIn("compare/$BASE_BRANCH...$BOT_BRANCH?expand=1", workflow)

    def test_every_publishing_step_requires_a_successful_sync(self):
        """A red run must never publish, and must never claim "nothing to do".

        GitHub runs a step with an explicit `if:` even when an earlier step
        failed or was skipped, so each of these four steps has to test the
        sync step's own outcome -- otherwise a failing lint/test step turns
        the job red while the last step still prints "Nothing to publish".
        """
        workflow = (self.ROOT / ".github/workflows/sync-vorobey-hackerpolice.yml").read_text(encoding="utf-8")
        steps = workflow.split("\n      - ")
        for name in (
            "Open or update pull request",
            "Push branch and link a manual pull request",
            "Commit directly to the default branch",
            "Nothing to do",
        ):
            block = next((step for step in steps if step.startswith(f"name: {name}")), None)
            self.assertIsNotNone(block, f"workflow step not found: {name}")
            condition = [line for line in block.splitlines() if line.strip().startswith("if:")]
            self.assertEqual(len(condition), 1, f"{name} must have exactly one condition")
            self.assertIn("steps.sync.outcome == 'success'", condition[0], f"{name} can run after a failed sync")

    def test_shipped_snapshot_is_a_usable_hackerpolice_list(self):
        snapshot = load_snapshot(self.ROOT / "snapshot" / "playerlist.vorobey-hackerpolice.json")
        self.assertIsNotNone(snapshot)
        index = snapshot[0] if snapshot is not None else None
        self.assertGreater(len(index.by_steamid), 1000)  # type: ignore[union-attr]
        self.assertEqual(index.skipped, 0)  # type: ignore[union-attr]


# --------------------------------------------------------------------------- #
# TF2BD playerlist helpers
# --------------------------------------------------------------------------- #
class NormalizeSteamIdTests(unittest.TestCase):
    def test_account_id_zero_is_never_a_valid_steamid(self):
        from playerlist import STEAMID64_BASE

        for probe in (
            0,
            "0",
            "[U:1:0]",
            STEAMID64_BASE,
            str(STEAMID64_BASE),
            f"https://steamcommunity.com/profiles/{STEAMID64_BASE}",
        ):
            self.assertIsNone(normalize_steamid(probe), probe)
        self.assertIsNone(playerlist_module._bounded_int("²"))  # defensive guard, unreachable from input

    def test_non_ascii_digits_are_rejected_not_crashed(self):
        """Regression: "²".isdigit() is True but int("²") raises, so a single
        corrupted SteamID used to crash the whole run; "١٢٣" was silently
        accepted and minted [U:1:123]. Both are now simply unusable."""
        for probe in ("²", "1²3", "١٢٣", "۷۳", "[U:1:١٢٣]", "[U:1:²]", "U:1:²", "STEAM_0:1:²"):
            self.assertIsNone(normalize_steamid(probe), probe)

    def test_canonical(self):
        self.assertEqual(normalize_steamid("[U:1:1730017]"), "[U:1:1730017]")

    def test_lower_case_notations_map_to_the_same_player(self):
        self.assertEqual(normalize_steamid("[u:1:1730017]"), "[U:1:1730017]")
        self.assertEqual(normalize_steamid("[u:1:1730017:1]"), "[U:1:1730017]")

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


class DocumentHandlingTests(unittest.TestCase):
    def test_non_object_json_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "list.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(PlayerListError):
                load(path)

    def test_validation_result_is_false_only_with_errors(self):
        self.assertTrue(ValidationResult())
        self.assertTrue(ValidationResult(warnings=["w"]))
        self.assertFalse(ValidationResult(errors=["e"]))

    def test_player_name_and_non_object_entries(self):
        self.assertEqual(player_name({"last_seen": {"player_name": "Bob"}}), "Bob")
        self.assertEqual(player_name({"last_seen": "nonsense"}), "")
        self.assertEqual(player_name({}), "")
        result = validate({"players": ["not a dict", player("[U:1:1]", ["cheater"])]})
        self.assertIn("players[0] is not an object", result.errors)

    def test_steam_notation_with_too_many_digits_is_unusable(self):
        self.assertIsNone(normalize_steamid("STEAM_0:1:12345678901"))


class ValidateTests(unittest.TestCase):
    def test_non_ascii_steamid_is_a_validation_error_not_a_crash(self):
        result = validate({"players": [{"steamid": "²", "attributes": ["cheater"]}]})
        self.assertTrue(result.errors)
        self.assertIn("unusable steamid", result.errors[0])

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
