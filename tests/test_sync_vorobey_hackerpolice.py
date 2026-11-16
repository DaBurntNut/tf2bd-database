#!/usr/bin/env python3
"""Tests for the Vorobey hackerpolice sync tool (stdlib only).

Modules under test:
  playerlist   - SteamID norms, load/dumps/validate/sort
  sources      - Vorobey list download + indexing
  policy       - promote / demote / sync
  report       - Markdown report rendering
"""

from __future__ import annotations

import ast
import base64
import contextlib
import copy
import fnmatch
import http.client
import io
import itertools
import json
import os
import random
import re
import runpy
import shutil
import stat
import string
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

# A GitHub Actions step always exports GITHUB_OUTPUT, and a successful run
# appends its own outputs to whatever that variable points at. Inheriting it
# made the suite write 294 lines into the RUNNER's real output file: the tests
# then depend on their environment, and a step that later reads its own outputs
# would be reading values produced by the test run. Tests that exercise the
# output file point the variable at a file of their own instead.
os.environ.pop("GITHUB_OUTPUT", None)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import playerlist as playerlist_module
import policy
import report as report_module
import sources
import sync_vorobey_hackerpolice as sync_module
from playerlist import (
    ATTRIBUTE_ORDER,
    KNOWN_ATTRIBUTES,
    MAX_SHOWN_PATH_CHARS,
    MAX_SHOWN_VALUE_CHARS,
    PlayerListError,
    ValidationResult,
    account_id,
    display_path,
    dumps,
    load,
    normalize_steamid,
    order_attributes,
    player_name,
    sort_players,
    steam_history_url,
    steam_profile_url,
    strict_json_loads,
    validate,
)
from policy import Change, demote, is_racist_proof, promote, sync
from report import (
    MAX_ATTRIBUTE_CELLS,
    MAX_ATTRIBUTE_CHARS,
    MAX_CHANGE_TABLE_ROWS,
    MAX_EVIDENCE_LINK_CHARS,
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
    HackerpoliceIndex,
    SyncError,
    added_steamids,
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
    def __init__(self, body: bytes, headers: dict[str, str] | None = None):
        self._body = body
        self.headers = headers or {}
        self.read_count = 0

    def __enter__(self):
        return self

    def __exit__(self, *_exc: object) -> bool:
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

    def test_a_non_string_download_url_is_ignored(self):
        """download_url is response data: it can be any JSON type, not just text."""
        for value in (42, None, {"url": "https://example.invalid/x"}, ["https://example.invalid/x"], True):
            envelope = json.dumps({"encoding": "none", "content": "", "download_url": value}).encode("utf-8")
            with (
                mock.patch("sources._OPENER.open", side_effect=[_FakeResponse(envelope)]) as urlopen,
                mock.patch("sources.time.sleep"),
                self.assertRaises(SyncError),
            ):
                load_first_available_raw([self.URL])
            self.assertEqual(urlopen.call_count, 1, value)  # nothing else was fetched

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

    def test_redact_url_hides_a_token_carried_in_the_query_string(self):
        """This URL is published in the pull request body: ?token=... must not be."""
        redacted = sources.redact_url("https://example.invalid/list.json?token=ghp_SECRET&ref=main")
        self.assertIn("token=REDACTED", redacted)
        self.assertNotIn("ghp_SECRET", redacted)
        # A harmless parameter keeps its value, so the line still identifies
        # what was fetched.
        self.assertIn("ref=main", redacted)

    def test_redact_url_hides_presigned_s3_credentials(self):
        url = (
            "https://bucket.example/list.json?X-Amz-Credential=AKIAEXAMPLE"
            "&X-Amz-Signature=deadbeef&X-Amz-Security-Token=session"
        )
        redacted = sources.redact_url(url)
        for secret in ("AKIAEXAMPLE", "deadbeef", "session"):
            self.assertNotIn(secret, redacted)
        self.assertIn("X-Amz-Signature=REDACTED", redacted)

    def test_every_credential_named_parameter_is_redacted_not_just_the_common_few(self):
        """An exact-name list leaked private_token, refresh_token, pass, bearer.

        Any of these can appear in a --source URL, and the URL is printed in the
        public pull request body, so a leak cannot be undone -- over-redacting a
        harmless parameter costs a reader nothing.
        """
        for name in (
            "token",
            "private_token",
            "refresh_token",
            "auth_token",
            "access_token",
            "id_token",
            "api_key",
            "apikey",
            "secret",
            "client_secret",
            "secret_key",
            "password",
            "passwd",
            "pass",
            "authorization",
            "bearer",
            "credential",
            "credentials",
            "session",
            "session_id",
            "sig",
            "signature",
            "X-Amz-Signature",
            "X-Goog-Credential",
            "jwt",
            "nonce",
            "ticket",
            "code",
        ):
            with self.subTest(name=name):
                redacted = sources.redact_url(f"https://example.invalid/x?{name}=SECRET")
                self.assertNotIn("SECRET", redacted)
                self.assertIn("REDACTED", redacted)

    def test_a_harmless_parameter_keeps_its_value(self):
        for name in ("ref", "dl", "y", "client_id", "path", "download", "branch"):
            with self.subTest(name=name):
                url = f"https://example.invalid/x?{name}=visible"
                self.assertIn(f"{name}=visible", sources.redact_url(url))

    def test_the_published_report_carries_no_credential_from_the_source_url(self):
        """The report is the pull request body, so this is the line that matters."""
        info = RunInfo(
            database_path=Path("db.json"),
            source="https://example.invalid/list.json?private_token=SUPERSECRET&ref=main",
            source_total=0,
            source_skipped=0,
            dry_run=True,
        )
        report = render_report(info)
        self.assertNotIn("SUPERSECRET", report)
        self.assertIn("private\\_token=REDACTED", report)  # "_" is markdown-escaped
        self.assertIn("ref=main", report)

    def test_redact_url_matches_a_secret_parameter_name_case_insensitively(self):
        self.assertIn("REDACTED", sources.redact_url("https://example.invalid/x?Token=abc"))
        self.assertIn("REDACTED", sources.redact_url("https://example.invalid/x?API_KEY=abc"))

    def test_redact_url_hides_a_credential_carried_in_the_fragment(self):
        """OAuth's implicit flow puts tokens after the ``#``.

        The query string was handled and the fragment was not, so
        ``https://host/callback#access_token=...`` published the token
        verbatim in the pull request body.
        """
        redacted = sources.redact_url("https://h/callback#access_token=s3cret&state=xyz")
        self.assertNotIn("s3cret", redacted)
        self.assertIn("access_token=REDACTED", redacted)
        self.assertIn("state=xyz", redacted)

    def test_redact_url_leaves_an_ordinary_fragment_alone(self):
        # "= in the fragment" is not enough to redact: a pair whose name is not
        # secret-looking must keep its value, exactly like the query string.
        for url in (
            "https://h/x#L10",
            "https://h/x#section-2",
            "https://h/x#",
            "https://h/x",
            "https://h/x#tab=1&line=20",
            "https://h/x#comment=hello",
        ):
            with self.subTest(url=url):
                self.assertEqual(sources.redact_url(url), url)

    def test_redact_url_leaves_a_harmless_query_completely_alone(self):
        url = "https://example.invalid/list.json?ref=main&page=2"
        self.assertEqual(sources.redact_url(url), url)

    def test_redact_url_bounds_an_absurdly_long_url(self):
        """A 100 kB URL used to truncate the whole report; logs too."""
        shown = sources.redact_url("https://example.invalid/" + "a" * 100_000)
        self.assertEqual(len(shown), sources.MAX_URL_DISPLAY_CHARS + 1)
        self.assertTrue(shown.endswith("…"))

    def test_redact_url_survives_a_malformed_port(self):
        """redact_url runs on error paths: it must never raise there."""
        redacted = sources.redact_url("https://user:secret@example.invalid:notaport/list.json")
        self.assertNotIn("secret", redacted)
        self.assertIn("example.invalid", redacted)

    def test_redact_url_survives_an_undecodable_url(self):
        """argv decodes invalid UTF-8 with surrogateescape.

        So ``--source $'https://h/?token=\xff'`` reaches this function holding
        a lone surrogate, which ``urlencode`` refuses to encode. Redaction runs
        on every error path, so raising there would replace a clean refusal
        with a traceback.
        """
        for url in (
            "https://example.invalid/x?token=\udcff",
            "https://example.invalid/\ud800/x?api_key=abc",
            "https://\udcff@example.invalid/x",
            "https://example.invalid/\udfff/x?ref=main",
        ):
            redacted = sources.redact_url(url)
            redacted.encode("utf-8")  # the report writes UTF-8: must not raise
            self.assertNotIn("abc", redacted)
            self.assertIn("example.invalid", redacted)

    def test_an_oversized_database_is_refused_not_read_into_memory(self):
        """A 4 GB file must be a clean refusal, not a MemoryError traceback."""
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "big.json"
            path.write_bytes(b"{}" + b" " * 32)
            with (
                mock.patch.object(playerlist_module, "MAX_FILE_BYTES", 16),
                self.assertRaises(PlayerListError) as raised,
            ):
                load(path)
        self.assertIn("larger than the", str(raised.exception))

    def test_an_oversized_snapshot_is_refused_not_read_into_memory(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "big-snapshot.json"
            path.write_bytes(b"{}" + b" " * 32)
            with (
                mock.patch.object(sources, "MAX_FILE_BYTES", 16),
                self.assertRaises(sources.SyncError) as raised,
            ):
                sources.load_snapshot(path)
        self.assertIn("larger than the", str(raised.exception))

    def test_an_unrepresentable_path_is_refused_cleanly(self):
        """A path the OS cannot even encode must not escape as ValueError.

        ``os`` raises ValueError (not OSError) for an embedded NUL or a lone
        surrogate, and every reader here documents "raises PlayerListError /
        SyncError". One ValueError percolating out of a path helper would turn
        a clean refusal into a traceback.
        """
        bad = "a\x00b.json"
        with self.assertRaises(PlayerListError):
            load(Path(bad))
        with self.assertRaises(sources.SyncError):
            sources._read_bytes(bad)
        # "no snapshot" is the honest answer for a path that cannot exist
        self.assertIsNone(sources.load_snapshot(Path("x\ud800.json")))
        self.assertFalse(sync_module._same_file(Path(bad), Path("x")))

    def test_redact_url_keeps_a_url_on_one_line(self):
        """A --source can contain any byte; a printed URL must stay one line.

        A raw newline in a log line forges a second one, and U+2028 splits a
        table row. Both are percent-encoded instead of being printed raw.
        """
        for url in (
            "https://example.invalid/x?y=\nforged",
            "https://example.invalid/a\u2028b",
            "https://example.invalid/a\x85b",
            "https://example.invalid/a\x00b",
            "https://[::1\nforged",  # urlsplit() itself refuses this one
        ):
            shown = sources.redact_url(url)
            self.assertEqual(len(shown.splitlines()), 1)
            self.assertNotIn("\n", shown)

    def test_http_scheme_is_case_insensitive_and_blank_for_a_local_path(self):
        """RFC 3986 schemes are case-insensitive, and urllib agrees."""
        self.assertEqual(sources.http_scheme("https://example.invalid/x"), "https")
        self.assertEqual(sources.http_scheme("HTTPS://example.invalid/x"), "https")
        self.assertEqual(sources.http_scheme("HTTP://example.invalid/x"), "http")
        self.assertEqual(sources.http_scheme("playerlist.garou3299.json"), "")
        self.assertEqual(sources.http_scheme("https://[::1/x"), "")  # malformed, never raises

    def test_an_uppercase_https_source_is_fetched_instead_of_treated_as_a_path(self):
        with mock.patch("sources._OPENER.open", return_value=_FakeResponse(b'{"players": []}')):
            self.assertEqual(sources._read_bytes("HTTPS://example.invalid/list.json"), b'{"players": []}')

    def test_parse_errors_redact_credentials(self):
        """A --source may carry a token; a bad document must not print it."""
        url = "https://bot:ghp_secret@example.invalid/list.json"
        with (
            mock.patch("sources._OPENER.open", return_value=_FakeResponse(b"<html>")),
            self.assertRaises(SyncError) as raised,
        ):
            load_first_available_raw([url])
        self.assertNotIn("ghp_secret", str(raised.exception))
        self.assertIn("https://example.invalid/list.json", str(raised.exception))

        # Same for a document that parses but is not a JSON object.
        with (
            mock.patch("sources._OPENER.open", return_value=_FakeResponse(b"[]")),
            self.assertRaises(SyncError) as raised,
        ):
            load_first_available_raw([url])
        self.assertNotIn("ghp_secret", str(raised.exception))

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

    def test_plain_http_source_is_refused(self):
        """Plain HTTP is refused even when the operator asks for it by hand.

        This file decides who gets promoted, so its transport is part of the
        trust model: a network attacker must not be able to inject entries by
        serving the list over HTTP. Local mirrors stay supported as a path.
        """
        with self.assertRaises(SyncError) as caught:
            load_first_available_raw(["http://example.invalid/list.json"])
        self.assertIn("non-HTTPS", str(caught.exception))
        self.assertIn("use https:// or a local path", str(caught.exception))

    def test_has_usable_steamids(self):
        """The chain's accept test: one normalisable SteamID is enough."""
        self.assertFalse(sources._has_usable_steamids({}))
        self.assertFalse(sources._has_usable_steamids({"players": "nope"}))
        self.assertFalse(sources._has_usable_steamids({"players": []}))
        self.assertFalse(sources._has_usable_steamids({"players": ["junk", 7, None]}))
        self.assertFalse(sources._has_usable_steamids({"players": [{"steamid": "junk"}]}))
        self.assertTrue(sources._has_usable_steamids({"players": [{"steamid": "junk"}, {"steamid": "[U:1:5]"}]}))
        self.assertTrue(sources._has_usable_steamids({"players": [{"steamid": 76561197960265733}]}))

    def test_an_empty_list_falls_back_to_the_next_source(self):
        """A mirror answering 200 with an empty list must not stop the chain.

        The nightly run would otherwise die on a stale or broken mirror while a
        healthy source was still available.
        """
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty.json"
            good = Path(tmp) / "good.json"
            empty.write_text(dumps({"players": []}), encoding="utf-8")
            good.write_text(dumps({"players": [{"steamid": "[U:1:7]", "attributes": ["cheater"]}]}), encoding="utf-8")
            document, source, raw = load_first_available_raw([str(empty), str(good)])
            self.assertEqual(source, str(good))
            self.assertEqual(raw, good.read_bytes())
            self.assertEqual(document["players"][0]["steamid"], "[U:1:7]")

    def test_every_empty_source_is_named_in_the_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "a.json"
            second = Path(tmp) / "b.json"
            for path in (first, second):
                path.write_text(dumps({"players": [{"steamid": "junk", "attributes": []}]}), encoding="utf-8")
            with self.assertRaises(SyncError) as caught:
                load_first_available_raw([str(first), str(second)])
            message = str(caught.exception)
            self.assertIn(str(first), message)
            self.assertIn(str(second), message)
            self.assertIn("no usable SteamIDs", message)

    def test_a_refused_http_source_falls_back_to_the_next_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / "list.json"
            local.write_text(dumps({"players": [{"steamid": "[U:1:7]", "attributes": ["cheater"]}]}), encoding="utf-8")
            document, source, raw = load_first_available_raw(["http://example.invalid/list.json", str(local)])
            self.assertEqual(source, str(local))
            self.assertEqual(raw, local.read_bytes())
            self.assertEqual(document["players"][0]["steamid"], "[U:1:7]")

    def test_a_byte_order_mark_in_the_database_is_accepted(self):
        """A BOM is still UTF-8, and the upstream list already tolerates one.

        Refusing it here would mean a file saved by an editor that adds a mark
        stops the nightly bot with a cryptic JSON error.
        """
        document = {"players": [{"steamid": "[U:1:5]", "attributes": ["cheater"]}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "playerlist.json"
            body = dumps(document).encode("utf-8")
            path.write_bytes(b"\xef\xbb\xbf" + body)
            loaded, original = load(path)
            self.assertEqual(loaded, document)
            self.assertEqual(original, body.decode("utf-8"))
            self.assertFalse(original.startswith("\ufeff"))

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

    @unittest.skipUnless(Path("/dev/zero").exists(), "needs a zero-size endless file")
    def test_special_file_reporting_zero_size_is_still_capped(self):
        """/dev/zero reports st_size 0 but never ends: the cap must apply to bytes READ."""
        with mock.patch("sources.MAX_SOURCE_BYTES", 1024), self.assertRaises(SyncError) as raised:
            load_first_available_raw(["/dev/zero"])
        self.assertIn("larger than the", str(raised.exception))

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

    def test_the_retry_count_comes_from_the_module_constant(self):
        """It used to be frozen into a keyword default, so patching did nothing."""
        with (
            mock.patch.object(sources, "FETCH_ATTEMPTS", 1),
            mock.patch("sources._OPENER.open", side_effect=urllib.error.URLError("boom")) as opener,
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError),
        ):
            load_first_available_raw([self.URL])
        self.assertEqual(opener.call_count, 1)

    def test_the_timeout_comes_from_the_module_constant(self):
        with (
            mock.patch.object(sources, "FETCH_TIMEOUT_SECONDS", 7),
            mock.patch("sources._OPENER.open", return_value=_FakeResponse(self.BODY)) as opener,
        ):
            load_first_available_raw([self.URL])
        self.assertEqual(opener.call_args.kwargs["timeout"], 7)

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
        # The DELAY matters, not just the number of attempts: retrying a
        # rate-limited server with a zero backoff is a hammer, and the delays
        # must grow instead of repeating.
        backoffs = [call.args[0] for call in sleep.call_args_list]
        self.assertTrue(all(delay > 0 for delay in backoffs), backoffs)
        self.assertEqual(backoffs, sorted(backoffs))
        self.assertEqual(backoffs[-1], sources.RETRY_BACKOFF_SECONDS * (sources.FETCH_ATTEMPTS - 1))

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

    def test_a_body_shorter_than_its_declared_length_is_retried(self):
        """A connection that dies mid-body must not hand back partial bytes."""
        short = _FakeResponse(self.BODY[:10], {"Content-Length": str(len(self.BODY))})
        (document, _, raw), calls = self.fetch([short, _FakeResponse(self.BODY)])
        self.assertEqual(raw, self.BODY)
        self.assertEqual(len(document["players"]), 1)
        self.assertEqual(calls, 2)

    def test_a_permanently_short_body_fails_after_every_attempt(self):
        short = _FakeResponse(self.BODY[:10], {"Content-Length": str(len(self.BODY))})
        with (
            mock.patch("sources._OPENER.open", side_effect=lambda *_, **__: short) as urlopen,
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError) as caught,
        ):
            load_first_available_raw([self.URL])
        self.assertEqual(urlopen.call_count, sources.FETCH_ATTEMPTS)
        self.assertIn("received 10 of", str(caught.exception))

    def test_a_chunked_body_that_ends_early_is_retried(self):
        broken = http.client.IncompleteRead(partial=self.BODY[:10], expected=len(self.BODY))
        (document, _, raw), calls = self.fetch([broken, _FakeResponse(self.BODY)])
        self.assertEqual(raw, self.BODY)
        self.assertEqual(len(document["players"]), 1)
        self.assertEqual(calls, 2)

    def test_a_permanently_truncated_chunked_body_fails_after_every_attempt(self):
        """The final attempt has no backoff left: it must still raise, not hang."""
        broken = http.client.IncompleteRead(partial=self.BODY[:10], expected=len(self.BODY))
        with (
            mock.patch("sources._OPENER.open", side_effect=broken) as urlopen,
            mock.patch("sources.time.sleep") as sleep,
            self.assertRaises(SyncError),
        ):
            load_first_available_raw([self.URL])
        self.assertEqual(urlopen.call_count, sources.FETCH_ATTEMPTS)
        self.assertEqual(sleep.call_count, sources.FETCH_ATTEMPTS - 1)

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

    def plan(self, removed_count, snapshot_entries, *, demote=True, allow=False, no_update=False):
        args = SimpleNamespace(demote=demote, allow_mass_demotion=allow, no_update_snapshot=no_update)
        previous = index_of(*[hackerpolice_entry(f"[U:1:{1000 + n}]") for n in range(snapshot_entries)])
        removed = {f"[U:1:{1000 + n}]" for n in range(removed_count)}
        with self.quiet():
            return sync_module._plan_demotion(args, previous, removed, Path("snapshot.json"))

    def test_exactly_fifty_removals_are_not_a_mass_removal(self):
        # 50 of 100 is 50% of the snapshot, but the floor is "more than 50".
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
        # 100 IDs is above the floor, but only 10% of 1000: real drift, not a break.
        removed, update_snapshot, note, _ = self.plan(100, 1000)
        self.assertEqual(len(removed), 100)
        self.assertTrue(update_snapshot)
        self.assertIsNone(note)

    def test_the_fraction_threshold_alone_can_trip_the_guard(self):
        # 201 of 1000 is just over 20%.
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
        # With both --no-update-snapshot and unapplied removals, the report
        # names the removals: that is the information the reviewer needs.
        _, update_snapshot, _, snapshot_note = self.plan(1, 10, demote=False, no_update=True)
        self.assertFalse(update_snapshot)
        self.assertIn("could not be applied", snapshot_note)


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
        self.assertNotIn("--include-proof", output.getvalue())

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

    def test_an_empty_username_still_hides_the_token(self):
        """``https://:TOKEN@host/`` is a real basic-auth form (empty user name).

        ``urlsplit`` reports the user name as ``""`` there, and ``""`` is
        falsy: a truthiness test instead of ``is not None`` would leave the
        token in the URL, and this URL is published in the pull request.
        """
        self.assertEqual(
            sources.redact_url("https://:ghp_secret@example.invalid/list.json"),
            "https://example.invalid/list.json",
        )
        # The same form with a port, and with both halves empty apart from the password.
        self.assertEqual(
            sources.redact_url("https://:s3cret@example.invalid:8443/x"),
            "https://example.invalid:8443/x",
        )

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

    def test_write_through_a_symlink_updates_the_target_and_keeps_the_link(self):
        """A symlinked playerlist must be edited, not replaced by a plain file.

        Replacing the link would leave the real file untouched while the run
        reported success -- the operator's file silently stops being updated.
        """
        real = self.root / "real.json"
        real.write_bytes(b"old\n")
        link = self.root / "link.json"
        link.symlink_to(real)
        sync_module._atomic_write_bytes(link, b"new\n")
        self.assertTrue(link.is_symlink())
        self.assertEqual(real.read_bytes(), b"new\n")
        self.assertEqual(link.read_bytes(), b"new\n")

    def test_write_through_a_chain_of_symlinks_lands_on_the_final_file(self):
        real = self.root / "real.json"
        real.write_bytes(b"old\n")
        middle = self.root / "middle.json"
        middle.symlink_to(real)
        link = self.root / "link.json"
        link.symlink_to(middle)
        sync_module._atomic_write_bytes(link, b"new\n")
        self.assertEqual(real.read_bytes(), b"new\n")
        self.assertTrue(link.is_symlink() and middle.is_symlink())

    def test_a_failed_write_names_the_file_the_operator_asked_for(self):
        """The raw OSError names a temporary file, which explains nothing."""
        target = self.root / "list.json"
        target.write_text(dumps({"players": []}), encoding="utf-8")
        with (
            mock.patch.object(Path, "replace", side_effect=OSError("disk full")),
            self.assertRaises(SyncError) as caught,
        ):
            sync_module.write_database(target, dumps({"players": []}), "different", dry_run=False)
        message = str(caught.exception)
        self.assertIn(str(target), message)
        self.assertIn("disk full", message)
        self.assertNotIn(".tmp", message)

    def test_a_failed_snapshot_write_names_the_snapshot_file(self):
        target = self.root / "snapshot.json"
        with (
            mock.patch.object(Path, "replace", side_effect=OSError("disk full")),
            self.assertRaises(SyncError) as caught,
        ):
            sync_module.write_snapshot(target, b"new\n", b"old\n", dry_run=False)
        message = str(caught.exception)
        self.assertIn(str(target), message)
        self.assertIn("disk full", message)
        self.assertNotIn(".tmp", message)

    def test_write_does_not_invent_a_missing_parent_directory(self):
        """A writer must not *create* state the operator never asked for.

        It used to ``mkdir -p`` for any target, so a typo'd ``--snapshot``
        silently produced a fresh baseline in a brand-new tree -- and a fresh
        baseline can never prove a removal, so ``--demote`` would quietly do
        nothing forever. The CLI refuses such a path up front (by name); the
        writer itself must not paper over it either.
        """
        nested = self.root / "a" / "b" / "list.json"
        with self.assertRaises(OSError):
            sync_module._atomic_write_bytes(nested, b"{}\n")
        self.assertFalse((self.root / "a").exists())

    def test_write_into_an_existing_directory_keeps_the_existing_mode(self):
        target = self.root / "list.json"
        target.write_bytes(b"old\n")
        target.chmod(0o640)
        sync_module._atomic_write_bytes(target, b"new\n")
        self.assertEqual(target.read_bytes(), b"new\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)  # mode preserved

    def test_a_new_file_takes_the_umask_not_a_hardcoded_0644(self):
        """``chmod(0o644)`` overrode the operator's umask.

        Under ``umask 077`` -- "only I may read this" -- the snapshot and the
        report used to be created world-readable, which on a shared machine is
        a silent exposure of the database and the review page.
        """
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "new.json"
            previous = os.umask(0o077)
            try:
                sync_module._atomic_write_bytes(target, b"x\n")
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(target.read_bytes(), b"x\n")

    def test_a_new_file_under_a_permissive_umask_is_still_group_readable(self):
        """The other side of it: do not over-correct into 0600 for everyone."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "new.json"
            previous = os.umask(0o022)
            try:
                sync_module._atomic_write_bytes(target, b"x\n")
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

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

    def test_same_file_treats_a_symlink_loop_as_different_files(self):
        """pathlib raises RuntimeError -- not OSError -- when resolving a loop.

        Both resolutions happen inside _same_file, so an uncaught RuntimeError
        escaped as a traceback for every one of the four paths.
        """
        loop = self.root / "loop.json"
        os.symlink(loop, loop)
        self.assertFalse(sync_module._same_file(loop, self.root / "other.json"))
        self.assertFalse(sync_module._same_file(self.root / "other.json", loop))

    def test_a_symlink_loop_on_any_path_is_never_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            loop = root / "loop.json"
            os.symlink(loop, loop)
            (root / "up.json").write_text(dumps({"players": [player("[U:1:1]", ["cheater"])]}), encoding="utf-8")
            (root / "db.json").write_text(dumps({"players": []}), encoding="utf-8")
            for flag in ("--database", "--snapshot", "--report", "--source"):
                with self.subTest(path=flag):
                    argv = {
                        "--database": str(root / "db.json"),
                        "--snapshot": str(root / "s.json"),
                        "--source": str(root / "up.json"),
                        "--report": str(root / "r.md"),
                        "-q": None,
                    }
                    argv[flag] = str(loop)
                    flat = [item for pair in argv.items() for item in pair if item is not None]
                    with contextlib.redirect_stdout(io.StringIO()):
                        code = main(flat)  # must not raise
                    self.assertIn(code, (0, 2))

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
        # Not "proof": [] -- no entry in the database spells it that way, and the
        # demotion must not invent a shape the rest of the file does not use.
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
        """The reason has to be quoted shut; the docstring always said so.

        A line that stops at the opening quote ("... | reason: \"") was
        accepted as a racist proof, so a demotion kept text that justifies
        nothing. TF2BD always closes the quote.
        """
        self.assertFalse(is_racist_proof('[auto] automatically marked: Racist | reason: "'))
        self.assertFalse(is_racist_proof("[auto] automatically marked: Racist | reason:"))
        # an empty but CLOSED reason is a complete line, and therefore stays
        self.assertTrue(is_racist_proof('[auto] automatically marked: Racist | reason: ""'))

    def test_is_racist_proof(self):
        self.assertTrue(is_racist_proof('[auto] automatically marked: Racist | reason: "x"'))
        # whitespace at the ends and letter case are still forgiven
        self.assertTrue(is_racist_proof('  [AUTO] Automatically marked: RACIST | reason: "x"  '))
        for value in (
            '[auto] automatically marked: Cheater | reason: "aimbot"',
            "https://youtu.be/x",
            "Racist behavior in voice chat",
            "[auto] automatically marked: Racist",
            "",
            # The quote is part of the prefix: an auto line whose reason is
            # missing, unquoted or differently spaced is NOT the machine record.
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
                        "[auto] automatically marked: Racist | reason:",  # truncated
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


# --------------------------------------------------------------------------- #
# Policy invariants over randomised inputs (seeded: fully deterministic)
# --------------------------------------------------------------------------- #
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
                self.assertNotIn("proof", player)  # nothing survived, so the key goes
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
                    # No attributes at all: malformed, left alone by the policy
                    # (the CLI refuses such a database before writing anything).
                    self.assertEqual(entry, original)
                    continue
                if steamid in listed and has:
                    # Still listed: never demoted, even if also in removed_ids.
                    self.assertEqual(entry, original)
                elif steamid in listed and was & {"suspicious", "racist"}:
                    # Promoted: cheater added, suspicious settled, everything else kept
                    # -- proofs included: a promotion never adds or rewrites one.
                    self.assertEqual(entry["attributes"], order_attributes((was | {"cheater"}) - {"suspicious"}))
                    self.assertEqual(entry["last_seen"], original["last_seen"])
                    self.assertEqual(entry.get("proof"), original.get("proof"), "promotion changed the proofs")
                elif steamid in removed and has and "racist" not in was:
                    # Removed upstream without a racist tag: the entry is gone.
                    self.assertIsNone(entry)
                elif steamid in removed and has:
                    # Only the cheater tag goes (other tags survive); the proofs that
                    # remain are exactly the [auto] racist lines -- nothing else
                    # (no video link, no hand-written note, no gibberish) survives.
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
                    self.assertEqual(got, before)  # untouched means byte-identical


# --------------------------------------------------------------------------- #
# Report rendering
# --------------------------------------------------------------------------- #
# A table separator is a pipe that is not escaped as "\\|" inside a cell.
_UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")


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
        return RunInfo(
            database_path=Path("playerlist.garou3299.json"),
            source=source,
            source_total=10,
            changes=tuple(changes),
            **{"source_skipped": 0, "dry_run": False, **kwargs},
        )

    def test_ansi_escapes_cannot_repaint_the_job_log(self):
        """The workflow `cat`s this report into the job log: ESC must not survive."""
        change = Change("[U:1:100]", "\x1b[31mRED\x1b[0m", ("suspicious",), ("cheater",))
        report = render_report(self.info([change]))
        self.assertNotIn("\x1b", report)
        self.assertIn("RED", report)  # the name itself is still readable

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
        self.assertIn("\\[x\\]", line)  # escaped, so it renders as literal text
        self.assertNotIn("[x](https://evil.example)", line)  # never a link

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
        the bidi set was neutralised, so these sailed into the pull request body.
        """
        for character in (
            "\u200b",  # zero-width space
            "\u2060",  # word joiner
            "\ufeff",  # zero-width no-break space / BOM
            "\u00ad",  # soft hyphen
            "\u061c",  # Arabic letter mark
            "\u180e",  # Mongolian vowel separator
            "\U000e0041",  # Unicode tag character
            "\ufff9",  # interlinear annotation anchor
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
            evidence=("https://example.invalid/\x1b[31mx", "https://example.invalid/a\u202eb"),
        )
        report = render_report(self.info([change]))
        self.assertNotIn("\x1b", report)
        self.assertNotIn("\u202e", report)
        self.assertIn("%1B", report)  # ESC
        self.assertIn("%E2%80%AE", report)  # U+202E, as UTF-8 bytes

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
        self.assertIn("…", report)
        self.assertNotIn(f"]({long_url})", report)
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
        # Main reference: the readable GitHub blob page, not a raw/API URL.
        self.assertIn(
            "Vorobey hackerpolice list (10 entries): "
            "https://github.com/Nocrex/Tom/blob/main/playerlist.vorobey-hackerpolice.json",
            report,
        )
        # The actual URL the bytes were fetched from stays visible for debugging.
        self.assertIn("- Fetched from: https://example.invalid/list.json", report)

    def test_the_fetch_line_never_publishes_a_credential(self):
        """The same line is the public pull request body's fetch record."""
        report = render_report(
            self.info(source="https://user:secret@example.invalid/list.json?token=ghp_SECRET&ref=main")
        )
        # "&" and "_" are markdown-escaped in running text (they render as
        # themselves; the escape is what stops a URL from forging emphasis).
        self.assertIn("- Fetched from: https://example.invalid/list.json?token=REDACTED&amp;ref=main", report)
        self.assertNotIn("secret", report)
        self.assertNotIn("ghp_SECRET", report)

    def test_every_change_row_links_the_player_to_steamhistory(self):
        """Reviewers can open the archived profile (past names, bans) in one click."""
        promote = Change("[U:1:100]", "a", ("suspicious",), ("cheater",))
        demote = Change("[U:1:200]", "b", ("cheater",), ("racist",), kind="demote")
        report = render_report(self.info([promote, demote]))
        self.assertIn("| SteamHistory |", report)  # column header, in both tables
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
            # An escaped "\\|" is part of a cell, not a separator.
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

    def test_normalised_file_is_reported_instead_of_no_changes(self):
        """The sync always writes entries in canonical form.

        A hand-appended entry is re-sorted without any tag changing: the file
        in the pull request differs, so the body must not claim "No changes".
        """
        report = render_report(self.info(database_changed=True))
        self.assertIn("**No player changes** (the database file was normalised:", report)
        self.assertNotIn("**No changes.**", report)
        self.assertNotIn("**No database changes**", report)

        both = render_report(self.info(database_changed=True, snapshot_changed=True))
        self.assertIn("the snapshot was refreshed too", both)

        # A dry run writes nothing, so the sentence must be conditional there.
        dry = render_report(self.info(database_changed=True, snapshot_changed=True, dry_run=True))
        self.assertIn("would be normalised", dry)
        self.assertIn("the snapshot would be refreshed too", dry)
        self.assertNotIn("was normalised", dry)

        # A snapshot-only run keeps its existing wording.
        snapshot_only = render_report(self.info(snapshot_changed=True))
        self.assertIn("**No database changes** (snapshot refresh only).", snapshot_only)

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
        # the proof itself survives in the database ...
        self.assertEqual(database["players"][0]["proof"], [line])
        # ... and never appears in the report
        self.assertNotIn(marker, report)
        self.assertNotIn("[auto] automatically marked", report)

    def test_line_terminators_cannot_split_a_table_row(self):
        """U+2028/U+2029/U+0085 break lines in CSS and in str.splitlines().

        A player name is attacker-controlled, so one containing a line
        terminator must not be able to end a table row early and start a new
        one. Everything that ends a line is neutralised, not just \n and \r.
        """
        name = "evil\u2028name\u2029other\x85nel\nlf\rcr\x0bvt\x0cff"
        change = Change("[U:1:1]", name, ("suspicious",), ("cheater",))
        report = render_report(self.info([change]))
        for terminator in ("\u2028", "\u2029", "\x85", "\x0b", "\x0c"):
            self.assertNotIn(terminator, report)
        # splitlines() must see exactly the same lines as a plain split: any
        # extra break would mean an unneutralised terminator survived.
        self.assertEqual(len(report.rstrip("\n").split("\n")), len(report.splitlines()))
        row = next(line for line in report.split("\n") if line.startswith("| `[U:1:1]`"))
        self.assertIn("evil name other nel lf cr vt ff", row)

    def test_a_backslash_cannot_neutralise_the_escape_that_follows_it(self):
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
        # Outside code spans every backtick must still be escaped: strip the
        # "\\<punct>" escapes, then nothing may be left to open a span.
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
        self.assertEqual(row.count("|"), 7)  # six cells, still six
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
            # Code spans are literal, so only the text OUTSIDE them matters.
            outside_code = re.sub(r"`+[^`]*`+", "", report)
            self.assertNotIn("<", outside_code)
            self.assertNotIn("](https://elsewhere.example)", outside_code)
            headline = next(line for line in report.split("\n") if "promoted to" in line)
            self.assertIn("database:**", headline)

    def test_a_url_cannot_inject_a_link_into_the_fetch_line(self):
        """The "Fetched from" line carries a URL, which can come from upstream.

        A URL holding "[click](https://elsewhere.example)" must render as
        literal text, not as a clickable link in a bot-authored pull request.
        """
        report = render_report(self.info(source="https://host/[click](https://elsewhere.example)/x"))
        line = next(line for line in report.split("\n") if "Fetched from" in line)
        self.assertIn("\\[click\\]", line)
        self.assertNotIn("[click](https://elsewhere.example)", report)

    def test_report_never_emits_raw_html(self):
        """Markdown previews that escape HTML would show the tag as literal text."""
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",), ("https://x/1", "https://x/2"))
        report = render_report(self.info([change], removed_upstream=("[U:1:2]",)))
        self.assertNotIn("<br>", report)
        self.assertNotIn("<br/>", report)
        self.assertNotIn("<br />", report)

    def test_prose_evidence_is_not_turned_into_a_link(self):
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",), ("seen spinbotting",))
        report = render_report(self.info([change]))
        self.assertIn("| seen spinbotting |", report)
        self.assertNotIn("[proof](seen spinbotting)", report)

    def test_invisible_characters_are_percent_encoded_in_link_targets(self):
        """A proof URL is a link target too, so it gets the same treatment.

        A zero-width space in a URL is invisible; two different targets then
        look identical, and the raw character lands in the published body.
        """
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",), ("https://youtu.be/\u200babc",))
        report = render_report(self.info([change]))
        self.assertIn("%E2%80%8B", report)
        self.assertNotIn("\u200b", report)

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
        self.assertEqual(rows[0].count("|"), 7)  # six cells, no stray separator

    def test_no_proof_note_without_evidence_links(self):
        change = Change("[U:1:1]", "a", ("suspicious",), ("cheater",))  # no evidence links
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
        # The exact shape that raised the question: no promotion table at all,
        # a demotion table and the removed-from-the-list table.
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
        self.assertIn("&lt;b&gt;this&lt;/b&gt;", report)  # rendered literally, not as HTML

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
                    # Both turn a line break into a space; the cell then trims
                    # it away and falls back to its "-" placeholder.
                    self.assertEqual(report_module._text(character), " ")
                    self.assertEqual(report_module._cell(character), "-")
                    continue
                self.assertNotEqual(replacement, character)  # actually an escape
                self.assertEqual(report_module._text(character), replacement)
                self.assertEqual(report_module._cell(character), replacement)
        # The one intentional difference: a pipe ends a table cell.
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
                # and an ordinary underscore survives, visibly unchanged:
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
                self.assertIn("&amp;#", cell)  # the entity spelling is now inert text

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
        # The two lines the pull request exists for are still there, in full.
        self.assertIn("; nothing else is modified.", report)
        self.assertIn("100 SteamIDs removed from the Vorobey hackerpolice list", report)
        self.assertIn("| SteamID | Profile Link | SteamHistory |", report)
        # Rows beyond the reduced cap are announced rather than silently dropped,
        # and the removed-SteamID list keeps every row: the change tables shrink
        # first, because those changes are visible in the PR's own diff too.
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
        report.encode("utf-8")  # always UTF-8 encodable

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
        budget = 700  # below one shrunken row plus the header
        with mock.patch.object(report_module, "MAX_REPORT_BYTES", budget):
            report = report_module.render_report(self.info(changes=changes))
        self.assertLessEqual(len(report.encode("utf-8")), budget)
        self.assertTrue(report.endswith("… report truncated to fit the pull request body limit."))
        self.assertTrue(report.startswith("## Vorobey hackerpolice sync"))
        self.assertNotIn("\ufffd", report)

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
        last_block = report.split("\n\n")[-1]
        self.assertTrue(last_block.startswith("In the Garou3299 database:"), last_block)

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
            # A change matters here: the path reaches the promotion HEADLINE as
            # well as the header bullet, and the headline is what used to push
            # the body past its budget and drop the closing sentence.
            changes=(Change("[U:1:1]", "name", ("suspicious",), ("cheater",)),),
        )
        report = render_report(info)
        self.assertLessEqual(len(report.encode("utf-8")), MAX_REPORT_BYTES)
        self.assertNotIn("report truncated to fit the pull request body limit", report)
        self.assertIn("; nothing else is modified.", report)
        self.assertIn("…", report)  # the path itself is the thing clipped
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
        # The cap is applied to the raw name, so no escape sequence is cut in half.
        self.assertEqual(report.count("| `[U:1:1"), 3)

    def test_the_number_of_proof_links_in_a_row_is_capped(self):
        """One row may not carry thousands of links: the tables must survive."""
        links = tuple(f"https://discord.com/channels/1/2/{n}" for n in range(2_000))
        changes = [Change(f"[U:1:{1000 + n}]", "name", ("suspicious",), ("cheater",), links) for n in range(3)]
        report = render_report(self.info(changes, removed_upstream=("[U:1:9]",)))
        self.assertLessEqual(len(report.encode("utf-8")), MAX_REPORT_BYTES)
        self.assertNotIn("report truncated to fit the pull request body limit", report)
        self.assertIn("; nothing else is modified.", report)
        # Pin the policy value itself: a test that only compares against the
        # constant would pass no matter how high the cap were raised.
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


# --------------------------------------------------------------------------- #
# "Removed from the Vorobey list" table
# --------------------------------------------------------------------------- #
class RemovedFromVorobeyTableTests(unittest.TestCase):
    """The PR body lists EVERY SteamID that disappeared from the Vorobey list.

    The Vorobey list stores no player names, so the table is exactly
    ``| SteamID | Profile Link | SteamHistory |`` and every link is a SteamID64
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
        # No explanatory filler above the table either: heading, then the table.
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
                # A demotion is an upstream removal the database still contains,
                # so the raw removed table is always printed with it.
                if "demoted (present" in report:
                    self.assertIn(markers[2], report)

    def test_closing_sentence_and_proof_note_are_always_last(self):
        change = Change("[U:1:400]", "a", ("suspicious",), ("cheater",), ("https://x/1",))
        report = render_report(self.info(changes=(change,), removed_upstream=("[U:1:5]",)))
        lines = [line for line in report.splitlines() if line.strip()]
        self.assertIn("Proof link", lines[-1])
        self.assertIn("nothing else is modified.", lines[-2])
        # The removed table sits above the closing sentence, not below it.
        self.assertLess(report.index("| Profile Link | SteamHistory |"), report.index("nothing else is modified."))

    def test_closing_sentence_names_the_database_that_changed(self):
        change = Change("[U:1:400]", "a", ("suspicious",), ("cheater",))
        other = Change("[U:1:401]", "c", ("suspicious",), ("cheater",))
        removed_entry = Change("[U:1:500]", "b", ("cheater",), (), kind="demote")
        report = render_report(self.info(changes=(change, other, removed_entry)))
        self.assertIn("In the Garou3299 database: attributes are changed for these SteamIDs", report)
        self.assertIn("entry is removed for this SteamID: [U:1:500]", report)
        # ... and only that once (the header bullet is a separate line):
        closing = next(line for line in report.splitlines() if "nothing else is modified" in line)
        self.assertEqual(closing.count("Garou3299"), 1)
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
        """A report must always encode: the CLI writes it with UTF-8.

        Lone surrogates are legal in a JSON database and impossible to encode,
        so this asserts the bytes really are produced -- not merely that no
        exception escaped.
        """
        report = render_report(self.info(removed_upstream=("[U:1:1]",), previous_source_total=10))
        encoded = report.encode("utf-8")
        self.assertTrue(encoded)
        self.assertIn(b"removed from the Vorobey hackerpolice list", encoded)


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

    def test_database_label_scopes_the_sentence(self):
        promote_change = Change("[U:1:400]", "a", ("suspicious",), ("cheater",), kind="promote")
        demote_change = Change("[U:1:300]", "b", ("cheater",), (), kind="demote")
        # The label scopes the whole sentence and is named exactly once.
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
            "mylist.json": "Mylist",
            "playerlist.json": "Playerlist",
            # A file whose owner part is empty falls back to the whole stem.
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
        # Exactly at the cap: every ID is named, no "more" suffix.
        at_cap = render_closing(at_limit, database="db.json")
        self.assertNotIn("more", at_cap)
        self.assertIn(f"[U+{limit - 1}]", at_cap)  # the last one is not dropped
        closing = render_closing(over, database="db.json")
        self.assertIn(" and 25 more", closing)
        self.assertIn(f"[U+{limit - 1}]", closing)  # everything up to the cap is named
        self.assertNotIn(f"[U+{limit}]", closing)  # and nothing past it
        self.assertLess(len(closing), 4_000)

    def test_closing_sentence_counts_hidden_ids_with_thousands_separators(self):
        changes = [Change(f"[U+{n}]", "n", ("cheater",), (), kind="demote") for n in range(1_200)]
        closing = render_closing(changes, database="db.json")
        self.assertIn("and 1,050 more", closing)


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
        # Exactly at the budget in bytes stays untouched.
        exact = "\u044b" * (MAX_REPORT_BYTES // 2)
        self.assertEqual(report_module._fit_body(exact), exact)

    def test_truncation_helper_handles_a_zero_or_negative_budget(self):
        self.assertEqual(report_module._truncate_to_bytes("abc", 0), "")
        self.assertEqual(report_module._truncate_to_bytes("abc", -5), "")
        # A negative limit must mean "nothing", not "drop that many bytes from the end".
        self.assertEqual(report_module._truncate_to_bytes("abcdefghij", -1), "")
        self.assertEqual(report_module._truncate_to_bytes("abc", 3), "abc")
        self.assertEqual(report_module._truncate_to_bytes("\u044b\u044b", 1), "")  # cannot split a character

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
                # Starts at 1, so proof_on=0 is the run with no link at all.
                for n in range(1, limit + 2)
            )

        def account_id(steamid: str) -> int:
            return int(steamid.rsplit(":", 1)[1].rstrip("]"))

        bare = render_report(self._info(changes=promotions(0)))
        self.assertNotIn("Proof link", bare)
        shown = [line.split("`")[1] for line in bare.splitlines() if line.startswith("| `[")]
        self.assertEqual(len(shown), limit)
        hidden = next(f"[U:1:{n}]" for n in range(1, limit + 2) if f"[U:1:{n}]" not in shown)

        # The only link rides on the entry the cap drops.
        dropped = render_report(self._info(changes=promotions(account_id(hidden))))
        self.assertIn("1 more entry not shown", dropped)
        self.assertNotIn("Proof link", dropped)
        # In a visible row the same link is annotated again.
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


class SnapshotReadTests(unittest.TestCase):
    def test_a_path_the_os_cannot_stat_is_a_read_error_not_a_crash(self):
        """``exists()`` raises for a path longer than the OS allows (ENAMETOOLONG).

        It must not escape as a bare OSError -- and it must not be read as "no
        snapshot" either, which would silently disable demotion.
        """
        path = Path("/tmp") / ("d" * 200) / "snap.json"
        with (
            mock.patch.object(Path, "exists", side_effect=OSError(36, "File name too long", str(path))),
            self.assertRaises(SyncError) as caught,
        ):
            sources.load_snapshot(path)
        self.assertIn("cannot read", str(caught.exception))
        self.assertIn("File name too long", str(caught.exception))


class SupportedPythonTests(unittest.TestCase):
    """pyproject.toml promises Python 3.10+, and only CI's 3.12 ever runs.

    Enforce the floor with the standard library: the parser knows which syntax
    each version accepts, so a 3.12-only construct fails here instead of in a
    contributor's 3.10 interpreter.
    """

    root = Path(__file__).resolve().parent.parent

    def test_the_scripts_parse_as_the_oldest_supported_python(self):
        for path in sorted((self.root / "scripts").glob("*.py")):
            with self.subTest(path.name):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 10))

    def test_the_tests_parse_as_the_oldest_supported_python(self):
        path = self.root / "tests" / "test_sync_vorobey_hackerpolice.py"
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 10))

    def test_the_floor_is_the_one_documented(self):
        pyproject = (self.root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('target-version = "py310"', pyproject)
        self.assertIn("Python 3.10+", pyproject)

    def test_the_guard_actually_rejects_newer_syntax(self):
        """A guard nobody tested is a guard that silently stops guarding."""
        with self.assertRaises(SyntaxError):
            ast.parse("type Alias = int\n", feature_version=(3, 10))


class WorkflowContractTests(unittest.TestCase):
    """The workflow is code too, and only the schedule ever executes it.

    A renamed CLI flag, a step output nobody writes any more, a report path that
    drifted from the pull-request body, an unpinned action or a job that stopped
    running the tests would all break the bot silently -- GitHub only finds out
    when the cron fires. Pin the contract in the suite instead.
    """

    root = Path(__file__).resolve().parent.parent
    workflow_path = root / ".github" / "workflows" / "sync-vorobey-hackerpolice.yml"
    dependabot_path = root / ".github" / "dependabot.yml"

    @classmethod
    def setUpClass(cls):
        cls.workflow = cls.workflow_path.read_text(encoding="utf-8")

    def jobs(self) -> dict[str, str]:
        """Split the jobs: mapping into one string per job."""
        _, _, body = self.workflow.partition("\njobs:\n")
        self.assertTrue(body, "the workflow must declare jobs")
        parts = re.split(r"^  ([a-z][a-z-]*):$", body, flags=re.M)
        return {parts[index]: parts[index + 1] for index in range(1, len(parts) - 1, 2)}

    def sync_invocation(self) -> str:
        start = self.workflow.index("python3 scripts/sync_vorobey_hackerpolice.py")
        lines = []
        for line in self.workflow[start:].splitlines():
            lines.append(line)
            if not line.rstrip().endswith("\\"):
                break
        return "\n".join(lines)

    def test_every_flag_it_passes_is_a_real_option(self):
        options = {option for action in sync_module.build_parser()._actions for option in action.option_strings}
        invocation = self.sync_invocation()
        passed = set(re.findall(r"--[a-z][a-z-]*", invocation))
        self.assertTrue(passed, "the sync step should pass flags")
        self.assertEqual(passed - options, set(), "the workflow passes a flag the parser dropped")
        # Flags hidden in the DRY_RUN / ALLOW_MASS_DEMOTION shell variables.
        for hidden in re.findall(r"'(--[a-z][a-z-]*)'", self.workflow):
            self.assertIn(hidden, options)

    def test_it_always_demotes(self):
        """Without --demote the bot never applies a single demotion."""
        self.assertIn("--demote", set(re.findall(r"--[a-z][a-z-]*", self.sync_invocation())))

    def test_it_passes_the_files_from_the_environment(self):
        invocation = self.sync_invocation()
        self.assertIn('--database "$DATABASE"', invocation)
        self.assertIn('--snapshot "$SNAPSHOT"', invocation)

    def test_every_step_output_it_reads_is_one_the_run_writes(self):
        written = run_sync_and_read_outputs(
            database=dumps({"players": [player("[U:1:1]", ["cheater"])]}),
            snapshot=dumps({"players": []}),
            source=dumps({"players": [player("[U:1:1]", ["cheater"])]}),
        )
        read = set(re.findall(r"steps\.sync\.outputs\.([a-z_]+)", self.workflow))
        self.assertTrue(read, "the workflow reads no step output at all")
        self.assertEqual(read - set(written), set(), "the workflow reads an output nothing writes")

    def test_the_publish_steps_require_a_successful_sync(self):
        for block in re.findall(
            r"- name: (?:Open or update pull request|Push branch|Commit directly)([\s\S]*?)(?=\n\s+- name:|\Z)",
            self.workflow,
        ):
            self.assertIn("steps.sync.outcome == 'success'", block, "publishing must not run after a failed sync")
            self.assertIn("steps.sync.outputs.changed == 'true'", block)

    def test_the_pull_request_carries_both_files_and_uses_the_report_as_its_body(self):
        block = self.workflow[self.workflow.index("add-paths:") :]
        block = block[: block.index("branch:")]
        self.assertIn("${{ env.DATABASE }}", block)
        self.assertIn("${{ env.SNAPSHOT }}", block)
        reported = re.search(r'--report "\$RUNNER_TEMP/([^"]+)"', self.workflow)
        self.assertIsNotNone(reported, "the sync step must write a report")
        body = re.search(r"body-path:\s*\$\{\{\s*runner\.temp\s*\}\}/(\S+)", self.workflow)
        self.assertIsNotNone(body, "the pull request must use the report as its body")
        self.assertEqual(body.group(1), reported.group(1))

    def test_every_action_is_pinned_to_a_commit_and_says_which_release_it_is(self):
        uses = re.findall(r"uses:\s*(\S+)\s*(#[^\n]*)?", self.workflow)
        self.assertGreaterEqual(len(uses), 3)
        for reference, comment in uses:
            repository, _, sha = reference.partition("@")
            self.assertRegex(repository, r"^[\w.-]+/[\w.-]+$")
            self.assertRegex(sha, r"^[0-9a-f]{40}$", f"{reference} is not pinned to a commit SHA")
            self.assertRegex(comment or "", r"#\s*v\d", f"{reference} needs its release tag in a comment")

    def test_a_change_to_any_file_the_suite_reads_runs_the_checks(self):
        """Every file these tests read must be able to trigger them.

        ``README.md`` and ``.github/dependabot.yml`` are both read here (the
        CLI inventory and the Dependabot contract) and neither was in the
        ``pull_request`` paths filter: a pull request touching only those files
        ran no checks at all, so the assertions guarding them could never fail.
        """
        block = self.workflow.split("  pull_request:\n", 1)[1].split("\npermissions:", 1)[0]
        patterns = re.findall(r'^\s+- "([^"]+)"', block, re.M)
        self.assertTrue(patterns, "the pull_request trigger has no paths at all")

        def covered(name: str) -> bool:
            return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)

        for name in (
            "README.md",
            ".github/dependabot.yml",
            ".github/workflows/sync-vorobey-hackerpolice.yml",
            "pyproject.toml",
            "scripts/playerlist.py",
            "tests/test_sync_vorobey_hackerpolice.py",
        ):
            self.assertTrue(covered(name), f"{name} can change without the checks running")

    def test_the_paths_it_names_exist(self):
        for key in ("DATABASE", "SNAPSHOT"):
            match = re.search(rf"^\s*{key}:\s*(\S+)$", self.workflow, re.M)
            self.assertIsNotNone(match, f"{key} is not defined")
            self.assertTrue((self.root / match.group(1)).is_file(), match.group(1))

    def test_both_jobs_run_the_full_check_suite(self):
        jobs = self.jobs()
        self.assertEqual(set(jobs), {"checks", "sync"})
        for name, block in jobs.items():
            for command in (
                "python3 -m ruff check scripts tests",
                "python3 -m ruff format --check scripts tests",
                "python3 -m mypy scripts",
                "python3 -m bandit -q -r scripts",
                "python3 -X warn_default_encoding -W error::EncodingWarning -m coverage run -m unittest discover -s tests -v",
                "python3 -m coverage report",
                "python3 -m vulture scripts tests --min-confidence 60",
            ):
                self.assertIn(command, block, f"the {name} job does not run: {command}")
            self.assertIn("timeout-minutes:", block, f"the {name} job has no timeout")
            self.assertIn("concurrency:", block, f"the {name} job has no concurrency group")

    def test_the_sync_job_always_acts_on_the_default_branch(self):
        """A dispatch from a feature branch must not commit or open a PR there.

        actions/checkout follows the branch a workflow_dispatch was started
        from. With no explicit ref, "commit the change" would commit to that
        branch, and create-pull-request (whose base defaults to the checked-out
        branch) would open a pull request against it -- a bot commit on someone's
        feature branch, or a pull request that can never be merged into the
        default branch. The sync maintains the default branch, and says so.
        """
        sync = self.jobs()["sync"]
        self.assertIn("ref: ${{ github.event.repository.default_branch }}", sync)
        # The checks job must NOT pin it: a pull request has to be tested on its
        # own merge ref.
        self.assertNotIn("ref: ${{ github.event.repository.default_branch }}", self.jobs()["checks"])

    def test_the_pull_request_targets_the_default_branch_explicitly(self):
        self.assertIn("base: ${{ env.BASE_BRANCH }}", self.workflow)

    def test_a_run_with_nothing_to_do_closes_a_stale_bot_pull_request(self):
        """Otherwise a day-old pull request stays open, offering a stale database.

        Merging it later would undo whatever changed in between -- a manual fix,
        or a newer upstream change. It must not fire on a dry run (which only
        reports), must not fire in "commit" mode (there is no pull request), and
        must never turn a clean run red if the token cannot manage pull requests.
        """
        steps = self.workflow.split("\n      - ")
        block = next((step for step in steps if step.startswith("name: Close a stale bot pull request")), None)
        self.assertIsNotNone(block, "the workflow must close a stale bot pull request")
        assert block is not None  # for type checkers
        self.assertIn("steps.sync.outputs.changed != 'true'", block)
        self.assertIn("env.MODE != 'commit'", block)
        self.assertIn("env.DRY_RUN_INPUT != 'true'", block)
        self.assertIn("continue-on-error: true", block)
        self.assertIn('gh pr list --repo "$REPOSITORY" --head "$BOT_BRANCH" --state open', block)

    def test_the_checks_job_tests_the_python_floor_the_readme_promises(self):
        """3.10 is promised in the README and was never exercised by CI.

        A 3.11+ API (``datetime.UTC``, ``tomllib``) or a 3.12-only f-string would
        keep CI green while breaking that promise for every user on the floor --
        and the only job that really runs the code (sync) also runs 3.12.
        """
        checks = self.jobs()["checks"]
        self.assertIn("matrix:", checks)
        self.assertIn('"3.10"', checks)  # the documented floor
        self.assertIn(
            '"3.12"',
            checks,
        )  # the production version
        self.assertIn("python-version: ${{ matrix.python-version }}", checks)
        # Each leg needs its own concurrency group: with cancel-in-progress on a
        # SHARED group the legs cancel each other and only one survives.
        group = next(line for line in checks.splitlines() if line.strip().startswith("group: checks-"))
        self.assertIn("matrix.python-version", group)
        # The sync job is production: it stays on one version, deliberately.
        self.assertNotIn("matrix:", self.jobs()["sync"])

    def test_the_suite_does_not_inherit_the_runners_output_file(self):
        """GITHUB_OUTPUT is exported by every CI step, including the test step.

        Inheriting it made the suite append ~300 lines to the runner's real
        output file: the tests then depended on their environment, and a step
        reading its own outputs would be reading values produced by the tests.

        Checked in a CHILD interpreter, because that is the only place the
        import-time behaviour can be observed -- and because asserting on this
        file's own text would match this test's own source and never fail.
        """
        code = (
            "import os, sys;"
            "os.environ['GITHUB_OUTPUT']='must-not-survive-the-import';"
            f"sys.path.insert(0, {str(Path(__file__).resolve().parent)!r});"
            "import test_sync_vorobey_hackerpolice;"  # importing runs the guard, no tests
            "print(os.environ.get('GITHUB_OUTPUT', '<popped>'))"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, encoding="utf-8", timeout=180
        )
        self.assertEqual(result.stdout.strip(), "<popped>", result.stderr[-500:])

    def test_the_coverage_gate_is_encoded_not_just_convention(self):
        """`coverage report` must fail on an untested statement OR branch.

        Without a [tool.coverage] section the gate only exists in a reviewer's
        head: a plain `coverage run` reports line coverage, and anything at all
        reports success. The thresholds belong in the file CI reads.
        """
        pyproject = (self.root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("branch = true", pyproject)
        self.assertIn("fail_under = 100", pyproject)
        self.assertIn('source = ["scripts"]', pyproject)

    def test_the_check_job_is_read_only(self):
        jobs = self.jobs()
        self.assertIn("contents: read", jobs["checks"])
        self.assertNotIn("contents: write", jobs["checks"])
        self.assertNotIn("pull-requests: write", jobs["checks"])

    def test_the_tool_versions_are_defined_once_and_interpolated(self):
        for name in ("RUFF_VERSION", "MYPY_VERSION", "BANDIT_VERSION", "COVERAGE_VERSION", "VULTURE_VERSION"):
            self.assertEqual(len(re.findall(rf'^\s*{name}:\s*"[^"]+"$', self.workflow, re.M)), 1, name)
        for name, tool in (
            ("RUFF_VERSION", "ruff"),
            ("MYPY_VERSION", "mypy"),
            ("BANDIT_VERSION", "bandit"),
            ("COVERAGE_VERSION", "coverage"),
            ("VULTURE_VERSION", "vulture"),
        ):
            self.assertIn(f'"{tool}==${{{name}}}"', self.workflow)

    def test_the_checks_job_runs_on_proposed_code_only(self):
        jobs = self.jobs()
        self.assertIn("github.event_name == 'pull_request'", jobs["checks"])
        self.assertIn("github.event_name != 'pull_request'", jobs["sync"])
        for watched in ("scripts/**", "tests/**", ".github/workflows/sync-vorobey-hackerpolice.yml"):
            self.assertIn(watched, self.workflow)

    def test_dependabot_only_bumps_the_pinned_actions(self):
        text = self.dependabot_path.read_text(encoding="utf-8")
        self.assertIn('package-ecosystem: "github-actions"', text)
        self.assertNotIn("pip", text)  # no runtime dependencies to watch
        self.assertNotIn("package-ecosystem: npm", text)
        self.assertIn('interval: "weekly"', text)


class WriteOrderTests(unittest.TestCase):
    """Append step outputs first, then write report, database, and snapshot.

    A snapshot failure can leave the database rewritten; reversing those two
    data writes could instead advance the baseline and lose removals.
    """

    def test_a_failing_snapshot_write_happens_after_the_database_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "up.json").write_text(dumps({"players": [player("[U:1:1]", ["cheater"])]}), encoding="utf-8")
            # deliberately non-canonical, so a successful rewrite is visible
            (root / "db.json").write_text(
                '{"players":[{"attributes":["cheater"],"steamid":"[U:1:1]"}]}', encoding="utf-8"
            )
            # A symlink whose target directory does not exist: the guard sees a
            # healthy parent (root), the previous-snapshot read sees "no file"
            # (a broken link does not exist), and the write -- which resolves the
            # link -- fails. That is the "last write fails after the database
            # changed" case, deterministically, even when tests run as root.
            (root / "snap.json.link").symlink_to(root / "nodir" / "snap.json")
            with contextlib.redirect_stdout(io.StringIO()):  # the report goes to stdout
                code = main(
                    [
                        "--database",
                        str(root / "db.json"),
                        "--snapshot",
                        str(root / "snap.json.link"),
                        "--source",
                        str(root / "up.json"),
                        "--report",
                        str(root / "r.md"),
                        "--demote",
                        "-q",
                    ]
                )
            self.assertEqual(code, 2)
            self.assertEqual(
                (root / "db.json").read_bytes(),
                dumps({"players": [player("[U:1:1]", ["cheater"])]}).encode("utf-8"),
            )
            self.assertTrue((root / "snap.json.link").is_symlink())  # the failed target is untouched
            self.assertEqual([p.name for p in root.iterdir() if ".tmp" in p.name], [])


class IdempotencyTests(unittest.TestCase):
    """Running the sync again on its own output must find nothing to do.

    The nightly cron consumes the files a previous run wrote. If a second run
    still found work, every night would open another pull request -- and the
    two reports would contradict each other.
    """

    def test_a_second_run_on_its_own_output_changes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            upstream = dumps(
                {
                    "players": [
                        player("[U:1:1]", ["cheater"]),
                        player("[U:1:2]", ["suspicious"]),
                        player("[U:1:3]", ["cheater", "racist"]),
                    ]
                }
            )
            (root / "up.json").write_text(upstream, encoding="utf-8")
            # Promoted, demoted (entry removed) and left alone, all in one run.
            (root / "db.json").write_text(
                dumps(
                    {
                        "players": [
                            player("[U:1:1]", ["suspicious"], name="One"),
                            player("[U:1:3]", ["cheater", "racist"], name="Three"),
                            player("[U:1:9]", ["cheater"], name="Nine"),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (root / "snap.json").write_text(
                dumps({"players": [{"steamid": "[U:1:3]"}, {"steamid": "[U:1:9]"}]}),
                encoding="utf-8",
            )

            def run(output: Path) -> dict[str, str]:
                argv = [
                    "--database",
                    str(root / "db.json"),
                    "--snapshot",
                    str(root / "snap.json"),
                    "--source",
                    str(root / "up.json"),
                    "--report",
                    str(root / "report.md"),
                    "--demote",
                    "-q",
                ]
                with (
                    mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
                    contextlib.redirect_stdout(io.StringIO()),  # the report goes to stdout
                ):
                    self.assertEqual(main(argv), 0)
                return dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())

            first = run(root / "out1")
            self.assertEqual(first["changed"], "true")
            self.assertEqual(first["count"], "2")  # one promotion, one demotion
            database_after, snapshot_after = (root / "db.json").read_bytes(), (root / "snap.json").read_bytes()
            self.assertEqual(snapshot_after, upstream.encode("utf-8"))  # baseline advanced

            second = run(root / "out2")
            self.assertEqual(second["changed"], "false")
            self.assertEqual(second["count"], "0")
            self.assertEqual(second["modified"], "false")
            self.assertEqual(second["snapshot_changed"], "false")
            # Byte-for-byte untouched, and the report says so.
            self.assertEqual((root / "db.json").read_bytes(), database_after)
            self.assertEqual((root / "snap.json").read_bytes(), snapshot_after)
            self.assertIn("No changes", (root / "report.md").read_text(encoding="utf-8"))


class StepOutputTests(unittest.TestCase):
    """The `changed` output is what makes the workflow open a pull request.

    It was never asserted from a real run: flipping its `or` to `and` (no PR for
    a database-only change) or dropping the dry-run guard (a PR from a dry run)
    both left the suite green.
    """

    def run_sync(self, *, database, snapshot, source, dry_run=False):
        outputs = run_sync_and_read_outputs(database=database, snapshot=snapshot, source=source, dry_run=dry_run)
        self.assertIsNotNone(outputs)
        return outputs

    def test_a_database_only_change_still_opens_a_pull_request(self):
        database = dumps({"players": [player("[U:1:1]", ["suspicious"])]})
        upstream = dumps({"players": [player("[U:1:1]", ["cheater"])]})
        values = self.run_sync(database=database, snapshot=upstream, source=upstream)
        self.assertEqual(values["changed"], "true")
        self.assertEqual(values["modified"], "true")
        self.assertEqual(values["snapshot_changed"], "false")

    def test_a_snapshot_only_change_opens_a_pull_request(self):
        database = dumps({"players": [player("[U:1:1]", ["cheater"])]})
        upstream = dumps({"players": [player("[U:1:1]", ["cheater"])]})
        values = self.run_sync(database=database, snapshot=dumps({"players": []}), source=upstream)
        self.assertEqual(values["changed"], "true")
        self.assertEqual(values["modified"], "false")
        self.assertEqual(values["snapshot_changed"], "true")

    def test_a_dry_run_never_opens_a_pull_request(self):
        database = dumps({"players": [player("[U:1:1]", ["suspicious"])]})
        upstream = dumps({"players": [player("[U:1:1]", ["cheater"])]})
        values = self.run_sync(database=database, snapshot=upstream, source=upstream, dry_run=True)
        self.assertEqual(values["changed"], "false")
        self.assertEqual(values["modified"], "true")

    def test_a_run_with_nothing_to_do_opens_nothing(self):
        database = dumps({"players": [player("[U:1:1]", ["cheater"])]})
        upstream = dumps({"players": [player("[U:1:1]", ["cheater"])]})
        values = self.run_sync(database=database, snapshot=upstream, source=upstream)
        self.assertEqual(values["changed"], "false")


class GithubOutputTests(unittest.TestCase):
    """Step outputs stay one line each, so a value can never add an output."""

    def test_bools_are_lowercased_and_ints_are_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "output"
            with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(target)}):
                sync_module._write_github_outputs(changed=True, count=3, modified=False)
            self.assertEqual(target.read_text(encoding="utf-8"), "changed=true\ncount=3\nmodified=false\n")

    def test_a_multiline_value_cannot_inject_an_extra_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "output"
            with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(target)}):
                sync_module._write_github_outputs(changed=True, count="a\ninjected=true")
            self.assertEqual(target.read_text(encoding="utf-8"), "changed=true\ncount=a injected=true\n")

    def test_an_unwritable_output_path_is_a_named_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "missing-dir" / "output"
            with (
                mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(target)}),
                self.assertRaises(SyncError) as caught,
            ):
                sync_module._write_github_outputs(changed=True)
            self.assertIn("cannot write the GitHub step outputs", str(caught.exception))

    def test_without_the_environment_variable_nothing_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "output"
            environment = {key: value for key, value in os.environ.items() if key != "GITHUB_OUTPUT"}
            with mock.patch.dict(os.environ, environment, clear=True):
                sync_module._write_github_outputs(changed=True)
            self.assertFalse(target.exists())


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

    def test_an_unusable_step_output_file_changes_nothing(self):
        """An output path that cannot even be opened must fail before any write.

        The early preflight catches a directory deterministically; a separate
        test covers a path that opens but fails when the actual append flushes.
        """
        target = self.root / "outputs"
        target.mkdir()  # opening a directory for append fails, like a full disk
        before = self.database.read_bytes()
        code, _, stderr = self.run_cli("--source", str(self.source), env={"GITHUB_OUTPUT": str(target)})
        self.assertEqual(code, 2)
        self.assertIn("cannot write the GitHub step outputs", stderr)
        self.assertEqual(self.database.read_bytes(), before, "the database must not be touched")
        self.assertFalse((self.root / "snapshot.json").exists(), "nor the snapshot")

    @unittest.skipUnless(Path("/dev/full").exists(), "requires the Linux full-device test fixture")
    def test_a_github_output_write_failure_changes_no_files(self):
        """Opening GITHUB_OUTPUT can succeed even when its later write cannot.

        /dev/full accepts append-open (so the early preflight passes), then
        fails on flush with ENOSPC. The real output append must happen before
        the report, database, or snapshot is written.
        """
        before = self.database.read_bytes()
        report = self.root / "report.md"
        code, stdout, stderr = self.run_cli(
            "--source", str(self.source), "--report", str(report), env={"GITHUB_OUTPUT": "/dev/full"}
        )
        self.assertEqual(code, 2)
        self.assertIn("cannot write the GitHub step outputs", stderr)
        self.assertEqual(stdout, "")
        self.assertEqual(self.database.read_bytes(), before)
        self.assertFalse((self.root / "snapshot.json").exists())
        self.assertFalse(report.exists())

    def test_github_output_cannot_alias_a_run_file(self):
        """Appending step metadata to an input or output silently corrupts it."""
        report = self.root / "report.md"
        cases = (
            ("--database", self.database, ()),
            ("--snapshot", self.root / "snapshot.json", ()),
            ("--report", report, ("--report", str(report))),
            ("--source", self.source, ()),
        )
        for flag, target, extra in cases:
            with self.subTest(alias=flag):
                before_database = self.database.read_bytes()
                before_source = self.source.read_bytes()
                code, _, stderr = self.run_cli("--source", str(self.source), *extra, env={"GITHUB_OUTPUT": str(target)})
                self.assertEqual(code, 2)
                self.assertIn(f"GITHUB_OUTPUT must not be the same file as {flag}", stderr)
                self.assertEqual(self.database.read_bytes(), before_database)
                self.assertEqual(self.source.read_bytes(), before_source)
                self.assertFalse((self.root / "snapshot.json").exists())
                self.assertFalse(report.exists())

    def test_version_flag(self):
        with contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit) as exit_:
            build_parser().parse_args(["--version"])
        self.assertEqual(exit_.exception.code, 0)
        self.assertIn(sources.VERSION, out.getvalue())

    def test_the_version_is_plain_digits_and_dots(self):
        """VERSION is interpolated into a User-Agent header.

        urllib rejects a header value holding a newline, so a version typo
        would turn every fetch into an exception rather than a request.
        """
        self.assertRegex(sources.VERSION, r"^[0-9]+\.[0-9]+$")
        self.assertIn(f"/{sources.VERSION} (", sources.USER_AGENT)
        self.assertNotIn("\n", sources.USER_AGENT)

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

    def test_empty_paths_are_refused_with_a_clear_message(self):
        """An unset shell variable used to surface as "Is a directory: '.'"."""
        for flag in ("--database", "--snapshot", "--report"):
            with self.subTest(flag=flag):
                code, _, stderr = self.run_cli("--source", str(self.source), flag, "")
                self.assertEqual(code, 2)
                self.assertIn(f"{flag} must not be empty", stderr)

    def test_an_empty_source_is_refused(self):
        code, _, stderr = self.run_cli("--source", "")
        self.assertEqual(code, 2)
        self.assertIn("--source must not be empty", stderr)

    def test_a_hostile_path_cannot_inject_a_log_line_or_an_ansi_escape(self):
        code, _, stderr = self.run_cli("--source", str(self.source), "--database", "a\nb\x1b[31m.json")
        self.assertEqual(code, 2)
        self.assertNotIn("\x1b", stderr)  # no raw ESC
        self.assertEqual(stderr.strip().count("\n"), 0)  # exactly one line
        self.assertIn("a\\nb", stderr)  # shown as an escape, not dropped

    def test_a_hostile_snapshot_path_cannot_repaint_the_log(self):
        """The success lines print paths too: escape them like the error lines."""
        snapshot = self.root / "s\x1b[0m.json"
        code, _, stderr = self.run_cli("--source", str(self.source), "--snapshot", str(snapshot))
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", stderr)
        self.assertIn("\\x1b[0m", stderr)  # shown as an escape, not dropped
        self.assertTrue(snapshot.exists())

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
            "- Snapshot diff: **2 new SteamIDs added**, **2 SteamIDs removed** (2 → 2 entries; no net change)",
            stdout,
        )

    def test_report_lists_every_removed_steamid_with_its_permalink(self):
        """Every ID gone from the list since the snapshot appears in the
        ``| SteamID | Profile Link | SteamHistory |`` table -- including ones that were not
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
        # The file IS the pull request body: exactly one trailing newline, so
        # the published body does not end with a blank line.
        self.assertTrue(report.endswith("\n"))
        self.assertFalse(report.endswith("\n\n"))
        self.assertEqual(report_file.read_bytes(), report.encode("utf-8"))
        self.assertIn("**3 SteamIDs removed from the Vorobey hackerpolice list since the previous snapshot:**", report)
        self.assertIn("| SteamID | Profile Link | SteamHistory |", report)
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

    def test_the_removed_flag_is_rejected_by_the_parser(self):
        """A future workflow could not re-enable proof writing by accident."""
        with (
            contextlib.redirect_stderr(io.StringIO()) as err,
            self.assertRaises(SystemExit) as caught,
        ):
            main(
                [
                    "--database",
                    str(self.database),
                    "--snapshot",
                    str(self.root / "snapshot.json"),
                    "--source",
                    str(self.source),
                    "--include-proof",
                ]
            )
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("unrecognized arguments: --include-proof", err.getvalue())

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

    def test_undecodable_source_is_refused_without_a_traceback(self):
        """A source with an undecodable byte is a clean refusal, not a crash."""
        code, _, stderr = self.run_cli("--source", "https://host.invalid/?token=\udcff")
        self.assertEqual(code, 2)
        self.assertIn("token=REDACTED", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_hand_appended_entry_is_resorted_and_reported(self):
        """A file out of SteamID order is normalised without any tag changing.

        The old behaviour said "No database changes" while rewriting the file,
        so a reviewer saw a diff with a body denying it.
        """
        self.database.write_text(
            dumps(
                {
                    "$schema": "x",
                    "file_info": {},
                    "players": [
                        player("[U:1:900]", ["cheater"]),  # appended by hand, out of order
                        player("[U:1:100]", ["cheater"]),
                    ],
                }
            ),
            encoding="utf-8",
        )
        code, stdout, stderr = self.run_cli("--source", str(self.source), "--demote")
        self.assertEqual(code, 0)

        self.assertEqual(
            [entry["steamid"] for entry in json.loads(self.database.read_text(encoding="utf-8"))["players"]],
            ["[U:1:100]", "[U:1:900]"],
        )
        self.assertIn("**No player changes** (the database file was normalised", stdout)
        self.assertIn("no tag changes: the file was normalised", stderr)
        self.assertNotIn("No changes.", stderr)

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
        self.assertIn("No database changes: nothing to update.", second[2])
        self.assertNotIn("Updated snapshot", second[2])

    def test_the_no_change_log_line_names_the_database(self):
        """A snapshot-only run writes a file and opens a PR.

        A bare "No changes: nothing to update." then contradicts both the
        report body ("No database changes (snapshot refresh only)") and the
        ``Updated snapshot …`` line that follows it. The upstream entry here
        is not in the database, so nothing is promoted and only the snapshot
        changes.
        """
        source = self.root / "unrelated-upstream.json"
        source.write_text(dumps({"players": [hackerpolice_entry("[U:1:12345]")]}), encoding="utf-8")
        snapshot = self.write_snapshot_fixture()
        code, stdout, stderr = self.run_cli("--source", str(source), "--snapshot", str(snapshot))
        self.assertEqual(code, 0)
        self.assertIn("**No database changes** (snapshot refresh only).", stdout)
        self.assertIn("No database changes: nothing to update.", stderr)
        self.assertIn(f"Updated snapshot {snapshot}", stderr)
        self.assertNotIn("No changes: nothing to update.", stderr)

    def test_quiet_prints_only_the_report(self):
        code, stdout, stderr = self.run_cli("--source", str(self.source), "--dry-run", "-q")
        self.assertEqual(code, 0)
        self.assertIn("## Vorobey hackerpolice sync", stdout)
        self.assertEqual(stderr.strip(), "")

    def test_verbose_reports_each_source_it_tries(self):
        """--verbose must actually add something: it used to set DEBUG with no
        DEBUG record anywhere, so it printed exactly what the default run did."""
        code, _, verbose = self.run_cli("--source", str(self.source), "--dry-run", "-v")
        self.assertEqual(code, 0)
        self.assertIn("Trying source", verbose)
        self.assertIn("from disk", verbose)
        code, _, plain = self.run_cli("--source", str(self.source), "--dry-run")
        self.assertEqual(code, 0)
        self.assertNotIn("Trying source", plain)

    def test_verbose_logs_the_index_and_the_diff(self):
        code, _, stderr = self.run_cli("--source", str(self.source), "--dry-run", "-v")
        self.assertEqual(code, 0)
        self.assertIn("Indexed 2 Vorobey hackerpolice SteamIDs", stderr)

    def test_snapshot_must_not_be_the_database(self):
        code, _, stderr = self.run_cli("--snapshot", str(self.database))
        self.assertEqual(code, 2)
        self.assertIn("--snapshot and --database must be different files", stderr)

    def test_load_index_still_refuses_an_empty_index(self):
        """Backstop: the chain normally filters these out, the guard stays."""
        with (
            mock.patch.object(sync_module, "load_first_available_raw", return_value=({"players": []}, "src", b"{}")),
            self.assertRaises(SyncError) as caught,
        ):
            sync_module._load_index(SimpleNamespace(source=["x"]))
        self.assertIn("no usable SteamIDs", str(caught.exception))

    def test_a_cancelled_write_leaves_no_temp_file(self):
        """Ctrl-C mid-write must not leave junk in the repository."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "playerlist.json"
            target.write_text("original\n", encoding="utf-8")
            with mock.patch("os.fsync", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                sync_module._atomic_write_bytes(target, b"new\n")
            self.assertEqual(target.read_text(encoding="utf-8"), "original\n")
            self.assertEqual(os.listdir(tmp), ["playerlist.json"])

    def test_a_failed_write_leaves_no_temp_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "playerlist.json"
            target.write_text("original\n", encoding="utf-8")
            with mock.patch("os.fsync", side_effect=OSError("disk full")), self.assertRaises(OSError):
                sync_module._atomic_write_bytes(target, b"new\n")
            self.assertEqual(target.read_text(encoding="utf-8"), "original\n")
            self.assertEqual(os.listdir(tmp), ["playerlist.json"])

    def test_plain_http_source_is_a_clean_error(self):
        code, _, stderr = self.run_cli("--source", "http://example.invalid/list.json")
        self.assertEqual(code, 2)
        self.assertIn("refusing to fetch a non-HTTPS URL", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_an_uppercase_http_source_is_refused_as_non_https_not_as_a_missing_path(self):
        """It used to be mistaken for a local path, giving "cannot read"."""
        code, _, stderr = self.run_cli("--source", "HTTP://example.invalid/list.json")
        self.assertEqual(code, 2)
        self.assertIn("refusing to fetch a non-HTTPS URL", stderr)
        self.assertNotIn("cannot read", stderr)

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

    def test_source_must_not_be_the_snapshot(self):
        """Aliasing the baseline with the source silently disables the bot.

        The run would compare the snapshot with itself: "0 added, 0 removed"
        every time, so no removal can ever be proven and promotions come from
        the stale baseline instead of the live list -- while the run exits 0
        and looks completely healthy.
        """
        snapshot = self.write_snapshot_fixture(hackerpolice_entry("[U:1:300]"))
        before = snapshot.read_bytes()
        code, _, stderr = self.run_cli("--source", str(snapshot), "--snapshot", str(snapshot))
        self.assertEqual(code, 2)
        self.assertIn("--source must not be the same file as --snapshot", stderr)
        # Nothing was written: the baseline is exactly as it was.
        self.assertEqual(snapshot.read_bytes(), before)

    def test_a_broken_snapshot_is_not_reported_as_a_broken_upstream_list(self):
        """The index builder serves two documents: the list AND the snapshot.

        A snapshot with no 'players' array used to be reported as "the Vorobey
        hackerpolice list has no 'players' array" -- pointing the operator at a
        file that was perfectly fine while the broken one stayed unnamed.
        """
        broken = self.root / "snapshot.json"
        broken.write_text('{"$schema": "x"}', encoding="utf-8")  # well-formed JSON, wrong shape
        # --source keeps this off the network: without it the run fetches the
        # real upstream list first (slow, and unreachable in an offline build).
        code, _, stderr = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 2)
        self.assertIn(f"the previous snapshot {broken}", stderr)
        self.assertNotIn("the Vorobey hackerpolice list has no", stderr)

    def test_a_snapshot_in_a_missing_directory_is_refused_by_name(self):
        """A writer must not invent a directory.

        It used to ``mkdir -p`` for any output, so a typo'd ``--snapshot``
        silently produced a FRESH baseline in a brand-new tree. That looks
        harmless but is not: a fresh baseline proves no removal (previous
        minus current is empty), so ``--demote`` would quietly do nothing
        forever -- the same silent stall the --source==--snapshot guard
        prevents, reached from the other side.
        """
        missing = self.root / "typo" / "snapshot.json"
        code, _, stderr = self.run_cli("--snapshot", str(missing))
        self.assertEqual(code, 2)
        self.assertIn(f"--snapshot directory does not exist: {missing.parent}", stderr)
        self.assertFalse(missing.parent.exists())  # and it was NOT created

    def test_a_report_in_a_missing_directory_is_refused_by_name(self):
        missing = self.root / "typo" / "report.md"
        code, _, stderr = self.run_cli("--report", str(missing))
        self.assertEqual(code, 2)
        self.assertIn(f"--report directory does not exist: {missing.parent}", stderr)
        self.assertFalse(missing.parent.exists())
        self.assertEqual(
            [p.name for p in self.root.iterdir() if ".tmp" in p.name], []
        )  # refused before anything was written

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
class UnpublishableJsonTests(unittest.TestCase):
    """Files this tool must refuse rather than rewrite into something broken.

    Python's json accepts NaN/Infinity (not JSON) and silently keeps the last
    of two duplicate keys; writing either back would publish a database that
    strict parsers reject, or quietly discard half of a hand-edited entry.
    """

    UPSTREAM = '{"players":[{"steamid":"[U:1:100]","attributes":["cheater"]}]}'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.database = dumps({"players": [player("[U:1:100]", ["suspicious"])]})

    def write(self, name, body):
        (self.root / name).write_text(body, encoding="utf-8")

    def read(self, name):
        return (self.root / name).read_text(encoding="utf-8")

    def run_cli(self):
        """Run the real entry point with the temporary directory as cwd."""
        previous = os.getcwd()
        os.chdir(self.root)
        try:
            return sync_module.main(["--database", "db.json", "--source", "up.json", "--snapshot", "snap.json", "-q"])
        finally:
            os.chdir(previous)

    def assert_refused(self, *, database, upstream, snapshot=None):
        self.write("db.json", database)
        self.write("up.json", upstream)
        if snapshot is not None:
            self.write("snap.json", snapshot)
        self.assertEqual(self.run_cli(), 2)
        self.assertEqual(self.read("db.json"), database)  # not rewritten
        if snapshot is None:
            self.assertFalse((self.root / "snap.json").exists())

    def test_an_out_of_range_number_in_the_database_is_refused(self):
        self.assert_refused(
            database='{"players":[{"steamid":"[U:1:100]","attributes":["suspicious"],"last_seen":{"time":1e999}}]}',
            upstream=self.UPSTREAM,
        )

    def test_nan_in_the_database_is_refused(self):
        self.assert_refused(
            database='{"players":[{"steamid":"[U:1:100]","attributes":["suspicious"],"last_seen":{"time":NaN}}]}',
            upstream=self.UPSTREAM,
        )

    def test_duplicate_players_key_in_the_database_is_refused(self):
        """Two 'players' keys would silently empty the database."""
        self.assert_refused(
            database='{"players":[{"steamid":"[U:1:100]","attributes":["suspicious"]}],"players":[]}',
            upstream=self.UPSTREAM,
        )

    def test_infinity_in_the_upstream_list_is_refused(self):
        self.assert_refused(
            database=self.database,
            upstream='{"players":[{"steamid":"[U:1:100]","attributes":["cheater"],"x":Infinity}]}',
        )

    def test_duplicate_key_in_the_upstream_list_is_refused(self):
        self.assert_refused(
            database=self.database,
            upstream='{"players":[{"steamid":"[U:1:100]"}],"players":[{"steamid":"[U:1:200]"}]}',
        )

    def test_duplicate_key_in_the_snapshot_is_refused(self):
        self.assert_refused(
            database=self.database,
            upstream=self.UPSTREAM,
            snapshot='{"players":[],"players":[]}',
        )

    def test_the_refusal_names_the_problem(self):
        self.write("db.json", '{"players":[],"players":[]}')
        self.write("up.json", self.UPSTREAM)
        with mock.patch.object(sync_module.LOGGER, "error") as logged:
            self.run_cli()
        message = " ".join(str(call.args) for call in logged.call_args_list)
        self.assertIn("duplicate key", message)


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
        subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True, text=True, encoding="utf-8")

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
            ["git", "status", "--porcelain"],
            cwd=self.root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        ).stdout
        self.assertEqual(status, "")


# --------------------------------------------------------------------------- #
# Repository data integrity
# --------------------------------------------------------------------------- #
class RepositoryDataTests(unittest.TestCase):
    """The data files this repository ships must be exactly what the bot expects."""

    ROOT = Path(__file__).resolve().parents[1]

    def test_every_auto_proof_in_the_shipped_database_still_qualifies(self):
        """Tightening the prefix rule must never drop a real machine record.

        The shipped list carries hundreds of TF2BD auto lines; if any of them
        stopped qualifying, a demotion would silently delete evidence that
        justifies a racist tag.
        """
        database, _ = load(self.ROOT / "playerlist.garou3299.json")
        auto = [
            line
            for entry in database["players"]
            for line in (entry.get("proof") or [])
            if isinstance(line, str) and line.strip().casefold().startswith(policy.RACIST_PROOF_PREFIX.casefold())
        ]
        self.assertGreater(len(auto), 100, "the fixture this guards has disappeared")
        self.assertEqual([line for line in auto if not is_racist_proof(line)], [])

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
            "Close a stale bot pull request",
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

    def test_absurdly_long_steamid_is_refused_without_parsing_it(self):
        """Thousands of digits would trip Python's int-parsing limit and crash.

        The ASCII + 10-digit guard rejects them before int() is ever called, so
        a corrupted or hostile file cannot take the run down.
        """
        self.assertIsNone(normalize_steamid("[U:1:" + "9" * 5_000 + "]"))
        self.assertIsNone(normalize_steamid("9" * 5_000))
        self.assertIsNone(normalize_steamid(int("9" * 400)))

    def test_steam_history_url(self):
        # Same SteamID64 as the Steam Community permalink, on SteamHistory's /id/ page.
        self.assertEqual(steam_history_url("[U:1:269327660]"), "https://steamhistory.net/id/76561198229593388")
        self.assertEqual(steam_history_url("STEAM_0:1:865008"), "https://steamhistory.net/id/76561197961995745")
        self.assertEqual(steam_history_url(76561198229593388), "https://steamhistory.net/id/76561198229593388")
        self.assertIsNone(steam_history_url("nope"))
        self.assertIsNone(steam_history_url(None))


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

    def test_the_canonical_attribute_order_is_pinned(self):
        """The order is part of the byte-identical-file guarantee.

        A single-element assertion cannot see an order, and nothing compared
        suspicious with racist: typo-ing either name in ATTRIBUTE_ORDER left
        the suite green while quietly reordering every future write.
        """
        self.assertEqual(ATTRIBUTE_ORDER, ("cheater", "suspicious", "exploiter", "racist"))
        self.assertEqual(order_attributes(list(reversed(ATTRIBUTE_ORDER))), list(ATTRIBUTE_ORDER))
        self.assertEqual(order_attributes(["racist", "suspicious"]), ["suspicious", "racist"])
        self.assertEqual(order_attributes(["exploiter", "suspicious"]), ["suspicious", "exploiter"])
        self.assertEqual(
            order_attributes(["zzz", "racist", "aaa", "suspicious"]),
            ["suspicious", "racist", "aaa", "zzz"],
        )

    def test_every_known_attribute_is_known_to_the_validator(self):
        self.assertEqual(KNOWN_ATTRIBUTES, frozenset({"cheater", "suspicious", "exploiter", "racist"}))
        result = validate(
            {"players": [{"steamid": "[U:1:1]", "attributes": ["cheater", "suspicious", "exploiter", "racist"]}]}
        )
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])


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

    def test_keys_are_written_in_sorted_order(self):
        """The committed file is key-sorted; an unsorted dump would rewrite it.

        Nothing else pins this down: dict equality ignores order, so a dump that
        kept insertion order would still round-trip and still parse.
        """
        rendered = dumps({"z": 1, "players": [], "a": {"y": 2, "b": 3}})
        self.assertLess(rendered.index('"a"'), rendered.index('"players"'))
        self.assertLess(rendered.index('"players"'), rendered.index('"z"'))
        self.assertLess(rendered.index('"b"'), rendered.index('"y"'))

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


class StrictJsonTests(unittest.TestCase):
    """What the standard library accepts but standard JSON does not."""

    def test_nan_and_infinity_are_refused(self):
        for body in ('{"t": NaN}', '{"t": Infinity}', '{"t": -Infinity}', '{"t": [1, NaN]}'):
            with self.assertRaises(ValueError) as caught:
                strict_json_loads(body)
            self.assertIn("not valid JSON", str(caught.exception))

    def test_a_number_that_overflows_into_infinity_is_refused(self):
        """``1e999`` is valid JSON syntax but becomes ``inf``.

        ``inf`` cannot be written back out (``dumps`` refuses it, as TF2BD's
        parser would), so a file holding one could never be round-tripped:
        it was refused only after validation passed, when the writer raised an
        uncaught ValueError -- a traceback instead of a named refusal.
        """
        for body in ('{"t": 1e999}', '{"t": -1e999}', '{"players": [], "file_info": {"y": 1e400}}'):
            with self.assertRaises(ValueError) as caught:
                strict_json_loads(body)
            self.assertIn("out of range for a JSON number", str(caught.exception))
        self.assertEqual(strict_json_loads('{"t": 1.5}'), {"t": 1.5})
        self.assertEqual(strict_json_loads('{"t": 1e-999}'), {"t": 0.0})  # underflow is finite

    def test_duplicate_keys_are_refused(self):
        with self.assertRaises(ValueError) as caught:
            strict_json_loads('{"players": [1], "players": []}')
        self.assertIn("duplicate key", str(caught.exception))
        with self.assertRaises(ValueError):
            strict_json_loads('{"a": {"attributes": ["x"], "attributes": ["y"]}}')

    def test_a_huge_duplicate_key_cannot_flood_the_log(self):
        key = "k" * 3_000_000
        with self.assertRaises(ValueError) as caught:
            strict_json_loads('{"' + key + '": 1, "' + key + '": 2}')
        self.assertIn("duplicate key", str(caught.exception))
        self.assertLessEqual(len(str(caught.exception)), 200)

    def test_the_same_input_as_the_standard_library_still_parses(self):
        for body in ('{"players": []}', '{"a": [1, 2.5, true, false, null]}', '{"s": "ы\\u00e9"}', "[]", "3"):
            self.assertEqual(strict_json_loads(body), json.loads(body))
        # Bytes, a BOM (already decoded away) and nesting depth behave as before.
        self.assertEqual(strict_json_loads(b'{"players": []}'), {"players": []})

    def test_serialising_a_non_finite_number_is_refused(self):
        """Belt and braces: even a future code path cannot write NaN to disk."""
        with self.assertRaises(ValueError):
            dumps({"players": [{"time": float("nan")}]})


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

    def test_a_malformed_name_never_prints_python_syntax(self):
        """A dict/list/float name is malformed: UNKNOWN, not "{'a': 1}"."""
        for value in ({"a": 1}, ["x"], 1.5, True, None):
            self.assertEqual(player_name({"last_seen": {"player_name": value}}), "", value)
        self.assertEqual(player_name({"last_seen": {"player_name": 12345}}), "12345")
        result = validate({"players": ["not a dict", player("[U:1:1]", ["cheater"])]})
        self.assertIn("players[0] is not an object", result.errors)

    def test_steam_notation_with_too_many_digits_is_unusable(self):
        self.assertIsNone(normalize_steamid("STEAM_0:1:12345678901"))

    def test_a_steamid_with_thousands_of_digits_is_unusable_without_crashing(self):
        """Python refuses to int() 5,000 digits; the length guard answers first."""
        for hostile in ("[U:1:" + "9" * 5000 + "]", "STEAM_0:1:" + "9" * 5000, "9" * 5000):
            self.assertIsNone(normalize_steamid(hostile))
        result = validate({"players": [{"steamid": "[U:1:" + "9" * 5000 + "]", "attributes": ["cheater"]}]})
        self.assertTrue(result.errors)


def run_sync_and_read_outputs(*, database, snapshot, source, dry_run=False) -> dict[str, str]:
    """Run the real CLI on three loose files and return its GitHub step outputs."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "db.json").write_text(database, encoding="utf-8")
        (root / "snap.json").write_text(snapshot, encoding="utf-8")
        (root / "up.json").write_text(source, encoding="utf-8")
        output = root / "github-output"
        argv = [
            "--database",
            str(root / "db.json"),
            "--snapshot",
            str(root / "snap.json"),
            "--source",
            str(root / "up.json"),
            "--report",
            str(root / "r.md"),
            "-q",
        ]
        if dry_run:
            argv.append("--dry-run")
        with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), contextlib.redirect_stdout(io.StringIO()):
            code = main(argv)
        if code != 0:
            raise AssertionError(f"the sync refused: exit {code}")
        return dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())


class DocumentedLimitsTests(unittest.TestCase):
    """The caps are contract, not tuning knobs -- so pin the numbers.

    Mutation testing found every one of these replaceable with a neighbouring
    value while the suite stayed green: ``CapBoundaryTests`` derives its sizes
    FROM the constant, so it proves the comparison is exact but cannot notice
    the constant itself moving. A one-digit typo in ``MAX_REPORT_BYTES`` would
    therefore ship a bot that truncates every busy report, and a typo in
    ``MAX_SOURCE_BYTES`` would ship one that refuses a legitimate download.
    Each number below is quoted from README.md so the two cannot drift.
    """

    def test_the_documented_report_limits(self):
        # README: "a table stops at 150 rows (100 for the removed-SteamID list)
        # and the whole body stops at 60,000 bytes".
        self.assertEqual(report_module.MAX_CHANGE_TABLE_ROWS, 150)
        self.assertEqual(report_module.MAX_REMOVED_TABLE_ROWS, 100)
        self.assertEqual(report_module.MAX_REPORT_BYTES, 60_000)

    def test_the_display_caps(self):
        self.assertEqual(report_module.MAX_NAME_CHARS, 80)
        self.assertEqual(report_module.MAX_ATTRIBUTE_CHARS, 40)
        self.assertEqual(report_module.MAX_ATTRIBUTE_CELLS, 8)
        self.assertEqual(report_module.MAX_EVIDENCE_LINKS, 10)
        self.assertEqual(report_module.MAX_CLOSING_STEAMIDS, 150)
        self.assertEqual(playerlist_module.MAX_SHOWN_VALUE_CHARS, 120)
        self.assertEqual(playerlist_module.MAX_SHOWN_PATH_CHARS, 200)
        self.assertEqual(sources.MAX_URL_DISPLAY_CHARS, 2048)

    def test_the_read_and_fetch_limits(self):
        # README: "64 MiB per download, 30 s, 3 attempts, then the next fallback.
        # The same 64 MiB cap applies to the database and snapshot files".
        self.assertEqual(playerlist_module.MAX_FILE_BYTES, 64 * 1024 * 1024)
        self.assertEqual(sources.MAX_SOURCE_BYTES, 64 * 1024 * 1024)
        self.assertEqual(sources.FETCH_TIMEOUT_SECONDS, 30)
        self.assertEqual(sources.FETCH_ATTEMPTS, 3)
        self.assertEqual(sources.RETRY_BACKOFF_SECONDS, 2)

    def test_the_documented_guard_and_account_bounds(self):
        # README: "more than 50 IDs *and* more than 20 % gone at once".
        self.assertEqual(sync_module.MASS_DEMOTION_MIN_IDS, 50)
        self.assertEqual(sync_module.MASS_DEMOTION_MAX_FRACTION, 0.2)
        # TF2BD account ids are 32-bit and never 0.
        self.assertEqual(playerlist_module.MAX_ACCOUNT_ID, 2**32)


class InterruptTests(unittest.TestCase):
    """Ctrl-C used to leave a KeyboardInterrupt traceback on stderr."""

    def test_an_interrupt_is_reported_in_one_line_with_exit_130(self):
        stderr = io.StringIO()
        with mock.patch.object(sync_module, "run", side_effect=KeyboardInterrupt), contextlib.redirect_stderr(stderr):
            code = sync_module.main(["--database", "unused.json"])
        self.assertEqual(code, 130)
        self.assertEqual(stderr.getvalue().strip(), "interrupted.")
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_the_exit_code_is_the_shell_convention(self):
        """128 + SIGINT(2) -- what a shell reports for a killed foreground job."""
        self.assertEqual(130, 128 + 2)


class ReadmeCliTests(unittest.TestCase):
    """The README promises they document the tool; make that mechanical.

    Seven of the twelve flags -- including ``--database``, ``--source`` and
    ``--snapshot``, the three that decide WHAT the run reads and writes --
    were reachable only through ``--help``. A flag nobody documented is a
    flag only its author can use, so both directions are pinned here.
    """

    @staticmethod
    def _readme() -> str:
        path = Path(__file__).resolve().parents[1] / "README.md"
        return path.read_text(encoding="utf-8")

    def test_every_flag_is_documented(self):
        readme = self._readme()
        flags = {
            flag
            for action in sync_module.build_parser()._actions
            for flag in action.option_strings
            if flag.startswith("--")
        }
        self.assertEqual(sorted(flag for flag in flags if flag not in readme), [])

    def test_the_readme_invents_no_flags(self):
        """The other direction: a documented flag that does not exist."""
        readme = self._readme()
        known = {flag for action in sync_module.build_parser()._actions for flag in action.option_strings}
        mentioned = set(re.findall(r"`(--[a-z][a-z0-9-]+)", readme))
        self.assertEqual(sorted(mentioned - known), [])


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

    def test_paths_are_exact_at_the_limit(self):
        at_limit = "/tmp/" + "d" * (MAX_SHOWN_PATH_CHARS - 5)
        self.assertEqual(display_path(at_limit), at_limit)
        self.assertTrue(display_path(at_limit + "d").endswith("…"))

    def test_a_printable_non_ascii_path_stays_readable(self):
        """Only control characters are escaped; ü is a character, not junk."""
        self.assertEqual(display_path("/tmp/über.json"), "/tmp/über.json")
        self.assertEqual(display_path("a\u2028b"), "a\\u2028b")

    def test_shorten_is_exact_at_the_limit(self):
        self.assertEqual(_shorten("abc", 3), "abc")
        self.assertEqual(_shorten("abcd", 3), "abc…")

    def test_evidence_links_are_exact_at_the_limit(self):
        prefix = "https://example.invalid/"
        link = prefix + "x" * (MAX_EVIDENCE_LINK_CHARS - len(prefix))
        self.assertEqual(len(link), MAX_EVIDENCE_LINK_CHARS)
        self.assertIn("](", report_module._evidence_cell([link]))  # a real link
        longer = link + "x"
        self.assertNotIn("](", report_module._evidence_cell([longer]))  # plain text, not a dead link

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
        self.assertEqual(full.count("| `[U:1:"), 150)  # nothing was dropped
        budget = len(full.encode("utf-8"))
        with mock.patch.object(report_module, "MAX_REPORT_BYTES", budget):
            self.assertEqual(render_report(info), full)  # fits exactly: no shrink, no cut


class DisplayPathTests(unittest.TestCase):
    """Paths are operator input too: one line, printable, bounded."""

    def test_control_characters_are_escaped_rather_than_dropped(self):
        self.assertEqual(display_path("a\nb.json"), "a\\nb.json")
        self.assertEqual(display_path("a\x1b[31m.json"), "a\\x1b[31m.json")
        self.assertEqual(display_path("a\r\tb"), "a\\r\\tb")
        self.assertEqual(display_path("/tmp/plain.json"), "/tmp/plain.json")

    def test_line_separators_are_escaped(self):
        """U+2028/U+2029 break a line in a renderer even though they print."""
        self.assertEqual(display_path("a\u2028b"), "a\\u2028b")
        self.assertEqual(display_path("a\u2029b"), "a\\u2029b")

    def test_a_lone_surrogate_is_still_printable(self):
        shown = display_path("a\udcffb")
        self.assertNotIn("\udcff", shown)
        shown.encode("utf-8")  # must not raise

    def test_a_very_long_path_is_clipped(self):
        shown = display_path("/tmp/" + "d" * 5_000)
        self.assertEqual(len(shown), MAX_SHOWN_PATH_CHARS + 1)
        self.assertTrue(shown.endswith("…"))

    def test_a_path_that_is_not_a_string_still_works(self):
        self.assertEqual(display_path(Path("/tmp/x.json")), "/tmp/x.json")


class ValidateTests(unittest.TestCase):
    def test_non_ascii_steamid_is_a_validation_error_not_a_crash(self):
        result = validate({"players": [{"steamid": "²", "attributes": ["cheater"]}]})
        self.assertTrue(result.errors)
        self.assertIn("unusable steamid", result.errors[0])

    def test_a_hostile_value_cannot_inject_a_log_line_or_an_ansi_escape(self):
        """These messages are printed to a terminal and to the CI job log."""
        result = validate(
            {
                "players": [
                    {"steamid": "x\n### fake heading\x1b[32m", "attributes": []},
                    {"steamid": "[U:1:2]", "attributes": ["scammer\nINFO: all good\x1b[0m"]},
                ]
            }
        )
        messages = result.errors + result.warnings
        self.assertTrue(messages)
        for message in messages:
            self.assertNotIn("\n", message)
            self.assertNotIn("\x1b", message)

    def test_no_malformed_entry_can_flood_the_log(self):
        """One bad entry used to print a single 3,000,038-character log line.

        Every combination matters: one entry produces several messages, and
        each of them used to carry the raw value (fixing only the first left
        the second just as long).
        """
        big = "x" * 3_000_000
        seen = 0
        for steamid, attributes, proof in itertools.product(
            ("[U:1:5]", big), (["cheater"], [], ["a" * 3_000_000]), (None, ["ok"], big)
        ):
            entry = {"steamid": steamid, "attributes": attributes}
            if proof is not None:
                entry["proof"] = proof
            result = validate({"players": [entry]})
            for message in result.errors + result.warnings:
                seen += 1
                self.assertLessEqual(len(message), 400, message[:80])
                self.assertNotIn("\n", message)
                self.assertNotIn("\x1b", message)
        self.assertGreaterEqual(seen, 18)

    def test_a_usable_steamid_is_still_reported_in_canonical_form(self):
        """Escaping the junk must not make the normal message noisier."""
        result = validate({"players": [{"steamid": "STEAM_0:0:1", "attributes": []}]})
        self.assertEqual(result.errors, ["players[0] ([U:1:2]) has no attributes"])

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

    def test_a_players_value_that_is_not_an_array_is_one_error_not_a_crash(self):
        """Deleting the early return makes this a TypeError (or a cascade)."""
        for players in (42, "players", {"steamid": "[U:1:1]"}, None, True):
            with self.subTest(players=players):
                result = validate({"players": players})
                self.assertEqual(result.errors, ["'players' is not an array"])

    def test_a_malformed_attributes_value_is_one_error_not_a_cascade(self):
        """A string is iterable and a list of characters "has duplicates".

        Falling through the guard would report a second, nonsensical problem
        for the same field, so pin the count -- one problem per field.
        """
        for attributes in ("cheater", [], None, 7, {"cheater": True}):
            with self.subTest(attributes=attributes):
                result = validate({"players": [{"steamid": "[U:1:1]", "attributes": attributes}]})
                self.assertEqual(len(result.errors), 1, result.errors)
                self.assertIn("has no attributes", result.errors[0])

    def test_unknown_attribute_is_only_a_warning(self):
        result = validate({"players": [{"steamid": "[U:1:1]", "attributes": ["scammer"]}]})
        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.warnings), 1)


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
        self.snapshot.parent.mkdir(parents=True, exist_ok=True)  # the CLI will not invent it

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
        self.assertNotIn("proof", entry)  # nothing was invented

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
        self.write(self.upstream, [hackerpolice_entry("[U:1:399]")])  # 300 is gone from upstream

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
        self.write(self.upstream, [hackerpolice_entry("[U:1:499]")])  # 400 is gone from upstream

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

        self.assertEqual(self.entry(after, "[U:1:500]")["attributes"], ["cheater"])  # the run did something
        self.assertEqual(self.snapshot.read_bytes(), raw)  # ... and the copy is exact

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

        self.assertEqual(after["players"][0]["attributes"], ["cheater"])  # no database change
        self.assertEqual(self.snapshot.read_bytes(), second)  # baseline still advanced


if __name__ == "__main__":
    unittest.main(verbosity=2)
