#!/usr/bin/env python3
"""Tests for the Vorobey hackerpolice sync tool."""

from __future__ import annotations

import base64
import http.client
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message
from pathlib import Path
from unittest import mock

from _support import (
    SOURCE_API_URL,
    SOURCE_BODY,
    SOURCE_URL,
    _FakeResponse,
    hackerpolice_entry,
    index_of,
)

import playerlist as playerlist_module
import report as report_module
import sources
import sync_vorobey_hackerpolice as sync_module
from playerlist import (
    PlayerListError,
    dumps,
    load,
)
from policy import Change
from report import (
    RunInfo,
    render_report,
)
from sources import (
    HackerpoliceIndex,
    SyncError,
    load_first_available_raw,
    load_snapshot,
)


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


class SourceFetchTests(unittest.TestCase):
    URL = SOURCE_URL
    API_URL = SOURCE_API_URL
    BODY = SOURCE_BODY

    def fetch(self, side_effect):
        with (
            mock.patch("sources._OPENER.open", side_effect=side_effect) as urlopen,
            mock.patch("sources.time.sleep"),
        ):
            result = load_first_available_raw([self.URL])
        return result, urlopen.call_count

    def test_fetch_returns_body_bytes_verbatim(self):
        (document, source, raw), _ = self.fetch([_FakeResponse(self.BODY)])
        self.assertEqual(raw, self.BODY)  # Preserve the fixture's BOM and exact source bytes in the snapshot.
        self.assertEqual(source, self.URL)
        self.assertIn("[U:1:100]", [p["steamid"] for p in document["players"]])

    def test_github_contents_envelope_is_unwrapped_to_the_file_bytes(self):
        inner = b'{"players": [{"steamid": "[U:1:100]", "attributes": ["cheater"]}]}'
        envelope = json.dumps({"encoding": "base64", "content": base64.b64encode(inner).decode("ascii")}).encode(
            "utf-8"
        )
        (document, _, raw), _ = self.fetch([_FakeResponse(envelope)])
        self.assertEqual(raw, inner)  # Snapshot the decoded file bytes, not the GitHub API envelope.
        self.assertEqual(len(document["players"]), 1)

    def test_malformed_github_contents_base64_is_rejected_and_uses_fallback(self):
        inner = b'{"players": [{"steamid": "[U:1:200]", "attributes": ["cheater"]}]}'
        encoded = base64.b64encode(inner).decode("ascii")
        for malformed in (f"!{encoded}", f"{encoded}!!!", f"{encoded[:-1]}!"):
            with self.subTest(content=malformed):
                envelope = json.dumps(
                    {
                        "encoding": "base64",
                        "content": malformed,
                        "download_url": "https://example.invalid/raw.json",
                    }
                ).encode("utf-8")
                (document, _, raw), calls = self.fetch([_FakeResponse(envelope), _FakeResponse(self.BODY)])
                self.assertEqual(raw, self.BODY)
                self.assertEqual(document["players"][0]["steamid"], "[U:1:100]")
                self.assertEqual(calls, 2)

    def test_non_https_download_url_is_never_followed(self):
        # Treat download_url as untrusted response data; reject plaintext and local
        # targets before opening a follow-up request.
        for bad_url in ("http://example.invalid/raw.json", "/etc/passwd"):
            envelope = json.dumps({"encoding": "none", "content": "", "download_url": bad_url}).encode("utf-8")
            with (
                mock.patch("sources._OPENER.open", side_effect=[_FakeResponse(envelope)]) as urlopen,
                mock.patch("sources.time.sleep"),
                self.assertRaises(SyncError),
            ):
                load_first_available_raw([self.URL])
            self.assertEqual(urlopen.call_count, 1)  # Only the API envelope was fetched.

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
            self.assertEqual(urlopen.call_count, 1, value)  # No follow-up URL was fetched.

    def test_large_file_envelope_falls_back_to_download_url(self):
        envelope = json.dumps(
            {"encoding": "none", "content": "", "download_url": "https://example.invalid/raw.json"}
        ).encode("utf-8")
        (document, _, raw), calls = self.fetch([_FakeResponse(envelope), _FakeResponse(self.BODY)])
        self.assertEqual(raw, self.BODY)
        self.assertEqual(len(document["players"]), 1)
        self.assertEqual(calls, 2)

    def test_unusable_inline_playerlist_falls_back_to_download_url(self):
        for inner in (b'{"players": []}', b'{"players": [{"steamid": "not-a-steamid"}]}'):
            with self.subTest(inner=inner):
                envelope = json.dumps(
                    {
                        "encoding": "base64",
                        "content": base64.b64encode(inner).decode("ascii"),
                        "download_url": "https://example.invalid/raw.json",
                    }
                ).encode("utf-8")
                (document, source, raw), calls = self.fetch([_FakeResponse(envelope), _FakeResponse(self.BODY)])
                self.assertEqual(source, self.URL)
                self.assertEqual(raw, self.BODY)
                self.assertEqual(len(document["players"]), 1)
                self.assertEqual(calls, 2)

    def test_redact_url_strips_credentials_only(self):
        self.assertEqual(sources.redact_url("https://u:secret@h.example/x?y=1"), "https://h.example/x?y=1")
        self.assertEqual(sources.redact_url("https://u:secret@[::1]/x"), "https://[::1]/x")
        self.assertEqual(sources.redact_url("https://u:secret@[::1]:8443/x"), "https://[::1]:8443/x")
        self.assertEqual(sources.redact_url("https://h.example:8443/x"), "https://h.example:8443/x")
        self.assertEqual(sources.redact_url("playerlist.garou3299.json"), "playerlist.garou3299.json")

    def test_all_unicode_format_characters_are_visible_in_url_output(self):
        """Future or rarely used format characters must not disguise targets."""
        for character in ("\u200c", "\u200d", "\u206a", "\u070f"):
            with self.subTest(character=f"U+{ord(character):04X}"):
                shown = sources.redact_url(f"https://example.invalid/{character}path")
                encoded = "".join(f"%{byte:02X}" for byte in character.encode("utf-8"))
                self.assertIn(encoded, shown)
                self.assertNotIn(character, shown)

    def test_redact_url_hides_a_token_carried_in_the_query_string(self):
        """This URL is published in the pull request body: ?token=... must not be."""
        redacted = sources.redact_url("https://example.invalid/list.json?token=ghp_SECRET&ref=main")
        self.assertIn("token=REDACTED", redacted)
        self.assertNotIn("ghp_SECRET", redacted)
        # Preserve harmless parameters so the fetch line remains useful for
        # identifying the requested source.
        self.assertIn("ref=main", redacted)

    def test_html_character_references_cannot_hide_url_credentials(self):
        """Markdown's character references can spell URL delimiters."""
        probes = (
            (
                "https://example.invalid/list?token&#x3d;HTML_QUERY_SECRET",
                "HTML_QUERY_SECRET",
                "token=REDACTED",
            ),
            (
                "https://example.invalid/list?ref&#x3d;main&#x26;access_token&#x3d;HTML_TOKEN_SECRET",
                "HTML_TOKEN_SECRET",
                "ref=main",
            ),
            (
                "https://user&#x3a;HTML_USERINFO_PASSWORD&#x40;example.invalid/watch",
                "HTML_USERINFO_PASSWORD",
                "https://example.invalid/watch",
            ),
        )
        for url, secret, safe_text in probes:
            with self.subTest(url=url):
                shown = sources.redact_url(url)
                self.assertNotIn(secret, shown)
                self.assertIn(safe_text, shown)

        harmless = "https://example.invalid/list?ref&#x3d;main"
        self.assertEqual(sources.redact_url(harmless), harmless)

        embedded = sources.redact_urls_in_text(
            "Proof: https&#x3a;//user&#x3a;HTML_TEXT_PASSWORD&#x40;example.invalid/watch"
        )
        self.assertNotIn("HTML_TEXT_PASSWORD", embedded)
        self.assertIn("https://example.invalid/watch", embedded)

    def test_over_encoded_html_delimiters_are_omitted_fail_closed(self):
        def overencode(entity):
            for _ in range(sources._MAX_NESTED_URL_DEPTH + 2):
                entity = entity.replace("&", "&amp;")
            return entity

        delimiter = overencode("&#x3d;")
        shown = sources.redact_url(f"https://example.invalid/x?token{delimiter}OVER_ENCODED_HTML_SECRET")
        self.assertNotIn("OVER_ENCODED_HTML_SECRET", shown)
        self.assertIn("too deeply encoded", shown)

        # parse_qsl decodes percent-encoded keys before the credential-name check;
        # unresolved HTML entities in keys must also fail closed.
        key = urllib.parse.quote(f"token{delimiter}KEY_SECRET", safe="")
        shown = sources.redact_url(f"https://example.invalid/x?{key}=ignored")
        self.assertNotIn("KEY_SECRET", shown)
        self.assertNotIn("ignored", shown)
        self.assertIn("REDACTED=REDACTED", shown)

        # Apply the nested-URL inspection limit to encoded scheme separators too.
        nested = f"https{overencode('&colon;')}{overencode('&sol;&sol;')}user:NESTED_HTML_PASSWORD@client.invalid/path"
        nested_url = "https://example.invalid/?redirect_uri=" + urllib.parse.quote(nested, safe="")
        shown = sources.redact_url(nested_url)
        self.assertNotIn("NESTED_HTML_PASSWORD", shown)
        self.assertIn("nested URL omitted", urllib.parse.unquote_plus(shown))

        text = sources.redact_urls_in_text(f"?token{delimiter}TEXT_HTML_SECRET")
        self.assertNotIn("TEXT_HTML_SECRET", text)
        self.assertIn("too deeply encoded", text)

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
            "state",
            "sessionid",
            "hmac",
            "SAMLResponse",
            "ticket",
            "code",
        ):
            with self.subTest(name=name):
                redacted = sources.redact_url(f"https://example.invalid/x?{name}=SECRET")
                self.assertNotIn("SECRET", redacted)
                self.assertIn("REDACTED", redacted)

    def test_percent_encoded_controls_cannot_split_a_sensitive_parameter_name(self):
        """A URL-decoded line break or zero-width character must not hide `token`."""
        for separator in ("%0A", "%0D", "%09", "%20", "%E2%80%8B", "%E2%80%8D", "%250A"):
            with self.subTest(separator=separator):
                redacted = sources.redact_url(f"https://example.invalid/x?to{separator}ken=ENCODED_NAME_SECRET")
                self.assertNotIn("ENCODED_NAME_SECRET", redacted)
                self.assertIn("REDACTED", redacted)

    def test_an_over_encoded_parameter_name_is_redacted_fail_closed(self):
        name = "to\nken"
        for _ in range(sources._MAX_NESTED_URL_DEPTH + 2):
            name = sources.urllib.parse.quote(name, safe="")
        shown = sources.redact_url(f"https://example.invalid/x?{name}=OVER_ENCODED_SECRET")
        self.assertNotIn("OVER_ENCODED_SECRET", shown)
        self.assertIn("REDACTED", shown)

    def test_an_encoded_equals_cannot_hide_a_secret_inside_a_parameter_name(self):
        shown = sources.redact_url("https://example.invalid/x?token%3DKEY_SECRET=ignored")
        self.assertNotIn("KEY_SECRET", shown)
        self.assertNotIn("ignored", shown)
        self.assertIn("REDACTED=REDACTED", shown)

        # The malformed-text fallback must also redact this obfuscated key.
        shown = sources.redact_urls_in_text("Context: ?token%3DPROSE_KEY_SECRET=VALUE")
        self.assertNotIn("PROSE_KEY_SECRET", shown)
        self.assertNotIn("VALUE", shown)
        self.assertIn("?REDACTED=REDACTED", shown)

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
        self.assertIn("private\\_token=REDACTED", report)  # The report escapes underscores for Markdown.
        self.assertIn("ref=main", report)

    def test_upstream_evidence_urls_never_publish_credentials(self):
        """Evidence links are untrusted URLs and the report is public."""
        evidence = (
            "https://user:URL_PASSWORD@example.invalid/watch"
            "?X-Amz-Signature=QUERY_SECRET&ref=main#access_token=FRAGMENT_SECRET"
        )
        change = Change("[U:1:100]", "name", ("suspicious",), ("cheater",), evidence=(evidence,))
        info = RunInfo(
            database_path=Path("db.json"),
            source="https://example.invalid/list.json",
            source_total=1,
            source_skipped=0,
            dry_run=False,
            changes=(change,),
        )
        report = render_report(info)
        for secret in ("URL_PASSWORD", "QUERY_SECRET", "FRAGMENT_SECRET"):
            self.assertNotIn(secret, report)
        self.assertIn("X-Amz-Signature=REDACTED", report)
        self.assertIn("ref=main", report)
        self.assertIn("access_token=REDACTED", report)
        # Redacted evidence URLs must not link to the altered target.
        cell = report_module._evidence_cell([evidence])
        self.assertNotIn("](", cell)

    def test_a_player_name_cannot_publish_credentials_inside_a_url(self):
        name = "clip https://user:NAME_PASSWORD@example.invalid/watch?token=NAME_TOKEN"
        change = Change("[U:1:100]", name, ("suspicious",), ("cheater",))
        report = render_report(RunInfo(Path("db.json"), "https://example.invalid/list.json", 1, 0, False, (change,)))
        self.assertNotIn("NAME_PASSWORD", report)
        self.assertNotIn("NAME_TOKEN", report)
        self.assertIn("clip `https://example.invalid/watch?token=REDACTED`", report)

    def test_redact_url_matches_a_secret_parameter_name_case_insensitively(self):
        self.assertIn("REDACTED", sources.redact_url("https://example.invalid/x?Token=abc"))
        self.assertIn("REDACTED", sources.redact_url("https://example.invalid/x?API_KEY=abc"))

    def test_redact_url_hides_a_credential_carried_in_the_fragment(self):
        """OAuth's implicit flow puts tokens after the ``#``.

        The query string was handled and the fragment was not, so
        ``https://host/callback#access_token=...`` published the token
        verbatim in the pull request body.
        """
        redacted = sources.redact_url("https://h/callback#access_token=s3cret&ref=xyz")
        self.assertNotIn("s3cret", redacted)
        self.assertIn("access_token=REDACTED", redacted)
        self.assertIn("ref=xyz", redacted)

    def test_redact_url_treats_legacy_semicolons_as_parameter_separators(self):
        for url, secret, safe_pair in (
            (
                "https://example.invalid/?ref=main;access_token=QUERY_SECRET",
                "QUERY_SECRET",
                "ref=main",
            ),
            (
                "https://example.invalid/#ref=main;state=FRAGMENT_SECRET",
                "FRAGMENT_SECRET",
                "ref=main",
            ),
        ):
            with self.subTest(url=url):
                redacted = sources.redact_url(url)
                self.assertNotIn(secret, redacted)
                self.assertIn("REDACTED", redacted)
                self.assertIn(safe_pair, redacted)

    def test_redact_url_recurses_into_nested_url_parameters(self):
        urls = (
            (
                "https://example.invalid/?redirect_uri="
                "https%3A%2F%2Fclient.invalid%2Fcallback%3Faccess_token%3DNESTED_QUERY_SECRET",
                "NESTED_QUERY_SECRET",
            ),
            (
                "https://example.invalid/#return_to="
                "https%3A%2F%2Fuser%3ANESTED_USERINFO_SECRET%40client.invalid%2Fcallback",
                "NESTED_USERINFO_SECRET",
            ),
            (
                "https://example.invalid/?redirect_uri="
                "%2F%2Fuser%3ANESTED_PROTOCOL_PASSWORD%40client.invalid%2Fcallback",
                "NESTED_PROTOCOL_PASSWORD",
            ),
            (
                "https://example.invalid/?redirect_uri="
                "https%253A%252F%252Fclient.invalid%252Fcallback%253Ftoken%253DDOUBLE_ENCODED_SECRET",
                "DOUBLE_ENCODED_SECRET",
            ),
        )
        for url, secret in urls:
            with self.subTest(url=url):
                redacted = sources.redact_url(url)
                self.assertNotIn(secret, redacted)
                self.assertIn("client.invalid", redacted)
        self.assertIn("REDACTED", sources.redact_url(urls[0][0]))

    def test_deeply_nested_url_redaction_is_bounded_and_fails_closed(self):
        url = "https://example.invalid/?next=" + "?next=" * 300 + "token=DEEP_SECRET"
        shown = sources.redact_url(url)
        self.assertNotIn("DEEP_SECRET", shown)
        self.assertIn("nested", shown)

    def test_over_encoded_nested_url_fails_closed_when_decode_budget_is_exceeded(self):
        nested = "https://client.invalid/callback?token=OVER_ENCODED_NESTED_SECRET"
        for _ in range(sources._MAX_NESTED_URL_DEPTH + 4):
            nested = sources.urllib.parse.quote(nested, safe="")
        shown = sources.redact_url("https://example.invalid/?redirect_uri=" + nested)
        self.assertNotIn("OVER_ENCODED_NESTED_SECRET", shown)
        self.assertIn("nested", shown.lower())

    def test_redact_url_credentials_inside_prose_without_rewriting_the_prose(self):
        text = "Context: https://user:PROSE_PASSWORD@example.invalid/watch?token=PROSE_TOKEN."
        shown = sources.redact_urls_in_text(text)
        self.assertEqual(shown, "Context: https://example.invalid/watch?token=REDACTED.")
        self.assertNotIn("PROSE_PASSWORD", shown)
        self.assertNotIn("PROSE_TOKEN", shown)

        parenthesized = "See (https://example.invalid/watch?token=PAREN_SECRET)."
        shown = sources.redact_urls_in_text(parenthesized)
        self.assertEqual(shown, "See (https://example.invalid/watch?token=REDACTED).")
        self.assertNotIn("PAREN_SECRET", shown)

        protocol_relative = "Context: //user:RELATIVE_PASSWORD@example.invalid/watch?token=RELATIVE_TOKEN."
        shown = sources.redact_urls_in_text(protocol_relative)
        self.assertEqual(shown, "Context: //example.invalid/watch?token=REDACTED.")
        self.assertNotIn("RELATIVE_PASSWORD", shown)
        self.assertNotIn("RELATIVE_TOKEN", shown)

        split_query = "Proof: https://example.invalid/watch\nb?token=LINEBREAK_TOKEN."
        shown = sources.redact_urls_in_text(split_query)
        self.assertNotIn("LINEBREAK_TOKEN", shown)
        self.assertIn("?token=REDACTED.", shown)

        # urlsplit() removes CR, LF, and TAB before parsing; malformed prose URLs
        # must still redact queries when a control splits the parameter name,
        # equals sign, or value.
        for split_parameter, secret in (
            ("?to ken=SPLIT_SPACE_NAME_SECRET", "SPLIT_SPACE_NAME_SECRET"),
            ("?to\u2002ken=SPLIT_UNICODE_SPACE_NAME_SECRET", "SPLIT_UNICODE_SPACE_NAME_SECRET"),
            ("?to\nken=SPLIT_NAME_SECRET", "SPLIT_NAME_SECRET"),
            ("?to\tken=SPLIT_TAB_NAME_SECRET", "SPLIT_TAB_NAME_SECRET"),
            ("?to\vken=SPLIT_VERTICAL_TAB_NAME_SECRET", "SPLIT_VERTICAL_TAB_NAME_SECRET"),
            ("?to\fken=SPLIT_FORM_FEED_NAME_SECRET", "SPLIT_FORM_FEED_NAME_SECRET"),
            ("?token\n=SPLIT_EQUALS_SECRET", "SPLIT_EQUALS_SECRET"),
            ("?token=\nSPLIT_VALUE_SECRET", "SPLIT_VALUE_SECRET"),
            ("?token=LEFT\nRIGHT_VALUE_SECRET", "RIGHT_VALUE_SECRET"),
            ("?token=LEFT RIGHT_SPACE_SECRET", "RIGHT_SPACE_SECRET"),
            ("?token=LEFT\tRIGHT_TAB_SECRET", "RIGHT_TAB_SECRET"),
            ("?token=LEFT\vRIGHT_VERTICAL_TAB_SECRET", "RIGHT_VERTICAL_TAB_SECRET"),
            ("?token=LEFT\fRIGHT_FORM_FEED_SECRET", "RIGHT_FORM_FEED_SECRET"),
            ('?token=LEFT"RIGHT_QUOTED_SECRET', "RIGHT_QUOTED_SECRET"),
            ("?token=LEFT<RIGHT_MARKUP_SECRET", "RIGHT_MARKUP_SECRET"),
        ):
            with self.subTest(split_parameter=split_parameter):
                shown = sources.redact_urls_in_text("Proof: https://example.invalid/" + split_parameter)
                self.assertNotIn(secret, shown)

        split_userinfo = "Proof: https://user:\nLINEBREAK_PASSWORD@example.invalid/watch"
        shown = sources.redact_urls_in_text(split_userinfo)
        self.assertNotIn("LINEBREAK_PASSWORD", shown)
        self.assertIn("https://example.invalid/watch", shown)

        split_username = "Proof: https://us\ner:USERNAME_PASSWORD@example.invalid/watch"
        shown = sources.redact_urls_in_text(split_username)
        self.assertNotIn("USERNAME_PASSWORD", shown)
        self.assertIn("https://example.invalid/watch", shown)

    def test_percent_encoded_controls_cannot_split_a_credential_in_prose(self):
        for separator in ("%0A", "%0D", "%09", "%20", "%E2%80%8B", "%250A"):
            with self.subTest(separator=separator):
                shown = sources.redact_urls_in_text(
                    f"Evidence: https://example.invalid/?to{separator}ken=PROSE_ENCODED_SECRET."
                )
                self.assertNotIn("PROSE_ENCODED_SECRET", shown)
                self.assertIn("REDACTED", shown)

    def test_redact_url_text_omits_overlong_content_before_scanning(self):
        text = "Context: https://user:LONG_SECRET@example.invalid/" + "x" * 5_000
        with mock.patch("sources.redact_url", side_effect=AssertionError("must short-circuit")):
            shown = sources.redact_urls_in_text(text)
        self.assertEqual(shown, "[URL omitted: too long to inspect safely]")
        self.assertNotIn("LONG_SECRET", shown)

    def test_redact_url_leaves_an_ordinary_fragment_alone(self):
        # An equals sign in the fragment is not enough to trigger redaction;
        # harmless pairs must retain their values, as in the query string.
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

    def test_redact_url_bounds_a_long_but_parseable_url(self):
        """A long-but-safe URL is truncated after inspection for credentials."""
        shown = sources.redact_url("https://example.invalid/" + "a" * 3_000)
        self.assertEqual(len(shown), sources.MAX_URL_DISPLAY_CHARS + 1)
        self.assertTrue(shown.endswith("…"))

    def test_redact_url_omits_oversized_queries_and_fragments_before_parsing(self):
        """A tiny display limit must not hide a huge parse_qsl allocation."""
        urls = (
            "https://example.invalid/?token=QUERY_SECRET&" + "ref=1&" * 2_000,
            "https://example.invalid/#access_token=FRAGMENT_SECRET&" + "ref=1&" * 2_000,
            "https://user:PATH_SECRET@example.invalid/" + "x" * 5_000,
        )
        for url in urls:
            with self.subTest(query="?" in url, fragment="#" in url):
                with mock.patch("sources.urllib.parse.urlsplit", side_effect=AssertionError("must short-circuit")):
                    shown = sources.redact_url(url)
                self.assertEqual(shown, "[URL omitted: too long to inspect safely]")
                self.assertNotIn("SECRET", shown)

    def test_http_scheme_classifies_overlong_values_without_scanning_them(self):
        values = (
            ("HTTPS://" + "x" * 5_000, "https"),
            ("HTTP://" + "x" * 5_000, "http"),
            ("x" * 5_000, ""),
        )
        with mock.patch("sources.urllib.parse.urlsplit", side_effect=AssertionError("must use the prefix")):
            for value, expected in values:
                self.assertEqual(sources.http_scheme(value), expected)

    def test_fetch_refuses_an_overlong_url_before_opening_a_request(self):
        url = "https://example.invalid/?" + "ref=1&" * 2_000
        with mock.patch("sources._OPENER.open") as opener, self.assertRaises(SyncError) as caught:
            sources._fetch_bytes(url)
        self.assertIn("4,096 characters", str(caught.exception))
        opener.assert_not_called()

    def test_redact_url_survives_a_malformed_port(self):
        """redact_url runs on error paths: it must never raise there."""
        redacted = sources.redact_url("https://user:secret@example.invalid:notaport/list.json")
        self.assertNotIn("secret", redacted)
        self.assertIn("example.invalid", redacted)

    def test_an_unparseable_url_never_echoes_credentials(self):
        url = "https://user:URL_SECRET@[::1/list?token=QUERY_SECRET"
        shown = sources.redact_url(url)
        self.assertEqual(shown, "[malformed URL omitted]")
        self.assertNotIn("URL_SECRET", shown)
        self.assertNotIn("QUERY_SECRET", shown)

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
            redacted.encode("utf-8")  # Reports are UTF-8 output, so encoding must succeed.
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
        # Treat an unrepresentable path as a missing snapshot.
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
            "https://example.invalid/a\u009b31mb",
            "https://example.invalid/a\x00b",
            "https://example.invalid/a\u202eb",
            "https://example.invalid/a\u200bb",
            "https://[::1\nforged",  # Exercise urlsplit()'s malformed-IPv6 exception path.
        ):
            shown = sources.redact_url(url)
            self.assertEqual(len(shown.splitlines()), 1)
            self.assertNotIn("\n", shown)
            self.assertNotIn("\u202e", shown)
            self.assertNotIn("\u200b", shown)
            self.assertNotIn("\u009b", shown)

    def test_http_scheme_is_case_insensitive_and_blank_for_a_local_path(self):
        """RFC 3986 schemes are case-insensitive, and urllib agrees."""
        self.assertEqual(sources.http_scheme("https://example.invalid/x"), "https")
        self.assertEqual(sources.http_scheme("HTTPS://example.invalid/x"), "https")
        self.assertEqual(sources.http_scheme("HTTP://example.invalid/x"), "http")
        self.assertEqual(sources.http_scheme("playerlist.garou3299.json"), "")
        self.assertEqual(sources.http_scheme("https://[::1/x"), "")  # Malformed IPv6 returns an empty scheme.

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

        # Parsed JSON with the wrong top-level type is rejected as well.
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

    def test_local_path_errors_redact_urls_and_escape_control_characters(self):
        path = "Context:\nhttps://user:PATH_PASSWORD@example.invalid/list\x1b[31m"
        with self.assertRaises(SyncError) as caught:
            sources._read_bytes(path)
        message = str(caught.exception)
        self.assertNotIn("PATH_PASSWORD", message)
        self.assertNotIn("\n", message)
        self.assertNotIn("\x1b", message)
        self.assertIn("Context:%0Ahttps://example.invalid/list%1B[31m", message)

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
        self.assertEqual(raw, inner)  # The API envelope must never be written as the snapshot.
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
        self.assertIsNone(sources._github_blob_url(self.URL, "a" * 40))  # Reject non-API hosts.
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
                load_snapshot(Path(tmp))  # A directory is not a source file.

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
        # Try download_url first, then the Git blob endpoint after three failures.
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

    @unittest.skipUnless(Path("/dev/zero").exists(), "needs a special file")
    def test_special_files_are_refused_before_opening(self):
        """A device is not a source file, even if a byte cap could bound its output."""
        real_open = os.open
        with (
            mock.patch("playerlist.os.open", wraps=real_open) as open_file,
            self.assertRaises(SyncError) as raised,
        ):
            sources._read_bytes("/dev/zero")
        self.assertIn("not a regular file", str(raised.exception))
        open_file.assert_not_called()

    @unittest.skipUnless(Path("/dev/zero").exists(), "needs a special file")
    def test_the_open_descriptor_is_checked_against_a_path_replacement(self):
        """The fstat check closes the race after the initial path stat."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.json"
            path.write_bytes(b'{"players": []}')
            special_status = Path("/dev/zero").stat()
            with (
                mock.patch("playerlist.os.fstat", return_value=special_status),
                self.assertRaises(SyncError) as raised,
            ):
                sources._read_bytes(str(path))
        self.assertIn("not a regular file", str(raised.exception))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs named pipes")
    def test_fifo_input_is_refused_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp) / "source.fifo"
            os.mkfifo(fifo)
            scripts = Path(__file__).resolve().parents[1] / "scripts"
            code = (
                f"import sys; sys.path.insert(0, {str(scripts)!r})\n"
                "import sources\n"
                f"try:\n    sources._read_bytes({str(fifo)!r})\n"
                "except sources.SyncError as exc:\n    print(exc)\n"
                "else:\n    raise SystemExit('FIFO unexpectedly accepted')\n"
            )
            result = subprocess.run(
                [sys.executable, "-c", code],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=5,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not a regular file", result.stdout)

    def test_malformed_urls_are_clean_errors_not_crashes(self):
        # Malformed IPv6 literals and control characters can make urllib raise
        # ValueError or InvalidURL. Convert these to SyncError so callers can fall
        # back or exit cleanly; neither case should reach the network.
        for url in ("https://[::1", "https://exa\nmple.invalid/"):
            with mock.patch("sources.time.sleep"), self.assertRaises(SyncError):
                load_first_available_raw([url])

    def test_malformed_url_errors_do_not_echo_raw_credentials(self):
        url = "https://user:URL_PASSWORD@example.invalid/a\nb?token=QUERY_SECRET"
        with self.assertRaises(SyncError) as caught:
            sources._fetch_bytes(url)
        message = str(caught.exception)
        self.assertIn("malformed URL or HTTP response", message)
        self.assertNotIn("URL_PASSWORD", message)
        self.assertNotIn("QUERY_SECRET", message)
        self.assertNotIn("\n", message)

    def test_server_controlled_http_reason_is_not_logged_or_echoed(self):
        url = "https://example.invalid/list?token=URL_SECRET"
        responses = [
            urllib.error.HTTPError(url, 503, "bad token=HTTP_SECRET\n\x1b[2J", Message(), None)
            for _ in range(sources.FETCH_ATTEMPTS)
        ]
        with (
            mock.patch("sources._OPENER.open", side_effect=responses),
            mock.patch("sources.time.sleep"),
            self.assertLogs("vorobey_sources", level="DEBUG") as captured,
            self.assertRaises(SyncError) as caught,
        ):
            sources._fetch_bytes(url)
        output = str(caught.exception) + "\n".join(captured.output)
        for secret in ("URL_SECRET", "HTTP_SECRET", "\x1b"):
            self.assertNotIn(secret, output)
        self.assertIn("HTTP status 503", output)

    def test_fetch_error_descriptions_discard_untrusted_exception_text(self):
        for exc, expected in ((OSError("SECRET"), "network I/O error"), (RuntimeError("SECRET"), "RuntimeError")):
            with self.subTest(exception=type(exc).__name__):
                shown = sources._safe_fetch_error(exc)
                self.assertEqual(shown, expected)
                self.assertNotIn("SECRET", shown)

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

    def test_http_error_response_body_is_closed(self):
        body = io.BytesIO(b"server error body")
        error = urllib.error.HTTPError(self.URL, 503, "unavailable", Message(), body)
        with (
            mock.patch("sources._OPENER.open", side_effect=[error]),
            mock.patch("sources.FETCH_ATTEMPTS", 1),
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError),
        ):
            load_first_available_raw([self.URL])
        self.assertTrue(body.closed)

    def test_http_error_without_a_response_body_is_still_handled(self):
        error = urllib.error.HTTPError(self.URL, 404, "not found", Message(), None)
        # HTTPError replaces a None body with an empty StringIO; set fp to None
        # explicitly to exercise cleanup when no response stream is owned.
        error.fp = None
        with (
            mock.patch("sources._OPENER.open", side_effect=[error]),
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError),
        ):
            load_first_available_raw([self.URL])

    def test_https_downgrade_redirect_is_refused(self):
        """A redirect from HTTPS to plain HTTP must never be followed: the
        fetched bytes become the snapshot and drive promotions."""
        handler = sources._HttpsOnlyRedirectHandler()
        request = urllib.request.Request("https://example.invalid/list.json")
        with self.assertRaises(SyncError):
            handler.redirect_request(request, None, 302, "Found", Message(), "http://example.invalid/list.json")
        upgraded = handler.redirect_request(request, None, 302, "Found", Message(), "https://cdn.invalid/list.json")
        self.assertEqual(upgraded.full_url, "https://cdn.invalid/list.json")

    def test_downgrade_redirect_error_redacts_credentials_in_location(self):
        handler = sources._HttpsOnlyRedirectHandler()
        request = urllib.request.Request("https://example.invalid/list.json")
        location = "http://cdn.invalid/list.json?token=REDIRECT_SECRET"
        with self.assertRaises(SyncError) as caught:
            handler.redirect_request(request, None, 302, "Found", Message(), location)
        self.assertNotIn("REDIRECT_SECRET", str(caught.exception))
        self.assertIn("token=REDACTED", str(caught.exception))

    def test_an_overlong_redirect_is_refused_before_url_parsing(self):
        handler = sources._HttpsOnlyRedirectHandler()
        request = urllib.request.Request("https://example.invalid/list.json")
        location = "https://cdn.invalid/list?" + "ref=1&" * 2_000
        with (
            mock.patch("sources.urllib.parse.urlparse", side_effect=AssertionError("must short-circuit")),
            self.assertRaises(SyncError) as caught,
        ):
            handler.redirect_request(request, None, 302, "Found", Message(), location)
        self.assertIn("longer than 4,096 characters", str(caught.exception))

    def test_relative_redirect_cannot_grow_past_the_url_limit(self):
        prefix = "https://example.invalid/"
        base_url = prefix + "a" * (sources._MAX_URL_PARSE_CHARS - len(prefix) - 1) + "/"
        request = urllib.request.Request(base_url)
        # urllib resolves a relative Location before invoking redirect_request;
        # validate the absolute target rather than the short header value.
        location = sources.urllib.parse.urljoin(base_url, "b" * 100)
        self.assertGreater(len(location), sources._MAX_URL_PARSE_CHARS)
        with (
            mock.patch("sources.urllib.parse.urlparse", side_effect=AssertionError("must short-circuit")),
            self.assertRaises(SyncError) as caught,
        ):
            sources._HttpsOnlyRedirectHandler().redirect_request(request, None, 302, "Found", Message(), location)
        self.assertIn("longer than 4,096 characters", str(caught.exception))

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
        # Assert the delay values as well as the attempt count: zero-delay retries
        # would hammer a rate-limited host, and each delay must increase.
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
                    self.assertEqual(response.read_count, 0)  # Reject the response before reading its body.

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
            # Do not sleep after the final attempt.
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
        self.assertEqual(response.read_count, 0)  # Reject an oversized response before downloading its body.

    def test_transient_http_error_is_retried_until_success(self):
        error = urllib.error.HTTPError(self.URL, 503, "unavailable", Message(), None)
        (_, _, raw), calls = self.fetch([error, error, _FakeResponse(self.BODY)])
        self.assertEqual(raw, self.BODY)
        self.assertEqual(calls, 3)


class SnapshotReadTests(unittest.TestCase):
    def test_a_self_referential_symlink_is_a_read_error_not_a_missing_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "loop.json"
            path.symlink_to(path)
            with self.assertRaises(SyncError) as caught:
                sources.load_snapshot(path)
            message = str(caught.exception).lower()
            self.assertTrue("symbolic link loop" in message or "too many levels of symbolic links" in message)
            self.assertTrue(path.is_symlink())

    def test_a_path_the_os_cannot_stat_is_a_read_error_not_a_crash(self):
        """An overlong path is a read error, never a missing baseline."""
        path = Path("/tmp") / ("d" * 200) / "snap.json"
        with (
            mock.patch.object(Path, "stat", side_effect=OSError(36, "File name too long", str(path))),
            self.assertRaises(SyncError) as caught,
        ):
            sources.load_snapshot(path)
        self.assertIn("cannot read", str(caught.exception))
        self.assertIn("File name too long", str(caught.exception))

    def test_a_snapshot_stat_failure_is_never_mistaken_for_a_missing_file(self):
        """pathlib.exists() can return False on errors in newer Python versions."""
        path = Path("/tmp/restricted/snapshot.json")
        with (
            mock.patch.object(Path, "stat", side_effect=PermissionError(13, "Permission denied", str(path))),
            mock.patch.object(Path, "exists", return_value=False),
            self.assertRaises(SyncError) as caught,
        ):
            sources.load_snapshot(path)
        self.assertIn("Permission denied", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
