#!/usr/bin/env python3
"""Tests for the Vorobey hackerpolice sync tool."""

from __future__ import annotations

import itertools
import json
import tempfile
import unittest
import urllib.parse
from pathlib import Path

from _support import (
    player,
)

import playerlist as playerlist_module
from playerlist import (
    ATTRIBUTE_ORDER,
    KNOWN_ATTRIBUTES,
    MAX_SHOWN_PATH_CHARS,
    MAX_VALIDATION_MESSAGES,
    PlayerListError,
    ValidationResult,
    account_id,
    display_path,
    dumps,
    load,
    normalize_steamid,
    order_attributes,
    player_name,
    redact_diagnostic_text,
    sort_players,
    steam_history_url,
    steam_profile_url,
    strict_json_loads,
    validate,
)


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
        self.assertIsNone(playerlist_module._bounded_int("²"))  # Defensive guard; normal input cannot reach this case.

    def test_non_ascii_digits_are_rejected_not_crashed(self):
        """Regression: "²".isdigit() is True but int("²") raises, so a single
        corrupted SteamID used to crash the whole run; "١٢٣" was silently
        accepted and minted [U:1:123]. Both are now simply unusable."""
        for probe in (
            "²",
            "1²3",
            "١٢٣",
            "۷۳",
            "[U:1:١٢٣]",
            "[U:1:²]",
            "U:1:²",
            "STEAM_0:1:²",
            "ſTEAM_0:1:865008",
        ):
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

    def test_instance_component_is_checked_as_a_20_bit_field(self):
        self.assertEqual(normalize_steamid("[U:1:1730017:1048575]"), "[U:1:1730017]")
        for value in (
            "[U:1:1730017:1048576]",
            "[U:1:1730017:" + "9" * 5_000 + "]",
        ):
            with self.subTest(value=value[:40]):
                self.assertIsNone(normalize_steamid(value))

    def test_space_warrior_and_steam64(self):
        self.assertEqual(normalize_steamid("STEAM_0:1:865008"), "[U:1:1730017]")
        self.assertEqual(normalize_steamid("steam_0:1:865008"), "[U:1:1730017]")
        self.assertEqual(normalize_steamid("STEAM_1:1:865008"), "[U:1:1730017]")
        self.assertEqual(normalize_steamid("76561197961995745"), "[U:1:1730017]")
        self.assertEqual(normalize_steamid(76561197961995745), "[U:1:1730017]")
        self.assertEqual(normalize_steamid("https://steamcommunity.com/profiles/76561197961995745"), "[U:1:1730017]")

    def test_profile_url_must_be_a_complete_steamcommunity_permalink(self):
        valid = (
            "https://steamcommunity.com/profiles/76561197961995745",
            "http://www.steamcommunity.com/profiles/76561197961995745/",
            "steamcommunity.com/profiles/76561197961995745",
        )
        for url in valid:
            with self.subTest(url=url):
                self.assertEqual(normalize_steamid(url), "[U:1:1730017]")

        for lookalike in (
            "https://evil.example/steamcommunity.com/profiles/76561197961995745",
            "text steamcommunity.com/profiles/76561197961995745 text",
            "https://steamcommunity.com.evil.example/profiles/76561197961995745",
            "https://steamcommunity.com/profiles/76561197961995745.evil.example",
            "https://steamcommunity.com/profiles/76561197961995745/other",
            "https://ſteamcommunity.com/profiles/76561197961995745",
        ):
            with self.subTest(url=lookalike):
                self.assertIsNone(normalize_steamid(lookalike))

    def test_bare_account_id(self):
        self.assertEqual(normalize_steamid(1730017), "[U:1:1730017]")

    def test_bare_account_id_as_string(self):
        self.assertEqual(normalize_steamid("1730017"), "[U:1:1730017]")
        self.assertEqual(normalize_steamid("0" * 16 + "1"), "[U:1:1]")
        self.assertIsNone(normalize_steamid("0"))

    def test_out_of_range_account_ids_are_rejected(self):
        for value in ("[U:1:0]", "[U:1:4294967296]", "U:1:0", "[U:1:0:1]"):
            self.assertIsNone(normalize_steamid(value), value)
        self.assertEqual(normalize_steamid("[U:1:4294967295]"), "[U:1:4294967295]")

    def test_steam2_ids_are_range_checked_too(self):
        # Regression: reject Steam2 IDs that would yield zero or exceed the 32-bit account range.
        self.assertIsNone(normalize_steamid("STEAM_0:0:0"))
        self.assertIsNone(normalize_steamid("STEAM_0:1:99999999999"))
        self.assertEqual(normalize_steamid("STEAM_0:1:2147483647"), "[U:1:4294967295]")

    def test_non_public_steam2_universes_cannot_alias_a_public_account(self):
        """The universe is part of a SteamID; dropping it can name the wrong person."""
        for universe in range(2, 6):
            with self.subTest(universe=universe):
                self.assertIsNone(normalize_steamid(f"STEAM_{universe}:1:865008"))

    def test_absurdly_large_int_is_rejected_without_crashing(self):
        self.assertIsNone(normalize_steamid(10**5000))

    def test_absurdly_long_digit_strings_are_rejected_without_crashing(self):
        # Reject values beyond Python's integer-digit limit without crashing.
        huge = "9" * 5000
        for value in (f"[U:1:{huge}]", huge, f"STEAM_0:1:{huge}"):
            self.assertIsNone(normalize_steamid(value), value[:20])
        # Leading zeros do not count toward the digit limit.
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
        # SteamHistory uses the same SteamID64 on its /id/ page.
        self.assertEqual(steam_history_url("[U:1:269327660]"), "https://steamhistory.net/id/76561198229593388")
        self.assertEqual(steam_history_url("STEAM_0:1:865008"), "https://steamhistory.net/id/76561197961995745")
        self.assertEqual(steam_history_url(76561198229593388), "https://steamhistory.net/id/76561198229593388")
        self.assertIsNone(steam_history_url("nope"))
        self.assertIsNone(steam_history_url(None))


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


class SerializationTests(unittest.TestCase):
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

    def test_a_json_integer_beyond_the_fixed_digit_limit_is_refused(self):
        for digits in ("9" * 5_000, "-" + "9" * 5_000):
            with self.subTest(sign=digits[:1]), self.assertRaisesRegex(ValueError, "out of range for a JSON integer"):
                strict_json_loads('{"value": ' + digits + "}")

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
        self.assertEqual(strict_json_loads('{"t": 1e-999}'), {"t": 0.0})  # Underflow remains finite.

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
        # Byte input is also accepted.
        self.assertEqual(strict_json_loads(b'{"players": []}'), {"players": []})

    def test_serializing_a_non_finite_number_is_refused(self):
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
        self.assertEqual(player_name({"last_seen": {"player_name": 10**5000}}), "<integer too large to display>")
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


class DisplayPathTests(unittest.TestCase):
    """Paths are operator input too: one line, printable, bounded."""

    def test_display_raw_escapes_without_inspecting_or_re_redacting(self):
        """It is the escape-only half used on finished, already-redacted messages.

        Running the redactor over a finished message re-inspects every
        ``key=value`` it mentions and, past the length cap, reports the whole
        message as an uninspectable URL.
        """
        self.assertEqual(playerlist_module.display_raw("a\nb.json"), "a\\nb.json")
        long_message = "players[0] has a problem: " + "key=value;" * 1_000
        shown = playerlist_module.display_raw(long_message)
        self.assertNotIn("omitted", shown)
        self.assertTrue(shown.endswith("…"))
        self.assertLessEqual(len(shown), playerlist_module.MAX_SHOWN_PATH_CHARS + 1)

    def test_display_raw_bounds_before_escaping_to_avoid_a_giant_copy(self):
        giant = "\x1b" * 200_000
        shown = playerlist_module.display_raw(giant)
        self.assertLessEqual(len(shown), playerlist_module.MAX_SHOWN_PATH_CHARS + 1)
        self.assertEqual(set(shown) - {"…"}, {"\\", "x", "1", "b"})

    def test_display_path_redacts_and_escapes_in_one_shared_helper(self):
        secret = "SHARED_HELPER_SECRET"
        shown = playerlist_module.display_path(f"https://user:{secret}@example.invalid/a\nb")
        self.assertNotIn(secret, shown)
        self.assertIn("REDACTED", shown)
        self.assertNotIn("\n", shown)

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
        shown.encode("utf-8")  # The escaped path remains UTF-8 encodable.

    def test_a_very_long_path_is_clipped(self):
        shown = display_path("/tmp/" + "d" * 5_000)
        self.assertEqual(len(shown), MAX_SHOWN_PATH_CHARS + 1)
        self.assertTrue(shown.endswith("…"))

    def test_bare_secrets_and_url_credentials_are_redacted_before_clipping(self):
        nested_secret = "NESTED_ENCODED_PATH_SECRET"
        nested_url = f"https://user:{nested_secret}@client.invalid/cb?access_token={nested_secret}"
        for safe in ("?=&", ".:", ".:", "/"):
            nested_url = urllib.parse.quote(nested_url, safe=safe)
        nested_path = "https://outer.invalid/?redirect=" + urllib.parse.quote(nested_url, safe="")

        for value, secret in (
            ("access_token=BARE_TOKEN_SECRET", "BARE_TOKEN_SECRET"),
            ("Authorization: Bearer HEADER_TOKEN_SECRET", "HEADER_TOKEN_SECRET"),
            ("Bearer STANDALONE_BEARER_SECRET", "STANDALONE_BEARER_SECRET"),
            ("https:/user:URL_PASSWORD_SECRET@example.invalid/list.json", "URL_PASSWORD_SECRET"),
            (
                "https:/user:LONG_URL_PASSWORD_SECRET" + "x" * 180 + "@example.invalid/list.json",
                "LONG_URL_PASSWORD_SECRET",
            ),
            (
                "https%3A%2F%2Fuser%3AENCODED_PATH_SECRET%40example.invalid%2Flist.json",
                "ENCODED_PATH_SECRET",
            ),
            (nested_path, nested_secret),
        ):
            with self.subTest(value=value):
                shown = display_path(value)
                self.assertNotIn(secret, shown)
                self.assertTrue("REDACTED" in shown or "omitted" in shown)

        benign_encoded = "https%3A%2F%2Fclient.invalid%2Fcallback"
        self.assertEqual(display_path(benign_encoded), benign_encoded)
        self.assertIn(
            "too long to inspect safely",
            display_path("https%3A%2F%2Fclient.invalid%2F" + "x" * MAX_SHOWN_PATH_CHARS),
        )
        deep_marker = "https%" + "25" * (playerlist_module._MAX_DIAGNOSTIC_DECODE_DEPTH + 2) + "3a"
        self.assertIn(
            "too deep to inspect safely",
            playerlist_module._redact_diagnostic_preview(deep_marker, len(deep_marker)),
        )

    def test_a_percent_encoded_field_name_cannot_hide_its_value(self):
        # A key can encode its own separator, so the raw spelling never looks
        # like a field name. Both the raw and the decoded spelling must redact.
        cases = (
            "?to%0Aken=ENCODED_KEY_SECRET",
            "?to%256ben=DOUBLE_ENCODED_KEY_SECRET",
            "?to%2520ken=SPACE_ENCODED_KEY_SECRET",
            "?to%09ken=TAB_ENCODED_KEY_SECRET",
            "?%74oken=PLAINLY_ENCODED_KEY_SECRET",
            "#access_token=FRAGMENT_KEY_SECRET",
        )
        for value in cases:
            with self.subTest(value=value):
                secret = value.rsplit("=", 1)[1]
                shown = display_path(value)
                self.assertNotIn(secret, shown)
                self.assertIn("REDACTED", shown)

    def test_a_field_name_that_never_finishes_decoding_fails_closed(self):
        # Nested escapes deeper than the decode budget: no guess, but no plain
        # name either, so the value is left alone rather than mis-parsed.
        deep = "%" + "25" * (playerlist_module._MAX_DIAGNOSTIC_DECODE_DEPTH + 4) + "74oken"
        self.assertIsNone(playerlist_module._normalized_field_name(deep))
        # And a name that decodes to something that is not a field name at all.
        self.assertIsNone(playerlist_module._normalized_field_name("tok%3Aen"))
        self.assertIsNone(playerlist_module._normalized_field_name("a/b"))
        # Plain names still decode to themselves.
        self.assertEqual(playerlist_module._normalized_field_name("access_token"), "access_token")
        self.assertEqual(playerlist_module._normalized_field_name("to%0Aken"), "token")

    def test_an_encoded_benign_key_is_left_alone(self):
        for value in ("?q=hello", "?ref=ma%69n", "/a%20b/list.json"):
            with self.subTest(value=value):
                self.assertEqual(display_path(value), value)

    def test_an_empty_quoted_value_does_not_shadow_the_real_secret(self):
        # ``password=''SECRET`` used to redact the empty body and leave SECRET.
        for value, secret in (
            ("access_token:''EMPTY_QUOTED_SECRET'", "EMPTY_QUOTED_SECRET"),
            ('access_token=""EMPTY_DQUOTED_SECRET"', "EMPTY_DQUOTED_SECRET"),
        ):
            with self.subTest(value=value):
                shown = display_path(value)
                self.assertNotIn(secret, shown)
                self.assertIn("REDACTED", shown)

    def test_ordinary_english_after_bearer_or_basic_is_not_redacted(self):
        # These words are ordinary English, and this redactor runs over player
        # names on their way into the published report, so redacting them would
        # rename innocent players in the output.
        for name in (
            "Bearer of bad news",
            "bearer of the flame",
            "Bearer Token King",
            "Basic Instinct",
            "The Bearer",
            "a Bearer",
        ):
            with self.subTest(name=name):
                self.assertEqual(redact_diagnostic_text(name), name)

    def test_a_bearer_credential_is_still_redacted_whatever_it_looks_like(self):
        for value, secret in (
            ("Bearer S3CRET", "S3CRET"),
            ("Bearer = S3CRET", "S3CRET"),
            ("Bearer: S3CRET", "S3CRET"),
            ("bearer  =  'S3CRET'", "S3CRET"),
            ("Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
            ("Bearer eyJhbGciOi.eyJzdWIi.SflK", "eyJhbGciOi"),
            ("Bearer HUNTER2", "HUNTER2"),
        ):
            with self.subTest(value=value):
                shown = redact_diagnostic_text(value)
                self.assertNotIn(secret, shown)
                self.assertIn("REDACTED", shown)

    def test_a_bearer_scheme_with_a_separator_still_redacts_its_credential(self):
        for value, secret in (
            ("Bearer = EQUALS_BEARER_SECRET", "EQUALS_BEARER_SECRET"),
            ("Bearer: COLON_BEARER_SECRET", "COLON_BEARER_SECRET"),
            ("Basic BASIC_AUTH_SECRET", "BASIC_AUTH_SECRET"),
        ):
            with self.subTest(value=value):
                shown = display_path(value)
                self.assertNotIn(secret, shown)
                self.assertIn("REDACTED", shown)
        # A lone scheme with nothing after it stays readable.
        self.assertEqual(display_path("a Bearer"), "a Bearer")

    def test_bare_secret_pair_parser_handles_quoted_empty_and_punctuated_values(self):
        cases = (
            ("access_token   =   SPACED_SECRET", "SPACED_SECRET", "access_token   =   REDACTED"),
            ('"access_token": "JSON_VALUE_SECRET"', "JSON_VALUE_SECRET", '"access_token": REDACTED'),
            ('"client_secret":"value\\"STILL_SECRET"', "STILL_SECRET", '"client_secret":REDACTED'),
            ('"client_secret":"', "", '"client_secret":REDACTED'),
            ("access_token=...", "...", "access_token=REDACTED"),
            ("access_token=TRAILING_SECRET.", "TRAILING_SECRET", "access_token=REDACTED."),
            ("access_token=TRAILING_SECRET).", "TRAILING_SECRET", "access_token=REDACTED)."),
            ("access_token=LEFT#RIGHT]TAIL", "LEFT#RIGHT]TAIL", "access_token=REDACTED"),
            ("access_token=", "", "access_token="),
            ("access_token=&ref=main", "", "access_token=&ref=main"),
        )
        for value, secret, safe in cases:
            with self.subTest(value=value):
                shown = playerlist_module.redact_diagnostic_text(value)
                self.assertEqual(shown, safe)
                if secret:
                    self.assertNotIn(secret, shown)

    def test_a_path_that_is_not_a_string_still_works(self):
        self.assertEqual(display_path(Path("/tmp/x.json")), "/tmp/x.json")


class ValidateTests(unittest.TestCase):
    def test_a_huge_integer_steamid_is_a_bounded_validation_error_not_a_crash(self):
        result = validate({"players": [{"steamid": 10**5000, "attributes": ["cheater"]}]})
        self.assertEqual(result.error_count, 1)
        self.assertIn("unusable steamid", result.errors[0])
        self.assertIn("integer too large to display", result.errors[0])
        self.assertLessEqual(len(result.errors[0]), 200)

    def test_validation_keeps_exact_counts_but_bounds_logged_details(self):
        players = [{"steamid": "not-a-steamid", "attributes": []} for _ in range(120)]
        result = validate({"players": players})
        self.assertEqual(len(result.errors), MAX_VALIDATION_MESSAGES)
        self.assertEqual(result.errors_omitted, 240 - MAX_VALIDATION_MESSAGES)
        self.assertEqual(result.error_count, 240)
        self.assertFalse(result)

        warnings = validate(
            {
                "players": [
                    {
                        "steamid": "[U:1:1]",
                        "attributes": [f"unknown-{index}" for index in range(MAX_VALIDATION_MESSAGES + 7)],
                    }
                ]
            }
        )
        self.assertEqual(len(warnings.warnings), MAX_VALIDATION_MESSAGES)
        self.assertEqual(warnings.warnings_omitted, 7)
        self.assertEqual(warnings.warning_count, MAX_VALIDATION_MESSAGES + 7)
        self.assertTrue(warnings)

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
        for proof in (None, "a link", {"url": "https://example.invalid"}, ["valid", 1]):
            with self.subTest(proof=proof):
                result = validate({"players": [{"steamid": "[U:1:1]", "attributes": ["cheater"], "proof": proof}]})
                self.assertTrue(any("malformed 'proof'" in error for error in result.errors))
        result = validate({"players": [{"steamid": "[U:1:1]", "attributes": ["cheater"]}]})
        self.assertFalse(any("malformed 'proof'" in error for error in result.errors))

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
