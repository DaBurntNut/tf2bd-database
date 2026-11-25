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

    def test_account_id_one_is_the_lowest_usable_steamid(self):
        """The test above pins the id just below the range; this pins the first
        id inside it, in every notation. Without it, narrowing either range
        check to ``1 < account`` passes the entire suite while quietly dropping
        a real player from the list.
        """
        from playerlist import STEAMID64_BASE

        for probe in (
            1,
            "1",
            "0000000001",
            "[U:1:1]",
            "U:1:1",
            "[U:1:1:0]",
            "STEAM_0:1:0",
            STEAMID64_BASE + 1,
            str(STEAMID64_BASE + 1),
            f"https://steamcommunity.com/profiles/{STEAMID64_BASE + 1}",
        ):
            with self.subTest(probe=probe):
                self.assertEqual(normalize_steamid(probe), "[U:1:1]")

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

    def test_a_quoted_secret_is_redacted_whole_even_when_it_holds_a_delimiter(self):
        """A quoted value runs to its closing quote, not to the first space or
        comma inside it. Scanning it as though it were unquoted would stop at
        the delimiter and leave the tail of the secret -- and a stray quote --
        in the message.
        """
        for value, expected in (
            ('password="a b"', "password=REDACTED"),
            ("token='a,b'", "token=REDACTED"),
            ('secret="a;b"', "secret=REDACTED"),
            ('api_key="a&b"', "api_key=REDACTED"),
            ('password="a\tb"', "password=REDACTED"),
        ):
            with self.subTest(value=value):
                self.assertEqual(display_path(value), expected)

    def test_a_backslash_escape_does_not_end_a_quoted_secret_early(self):
        """An escaped quote is part of the value; an escaped backslash is not an
        escape for the quote that follows it. Getting either wrong ends the
        value at the wrong character and prints the rest of the secret.
        """
        for value, expected in (
            ('token="a\\"b c"', "token=REDACTED"),
            ('key:"a\\\\".', "key:REDACTED."),
            ("token='\\\\'&z=1", "token=REDACTED&z=1"),
            ('api_key="a\\\\\\\\"', "api_key=REDACTED"),
        ):
            with self.subTest(value=value):
                self.assertEqual(display_path(value), expected)

    def test_an_unterminated_quoted_secret_is_redacted_to_the_end(self):
        """A value whose quote never closes runs to the end of the text, and it
        stays a QUOTED span: the trailing-punctuation rule that would hand back
        a final ``.`` or ``!`` applies to bare values only. Treating the span as
        bare here would print the last character of the secret.
        """
        for value, expected in (
            ('key:"abc.', "key:REDACTED"),
            ('token="secret!', "token=REDACTED"),
            ('password="a b.', "password=REDACTED"),
            ("api_key='x,", "api_key=REDACTED"),
        ):
            with self.subTest(value=value):
                self.assertEqual(display_path(value), expected)

    def test_an_unquoted_secret_ends_at_the_delimiter_and_keeps_the_rest(self):
        """The counterpart to the quoted cases: a bare value stops at the first
        delimiter, and whatever follows it is ordinary text that must survive.
        """
        for value, expected in (
            ("api_key=a)b more", "api_key=REDACTED more"),
            ("token=a,b", "token=REDACTED,b"),
            ('token="x".', "token=REDACTED."),
            ("password:''.", "password:REDACTED."),
        ):
            with self.subTest(value=value):
                self.assertEqual(display_path(value), expected)

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

    def test_a_credential_name_spelled_as_character_references_is_still_matched(self):
        """``&#116;&#111;&#107;&#101;&#110;`` is ``token``, and matched no field name.

        Percent-encoding of the same trick was already decoded before matching.
        A database value carrying this reached the console -- and so a public
        job log -- with the secret intact.
        """
        secret = "ENTITY_NAME_SECRET"
        for value in (
            f"https://h.invalid/p?&#116;&#111;&#107;&#101;&#110;={secret}",
            f"https://h.invalid/p?&#x74;&#x6f;&#x6b;&#x65;&#x6e;={secret}",
            f"https://h.invalid/p?&amp;#116;&amp;#111;&amp;#107;&amp;#101;&amp;#110;={secret}",
        ):
            with self.subTest(value=value):
                shown = redact_diagnostic_text(value)
                self.assertNotIn(secret, shown)
                self.assertIn("REDACTED", shown)

    def test_character_references_in_ordinary_text_are_left_as_the_author_wrote_them(self):
        """Only a reference that *hides a credential* may change the spelling."""
        for value in ("a &amp; b", "Tom &lt;3", "see &#9731; snowman", "&amp;&amp;&amp;"):
            with self.subTest(value=value):
                self.assertEqual(redact_diagnostic_text(value), value)

    def test_decoding_stops_at_the_depth_limit_without_rewriting_harmless_text(self):
        """``&amp;amp;...`` peels one layer per pass and never reveals a secret.

        The decode loop has to end somewhere; when it ends by exhausting the
        limit rather than by settling, the text the author wrote is what gets
        printed -- there is no credential here to justify a different spelling.
        """
        nested = "&" + "amp;" * (playerlist_module._MAX_DIAGNOSTIC_DECODE_DEPTH + 4) + "x"
        self.assertEqual(redact_diagnostic_text(nested), nested)

    def test_a_blank_in_userinfo_cannot_hide_a_password_from_a_diagnostic(self):
        """A blank ends the single-token scan before its ``@``; the span must still go.

        This is the diagnostic twin of ``sources._SPLIT_USERINFO_IN_TEXT``: an
        unusable database value is previewed into the log, so the same shapes
        have to be caught here.
        """
        secret = "DIAGNOSTIC_BLANK_USERINFO_SECRET"
        for blank in (" ", "\t", "\n", "\r"):
            for template in (
                f"https://u x:{secret}@h.invalid/p",
                f"https:u x:{secret}@h.invalid/p",
                f"//u x:{secret}@h.invalid/p",
                f"https://u x%3a{secret}%40h.invalid/p",
                f"https://u x:{secret}%2540h.invalid/p",
            ):
                value = template.replace(" ", blank)
                with self.subTest(value=value):
                    shown = redact_diagnostic_text(value)
                    self.assertNotIn(secret, shown)
                    self.assertIn("REDACTED", shown)

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
                    {"steamid": "[U:1:2]", "attributes": ["not-a-real-attribute\nINFO: all good\x1b[0m"]},
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
        # Any string that is not one of KNOWN_ATTRIBUTES will do; it is spelled
        # out here so nobody mistakes it for a tag this project recognises.
        result = validate({"players": [{"steamid": "[U:1:1]", "attributes": ["not-a-real-attribute"]}]})
        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.warnings), 1)


class DeclaredSchemaTests(unittest.TestCase):
    """The playerlist files name a TF2BD schema; warn where they do not meet it.

    ``normalize_steamid`` reads legacy and SteamID64 spellings on purpose, so
    an upstream list in any format can be matched. A database that *stores*
    one of those spellings still loads here but fails validation in an editor
    pointed at the schema the file itself declares. Every check below is a
    warning: none of them stops a sync.
    """

    def _only_warnings(self, entry):
        result = validate({"players": [entry]})
        self.assertEqual(result.errors, [], "a shape issue must never block a sync")
        return result.warnings

    def test_a_steamid_spelling_the_schema_rejects_is_flagged(self):
        for spelling in (
            "STEAM_0:1:123",
            "STEAM_1:0:456",
            "76561197960531246",
            "https://steamcommunity.com/profiles/76561197960531246",
            "U:1:123",
        ):
            with self.subTest(steamid=spelling):
                warnings = self._only_warnings({"steamid": spelling, "attributes": ["cheater"]})
                self.assertTrue(
                    any("declared schema rejects" in w for w in warnings),
                    f"{spelling} is stored in a form the schema forbids: {warnings}",
                )

    def test_the_canonical_spellings_are_not_flagged(self):
        for spelling in ("[U:1:123]", "[U:1:123:2]", 76561197960531246):
            with self.subTest(steamid=spelling):
                self.assertEqual(self._only_warnings({"steamid": spelling, "attributes": ["cheater"]}), [])

    def test_a_non_player_account_type_stays_a_hard_error(self):
        """Here the tool is deliberately stricter than the schema it declares.

        The schema's SteamID pattern accepts any letter, so ``[G:1:4]`` (a
        group) and ``[A:1:4]`` (an anonymous account) satisfy it. Neither is a
        player, so neither belongs in a playerlist, and the tool cannot reason
        about an entry it cannot resolve to a person: that is an error that
        stops the run, not a cosmetic warning.
        """
        for spelling in ("[A:1:123]", "[G:1:123]", "[C:1:123]", "[P:1:123]"):
            with self.subTest(steamid=spelling):
                result = validate({"players": [{"steamid": spelling, "attributes": ["cheater"]}]})
                self.assertEqual(len(result.errors), 1, result.errors)
                self.assertIn("unusable steamid", result.errors[0])

    def test_an_unusable_steamid_is_one_complaint_not_two(self):
        """The error already names the field; a spelling warning adds nothing.

        One problem per field is the rule the rest of the validator follows.
        """
        for spelling in ("not-a-steamid", "", "-5", "[G:1:123]", 0, {"a": 1}, []):
            with self.subTest(steamid=spelling):
                result = validate({"players": [{"steamid": spelling, "attributes": ["cheater"]}]})
                self.assertEqual(len(result.errors), 1, result.errors)
                self.assertEqual(result.warnings, [], "the error already covers this field")

    def test_a_steamid_warning_names_the_canonical_form_to_use(self):
        (warning,) = self._only_warnings({"steamid": "STEAM_0:1:123", "attributes": ["cheater"]})
        self.assertIn("expected [U:1:247]", warning)

    def test_last_seen_must_carry_an_integer_time(self):
        for last_seen in ({"player_name": "x"}, {"time": "1"}, {"time": 1.5}, {"time": True}, {"time": None}):
            with self.subTest(last_seen=last_seen):
                warnings = self._only_warnings(
                    {"steamid": "[U:1:1]", "attributes": ["cheater"], "last_seen": last_seen}
                )
                self.assertTrue(any("integer 'time'" in w for w in warnings), warnings)

    def test_a_well_formed_last_seen_is_silent(self):
        for last_seen in ({"time": 1}, {"time": 1, "player_name": "x"}, {"time": 0}):
            with self.subTest(last_seen=last_seen):
                self.assertEqual(
                    self._only_warnings({"steamid": "[U:1:1]", "attributes": ["cheater"], "last_seen": last_seen}),
                    [],
                )

    def test_a_non_string_player_name_is_flagged_but_still_renders(self):
        """The report prints whatever is there; the schema still wants a string."""
        for value in (7, None, ["x"], {"a": 1}, True):
            with self.subTest(player_name=value):
                entry = {
                    "steamid": "[U:1:1]",
                    "attributes": ["cheater"],
                    "last_seen": {"time": 1, "player_name": value},
                }
                warnings = self._only_warnings(entry)
                self.assertTrue(any("non-string 'last_seen.player_name'" in w for w in warnings), warnings)
                playerlist_module.player_name(entry)

    def test_unexpected_keys_are_named(self):
        warnings = self._only_warnings(
            {"steamid": "[U:1:1]", "attributes": ["cheater"], "notes": "x", "last_seen": {"time": 1, "zz": 2}}
        )
        self.assertTrue(any("unexpected key: 'notes'" in w for w in warnings), warnings)
        self.assertTrue(any("unexpected 'last_seen' key: 'zz'" in w for w in warnings), warnings)

    def test_a_missing_last_seen_is_fine(self):
        """It is optional in the schema, and most of a hand-built list omits it."""
        self.assertEqual(self._only_warnings({"steamid": "[U:1:1]", "attributes": ["cheater"]}), [])

    def test_a_malformed_last_seen_does_not_also_crash_the_name_lookup(self):
        for last_seen in ("nope", 7, None, []):
            with self.subTest(last_seen=last_seen):
                entry = {"steamid": "[U:1:1]", "attributes": ["cheater"], "last_seen": last_seen}
                self.assertTrue(self._only_warnings(entry))
                self.assertEqual(playerlist_module.player_name(entry), "")


class ShippedDataMatchesItsDeclaredSchemaTests(unittest.TestCase):
    """The file the bot writes must satisfy the schema it points at.

    The bot only ever rewrites ``attributes``, so a violation here means a
    hand edit introduced one. Catching it in CI is the whole point: the
    maintainer's editor would show it, but a commit need not go through one.
    """

    ROOT = Path(__file__).resolve().parent.parent
    # Only the file the bot actually syncs. The other lists in this repository
    # are the maintainer's to edit freely; nothing here may fail because of one.
    DATABASE = "playerlist.garou3299.json"
    SCHEMA_URL = "https://raw.githubusercontent.com/PazerOP/tf2_bot_detector/master/schemas/v3/playerlist.schema.json"
    # The v3 playerlist schema sets additionalProperties:false at the top level.
    TOP_LEVEL_KEYS = frozenset({"$schema", "file_info", "players"})

    def _load(self):
        return json.loads((self.ROOT / self.DATABASE).read_text(encoding="utf-8"))

    def test_the_database_declares_the_schema_it_is_written_against(self):
        """``$schema`` is required, and it is what makes the file self-describing.

        ``validate()`` cannot own this rule: nearly every fixture in this suite
        is a bare ``{"players": [...]}``, and warning there would be noise in
        636 tests to catch one edit to one real file. Guard the real file.
        """
        self.assertEqual(self._load().get("$schema"), self.SCHEMA_URL)

    def test_the_database_carries_no_top_level_key_the_schema_forbids(self):
        self.assertEqual(set(self._load()) - self.TOP_LEVEL_KEYS, set())

    def test_the_database_has_a_players_array(self):
        self.assertIsInstance(self._load().get("players"), list)

    def test_the_synced_database_has_no_schema_warnings_at_all(self):
        result = validate(self._load())
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [], "the file declares a schema it no longer matches")


if __name__ == "__main__":
    unittest.main(verbosity=2)
