#!/usr/bin/env python3
"""Tests for the monthly Python version check.

This bot's whole job is to decide, unattended, that a new runtime is safe for
the one that rewrites a published database. The decision it must never get
wrong is the false "yes": proposing a version a tool does not support. Most of
what follows pushes it toward "no" -- missing classifiers, prereleases,
malformed metadata -- and checks it stays there.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import io
import json
import logging
import random
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _support  # noqa: F401  (puts scripts/ on sys.path and isolates GITHUB_OUTPUT)

import python_version_check as checker
from sources import SyncError

MANIFEST_URL = checker.MANIFEST_URL

WORKFLOW = 'on:\n  schedule: []\n\nenv:\n  PYTHON_VERSION: "3.12"\n\njobs:\n  checks:\n'
PINS = '[dependency-groups]\nci = [\n    "ruff==0.17.6",\n    "mypy==2.4.1",\n]\n\n[tool.ruff]\n'


@contextlib.contextmanager
def quiet_logger():
    """Keep the check's own logging out of the test runner's output."""
    logging.disable(logging.CRITICAL)
    try:
        yield
    finally:
        logging.disable(logging.NOTSET)


def manifest(*releases: str, stable: bool | str = True) -> bytes:
    """A runner-image manifest listing the given releases."""
    return json.dumps([{"version": release, "stable": stable} for release in releases]).encode()


def pypi(*series: str) -> bytes:
    """A PyPI response whose classifiers claim support for the given series."""
    classifiers = [f"Programming Language :: Python :: {item}" for item in series]
    return json.dumps({"info": {"classifiers": classifiers}}).encode()


def fetcher(manifest_body: bytes, **tools: bytes):
    """A fetch function answering the manifest and each tool URL from memory."""

    def fetch(url: str) -> bytes:
        if url == MANIFEST_URL:
            return manifest_body
        for name, body in tools.items():
            if f"/{name}/" in url:
                return body
        raise AssertionError(f"unexpected fetch: {url}")

    return fetch


class DecisionTests(unittest.TestCase):
    """What the check proposes, given what the tools claim."""

    def gather(self, releases, ruff, mypy, workflow=WORKFLOW):
        return checker.gather(workflow, PINS, fetcher(manifest(*releases), ruff=pypi(*ruff), mypy=pypi(*mypy)))

    def test_it_proposes_the_newest_version_every_tool_supports(self):
        decision = self.gather(["3.12.16", "3.13.9", "3.14.10"], ["3.13", "3.14"], ["3.13", "3.14"])
        self.assertEqual(decision.target, "3.14")
        self.assertTrue(decision.upgrade)

    def test_it_skips_a_version_rather_than_stepping_through_every_one(self):
        """3.12 -> 3.14 directly. Nothing is owed to 3.13 for having existed."""
        decision = self.gather(["3.12.16", "3.13.9", "3.14.10"], ["3.12", "3.14"], ["3.12", "3.14"])
        self.assertEqual(decision.target, "3.14")

    def test_one_unsupported_tool_blocks_the_upgrade(self):
        decision = self.gather(["3.12.16", "3.14.10"], ["3.12", "3.14"], ["3.12"])
        self.assertIsNone(decision.target)
        self.assertFalse(decision.upgrade)

    def test_it_falls_back_to_the_newest_version_all_tools_do_support(self):
        decision = self.gather(["3.12.16", "3.13.9", "3.14.10"], ["3.13", "3.14"], ["3.13"])
        self.assertEqual(decision.target, "3.13")

    def test_it_proposes_nothing_when_already_current(self):
        decision = self.gather(["3.12.16"], ["3.12"], ["3.12"])
        self.assertIsNone(decision.target)
        self.assertIsNone(decision.candidate)

    def test_it_never_proposes_a_downgrade(self):
        """A yanked release or a shrunken manifest must not walk the bot back."""
        workflow = WORKFLOW.replace("3.12", "3.14")
        decision = self.gather(["3.12.16", "3.13.9"], ["3.12", "3.13"], ["3.12", "3.13"], workflow=workflow)
        self.assertIsNone(decision.target)

    def test_a_tool_that_publishes_no_classifiers_blocks_the_upgrade(self):
        """Silence is not consent. No claim of support reads as "not yet"."""
        fetch = fetcher(manifest("3.12.16", "3.14.10"), ruff=pypi("3.12", "3.14"), mypy=b'{"info": {}}')
        self.assertIsNone(checker.gather(WORKFLOW, PINS, fetch).target)

    def test_prereleases_are_not_offered(self):
        """``stable`` must be exactly True, never merely truthy."""
        fetch = fetcher(
            manifest("3.12.16", "3.15.0", stable="true"), ruff=pypi("3.12", "3.15"), mypy=pypi("3.12", "3.15")
        )
        with self.assertRaises(SyncError):
            checker.gather(WORKFLOW, PINS, fetch)

    def test_a_mixed_manifest_keeps_only_the_stable_entries(self):
        body = json.dumps(
            [
                {"version": "3.12.16", "stable": True},
                {"version": "3.15.0", "stable": False},
                {"version": "3.15.1", "stable": "yes"},
            ]
        ).encode()
        decision = checker.gather(WORKFLOW, PINS, fetcher(body, ruff=pypi("3.12", "3.15"), mypy=pypi("3.12", "3.15")))
        self.assertIsNone(decision.target)
        self.assertEqual(decision.newest, "3.12")

    def test_it_reports_the_newest_patch_of_a_series(self):
        decision = self.gather(["3.14.1", "3.14.10", "3.14.9"], ["3.14"], ["3.14"])
        self.assertEqual(decision.releases["3.14"], "3.14.10")

    def test_series_are_compared_as_numbers_not_strings(self):
        """String order puts 3.9 above 3.10; that would freeze the bot forever."""
        decision = self.gather(["3.9.22", "3.10.18"], ["3.9", "3.10"], ["3.9", "3.10"])
        self.assertEqual(decision.newest, "3.10")

    def test_support_is_read_for_the_pinned_version_not_the_newest(self):
        """CI installs the pin, so the pin is what has to support the runtime."""
        seen: list[str] = []

        def fetch(url: str) -> bytes:
            seen.append(url)
            return manifest("3.12.16") if url == MANIFEST_URL else pypi("3.12")

        checker.gather(WORKFLOW, PINS, fetch)
        self.assertIn(checker.PYPI_URL.format(name="ruff", version="0.17.6"), seen)
        self.assertIn(checker.PYPI_URL.format(name="mypy", version="2.4.1"), seen)


class BadInputTests(unittest.TestCase):
    """Every remote document is hostile until parsed. Fail loudly, never silently."""

    def test_a_manifest_that_is_not_a_list_is_an_error(self):
        with self.assertRaises(SyncError):
            checker.newest_releases({"versions": []})

    def test_a_manifest_with_no_stable_release_is_an_error(self):
        with self.assertRaises(SyncError):
            checker.newest_releases([{"version": "3.15.0", "stable": False}])

    def test_junk_version_strings_are_ignored(self):
        self.assertEqual(
            checker.newest_releases([{"version": "3.14", "stable": True}, {"version": "3.14.2", "stable": True}]),
            {"3.14": "3.14.2"},
        )

    def test_unreadable_json_names_the_source(self):
        with self.assertRaises(SyncError) as caught:
            checker.gather(WORKFLOW, PINS, lambda url: b"<html>not json</html>")
        self.assertIn("readable JSON", str(caught.exception))

    def test_a_parser_recursion_error_is_an_error_and_not_a_traceback(self):
        """RecursionError is not a ValueError, so it has to be named explicitly.

        Both other callers of strict_json_loads in this repository catch it.
        If this one does not, a nested body from the network leaves the runner
        a traceback instead of the exit code and message every other bad
        response produces -- and the difference is invisible until it happens.

        The parser is replaced rather than fed a deeply nested document on
        purpose. How deep a document has to be before CPython gives up is an
        interpreter detail: it changed in 3.12 when the C recursion limit was
        split out, and again in 3.14. A test that provokes the error by
        nesting reports a perfectly good guard as broken on the next runtime
        that raises its limit -- which is precisely the upgrade this very
        script exists to propose. The contract being pinned here is "the
        parser raising RecursionError becomes a named SyncError", and that
        does not depend on any of it.
        """
        original = checker.strict_json_loads

        def refuse(raw: str | bytes) -> object:
            raise RecursionError("maximum recursion depth exceeded while decoding a JSON array")

        checker.strict_json_loads = refuse
        try:
            with self.assertRaises(SyncError) as caught:
                checker._decode_json(b"[]", "https://example.test/manifest.json")
        finally:
            checker.strict_json_loads = original
        self.assertIn("readable JSON", str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, RecursionError)

    def test_every_strict_json_caller_in_the_repository_catches_the_same_errors(self):
        """The three call sites must agree, because they fail the same way.

        Named rather than inferred: a fourth caller is the likely future, and
        a reader comparing them should find the list in one place.
        """
        root = Path(__file__).resolve().parent.parent / "scripts"
        sources_ = {path: path.read_text(encoding="utf-8") for path in sorted(root.glob("*.py"))}
        callers = {path: text for path, text in sources_.items() if "strict_json_loads(" in text}
        self.assertGreaterEqual(len(callers), 3)
        for path, text in callers.items():
            with self.subTest(module=path.name):
                # assertTrue, not assertIn: assertIn prints the haystack, and
                # the haystack here is a thousand-line module.
                self.assertTrue(
                    "RecursionError" in text,
                    f"{path.name} parses JSON without catching RecursionError",
                )

    def test_pypi_metadata_without_info_is_an_error(self):
        with self.assertRaises(SyncError):
            checker.supported_series({}, "ruff")

    def test_pypi_metadata_that_is_not_an_object_is_an_error(self):
        with self.assertRaises(SyncError):
            checker.supported_series([], "ruff")

    def test_non_string_classifiers_do_not_crash_the_check(self):
        self.assertEqual(checker.supported_series({"info": {"classifiers": [None, 3, "x"]}}, "ruff"), frozenset())

    def test_classifiers_that_are_not_a_list_read_as_no_support(self):
        self.assertEqual(checker.supported_series({"info": {"classifiers": "3.14"}}, "ruff"), frozenset())

    def test_implementation_classifiers_are_not_mistaken_for_versions(self):
        metadata = {
            "info": {
                "classifiers": [
                    "Programming Language :: Python :: 3",
                    "Programming Language :: Python :: 3.14",
                    "Programming Language :: Python :: Implementation :: CPython",
                ]
            }
        }
        self.assertEqual(checker.supported_series(metadata, "ruff"), frozenset({"3.14"}))

    def test_a_missing_dependency_group_is_an_error(self):
        with self.assertRaises(SyncError):
            checker.pinned_tools("[tool.ruff]\nline-length = 120\n")

    def test_an_empty_dependency_group_is_an_error(self):
        with self.assertRaises(SyncError):
            checker.pinned_tools("[dependency-groups]\nci = [\n]\n")

    def test_a_requirement_it_cannot_read_stops_the_check(self):
        """Regression. These were silently skipped, which is the unsafe answer.

        A tool missing from the table is a tool whose opinion was never asked,
        and the upgrade would then be proposed on the word of the pins that
        happened to be legible. Stopping is the only safe response.
        """
        for label, entry in {
            "an extra": '"coverage[toml]==7.17.5"',
            "an environment marker": "\"mypy==2.4.1 ; python_version >= '3.9'\"",
            "a range rather than a pin": '"mypy>=2.4.1"',
            "a bare name": '"mypy"',
        }.items():
            with self.subTest(case=label), self.assertRaises(SyncError):
                checker.pinned_tools(f'[dependency-groups]\nci = [\n    "ruff==0.17.6",\n    {entry},\n]\n')

    def test_one_tool_pinned_twice_is_refused(self):
        """Last-one-wins would silently drop the first pin's verdict."""
        with self.assertRaises(SyncError):
            checker.pinned_tools('[dependency-groups]\nci = [\n    "ruff==0.17.6",\n    "ruff==0.18.0",\n]\n')

    def test_a_comment_is_not_mistaken_for_a_requirement(self):
        pins = '[dependency-groups]\nci = [\n    "ruff==0.17.6",  # the "fast" one\n    "mypy==2.4.1",\n]\n'
        self.assertEqual(checker.pinned_tools(pins), {"ruff": "0.17.6", "mypy": "2.4.1"})

    def test_an_absurd_number_of_pins_is_refused(self):
        pins = "".join(f'    "tool{index}==1.0",\n' for index in range(checker.MAX_TOOLS + 1))
        with self.assertRaises(SyncError):
            checker.pinned_tools(f"[dependency-groups]\nci = [\n{pins}]\n")

    def test_an_envelope_the_check_cannot_open_is_an_error(self):
        with self.assertRaises(SyncError) as caught:
            checker.fetch_manifest(lambda url: b'{"encoding": "none"}')
        self.assertIn("cannot read", str(caught.exception))

    def test_a_github_error_object_is_reported_with_its_message(self):
        """A 404 body is an object too; saying "envelope" would send the reader
        looking for a decoding problem that is not there."""
        with self.assertRaises(SyncError) as caught:
            checker.fetch_manifest(lambda url: b'{"message": "Not Found"}')
        self.assertIn("Not Found", str(caught.exception))

    def test_a_base64_envelope_is_unwrapped(self):
        payload = base64.b64encode(manifest("3.14.10")).decode()
        body = json.dumps({"encoding": "base64", "content": payload}).encode()
        self.assertEqual(checker.newest_releases(checker.fetch_manifest(lambda url: body)), {"3.14": "3.14.10"})


class WorkflowEditTests(unittest.TestCase):
    """The check edits a file that controls the bot's runtime. It edits one line."""

    def test_it_reads_the_pinned_version(self):
        self.assertEqual(checker.current_series(WORKFLOW), "3.12")

    def test_a_workflow_without_a_pin_is_an_error(self):
        with self.assertRaises(SyncError):
            checker.current_series("jobs:\n  checks:\n")

    def test_two_pins_are_an_error_rather_than_a_guess(self):
        with self.assertRaises(SyncError):
            checker.current_series(WORKFLOW + '\nenv:\n  PYTHON_VERSION: "3.13"\n')

    def test_the_rewrite_changes_exactly_one_line(self):
        updated = checker.rewrite_version(WORKFLOW, "3.14")
        before, after = WORKFLOW.splitlines(), updated.splitlines()
        self.assertEqual(len(before), len(after))
        differing = [index for index, (old, new) in enumerate(zip(before, after, strict=True)) if old != new]
        self.assertEqual(len(differing), 1)
        self.assertEqual(after[differing[0]], '  PYTHON_VERSION: "3.14"')

    def test_the_rewrite_writes_two_numbers_and_never_a_patch(self):
        """Pinning the patch would stop security releases arriving on their own."""
        updated = checker.rewrite_version(WORKFLOW, "3.14")
        self.assertIn('PYTHON_VERSION: "3.14"', updated)
        self.assertNotRegex(updated, r'PYTHON_VERSION: "\d+\.\d+\.\d+"')

    def test_the_rewrite_refuses_a_file_it_cannot_identify(self):
        with self.assertRaises(SyncError):
            checker.rewrite_version("nothing here\n", "3.14")


class ComparisonTests(unittest.TestCase):
    """The byte-for-byte proof. Its own failure modes matter as much as its verdict."""

    REPORT = "## Vorobey hackerpolice sync\n\n- Run at: 2026-12-01 06:00 UTC\n- Entries: 6,418\n"

    def test_identical_reports_compare_equal(self):
        other = self.REPORT.replace("06:00", "06:07")
        self.assertEqual(checker.compare_reports(self.REPORT, other), [])

    def test_a_changed_line_is_reported(self):
        other = self.REPORT.replace("6,418", "6,419")
        diff = checker.compare_reports(self.REPORT, other)
        self.assertTrue(any("6,419" in line for line in diff))

    def test_only_the_timestamp_line_is_ignored(self):
        """A date anywhere else in the report is still compared."""
        report = self.REPORT + "- Seen on 2026-12-01 06:00 UTC\n"
        other = report.replace("- Seen on 2026-12-01 06:00 UTC", "- Seen on 2027-01-01 06:00 UTC")
        self.assertNotEqual(checker.compare_reports(report, other), [])

    def test_a_missing_timestamp_raises_instead_of_masking_nothing(self):
        with self.assertRaises(SyncError):
            checker.mask_clock("## report\n", "test report")

    def test_a_duplicated_timestamp_raises_instead_of_masking_both(self):
        with self.assertRaises(SyncError):
            checker.mask_clock(self.REPORT + self.REPORT, "test report")

    def test_the_diff_is_capped(self):
        big = self.REPORT + "".join(f"- line {index}\n" for index in range(5000))
        diff = checker.compare_reports(self.REPORT, big)
        self.assertLessEqual(len(diff), checker.MAX_DIFF_LINES)

    def test_a_difference_a_line_diff_cannot_show_is_still_reported(self):
        """Regression. This check reported "identical" for differing files.

        ``str.splitlines()`` drops the terminator it split on and treats
        U+2028, U+000B and U+000C as line breaks, so these pairs produced
        identical line lists and an empty diff -- which the caller read as
        agreement. The verdict now comes from the masked strings themselves.

        U+2028 is not hypothetical here: this repository's own corpus uses it
        in player names, and names are rendered into the report.
        """
        cases = {
            "no trailing newline": self.REPORT.rstrip("\n"),
            "U+2028 line separator": self.REPORT.replace("- Entries: 6,418\n", "- Entries: 6,418\u2028"),
            "U+000B vertical tab": self.REPORT.replace("- Entries: 6,418\n", "- Entries: 6,418\u000b"),
            "U+000C form feed": self.REPORT.replace("- Entries: 6,418\n", "- Entries: 6,418\u000c"),
            "CR instead of LF": self.REPORT.replace("- Entries: 6,418\n", "- Entries: 6,418\r"),
        }
        for label, other in cases.items():
            with self.subTest(case=label):
                self.assertNotEqual(self.REPORT, other, "the fixture must actually differ")
                self.assertNotEqual(checker.compare_reports(self.REPORT, other), [])

    def test_the_readable_diff_is_only_ever_a_nicety(self):
        """The verdict must not depend on difflib producing output.

        ``splitlines(keepends=True)`` round-trips exactly, so two texts with
        equal line lists are equal texts -- which is what lets an empty diff
        be replaced by a description instead of being trusted.
        """
        alphabet = "ab\n\r\u2028\u2029\u000b\u000c\u0085 "
        random.seed(20261114)
        for _ in range(2000):
            text = "".join(random.choice(alphabet) for _ in range(random.randrange(12)))
            self.assertEqual("".join(text.splitlines(keepends=True)), text)

    def test_the_description_points_at_the_offset(self):
        diff = checker.compare_reports(self.REPORT, self.REPORT.rstrip("\n"))
        self.assertTrue(any("first difference at character" in line for line in diff))
        self.assertTrue(any("lengths:" in line for line in diff))


class CommandLineTests(unittest.TestCase):
    """Exit codes are the only thing the workflow reads."""

    def invoke(self, args, *fetch):
        """Call run() with its report and logging captured, as the other suites do.

        Not named run(): that is TestCase's own method, and overriding it hands
        the framework's result object to the code under test.
        """
        with contextlib.redirect_stdout(io.StringIO()), quiet_logger():
            return checker.run(args, *fetch)

    def args(self, **overrides):
        defaults = {
            "workflow": Path("w.yml"),
            "pins": Path("p.toml"),
            "report": None,
            "write": False,
            "compare": None,
            "quiet": True,
        }
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def test_an_unreadable_file_exits_two(self):
        with mock.patch.object(checker, "run", side_effect=SyncError("nope")), quiet_logger():
            self.assertEqual(checker.main([]), 2)

    def test_an_interrupt_exits_one_hundred_and_thirty(self):
        with mock.patch.object(checker, "run", side_effect=KeyboardInterrupt), quiet_logger():
            self.assertEqual(checker.main([]), 130)

    def test_a_failed_check_is_never_silent(self):
        """Rule: if the checker cannot run, the run goes red."""
        with (
            mock.patch.object(checker, "run", side_effect=SyncError("PyPI unreachable")),
            self.assertLogs(checker.LOGGER, level="ERROR") as logs,
        ):
            self.assertEqual(checker.main([]), 2)
        self.assertTrue(any("PyPI unreachable" in line for line in logs.output))

    def test_compare_exits_zero_when_identical(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = "## r\n- Run at: 2026-12-01 06:00 UTC\n"
            (root / "a.md").write_text(report, encoding="utf-8")
            (root / "b.md").write_text(report.replace("06:00", "06:09"), encoding="utf-8")
            self.assertEqual(self.invoke(self.args(compare=[root / "a.md", root / "b.md"])), 0)

    def test_compare_exits_one_when_the_reports_differ(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.md").write_text("## r\n- Run at: 2026-12-01 06:00 UTC\n- x\n", encoding="utf-8")
            (root / "b.md").write_text("## r\n- Run at: 2026-12-01 06:00 UTC\n- y\n", encoding="utf-8")
            self.assertEqual(self.invoke(self.args(compare=[root / "a.md", root / "b.md"])), 1)

    def test_a_missing_report_file_exits_two(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "gone.md"
            with mock.patch.object(checker, "build_parser") as parser:
                parser.return_value.parse_args.return_value = self.args(compare=[missing, missing])
                with quiet_logger():
                    self.assertEqual(checker.main([]), 2)

    def test_the_write_flag_only_fires_on_an_upgrade(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / "w.yml"
            workflow.write_text(WORKFLOW, encoding="utf-8")
            (root / "p.toml").write_text(PINS, encoding="utf-8")
            fetch = fetcher(manifest("3.12.16"), ruff=pypi("3.12"), mypy=pypi("3.12"))
            args = self.args(workflow=workflow, pins=root / "p.toml", write=True)
            self.assertEqual(self.invoke(args, fetch), 0)
            self.assertEqual(workflow.read_text(encoding="utf-8"), WORKFLOW)

    def test_the_write_flag_applies_an_available_upgrade(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / "w.yml"
            workflow.write_text(WORKFLOW, encoding="utf-8")
            (root / "p.toml").write_text(PINS, encoding="utf-8")
            report = root / "out.md"
            fetch = fetcher(manifest("3.12.16", "3.14.10"), ruff=pypi("3.12", "3.14"), mypy=pypi("3.12", "3.14"))
            args = self.args(workflow=workflow, pins=root / "p.toml", write=True, report=report)
            self.assertEqual(self.invoke(args, fetch), 0)
            self.assertIn('PYTHON_VERSION: "3.14"', workflow.read_text(encoding="utf-8"))
            self.assertIn("all 2 tools support 3.14", report.read_text(encoding="utf-8"))

    def test_the_step_outputs_carry_the_decision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "github_output"
            output.touch()
            workflow = root / "w.yml"
            workflow.write_text(WORKFLOW, encoding="utf-8")
            (root / "p.toml").write_text(PINS, encoding="utf-8")
            fetch = fetcher(manifest("3.12.16", "3.14.10"), ruff=pypi("3.12", "3.14"), mypy=pypi("3.12", "3.14"))
            with mock.patch.dict(checker.os.environ, {"GITHUB_OUTPUT": str(output)}):
                self.invoke(self.args(workflow=workflow, pins=root / "p.toml"), fetch)
            written = output.read_text(encoding="utf-8")
        self.assertIn("upgrade=true\n", written)
        self.assertIn("target=3.14\n", written)
        self.assertIn("current=3.12\n", written)

    def test_no_outputs_are_written_outside_actions(self):
        with mock.patch.dict(checker.os.environ, {}, clear=True):
            checker._write_outputs(checker.Decision("3.12", "3.12", None, None, (), {}))


class FailureToWriteTests(unittest.TestCase):
    """Writing is where an unattended job meets a full disk or a read-only mount.

    None of these may raise a bare traceback: the workflow reads exit codes, and
    2 is the one that means "the check could not run".
    """

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.workflow = self.root / "w.yml"
        self.workflow.write_text(WORKFLOW, encoding="utf-8")
        self.pins = self.root / "p.toml"
        self.pins.write_text(PINS, encoding="utf-8")
        self.fetch = fetcher(manifest("3.12.16", "3.14.10"), ruff=pypi("3.12", "3.14"), mypy=pypi("3.12", "3.14"))

    def args(self, **overrides):
        defaults = {
            "workflow": self.workflow,
            "pins": self.pins,
            "report": None,
            "write": False,
            "compare": None,
            "quiet": True,
        }
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def test_an_unreadable_input_names_the_file(self):
        with self.assertRaises(SyncError) as caught:
            checker.run(self.args(pins=self.root / "absent.toml"), self.fetch)
        self.assertIn("absent.toml", str(caught.exception))

    def test_a_workflow_that_cannot_be_written_is_an_error(self):
        with (
            mock.patch.object(Path, "write_text", side_effect=OSError(28, "No space left on device")),
            self.assertRaises(SyncError) as caught,
        ):
            checker.run(self.args(write=True), self.fetch)
        self.assertIn("cannot write", str(caught.exception))

    def test_a_report_that_cannot_be_written_is_an_error(self):
        target = self.root / "missing-directory" / "out.md"
        with self.assertRaises(SyncError) as caught:
            checker.run(self.args(report=target), self.fetch)
        self.assertIn("cannot write", str(caught.exception))

    def test_step_outputs_that_cannot_be_written_are_an_error(self):
        decision = checker.Decision("3.12", "3.14", "3.14", "3.14", (), {})
        with (
            mock.patch.dict(checker.os.environ, {"GITHUB_OUTPUT": str(self.root / "nope" / "out")}),
            self.assertRaises(SyncError) as caught,
        ):
            checker._write_outputs(decision)
        self.assertIn("step outputs", str(caught.exception))

    def test_a_dead_stdout_does_not_cost_a_finished_check_its_exit_code(self):
        """The summary is already in --report, which is what the workflow reads.

        The sibling sync CLI suppresses exactly this; an unattended job should
        not have two answers to the same question.
        """
        dead = io.StringIO()
        dead.close()
        with contextlib.redirect_stdout(dead), quiet_logger():
            self.assertEqual(checker.run(self.args(), self.fetch), 0)

    def test_an_oserror_is_an_exit_code_and_not_a_traceback(self):
        """Matches the sync CLI's mapping: 0 / 2 / 130, never a stack trace."""
        with mock.patch.object(checker, "run", side_effect=OSError(28, "No space left on device")), quiet_logger():
            self.assertEqual(checker.main([]), 2)

    def test_a_fifo_at_the_output_path_is_refused_rather_than_blocking(self):
        """The sync's opener is reused precisely so this cannot hang the job."""
        fifo = self.root / "fifo"
        checker.os.mkfifo(fifo)
        decision = checker.Decision("3.12", "3.14", "3.14", "3.14", (), {})
        with (
            mock.patch.dict(checker.os.environ, {"GITHUB_OUTPUT": str(fifo)}),
            self.assertRaises(SyncError),
        ):
            checker._write_outputs(decision)


class EntryPointTests(unittest.TestCase):
    """The workflow runs this file as a script, not as an import."""

    def test_running_the_module_as_a_script_uses_main(self):
        output = io.StringIO()
        with (
            mock.patch.object(checker.sys, "argv", ["python_version_check.py", "--help"]),
            contextlib.redirect_stdout(output),
            self.assertRaises(SystemExit) as caught,
        ):
            runpy.run_module("python_version_check", run_name="__main__")
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("--compare", output.getvalue())

    def test_the_default_fetcher_is_the_sync_s_hardened_one(self):
        """Not a second HTTP client: one place enforces HTTPS and the size cap."""
        with mock.patch.object(checker.sources, "_fetch_bytes", return_value=b"{}") as fetch:
            self.assertEqual(checker._default_fetch("https://example.invalid/x"), b"{}")
        fetch.assert_called_once_with("https://example.invalid/x")

    def test_the_default_fetcher_refuses_plain_http(self):
        with self.assertRaises(SyncError):
            checker._default_fetch("http://example.invalid/x")


class ReportTests(unittest.TestCase):
    """The pull-request body is the only thing a human reads before merging."""

    def decide(self, target, candidate="3.14", supported=True):
        verdicts = (checker.ToolVerdict("ruff", "0.17.6", supported), checker.ToolVerdict("mypy", "2.4.1", True))
        releases = {"3.12": "3.12.16", "3.14": "3.14.10"}
        return checker.Decision("3.12", "3.14", candidate, target, verdicts, releases)

    def test_an_upgrade_body_names_both_versions_and_their_patches(self):
        body = checker.render_report(self.decide("3.14"), "2026-12-01 06:00 UTC")
        self.assertIn("`3.12` (running 3.12.16)", body)
        self.assertIn("`3.14` (running 3.14.10)", body)
        self.assertIn("all 2 tools support 3.14", body)
        self.assertIn("Only the Python version changes", body)

    def test_a_hold_says_how_many_tools_are_missing_and_when_it_retries(self):
        body = checker.render_report(self.decide(None, supported=False), "2026-12-01 06:00 UTC")
        self.assertIn("not yet - 1 of 2 tools do not support 3.14", body)
        self.assertIn("Will check again next month", body)
        self.assertNotIn("Only the Python version changes", body)

    def test_the_table_marks_the_blocking_tool(self):
        body = checker.render_report(self.decide(None, supported=False), "2026-12-01 06:00 UTC")
        self.assertIn("| ruff | 0.17.6 | **no** |", body)
        self.assertIn("| mypy | 2.4.1 | yes |", body)

    def test_being_current_says_so_without_a_table(self):
        body = checker.render_report(self.decide(None, candidate=None), "2026-12-01 06:00 UTC")
        self.assertIn("already on the newest series", body)
        self.assertNotIn("| Tool |", body)

    def test_the_body_ends_with_a_newline(self):
        self.assertTrue(checker.render_report(self.decide("3.14"), "x").endswith("\n"))


class RealRepositoryTests(unittest.TestCase):
    """The check must fit the repository as it is actually written."""

    root = Path(__file__).resolve().parent.parent

    def test_it_can_read_this_repository_s_own_workflow_and_pins(self):
        workflow = (self.root / checker.DEFAULT_WORKFLOW).read_text(encoding="utf-8")
        self.assertRegex(checker.current_series(workflow), r"^\d+\.\d+$")

    def test_the_default_paths_exist(self):
        self.assertTrue((self.root / checker.DEFAULT_WORKFLOW).is_file())
        self.assertTrue((self.root / checker.DEFAULT_PYPROJECT).is_file())

    def test_every_pinned_tool_is_a_name_and_an_exact_version(self):
        pins = checker.pinned_tools((self.root / checker.DEFAULT_PYPROJECT).read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(pins), 5)
        for name, version in pins.items():
            with self.subTest(tool=name):
                self.assertRegex(version, r"^\d[\w.]*$")

    def test_the_rewrite_leaves_the_real_workflow_otherwise_untouched(self):
        """One line changes; the file the bot runs from is not reformatted."""
        path = self.root / checker.DEFAULT_WORKFLOW
        original = path.read_text(encoding="utf-8")
        updated = checker.rewrite_version(original, "9.99")
        self.assertEqual(len(original.splitlines()), len(updated.splitlines()))
        differing = [
            (old, new) for old, new in zip(original.splitlines(), updated.splitlines(), strict=True) if old != new
        ]
        self.assertEqual(
            differing, [(f'  PYTHON_VERSION: "{checker.current_series(original)}"', '  PYTHON_VERSION: "9.99"')]
        )

    def test_the_masked_line_matches_what_the_report_actually_writes(self):
        """If report.py restyles its timestamp, this fails here, not in CI at 06:00."""
        import report

        source = Path(report.__file__).read_text(encoding="utf-8")
        self.assertIn("f\"- Run at: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}\"", source)


if __name__ == "__main__":
    unittest.main()
