#!/usr/bin/env python3
"""Tests for the Vorobey hackerpolice sync tool."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import random
import re
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from _support import (
    HACKERPOLICE_PROOF,
    SOURCE_API_URL,
    SOURCE_BODY,
    SOURCE_URL,
    _FakeResponse,
    hackerpolice_entry,
    index_of,
    player,
    run_sync_and_read_outputs,
)

import playerlist as playerlist_module
import report as report_module
import sources
import sync_vorobey_hackerpolice as sync_module
from playerlist import (
    dumps,
)
from policy import demote, promote, sync
from sources import (
    SyncError,
    load_first_available_raw,
)
from sync_vorobey_hackerpolice import DEFAULT_SNAPSHOT, build_parser, main


class ReadmeCliTests(unittest.TestCase):
    """Keep the CLI flags discoverable and accurate in the README."""

    @staticmethod
    def _readme() -> str:
        path = Path(__file__).resolve().parents[1] / "README.md"
        return path.read_text(encoding="utf-8")

    def test_every_flag_is_documented(self):
        readme = self._readme()
        flags = {flag for action in build_parser()._actions for flag in action.option_strings if flag.startswith("--")}
        self.assertEqual(sorted(flag for flag in flags if flag not in readme), [])

    def test_the_readme_invents_no_flags(self):
        """The other direction: every documented flag must still exist."""
        readme = self._readme()
        known = {flag for action in build_parser()._actions for flag in action.option_strings}
        mentioned = set(re.findall(r"`(--[a-z][a-z0-9-]+)", readme))
        self.assertEqual(sorted(mentioned - known), [])


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
        self.assertFalse(self.path.exists())  # No file is written when the snapshot already matches.

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
        # Reject a body over the download limit rather than writing it to disk.
        with (
            mock.patch.object(sources, "MAX_SOURCE_BYTES", 100),
            mock.patch(
                "sources._OPENER.open",
                side_effect=[_FakeResponse(b"x" * 101), _FakeResponse(SOURCE_BODY)],
            ),
            mock.patch("sources.time.sleep"),
        ):
            document, source, raw = load_first_available_raw(["https://example.invalid/big.json", SOURCE_URL])
        self.assertEqual(source, SOURCE_URL)
        self.assertEqual(raw, SOURCE_BODY)
        self.assertEqual(document["players"][0]["steamid"], "[U:1:100]")

    def test_non_http_url_is_refused_before_any_request(self):
        with mock.patch("sources._OPENER.open") as urlopen, self.assertRaises(SyncError):
            sources._fetch_bytes("file:///etc/passwd")
        urlopen.assert_not_called()

    def test_database_path_errors_redact_url_like_credentials_before_clipping(self):
        secret = "PATH_SECRET"
        path = Path("https:/user:" + secret + "x" * 180 + "@example.invalid/db.json")
        self.assertNotIn(secret, sync_module.display_path(path))
        with self.assertRaises(SyncError) as caught:
            sync_module.load_database(path)
        self.assertNotIn(secret, str(caught.exception))
        self.assertTrue("omitted" in str(caught.exception))
        self.assertLessEqual(len(str(caught.exception)), 300)

        nested_secret = "NESTED_PATH_SECRET"
        nested_path = Path(
            "https://example.invalid/https%3A%2F%2Fuser%3A" + nested_secret + "%40client.invalid%2Fdb.json"
        )
        self.assertNotIn(nested_secret, sync_module.display_path(nested_path))
        with self.assertRaises(SyncError) as caught:
            sync_module.load_database(nested_path)
        self.assertNotIn(nested_secret, str(caught.exception))

    def test_unreadable_local_source_falls_through_to_the_next_one(self):
        local = self.root / "present.json"
        local.write_text("{}", encoding="utf-8")
        with (
            mock.patch("sources._OPENER.open", side_effect=[_FakeResponse(SOURCE_BODY)]),
            mock.patch("playerlist.os.open", side_effect=OSError("input/output error")) as open_file,
            mock.patch("sources.time.sleep"),
        ):
            _, source, _ = load_first_available_raw([str(local), SOURCE_URL])
        self.assertEqual(source, SOURCE_URL)  # Report the I/O error as a skipped source.
        open_file.assert_called_once()  # The first local-source read failed before fallback.

    def test_blob_url_is_only_derived_from_a_contents_api_url(self):
        sha = "a" * 40
        self.assertIsNone(sources._github_blob_url("https://api.github.com/repos/x/y/git/refs/main", sha))
        self.assertIsNone(sources._github_blob_url("https://example.invalid/repos/x/y/contents/f.json", sha))
        self.assertIsNone(sources._github_blob_url(SOURCE_API_URL, "not-a-sha"))
        self.assertEqual(
            sources._github_blob_url(SOURCE_API_URL, sha),
            f"https://api.github.com/repos/Nocrex/Tom/git/blobs/{sha}",
        )

    def test_running_the_module_as_a_script_uses_main(self):
        # Match the workflow's direct script invocation.
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
        # Base64 content must be text; reject other types before decoding so
        # b64decode() cannot turn malformed input into an uncaught exception.
        self.assertIsNone(sources._unwrap_github_contents_envelope({"encoding": "base64", "content": 123}))
        self.assertIsNone(sources._unwrap_github_contents_envelope({"content": "e30="}))
        self.assertIsNone(sources._unwrap_github_contents_envelope({"encoding": "base64"}))
        self.assertIsNone(sources._unwrap_github_contents_envelope({"encoding": "base64", "content": ""}))

    def test_envelope_content_with_line_breaks_still_decodes(self):
        # Accept GitHub's line wrapping while validating the remaining Base64 characters.
        encoded = base64.encodebytes(b'{"players": []}').decode("ascii")
        self.assertIn("\n", encoded)
        self.assertEqual(
            sources._unwrap_github_contents_envelope({"encoding": "base64", "content": encoded}), b'{"players": []}'
        )

    def test_redact_url_omits_a_url_it_cannot_parse(self):
        # A malformed IPv6 literal makes urlsplit() raise; redaction must not
        # crash or expose credentials from the unparseable URL.
        broken = "https://user:secret@[::1/list.json"
        self.assertEqual(sources.redact_url(broken), "[malformed URL omitted]")

    def test_indirect_document_skips_a_candidate_that_is_not_a_playerlist(self):
        # Reject follow-up JSON that is neither a playerlist nor a base64
        # envelope.
        envelope = json.dumps(
            {
                "encoding": "base64",
                "content": base64.b64encode(b"{}").decode("ascii"),
                "sha": "a" * 40,
                "download_url": "https://raw.githubusercontent.com/Nocrex/Tom/main/download.json",
            }
        ).encode("utf-8")

        def read(url):
            if url == SOURCE_API_URL:
                return envelope
            if url == "https://raw.githubusercontent.com/Nocrex/Tom/main/download.json":
                return b'{"$schema": "x"}'  # Valid JSON, but not a playerlist document.
            raise SyncError("blocked")

        with (
            mock.patch("sources._read_bytes", side_effect=read),
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError),
        ):
            load_first_available_raw([SOURCE_API_URL])

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
        # The empty-username case must also preserve a non-default port.
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
        # Some platforms cannot fsync directories. The atomic rename is already
        # complete, so unsupported directory durability must not fail the write.
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
        # An unusable API envelope with blocked fallback URLs must produce a
        # clear SyncError rather than a traceback or partially parsed document.
        envelope = json.dumps(
            {"encoding": "base64", "content": base64.b64encode(b"{}").decode("ascii"), "sha": "a" * 40}
        ).encode("utf-8")

        def read(url):
            if url == SOURCE_API_URL:
                return envelope
            raise SyncError("blocked")

        with (
            mock.patch("sources._read_bytes", side_effect=read),
            mock.patch("sources.time.sleep"),
            self.assertRaises(SyncError) as caught,
        ):
            load_first_available_raw([SOURCE_API_URL])
        self.assertIn("cannot load the Vorobey hackerpolice list", str(caught.exception))

    def test_failed_write_leaves_no_temp_file_behind(self):
        target = self.root / "list.json"
        with mock.patch.object(Path, "replace", side_effect=OSError("disk full")), self.assertRaises(OSError):
            sync_module._atomic_write_bytes(target, b"{}\n")
        self.assertEqual(list(self.root.iterdir()), [])  # Failed writes must not leave a temporary file behind.

    def test_a_valid_long_basename_can_still_be_written_atomically(self):
        name_limit = os.pathconf(self.root, "PC_NAME_MAX")
        target = self.root / ("x" * (name_limit - 5))
        sync_module._atomic_write_bytes(target, b"long name\n")
        self.assertEqual(target.read_bytes(), b"long name\n")

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

    def test_a_self_referential_symlink_is_refused_and_preserved(self):
        """Every failure mode here must be a clean SyncError, never a traceback."""
        link = self.root / "loop.json"
        link.symlink_to(link)
        with self.assertRaises(SyncError) as caught:
            sync_module.write_snapshot(link, b"new\n", None, dry_run=False)
        self.assertIn("too many levels of symbolic links", str(caught.exception).lower())
        self.assertTrue(link.is_symlink())

    def test_a_symlink_loop_when_Git_style_resolution_fails_is_still_a_SyncError(self):
        """``Path.resolve`` raises RuntimeError for a loop, which is not an OSError.

        Depending on the platform, ``is_symlink()``/``resolve()`` can report the
        loop instead of ``os.open``; either way the caller must get the same
        named, path-aware write error rather than a RuntimeError escaping as a
        traceback.
        """
        link = self.root / "loop.json"
        link.symlink_to(link)
        with (
            mock.patch.object(Path, "resolve", side_effect=RuntimeError("Symlink loop from 'loop.json'")),
            self.assertRaises(SyncError) as caught,
        ):
            sync_module.write_snapshot(link, b"new\n", None, dry_run=False)
        self.assertIn("too many levels of symbolic links", str(caught.exception).lower())
        self.assertIn("loop.json", str(caught.exception))
        self.assertTrue(link.is_symlink())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs named pipes")
    def test_atomic_write_refuses_a_fifo_instead_of_replacing_it(self):
        fifo = self.root / "output.fifo"
        os.mkfifo(fifo)
        with self.assertRaises(OSError) as caught:
            sync_module._atomic_write_bytes(fifo, b"new\n")
        self.assertIn("not a regular file", str(caught.exception))
        self.assertTrue(stat.S_ISFIFO(fifo.stat().st_mode))
        self.assertEqual(list(self.root.iterdir()), [fifo])

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
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)  # Preserve the existing file mode.

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
                        code = main(flat)  # Return a clean refusal and leave the symlink intact.
                    self.assertEqual(code, 2)
                    self.assertTrue(loop.is_symlink())

    def test_database_that_fails_validation_after_sync_is_not_written(self):
        database = self.root / "list.json"
        database.write_text(dumps({"players": [player("[U:1:100]", ["suspicious"])]}), encoding="utf-8")
        source = self.root / "upstream.json"
        source.write_text(dumps({"players": [hackerpolice_entry("[U:1:100]")]}), encoding="utf-8")
        before = database.read_bytes()
        clean = playerlist_module.ValidationResult()
        broken = playerlist_module.ValidationResult(errors=["simulated problem"])
        # Let load_database() pass, then fail validation after the sync.
        with mock.patch.object(sync_module, "validate", side_effect=[clean, broken]):
            code = main(
                ["--database", str(database), "--source", str(source), "--snapshot", str(self.root / "snapshot.json")]
            )
        self.assertEqual(code, 2)
        self.assertEqual(database.read_bytes(), before)  # A validation failure must leave the database unchanged.

    def test_policy_keeps_an_entry_whose_attributes_are_not_a_list(self):
        # Strings and other iterables must not be mistaken for tag lists.
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
        # validate() rejects this at the CLI boundary. Policy helpers should
        # still leave malformed entries unchanged if called directly.
        database = {"players": [{"steamid": "[U:1:100]", "attributes": [1, "cheater"]}]}
        changes = demote(database, ["[U:1:100]"])  # type: ignore[arg-type]
        self.assertEqual(changes, [])
        self.assertEqual(len(database["players"]), 1)

    def test_sync_without_a_players_array_is_a_no_op(self):
        database = {"players": None}
        self.assertEqual(sync(database, index_of(), enable_demote=True, removed_ids={"[U:1:100]"}), [])  # type: ignore[arg-type]


class ValidationLoggingTests(unittest.TestCase):
    def test_untrusted_validation_values_are_redacted_before_logging(self):
        secret = "VALIDATION_LOG_PASSWORD"
        bearer = "VALIDATION_BEARER_SECRET"
        result = playerlist_module.validate(
            {
                "players": [
                    {
                        "steamid": f"https://user:{secret}@example.invalid/bad-id?access_token={secret}",
                        "attributes": ["cheater"],
                    },
                    {
                        "steamid": "[U:1:1]",
                        "attributes": [
                            f"https://user:{secret}@example.invalid/unknown-attribute?access_token={secret}"
                        ],
                    },
                    {"steamid": f"access_token={secret}", "attributes": ["cheater"]},
                    {"steamid": "[U:1:2]", "attributes": [f"Authorization: Bearer {bearer}"]},
                ]
            }
        )
        with self.assertLogs(sync_module.LOGGER, level="WARNING") as captured:
            sync_module._log_validation(result, "database validation")
        output = "\n".join(captured.output)
        self.assertNotIn(secret, output)
        self.assertNotIn(bearer, output)
        self.assertIn("example.invalid", output)
        self.assertIn("REDACTED", output)

    def test_omitted_validation_messages_are_summarised(self):
        result = playerlist_module.ValidationResult(
            errors=["invalid entry"],
            warnings=["unknown attribute"],
            errors_omitted=2,
            warnings_omitted=3,
        )
        with self.assertLogs(sync_module.LOGGER, level="WARNING") as captured:
            sync_module._log_validation(result, "database validation")
        output = "\n".join(captured.output)
        self.assertIn("3 additional validation warning(s) omitted", output)
        self.assertIn("database validation: 2 additional validation problem(s) omitted", output)

    def test_the_summary_is_flushed_before_the_outcome_is_logged(self):
        """A piped stdout is block-buffered while stderr is not.

        Without an explicit flush, the outcome lines ("Updated N entries ...")
        reached the reader BEFORE the summary they refer to.
        """
        flushed = []
        real_stdout = sys.stdout
        try:
            with mock.patch.object(sys, "stdout", new_callable=io.StringIO) as fake_out:
                fake_out.flush = lambda: flushed.append("flush")
                with (
                    tempfile.TemporaryDirectory() as tmp,
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    root = Path(tmp)
                    (root / "db.json").write_text(
                        dumps({"players": [player("[U:1:100]", ["suspicious"])]}), encoding="utf-8"
                    )
                    (root / "up.json").write_text(
                        dumps({"players": [player("[U:1:100]", ["cheater"])]}), encoding="utf-8"
                    )
                    code = main(
                        [
                            "--database",
                            str(root / "db.json"),
                            "--snapshot",
                            str(root / "snap.json"),
                            "--source",
                            str(root / "up.json"),
                            "--dry-run",
                            "-q",
                        ]
                    )
        finally:
            sys.stdout = real_stdout
        self.assertEqual(code, 0)
        self.assertEqual(flushed, ["flush"])

    def test_validation_messages_are_not_escaped_twice(self):
        """An escaped newline must stay a two-character escape, not become ``\\\\n``.

        ``validate()`` already quotes untrusted values through its bounded,
        redacting preview. Re-running the redacting path formatter over the
        finished message escaped the backslash again and re-inspected the text.
        """
        result = playerlist_module.ValidationResult()
        result.add_warning("players[0] uses unknown attribute 'a\\nb'")
        with self.assertLogs(sync_module.LOGGER, level="WARNING") as captured:
            sync_module._log_validation(result, "database validation")
        output = "\n".join(captured.output)
        self.assertIn("'a\\nb'", output)
        self.assertNotIn("a\\\\nb", output)

    def test_a_long_validation_message_is_still_a_message_not_an_omitted_url(self):
        """A long message must not be re-classified as an uninspectable URL."""
        result = playerlist_module.ValidationResult()
        result.add_error("players[0] has a problem: " + "ref=1&" * 1_000)
        with self.assertLogs(sync_module.LOGGER, level="WARNING") as captured:
            sync_module._log_validation(result, "database validation")
        output = "\n".join(captured.output)
        self.assertNotIn("too long to inspect safely", output)
        self.assertIn("players[0] has a problem", output)


class WriteOrderTests(unittest.TestCase):
    """Append step outputs first, then write report, database, and snapshot.

    A snapshot failure can leave the database rewritten; reversing those two
    data writes could instead advance the baseline and lose removals.
    """

    def test_a_failing_snapshot_write_happens_after_the_database_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "up.json").write_text(dumps({"players": [player("[U:1:1]", ["cheater"])]}), encoding="utf-8")
            # Keep the input non-canonical so a successful write is observable.
            (root / "db.json").write_text(
                '{"players":[{"attributes":["cheater"],"steamid":"[U:1:1]"}]}', encoding="utf-8"
            )
            # A dangling link passes path checks and snapshot loading; writing resolves it
            # and fails at the missing target, even when tests run as root.
            (root / "snap.json.link").symlink_to(root / "nodir" / "snap.json")
            with contextlib.redirect_stdout(io.StringIO()):  # The CLI prints the report even with --report set.
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
            self.assertTrue((root / "snap.json.link").is_symlink())  # Preserve the failed target symlink.
            self.assertEqual([p.name for p in root.iterdir() if ".tmp" in p.name], [])


class UnusableStdoutTests(unittest.TestCase):
    """A stdout that cannot accept the summary must not cost the run its writes.

    The summary is also the ``--report`` file, i.e. the pull request body. If a dead
    stdout aborted the run after that file was written, the report would describe
    changes that were never applied -- and it would be published as if they had been.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        # Two entries: one promotable, so the run genuinely has something to write.
        (self.root / "up.json").write_text(dumps({"players": [player("[U:1:1]", ["cheater"])]}), encoding="utf-8")
        (self.root / "db.json").write_text(dumps({"players": [player("[U:1:1]", ["suspicious"])]}), encoding="utf-8")

    def test_a_closed_stdout_still_lets_the_database_and_report_be_written(self):
        stdout = io.StringIO()
        stdout.close()  # Every write raises ValueError, as a closed fd 1 does on flush.
        with contextlib.redirect_stdout(stdout):
            code = main(
                [
                    "--database",
                    str(self.root / "db.json"),
                    "--snapshot",
                    str(self.root / "snap.json"),
                    "--source",
                    str(self.root / "up.json"),
                    "--report",
                    str(self.root / "r.md"),
                    "-q",
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(
            (self.root / "db.json").read_text(encoding="utf-8"),
            dumps({"players": [player("[U:1:1]", ["cheater"])]}),
        )
        self.assertIn("[U:1:1]", (self.root / "r.md").read_text(encoding="utf-8"))


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
            # Exercise promotion, full-entry demotion, and an unrelated player in one run.
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
                    contextlib.redirect_stdout(io.StringIO()),  # The report is printed to stdout.
                ):
                    self.assertEqual(main(argv), 0)
                return dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())

            first = run(root / "out1")
            self.assertEqual(first["changed"], "true")
            self.assertEqual(first["count"], "2")  # One promotion and one demotion were applied.
            database_after, snapshot_after = (root / "db.json").read_bytes(), (root / "snap.json").read_bytes()
            self.assertEqual(snapshot_after, upstream.encode("utf-8"))  # Advance the snapshot baseline.

            second = run(root / "out2")
            self.assertEqual(second["changed"], "false")
            self.assertEqual(second["count"], "0")
            self.assertEqual(second["modified"], "false")
            self.assertEqual(second["snapshot_changed"], "false")
            # The second run leaves both files byte-for-byte unchanged.
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

    def test_the_open_output_descriptor_is_rechecked_after_path_stat(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "output"
            target.touch()
            directory_status = root.stat()
            with (
                mock.patch.object(sync_module.os, "fstat", return_value=directory_status),
                self.assertRaises(OSError) as caught,
            ):
                sync_module._open_github_output(str(target))
            self.assertIn("not a regular file", str(caught.exception))
            self.assertEqual(target.read_bytes(), b"")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs named pipes")
    def test_fifo_output_is_refused_without_waiting_for_a_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp) / "output.fifo"
            os.mkfifo(fifo)
            scripts = Path(__file__).resolve().parents[1] / "scripts"
            code = (
                f"import sys; sys.path.insert(0, {str(scripts)!r})\n"
                "import sync_vorobey_hackerpolice as sync\n"
                "try:\n    sync._check_github_output()\n"
                "except sync.SyncError as exc:\n    print(exc)\n"
                "else:\n    raise SystemExit('FIFO unexpectedly accepted')\n"
            )
            result = subprocess.run(
                [sys.executable, "-c", code],
                capture_output=True,
                text=True,
                encoding="utf-8",
                env={**os.environ, "GITHUB_OUTPUT": str(fifo)},
                timeout=5,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not a regular file", result.stdout)

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
        """A directory output path must fail before any report or data write."""
        target = self.root / "outputs"
        target.mkdir()
        before = self.database.read_bytes()
        code, _, stderr = self.run_cli("--source", str(self.source), env={"GITHUB_OUTPUT": str(target)})
        self.assertEqual(code, 2)
        self.assertIn("cannot write the GitHub step outputs", stderr)
        self.assertEqual(self.database.read_bytes(), before, "the database must not be touched")
        self.assertFalse((self.root / "snapshot.json").exists(), "nor the snapshot")

    @unittest.skipUnless(Path("/dev/full").exists(), "requires the Linux full-device test fixture")
    def test_a_special_github_output_is_refused_before_any_file_write(self):
        """A device is not a step-output file, even if it accepts append-open."""
        before = self.database.read_bytes()
        report = self.root / "report.md"
        code, stdout, stderr = self.run_cli(
            "--source", str(self.source), "--report", str(report), env={"GITHUB_OUTPUT": "/dev/full"}
        )
        self.assertEqual(code, 2)
        self.assertIn("cannot write the GitHub step outputs", stderr)
        self.assertIn("not a regular file", stderr)
        self.assertEqual(stdout, "")
        self.assertEqual(self.database.read_bytes(), before)
        self.assertFalse((self.root / "snapshot.json").exists())
        self.assertFalse(report.exists())

    def test_a_regular_output_write_failure_changes_no_files(self):
        """A failure after the preflight append still precedes every data write."""
        output = self.root / "github-output"
        report = self.root / "report.md"
        before = self.database.read_bytes()
        preflight_handle = mock.MagicMock()
        preflight_handle.__enter__.return_value = mock.MagicMock()
        preflight_handle.__exit__.return_value = False
        failing_handle = mock.MagicMock()
        failing_handle.__enter__.return_value.write.side_effect = OSError("disk full")
        failing_handle.__exit__.return_value = False
        with mock.patch.object(
            sync_module,
            "_open_github_output",
            side_effect=[preflight_handle, failing_handle],
        ) as open_output:
            code, stdout, stderr = self.run_cli(
                "--source", str(self.source), "--report", str(report), env={"GITHUB_OUTPUT": str(output)}
            )
        self.assertEqual(open_output.call_count, 2)
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

    def test_upstream_proof_credentials_are_redacted_end_to_end(self):
        """Credentials on an evidence URL must not reach the public PR body."""
        evidence = (
            "https://user:URL_PASSWORD@example.invalid/watch"
            "?X-Amz-Signature=QUERY_SECRET&ref=main#access_token=FRAGMENT_SECRET"
        )
        embedded_evidence = "Context: https://user:PROSE_PASSWORD@example.invalid/watch?token=PROSE_TOKEN."
        source_document = json.loads(self.source.read_text(encoding="utf-8"))
        source_document["players"][0]["proof"] = [evidence, embedded_evidence]
        self.source.write_text(json.dumps(source_document), encoding="utf-8")

        report = self.root / "report.md"
        code, _, stderr = self.run_cli("--source", str(self.source), "--report", str(report))
        self.assertEqual(code, 0, stderr)
        body = report.read_text(encoding="utf-8")
        for secret in (
            "URL_PASSWORD",
            "QUERY_SECRET",
            "FRAGMENT_SECRET",
            "PROSE_PASSWORD",
            "PROSE_TOKEN",
        ):
            self.assertNotIn(secret, body)
        self.assertIn("Context: https://example.invalid/watch?token=REDACTED.", body)
        self.assertIn("X-Amz-Signature=REDACTED", body)
        self.assertIn("ref=main", body)
        self.assertIn("access_token=REDACTED", body)

    def test_version_flag_is_not_part_of_the_cli(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exit_:
            build_parser().parse_args(["--version"])
        self.assertEqual(exit_.exception.code, 2)

    def test_user_agent_identifies_the_bot_without_a_software_version(self):
        self.assertTrue(sources.USER_AGENT.startswith("Garou3299-tf2bd-database-vorobey-hackerpolice-sync ("))
        self.assertIn("+https://github.com/Garou3299/tf2bd-database", sources.USER_AGENT)
        self.assertNotIn("\n", sources.USER_AGENT)

    def test_snapshot_default_path_and_flags(self):
        self.assertEqual(DEFAULT_SNAPSHOT, "snapshot/playerlist.vorobey-hackerpolice.json")
        self.assertEqual(build_parser().parse_args([]).snapshot, DEFAULT_SNAPSHOT)
        args = build_parser().parse_args(["--snapshot", "some/path.json", "--no-update-snapshot"])
        self.assertEqual(args.snapshot, "some/path.json")
        self.assertTrue(args.no_update_snapshot)
        # The obsolete --backup options must remain rejected.
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            build_parser().parse_args(["--backup", "old/path.json"])

    def run_cli(self, *extra, env=None):
        # Use a temporary snapshot path so tests never touch the repository file.
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
        self.assertNotIn("\x1b", stderr)  # The log contains no raw ESC character.
        self.assertEqual(stderr.strip().count("\n"), 0)  # The hostile path does not add log lines.
        self.assertIn("a\\nb", stderr)  # Preserve the value in escaped form rather than dropping it.

    def test_a_hostile_snapshot_path_cannot_repaint_the_log(self):
        """The success lines print paths too: escape them like the error lines."""
        snapshot = self.root / "s\x1b[0m.json"
        code, _, stderr = self.run_cli("--source", str(self.source), "--snapshot", str(snapshot))
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", stderr)
        self.assertIn("\\x1b[0m", stderr)  # Preserve the value in escaped form rather than dropping it.
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

    def test_entry_totals_use_raw_rows_when_snapshot_contains_duplicate_ids(self):
        self.write_snapshot_fixture(
            hackerpolice_entry("[U:1:100]"),
            hackerpolice_entry("[U:1:100]"),
            hackerpolice_entry("[U:1:200]"),
        )
        code, stdout, stderr = self.run_cli("--source", str(self.source))
        self.assertEqual(code, 0, stderr)
        self.assertIn("Previous snapshot: 3 entries; 0 SteamIDs removed upstream", stdout)
        # The net is derived from distinct-ID additions/removals, so it cannot
        # contradict the counts printed next to it when a duplicate row exists.
        self.assertIn("(3 → 2 entries; no net change)", stdout)

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
                        player("[U:1:400]", ["cheater"]),  # Removed upstream; demote this local cheater.
                        player("[U:1:300]", ["suspicious"]),  # Removed upstream, but this player is not a cheater.
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.write_snapshot_fixture(
            hackerpolice_entry("[U:1:300]"),
            hackerpolice_entry("[U:1:400]"),
            hackerpolice_entry("[U:1:500]"),  # Removed upstream, but absent from this database.
        )
        report_file = self.root / "report.md"
        code, stdout, _ = self.run_cli("--source", str(self.source), "--demote", "--report", str(report_file))
        self.assertEqual(code, 0)
        report = report_file.read_text(encoding="utf-8")
        self.assertEqual(report, stdout)
        # The report file becomes the PR body: include exactly one trailing newline
        # so the published body does not end with a blank line.
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
        # IDs still present upstream are not removals.
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
        # Demotion was skipped, so the snapshot baseline did not advance.
        self.assertEqual(
            {p["steamid"] for p in json.loads(snapshot_fixture.read_text(encoding="utf-8"))["players"]},
            {f"[U:1:{n}]" for n in range(400, 461)},
        )

    def test_unusable_upstream_entries_hold_back_demotion_and_snapshot_refresh(self):
        """A malformed row makes any missing ID ambiguous, even below the mass guard."""
        self.database.write_text(
            dumps({"$schema": "x", "file_info": {}, "players": [player("[U:1:400]", ["cheater"])]}),
            encoding="utf-8",
        )
        snapshot_fixture = self.write_snapshot_fixture(hackerpolice_entry("[U:1:400]"))
        snapshot_before = snapshot_fixture.read_bytes()
        self.source.write_text(
            dumps(
                {
                    "$schema": "x",
                    "file_info": {},
                    "players": [hackerpolice_entry("[U:1:100]"), hackerpolice_entry("not-a-steamid")],
                }
            ),
            encoding="utf-8",
        )
        database_before = self.database.read_bytes()

        code, stdout, _ = self.run_cli("--source", str(self.source), "--demote")
        self.assertEqual(code, 0)
        self.assertIn("1 unusable", stdout)
        self.assertIn("cannot be confirmed safely", stdout)
        self.assertIn("demotion candidates", stdout)
        self.assertEqual(self.database.read_bytes(), database_before)
        self.assertEqual(snapshot_fixture.read_bytes(), snapshot_before)

    def test_snapshot_is_frozen_when_demotion_is_disabled(self):
        """A run without --demote must not advance the baseline past removals
        it could not apply -- that would forget them forever."""
        self.database.write_text(
            dumps({"$schema": "x", "file_info": {}, "players": [player("[U:1:400]", ["cheater"])]}),
            encoding="utf-8",
        )
        snapshot_fixture = self.write_snapshot_fixture(hackerpolice_entry("[U:1:300]"), hackerpolice_entry("[U:1:400]"))
        before = snapshot_fixture.read_bytes()

        code, stdout, _ = self.run_cli("--source", str(self.source))  # Demotion is disabled.
        self.assertEqual(code, 0)
        self.assertEqual(snapshot_fixture.read_bytes(), before)  # Keep the pending-removal baseline unchanged.
        self.assertIn("**not refreshed**", stdout)
        self.assertIn("demotion is disabled", stdout)

        # Passing --demote applies those pending removals.
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
        # This run creates the baseline. The next run can then prove removals
        # against that snapshot.
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
        # Do not advance the snapshot past unapplied removals; they would no
        # longer be available as demotion candidates.
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
        # The next run sees the current list as its baseline and makes no changes.
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
        # Run four processes against the same database and snapshot. Unique temp
        # files and atomic replacements must leave complete files; the last writer
        # may win, but writes must never interleave.
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
        # Preserve the byte-for-byte snapshot and leave no temporary files behind.
        self.assertEqual((self.root / "snapshot.json").read_bytes(), self.source.read_bytes())
        self.assertEqual(list(self.root.glob(".*.tmp")), [])

    def test_corrupted_files_never_crash(self):
        # Randomly corrupt the database, source, and snapshot; each run must exit
        # cleanly with status 0 or 2, never with an uncaught exception.
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
        # Regression: ASCII or legacy-codepage stdout (for example,
        # PYTHONIOENCODING=ascii) previously raised UnicodeEncodeError when printing
        # arrows and non-ASCII names in the report.
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
                        player("[U:1:900]", ["cheater"]),  # This entry was appended by hand and is out of order.
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
        # A report-write failure must occur before any database update.
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

    def test_unexpected_os_error_does_not_echo_a_hostile_filename(self):
        error = OSError(5, "disk full", "bad\n\x1b[31m-secret.txt")
        stderr = io.StringIO()
        with (
            mock.patch("sync_vorobey_hackerpolice.run", side_effect=error),
            contextlib.redirect_stderr(stderr),
        ):
            code = main(["--source", str(self.source)])
        message = stderr.getvalue()
        self.assertEqual(code, 2)
        self.assertIn("error: disk full", message)
        self.assertNotIn("secret.txt", message)
        self.assertNotIn("\x1b", message)
        self.assertEqual(message.strip().count("\n"), 0)

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
        # The failed run must leave the snapshot baseline unchanged.
        self.assertEqual(snapshot.read_bytes(), before)

    def test_a_broken_snapshot_is_not_reported_as_a_broken_upstream_list(self):
        """The index builder serves two documents: the list AND the snapshot.

        A snapshot with no 'players' array used to be reported as "the Vorobey
        hackerpolice list has no 'players' array" -- pointing the operator at a
        file that was perfectly fine while the broken one stayed unnamed.
        """
        broken = self.root / "snapshot.json"
        broken.write_text('{"$schema": "x"}', encoding="utf-8")  # Valid JSON with an invalid playerlist shape.
        # Use a local source to avoid a slow live fetch in offline tests.
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
        self.assertFalse(missing.parent.exists())  # The missing output directory must not be created.

    def test_a_missing_output_directory_cannot_inject_a_log_line(self):
        hostile = self.root / ("bad\n\x1b[31m" + "x" * 100) / "report.md"
        code, _, stderr = self.run_cli("--report", str(hostile))
        self.assertEqual(code, 2)
        self.assertNotIn("\x1b", stderr)
        self.assertEqual(stderr.strip().count("\n"), 0)
        self.assertIn("bad\\n\\x1b[31m", stderr)
        self.assertLess(len(stderr.strip()), 300)

    def test_a_report_in_a_missing_directory_is_refused_by_name(self):
        missing = self.root / "typo" / "report.md"
        code, _, stderr = self.run_cli("--report", str(missing))
        self.assertEqual(code, 2)
        self.assertIn(f"--report directory does not exist: {missing.parent}", stderr)
        self.assertFalse(missing.parent.exists())
        self.assertEqual(
            [p.name for p in self.root.iterdir() if ".tmp" in p.name], []
        )  # Refuse before creating any output files.

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
        # Regression: the report is written before the database; an aliased path
        # could overwrite the database, including during a dry run.
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
        self.assertEqual(self.read("db.json"), database)  # The rejected database must not be rewritten.
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
                player("[U:1:999]", ["cheater"]),  # This manually added cheater has never appeared upstream.
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

        # Run 1 applies the promotion and commits the updated baseline.
        self.run_bot()
        self.assertEqual(self.players()["[U:1:100]"]["attributes"], ["cheater"])
        self.git("add", "-A")
        self.git("commit", "-qm", "sync 1")

        # After upstream removes IDs 200 and 300, discard the proposal as if its PR
        # were closed. The next run must propose the same demotions from the old baseline.
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

        # Run 3: no changes; the data and worktree have converged.
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
        # README contract: change tables stop at 150 rows, the removed-ID table
        # at 100 rows, and the report body at 60,000 bytes.
        self.assertEqual(report_module.MAX_CHANGE_TABLE_ROWS, 150)
        self.assertEqual(report_module.MAX_REMOVED_TABLE_ROWS, 100)
        self.assertEqual(report_module.MAX_REPORT_BYTES, 60_000)

    def test_the_readme_states_the_report_byte_cap_it_enforces(self):
        """The prose must name the cap the code enforces.

        The number was pinned in tests already, but the README described the cap
        only as "its last-resort byte limit", so a reader could not tell what it
        was and a change to the constant would leave the prose stale.
        """
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        stated = f"{report_module.MAX_REPORT_BYTES // 1000:,} KB"
        self.assertIn(stated, readme)
        self.assertIn(f"stops at {report_module.MAX_CHANGE_TABLE_ROWS}", readme)

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
        # README contract: downloads allow 64 MiB, 30 seconds, and three attempts
        # before fallback; database and snapshot files share the 64 MiB limit.
        self.assertEqual(playerlist_module.MAX_FILE_BYTES, 64 * 1024 * 1024)
        self.assertEqual(sources.MAX_SOURCE_BYTES, 64 * 1024 * 1024)
        self.assertEqual(sources._MAX_URL_PARSE_CHARS, 4_096)
        self.assertEqual(sources.FETCH_TIMEOUT_SECONDS, 30)
        self.assertEqual(sources.FETCH_ATTEMPTS, 3)
        self.assertEqual(sources.RETRY_BACKOFF_SECONDS, 2)

    def test_the_documented_guard_and_account_bounds(self):
        # README contract: the guard requires more than 50 IDs and more than 20% removal.
        self.assertEqual(sync_module.MASS_DEMOTION_MIN_IDS, 50)
        self.assertEqual(sync_module.MASS_DEMOTION_MAX_FRACTION, 0.2)
        # The second, database-relative guard: the snapshot dwarfs the database,
        # so a purge of every tracked cheater stayed under the snapshot rule.
        self.assertEqual(sync_module.MASS_DEMOTION_MAX_DATABASE_FRACTION, 0.25)
        self.assertEqual(sync_module.MASS_DEMOTION_MIN_DATABASE_IDS, 5)
        # Steam account IDs are 32-bit; instance identifiers use 20 bits.
        self.assertEqual(playerlist_module.MAX_ACCOUNT_ID, 2**32)
        self.assertEqual(playerlist_module.MAX_STEAMID_INSTANCE, 2**20)


class InterruptTests(unittest.TestCase):
    """Ctrl-C used to leave a KeyboardInterrupt traceback on stderr."""

    def test_an_interrupt_is_reported_in_one_line_with_exit_130(self):
        stderr = io.StringIO()
        with mock.patch.object(sync_module, "run", side_effect=KeyboardInterrupt), contextlib.redirect_stderr(stderr):
            code = sync_module.main(["--database", "unused.json"])
        self.assertEqual(code, 130)
        self.assertEqual(stderr.getvalue().strip(), "interrupted.")
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_the_process_exit_status_preserves_the_sigint_code(self):
        """The Python entry point must preserve the CLI's conventional SIGINT status."""
        root = Path(__file__).resolve().parents[1]
        code = (
            f"import sys; sys.path.insert(0, {str(root / 'scripts')!r})\n"
            "from unittest.mock import patch\n"
            "import sync_vorobey_hackerpolice as sync\n"
            "with patch.object(sync, 'run', side_effect=KeyboardInterrupt):\n"
            "    sys.exit(sync.main(['--database', 'unused.json']))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], cwd=root, capture_output=True, text=True, encoding="utf-8", timeout=30
        )
        self.assertEqual(result.returncode, 130, result.stderr)
        self.assertEqual(result.stderr.strip(), "interrupted.")
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
