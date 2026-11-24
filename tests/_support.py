"""Shared fixtures for the sync-bot tests.

Importing this module isolates tests from the runner's GITHUB_OUTPUT file and
puts the production scripts on sys.path. Test discovery imports this module
from each focused test module.
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

# Isolate tests from Actions output; output tests supply a temporary file.
os.environ.pop("GITHUB_OUTPUT", None)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from sources import HackerpoliceIndex
from sync_vorobey_hackerpolice import main

HACKERPOLICE_PROOF = "https://discord.com/channels/1/2"
SOURCE_URL = "https://example.invalid/list.json"
SOURCE_API_URL = "https://api.github.com/repos/Nocrex/Tom/contents/playerlist.vorobey-hackerpolice.json"
SOURCE_BODY = b'\xef\xbb\xbf{"players": [{"steamid": "[U:1:100]", "attributes": ["cheater"]}]}'


@contextlib.contextmanager
def frozen_clock():
    """Hold the report's ``Run at:`` line still for the duration of a test.

    The header carries the wall-clock minute, so any test that renders the
    same run twice and compares the two is a coin flip: it passes unless the
    minute happens to tick between the renders. That failed once in CI here,
    and a test that fails once every few thousand runs is worse than one that
    fails every time, because it trains everyone to re-run instead of look.

    Tests about size, shrinking or stability should freeze the clock; tests
    about the timestamp itself should not.
    """
    import time as _time

    fixed = _time.gmtime(1_700_000_000)
    with mock.patch.object(_time, "gmtime", return_value=fixed):
        yield


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


def run_sync_and_read_outputs(*, database, snapshot, source, dry_run=False) -> dict[str, str]:
    """Run the real CLI over temporary files and return its step outputs."""
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
