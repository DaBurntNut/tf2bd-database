#!/usr/bin/env python3
"""Run the whole suite with a clock that never reads the same twice.

The report header carries the wall-clock minute, so any test that renders the
same run twice and compares the results only passes while the minute happens
not to tick between them. That is a coin flip weighted heavily towards
passing, which is the worst shape a failure can take: it goes red once in a
few thousand runs, nobody can reproduce it, and everyone learns to press
re-run instead of looking. Two such tests existed here and one of them did
fail a real run.

Advancing the clock a minute on every read turns that rare flake into a
guaranteed failure, so this script makes the condition reproducible and keeps
it reproducible. Run from CI after the normal suite: the ordinary run proves
the tests pass, this one proves none of them depended on the clock standing
still.

Only ``time.gmtime()`` is advanced. It is the single clock the published
output reads, and leaving ``time.time()`` alone keeps timeouts, retries and
logging behaving normally, so a failure here means a real dependency on the
displayed time rather than a side effect of the harness.

Exit status is 0 when every test passes, 1 when any test fails.
"""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
SECONDS_PER_READ = 60

sys.path.insert(0, str(TESTS))
sys.path.insert(0, str(TESTS.parent / "scripts"))

_real_gmtime = time.gmtime
_reads = [0]


def _ticking_gmtime(seconds: float | None = None) -> time.struct_time:
    """Return a later moment on every argument-free read.

    A call that passes an explicit timestamp is asking to convert a specific
    moment rather than to read the clock, so it is answered truthfully.
    """
    if seconds is not None:
        return _real_gmtime(seconds)
    _reads[0] += SECONDS_PER_READ
    return _real_gmtime(time.time() + _reads[0])


def main() -> int:
    time.gmtime = _ticking_gmtime  # type: ignore[assignment]
    try:
        suite = unittest.TestLoader().discover(str(TESTS))
        result = unittest.TextTestRunner(verbosity=1).run(suite)
    finally:
        time.gmtime = _real_gmtime  # type: ignore[assignment]

    broken = result.failures + result.errors
    if broken:
        print(f"\n{len(broken)} test(s) depend on the clock standing still:", file=sys.stderr)
        for test, _ in broken:
            print(f"  {test.id()}", file=sys.stderr)
        print(
            "\nEach renders the same run more than once and compares the results. "
            "Wrap the comparison in tests._support.frozen_clock().",
            file=sys.stderr,
        )
        return 1
    print(f"\nNo test depends on the clock standing still ({result.testsRun} tests, clock advanced on every read).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
