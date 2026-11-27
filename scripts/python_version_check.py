#!/usr/bin/env python3
"""Propose a Python upgrade once every pinned check tool supports a newer series.

The sync workflow pins ONE Python version (``PYTHON_VERSION``) for both the
checks and the write-capable sync job. This decides when that line may move.

The rule is a measurement, not a calendar: take the newest series GitHub's
runners can install, and move only when EVERY tool pinned in pyproject.toml's
``[dependency-groups]`` declares support for it. Nothing else gates it -- no
"newest minus one", no "skip x.y.0". Both were guesses standing next to this
measurement, and the measurement is strictly slower: by the time five tools
have shipped support, the series has been out for months and has patches.

Support is read from each tool's own PyPI classifiers, for the EXACT version
pinned today -- the one CI installs, not the newest one. A tool that works on a
new series without saying so reads as "not yet", which delays an upgrade but
never breaks one. That is the right way round for a bot nobody is watching.

Never pin the patch number: the workflow carries two numbers so security
releases arrive without an edit. This script preserves that.

Usage:
    python3 scripts/python_version_check.py --report out.md
    python3 scripts/python_version_check.py --report out.md --write
    python3 scripts/python_version_check.py --compare old.md new.md

Exit codes: 0 = the check ran (whether or not it proposes an upgrade),
1 = ``--compare`` found the two reports differ, 2 = the check could not run,
130 = interrupted (Ctrl-C).
"""

from __future__ import annotations

import argparse
import difflib
import itertools
import logging
import os
import re
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import sources
import sync_vorobey_hackerpolice as sync
from playerlist import error_reason, strict_json_loads
from sources import SyncError

LOGGER = logging.getLogger("python_version_check")

# Which Pythons actions/setup-python can actually install. Asking the runner
# images themselves beats hardcoding a release calendar that goes stale.
MANIFEST_URL = "https://api.github.com/repos/actions/python-versions/contents/versions-manifest.json"
PYPI_URL = "https://pypi.org/pypi/{name}/{version}/json"

DEFAULT_WORKFLOW = Path(".github/workflows/sync-vorobey-hackerpolice.yml")
DEFAULT_PYPROJECT = Path("pyproject.toml")

# A classifier names the series a release claims to run on.
_CLASSIFIER_PREFIX = "Programming Language :: Python :: "

_SERIES = re.compile(r"\d+\.\d+")
_RELEASE = re.compile(r"\d+\.\d+\.\d+")
# The pinned version lives in exactly one line of the workflow; capture its
# halves so a rewrite cannot disturb the quoting or indentation around it.
_PINNED_VERSION = re.compile(r'^(?P<head>  PYTHON_VERSION: ")(?P<series>\d+\.\d+)(?P<tail>")$', re.MULTILINE)
_TOOL_PIN = re.compile(r'"([A-Za-z][\w.-]*)==([\w.]+)"')

# Bound every decoded document: these are remote inputs like any other.
MAX_TOOLS = 50
# A failing comparison prints a diff; cap it so a wholly different report
# cannot bury the rest of the job log.
MAX_DIFF_LINES = 200

# The sync report stamps the minute it ran. Pinned to the exact shape
# report.py writes, so a reformat is caught rather than masked.
_RUN_AT = re.compile(r"^- Run at: \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$", re.MULTILINE)

Fetch = Callable[[str], bytes]


@dataclass(frozen=True)
class ToolVerdict:
    """One pinned tool's answer about one Python series."""

    name: str
    version: str
    supported: bool


@dataclass(frozen=True)
class Decision:
    """What the check found, and what (if anything) should change."""

    current: str
    newest: str
    candidate: str | None
    target: str | None
    verdicts: tuple[ToolVerdict, ...]
    releases: Mapping[str, str]

    @property
    def upgrade(self) -> bool:
        """True when a newer series is available and every tool backs it."""
        return self.target is not None


def _series_key(series: str) -> tuple[int, ...]:
    """Sort key for ``3.9`` vs ``3.10`` -- string order gets this wrong."""
    return tuple(int(part) for part in series.split("."))


def newest_releases(manifest: object) -> dict[str, str]:
    """Map each stable series to its newest patch release.

    Prereleases are skipped: ``stable`` must be exactly ``True``, never merely
    truthy, so a manifest that ever starts sending strings cannot promote a
    release candidate into the bot's runtime.
    """
    if not isinstance(manifest, list):
        raise SyncError("the Python version manifest is not a list")
    newest: dict[str, str] = {}
    for entry in manifest:
        if not isinstance(entry, dict) or entry.get("stable") is not True:
            continue
        release = entry.get("version")
        if not isinstance(release, str) or _RELEASE.fullmatch(release) is None:
            continue
        major, minor, _ = release.split(".", 2)
        series = f"{major}.{minor}"
        best = newest.get(series)
        if best is None or _series_key(release) > _series_key(best):
            newest[series] = release
    if not newest:
        raise SyncError("the Python version manifest listed no stable releases")
    return newest


def supported_series(metadata: object, tool: str) -> frozenset[str]:
    """The series a PyPI release declares support for, from its classifiers.

    No classifiers means no claim, which reads as "supports nothing" and holds
    the upgrade. A tool that stops publishing classifiers would freeze the
    version rather than wave an untested runtime through.
    """
    if not isinstance(metadata, dict):
        raise SyncError(f"PyPI returned no object for {tool}")
    info = metadata.get("info")
    if not isinstance(info, dict):
        raise SyncError(f"PyPI returned no release info for {tool}")
    classifiers = info.get("classifiers")
    if not isinstance(classifiers, list):
        return frozenset()
    found = set()
    for item in classifiers:
        if not isinstance(item, str) or not item.startswith(_CLASSIFIER_PREFIX):
            continue
        tail = item[len(_CLASSIFIER_PREFIX) :].strip()
        if _SERIES.fullmatch(tail):
            found.add(tail)
    return frozenset(found)


def pinned_tools(config_text: str) -> dict[str, str]:
    """Read the ``ci`` dependency group's exact pins, in file order."""
    block = re.search(r"^ci = \[\n(.*?)^\]", config_text, flags=re.MULTILINE | re.DOTALL)
    if block is None:
        raise SyncError("could not find the ci dependency group")
    tools = dict(_TOOL_PIN.findall(block[1]))
    if not tools:
        raise SyncError("the ci dependency group pins no tools")
    if len(tools) > MAX_TOOLS:
        raise SyncError(f"the ci dependency group pins more than {MAX_TOOLS} tools")
    return tools


def current_series(workflow_text: str) -> str:
    """The single series the workflow pins today."""
    matches = _PINNED_VERSION.findall(workflow_text)
    if len(matches) != 1:
        raise SyncError(f"expected exactly one PYTHON_VERSION line, found {len(matches)}")
    return str(matches[0][1])


def rewrite_version(workflow_text: str, target: str) -> str:
    """Return the workflow with its pinned series replaced by ``target``."""
    current_series(workflow_text)  # Refuse to edit a file with 0 or 2+ pins.
    return _PINNED_VERSION.sub(lambda match: f"{match['head']}{target}{match['tail']}", workflow_text, count=1)


def choose_target(current: str, available: Mapping[str, str], support: Mapping[str, frozenset[str]]) -> str | None:
    """The newest installable series above ``current`` that every tool backs."""
    common = set(available)
    for series in support.values():
        common &= series
    newer = [series for series in common if _series_key(series) > _series_key(current)]
    if not newer:
        return None
    return max(newer, key=_series_key)


def _decode_json(raw: bytes, url: str) -> object:
    """Parse a fetched body as JSON, naming the source when it is not."""
    try:
        # strict_json_loads, not json.loads: it rejects NaN/Infinity, duplicate
        # keys and unbounded integers, which are remote inputs here like any other.
        return strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SyncError(f"{sources.redact_url(url)} did not return readable JSON: {exc}") from exc


def _default_fetch(url: str) -> bytes:
    """Fetch over the sync's own hardened HTTPS path.

    Reusing it keeps one place that enforces HTTPS-only, refuses redirect
    downgrades, bounds the response and retries transient failures. A second
    fetcher here would be a second thing to get wrong.
    """
    return sources._fetch_bytes(url)


def fetch_manifest(fetch: Fetch) -> object:
    """Read the runner image manifest, unwrapping GitHub's base64 envelope."""
    document = _decode_json(fetch(MANIFEST_URL), MANIFEST_URL)
    if isinstance(document, dict):
        # The Contents API answers with the file wrapped, not the file itself.
        unwrapped = sources._unwrap_github_contents_envelope(document)
        if unwrapped is None:
            raise SyncError("the Python version manifest arrived in an envelope this check cannot open")
        document = _decode_json(unwrapped, MANIFEST_URL)
    return document


def gather(workflow_text: str, config_text: str, fetch: Fetch = _default_fetch) -> Decision:
    """Run the whole check: read the pins, ask the network, decide."""
    current = current_series(workflow_text)
    tools = pinned_tools(config_text)
    releases = newest_releases(fetch_manifest(fetch))

    support: dict[str, frozenset[str]] = {}
    for name, version in tools.items():
        url = PYPI_URL.format(name=name, version=version)
        support[name] = supported_series(_decode_json(fetch(url), url), name)

    newest = max(releases, key=_series_key)
    above = [series for series in releases if _series_key(series) > _series_key(current)]
    candidate = max(above, key=_series_key) if above else None
    target = choose_target(current, releases, support)
    # Report every tool against the series actually under consideration.
    measured = target or candidate
    verdicts = tuple(
        ToolVerdict(name, version, measured is not None and measured in support[name])
        for name, version in tools.items()
    )
    return Decision(current, newest, candidate, target, verdicts, releases)


def _running(decision: Decision, series: str) -> str:
    """``3.14`` -> ``3.14 (running 3.14.10)`` when the patch is known."""
    release = decision.releases.get(series)
    return f"`{series}` (running {release})" if release else f"`{series}`"


def render_report(decision: Decision, checked_at: str) -> str:
    """The pull-request body, or the job summary when nothing is proposed."""
    measured = decision.target or decision.candidate
    lines = [
        "## Python version check",
        "",
        f"- Current version: {_running(decision, decision.current)}",
        f"- Newest stable: {_running(decision, decision.newest)}",
        f"- Target: {_running(decision, decision.target) if decision.target else 'none'}",
        f"- Checked at: {checked_at}",
    ]
    total = len(decision.verdicts)
    if decision.target is not None:
        lines.append(f"- Tool support: **all {total} tools support {decision.target}**")
    elif measured is not None:
        blocked = sum(1 for verdict in decision.verdicts if not verdict.supported)
        lines.append(f"- Result: **not yet - {blocked} of {total} tools do not support {measured}**")
    else:
        lines.append(f"- Result: **already on the newest series all {total} tools support**")

    if measured is not None:
        lines += [
            "",
            (
                f"**Upgrading `{decision.current}` -> `{decision.target}`:**"
                if decision.target
                else f"**Holding at `{decision.current}`:**"
            ),
            "",
            f"| Tool | Pinned version | Supports {measured} |",
            "| --- | --- | --- |",
        ]
        lines += [
            f"| {verdict.name} | {verdict.version} | {'yes' if verdict.supported else '**no**'} |"
            for verdict in decision.verdicts
        ]

    lines.append("")
    if decision.target is not None:
        lines.append("Only the Python version changes; no script, test or database file is touched.")
        lines.append("Support is read from each tool's own PyPI metadata and is shown for review only.")
    else:
        lines.append("No pull request opened. Will check again next month.")
    return "\n".join(lines) + "\n"


def mask_clock(text: str, label: str) -> str:
    """Blank the one wall-clock line in a sync report so two runs can be compared.

    The report stamps the minute it ran, so two runs are never byte-identical
    and a raw ``cmp`` would fail on every upgrade. Exactly one line is masked
    and the count is checked: if that line ever vanishes, moves, or gains a
    twin, this raises instead of quietly widening what it ignores. Masking more
    than intended is how a comparison starts passing through real differences.
    """
    masked, count = _RUN_AT.subn("- Run at: <masked for comparison>", text)
    if count != 1:
        raise SyncError(f"expected exactly one timestamp line in {label}, found {count}")
    return masked


def compare_reports(old_text: str, new_text: str) -> list[str]:
    """Diff two sync reports, ignoring only the timestamp; empty means identical."""
    old_masked = mask_clock(old_text, "the report from the current version")
    new_masked = mask_clock(new_text, "the report from the proposed version")
    if old_masked == new_masked:
        return []
    diff = difflib.unified_diff(
        old_masked.splitlines(), new_masked.splitlines(), fromfile="current", tofile="proposed", lineterm=""
    )
    return list(itertools.islice(diff, MAX_DIFF_LINES))


def build_parser() -> argparse.ArgumentParser:
    """Command-line interface for the monthly check."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--workflow", type=Path, default=DEFAULT_WORKFLOW, help="workflow file holding PYTHON_VERSION")
    parser.add_argument("--pins", type=Path, default=DEFAULT_PYPROJECT, help="file holding the ci dependency group")
    parser.add_argument("--report", metavar="PATH", help="write the Markdown summary to this file")
    parser.add_argument("--write", action="store_true", help="apply the upgrade to the workflow file")
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("CURRENT", "PROPOSED"),
        type=Path,
        help="compare two sync reports instead of checking versions; differences exit 1",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="only print the Markdown summary")
    return parser


def _read(path: Path) -> str:
    """Read a UTF-8 input file, reporting the path rather than a traceback."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SyncError(f"cannot read {path}: {error_reason(exc)}") from exc


def run_comparison(args: argparse.Namespace) -> int:
    """Prove the proposed version produces the identical report, or say how it differs."""
    current, proposed = args.compare
    diff = compare_reports(_read(current), _read(proposed))
    if not diff:
        LOGGER.info("The two reports are identical (ignoring the run timestamp).")
        return 0
    LOGGER.error("The reports differ. The proposed Python version changes the published output:")
    for line in diff:
        LOGGER.error("%s", line)
    return 1


def run(args: argparse.Namespace, fetch: Fetch = _default_fetch) -> int:
    """Perform the check and report; returns the process exit status."""
    if args.compare:
        return run_comparison(args)
    workflow_text = _read(args.workflow)
    decision = gather(workflow_text, _read(args.pins), fetch)
    report = render_report(decision, time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()))

    if args.write and decision.target is not None:
        updated = rewrite_version(workflow_text, decision.target)
        try:
            args.workflow.write_text(updated, encoding="utf-8")
        except OSError as exc:
            raise SyncError(f"cannot write {args.workflow}: {error_reason(exc)}") from exc
        LOGGER.info("Pinned %s in %s.", decision.target, args.workflow)

    if args.report:
        try:
            Path(args.report).write_text(report, encoding="utf-8")
        except OSError as exc:
            raise SyncError(f"cannot write {args.report}: {error_reason(exc)}") from exc
    print(report, end="")
    _write_outputs(decision)
    return 0


def _write_outputs(decision: Decision) -> None:
    """Expose the decision to later workflow steps, when running in Actions."""
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    values = {
        "upgrade": "true" if decision.upgrade else "false",
        "current": decision.current,
        "target": decision.target or "",
    }
    try:
        # The sync's opener, which refuses a non-regular path: a FIFO planted at
        # $GITHUB_OUTPUT would otherwise hang the job until the 10-minute timeout.
        with sync._open_github_output(path) as handle:
            handle.write("".join(f"{key}={value}\n" for key, value in values.items()))
    except OSError as exc:
        raise SyncError(f"cannot write the GitHub step outputs: {error_reason(exc)}") from exc


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point: parse arguments, run the check, map failures to exit codes."""
    # Before the parser is built: see sync._force_plain_output.
    sync._force_plain_output()
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        stream=sys.stderr, level=logging.ERROR if args.quiet else logging.INFO, format="%(message)s", force=True
    )
    try:
        return run(args)
    except SyncError as exc:
        # A silent failure is worse than no check: make the run red.
        LOGGER.error("error: %s", exc)
        return 2
    except KeyboardInterrupt:
        LOGGER.warning("interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
