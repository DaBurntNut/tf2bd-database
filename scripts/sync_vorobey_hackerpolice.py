#!/usr/bin/env python3
"""Sync a TF2BD playerlist against the Vorobey hackerpolice cheater list.

Promotes matching entries (suspicious/racist -> cheater) and, with
``--demote``, removes cheater from entries that DISAPPEARED upstream. An
entry is only deleted when the cheater tag was the last thing it had to say
about the player; any other attribute it carries (racist, exploiter, ...)
survives the demotion.

Demotion is snapshot-based, never "absent from the current list": an ID is
only demoted if it is in the previous snapshot (``--snapshot``, default
``snapshot/playerlist.vorobey-hackerpolice.json``) AND missing from the
current list. Cheaters this database added manually -- never listed by
Vorobey at all -- are therefore never touched. Every run also refreshes
the snapshot with the RAW BYTES of the current upstream file (an exact
replica, never decoded/re-serialised) in the same working tree,
so the workflow commits both files in one pull request and the baseline
only advances when that PR is merged.

The report also lists every SteamID that disappeared from the upstream
list since the previous snapshot in a ``SteamID | Profile Link`` table.
That diff describes the Vorobey list itself, so it is shown whether or not
``--demote`` is enabled -- and, because the Vorobey list stores no player
names, the profile permalink is the only human-readable identifier there.

Usage:
    python3 scripts/sync_vorobey_hackerpolice.py --dry-run
    python3 scripts/sync_vorobey_hackerpolice.py --report out.md
    python3 scripts/sync_vorobey_hackerpolice.py --demote --report out.md

Exit codes: 0 = success, 2 = a user-facing failure (unusable database,
snapshot or list, conflicting paths, an unwritable report), 130 = interrupted.
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import os
import stat
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from playerlist import PlayerList, PlayerListError, ValidationResult, dumps, load, validate
from policy import Change, sync
from report import RunInfo, plural, render_report
from sources import (
    # Re-exported here: sources.py owns the snapshot, so the CLI default and
    # the path named in the report cannot drift apart.
    DEFAULT_SNAPSHOT,
    DEFAULT_SOURCES,
    VERSION,
    HackerpoliceIndex,
    SyncError,
    added_steamids,
    is_url,
    load_first_available_raw,
    load_snapshot,
    removed_steamids,
)

__version__ = VERSION

__all__ = ["DEFAULT_SNAPSHOT", "build_parser", "load_database", "main", "run", "write_database", "write_snapshot"]

LOGGER = logging.getLogger("sync_vorobey_hackerpolice")

DEFAULT_DATABASE = "playerlist.garou3299.json"

# Mass-demotion guard: if upstream suddenly "removes" more than this share
# (and more than this many IDs), something upstream broke or was renamed --
# skip demotion for the run rather than stripping hundreds of entries.
MASS_DEMOTION_MIN_IDS = 50
MASS_DEMOTION_MAX_FRACTION = 0.2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--database",
        default=DEFAULT_DATABASE,
        metavar="PATH",
        help=f"playerlist to update (default: {DEFAULT_DATABASE})",
    )
    parser.add_argument(
        "--source",
        action="append",
        metavar="URL_OR_PATH",
        help="Vorobey hackerpolice list URL or local path (never the database or the snapshot file); "
        "repeat for fallbacks (default: built-in GitHub URLs)",
    )
    parser.add_argument("--report", metavar="PATH", help="also write the Markdown summary to this file")
    parser.add_argument("--dry-run", action="store_true", help="report what would change without writing the database")
    parser.add_argument(
        "--include-proof",
        action="store_true",
        help="copy the hackerpolice evidence link into each entry as a proof line (off by default)",
    )
    parser.add_argument(
        "--demote",
        action="store_true",
        help="remove cheater ONLY for SteamIDs that were in the previous snapshot but are gone from the "
        "current hackerpolice list (the entry is deleted only when no other attribute is left; off by default)",
    )
    parser.add_argument(
        "--snapshot",
        dest="snapshot",
        default=DEFAULT_SNAPSHOT,
        metavar="PATH",
        help=f"previous hackerpolice snapshot used as the demotion baseline (default: {DEFAULT_SNAPSHOT}); "
        "rewritten every run as an exact verbatim copy of the current upstream file",
    )
    parser.add_argument(
        "--no-update-snapshot",
        dest="no_update_snapshot",
        action="store_true",
        help="never refresh the snapshot (demotion candidates are then re-reported every run)",
    )
    parser.add_argument(
        "--allow-mass-demotion",
        action="store_true",
        help="demote even if an implausibly large share of the snapshot disappeared upstream",
    )
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-q", "--quiet", action="store_true", help="only print the Markdown summary")
    verbosity.add_argument("-v", "--verbose", action="store_true", help="log fetch attempts and index details")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _write_github_outputs(**outputs: str | int | bool) -> None:
    """Expose step outputs when running inside GitHub Actions.

    Every value written here is a count or a flag this run computed, so the
    ``KEY=value`` form is safe; ``str`` normalises bools to ``true``/``false``.
    """
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    lines = [f"{key}={str(value).lower() if isinstance(value, bool) else value}" for key, value in outputs.items()]
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def _log_validation(result: ValidationResult, context: str, *, warnings: bool = True) -> None:
    """Report what validation found; ``warnings=False`` keeps errors only.

    The database is validated twice (before the sync, and again before it is
    written). Warnings are about the entries themselves and were already
    reported by the first pass, so repeating them would print every unknown
    attribute twice for no new information.
    """
    if warnings:
        for warning in result.warnings:
            LOGGER.warning("%s", warning)
    for error in result.errors:
        LOGGER.error("%s: %s", context, error)


def load_database(path: Path) -> tuple[PlayerList, str]:
    """Read and validate a playerlist, raising SyncError with a readable reason."""
    try:
        database, original = load(path)
    except PlayerListError as exc:
        raise SyncError(str(exc)) from exc

    result = validate(database)
    _log_validation(result, f"{path} is not a usable playerlist")
    if result.errors:
        raise SyncError(f"{path} has {len(result.errors)} problem(s), nothing was written")
    return database, original


def _fsync_directory(directory: Path) -> None:
    """Best-effort fsync of a directory so a rename survives an OS crash."""
    try:
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass  # e.g. platforms that cannot fsync directories


def _write_target(path: Path) -> Path:
    """The file an atomic write must replace, following a symbolic link.

    ``os.replace`` replaces the *path*, so writing straight to a symlink
    would delete the link and leave the real file untouched. That is exactly
    how a playerlist is usually wired into TF2BD (``cfg/playerlist.json`` ->
    this repository), so the write goes to the link's target instead. A
    dangling link resolves to the path it points at, so the first write
    creates the file the user asked for.
    """
    if not path.is_symlink():
        return path
    try:
        return path.resolve()
    except (OSError, RuntimeError) as exc:  # RuntimeError: symlink loop
        raise SyncError(f"{path} is a symbolic link that cannot be resolved: {exc}") from exc


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write bytes via a temp file in the same directory, then atomically replace.

    A crash mid-write can never leave a half-written file behind, and the
    bytes land on disk exactly as given -- this is what makes the snapshot
    an exact replica of the upstream file (no encoding/newline translation
    ever touches them).
    """
    target = _write_target(path)
    tmp: Path | None = None
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        # mkstemp creates the file with O_EXCL and a unique name, so
        # concurrent runs -- separate processes or threads -- never share
        # (and interleave writes into) one temp file. The final replace is
        # atomic, so readers only ever see complete files.
        fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
        tmp = Path(tmp_name)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())  # content durable BEFORE it becomes visible
        # mkstemp forces 0600 permissions; keep the file's usual mode: the
        # replaced file's own permissions, or a plain 0644 for new ones.
        try:
            mode = stat.S_IMODE(target.stat().st_mode)
        except FileNotFoundError:
            mode = 0o644
        tmp.chmod(mode)
        tmp.replace(target)
        _fsync_directory(target.parent)  # make the rename itself durable
    except OSError as exc:
        if tmp is not None:
            tmp.unlink(missing_ok=True)  # never leave a stale .tmp file behind
        # Name the file the user asked for, not the temp file we were
        # creating: "Permission denied: /…/.list.json.k2j4.tmp" helps nobody.
        # strerror is the OS reason alone ("Permission denied"), without the
        # temp-file path the exception object carries.
        raise SyncError(f"cannot write {path}: {exc.strerror or exc}") from exc


def write_database(path: Path, rendered: str, original: str, *, dry_run: bool) -> bool:
    """Write the already-rendered playerlist if it changed; returns whether it changed.

    ``rendered`` is passed in rather than computed here so a run serialises
    the (possibly large) playerlist exactly once.
    """
    modified = rendered != original
    if modified and not dry_run:
        _atomic_write_bytes(path, rendered.encode("utf-8"))
    return modified


def write_snapshot(path: Path, raw: bytes, original: bytes | None, *, dry_run: bool) -> bool:
    """Overwrite the snapshot with the source's RAW bytes; returns whether it changed.

    The bytes are written verbatim -- never decoded, parsed or
    re-serialised -- so after an update the snapshot is an exact replica of
    the original upstream file, byte for byte.
    """
    changed = raw != original
    if changed and not dry_run:
        _atomic_write_bytes(path, raw)
    return changed


def _log_outcome(modified: bool, changes: list[Change], path: Path, *, dry_run: bool) -> None:
    count = len(changes)
    what = f"{count} {plural(count, 'entry', 'entries')}"
    if not modified:
        LOGGER.info("No database changes: nothing to update.")
    elif dry_run:
        LOGGER.info("Dry run: would update %s in %s.", what, path)
    else:
        LOGGER.info("Updated %s in %s.", what, path)


def _same_file(first: Path, second: Path) -> bool:
    """True if two paths name the same file (via symlink, hardlink, or ``..``).

    Never raises: a path that cannot be resolved (a symlink loop, a
    permission problem, an exotic filesystem) is compared textually instead
    of crashing the run with a traceback.
    """
    try:
        if first.resolve() == second.resolve():
            return True
    except (OSError, RuntimeError):  # RuntimeError: symlink loop
        return os.path.abspath(first) == os.path.abspath(second)
    try:
        return first.exists() and second.exists() and os.path.samefile(first, second)
    except OSError:
        return False


def _local_sources(sources: Sequence[str]) -> list[Path]:
    """The sources that are local files (as opposed to HTTP(S) URLs)."""
    return [Path(source) for source in sources if not is_url(source)]


def _check_input_paths(args: argparse.Namespace) -> None:
    """Refuse path combinations that would corrupt an input file.

    The report is written BEFORE the database/snapshot, so a report path
    aliasing one of them would destroy it: when nothing else changes,
    nothing would ever rewrite the real content back (and a dry run would
    corrupt the database while claiming to write nothing). A local --source
    aliasing the database or the snapshot is just as wrong: the run would
    "sync" our own file against itself and then overwrite the snapshot with
    it, silently making demotion impossible.
    """
    database_path = Path(args.database)
    snapshot_path = Path(args.snapshot)
    if _same_file(snapshot_path, database_path):
        raise SyncError("--snapshot and --database must be different files")

    local_sources = _local_sources(args.source or ())
    for source in local_sources:
        if _same_file(source, database_path):
            raise SyncError(f"--source {source} must not be the same file as --database")
        if _same_file(source, snapshot_path):
            raise SyncError(f"--source {source} must not be the same file as --snapshot")

    if not args.report:
        return
    report_path = Path(args.report)
    protected = [database_path, snapshot_path, *local_sources]
    if any(_same_file(report_path, path) for path in protected):
        raise SyncError("--report must not be the same file as --database, --snapshot, or a local --source")


def _load_upstream(sources: Sequence[str]) -> tuple[HackerpoliceIndex, str, bytes]:
    """Fetch the first usable upstream list and index it.

    An empty/unusable upstream list is a broken fetch, not a mass unban:
    never promote, demote, or overwrite the snapshot from it.
    """
    document, source, raw = load_first_available_raw(sources)
    index = HackerpoliceIndex.build(document)
    LOGGER.info("Indexed %d Vorobey hackerpolice SteamIDs (%d unusable).", len(index.by_steamid), index.skipped)
    if not index.by_steamid:
        raise SyncError("the Vorobey hackerpolice list contains no usable SteamIDs, nothing was written")
    return index, source, raw


@dataclass(frozen=True)
class _SnapshotDiff:
    """How the current upstream list differs from the previous snapshot."""

    previous_total: int | None
    added: int
    # Every SteamID the current list no longer contains. Reported in the PR
    # as a table (with profile links) whether or not --demote is used: it
    # describes the upstream list, not what this database did, and the
    # Vorobey list stores no names.
    removed: frozenset[str]


@dataclass(frozen=True)
class _DemotionPlan:
    """Which SteamIDs may be demoted, whether the snapshot advances, and why not."""

    candidates: frozenset[str]
    note: str | None
    advance_snapshot: bool


def _snapshot_diff(previous: HackerpoliceIndex | None, current: HackerpoliceIndex) -> _SnapshotDiff:
    """Compare the previous snapshot against the current upstream list."""
    if previous is None:
        # No baseline yet: every current ID is new in the initial snapshot.
        return _SnapshotDiff(previous_total=None, added=len(current.by_steamid), removed=frozenset())
    removed = frozenset(removed_steamids(previous, current))
    diff = _SnapshotDiff(
        previous_total=len(previous.by_steamid),
        added=len(added_steamids(previous, current)),
        removed=removed,
    )
    LOGGER.info(
        "Snapshot diff vs. previous snapshot: %d %s added, %d removed (%d -> %d entries).",
        diff.added,
        plural(diff.added, "SteamID", "SteamIDs"),
        len(removed),
        diff.previous_total,
        len(current.by_steamid),
    )
    return diff


def _plan_demotion(
    args: argparse.Namespace,
    diff: _SnapshotDiff,
    *,
    snapshot_path: Path,
) -> _DemotionPlan:
    """Decide what demotion may touch, refusing implausibly large removals.

    The mass-demotion guard treats "most of the list vanished at once" as an
    upstream problem (renamed file, truncated fetch) rather than as real
    removals, so a broken upstream run cannot strip the database.
    """
    advance = not args.no_update_snapshot
    if not args.demote:
        return _DemotionPlan(candidates=frozenset(), note=None, advance_snapshot=advance)

    if diff.previous_total is None:
        note = f"skipped - no snapshot at {snapshot_path} yet, so no removal can be proven"
        LOGGER.warning("Demotion %s.", note)
        return _DemotionPlan(candidates=frozenset(), note=note, advance_snapshot=advance)

    removed = diff.removed
    if (
        not args.allow_mass_demotion
        and len(removed) > MASS_DEMOTION_MIN_IDS
        and len(removed) > MASS_DEMOTION_MAX_FRACTION * diff.previous_total
    ):
        note = (
            f"skipped - {len(removed)} of {diff.previous_total} snapshot entries "
            "disappeared upstream at once, which looks like an upstream problem, "
            "not real removals (re-run with --allow-mass-demotion to force)"
        )
        LOGGER.warning("Demotion %s.", note)
        # The snapshot must NOT advance past removals we refused to apply,
        # or they could never be demoted later.
        return _DemotionPlan(candidates=frozenset(), note=note, advance_snapshot=False)

    return _DemotionPlan(candidates=removed, note=None, advance_snapshot=advance)


def _github_warning(message: str) -> None:
    """Emit a GitHub Actions warning annotation (no-op elsewhere).

    A run that only *skips* something -- the mass-demotion guard, or a
    missing baseline -- changes no file, so it would otherwise end as a
    silent green workflow run that nobody looks at.
    """
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::warning::{message}", flush=True)


def _emit_report(path: str | None, report: str) -> None:
    """Print the report and, when asked, write it where the workflow wants it."""
    if path:
        try:
            Path(path).write_text(report + "\n", encoding="utf-8")
        except OSError as exc:
            raise SyncError(f"cannot write report {path}: {exc}") from exc
    print(report)


def run(args: argparse.Namespace) -> int:
    """Do the work; returns the process exit code."""
    _check_input_paths(args)
    database_path = Path(args.database)
    snapshot_path = Path(args.snapshot)

    # Everything local is read and validated BEFORE the network is touched:
    # a corrupt database or snapshot fails immediately instead of after a
    # fetch (or several, with retries), and the baseline is known before any
    # decision is made.
    database, original = load_database(database_path)
    snapshot = load_snapshot(snapshot_path)
    previous_index, previous_bytes = snapshot if snapshot is not None else (None, None)

    index, source, source_bytes = _load_upstream(args.source or DEFAULT_SOURCES)

    diff = _snapshot_diff(previous_index, index)
    if not args.demote and diff.removed:
        # Nothing is withheld here: the snapshot is an exact copy of the
        # upstream file, so refreshing it is always correct. The consequence
        # deserves a warning though -- the removals listed in this run's
        # report are the last time they can be demoted, because the next
        # snapshot no longer contains them.
        removed_count = len(diff.removed)
        LOGGER.warning(
            "Demotion is off (no --demote): %d %s disappeared upstream and will not be demoted; "
            "once the refreshed snapshot lands, %s can no longer be demoted automatically.",
            removed_count,
            plural(removed_count, "SteamID", "SteamIDs"),
            plural(removed_count, "it", "they"),
        )
    plan = _plan_demotion(args, diff, snapshot_path=snapshot_path)
    if plan.note:
        _github_warning(f"Demotion {plan.note}")

    changes = sync(
        database,
        index,
        include_proof=args.include_proof,
        enable_demote=args.demote,
        removed_ids=plan.candidates,
    )

    result = validate(database)
    _log_validation(result, "refusing to write an invalid database", warnings=False)
    if result.errors:
        raise SyncError("the synced playerlist is invalid, nothing was written")

    # Decide what WOULD change before touching any file, render and write the
    # report first, and only then write the database and the snapshot: if the
    # report cannot be written, nothing else has been modified yet.
    rendered = dumps(database)
    snapshot_changed = plan.advance_snapshot and source_bytes != previous_bytes

    report = render_report(
        RunInfo(
            database_path=database_path,
            source=source,
            source_total=index.total,
            source_skipped=index.skipped,
            source_duplicates=index.duplicates,
            dry_run=args.dry_run,
            include_proof=args.include_proof,
            changes=tuple(changes),
            previous_source_total=diff.previous_total,
            added_to_source=diff.added,
            removed_from_source=len(diff.removed),
            removed_upstream=tuple(diff.removed),
            demotion_note=plan.note,
            snapshot_changed=snapshot_changed,
            snapshot_path=snapshot_path,
        )
    )
    _emit_report(args.report, report)

    # Write the database, then refresh the snapshot in the SAME working tree
    # (=> same pull request) so the baseline only advances once a human
    # merges the changes it produced. The snapshot refresh happens on every
    # run, even if the Garou database itself did not change, so a run whose
    # only change is the snapshot still opens a snapshot-only PR. Exception:
    # when demotion was skipped as unsafe (mass-demotion guard),
    # plan.advance_snapshot is False and the snapshot is left alone so the
    # same removals are re-evaluated next run.
    modified = write_database(database_path, rendered, original, dry_run=args.dry_run)
    _log_outcome(modified, changes, database_path, dry_run=args.dry_run)
    refreshed = plan.advance_snapshot and write_snapshot(
        snapshot_path, source_bytes, previous_bytes, dry_run=args.dry_run
    )
    if refreshed:
        LOGGER.info("%s snapshot %s.", "Would update" if args.dry_run else "Updated", snapshot_path)

    _write_github_outputs(
        changed=(modified or snapshot_changed) and not args.dry_run,
        count=len(changes),
        modified=modified,
        snapshot_changed=snapshot_changed,
        snapshot_added=diff.added,
        snapshot_removed=len(diff.removed),
        demotion_skipped=bool(plan.note),
    )
    return 0


def _force_utf8_streams() -> None:
    """Make stdout/stderr UTF-8 so the report can never crash the run.

    The report contains arrows and non-ASCII player names; on an ASCII or
    legacy-codepage stream (e.g. Windows cp1252, PYTHONIOENCODING=ascii)
    printing it would raise UnicodeEncodeError mid-run. Unencodable
    characters fall back to backslash escapes instead of an exception.
    """
    for stream in (sys.stdout, sys.stderr):
        # StringIO in tests (or an already-closed stream) cannot be
        # reconfigured -- those are already safe, so skip them silently.
        with contextlib.suppress(AttributeError, OSError, ValueError):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")  # type: ignore[union-attr]


def main(argv: Sequence[str] | None = None) -> int:
    _force_utf8_streams()
    args = build_parser().parse_args(argv)

    level = logging.INFO
    if args.quiet:
        level = logging.ERROR
    elif args.verbose:
        level = logging.DEBUG
    logging.basicConfig(stream=sys.stderr, level=level, format="%(message)s", force=True)
    try:
        return run(args)
    except (SyncError, OSError) as exc:
        # A user-facing failure (bad input/unreachable source, or e.g. the
        # database/snapshot/report path becoming unwritable mid-run): report
        # it cleanly instead of dumping a traceback. -v still shows the
        # traceback for debugging.
        LOGGER.error("error: %s", exc)
        LOGGER.debug("details", exc_info=True)
        return 2
    except KeyboardInterrupt:
        # 130 is the conventional exit status for an interrupted command.
        LOGGER.error("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
