#!/usr/bin/env python3
"""Sync a TF2BD playerlist against the Vorobey hackerpolice cheater list.

Promotes matching entries (suspicious/racist -> cheater) and, with
``--demote``, removes cheater from entries that DISAPPEARED upstream.

Demotion is snapshot-based, never "absent from the current list": an ID is
only demoted if it is in the previous snapshot (``--snapshot``, default
``snapshot/playerlist.vorobey-hackerpolice.json``) AND missing from the
current list. Cheaters this database added manually -- never listed by
Vorobey at all -- are therefore never touched. Every run also refreshes
the snapshot with the RAW BYTES of the current upstream file (an exact
replica, never decoded/re-serialised) in the same working tree,
so the workflow commits both files in one pull request and the baseline
only advances when that PR is merged.

Usage:
    python3 scripts/sync_vorobey_hackerpolice.py --dry-run
    python3 scripts/sync_vorobey_hackerpolice.py --report out.md
    python3 scripts/sync_vorobey_hackerpolice.py --demote --report out.md

Exit codes: 0 = success, 2 = unusable database or Vorobey hackerpolice list.
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
from pathlib import Path

from playerlist import PlayerList, PlayerListError, ValidationResult, dumps, load, validate
from policy import Change, sync
from report import RunInfo, plural, render_report
from sources import (
    DEFAULT_SOURCES,
    VERSION,
    HackerpoliceIndex,
    SyncError,
    added_steamids,
    load_first_available_raw,
    load_snapshot,
    removed_steamids,
)

__version__ = VERSION

__all__ = ["DEFAULT_SNAPSHOT", "build_parser", "load_database", "main", "run", "write_database", "write_snapshot"]

LOGGER = logging.getLogger("sync_vorobey_hackerpolice")

DEFAULT_DATABASE = "playerlist.garou3299.json"
DEFAULT_SNAPSHOT = "snapshot/playerlist.vorobey-hackerpolice.json"

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
        help="Vorobey hackerpolice list URL or local path; repeat for fallbacks (default: built-in GitHub URLs)",
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
        help="remove cheater (or the whole entry) ONLY for SteamIDs that were in the previous snapshot "
        "but are gone from the current hackerpolice list (off by default)",
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
    """Expose step outputs when running inside GitHub Actions."""
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    lines = [f"{key}={str(value).lower() if isinstance(value, bool) else value}" for key, value in outputs.items()]
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def _log_validation(result: ValidationResult, context: str) -> None:
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


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write bytes via a temp file in the same directory, then atomically replace.

    A crash mid-write can never leave a half-written file behind, and the
    bytes land on disk exactly as given -- this is what makes the snapshot
    an exact replica of the upstream file (no encoding/newline translation
    ever touches them).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # mkstemp creates the file with O_EXCL and a unique name, so concurrent
    # runs -- separate processes or threads -- never share (and interleave
    # writes into) one temp file. The final replace is atomic, so readers
    # only ever see complete files.
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())  # content durable BEFORE it becomes visible
        # mkstemp forces 0600 permissions; keep the file's usual mode:
        # the replaced file's own permissions, or a plain 0644 for new ones.
        tmp.chmod(stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644)
        tmp.replace(path)
        _fsync_directory(path.parent)  # make the rename itself durable
    except OSError:
        tmp.unlink(missing_ok=True)  # never leave a stale .tmp file behind
        raise


def write_database(path: Path, database: PlayerList, original: str, *, dry_run: bool) -> bool:
    """Write the playerlist if it changed; returns whether it changed."""
    rendered = dumps(database)
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
        LOGGER.info("No changes: nothing to update.")
    elif dry_run:
        LOGGER.info("Dry run: would update %s in %s.", what, path)
    else:
        LOGGER.info("Updated %s in %s.", what, path)


def _same_file(first: Path, second: Path) -> bool:
    """True if two paths name the same file (via symlink, hardlink, or ``..``)."""
    if first.resolve() == second.resolve():
        return True
    try:
        return first.exists() and second.exists() and os.path.samefile(first, second)
    except OSError:
        return False


def run(args: argparse.Namespace) -> int:
    """Do the work; returns the process exit code."""
    database_path = Path(args.database)
    snapshot_path = Path(args.snapshot)
    if _same_file(snapshot_path, database_path):
        raise SyncError("--snapshot and --database must be different files")
    if args.report:
        # The report is written BEFORE the database/snapshot, so a report
        # path aliasing one of them would destroy it: when nothing else
        # changes, nothing would ever rewrite the real content back (and a
        # dry run would corrupt the database while claiming to write
        # nothing). Refuse aliased paths outright.
        report_path = Path(args.report)
        protected = [database_path, snapshot_path]
        protected += [Path(source) for source in args.source or [] if not source.startswith(("http://", "https://"))]
        if any(_same_file(report_path, path) for path in protected):
            raise SyncError("--report must not be the same file as --database, --snapshot, or a local --source")
    database, original = load_database(database_path)

    source_document, source, source_bytes = load_first_available_raw(args.source or DEFAULT_SOURCES)
    index = HackerpoliceIndex.build(source_document)
    LOGGER.info("Indexed %d Vorobey hackerpolice SteamIDs (%d unusable).", len(index.by_steamid), index.skipped)
    if not index.by_steamid:
        # An empty/unusable upstream list is a broken fetch, not a mass
        # unban: never promote, demote, or overwrite the snapshot from it.
        raise SyncError("the Vorobey hackerpolice list contains no usable SteamIDs, nothing was written")

    # --- Demotion baseline: previous snapshot vs. current list --------------
    snapshot = load_snapshot(snapshot_path)
    previous_index, previous_bytes = snapshot if snapshot is not None else (None, None)
    removed: set[str] = set()
    removed_count = 0
    # Snapshot diff vs. the previous snapshot, independent of --demote: how
    # many IDs the refreshed snapshot gains/loses. With no snapshot yet,
    # every current ID counts as newly added (initial snapshot).
    added_count = len(index.by_steamid)
    if previous_index is not None:
        added_count = len(added_steamids(previous_index, index))
        removed_count = len(removed_steamids(previous_index, index))
        LOGGER.info(
            "Snapshot diff vs. previous snapshot: %d SteamIDs added, %d removed (%d -> %d entries).",
            added_count,
            removed_count,
            len(previous_index.by_steamid),
            len(index.by_steamid),
        )
    demotion_note: str | None = None
    # Set to False when demotion was skipped as unsafe: the snapshot must
    # NOT advance then, or the skipped removals would be lost forever.
    update_snapshot = not args.no_update_snapshot
    if args.demote:
        if previous_index is None:
            demotion_note = f"skipped - no snapshot at {snapshot_path} yet, so no removal can be proven"
            LOGGER.warning("Demotion %s.", demotion_note)
        else:
            removed = removed_steamids(previous_index, index)
            removed_count = len(removed)
            LOGGER.info(
                "%d SteamIDs removed upstream since the snapshot (%d entries).",
                len(removed),
                len(previous_index.by_steamid),
            )
            if (
                not args.allow_mass_demotion
                and len(removed) > MASS_DEMOTION_MIN_IDS
                and len(removed) > MASS_DEMOTION_MAX_FRACTION * len(previous_index.by_steamid)
            ):
                demotion_note = (
                    f"skipped - {len(removed)} of {len(previous_index.by_steamid)} snapshot entries "
                    "disappeared upstream at once, which looks like an upstream problem, "
                    "not real removals (re-run with --allow-mass-demotion to force)"
                )
                LOGGER.warning("Demotion %s.", demotion_note)
                removed = set()
                update_snapshot = False

    changes = sync(database, index, include_proof=args.include_proof, enable_demote=args.demote, removed_ids=removed)

    result = validate(database)
    _log_validation(result, "refusing to write an invalid database")
    if result.errors:
        raise SyncError("the synced playerlist is invalid, nothing was written")

    # Decide what WOULD change before touching any file, render and write
    # the report first, and only then write the database and the snapshot:
    # if the report cannot be written, nothing else has been modified yet.
    modified = dumps(database) != original
    snapshot_changed = update_snapshot and source_bytes != previous_bytes

    report = render_report(
        RunInfo(
            database_path=database_path,
            source=source,
            source_total=index.total,
            source_skipped=index.skipped,
            dry_run=args.dry_run,
            include_proof=args.include_proof,
            changes=tuple(changes),
            previous_source_total=len(previous_index.by_steamid) if previous_index is not None else None,
            added_to_source=added_count,
            removed_from_source=removed_count,
            demotion_note=demotion_note,
            snapshot_changed=snapshot_changed,
        )
    )
    if args.report:
        try:
            Path(args.report).write_text(report + "\n", encoding="utf-8")
        except OSError as exc:
            raise SyncError(f"cannot write report {args.report}: {exc}") from exc
    print(report)

    # Write the database, then refresh the snapshot in the SAME working tree
    # (=> same pull request) so the baseline only advances once a human
    # merges the changes it produced. The snapshot refresh happens on every
    # run, even if the Garou database itself did not change, so a run whose
    # only change is the snapshot still opens a snapshot-only PR. Exception:
    # when demotion was skipped as unsafe (mass-demotion guard),
    # update_snapshot is False and the snapshot is left alone so the same
    # removals are re-evaluated next run.
    write_database(database_path, database, original, dry_run=args.dry_run)
    _log_outcome(modified, changes, database_path, dry_run=args.dry_run)
    if update_snapshot:
        write_snapshot(snapshot_path, source_bytes, previous_bytes, dry_run=args.dry_run)
        if snapshot_changed:
            LOGGER.info("%s snapshot %s.", "Would update" if args.dry_run else "Updated", snapshot_path)

    changed = (modified or snapshot_changed) and not args.dry_run
    _write_github_outputs(
        changed=changed,
        count=len(changes),
        modified=modified,
        snapshot_changed=snapshot_changed,
        snapshot_added=added_count,
        snapshot_removed=removed_count,
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
    except SyncError as exc:
        LOGGER.error("error: %s", exc)
        return 2
    except OSError as exc:
        # e.g. the database/snapshot/report path became unwritable mid-run:
        # report it cleanly instead of dumping a traceback.
        LOGGER.error("error: %s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
