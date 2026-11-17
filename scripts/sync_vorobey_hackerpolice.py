#!/usr/bin/env python3
"""Sync a TF2BD playerlist against the Vorobey hackerpolice cheater list.

Promotes matching entries (suspicious/racist -> cheater) and, with
``--demote``, removes cheater from entries that DISAPPEARED upstream.

Demotion is snapshot-based, never "absent from the current list": an ID is
only demoted if it is in the previous snapshot (``--snapshot``, default
``snapshot/playerlist.vorobey-hackerpolice.json``) AND missing from the
current list. Cheaters this database added manually -- never listed by
Vorobey at all -- are therefore never touched. When it is safe and the
upstream bytes differ, the snapshot is refreshed with the RAW BYTES of the
current file (an exact replica, never decoded/re-serialised) alongside the
database. Pull-request mode proposes both together; manual direct-commit mode
publishes both together on the default branch.

The snapshot is deliberately NOT advanced when the removals it found could
not be applied -- demotion disabled (``--demote`` missing), vetoed by the
mass-demotion guard, or ambiguous because the current list has unusable rows --
because advancing it would forget those removals.

The report (pull request body / job summary) lists every SteamID that
disappeared from the upstream list since the previous snapshot, as a
``| SteamID | Profile Link | SteamHistory |`` table -- the upstream list
stores no player names, so each ID is shown with its Steam profile
permalink and its SteamHistory page.

Usage:
    python3 scripts/sync_vorobey_hackerpolice.py --dry-run
    python3 scripts/sync_vorobey_hackerpolice.py --report out.md
    python3 scripts/sync_vorobey_hackerpolice.py --demote --report out.md

Exit codes: 0 = success, 2 = refused or failed (an unusable database or
upstream list, paths that alias each other, or output that cannot be written),
130 = interrupted (Ctrl-C).
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import logging
import os
import stat
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from playerlist import PlayerList, PlayerListError, ValidationResult, display_path, dumps, error_reason, load, validate
from policy import Change, sync
from report import RunInfo, plural, render_report
from sources import (
    DEFAULT_SOURCES,
    VERSION,
    HackerpoliceIndex,
    SyncError,
    added_steamids,
    http_scheme,
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
        help="Vorobey hackerpolice list HTTPS URL or local path; repeat for fallbacks (default: built-in GitHub URLs)",
    )
    parser.add_argument("--report", metavar="PATH", help="also write the Markdown summary to this file")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would change without updating the database or snapshot (a requested report is still written)",
    )
    parser.add_argument(
        "--demote",
        action="store_true",
        help="remove cheater (or the whole entry) ONLY for SteamIDs that were in the previous snapshot "
        "but are gone from the current hackerpolice list (off by default); while it is off, a run that "
        "finds removals leaves the snapshot untouched so they stay demotion candidates",
    )
    parser.add_argument(
        "--snapshot",
        dest="snapshot",
        default=DEFAULT_SNAPSHOT,
        metavar="PATH",
        help=f"previous hackerpolice snapshot used as the demotion baseline (default: {DEFAULT_SNAPSHOT}); "
        "refreshed when the upstream bytes differ, as an exact verbatim copy",
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
        help="override the mass-demotion veto (an incomplete-source safety check still blocks demotions)",
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
    # One output per line: a newline inside a value would silently inject an
    # extra output, so flatten it. Every caller passes a bool or an int today,
    # but this keeps the file well formed if a caller ever passes free text.
    lines = []
    for key, value in outputs.items():
        text = str(value).lower() if isinstance(value, bool) else str(value)
        lines.append(f"{key}={' '.join(text.splitlines())}")
    try:
        with Path(path).open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    except (OSError, ValueError) as exc:
        # Name the output file rather than exposing a bare or oversized OS path.
        raise SyncError(f"cannot write the GitHub step outputs at {display_path(path)}: {error_reason(exc)}") from exc


def _check_github_output() -> None:
    """Refuse obvious ``$GITHUB_OUTPUT`` path failures before reading inputs.

    Append-open catches a directory, a missing parent, and permission errors
    before network or database work begins. It cannot prove a later write will
    succeed (for example, a full device accepts open), so the real append also
    happens before the report, database, snapshot, or stdout is written.
    """
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    try:
        # Append mode creates the file if the runner has not, and fails exactly
        # the way the real write would (a directory, a missing parent, no
        # permission). Nothing is written.
        with Path(path).open("a", encoding="utf-8"):
            pass
    except (OSError, ValueError) as exc:
        raise SyncError(f"cannot write the GitHub step outputs at {display_path(path)}: {error_reason(exc)}") from exc


def _log_validation(result: ValidationResult, context: str) -> None:
    for warning in result.warnings:
        LOGGER.warning("%s", warning)
    if result.warnings_omitted:
        LOGGER.warning("%s additional validation warning(s) omitted", result.warnings_omitted)
    for error in result.errors:
        LOGGER.error("%s: %s", context, error)
    if result.errors_omitted:
        LOGGER.error("%s: %s additional validation problem(s) omitted", context, result.errors_omitted)


def load_database(path: Path) -> tuple[PlayerList, str]:
    """Read and validate a playerlist, raising SyncError with a readable reason."""
    try:
        database, original = load(path)
    except PlayerListError as exc:
        raise SyncError(str(exc)) from exc

    result = validate(database)
    _log_validation(result, f"{display_path(path)} is not a usable playerlist")
    if result.error_count:
        raise SyncError(f"{display_path(path)} has {result.error_count} problem(s), nothing was written")
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
    # Write THROUGH a symlink. Replacing the link itself would delete it and
    # leave the file it points at -- the one the operator actually keeps, and
    # the one every other tool reads -- untouched, while this run reported
    # success. Resolve strictly enough to detect a self-referential/recursive
    # link: os.path.realpath() silently returns the unresolved name for a loop,
    # and replacing that name would destroy the link rather than refuse it.
    target = path
    if path.is_symlink():
        try:
            target = path.resolve(strict=False)
        except RuntimeError as exc:
            # pathlib has surfaced symlink loops as RuntimeError on some
            # versions and OSError on others. Normalize this form into the
            # write error path, which names the operator-supplied output path.
            raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), os.fspath(path)) from exc
    # mkstemp creates the file with O_EXCL and a unique name, so concurrent
    # runs -- separate processes or threads -- never share (and interleave
    # writes into) one temp file. The final replace is atomic, so readers
    # only ever see complete files.
    fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())  # content durable BEFORE it becomes visible
        # mkstemp forces 0600 permissions, so put back the mode the file
        # should have. An existing file keeps exactly its own mode. A NEW file
        # takes the umask-derived default (0666 & ~umask): chmod'ing a flat
        # 0644 overrode the operator's umask, so under `umask 077` -- which
        # means "only I may read this" -- the snapshot and the report were
        # created world-readable on a shared machine.
        if target.exists():
            mode = stat.S_IMODE(target.stat().st_mode)
        else:
            mask = os.umask(0)
            os.umask(mask)  # set-and-restore: os.umask has no read-only form
            mode = 0o666 & ~mask
        tmp.chmod(mode)
        tmp.replace(target)
        _fsync_directory(target.parent)  # make the rename itself durable
    finally:
        # Runs on success as well, where the rename already moved the file and
        # this is a no-op. Any other outcome -- OSError, Ctrl-C, SystemExit --
        # deletes the temp file, so an interrupted run cannot leave a stray
        # .tmp file in the repository. (SIGTERM has no Python handler: the
        # process dies at once. The runners are ephemeral and both git add calls
        # name their paths, so nothing is committed from such a run.)
        tmp.unlink(missing_ok=True)


def write_database(path: Path, rendered: str, original: str, *, dry_run: bool) -> bool:
    """Write the serialised playerlist if it changed; returns whether it changed.

    ``rendered`` is the text the caller already produced to decide what
    changed, so the database is never serialised twice and what was compared
    is exactly what is written.
    """
    modified = rendered != original
    if modified and not dry_run:
        try:
            _atomic_write_bytes(path, rendered.encode("utf-8"))
        except (OSError, ValueError) as exc:
            # Name the file the operator asked for; the raw OSError mentions
            # the temporary file, which means nothing to them. ValueError: a
            # path the OS cannot encode (embedded NUL, lone surrogate).
            raise SyncError(f"cannot write {display_path(path)}: {error_reason(exc)}") from exc
    return modified


def write_snapshot(path: Path, raw: bytes, original: bytes | None, *, dry_run: bool) -> bool:
    """Overwrite the snapshot with the source's RAW bytes; returns whether it changed.

    The bytes are written verbatim -- never decoded, parsed or
    re-serialised -- so after an update the snapshot is an exact replica of
    the original upstream file, byte for byte.
    """
    changed = raw != original
    if changed and not dry_run:
        try:
            _atomic_write_bytes(path, raw)
        except (OSError, ValueError) as exc:
            raise SyncError(f"cannot write {display_path(path)}: {error_reason(exc)}") from exc
    return changed


def _log_outcome(modified: bool, changes: list[Change], path: Path, *, dry_run: bool) -> None:
    count = len(changes)
    what = f"{count} {plural(count, 'entry', 'entries')}"
    if not modified:
        # Scoped to the database on purpose: a snapshot-only run writes the
        # snapshot and opens a pull request, so a bare "No changes" would
        # contradict both the report body and the log line that follows.
        LOGGER.info("No database changes: nothing to update.")
    elif not changes:
        # The file changes without any tag changing: entries were re-sorted
        # or the file's formatting was restored. "Updated 0 entries" would be
        # nonsense, and "No changes" would contradict the written file.
        LOGGER.info(
            "%s %s (no tag changes: the file was normalised).",
            "Dry run: would rewrite" if dry_run else "Rewrote",
            display_path(path),
        )
    elif dry_run:
        LOGGER.info("Dry run: would update %s in %s.", what, display_path(path))
    else:
        LOGGER.info("Updated %s in %s.", what, display_path(path))


def _same_file(first: Path, second: Path) -> bool:
    """True if two paths name the same file (via symlink, hardlink, or ``..``)."""
    try:
        if first.resolve() == second.resolve():
            return True
        return first.exists() and second.exists() and os.path.samefile(first, second)
    except (OSError, ValueError, RuntimeError):
        # ValueError: a path the OS cannot encode (embedded NUL, lone
        # surrogate). pathlib has reported symlink loops as either RuntimeError
        # or OSError depending on version; resolving both paths happens here,
        # so an uncaught loop escaped as a traceback for every guarded path.
        # Such a path cannot be an alias of a real file; the operation that uses
        # it refuses it cleanly further down.
        return False


def _guard_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    """Refuse any arrangement where the tool would overwrite its own inputs.

    Every check exists because each one is a real way to lose the database or
    to make a run succeed while doing nothing: the report is written before
    the database, so an aliased report path would destroy it; a --source
    pointing at the database would compare the file with itself and then
    rewrite it; and an output path in a directory that does not exist is a
    typo, never a design case.
    """
    # An empty path is what a shell hands over for --database "$UNSET": Path("")
    # is ".", so the run used to fail with "Is a directory: '.'" -- and an empty
    # --report was worse, because it is falsy and was silently ignored, so the
    # operator got no report and no warning. Name the real problem instead.
    for flag, value in (("--database", args.database), ("--snapshot", args.snapshot), ("--report", args.report)):
        if value == "":
            raise SyncError(f"{flag} must not be empty")
    if any(source == "" for source in args.source or []):
        raise SyncError("--source must not be empty")

    database_path = Path(args.database)
    snapshot_path = Path(args.snapshot)
    if _same_file(snapshot_path, database_path):
        raise SyncError("--snapshot and --database must be different files")
    if args.report:
        report_path = Path(args.report)
        protected = [database_path, snapshot_path]
        protected += [Path(source) for source in args.source or [] if not http_scheme(source)]
        if any(_same_file(report_path, path) for path in protected):
            raise SyncError("--report must not be the same file as --database, --snapshot, or a local --source")
    for source in args.source or []:
        if http_scheme(source):
            continue
        # A local --source may not be any of the files this run writes or reads
        # as a baseline. Pointing it at the SNAPSHOT is the subtle one: the run
        # then compares the baseline with itself, so the diff is always
        # "0 added, 0 removed", no removal can ever be proven, and every
        # promotion is computed from the stale baseline instead of the live
        # list -- a run that exits 0 and looks healthy while the bot is
        # quietly demoting nothing and never noticing an upstream change.
        for flag, other in (("--database", database_path), ("--snapshot", snapshot_path)):
            if _same_file(Path(source), other):
                raise SyncError(f"--source must not be the same file as {flag}")

    # GitHub step outputs are an output file too. If one path aliases the
    # database, snapshot, report, or a local source, appending the key=value
    # lines can corrupt that file or silently erase the outputs when the other
    # writer atomically replaces it. Check before loading or writing anything.
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        github_protected = [("--database", database_path), ("--snapshot", snapshot_path)]
        if args.report:
            github_protected.append(("--report", Path(args.report)))
        github_protected.extend(("--source", Path(source)) for source in args.source or [] if not http_scheme(source))
        for flag, path in github_protected:
            if _same_file(Path(github_output), path):
                raise SyncError(f"GITHUB_OUTPUT must not be the same file as {flag}")

    # A writer must not invent directories. `mkdir -p` on a typo'd --snapshot
    # silently wrote a FRESH baseline, and a fresh baseline proves nothing was
    # removed (previous - current is empty), so --demote would quietly do
    # nothing forever -- the same silent stall the --source == --snapshot guard
    # above exists to prevent. The snapshot FILE may legitimately be absent
    # (that is the first run); its directory may not be.
    outputs = [("--snapshot", snapshot_path)]
    if args.report:
        outputs.append(("--report", Path(args.report)))
    for flag, path in outputs:
        if not path.parent.is_dir():
            raise SyncError(f"{flag} directory does not exist: {display_path(path.parent)}")

    return database_path, snapshot_path


def _load_index(args: argparse.Namespace) -> tuple[HackerpoliceIndex, str, bytes]:
    """Fetch the upstream list and index it, refusing an empty result."""
    source_document, source, source_bytes = load_first_available_raw(args.source or DEFAULT_SOURCES)
    index = HackerpoliceIndex.build(source_document)
    LOGGER.info("Indexed %d Vorobey hackerpolice SteamIDs (%d unusable).", len(index.by_steamid), index.skipped)
    if not index.by_steamid:
        # An empty/unusable upstream list is a broken fetch, not a mass
        # unban: never promote, demote, or overwrite the snapshot from it.
        raise SyncError("the Vorobey hackerpolice list contains no usable SteamIDs, nothing was written")
    return index, source, source_bytes


def _plan_demotion(
    args: argparse.Namespace,
    previous_index: HackerpoliceIndex | None,
    removed_upstream: set[str],
    snapshot_path: Path,
    *,
    source_skipped: int = 0,
) -> tuple[set[str], bool, str | None, str | None]:
    """Decide what may be demoted, and whether the baseline may advance.

    Returns ``(removed, update_snapshot, demotion_note, snapshot_note)``. The
    snapshot is held back whenever removals could not be applied, so a
    skipped removal is never silently forgotten.
    """
    demotion_note: str | None = None
    # Set to False when demotion was skipped as unsafe: the snapshot must
    # NOT advance then, or the skipped removals would be lost forever.
    update_snapshot = not args.no_update_snapshot
    snapshot_note: str | None = "**not refreshed** (`--no-update-snapshot`)" if args.no_update_snapshot else None
    removed: set[str] = set()

    if args.demote:
        if previous_index is None:
            demotion_note = f"skipped - no snapshot at {display_path(snapshot_path)} yet, so no removal can be proven"
            LOGGER.warning("Demotion %s.", demotion_note)
        else:
            removed = set(removed_upstream)
            LOGGER.info(
                "%d SteamIDs removed upstream since the snapshot (%d entries).",
                len(removed),
                len(previous_index.by_steamid),
            )
            if removed and source_skipped:
                demotion_note = (
                    f"skipped - the current list contains {source_skipped:,} unusable "
                    f"SteamID {plural(source_skipped, 'entry', 'entries')}, so its upstream removals "
                    "cannot be confirmed safely"
                )
                LOGGER.warning("Demotion %s.", demotion_note)
                removed = set()
                update_snapshot = False
                snapshot_note = (
                    "**not refreshed** - the current list is incomplete, so these removals stay "
                    "demotion candidates until a clean list can confirm them"
                )
            elif (
                not args.allow_mass_demotion
                and len(removed) > MASS_DEMOTION_MIN_IDS
                and len(removed) > MASS_DEMOTION_MAX_FRACTION * len(previous_index.by_steamid)
            ):
                demotion_note = (
                    f"skipped - {len(removed):,} of {len(previous_index.by_steamid):,} snapshot entries "
                    "disappeared upstream at once, which looks like an upstream problem, "
                    "not real removals (re-run with --allow-mass-demotion to force)"
                )
                LOGGER.warning("Demotion %s.", demotion_note)
                removed = set()
                update_snapshot = False
                snapshot_note = "**not refreshed** - demotion was skipped, so these removals stay demotion candidates"

    if not args.demote and removed_upstream:
        # Demotion is off, so these removals cannot be applied. Advancing the
        # baseline anyway would silently forget them forever (the next run
        # would see "previous == current"). Keep the old snapshot instead.
        update_snapshot = False
        snapshot_note = (
            f"**not refreshed** - demotion is disabled (`--demote`) so the "
            f"{len(removed_upstream):,} upstream {plural(len(removed_upstream), 'removal', 'removals')} "
            "could not be applied; the baseline is kept so they stay demotion candidates"
        )
        LOGGER.warning(
            "Snapshot left alone: demotion is disabled and %d upstream removals are pending.", len(removed_upstream)
        )

    return removed, update_snapshot, demotion_note, snapshot_note


def run(args: argparse.Namespace) -> int:
    """Do the work; returns the process exit code."""
    database_path, snapshot_path = _guard_paths(args)
    _check_github_output()
    database, original = load_database(database_path)
    index, source, source_bytes = _load_index(args)

    # --- Demotion baseline: previous snapshot vs. current list --------------
    snapshot = load_snapshot(snapshot_path)
    previous_index, previous_bytes = snapshot if snapshot is not None else (None, None)
    # Snapshot diff vs. the previous snapshot, independent of --demote: how
    # many IDs the refreshed snapshot gains/loses. With no snapshot yet,
    # every current ID counts as newly added (initial snapshot).
    added_count = len(index.by_steamid)
    removed_upstream: set[str] = set()
    removed_count = 0
    if previous_index is not None:
        added_count = len(added_steamids(previous_index, index))
        removed_upstream = removed_steamids(previous_index, index)
        removed_count = len(removed_upstream)
        LOGGER.info(
            "Snapshot diff vs. previous snapshot: %d SteamIDs added, %d removed (%d -> %d entries).",
            added_count,
            removed_count,
            len(previous_index.by_steamid),
            len(index.by_steamid),
        )

    removed, update_snapshot, demotion_note, snapshot_note = _plan_demotion(
        args, previous_index, removed_upstream, snapshot_path, source_skipped=index.skipped
    )
    changes = sync(database, index, enable_demote=args.demote, removed_ids=removed)

    result = validate(database)
    _log_validation(result, "refusing to write an invalid database")
    if result.error_count:
        raise SyncError("the synced playerlist is invalid, nothing was written")

    # Decide what WOULD change and render the report before writing anything.
    # The step outputs are appended first; if that append fails, report,
    # database, and snapshot stay untouched. Then the report is written before
    # the database and snapshot, so a report failure cannot advance either one.
    rendered = dumps(database)
    modified = rendered != original
    snapshot_changed = update_snapshot and source_bytes != previous_bytes

    report = render_report(
        RunInfo(
            database_path=database_path,
            source=source,
            source_total=index.total,
            source_skipped=index.skipped,
            dry_run=args.dry_run,
            changes=tuple(changes),
            previous_source_total=len(previous_index.by_steamid) if previous_index is not None else None,
            added_to_source=added_count,
            removed_from_source=removed_count,
            removed_upstream=tuple(removed_upstream),
            demotion_note=demotion_note,
            snapshot_note=snapshot_note,
            snapshot_changed=snapshot_changed,
            database_changed=modified,
            snapshot_path=snapshot_path,
        )
    )
    # Exactly one trailing newline, and the file and stdout carry the SAME
    # bytes: the report file is the pull request body, so there is no second
    # version of it to get out of step. (The old code appended a newline to a
    # report that already ended with one, leaving a blank line at the end of
    # every published pull request.)
    body = report if report.endswith("\n") else report + "\n"

    # Step outputs are required by the workflow, but a failure while appending
    # them must not turn a successful database/snapshot write into an exit-2
    # run with unpublished changes. Write them before every file and stdout
    # output; the workflow only consumes them when this step succeeds.
    changed = (modified or snapshot_changed) and not args.dry_run
    _write_github_outputs(
        changed=changed,
        count=len(changes),
        modified=modified,
        snapshot_changed=snapshot_changed,
        snapshot_added=added_count,
        snapshot_removed=removed_count,
    )

    if args.report:
        # Written atomically, like the database and the snapshot: this same file
        # is the pull request body, so a crash or a full disk must never leave a
        # half-written report for the next step to publish.
        try:
            _atomic_write_bytes(Path(args.report), body.encode("utf-8"))
        except (OSError, ValueError) as exc:
            raise SyncError(f"cannot write report {display_path(args.report)}: {error_reason(exc)}") from exc
    print(body, end="")

    # Write the database, then refresh the snapshot in the SAME working tree
    # (=> same pull request) so the baseline only advances once a human
    # merges the changes it produced. The order matters: if the process dies
    # between the two writes, a stale snapshot only makes the next run
    # re-evaluate removals that are already applied (a no-op), whereas a
    # fresh snapshot with an unwritten database would lose them forever. The
    # snapshot refresh happens whenever it is safe, even if the Garou database
    # itself did not change, so a run whose only change is the snapshot still
    # opens a snapshot-only PR. Exception: if demotion is disabled, vetoed by
    # either safety guard, or the source is incomplete, update_snapshot is
    # False and the same removals are re-evaluated next run.
    write_database(database_path, rendered, original, dry_run=args.dry_run)
    _log_outcome(modified, changes, database_path, dry_run=args.dry_run)
    if update_snapshot:
        write_snapshot(snapshot_path, source_bytes, previous_bytes, dry_run=args.dry_run)
        if snapshot_changed:
            LOGGER.info("%s snapshot %s.", "Would update" if args.dry_run else "Updated", display_path(snapshot_path))

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
        # report a bounded reason without echoing an untrusted filename from
        # OSError.__str__ (which could inject a log line or expose a path).
        LOGGER.error("error: %s", display_path(error_reason(exc)))
        return 2
    except KeyboardInterrupt:
        # Ctrl-C is not a crash. The atomic writes have already removed their
        # temporaries (the cleanup is in a finally block), and a half-written
        # file was never possible, so say so in one line and use the shell's
        # conventional 128 + SIGINT instead of dumping a stack trace into a
        # cancelled CI job.
        LOGGER.warning("interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
