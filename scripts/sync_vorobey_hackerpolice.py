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
current file (an exact replica, never decoded/re-serialized) alongside the
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
from collections.abc import Collection, Sequence
from pathlib import Path
from typing import TextIO

import playerlist
from playerlist import (
    PlayerList,
    PlayerListError,
    ValidationResult,
    dumps,
    error_reason,
    load,
    normalize_steamid,
    validate,
)
from policy import Change, sync
from report import RunInfo, plural, render_report
from sources import (
    DEFAULT_SOURCES,
    HackerpoliceIndex,
    SyncError,
    added_steamids,
    http_scheme,
    load_first_available_raw,
    load_snapshot,
    redact_urls_in_text,
    removed_steamids,
)

__all__ = ["DEFAULT_SNAPSHOT", "build_parser", "load_database", "main", "run", "write_database", "write_snapshot"]

LOGGER = logging.getLogger("sync_vorobey_hackerpolice")

DEFAULT_DATABASE = "playerlist.garou3299.json"
DEFAULT_SNAPSHOT = "snapshot/playerlist.vorobey-hackerpolice.json"

# Veto demotion if removals exceed both the minimum count and fraction thresholds.
MASS_DEMOTION_MIN_IDS = 50
MASS_DEMOTION_MAX_FRACTION = 0.2
# Also veto when the removal would demote a large share of THIS database's own
# demotable entries. The snapshot is an order of magnitude larger than the
# database, so a purge of every demotable entry is still a small fraction of
# the snapshot, and the snapshot-relative rule alone would let it pass. No
# figures are quoted here: both files grow every run, so any would go stale.
MASS_DEMOTION_MAX_DATABASE_FRACTION = 0.25
MASS_DEMOTION_MIN_DATABASE_IDS = 5


def display_path(path: Path | str) -> str:
    """A path for a log line: redacted, one line, bounded (one shared helper)."""
    return playerlist.display_path(path)


def _one_line_message(value: str) -> str:
    """Redact and flatten a message that quotes a path, escaping it exactly once."""
    return playerlist.display_raw(redact_urls_in_text(value))


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser (also used by the tests as the CLI contract)."""
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
    return parser


def _open_github_output(path: str) -> TextIO:
    """Open a regular GitHub output file for append without blocking on a special file."""
    target = Path(path)
    try:
        existing = target.stat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(existing.st_mode):
            raise OSError(errno.EINVAL, "not a regular file", os.fspath(target))

    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(target, flags, 0o666)
    try:
        # Recheck after open to avoid races and non-blocking FIFO hangs.
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", os.fspath(target))
        handle = os.fdopen(fd, "a", encoding="utf-8")
        fd = -1  # The text handle now owns the descriptor.
        return handle
    finally:
        if fd >= 0:
            os.close(fd)


def _write_github_outputs(**outputs: str | int | bool) -> None:
    """Expose step outputs when running inside GitHub Actions."""
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    # Flatten values to one line to prevent extra GitHub outputs.
    lines = []
    for key, value in outputs.items():
        text = str(value).lower() if isinstance(value, bool) else str(value)
        lines.append(f"{key}={' '.join(text.splitlines())}")
    try:
        with _open_github_output(path) as handle:
            handle.write("\n".join(lines) + "\n")
    except (OSError, ValueError) as exc:
        # Report the output path without exposing an oversized raw path.
        raise SyncError(f"cannot write the GitHub step outputs at {display_path(path)}: {error_reason(exc)}") from exc


def _check_github_output() -> None:
    """Refuse obvious ``$GITHUB_OUTPUT`` path failures before reading inputs.

    Append-open catches a directory, special file, missing parent, and
    permission errors before network or database work begins. It cannot prove
    a later regular-file write will succeed, so the real append also happens
    before the report, database, snapshot, or stdout is written.
    """
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    try:
        # Probe append access before the run writes any outputs.
        with _open_github_output(path):
            pass
    except (OSError, ValueError) as exc:
        raise SyncError(f"cannot write the GitHub step outputs at {display_path(path)}: {error_reason(exc)}") from exc


def _log_validation(result: ValidationResult, context: str) -> None:
    """Log bounded validation details without escaping any value twice.

    ``playerlist.validate`` already quotes untrusted values through its own
    bounded, redacting preview, so these messages carry newlines as the two
    characters ``\\n``. Running the redacting path formatter over them
    escaped that backslash a second time (``\\\\n``) and re-inspected every
    ``key=value`` the message mentions; ``display_raw`` only makes the text
    safe for a terminal.
    """
    for warning in result.warnings:
        LOGGER.warning("%s", playerlist.display_raw(warning))
    if result.warnings_omitted:
        LOGGER.warning(
            "%s additional validation %s omitted",
            result.warnings_omitted,
            plural(result.warnings_omitted, "warning", "warnings"),
        )
    safe_context = display_path(context)
    for error in result.errors:
        LOGGER.error("%s: %s", safe_context, playerlist.display_raw(error))
    if result.errors_omitted:
        LOGGER.error(
            "%s: %s additional validation %s omitted",
            safe_context,
            result.errors_omitted,
            plural(result.errors_omitted, "problem", "problems"),
        )


def load_database(path: Path) -> tuple[PlayerList, str]:
    """Read and validate a playerlist, raising SyncError with a readable reason."""
    try:
        database, original = load(path)
    except PlayerListError as exc:
        # ``load()`` clipped the raw path before this boundary could redact it. Swap
        # that preview for the redacted one, then flatten the finished message once.
        quoted = playerlist.display_raw(path)
        message = str(exc).replace(quoted, display_path(path))
        raise SyncError(_one_line_message(message)) from exc

    result = validate(database)
    _log_validation(result, f"{display_path(path)} is not a usable playerlist")
    if result.error_count:
        raise SyncError(
            f"{display_path(path)} has {result.error_count} "
            f"{plural(result.error_count, 'problem', 'problems')}, nothing was written"
        )
    return database, original


def _fsync_directory(directory: Path) -> None:
    """Best-effort fsync of a directory so a rename survives an OS crash."""
    # Directory fsync is best-effort; some platforms do not support it.
    with contextlib.suppress(OSError):
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write bytes via a temp file in the same directory, then atomically replace.

    A crash mid-write can never leave a half-written file behind, and the
    bytes land on disk exactly as given -- this is what makes the snapshot
    an exact replica of the upstream file (no encoding/newline translation
    ever touches them).
    """
    # Resolve a symlink so the replacement lands on its target, not on the link itself.
    target = path
    if path.is_symlink():
        try:
            target = path.resolve(strict=False)
        except RuntimeError as exc:
            # ``resolve`` reports a symlink LOOP as RuntimeError, which is not an OSError.
            # Convert it so the caller's error handling names the file instead of
            # letting a RuntimeError escape as a traceback mid-write.
            raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), os.fspath(path)) from exc
    # Use unique, short temp names to avoid collisions and keep long basenames valid.
    fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=".tf2bd-sync-", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())  # Fsync file contents before publishing the rename.
        # Restore the existing mode, or use the process umask for a new file.
        try:
            existing = target.stat()
        except FileNotFoundError:
            existing_mode = None
        else:
            if not stat.S_ISREG(existing.st_mode):
                raise OSError(errno.EINVAL, "not a regular file", os.fspath(path))
            existing_mode = stat.S_IMODE(existing.st_mode)
        if existing_mode is None:
            mask = os.umask(0)
            os.umask(mask)  # Restore immediately; os.umask has no read-only query.
            mode = 0o666 & ~mask
        else:
            mode = existing_mode
        tmp.chmod(mode)
        tmp.replace(target)
        _fsync_directory(target.parent)  # Persist the rename.
    finally:
        # Always remove the temp file on exit; after a successful rename this is a no-op.
        tmp.unlink(missing_ok=True)


def write_database(path: Path, rendered: str, original: str, *, dry_run: bool) -> bool:
    """Write the serialized playerlist if it changed; returns whether it changed.

    ``rendered`` is the text the caller already produced to decide what
    changed, so the database is never serialized twice and what was compared
    is exactly what is written.
    """
    modified = rendered != original
    if modified and not dry_run:
        try:
            _atomic_write_bytes(path, rendered.encode("utf-8"))
        except (OSError, ValueError) as exc:
            # Name the requested output path, not the temp file; ValueError also covers unencodable paths.
            raise SyncError(f"cannot write {display_path(path)}: {error_reason(exc)}") from exc
    return modified


def write_snapshot(path: Path, raw: bytes, original: bytes | None, *, dry_run: bool) -> bool:
    """Overwrite the snapshot with the source's RAW bytes; returns whether it changed.

    The bytes are written verbatim -- never decoded, parsed or
    re-serialized -- so after an update the snapshot is an exact replica of
    the original upstream file, byte for byte.
    """
    changed = raw != original
    if changed and not dry_run:
        try:
            _atomic_write_bytes(path, raw)
        except (OSError, ValueError) as exc:
            raise SyncError(f"cannot write {display_path(path)}: {error_reason(exc)}") from exc
    return changed


def _log_outcome(changes: list[Change], path: Path, *, modified: bool, dry_run: bool) -> None:
    """Log what the run did to the database, in the tense the run deserves.

    The three outcomes are kept apart on purpose: nothing to do, a rewrite
    that changed no tags, and a real set of changes. Each reads differently
    under --dry-run, so a log line never claims a write that did not happen.
    """
    count = len(changes)
    what = f"{count} {plural(count, 'entry', 'entries')}"
    if not modified:
        # Scope the no-change message to the database; the snapshot may still change.
        LOGGER.info("No database changes: nothing to update.")
    elif not changes:
        # Report file-only normalization separately from tag changes.
        LOGGER.info(
            "%s %s (no tag changes: the file was normalized).",
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
        return first.exists() and second.exists() and first.samefile(second)
    except (OSError, ValueError, RuntimeError):
        # Treat path-resolution failures as non-aliases; later file operations report unusable paths.
        return False


def _local_source_paths(args: argparse.Namespace) -> list[Path]:
    """The ``--source`` values that name a file on disk rather than a URL."""
    return [Path(source) for source in args.source or [] if not http_scheme(source)]


def _reject_empty_paths(args: argparse.Namespace) -> None:
    """Reject empty paths instead of silently meaning the current directory or no report."""
    for flag, value in (("--database", args.database), ("--snapshot", args.snapshot), ("--report", args.report)):
        if value == "":
            raise SyncError(f"{flag} must not be empty")
    if any(source == "" for source in args.source or []):
        raise SyncError("--source must not be empty")


def _reject_report_aliases(args: argparse.Namespace, database_path: Path, snapshot_path: Path) -> None:
    """The report is written first, so an aliased report path would destroy its own input."""
    if not args.report:
        return
    report_path = Path(args.report)
    protected = [database_path, snapshot_path, *_local_source_paths(args)]
    if any(_same_file(report_path, path) for path in protected):
        raise SyncError("--report must not be the same file as --database, --snapshot, or a local --source")


def _reject_source_aliases(args: argparse.Namespace, database_path: Path, snapshot_path: Path) -> None:
    """Keep a local source from aliasing an input or output, especially the snapshot baseline."""
    for source in args.source or []:
        if http_scheme(source):
            continue
        for flag, other in (("--database", database_path), ("--snapshot", snapshot_path)):
            if _same_file(Path(source), other):
                raise SyncError(f"--source must not be the same file as {flag}")


def _reject_github_output_aliases(args: argparse.Namespace, database_path: Path, snapshot_path: Path) -> None:
    """Keep the Actions output file from aliasing any input or output of the run."""
    github_output = os.environ.get("GITHUB_OUTPUT")
    if not github_output:
        return
    protected = [("--database", database_path), ("--snapshot", snapshot_path)]
    if args.report:
        protected.append(("--report", Path(args.report)))
    protected.extend(("--source", path) for path in _local_source_paths(args))
    for flag, path in protected:
        if _same_file(Path(github_output), path):
            raise SyncError(f"GITHUB_OUTPUT must not be the same file as {flag}")


def _require_output_directories(args: argparse.Namespace, snapshot_path: Path) -> None:
    """Fail before any work when an output directory is missing -- always a typo."""
    outputs = [("--snapshot", snapshot_path)]
    if args.report:
        outputs.append(("--report", Path(args.report)))
    for flag, path in outputs:
        if not path.parent.is_dir():
            raise SyncError(f"{flag} directory does not exist: {display_path(path.parent)}")


def _guard_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    """Refuse any arrangement where the tool would overwrite its own inputs.

    Every check exists because each one is a real way to lose the database or
    to make a run succeed while doing nothing: the report is written before
    the database, so an aliased report path would destroy it; a --source
    pointing at the database would compare the file with itself and then
    rewrite it; and an output path in a directory that does not exist is a
    typo, never a design case.
    """
    _reject_empty_paths(args)
    database_path = Path(args.database)
    snapshot_path = Path(args.snapshot)
    if _same_file(snapshot_path, database_path):
        raise SyncError("--snapshot and --database must be different files")
    _reject_report_aliases(args, database_path, snapshot_path)
    _reject_source_aliases(args, database_path, snapshot_path)
    _reject_github_output_aliases(args, database_path, snapshot_path)
    _require_output_directories(args, snapshot_path)
    return database_path, snapshot_path


def _load_index(args: argparse.Namespace) -> tuple[HackerpoliceIndex, str, bytes]:
    """Fetch the upstream list and index it, refusing an empty result."""
    source_document, source, source_bytes = load_first_available_raw(args.source or DEFAULT_SOURCES)
    index = HackerpoliceIndex.build(source_document)
    LOGGER.info("Indexed %d Vorobey hackerpolice SteamIDs (%d unusable).", len(index.by_steamid), index.skipped)
    if not index.by_steamid:
        # Reject empty indexes; an unusable fetch must not drive policy or overwrite the snapshot.
        raise SyncError("the Vorobey hackerpolice list contains no usable SteamIDs, nothing was written")
    return index, source, source_bytes


def _demotion_impact(
    database: PlayerList, removed: Collection[str], previous_index: HackerpoliceIndex
) -> tuple[int, int]:
    """Return ``(to_demote, at_risk)`` for this database, in entries.

    ``at_risk`` is every entry carrying ``cheater`` that the PREVIOUS snapshot
    lists -- the whole population upstream could ever demote. Entries upstream
    never listed were added by hand and are never demoted, so counting them
    would make the guard fire on runs that are actually harmless.

    ``to_demote`` is the part of that population this run would really change,
    i.e. the ones among ``removed`` (previous snapshot minus the current list).

    Measuring against the CURRENT index would be useless: demotion targets are
    precisely the entries missing from it, so that denominator collapses to
    zero exactly when a purge is largest and the guard is most needed.
    """
    players = database.get("players")
    if not isinstance(players, list):
        return 0, 0
    to_demote = 0
    at_risk = 0
    for player in players:
        if not isinstance(player, dict):
            continue
        attributes = player.get("attributes")
        if not isinstance(attributes, list) or "cheater" not in attributes:
            continue
        canonical = normalize_steamid(player.get("steamid"))
        if canonical is None or canonical not in previous_index.by_steamid:
            continue
        at_risk += 1
        if canonical in removed:
            to_demote += 1
    return to_demote, at_risk


def _looks_like_mass_removal(removed: int, baseline: int, to_demote: int, at_risk: int) -> bool:
    """True when these removals look like an upstream accident, not real news.

    Two independent tests, because they catch different shapes of accident:

    * the removals are a large share of the SNAPSHOT (upstream collapsed). This
      measures ALL removals: upstream losing most of its list is a problem even
      if this database happens to track few of them.
    * the removals are a large share of what THIS database could lose. The
      snapshot is much bigger than the database, so a purge of every tracked
      cheater can still be a tiny fraction of the baseline and slip past the
      first test.
    """
    if removed > MASS_DEMOTION_MIN_IDS and baseline and removed > MASS_DEMOTION_MAX_FRACTION * baseline:
        return True
    return (
        to_demote >= MASS_DEMOTION_MIN_DATABASE_IDS
        and at_risk > 0
        and to_demote > MASS_DEMOTION_MAX_DATABASE_FRACTION * at_risk
    )


def _demotion_scale(to_demote: int, at_risk: int) -> str:
    """Describe the removal against the database when it is the tighter bound."""
    if at_risk <= 0:
        return "no tracked cheaters to compare against"
    share = min(to_demote, at_risk) / at_risk
    return f"{share:.0%} of the {at_risk:,} {plural(at_risk, 'cheater', 'cheaters')} this database could lose"


def _plan_demotion(
    args: argparse.Namespace,
    previous_index: HackerpoliceIndex | None,
    removed_upstream: set[str],
    snapshot_path: Path,
    *,
    source_skipped: int = 0,
    demotion_impact: tuple[int, int] = (0, 0),
) -> tuple[set[str], bool, str | None, str | None]:
    """Decide what may be demoted, and whether the baseline may advance.

    Returns ``(removed, update_snapshot, demotion_note, snapshot_note)``. The
    snapshot is held back whenever removals could not be applied, so a
    skipped removal is never silently forgotten.

    ``demotion_impact`` is ``(to_demote, at_risk)`` for this database (see
    :func:`_demotion_impact`). It is a separate guard from the snapshot-relative
    one because the snapshot is an order of magnitude larger than the database:
    a removal that looks like a rounding error of the baseline can still wipe
    out most of the database's tracked cheaters.
    """
    demotion_note: str | None = None
    # Hold the snapshot when demotion is vetoed, or skipped removals would be lost.
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
                "%d SteamIDs removed upstream since the snapshot (%d SteamIDs).",
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
            elif not args.allow_mass_demotion and _looks_like_mass_removal(
                len(removed), len(previous_index.by_steamid), *demotion_impact
            ):
                demotion_note = (
                    f"skipped - {len(removed):,} of {len(previous_index.by_steamid):,} snapshot SteamIDs "
                    f"disappeared upstream at once ({_demotion_scale(*demotion_impact)}), which looks "
                    "like an upstream problem, not real removals "
                    "(re-run with --allow-mass-demotion to force)"
                )
                LOGGER.warning("Demotion %s.", demotion_note)
                removed = set()
                update_snapshot = False
                snapshot_note = "**not refreshed** - demotion was skipped, so these removals stay demotion candidates"

    if not args.demote and removed_upstream:
        # Keep the old baseline while removals cannot be applied.
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

    snapshot = load_snapshot(snapshot_path)
    previous_index, previous_bytes = snapshot if snapshot is not None else (None, None)
    # Compute the snapshot diff even when demotion is disabled; a first snapshot counts all IDs as new.
    added_count = len(index.by_steamid)
    removed_upstream: set[str] = set()
    removed_count = 0
    if previous_index is not None:
        added_count = len(added_steamids(previous_index, index))
        removed_upstream = removed_steamids(previous_index, index)
        removed_count = len(removed_upstream)
        LOGGER.info(
            "Snapshot diff vs. previous snapshot: %d SteamIDs added, %d removed (%d -> %d SteamIDs).",
            added_count,
            removed_count,
            len(previous_index.by_steamid),
            len(index.by_steamid),
        )

    demotion_impact = (0, 0) if previous_index is None else _demotion_impact(database, removed_upstream, previous_index)
    removed, update_snapshot, demotion_note, snapshot_note = _plan_demotion(
        args,
        previous_index,
        removed_upstream,
        snapshot_path,
        source_skipped=index.skipped,
        demotion_impact=demotion_impact,
    )
    changes = sync(database, index, enable_demote=args.demote, removed_ids=removed)

    result = validate(database)
    _log_validation(result, "refusing to write an invalid database")
    if result.error_count:
        raise SyncError("the synced playerlist is invalid, nothing was written")

    # Render first; output or report failures must not advance the database or snapshot.
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
            previous_source_total=previous_index.total if previous_index is not None else None,
            source_ids=len(index.by_steamid),
            previous_source_ids=len(previous_index.by_steamid) if previous_index is not None else 0,
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
    # Use exactly one trailing newline for both the report file and stdout.
    body = report if report.endswith("\n") else report + "\n"

    # Append required step outputs before file writes so failures cannot leave unpublished data changes.
    changed = (modified or snapshot_changed) and not args.dry_run
    _write_github_outputs(
        changed=changed,
        count=len(changes),
        modified=modified,
        snapshot_changed=snapshot_changed,
        snapshot_added=added_count,
        snapshot_removed=removed_count,
    )

    # Print before the report file is written. Showing the summary cannot fail in a way
    # that needs to abort anything: a closed stdout raises here, and aborting AFTER the
    # report file was written used to leave a report describing changes that were never
    # applied -- the file is also the pull request body, so it would have been published
    # as if the sync had happened. Failing before any file is written keeps the two in
    # step. Flush before the outcome logging: stdout is block-buffered when it is a pipe
    # or a workflow log file, while stderr (where log records go) is not, so without this
    # the summary and the "Updated ..." lines could reach the reader out of order.
    # No usable stdout (closed or broken) is not fatal on its own: the --report file
    # below still carries the same summary, which is what gets published.
    with contextlib.suppress(OSError, ValueError):
        print(body, end="", flush=True)
    if args.report:
        # Write the report atomically; it is also the pull request body.
        try:
            _atomic_write_bytes(Path(args.report), body.encode("utf-8"))
        except (OSError, ValueError) as exc:
            raise SyncError(f"cannot write report {display_path(args.report)}: {error_reason(exc)}") from exc

    # Write the database before advancing the snapshot; skipped demotions remain candidates.
    # Safe snapshot-only changes still refresh the baseline.
    write_database(database_path, rendered, original, dry_run=args.dry_run)
    _log_outcome(changes, database_path, modified=modified, dry_run=args.dry_run)
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
        # Test streams may not support reconfiguration; leave them unchanged.
        with contextlib.suppress(AttributeError, OSError, ValueError):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")  # type: ignore[union-attr]


def main(argv: Sequence[str] | None = None) -> int:
    """Run the sync and return the process exit status."""
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
        # Anything that reaches here escaped a handler that already names its file, so
        # the useful half is ``strerror`` -- ``str(OSError)`` would repeat the path.
        # It is still free-form text: redact it, flatten it, bound it before logging.
        LOGGER.error("error: %s", _one_line_message(error_reason(exc)))
        return 2
    except KeyboardInterrupt:
        # Return 128 + SIGINT for Ctrl-C; atomic writes clean up temporary files.
        LOGGER.warning("interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
