![social-preview](https://raw.githubusercontent.com/Garou3299/tf2bd-database/refs/heads/master/public/social-preview.png)
# TF2BD Database

My database of cheaters and suspicious players in Team Fortress 2, kept in sync
with the [Vorobey hackerpolice list](https://github.com/Nocrex/Tom/blob/main/playerlist.vorobey-hackerpolice.json).

## Use it

Download `playerlist.garou3299.json`
([direct link](https://github.com/Garou3299/tf2bd-database/blob/master/playerlist.garou3299.json),
or `Code → Download ZIP`) and drop it into TF2BD's `cfg` folder. Built for
[this fork](https://github.com/surepy/tf2_bot_detector) of
[TF2BD](https://github.com/PazerOP/tf2_bot_detector).

## Contribute

Send a permanent Steam profile link or ID **with video evidence** to
[Discussions](https://github.com/Garou3299/tf2bd-database/discussions/1).

## What the bot does

Every day at **05:23 UTC** (GitHub can delay the run) it compares this database
with Vorobey's list and opens a pull request. Scheduled runs do not change the
default branch until you merge that pull request. A manual run from the default
branch (**Actions → Run workflow**) can instead open a pull request, commit
directly, or only report a dry run; a dispatch from another branch runs the
read-only checks but never the write-capable sync.

| On Vorobey's list | Result |
| --- | --- |
| `suspicious` | `cheater` |
| `racist` | `cheater` + `racist` |
| `suspicious` + `racist` | `cheater` + `racist` |
| `cheater` already | unchanged |
| no `suspicious`/`racist` tag at all | unchanged |

Vorobey's list is a cheater list and nothing else: every entry carries
`cheater`, and it always will. The bot therefore never reads the list's
attributes — being listed *is* the cheater verdict, whatever tags this database
happened to have on the player (that is why a lone `racist` becomes
`cheater` + `racist` too).

| Gone from Vorobey's list | Result |
| --- | --- |
| `cheater`, and it was in the previous snapshot | entry removed |
| `cheater` + `racist` | `racist` kept; `cheater` removed, and with it every proof that is not an `[auto] automatically marked: Racist \| reason: "…"` line |
| `cheater` + any other tag | entry removed |

The bot only ever edits entries that are already in the database: a SteamID that
is on Vorobey's list but missing here is **not** added.

When a `cheater` + `racist` entry is demoted, only proofs that start with
`[auto] automatically marked: Racist | reason: "` survive — that is the machine record
that justifies the remaining `racist` tag. A video link, a hand-written note, or a
half-written auto line goes with the cheater tag it was collected for.

Those auto lines are written by TF2BD itself when its chat filter fires, using
the rule in [`rules.garou3299.json`](rules.garou3299.json) (`chatmsg_text_match`,
case-insensitive, word mode, marking `racist`). The `reason` is the quoted chat
text that matched, which is why the tool insists on the complete line — quote
included — before trusting one to justify a tag.

Only players who were in the previous snapshot and are gone now are demoted, so
**cheaters added by hand are never touched**.

The pull request summarizes each change in tables with the SteamID, last known
name, tags before/after, and links (Steam profile, SteamHistory, and upstream
evidence). The full diff remains the complete record. The report never quotes
`proof` text stored in the database — those auto-marked chat lines stay in the
database and are not copied into the public report. The removed-ID table lists
up to 100 SteamIDs with profile and [SteamHistory](https://steamhistory.net/)
links, then reports how many more were omitted. `snapshot/playerlist.vorobey-hackerpolice.json`
is the previous byte-for-byte copy of Vorobey's list — the bot compares against
it to know who was removed, and refreshes it alongside the database whenever
the upstream bytes differ (in the same pull request or direct commit). Evidence
links stay in the pull request: they are shown for review and are never written
into the database.
A promotion only ever changes `attributes` — never `proof`. Each promotion row
shows at most 10 distinct upstream evidence links; any remaining proof entries
are counted as omitted rather than retained in the change record. The label is
uniform: `proof` when a row has exactly one link, `proof 1`, `proof 2`, … when it
has several, whatever each link points at — a mixed row stays readable because
every entry is named the same way. The link target points at the exact upstream
URL, except a YouTube video, which targets YouTube's own short form
(`https://youtu.be/<id>`): a faithful alias of the same video that keeps the
markdown short. A timestamp in the long form (`&t=42s`, `&start=90`) is carried
across, because a proof is often one specific moment in a long video; nothing
else from the query survives, and no timestamp is ever invented. That is a pure text rewrite — no
request and no third-party shortener — so the report stays offline and the link
stays verifiable. A link whose credentials had to be redacted is shown as plain
code instead, never as a clickable target.

The report is kept below GitHub's body limit: each change table stops at 150 rows
and the removed-ID table at 100, with an `… and N more` overflow note. If needed,
the report reduces those caps further; its last-resort byte limit is also marked
rather than silently cutting text. The tables aid review; the repository diff
remains the complete record.

Entry totals in the header count the raw rows the upstream file contains, so a
duplicated row is visible; the added/removed counts and the `net` beside them
count distinct SteamIDs, and the `net` is derived from those two counts rather
than from the raw totals, so the line can never contradict itself.

## Safety rails

- **Demotion is opt-in** — promotion runs on every invocation, but an entry is only
  ever demoted with `--demote`; without that flag the bot can only add `cheater`.
- **Frozen baseline** — if removals cannot be applied (demotion off, a safety
  guard veto, or an incomplete source), the snapshot is not advanced, so they are
  not forgotten.
  `--no-update-snapshot` holds the baseline back on purpose; every later run then
  re-reports the same candidates (and re-applies nothing).
- **Mass-removal guard** — demotion is skipped when the removals look like an
  upstream accident rather than real news. Two independent tests, because the
  upstream list is an order of magnitude larger than this database (5,574 snapshot
  entries against 108 demotable cheaters at the time of writing): more than 50 IDs
  *and* more than 20 % of the snapshot gone at once, **or** more than 25 % of the
  entries this database could actually lose. The second test exists because a purge
  of *every* tracked cheater was only 1.9 % of the snapshot, so the first test alone
  would have let it through silently. `--allow-mass-demotion` overrides this guard,
  not the separate incomplete-source safety check.
- **Incomplete-source guard** — if the current list has unusable SteamID rows and
  the snapshot shows removals, demotion and snapshot refresh are postponed until a
  clean list can confirm them. A single malformed row cannot silently look like
  a real removal.
- **Strict JSON** — non-standard `NaN`/`Infinity`, floating-point overflow,
  integer tokens over 4,300 digits and duplicate keys are rejected. This avoids
  invalid numeric values, version-dependent integer parsing and silent data loss.
  A file that is not UTF-8 is reported as an encoding problem rather than as
  invalid JSON, and a UTF-8 byte-order mark is accepted (and preserved in the
  snapshot).
- **Bounded reads** — HTTPS only (a redirect downgrade or a URL over 4,096
  characters is refused); API-provided follow-up URLs stay on the same origin,
  except GitHub Contents API downloads from `api.github.com` to
  `raw.githubusercontent.com`. Downloads are capped at 64 MiB, 30 s and 3
  attempts before trying the next fallback. The same 64 MiB cap applies to
  database, snapshot and local-source files. FIFOs/devices are refused before
  reading, so a local path cannot hang the run or stream indefinitely.
  Credentials in a URL (including nested links in proof text) are redacted before
  anything is printed or published; overlong URLs are omitted before parsing,
  and a URL cannot ping a user with `@handle`. A malformed `Content-Length`
  header cannot crash a fetch, and a source that names a scheme other than
  `https://` (say `ftp://`) is reported as an unsupported scheme instead of a
  missing local file.
- **Safe messages** — every value that reaches a log line or the pull request is
  escaped and bounded: a player name or a path cannot start a second log line,
  repaint the terminal, hide itself behind invisible or bidirectional characters
  in the review table, or flood the CI log, and one bad entry cannot bury the
  error that explains it. The review text is also *inert* as Markdown: a name or
  a path cannot render bold or struck-through, cannot forge a link, and cannot
  spell an HTML entity (`&#x202E;`, `&#8203;`, `&#64;handle`) that the renderer
  would turn back into an override, an invisible character or a mention.
- **Atomic writes** — each report, database and snapshot file is replaced in one
  step, so a crash or a full disk never leaves a partial file. These are separate
  atomic writes, not a multi-file transaction.
- **Step-output safety** — `$GITHUB_OUTPUT` cannot alias an input or output file,
  and its real append happens before the report, database or snapshot is written.
  If the runner's output file fails during the append, the run cannot leave an
  unpublished database or snapshot change behind.
- **Checked changes** — a pull request touching `scripts/`, `tests/`,
  `playerlist.garou3299.json`, `playerlist.scammers.json`, `rules.garou3299.json`,
  the hackerpolice snapshot,
  `pyproject.toml`, `.gitattributes`, `.gitignore`, `README.md`, `.github/dependabot.yml` or
  the workflow runs ruff, `mypy --strict`,
  a bandit security scan, vulture (dead code) and the tests under a coverage gate
  that keeps statements *and branches* at 100 %, in a read-only job. The same
  checks gate every scheduled/manual sync; only the separate sync job gets write
  permissions.
- **Pinned actions** — the workflow uses each action at a commit SHA, not at a
  movable tag, and Dependabot bumps those pins weekly; a compromised release in
  someone else's repository cannot run code here with a write token.
- **Least-privilege workflow** — the workflow itself grants no permissions at
  all (`permissions: {}`); each job opts in to exactly what it needs, so a job
  added later cannot inherit a write token by accident. The checks job does not
  even fetch the Git history it never reads.

## Run it yourself

```
python3 scripts/sync_vorobey_hackerpolice.py --dry-run
python3 scripts/sync_vorobey_hackerpolice.py --demote --report out.md
```

The scripts use only Python's standard library. To run the coverage gate locally,
install the same coverage version as CI first:

```
python3 -m pip install coverage==7.16.2
python3 -X warn_default_encoding -W error::EncodingWarning -m coverage run -m unittest discover -s tests -v
python3 -m coverage report
```

Python 3.10 or newer; CI checks both 3.10 (the minimum) and 3.12 (the runtime
used by the sync job).

The interface (`--help` prints the long version):

- `--database PATH` — the playerlist to update (default `playerlist.garou3299.json`)
- `--source URL_OR_PATH` — the hackerpolice list, an HTTPS URL or a local path;
  repeat it for fallbacks (default: the built-in GitHub URLs)
- `--snapshot PATH` — the demotion baseline, refreshed when upstream bytes differ
  (unless `--no-update-snapshot`) as a verbatim copy (default
  `snapshot/playerlist.vorobey-hackerpolice.json`)
- `--report PATH` — also write the Markdown summary to this file
- `--demote` — remove `cheater` only from IDs that were in the snapshot and are
  gone from the current list
- `--no-update-snapshot` — never refresh the baseline
- `--allow-mass-demotion` — override the mass-demotion veto
- `--dry-run` — report changes without updating the database or snapshot; a
  requested `--report` file is still written
- `--quiet` / `--verbose` — log level (`-q` / `-v`)
- `--help`

Exit `0` means success. Exit `130` means you interrupted it (Ctrl-C; no report,
database or snapshot file is left half-written, and the handler cleans up its
temporary files). Exit `2` means the run refused or failed: bad input, two paths
pointing at the same file, an invalid/unreadable source (plain HTTP is refused),
or an output that cannot be written. Outputs are
written in report → database → snapshot order. A failure can leave an earlier
atomic output updated (including the report, or the database if the final
snapshot write fails), but the snapshot can never advance before the database.
Keeping an old snapshot only re-evaluates removals next run; advancing it before
the database write could lose them.
