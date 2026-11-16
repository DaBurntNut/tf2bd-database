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
with Vorobey's list and opens a pull request. **Nothing changes until you merge
it.** It can also be run
by hand (**Actions → Run workflow**) as a pull request, a direct commit or a dry
run.

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

The pull request describes each change with the SteamID, the last known name, the
tags before/after and links (Steam profile, SteamHistory, and the upstream evidence
links). It never quotes the `proof` text stored in the database — those auto-marked
chat lines are left where they are, so the public pull request never carries them. Every removed SteamID is listed in
the pull request with its profile link, and every table also links each player's
[SteamHistory](https://steamhistory.net/) page. `snapshot/playerlist.vorobey-hackerpolice.json`
is yesterday's copy of Vorobey's list — the bot compares against it to know who
was removed, and updates it in the same pull request. Evidence links stay in the
pull request: they are shown for review and are never written into the database.
A promotion only ever changes `attributes` — never `proof`.

The pull request is kept to a size GitHub accepts: a table stops at 150 rows (100
for the removed-SteamID list) and the whole body stops at 60,000 bytes, saying so
with an `… and N more` note instead of cutting silently. The tables are the review
aid; the diff is the change.

## Safety rails

- **Demotion is opt-in** — promotion runs on every invocation, but an entry is only
  ever demoted with `--demote`; without that flag the bot can only add `cheater`.
- **Frozen baseline** — if the removals it found cannot be applied (demotion off,
  or vetoed by the guard), the snapshot is not advanced, so they are not forgotten.
  `--no-update-snapshot` holds the baseline back on purpose; every later run then
  re-reports the same candidates (and re-applies nothing).
- **Mass-removal guard** — more than 50 IDs *and* more than 20 % gone at once means
  demotion is skipped; `--allow-mass-demotion` forces it through.
- **Strict JSON** — `NaN`, `Infinity` and duplicate keys are refused, never
  rewritten, so the bot cannot publish a file TF2BD itself cannot load.
- **Bounded reads** — HTTPS only (a redirect downgrade is refused), 64 MiB per
  download, 30 s, 3 attempts, then the next fallback. The same 64 MiB cap applies
  to the database and snapshot files it reads from disk, so a runaway file is
  refused instead of exhausting memory. Credentials in a URL (in the userinfo, a
  query parameter, or an OAuth-style fragment) are redacted before anything is
  printed or published, and a URL cannot ping a user with `@handle`.
- **Safe messages** — every value that reaches a log line or the pull request is
  escaped and bounded: a player name or a path cannot start a second log line,
  repaint the terminal, hide itself behind invisible or bidirectional characters
  in the review table, or flood the CI log, and one bad entry cannot bury the
  error that explains it. The review text is also *inert* as Markdown: a name or
  a path cannot render bold or struck-through, cannot forge a link, and cannot
  spell an HTML entity (`&#x202E;`, `&#8203;`, `&#64;handle`) that the renderer
  would turn back into an override, an invisible character or a mention.
- **Atomic writes** — the report, database and snapshot are replaced in one
  step, so a crash or a full disk leaves the previous file intact.
- **Step-output safety** — `$GITHUB_OUTPUT` cannot alias an input or output file,
  and its real append happens before the report, database or snapshot is written.
  If the runner's output file fails during the append, the run cannot leave an
  unpublished database or snapshot change behind.
- **Checked changes** — a pull request touching `scripts/`, `tests/`,
  `pyproject.toml`, `.gitattributes`, `README.md`, `.github/dependabot.yml` or
  the workflow runs ruff, `mypy --strict`,
  a bandit security scan, vulture (dead code) and the tests under a coverage gate
  that keeps statements *and branches* at 100 %, read-only.
- **Pinned actions** — the workflow uses each action at a commit SHA, not at a
  movable tag, and Dependabot bumps those pins weekly; a compromised release in
  someone else's repository cannot run code here with a write token.

## Run it yourself

```
python3 scripts/sync_vorobey_hackerpolice.py --dry-run
python3 scripts/sync_vorobey_hackerpolice.py --demote --report out.md
python3 -m coverage run -m unittest discover -s tests   # the gate is in pyproject.toml
python3 -m coverage report
```

Python 3.10 or newer, no dependencies: the scripts use the standard library
only. CI runs both 3.10 (the floor the promise rests on) and 3.12 (what the
sync itself runs on).

The interface (`--help` prints the long version):

- `--database PATH` — the playerlist to update (default `playerlist.garou3299.json`)
- `--source URL_OR_PATH` — the hackerpolice list, an HTTPS URL or a local path;
  repeat it for fallbacks (default: the built-in GitHub URLs)
- `--snapshot PATH` — the demotion baseline, rewritten on every run as a verbatim
  copy of the upstream file (default `snapshot/playerlist.vorobey-hackerpolice.json`)
- `--report PATH` — also write the Markdown summary to this file
- `--demote` — remove `cheater` only from IDs that were in the snapshot and are
  gone from the current list
- `--no-update-snapshot` — never refresh the baseline
- `--allow-mass-demotion` — override the mass-demotion veto
- `--dry-run` — report the changes without writing the database
- `--quiet` / `--verbose` — log level (`-q` / `-v`)
- `--version`, `--help`

Exit `0` means success and `130` means you interrupted it (Ctrl-C; nothing is
half-written, the handler cleans up its temporaries). Exit `2` means the run
refused or failed — bad input, two paths pointing at the same file, a source
that is not HTTPS, or an output that cannot be written. Every file is written atomically (temporary file, then
rename), so a failed run never leaves a half-written file; the report is
written first and the snapshot last, so the only file a late failure can leave
changed is the database (a stale snapshot would cost removals, a stale
database costs nothing).
