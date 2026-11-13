![social-preview](https://raw.githubusercontent.com/Garou3299/tf2bd-database/refs/heads/master/public/social-preview.png)
# TF2BD Database
My Database of Cheaters and Suspicious Players in Team Fortress 2.

---
I’m currently using [this](https://github.com/surepy/tf2_bot_detector), which is a fork of [PazerOP's TF2BD](https://github.com/PazerOP/tf2_bot_detector).

**Q:** *How can I use your TF2 Cheaters Database?*

**A:**

**Option A:** Download the ZIP file of this repository by clicking the `Code` button, then selecting `Download ZIP`. After extracting it, all you need is the `playerlist.garou3299.json` file then simply paste this file inside the `cfg` folder.

**Option B:** Go [here](https://github.com/Garou3299/tf2bd-database/blob/master/playerlist.garou3299.json), click the `More file actions` button in the top-right corner, and download the `playerlist.garou3299.json` file directly or just click the `Download raw file` button then simply paste this file inside the `cfg` folder.

**Q:** *How I can contribute to your Database?*

**A:** If you have a cheater’s permanent Steam profile link or ID along with video evidence proving the behavior, please submit it [here](https://github.com/Garou3299/tf2bd-database/discussions/1).

---


---

## What does the Bot do?

Every day, a bot compares `playerlist.garou3299.json` with the
[Vorobey hackerpolice cheater list](https://github.com/Nocrex/Tom/blob/main/playerlist.vorobey-hackerpolice.json)
and opens a pull request with its proposals. **Nothing changes until the
pull request is merged.**

### Promote (player is also on Vorobey's list)

| Tags before | Tags after |
| --- | --- |
| `suspicious` | `cheater` |
| `racist` | `cheater` + `racist` |
| `suspicious` + `racist` | `cheater` + `racist` |
| `cheater` (already) | unchanged |

### Demote (player was on Vorobey's list before, but has been removed from it)

| Tags before | Tags after |
| --- | --- |
| `cheater` | entry removed from the database |
| `cheater` + `racist` | `racist` (`cheater` and its proofs are removed, the racist proofs stay) |
| `cheater` + anything else | the other tags stay (`cheater` and the proofs that came with it are removed) |

Players who were added to this database and were never on
Vorobey's list are **never** demoted or removed by the bot.

`--demote` is opt-in. A run without it still reports every removal, and still
refreshes the snapshot to an exact copy of the new upstream list — so it also
warns that those removals can no longer be proven (and therefore can no longer
be demoted automatically) once that snapshot lands.

### Report who was removed from Vorobey's list

Every pull request also lists the SteamIDs that disappeared from Vorobey's
list since the previous snapshot. Vorobey's list stores no player names, so
the table only has the SteamID and a link to the Steam profile:

| SteamID | Profile Link |
| --- | --- |
| `[U:1:269327660]` | [profile](https://steamcommunity.com/profiles/76561198229593388) |

This is the raw snapshot diff: it is shown whether or not `--demote` is
enabled, and it includes IDs this database never contained (those produce no
database change, they were simply dropped upstream).

Every table in the report has a size budget, because the report *is* the pull
request body and GitHub rejects anything over 65,536 characters. A normal run
is never truncated; a mass run (upstream suddenly matching or dropping most of
the database) keeps the counts and the first rows and adds a
`…and N more …` line — the file diffs in the same pull request always list
every single change.

### Safety guards

The bot is deliberately conservative: it never guesses, and it never
writes a file it could not read back.

| Guard | What it prevents |
| --- | --- |
| Snapshot-based demotion | Only a SteamID that was in the previous snapshot **and** is gone from the current list may be demoted, and only its `cheater` tag is removed: any other tag the entry carries survives, and the entry itself is deleted only when nothing is left. Cheaters added by hand are never touched. |
| Mass-demotion guard | If more than 50 IDs **and** more than 20% of the snapshot vanish at once, demotion is skipped and the snapshot is left alone, because that looks like an upstream problem (renamed file, truncated fetch). `--allow-mass-demotion` overrides it. |
| Empty upstream list | A list without a single usable SteamID is a failed fetch: nothing is promoted, demoted, or snapshotted. |
| Snapshot advances last | The baseline is only refreshed after the changes derived from it were applied, so a refused demotion is re-evaluated on the next run instead of being lost. |
| Path aliasing | `--report` and `--source` may not point at the database or the snapshot — sharing a path would overwrite an input file. |
| Atomic writes | The database and the snapshot are written to a temp file and renamed into place, so a crash (or two runs at once) can never leave a half-written file behind. |
| Symlink-safe writes | If the playerlist or the snapshot is a symbolic link — the usual way to point TF2BD's `cfg/playerlist.json` at this repository — the file it points at is updated. The link itself is never replaced. |
| Clean failures | Bad JSON, `NaN`/`Infinity`, a corrupt snapshot, a non-UTF-8 database or an unreachable source ends in exit code 2 with a readable message, never a traceback. |
| Size limits | A fetched or local list over 64 MiB is refused instead of being read into memory. The limit is applied to the bytes actually read, so a pipe or a device (`--source /dev/zero`) that reports no size cannot slip past it. The pull request body is always kept below GitHub's 65,536-character limit. |
| Encrypted transport | A source that redirects from `https` to a plaintext URL is refused rather than trusted: the response becomes the committed snapshot. A truncated response is retried like any other transport failure instead of being blamed on the URL. |
| Strict JSON | A playerlist containing `NaN`/`Infinity` — which Python parses but JSON does not allow — is refused at load time, so the bot can never write a file that a strict parser (TF2BD itself) cannot read back. |
| Untrusted text stays text | Proof strings and names coming from Vorobey's list are escaped, so they can never inject HTML (a phishing link) into this repository's pull request or a newline into the database. |
| Visible skips | A run that skips demotion (no baseline yet, or the mass-demotion guard) changes no file, so it also emits a GitHub Actions warning annotation instead of ending as a silent green run. |

### Update the Vorobey database copy

| File | What the bot does |
| --- | --- |
| `snapshot/playerlist.vorobey-hackerpolice.json` | Updated in the same pull request to an exact, byte-for-byte copy of the current `playerlist.vorobey-hackerpolice.json` list. By comparing the previous copy against the new list, the bot knows exactly who was removed from the Vorobey hackerpolice list and it never touches players who were added manually to this database. |

---

## Development

The scripts use only the Python standard library (Python 3.10+).

```sh
python3 -m unittest discover -s tests -v   # run the tests
ruff check scripts tests                   # lint (includes security rules)
ruff format --check scripts tests          # formatting
mypy scripts                               # type-check
```

CI (`.github/workflows/ci.yml`) runs them for every pull request and for
pushes to `master`, on Python 3.10 (the minimum) and 3.12 (what the bot runs).
The sync workflow repeats them inline, so the bot never commits untested code —
which matters because a pull request opened with `GITHUB_TOKEN` does not
trigger other workflows.

### Running the bot from a fork

This checkout is a fork, so changes made here reach the published database
through a pull request to the upstream repository. Two things follow from
that and are deliberate:

- Every `update_url` inside the data files points at the **canonical upstream
  repository**, not at this fork. TF2BD installs poll that URL for updates;
  rewriting it to a fork would cut every user off from new entries until the
  change is merged upstream. Leave those files' `file_info` alone.
- GitHub does not run scheduled workflows in forks. Enable Actions in the
  fork's *Actions* tab and then either trigger **Sync Vorobey hackerpolice
  list** by hand (`workflow_dispatch`, with the optional dry-run / mass-demotion
  inputs) or keep the daily schedule alive — GitHub also disables a schedule
  after 60 days without repository activity. The pull request, the report and
  the commit work the same in a fork as upstream.
