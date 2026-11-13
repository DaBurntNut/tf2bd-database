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

Players who were added to this database and were never on
Vorobey's list are **never** demoted or removed by the bot.

### Report who was removed from Vorobey's list

Every pull request also lists the SteamIDs that disappeared from Vorobey's
list since the previous snapshot. Vorobey's list stores no player names, so
the table only has the SteamID and a link to the Steam profile:

| SteamID | Profile Link |
| --- | --- |
| `[U:1:269327660]` | [profile](https://steamcommunity.com/profiles/76561198229593388) |

This is the raw snapshot diff: it is shown whether or not `--demote` is
enabled, and it includes IDs this database never contained (those produce no
database change, they were simply dropped upstream). Very large diffs are
truncated after 200 rows to keep the pull request readable — the snapshot
file's own diff still shows every removed SteamID.

### Safety guards

The bot is deliberately conservative: it never guesses, and it never
writes a file it could not read back.

| Guard | What it prevents |
| --- | --- |
| Snapshot-based demotion | Only a SteamID that was in the previous snapshot **and** is gone from the current list may be demoted. Cheaters added by hand are never touched. |
| Mass-demotion guard | If more than 50 IDs **and** more than 20% of the snapshot vanish at once, demotion is skipped and the snapshot is left alone, because that looks like an upstream problem (renamed file, truncated fetch). `--allow-mass-demotion` overrides it. |
| Empty upstream list | A list without a single usable SteamID is a failed fetch: nothing is promoted, demoted, or snapshotted. |
| Snapshot advances last | The baseline is only refreshed after the changes derived from it were applied, so a refused demotion is re-evaluated on the next run instead of being lost. |
| Path aliasing | `--report` and `--source` may not point at the database or the snapshot — sharing a path would overwrite an input file. |
| Atomic writes | The database and the snapshot are written to a temp file and renamed into place, so a crash (or two runs at once) can never leave a half-written file behind. |
| Clean failures | Bad JSON, a corrupt snapshot, a non-UTF-8 database or an unreachable source ends in exit code 2 with a readable message, never a traceback. |

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

All four run in CI before the bot is allowed to open a pull request.
