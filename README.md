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

Every day at **05:23 UTC** it compares this database with Vorobey's list and
opens a pull request. **Nothing changes until you merge it.** It can also be run
by hand (**Actions → Run workflow**) as a pull request, a direct commit or a dry
run.

| On Vorobey's list | Result |
| --- | --- |
| `suspicious` | `cheater` |
| `racist` | `cheater` + `racist` |
| `suspicious` + `racist` | `cheater` + `racist` |
| `cheater` already | unchanged |

| Gone from Vorobey's list | Result |
| --- | --- |
| `cheater`, and it was in the previous snapshot | entry removed |
| `cheater` + `racist` | `racist` kept; `cheater` and its proofs removed |
| `cheater` + any other tag | entry removed |

Only players who were in the previous snapshot and are gone now are demoted, so
**cheaters added by hand are never touched**. Every removed SteamID is listed in
the pull request with its profile link, and every table also links each player's
[SteamHistory](https://steamhistory.net/) page. `snapshot/playerlist.vorobey-hackerpolice.json`
is yesterday's copy of Vorobey's list — the bot compares against it to know who
was removed, and updates it in the same pull request. Evidence links stay in the
pull request; they reach the database only if you run the script yourself with
`--include-proof`.

## Safety rails

- **Frozen baseline** — if the removals it found cannot be applied (demotion off,
  or vetoed by the guard), the snapshot is not advanced, so they are not forgotten.
- **Mass-removal guard** — more than 50 IDs *and* more than 20 % gone at once means
  demotion is skipped; `--allow-mass-demotion` forces it through.
- **Strict JSON** — `NaN`, `Infinity` and duplicate keys are refused, never
  rewritten, so the bot cannot publish a file TF2BD itself cannot load.
- **Bounded fetch** — HTTPS only (a redirect downgrade is refused), 64 MiB, 30 s,
  3 attempts, then the next fallback; credentials in a URL are redacted.
- **Atomic writes** — every file is replaced in one step, so a crash or a full disk
  leaves the previous file intact.
- **Checked changes** — a pull request touching `scripts/`, `tests/`,
  `pyproject.toml`, `.gitattributes` or the workflow runs ruff, `mypy --strict` and
  the tests, read-only.

## Run it yourself

```
python3 scripts/sync_vorobey_hackerpolice.py --dry-run
python3 scripts/sync_vorobey_hackerpolice.py --demote --report out.md
python3 -m unittest discover -s tests
```

Exit `0` means success. Exit `2` means the run refused or failed — bad input,
two paths pointing at the same file, a source that is not HTTPS, or an output
that cannot be written — and no partial file is left behind.
