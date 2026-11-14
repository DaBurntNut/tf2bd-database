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
| `cheater` + `racist` | `racist` (`cheater` and every proof that is not an `[auto] automatically marked: Racist \| reason: …` line are removed; those racist lines stay) |
| `cheater` + any other tag | entry removed (the entry as a whole was a false positive) |

Players who were added to this database and were never on
Vorobey's list are **never** demoted or removed by the bot.

### Removed from Vorobey's list

Every SteamID that was in the previous snapshot but is gone from the current
Vorobey list is listed in the pull request, whether or not it was demoted
above:

| SteamID | Profile Link |
| --- | --- |
| `[U:1:1582772205]` | [Profile](https://steamcommunity.com/profiles/76561199543037933) |

Vorobey's list stores no player names, so this table only shows the SteamID
and the Steam profile permalink (the SteamID64 URL), which keeps working even
after a player renames themselves. Very long lists are capped in the pull
request body with the number of remaining SteamIDs stated, so the body always
fits GitHub's size limit.

### Safety rails

| Rail | What it guarantees |
| --- | --- |
| Snapshot-only demotion | An entry is only demoted when its SteamID was in the previous snapshot *and* is gone from today's list — never merely "absent from Vorobey". Manually added cheaters are untouched. |
| Mass-removal guard | If an implausibly large share of the snapshot disappears at once (more than 50 IDs and more than 20 %), demotion is skipped and the baseline is kept, so an upstream outage cannot wipe entries. A human can force it with `--allow-mass-demotion`. |
| Frozen baseline | If a run finds removals it cannot apply (demotion disabled, or vetoed by the guard), the snapshot is **not** advanced — otherwise those removals would be forgotten forever. |
| Exact snapshot | The snapshot is written from the fetched **bytes**, never re-encoded, and `.gitattributes` keeps Git from touching line endings. |
| Bounded fetch | HTTPS only (a redirect downgrade to plain HTTP is refused), 64 MiB maximum, 30 s timeout, 3 attempts, then the next fallback URL. |
| Bounded PR body | Tables are row-capped and the body is hard-truncated below GitHub's 65,536-character limit, so opening the pull request can never fail on size. |
| Escaped output | Player names and proofs are escaped for Markdown: no broken tables, no forged links, no injected HTML, no `@` mentions. |

### Run it yourself

```
python3 scripts/sync_vorobey_hackerpolice.py --dry-run      # report only
python3 scripts/sync_vorobey_hackerpolice.py --demote --report out.md
python3 -m unittest discover -s tests                        # run the test suite
```

Exit code `0` means success, `2` means the database or the Vorobey list was
unusable (nothing is written in that case).

### Update the Vorobey database copy

| File | What the bot does |
| --- | --- |
| `snapshot/playerlist.vorobey-hackerpolice.json` | Updated in the same pull request to an exact, byte-for-byte copy of the current `playerlist.vorobey-hackerpolice.json` list. By comparing the previous copy against the new list, the bot knows exactly who was removed from the Vorobey hackerpolice list and it never touches players who were added manually to this database. |
