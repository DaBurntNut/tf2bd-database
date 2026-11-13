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

### Update the Vorobey database copy

| File | What the bot does |
| --- | --- |
| `snapshot/playerlist.vorobey-hackerpolice.json` | Updated in the same pull request to an exact, byte-for-byte copy of the current `playerlist.vorobey-hackerpolice.json` list. By comparing the previous copy against the new list, the bot knows exactly who was removed from the Vorobey hackerpolice list and it never touches players who were added manually to this database. |
