# Marvel Rivals Groot skin monitor

Daily check for new Groot skins. When one shows up, the job sends a single email and records the skin in `state.json` so the same skin is not alerted again.

## What it watches

| Source label | Where it is read | What it catches |
| --- | --- | --- |
| `store` | Official patch notes, the **New In Store** section (and vault / throwback restocks) | Skins and bundles listed for purchase |
| `season pass` | [rivals.gs](https://rivals.gs/heroes/groot/) Groot costume pages, plus a battle-pass mention in new patch notes | Battle-pass costumes, free track and Luxury track |
| `event`, `twitch drop`, `rank reward`, `college perk` | New official patch notes, and rivals.gs when the costume page names that unlock | Event rewards, Twitch drops, competitive rewards, college-perk rotations |
| `other` | rivals.gs, when the game files have the costume but do not record a price or pass tier | Unlocks the files leave blank (some event costumes) |

Emoji, emote, spray, nameplate, and the other non-skin keywords in `monitor.py` are ignored. A store bundle and the matching costume share one alert: `Mecha-Flora Bundle` and `Mecha-Flora` are the same skin.

## Why rivals.gs for the season pass

Official patch notes are the right source for the store. They are also a poor source for the battle pass. A season launch names about three highlight costumes. Season 10's notes highlight White Fox, Captain America, and Loki, and do not mention Groot's pass costume, Grootlactus.

[rivals.gs](https://rivals.gs/about/) rebuilds heroes, costumes, and battle passes from the game's data tables after each patch. Each Groot costume page has a **How to get it** section. Pass costumes say which season and tier they come from, for example "Tier 10 of the S10 battle pass". No API key is required. The monitor reads `https://rivals.gs/heroes/groot/`, skips anything listed on `https://rivals.gs/unreleased/`, and skips costumes whose **Available from** date is still in the future.

You do not need a MarvelRivalsAPI key. This job never calls `marvelrivalsapi.com`. As of 7 Oct 2026 that host returns Cloudflare 502 for the homepage, the dashboard at `/dashboard/settings`, and `/api/v1/heroes`. The docs site still loads, which is why key signup looks documented and then fails. rivals.gs answered 200 on the same check.

Other options that were considered:

- **MarvelRivalsAPI** (`/api/v1/battlepass`) documents structured pass items, but the app and API are unreachable (502), every request would need an `x-api-key`, and the published item objects do not name the hero.
- **Official notes alone** stay in the job for store, event, Twitch, rank, and college wording (`Groot - Skin name`). They cannot list a pass skin the notes never mention.
- **Fandom and Liquipedia** describe costumes, but availability is hand-edited and easier to lag or scrape-block than the game-file extract.

Tradeoffs of rivals.gs: it is an unofficial fan site, so the HTML can change; the extract can land a few days after a patch; and some event costumes are in the files without an unlock method (those alert as `other`). Store prices on that site are ignored on purpose, so a shop skin still alerts from the official notes with the patch-note link.

## Schedule

`.github/workflows/monitor.yml` runs every day at 00:00 UTC, and on manual `workflow_dispatch`. It installs dependencies, runs the unit tests, runs `monitor.py`, and commits `state.json` when the seen-skin list changes.

The first run after this season-pass check will email every qualifying Groot skin that is not already in `state.json`. That includes older pass skins the store-only monitor never recorded. Later runs only email skins that are new since that state.

## Configuration

No new environment variables. The workflow already expects these repository secrets:

| Secret | Required | Purpose |
| --- | --- | --- |
| `SMTP_HOST` | yes | SMTP server |
| `SMTP_PORT` | no | Defaults to `587` |
| `SMTP_USER` | yes | SMTP username |
| `SMTP_PASS` | yes | SMTP password |
| `TO_EMAIL` | yes | Alert recipient |
| `FROM_EMAIL` | no | Defaults to `SMTP_USER` |

Catalog and patch-note URLs are constants in `monitor.py`. Do not commit SMTP credentials or a copy of `state.json` from another environment if it contains anything other than public skin names and URLs.

## Tests

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

## Limits

- A pass costume alerts once rivals.gs has extracted it and its available-from date has arrived. Marketing posts that preview a skin before it is in the game files will not alert.
- Patch notes that are already listed in `seen_update_urls` are not downloaded again. A newly recognized event phrase in an old note will not be replayed; the catalog backfill covers pass skins and file-unlocks with no store price.
- If rivals.gs is down (timeout or HTTP error), that is a warning in the log and the run still exits 0. Pass detection retries the next day. Store alerts from new patch notes still send.
- If rivals.gs returns a page that no longer has Groot costume links, or a costume page is missing its name, **How to get it** section, or **Details** section, the run emails `Marvel Rivals monitor: rivals.gs HTML needs a fix` and exits 1. The GitHub Action turns red after `state.json` is committed, so the same skin is not alerted twice while the parser is broken. The failure email repeats until the HTML matches `monitor.py` again.
- Non-skin items whose names happen to avoid the keyword list can still alert. Avatar items are intentionally not filtered.
