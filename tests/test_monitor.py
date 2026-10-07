import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import monitor


STORE_UPDATE_HTML = """
<html><body>
<h1>Marvel Rivals Version 20260205 Patch Notes</h1>
<h2>All-New Content</h2>
<h3>New In Store</h3>
<p>1. Groot - Mecha-Flora Bundle
2. Magneto - Seat of Autumn Bundle
3. Groot - Mecha-Flora Emoji Bundle
4. Take a Seat Emote Combo Bundle
Available From: February 6th, 2026, at 02:00:00 (UTC).</p>
<h3>Heroes</h3>
<p>Groot's wall health was adjusted.</p>
</body></html>
"""

MIXED_UPDATE_HTML = """
<html><body>
<h2>All-New Content</h2>
<h3>New In Store</h3>
<p>1. Groot - Flora King Bundle
2. Groot - Flora King Emoji Bundle
3. Star-Lord - Starcracker Bundle</p>
<h3>New Event: Shenloong Tournament</h3>
<p>Complete event missions to unlock the Groot - Ironwood Serpent costume absolutely free!</p>
<h3>S10 Battle Pass</h3>
<p>Highlights include: White Fox - Cosmic Kumiho, Captain America - Astral Aegis, and Loki - The Chronicler.</p>
<h3>Twitch Drops</h3>
<p>This round's drops include the Groot - Stream Sprout costume along with related bundle content.</p>
<h3>Rank Rewards</h3>
<p>Season gold-tier costume reward is Groot - Bark Champion.</p>
<h3>College Perks</h3>
<p>College Perk costumes are changing to the following: Groot - Campus Canopy, Luna Snow - Lunar Luna.</p>
<h3>616 Vault</h3>
<p>The re-released contents include: Groot - Holiday Happiness Bundle.</p>
<h3>Heroes</h3>
<p>1. Groot - Should Not Count From Bugs</p>
</body></html>
"""

SEASON_PASS_COSTUME_HTML = """
<html><body><main>
<h1>Grootlactus</h1>
<section id="obtain"><h2>// How to get it</h2>
<p>Tier 10 of the S10 battle pass, free track, 400 Chrono Tokens to claim.
<a href="/battle-pass/s10/">S10 · Godbomb</a></p>
<ul><li>From S10 BattlePass</li></ul>
</section>
<section><h2>// Details</h2>
<p>Rarity Epic Hero Groot Available from 11 Sept 2026 Battle pass S10 · tier 10</p>
</section>
</main></body></html>
"""

STORE_COSTUME_HTML = """
<html><body><main>
<h1>Mecha-Flora</h1>
<section><h2>// How to get it</h2>
<p>Sold in Mecha-Flora Bundle for 2,200 Units.</p>
</section>
<section><h2>// Details</h2>
<p>Hero Groot Available from 6 Feb 2026 Bundle price 2,200 Units</p>
</section>
</main></body></html>
"""

UNKNOWN_COSTUME_HTML = """
<html><body><main>
<h1>Ironwood Serpent</h1>
<section><h2>// How to get it</h2>
<p>The game files do not say how this costume is unlocked.</p>
</section>
<section><h2>// Details</h2>
<p>Hero Groot Available from 12 Jun 2026</p>
</section>
</main></body></html>
"""

FUTURE_COSTUME_HTML = """
<html><body><main>
<h1>Future Bark</h1>
<section><h2>// How to get it</h2>
<p>Tier 2 of the S11 battle pass, Luxury track, 400 Chrono Tokens to claim.</p>
</section>
<section><h2>// Details</h2>
<p>Available from 11 Dec 2026 Battle pass S11 · tier 2</p>
</section>
</main></body></html>
"""

EVENT_COSTUME_HTML = """
<html><body><main>
<h1>Lantern Limb</h1>
<section><h2>// How to get it</h2>
<p>Earned from the Midnight Features event.</p>
</section>
<section><h2>// Details</h2>
<p>Hero Groot Available from 21 Feb 2025</p>
</section>
</main></body></html>
"""

SOLD_EVENT_COSTUME_HTML = """
<html><body><main>
<h1>Carved Traveler</h1>
<section><h2>// How to get it</h2>
<p>Sold in Carved Traveler for 800 Units. From Midnight Features II Season 1 Event</p>
</section>
<section><h2>// Details</h2>
<p>Available from 21 Feb 2025 Bundle price 800 Units</p>
</section>
</main></body></html>
"""

HERO_HTML = """
<html><body>
<a href="/costumes/groot-grootlactus-costume/">Grootlactus</a>
<a href="/costumes/groot-mecha-flora-costume/">Mecha-Flora</a>
<a href="/costumes/groot-future-bark-costume/">Future Bark</a>
<a href="/costumes/groot-lantern-limb-costume/">Lantern Limb</a>
<a href="/heroes/groot/">Groot</a>
<a href="/zh/costumes/groot-grootlactus-costume/">zh</a>
</body></html>
"""

UNRELEASED_HTML = """
<html><body>
<a href="/costumes/groot-future-bark-costume/">Future Bark</a>
<a href="/costumes/luna-snow-lunar-luna-costume/">Lunar Luna</a>
</body></html>
"""

INDEX_HTML = """
<html><body>
<a href="/gameupdate/20261007/41548_9999999.html">new</a>
<a href="https://www.marvelrivals.com/gameupdate/20260204/41548_1285429.html?utm=1">old</a>
<a href="/news/not-an-update.html">nope</a>
</body></html>
"""


class SkinKeyTests(unittest.TestCase):
    def test_bundle_suffix_collapses_to_the_skin(self):
        self.assertEqual(monitor.skin_key("Mecha-Flora Bundle"), "mecha-flora")
        self.assertEqual(monitor.skin_key("mecha-flora bundle"), "mecha-flora")
        self.assertEqual(monitor.skin_key("Groot - Mecha-Flora Emoji Bundle"), "mecha-flora")
        self.assertEqual(monitor.skin_key("Grootlactus"), "grootlactus")

    def test_legacy_state_key_matches_catalog_name(self):
        seen = monitor.index_seen_skins(
            {
                "mecha-flora bundle": {
                    "item": "Mecha-Flora Bundle",
                    "url": "https://www.marvelrivals.com/gameupdate/20260204/41548_1285429.html",
                }
            }
        )
        self.assertIn("mecha-flora", seen)
        self.assertEqual(seen["mecha-flora"]["source"], "store")
        self.assertNotIn("mecha-flora bundle", seen)


class StoreParserTests(unittest.TestCase):
    def test_store_block_keeps_bundle_and_drops_emoji(self):
        skins = monitor.parse_update_html(STORE_UPDATE_HTML, "https://example.test/update")
        self.assertEqual(
            [(s["name"], s["source"]) for s in skins],
            [("Mecha-Flora Bundle", "store")],
        )

    def test_store_heading_present_does_not_scan_later_groot_lines(self):
        html = """
        <html><body>
        <h3>New In Store</h3>
        <p>1. Star-Lord - Starcracker Bundle</p>
        <h3>Heroes</h3>
        <p>1. Groot - Should Not Count From Bugs</p>
        </body></html>
        """
        self.assertEqual(monitor.parse_update_html(html, "https://example.test/u"), [])

    def test_missing_store_heading_still_scans_groot_lines(self):
        html = "<html><body><p>1. Groot - Lost Bundle</p></body></html>"
        skins = monitor.parse_update_html(html, "https://example.test/u")
        self.assertEqual(skins[0]["name"], "Lost Bundle")
        self.assertEqual(skins[0]["source"], "store")


class NonStorePatchNoteTests(unittest.TestCase):
    def test_sections_are_labeled_and_highlights_without_groot_are_ignored(self):
        skins = monitor.parse_update_html(MIXED_UPDATE_HTML, "https://example.test/mixed")
        labeled = {s["name"]: s["source"] for s in skins}
        self.assertEqual(labeled["Flora King Bundle"], "store")
        self.assertEqual(labeled["Ironwood Serpent"], "event")
        self.assertEqual(labeled["Stream Sprout"], "twitch drop")
        self.assertEqual(labeled["Bark Champion"], "rank reward")
        self.assertEqual(labeled["Campus Canopy"], "college perk")
        self.assertEqual(labeled["Holiday Happiness Bundle"], "store")
        self.assertNotIn("Flora King Emoji Bundle", labeled)
        self.assertNotIn("Should Not Count From Bugs", labeled)
        self.assertNotIn("Cosmic Kumiho", labeled)
        ironwood = next(s for s in skins if s["name"] == "Ironwood Serpent")
        self.assertIn("Shenloong", ironwood["detail"])


class CatalogTests(unittest.TestCase):
    def test_season_pass_costume(self):
        skin = monitor.parse_costume_html(
            SEASON_PASS_COSTUME_HTML,
            "https://rivals.gs/costumes/groot-grootlactus-costume/",
            today=date(2026, 10, 7),
        )
        self.assertIsNotNone(skin)
        self.assertEqual(skin["name"], "Grootlactus")
        self.assertEqual(skin["source"], "season pass")
        self.assertIn("S10 battle pass", skin["detail"])

    def test_obtain_summary_tidies_spacing(self):
        text = "How to get it Tier 10 of the S10 battle pass, free track , 400 Chrono Tokens to claim ."
        self.assertEqual(
            monitor._summarize_obtain(text),
            "Tier 10 of the S10 battle pass, free track, 400 Chrono Tokens to claim",
        )

    def test_store_costume_is_left_to_patch_notes(self):
        skin = monitor.parse_costume_html(
            STORE_COSTUME_HTML,
            "https://rivals.gs/costumes/groot-mecha-flora-costume/",
            today=date(2026, 10, 7),
        )
        self.assertIsNone(skin)

    def test_unknown_unlock_is_labeled_other(self):
        skin = monitor.parse_costume_html(
            UNKNOWN_COSTUME_HTML,
            "https://rivals.gs/costumes/groot-ironwood-serpent-costume/",
            today=date(2026, 10, 7),
        )
        self.assertEqual(skin["source"], "other")
        self.assertIn("do not say how", skin["detail"])

    def test_future_pass_skin_is_skipped(self):
        skin = monitor.parse_costume_html(
            FUTURE_COSTUME_HTML,
            "https://rivals.gs/costumes/groot-future-bark-costume/",
            today=date(2026, 10, 7),
        )
        self.assertIsNone(skin)

    def test_free_event_costume_is_kept_and_priced_event_is_not(self):
        event = monitor.parse_costume_html(
            EVENT_COSTUME_HTML,
            "https://rivals.gs/costumes/groot-lantern-limb-costume/",
            today=date(2026, 10, 7),
        )
        sold = monitor.parse_costume_html(
            SOLD_EVENT_COSTUME_HTML,
            "https://rivals.gs/costumes/groot-carved-traveler-costume/",
            today=date(2026, 10, 7),
        )
        self.assertEqual(event["source"], "event")
        self.assertIsNone(sold)

    def test_catalog_skips_unreleased_and_store_entries(self):
        pages = {
            monitor.HERO_CATALOG_URL: HERO_HTML,
            monitor.UNRELEASED_URL: UNRELEASED_HTML,
            "https://rivals.gs/costumes/groot-grootlactus-costume/": SEASON_PASS_COSTUME_HTML,
            "https://rivals.gs/costumes/groot-mecha-flora-costume/": STORE_COSTUME_HTML,
            "https://rivals.gs/costumes/groot-lantern-limb-costume/": EVENT_COSTUME_HTML,
            "https://rivals.gs/costumes/groot-future-bark-costume/": FUTURE_COSTUME_HTML,
        }
        fetched = []

        def fake_fetch(url):
            fetched.append(url)
            if url not in pages:
                raise AssertionError(url)
            return pages[url]

        skins = monitor.collect_catalog_skins(fake_fetch, today=date(2026, 10, 7))
        labeled = {s["name"]: s["source"] for s in skins}
        self.assertEqual(labeled, {"Grootlactus": "season pass", "Lantern Limb": "event"})
        self.assertNotIn("https://rivals.gs/costumes/groot-future-bark-costume/", fetched)


class EmailAndMainTests(unittest.TestCase):
    def test_email_labels_source(self):
        subject, body = monitor.build_email(
            [
                {
                    "name": "Grootlactus",
                    "url": "https://rivals.gs/costumes/groot-grootlactus-costume/",
                    "source": "season pass",
                    "detail": "Tier 10 of the S10 battle pass, free track",
                }
            ]
        )
        self.assertEqual(subject, "Marvel Rivals: Groot - Grootlactus [season pass]")
        self.assertIn("[season pass]", body)
        self.assertIn("Tier 10 of the S10 battle pass", body)
        self.assertIn("https://rivals.gs/costumes/groot-grootlactus-costume/", body)

        subject, body = monitor.build_email(
            [
                {"name": "A", "url": "https://example.test/a", "source": "store", "detail": ""},
                {"name": "B", "url": "https://example.test/b", "source": "event", "detail": "New Event"},
            ]
        )
        self.assertEqual(subject, "Marvel Rivals: 2 New Groot Items")
        self.assertIn("[store]", body)
        self.assertIn("[event]", body)

    def test_main_alerts_once_and_keeps_store_behavior(self):
        new_update = "https://www.marvelrivals.com/gameupdate/20261007/41548_9999999.html"
        pages = {
            monitor.INDEX_URL: INDEX_HTML,
            new_update: MIXED_UPDATE_HTML,
            monitor.HERO_CATALOG_URL: HERO_HTML,
            monitor.UNRELEASED_URL: UNRELEASED_HTML,
            "https://rivals.gs/costumes/groot-grootlactus-costume/": SEASON_PASS_COSTUME_HTML,
            "https://rivals.gs/costumes/groot-mecha-flora-costume/": STORE_COSTUME_HTML,
            "https://rivals.gs/costumes/groot-lantern-limb-costume/": EVENT_COSTUME_HTML,
        }
        sent = []

        def fake_fetch(url):
            if url not in pages:
                raise AssertionError(url)
            return pages[url]

        def fake_send(subject, body):
            sent.append((subject, body))

        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            state_path.write_text(
                """
                {
                  "seen_groot_skins": {
                    "mecha-flora bundle": {
                      "item": "Mecha-Flora Bundle",
                      "url": "https://www.marvelrivals.com/gameupdate/20260204/41548_1285429.html"
                    }
                  },
                  "seen_update_urls": [
                    "https://www.marvelrivals.com/gameupdate/20260204/41548_1285429.html"
                  ]
                }
                """,
                encoding="utf-8",
            )
            original_path = monitor.STATE_PATH
            original_fetch = monitor.fetch
            original_send = monitor.send_email
            monitor.STATE_PATH = state_path
            monitor.fetch = fake_fetch
            monitor.send_email = fake_send
            try:
                self.assertEqual(monitor.main(), 0)
                self.assertEqual(len(sent), 1)
                subject, body = sent[0]
                self.assertIn("New Groot Items", subject)
                self.assertIn("Flora King Bundle [store]", body)
                self.assertIn("Ironwood Serpent [event]", body)
                self.assertIn("Stream Sprout [twitch drop]", body)
                self.assertIn("Grootlactus [season pass]", body)
                self.assertIn("Lantern Limb [event]", body)
                self.assertNotIn("Mecha-Flora", body)
                self.assertNotIn("Emoji", body)
                self.assertNotIn("Future Bark", body)
                self.assertNotIn("Should Not Count", body)

                sent.clear()
                self.assertEqual(monitor.main(), 0)
                self.assertEqual(sent, [])
            finally:
                monitor.STATE_PATH = original_path
                monitor.fetch = original_fetch
                monitor.send_email = original_send

    def test_catalog_failure_still_sends_store_alert(self):
        new_update = "https://www.marvelrivals.com/gameupdate/20261007/41548_9999999.html"

        def fake_fetch(url):
            if url == monitor.INDEX_URL:
                return INDEX_HTML
            if url == new_update:
                return STORE_UPDATE_HTML
            raise RuntimeError("catalog down")

        sent = []

        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            original_path = monitor.STATE_PATH
            original_fetch = monitor.fetch
            original_send = monitor.send_email
            monitor.STATE_PATH = state_path
            monitor.fetch = fake_fetch
            monitor.send_email = lambda subject, body: sent.append((subject, body))
            try:
                self.assertEqual(monitor.main(), 0)
            finally:
                monitor.STATE_PATH = original_path
                monitor.fetch = original_fetch
                monitor.send_email = original_send

        self.assertEqual(len(sent), 1)
        self.assertIn("Mecha-Flora Bundle [store]", sent[0][0])
        self.assertIn(new_update, sent[0][1])


class IndexTests(unittest.TestCase):
    def test_update_urls_from_index(self):
        urls = monitor.extract_update_urls_from_index(INDEX_HTML)
        self.assertEqual(
            urls,
            [
                "https://www.marvelrivals.com/gameupdate/20261007/41548_9999999.html",
                "https://www.marvelrivals.com/gameupdate/20260204/41548_1285429.html",
            ],
        )


if __name__ == "__main__":
    unittest.main()
