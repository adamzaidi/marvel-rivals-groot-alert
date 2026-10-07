import json
import os
import re
import smtplib
from datetime import date
from email.message import EmailMessage
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


BASE = "https://www.marvelrivals.com"
INDEX_URL = "https://www.marvelrivals.com/gameupdate/"
# rivals.gs rebuilds Marvel Rivals data tables from the game files after each
# patch, including which costumes belong to a battle pass. Official patch notes
# only name a few battle-pass highlights, so they miss most Groot pass skins.
RIVALS_GS = "https://rivals.gs"
HERO_CATALOG_URL = "https://rivals.gs/heroes/groot/"
UNRELEASED_URL = "https://rivals.gs/unreleased/"
STATE_PATH = Path("state.json")

# Matches:
#   /gameupdate/YYYYMMDD/41548_1286781.html
#   gameupdate/YYYYMMDD/41548_1286781.html
UPDATE_PATH_RE = re.compile(r"^/?gameupdate/\d{8}/\d+_\d+\.html$", re.IGNORECASE)

# Groot line variants:
# - allows leading bullets/numbers/punctuation like:
#   "• Groot - Skin", "- Groot - Skin", "1. Groot - Skin", "1) Groot - Skin"
# - supports hyphen/en-dash/em-dash
GROOT_LINE_RE = re.compile(
    r"^\s*(?:[•\-\*\u2022]|\d+[.)])?\s*Groot\s*[-–—]\s*(.+?)\s*$",
    re.IGNORECASE,
)

# Inline "Groot - Name costume" mentions used outside the store list.
# The optional kind word is how patch notes distinguish a costume from an emoji.
_MENTION_KIND = (
    r"costume|bundle|skin|chroma|emoji|emote|spray|nameplate|mvp|banner|frame|title|voice|announcer|sticker"
)
GROOT_MENTION_RE = re.compile(
    r"Groot\s*[-–—]\s*"
    r"(?P<name>(?:(?!\s+(?:" + _MENTION_KIND + r")\b)[^,.;!\n])+)"
    r"(?:\s+(?P<kind>" + _MENTION_KIND + r"))?",
    re.IGNORECASE,
)

GROOT_COSTUME_PATH_RE = re.compile(r"^/costumes/groot-[a-z0-9-]+-costume/?$")
ANY_COSTUME_PATH_RE = re.compile(r"^/costumes/[a-z0-9-]+-costume/?$")

# Option B: filter obvious non-skin items
# (Per your request, "avatar" is NOT blacklisted.)
NON_SKIN_KEYWORDS = {
    "emoji",
    "emote",
    "spray",
    "nameplate",
    "sticker",
    "voice",
    "announcer",
    "banner",
    "frame",
    "title",
    "mvp",
}

NON_SKIN_KINDS = {
    "emoji",
    "emote",
    "spray",
    "nameplate",
    "sticker",
    "voice",
    "announcer",
    "banner",
    "frame",
    "title",
    "mvp",
}

SKIN_KEY_SUFFIXES = (
    "emoji bundle",
    "bundle",
    "emoji",
    "chroma",
    "costume",
    "skin",
    "emote",
    "spray",
    "nameplate",
    "mvp",
)

STORE_HEADINGS = {"## new in store", "new in store", "## new in-store", "new in-store"}

MONTHS = {
    "jan": 1,
    "january": 1,
    "feb": 2,
    "february": 2,
    "mar": 3,
    "march": 3,
    "apr": 4,
    "april": 4,
    "may": 5,
    "jun": 6,
    "june": 6,
    "jul": 7,
    "july": 7,
    "aug": 8,
    "august": 8,
    "sep": 9,
    "sept": 9,
    "september": 9,
    "oct": 10,
    "october": 10,
    "nov": 11,
    "november": 11,
    "dec": 12,
    "december": 12,
}

AVAILABLE_FROM_RE = re.compile(
    r"Available from\s+(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})",
    re.IGNORECASE,
)

FetchFn = Callable[[str], str]


def load_state() -> Dict:
    if not STATE_PATH.exists():
        return {"seen_update_urls": [], "seen_groot_skins": {}}
    return json.loads(STATE_PATH.read_text(encoding="utf-8"))


def save_state(state: Dict) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def fetch(url: str) -> str:
    # User-Agent helps with basic bot filtering
    headers = {"User-Agent": "Mozilla/5.0 (compatible; GrootSkinMonitor/1.0)"}
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    return r.text


def skin_key(name: str) -> str:
    """Normalize a skin name so 'Mecha-Flora Bundle' and 'Mecha-Flora' match."""
    n = name.lower().strip()
    n = re.sub(r"^groot\s*[-–—:]\s*", "", n)
    n = re.sub(r"\s+", " ", n).strip()
    changed = True
    while changed:
        changed = False
        for suffix in SKIN_KEY_SUFFIXES:
            tail = " " + suffix
            if n.endswith(tail):
                n = n[: -len(tail)].strip()
                changed = True
    return n


def index_seen_skins(seen: Dict) -> Dict:
    """Key seen skins by normalized name and keep a source label."""
    indexed: Dict[str, Dict] = {}
    for key, meta in seen.items():
        if not isinstance(meta, dict):
            meta = {"item": str(meta)}
        item = str(meta.get("item") or key)
        normalized = skin_key(item)
        if not normalized or normalized in indexed:
            continue
        indexed[normalized] = {
            "item": item,
            "url": meta.get("url", ""),
            "source": meta.get("source") or "store",
        }
    return indexed


def extract_update_urls_from_index(html: str) -> List[str]:
    """
    Best-effort extraction:
    - collect <a href> links that look like update detail pages
      (robust to missing leading slash, absolute URLs, query strings)
    - also scan raw HTML for occurrences (in case links are embedded in scripts)
    """
    soup = BeautifulSoup(html, "lxml")
    urls = set()

    # 1) Normal anchors (robust to absolute urls / missing leading slash / query strings)
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()

        # strip query/fragment
        href = href.split("?", 1)[0].split("#", 1)[0]

        # reduce absolute URL to path-like string for matching
        href_path = href.replace("https://www.marvelrivals.com/", "").lstrip("/")

        if UPDATE_PATH_RE.match(href_path):
            urls.add(urljoin(BASE, "/" + href_path))

    # 2) Raw HTML scan fallback (covers absolute urls and relative paths)
    for m in re.finditer(
        r"(https?://www\.marvelrivals\.com)?/?gameupdate/\d{8}/\d+_\d+\.html",
        html,
        re.IGNORECASE,
    ):
        path_or_url = m.group(0)
        urls.add(urljoin(BASE, path_or_url))

    # Sort newest-ish first by date embedded in URL
    def key(u: str) -> str:
        # .../gameupdate/YYYYMMDD/...
        parts = u.split("/gameupdate/")
        if len(parts) < 2:
            return ""
        tail = parts[1]
        return tail[:8]

    return sorted(urls, key=key, reverse=True)


def get_text_lines(html: str) -> List[str]:
    soup = BeautifulSoup(html, "lxml")
    # Remove scripts/styles
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    text = soup.get_text("\n")
    # Normalize whitespace and drop empties
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            lines.append(line)
    return lines


def find_new_in_store_block(lines: List[str]) -> List[str]:
    """
    Find the "New In Store" section and return its lines until next section-ish boundary.
    """
    start_idx = None
    for i, line in enumerate(lines):
        if line.lower().replace(":", "") in STORE_HEADINGS:
            start_idx = i
            break

    if start_idx is None:
        # sometimes headers render without ##
        for i, line in enumerate(lines):
            if line.lower().replace(":", "") in {"new in store", "new in-store"}:
                start_idx = i
                break

    if start_idx is None:
        return []

    block = []
    for j in range(start_idx + 1, len(lines)):
        l = lines[j]
        # Stop at next section heading
        if l.startswith("## "):
            break
        # Also stop at very common “section” words if they appear as standalone headings
        if l.lower() in {"bug fixes", "balance adjustments", "known issues", "optimization", "patch notes"}:
            break
        block.append(l)

    return block


def _is_non_skin_item(name: str) -> bool:
    lowered = name.lower()
    return any(k in lowered for k in NON_SKIN_KEYWORDS)


def _clean_skin_name(name: str) -> str:
    name = re.sub(r"\s+", " ", name).strip(" -–—:|")
    return name


def groot_names_from_store_lines(lines: List[str]) -> List[str]:
    found: List[str] = []
    for line in lines:
        m = GROOT_LINE_RE.match(line)
        if not m:
            continue
        item = _clean_skin_name(m.group(1))
        if not item or _is_non_skin_item(item):
            continue
        found.append(item)
    return found


def source_for_heading(title: str) -> Optional[str]:
    """Label a patch-note section. Store headings stay on the existing parser."""
    t = title.lower().replace("–", "-").replace("—", "-")
    if "new in store" in t or "new in-store" in t:
        return None
    if "battle pass" in t or "battlepass" in t:
        return "season pass"
    if "twitch" in t:
        return "twitch drop"
    if "rank reward" in t:
        return "rank reward"
    if "college" in t:
        return "college perk"
    if "vault" in t or "throwback" in t:
        return "store"
    if "event" in t:
        return "event"
    return None


def _is_store_heading(title: str) -> bool:
    return title.lower().replace(":", "").strip() in STORE_HEADINGS


def iter_update_sections(html: str):
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    for heading in soup.find_all(["h2", "h3"]):
        title = heading.get_text(" ", strip=True)
        parts = []
        for sib in heading.find_next_siblings():
            if getattr(sib, "name", None) in ("h2", "h3"):
                break
            # Keep list items on their own lines so the store line parser still matches.
            text = sib.get_text("\n", strip=True)
            if text:
                parts.append(text)
        yield title, "\n".join(parts)


def extract_groot_mentions(text: str) -> List[str]:
    names: List[str] = []
    for match in GROOT_MENTION_RE.finditer(text):
        kind = (match.group("kind") or "").lower()
        if kind in NON_SKIN_KINDS:
            continue
        name = _clean_skin_name(match.group("name"))
        if kind in {"bundle", "chroma"}:
            name = _clean_skin_name(f"{name} {kind.capitalize()}")
        if not name or _is_non_skin_item(name):
            continue
        names.append(name)
    return names


def _dedupe_skins(skins: List[Dict]) -> List[Dict]:
    uniq: Dict[str, Dict] = {}
    for skin in skins:
        key = skin_key(skin["name"])
        if key and key not in uniq:
            uniq[key] = skin
    return list(uniq.values())


def parse_update_html(html: str, update_url: str) -> List[Dict]:
    """
    Groot skins on one official update page.
    Store rows keep the historical line parser. Other sections (battle pass
    highlights, events, Twitch drops, rank rewards, college perks, vault
    restocks) are labeled separately.
    """
    sections = list(iter_update_sections(html))
    store_names: List[str] = []
    saw_store_heading = False
    for title, body in sections:
        if _is_store_heading(title):
            saw_store_heading = True
            store_names.extend(groot_names_from_store_lines(body.splitlines()))

    if not saw_store_heading:
        # Older pages, or a heading the tag scan missed: original line-block logic.
        lines = get_text_lines(html)
        store_block = find_new_in_store_block(lines)
        if store_block:
            store_names = groot_names_from_store_lines(store_block)
        else:
            store_names = groot_names_from_store_lines(lines)

    found: List[Dict] = []
    for name in store_names:
        found.append({"name": name, "url": update_url, "source": "store", "detail": ""})

    for title, body in sections:
        source = source_for_heading(title)
        if not source or not body:
            continue
        for name in extract_groot_mentions(body):
            found.append(
                {
                    "name": name,
                    "url": update_url,
                    "source": source,
                    "detail": title.strip(),
                }
            )

    return _dedupe_skins(found)


def parse_groot_skins(update_url: str) -> List[Dict]:
    """
    Returns Groot skins found on that update page, excluding obvious non-skin items.
    """
    html = fetch(update_url)
    return parse_update_html(html, update_url)


def _section_text(soup: BeautifulSoup, heading: str) -> str:
    needle = heading.lower()
    for h2 in soup.find_all(["h2", "h3"]):
        if needle in h2.get_text(" ", strip=True).lower():
            section = h2.find_parent("section") or h2.parent
            if section is not None:
                return section.get_text(" ", strip=True)
    return ""


def _parse_available_from(text: str) -> Optional[date]:
    match = AVAILABLE_FROM_RE.search(text)
    if not match:
        return None
    month = MONTHS.get(match.group(2).lower())
    if not month:
        return None
    try:
        return date(int(match.group(3)), month, int(match.group(1)))
    except ValueError:
        return None


def _summarize_obtain(text: str) -> str:
    cleaned = re.sub(r"^.*?How to get it\s*", "", text, count=1, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s+", " ", cleaned)
    cleaned = re.sub(r"\s+([,.;:])", r"\1", cleaned)
    cleaned = cleaned.strip(" .")
    if len(cleaned) > 240:
        cleaned = cleaned[:237].rstrip() + "..."
    return cleaned


def classify_acquisition(obtain: str, details: str) -> Optional[str]:
    """
    Map a rivals.gs costume page to an alert source.
    Store purchases stay on the official patch-note parser, so they return None.
    """
    blob = f"{obtain}\n{details}".lower()
    if "battle pass" in blob or "battlepass" in blob:
        return "season pass"
    if "twitch" in blob:
        return "twitch drop"
    if "college" in blob:
        return "college perk"
    if "rank reward" in blob or "gold-tier" in blob:
        return "rank reward"
    sold = "sold in" in blob or re.search(r"\bunits\b", blob) is not None
    if "event" in blob and not sold:
        return "event"
    if "do not say how" in blob or "does not say how" in blob:
        return "other"
    return None


def parse_costume_html(html: str, url: str, today: Optional[date] = None) -> Optional[Dict]:
    """Return a non-store Groot costume, or None when it should not alert."""
    soup = BeautifulSoup(html, "lxml")
    heading = soup.find("h1")
    name = heading.get_text(" ", strip=True) if heading else ""
    name = _clean_skin_name(name)
    if not name or name.lower() == "groot" or _is_non_skin_item(name):
        return None

    obtain = _section_text(soup, "how to get it")
    details = _section_text(soup, "details")
    available = _parse_available_from(f"{details} {obtain}")
    if today is None:
        today = date.today()
    if available is not None and available > today:
        print(f"[INFO] Skipping unreleased Groot costume {name} (available {available.isoformat()}).")
        return None

    source = classify_acquisition(obtain, details)
    if not source:
        return None
    return {
        "name": name,
        "url": url,
        "source": source,
        "detail": _summarize_obtain(obtain),
    }


def _costume_paths(html: str, pattern: re.Pattern) -> List[str]:
    soup = BeautifulSoup(html, "lxml")
    paths: List[str] = []
    seen = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip().split("?", 1)[0].split("#", 1)[0]
        if not pattern.match(href):
            continue
        if not href.endswith("/"):
            href += "/"
        if href not in seen:
            seen.add(href)
            paths.append(href)
    return paths


def collect_catalog_skins(fetch_fn: FetchFn, today: Optional[date] = None) -> List[Dict]:
    """
    Non-store Groot costumes from the rivals.gs hero catalog.
    Future-dated and /unreleased costumes are left for a later run.
    """
    hero_html = fetch_fn(HERO_CATALOG_URL)
    paths = _costume_paths(hero_html, GROOT_COSTUME_PATH_RE)
    if not paths:
        print("[WARN] rivals.gs hero page listed no Groot costumes.")
        return []

    unreleased = set()
    try:
        unreleased_html = fetch_fn(UNRELEASED_URL)
        unreleased = set(_costume_paths(unreleased_html, ANY_COSTUME_PATH_RE))
    except Exception as e:
        print(f"[WARN] Failed to read rivals.gs unreleased list: {e}")

    found: List[Dict] = []
    for path in paths:
        if path in unreleased:
            print(f"[INFO] Skipping unreleased Groot costume path {path}.")
            continue
        url = urljoin(RIVALS_GS, path)
        try:
            html = fetch_fn(url)
        except Exception as e:
            print(f"[WARN] Failed to read {url}: {e}")
            continue
        skin = parse_costume_html(html, url, today=today)
        if skin:
            found.append(skin)
    return _dedupe_skins(found)


def build_email(notifications: List[Dict]) -> tuple:
    lines = []
    for skin in notifications:
        lines.append(f"- Groot - {skin['name']} [{skin['source']}]")
        detail = (skin.get("detail") or "").strip()
        if detail:
            lines.append(f"  Note: {detail}")
        lines.append(f"  {skin['url']}")
    body = "New Groot item(s) found in Marvel Rivals:\n\n" + "\n".join(lines)
    if len(notifications) == 1:
        skin = notifications[0]
        subject = f"Marvel Rivals: Groot - {skin['name']} [{skin['source']}]"
    else:
        subject = f"Marvel Rivals: {len(notifications)} New Groot Items"
    return subject, body


def send_email(subject: str, body: str) -> None:
    smtp_host = os.environ["SMTP_HOST"]
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ["SMTP_USER"]
    smtp_pass = os.environ["SMTP_PASS"]
    to_addr = os.environ["TO_EMAIL"]
    from_addr = os.environ.get("FROM_EMAIL", smtp_user)

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(body)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)


def _add_new(notifications: List[Dict], seen_skins: Dict, skin: Dict) -> None:
    key = skin_key(skin["name"])
    if not key or key in seen_skins:
        return
    notifications.append(skin)
    seen_skins[key] = {
        "item": skin["name"],
        "url": skin["url"],
        "source": skin["source"],
    }


def main() -> int:
    state = load_state()
    seen_urls = set(state.get("seen_update_urls", []))
    seen_skins = index_seen_skins(state.get("seen_groot_skins", {}))

    index_html = fetch(INDEX_URL)
    update_urls = extract_update_urls_from_index(index_html)

    # Only process URLs we have not seen before
    new_update_urls = [u for u in update_urls if u not in seen_urls]

    notifications: List[Dict] = []
    for url in new_update_urls:
        try:
            items = parse_groot_skins(url)
        except Exception as e:
            print(f"[WARN] Failed to parse {url}: {e}")
            continue

        for skin in items:
            _add_new(notifications, seen_skins, skin)

        # Mark URL as seen regardless (so we don’t re-parse endlessly)
        seen_urls.add(url)

    try:
        catalog = collect_catalog_skins(fetch)
    except Exception as e:
        catalog = []
        print(f"[WARN] Failed to read rivals.gs catalog: {e}")

    for skin in catalog:
        _add_new(notifications, seen_skins, skin)

    # Save updated state
    state["seen_update_urls"] = sorted(seen_urls)
    state["seen_groot_skins"] = seen_skins
    save_state(state)

    # Send notifications (one email per run, can include multiple items)
    if notifications:
        subject, body = build_email(notifications)
        send_email(subject, body)
        print(f"[INFO] Sent email for {len(notifications)} new item(s).")
        for skin in notifications:
            print(f"[INFO] {skin['source']}: Groot - {skin['name']}")
    else:
        print("[INFO] No new Groot items.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
