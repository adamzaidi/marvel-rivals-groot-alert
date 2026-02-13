import json
import os
import re
import smtplib
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


BASE = "https://www.marvelrivals.com"
INDEX_URL = "https://www.marvelrivals.com/gameupdate/"
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
}


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
        if line.lower().replace(":", "") in {"## new in store", "new in store", "## new in-store", "new in-store"}:
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


def parse_groot_skins(update_url: str) -> List[Tuple[str, str]]:
    """
    Returns list of (item_name, update_url) found in that update page,
    filtered to exclude obvious non-skin items (Option B).
    """
    html = fetch(update_url)
    lines = get_text_lines(html)
    store_block = find_new_in_store_block(lines)
    found: List[Tuple[str, str]] = []

    def maybe_add(line: str) -> None:
        m = GROOT_LINE_RE.match(line)
        if not m:
            return
        item = m.group(1).strip()
        if not item:
            return
        if _is_non_skin_item(item):
            return
        found.append((item, update_url))

    # scan store block first
    for line in store_block:
        maybe_add(line)

    # backup: sometimes formatting might put Groot lines outside the extracted block
    if not found:
        for line in lines:
            maybe_add(line)

    # de-dupe within page
    uniq: Dict[str, Tuple[str, str]] = {}
    for item, url in found:
        uniq[item.lower()] = (item, url)
    return list(uniq.values())


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


def main() -> int:
    state = load_state()
    seen_urls = set(state.get("seen_update_urls", []))
    seen_skins = state.get("seen_groot_skins", {})  # key: lower item name -> metadata

    index_html = fetch(INDEX_URL)
    update_urls = extract_update_urls_from_index(index_html)

    # Only process URLs we have not seen before
    new_update_urls = [u for u in update_urls if u not in seen_urls]

    notifications: List[Tuple[str, str]] = []
    for url in new_update_urls:
        try:
            items = parse_groot_skins(url)
        except Exception as e:
            print(f"[WARN] Failed to parse {url}: {e}")
            continue

        for item, src_url in items:
            k = item.lower()
            if k not in seen_skins:
                notifications.append((item, src_url))
                seen_skins[k] = {"item": item, "url": src_url}

        # Mark URL as seen regardless (so we don’t re-parse endlessly)
        seen_urls.add(url)

    # Save updated state
    state["seen_update_urls"] = sorted(seen_urls)
    state["seen_groot_skins"] = seen_skins
    save_state(state)

    # Send notifications (one email per run, can include multiple items)
    if notifications:
        lines = []
        for item, url in notifications:
            # Include the URL in the email for verification (your request)
            lines.append(f"- Groot - {item}\n  Source: {url}")

        body = "New Groot item(s) found in Marvel Rivals updates:\n\n" + "\n".join(lines)

        # Option A subject formatting:
        # - 1 item: include item name
        # - many: show count
        if len(notifications) == 1:
            item_name, _ = notifications[0]
            subject = f"Marvel Rivals: Groot - {item_name}"
        else:
            subject = f"Marvel Rivals: {len(notifications)} New Groot Items"

        send_email(subject, body)
        print(f"[INFO] Sent email for {len(notifications)} new item(s).")
    else:
        print("[INFO] No new Groot items.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())