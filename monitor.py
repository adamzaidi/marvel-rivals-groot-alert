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

# Matches /gameupdate/YYYYMMDD/41548_1286781.html
UPDATE_PATH_RE = re.compile(r"^/gameupdate/\d{8}/\d+_\d+\.html$")

# Groot line variants: "-" or "–" or "—"
GROOT_LINE_RE = re.compile(r"^\s*Groot\s*[-–—]\s*(.+?)\s*$", re.IGNORECASE)


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
    - collect all <a href="/gameupdate/..."> links matching our known pattern
    - also scan raw HTML for occurrences (in case links are embedded in scripts)
    """
    soup = BeautifulSoup(html, "lxml")

    urls = set()

    # 1) Normal anchors
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if UPDATE_PATH_RE.match(href):
            urls.add(urljoin(BASE, href))

    # 2) Raw HTML scan fallback
    for m in re.finditer(r'"/gameupdate/\d{8}/\d+_\d+\.html"', html):
        path = m.group(0).strip('"')
        if UPDATE_PATH_RE.match(path):
            urls.add(urljoin(BASE, path))

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

    Many pages look markdown-ish in text extraction:
      "## New In Store"
      "Groot - <Skin>"
      ...
      "## Bug Fixes"
    We'll treat lines that start with "## " as new section boundaries.
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


def parse_groot_skins(update_url: str) -> List[Tuple[str, str]]:
    """
    Returns list of (skin_name, update_url) found in that update page.
    """
    html = fetch(update_url)
    lines = get_text_lines(html)
    store_block = find_new_in_store_block(lines)
    found = []

    # scan store block first
    for line in store_block:
        m = GROOT_LINE_RE.match(line)
        if m:
            skin = m.group(1).strip()
            if skin:
                found.append((skin, update_url))

    # backup: sometimes formatting might put Groot lines outside the extracted block
    if not found:
        for line in lines:
            m = GROOT_LINE_RE.match(line)
            if m:
                skin = m.group(1).strip()
                if skin:
                    found.append((skin, update_url))

    # de-dupe within page
    uniq = {}
    for skin, url in found:
        key = skin.lower()
        uniq[key] = (skin, url)
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
    seen_skins = state.get("seen_groot_skins", {})  # key: lower skin name -> metadata

    index_html = fetch(INDEX_URL)
    update_urls = extract_update_urls_from_index(index_html)

    # Only process URLs we have not seen before
    new_update_urls = [u for u in update_urls if u not in seen_urls]

    notifications = []
    for url in new_update_urls:
        try:
            skins = parse_groot_skins(url)
        except Exception as e:
            print(f"[WARN] Failed to parse {url}: {e}")
            continue

        for skin, src_url in skins:
            k = skin.lower()
            if k not in seen_skins:
                notifications.append((skin, src_url))
                seen_skins[k] = {"skin": skin, "url": src_url}

        # Mark URL as seen regardless (so we don’t re-parse endlessly)
        seen_urls.add(url)

    # Save updated state
    state["seen_update_urls"] = sorted(seen_urls)
    state["seen_groot_skins"] = seen_skins
    save_state(state)

    # Send notifications (one email per run, can include multiple skins)
    if notifications:
        lines = []
        for skin, url in notifications:
            lines.append(f"- Groot - {skin}\n  {url}")
        body = "New Groot skin(s) found in Marvel Rivals updates:\n\n" + "\n".join(lines)
        subject = f"Marvel Rivals: New Groot skin ({len(notifications)})"
        send_email(subject, body)
        print(f"[INFO] Sent email for {len(notifications)} new skin(s).")
    else:
        print("[INFO] No new Groot skins.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())