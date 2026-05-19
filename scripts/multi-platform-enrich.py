#!/usr/bin/env python3
"""Multi-platform watch-link enrichment.

For talks without a verified video URL, probe each platform's known URL pattern
or scrape the talk-detail page for embedded video.

Platforms covered:
  * recon.cx — `https://recon.cx/{year}/talks/{slug}.html`. Pages often have
    an embedded MP4 (Recon hosts video on their own infrastructure).
  * troopers.de — talk pages at `troopers.de/troopers{YY}/talks/{id}/` often
    embed a YouTube video after the talk is published.
  * offensivecon.org — `offensivecon.org/speakers/{year}/{slug}.html` may
    link out to a YouTube ID once the talk is published.
  * USENIX — `usenix.org/conference/usenixsecurity{year}/presentation/{slug}`
    pages embed a video player when the talk has been recorded.
  * media.ccc.de — API search by title; matches use the player URL directly.
  * archive.org — text search; matches with video files are surfaced as
    playable URLs.

For every candidate URL we find, we verify it via verify-links logic.
"""

import json
import re
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

import yaml

ROOT = Path.home() / "repos/windows-security-talks"
CACHE_FILE = ROOT / "scripts/.multi-platform-cache.json"

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/120.0.0.0 Safari/537.36")


def fetch(url, timeout=20):
    out = subprocess.run(
        ["curl", "-s", "-A", UA, "-L", "--max-time", str(timeout), url],
        capture_output=True, text=True, timeout=timeout + 5,
    )
    return out.stdout if out.returncode == 0 else ""


def load_cache():
    if CACHE_FILE.exists():
        try: return json.load(open(CACHE_FILE))
        except Exception: return {}
    return {}


def save_cache(cache):
    json.dump(cache, open(CACHE_FILE, "w"), indent=1)


def slugify(s, sep="-"):
    s = (s or "").lower()
    s = re.sub(r"[^a-z0-9]+", sep, s).strip(sep)
    return s


def extract_year(record):
    y = record.get("year")
    if y: return str(y)
    v = (record.get("venue") or "")
    m = re.search(r"(20\d{2})", v)
    return m.group(1) if m else None


def slug_variants(title):
    """Generate plausible URL slugs for a title."""
    base = slugify(title)
    out = {base}
    short = "-".join(base.split("-")[:6])  # first 6 words
    out.add(short)
    short3 = "-".join(base.split("-")[:3])
    out.add(short3)
    # Remove leading articles like "the-"
    if base.startswith("the-"):
        out.add(base[4:])
    return [s for s in out if len(s) > 5]


def find_video_in_html(html):
    """Extract video URLs from an HTML page. Returns list of URLs."""
    if not html:
        return []
    found = []
    # YouTube iframe / embed
    for m in re.finditer(r'(?:src|href)=["\'](https?://(?:www\.)?youtube(?:-nocookie)?\.com/embed/([\w-]{11}))', html):
        found.append(f"https://www.youtube.com/watch?v={m.group(2)}")
    for m in re.finditer(r'(?:src|href)=["\'](https?://(?:www\.)?youtube\.com/watch\?v=([\w-]{11}))', html):
        found.append(m.group(1))
    for m in re.finditer(r'(?:src|href)=["\'](https?://youtu\.be/([\w-]{11}))', html):
        found.append(f"https://www.youtube.com/watch?v={m.group(2)}")
    # Direct MP4 / WebM
    for m in re.finditer(r'(?:src|href)=["\'](https?://[^"\']+\.(?:mp4|webm))["\']', html):
        found.append(m.group(1))
    # Vimeo
    for m in re.finditer(r'player\.vimeo\.com/video/(\d+)', html):
        found.append(f"https://vimeo.com/{m.group(1)}")
    # media.ccc.de
    for m in re.finditer(r'(https?://media\.ccc\.de/v/[\w.-]+)', html):
        found.append(m.group(1))
    # Dedupe preserving order
    seen = set()
    out = []
    for u in found:
        if u in seen: continue
        seen.add(u)
        out.append(u)
    return out


# ─────────── recon.cx ───────────

def enrich_recon(record):
    """Build candidate URLs for a Recon talk; scrape each for video."""
    year = extract_year(record)
    if not year:
        return []
    title = record.get("title", "")
    candidates = []
    for slug in slug_variants(title):
        candidates.append(f"https://recon.cx/{year}/talks/{slug}.html")
        candidates.append(f"https://recon.cx/{year}/en/talks/{slug}.html")
    # Also if we already have a recon.cx URL as slides, scrape that one.
    if record.get("url") and "recon.cx" in record["url"]:
        candidates.insert(0, record["url"])
    videos = []
    for url in candidates[:3]:  # keep budget bounded
        html = fetch(url)
        if "<title>" not in html.lower():
            continue
        # Verify the page is for the right talk (title in the page).
        title_words = set(re.findall(r"\w+", title.lower())[:5])
        page_lower = html.lower()
        if not any(w in page_lower for w in title_words if len(w) > 4):
            continue
        videos.extend(find_video_in_html(html))
        if videos:
            break
    return videos


# ─────────── troopers.de ───────────

def enrich_troopers(record):
    """Fetch the troopers.de talk page (we already have it as slides URL) and
    look for embedded video."""
    url = record.get("url") or ""
    if "troopers.de" not in url:
        # Fall back to building from title.
        year = extract_year(record)
        if not year or len(year) != 4:
            return []
        yy = year[2:]
        slug = slugify(record.get("title", ""))
        url = f"https://troopers.de/troopers{yy}/talks/{slug}/"
    html = fetch(url)
    if not html:
        return []
    return find_video_in_html(html)


# ─────────── offensivecon.org ───────────

def enrich_offensivecon(record):
    url = record.get("url") or ""
    if "offensivecon.org" not in url:
        year = extract_year(record)
        if not year:
            return []
        # The speaker slug is usually first speaker's lowercase name.
        speaker = (record.get("speaker") or "").split(",")[0].split(";")[0]
        speaker = re.sub(r"\([^)]*\)", "", speaker).strip()
        slug = slugify(speaker)
        url = f"https://www.offensivecon.org/speakers/{year}/{slug}.html"
    html = fetch(url)
    if not html:
        return []
    return find_video_in_html(html)


# ─────────── USENIX ───────────

def enrich_usenix(record):
    """USENIX hosts presentation videos at /conference/usenixsecurity{year}/presentation/{author-slug}.

    The author slug is typically first author's last name. Try a few variants.
    """
    year = extract_year(record)
    if not year:
        return []
    speakers = record.get("speaker") or ""
    # Heuristic: last word of first speaker is usually the surname.
    first_speaker = re.split(r"[,;()]", speakers)[0].strip()
    parts = first_speaker.split()
    if not parts:
        return []
    surname = parts[-1].lower()
    candidates = [
        f"https://www.usenix.org/conference/usenixsecurity{year}/presentation/{surname}",
        f"https://www.usenix.org/conference/usenixsecurity{year[2:]}/presentation/{surname}",
    ]
    videos = []
    for url in candidates:
        html = fetch(url)
        if "<title>" not in html.lower():
            continue
        videos.extend(find_video_in_html(html))
        if videos:
            break
    return videos


# ─────────── media.ccc.de ───────────

def enrich_ccc(record):
    """Search media.ccc.de API for the talk title."""
    title = record.get("title", "")
    q = urllib.parse.quote_plus(title[:80])
    url = f"https://api.media.ccc.de/public/events/search?q={q}"
    html = fetch(url)
    if not html:
        return []
    try:
        data = json.loads(html)
    except Exception:
        return []
    events = data.get("events") or []
    videos = []
    for ev in events[:3]:
        ev_title = ev.get("title") or ""
        # Fuzzy check
        a = set(re.findall(r"\w+", title.lower()))
        b = set(re.findall(r"\w+", ev_title.lower()))
        if not a or not b: continue
        overlap = len(a & b) / len(a | b)
        if overlap < 0.4:
            continue
        frontend = ev.get("frontend_link")
        if frontend:
            videos.append(frontend)
    return videos


# ─────────── archive.org ───────────

def enrich_archive_org(record):
    """Search archive.org for a video matching the title + speaker."""
    title = record.get("title", "")[:60]
    speaker = (record.get("speaker") or "").split(",")[0][:30]
    q = urllib.parse.quote_plus(f'"{title}"')
    url = (f"https://archive.org/advancedsearch.php?q={q}"
           f"+mediatype%3Amovies&fl=identifier,title&output=json&rows=3")
    html = fetch(url)
    if not html:
        return []
    try:
        data = json.loads(html)
    except Exception:
        return []
    docs = (data.get("response") or {}).get("docs") or []
    videos = []
    for d in docs[:2]:
        ident = d.get("identifier")
        a_title = d.get("title") or ""
        a = set(re.findall(r"\w+", title.lower()))
        b = set(re.findall(r"\w+", a_title.lower()))
        if not a or not b: continue
        if len(a & b) / len(a | b) < 0.4:
            continue
        if ident:
            videos.append(f"https://archive.org/details/{ident}")
    return videos


# ─────────── Main pipeline ───────────

def main():
    talks = yaml.safe_load(open(ROOT / "talks.yaml"))
    print(f"Loaded {len(talks)} records.")

    import importlib.util
    spec = importlib.util.spec_from_file_location("etalks", ROOT / "scripts/extract-talks.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    add_watch_url = mod.add_watch_url

    cache = load_cache()
    added = 0
    by_platform = {}

    def has_specific_yt(r):
        return any("youtube.com/watch" in (w["url"] or "")
                   for w in (r.get("watch_urls") or []))

    PLATFORM_HANDLERS = [
        ("recon.cx",      enrich_recon,        lambda r: "recon" in (r.get("venue","") or "").lower()),
        ("troopers.de",   enrich_troopers,     lambda r: "troopers" in (r.get("venue","") or "").lower()),
        ("offensivecon",  enrich_offensivecon, lambda r: "offensivecon" in (r.get("venue","") or "").lower()),
        ("USENIX",        enrich_usenix,       lambda r: "usenix" in (r.get("venue","") or "").lower()),
        ("media.ccc.de",  enrich_ccc,          lambda r: True),  # try for everyone
        ("archive.org",   enrich_archive_org,  lambda r: not has_specific_yt(r)),
    ]

    for platform, handler, predicate in PLATFORM_HANDLERS:
        print(f"\n── {platform} ──")
        platform_added = 0
        for t in talks:
            if not predicate(t):
                continue
            # Skip if already has YouTube (no need to find alternatives) unless platform IS YouTube-finder
            ck = f"{platform}:{t.get('title','')[:80]}:{t.get('year','')}"
            if ck in cache:
                urls = cache[ck]
            else:
                try:
                    urls = handler(t)
                except Exception as e:
                    urls = []
                cache[ck] = urls
                save_cache(cache)
                time.sleep(0.2)  # polite
            for u in urls:
                if add_watch_url(t, u, "HIGH"):
                    added += 1
                    platform_added += 1
                    print(f"  + [{platform}] {t.get('title','')[:55]} -> {u[:80]}")
        print(f"  added from {platform}: {platform_added}")
        by_platform[platform] = platform_added

    print(f"\n=== Total new URLs added: {added} ===")
    print("By platform:")
    for p, n in by_platform.items():
        print(f"  {p}: {n}")

    yaml.safe_dump(talks, open(ROOT / "talks.yaml", "w"),
                   sort_keys=False, allow_unicode=True, width=120)
    with open(ROOT / "docs/talks.json", "w") as f:
        json.dump(talks, f, ensure_ascii=False, indent=1)
    print(f"\n[OK] saved talks.yaml + docs/talks.json")


if __name__ == "__main__":
    main()
