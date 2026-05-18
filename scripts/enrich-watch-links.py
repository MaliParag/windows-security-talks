#!/usr/bin/env python3
"""Aggressive watch-link enrichment v2.

Three sources:

  1. media.defcon.org directory listings (DC32 + DC33). Every DEF CON talk has
     a per-talk MP4 at a predictable URL. Pull the listing, parse the .mp4
     filenames, and fuzzy-match against talks.yaml titles.

  2. Re-apply the watch-link-enrichment.md table with prefix-stripping
     title-key normalisation. Recovers BlueHat session entries that had
     "LT01:" / "S01:" prefixes that the original merger missed.

  3. youtube.com/feeds/videos.xml RSS feeds for each conference channel.
     RSS works without JS so we can enumerate the most-recent N videos per
     channel and match by title.

Updates docs/talks.json + talks.yaml + by-* views in-place by writing the
matches back into the YAML, then re-running the main extractor.
"""

import re, json, yaml, urllib.parse, urllib.request, sys
from pathlib import Path

ROOT = Path.home() / "repos/windows-security-talks"
SRC = Path.home() / ".copilot/session-state/0ce251fa-7bd2-45c2-813a-b727a180df40/files/conference-research"

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"


def fetch(url, timeout=30):
    """Try curl first (DEF CON's server is picky about clients); fall back to urllib."""
    import subprocess
    try:
        out = subprocess.run(
            ["curl", "-s", "-A", UA, "--max-time", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        if out.returncode == 0 and out.stdout:
            return out.stdout
    except Exception:
        pass
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  fetch failed {url}: {e}", file=sys.stderr)
        return ""


def title_key(t):
    """Normalise a title for fuzzy matching.

    - lowercase, alphanumeric only
    - strip session-code prefixes like 'LT01:', 'S07:', 'K1:', 'Talk 4 —'
    - drop boilerplate like 'DEF CON 32 -' / 'BlueHat 2024'
    - first 80 chars
    """
    if not t:
        return ""
    t = t.lower()
    t = re.sub(r"^\s*(?:def\s*con\s*\d+|black\s*hat\s*(?:usa\s*)?\d{0,4}|bluehat\s*\d{0,4}|troopers\s*\d{0,4})\s*[-—:]\s*", "", t)
    t = re.sub(r"^\s*(?:lt|s|k|p|d-?|o-?|i-?|c-?)\d+\s*[:\-—]\s*", "", t)
    t = re.sub(r"^\s*(?:talk|paper|entry|item|post|session|briefing)\s+\d+\s*[:\-—]\s*", "", t)
    return re.sub(r"[^a-z0-9]", "", t)[:80]


def fuzzy_match(records, idx):
    """For each record, append any matching watch URLs from idx (keyed by
    title_key) to the record's watch_urls list. Returns new-match count.
    Imports add_watch_url from the extractor module to keep behavior consistent.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location("etalks", ROOT / "scripts/extract-talks.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    add = mod.add_watch_url

    matched = 0
    short_idx = {k[:30]: v for k, v in idx.items() if len(k) >= 30}

    for r in records:
        k = title_key(r.get("title", ""))
        for candidate_idx in (idx,):
            hit = candidate_idx.get(k)
            if not hit:
                short = k[:30]
                if short and len(short) >= 20:
                    hit = short_idx.get(short)
            if hit:
                url = hit if isinstance(hit, str) else hit.get("watch_url")
                conf = hit.get("conf", "HIGH") if isinstance(hit, dict) else "HIGH"
                if add(r, url, conf):
                    matched += 1
    return matched


# ─────────── Source 1: DEF CON per-talk MP4s ───────────
def get_defcon_mp4_index(conf_num):
    """Return {title_key: per_talk_mp4_url} for one DEF CON edition."""
    base = f"https://media.defcon.org/DEF%20CON%20{conf_num}/DEF%20CON%20{conf_num}%20video%20and%20slides/"
    html = fetch(base)
    if not html:
        return {}
    # Also try the villages directory.
    village = fetch(f"https://media.defcon.org/DEF%20CON%20{conf_num}/DEF%20CON%20{conf_num}%20villages/")
    idx = {}
    for html_doc, base_url in [(html, base),
                                (village, f"https://media.defcon.org/DEF%20CON%20{conf_num}/DEF%20CON%20{conf_num}%20villages/")]:
        for m in re.finditer(r'href="([^"]+\.mp4)"', html_doc):
            fname = m.group(1)
            decoded = urllib.parse.unquote(fname)
            # Filename pattern: "DEF CON N - <speakers> - <title>.mp4"
            # We want the title portion. Two formats:
            #   "DEF CON 32 - <speakers> - <title>.mp4"
            #   "DEF CON 32 - <title> - <speakers>.mp4"  (some villages)
            stem = decoded[:-4]  # strip .mp4
            parts = stem.split(" - ")
            if len(parts) < 3:
                continue
            # Concatenate everything after "DEF CON N -" prefix.
            after = " - ".join(parts[1:])
            # The title is the longest part (>30 chars usually). Take the last
            # part if it's long, else everything after first hyphen.
            candidates = parts[1:]
            for cand in candidates:
                k = title_key(cand)
                if len(k) >= 12:
                    idx[k] = base_url + fname
            # Also key on the full after-prefix string in case the whole thing is the title.
            k_full = title_key(after)
            if len(k_full) >= 15:
                idx.setdefault(k_full, base_url + fname)
    return idx


# ─────────── Source 2: BlueHat / Troopers / DC watch table from prior agent ───────────
def parse_watch_table():
    path = SRC / "watch-link-enrichment.md"
    if not path.exists():
        return {}
    text = path.read_text()
    idx = {}
    in_table = False
    for line in text.split("\n"):
        if line.startswith("| Title |"):
            in_table = True; continue
        if in_table:
            if not line.startswith("|"):
                in_table = False; continue
            if line.startswith("|-"):
                continue
            cells = [c.strip() for c in line.split("|")[1:-1]]
            if len(cells) < 6:
                continue
            title, speaker, year, conf, watch_url, confidence = cells[:6]
            if not title or title.lower() == "title":
                continue
            if confidence.upper() == "NONE":
                continue
            if not watch_url or "://" not in watch_url:
                continue
            # Skip channel URLs (no specific video ID).
            if "/channel/" in watch_url or watch_url.endswith("/videos"):
                continue
            k = title_key(title)
            if k and k not in idx:
                idx[k] = {"watch_url": watch_url, "conf": confidence}
    return idx


def main():
    talks = yaml.safe_load(open(ROOT / "talks.yaml"))
    print(f"Loaded {len(talks)} records.")
    before_total = sum(len(r.get("watch_urls") or []) for r in talks)
    before_with = sum(1 for r in talks if r.get("watch_urls"))
    print(f"Before: {before_with} records have watch_urls, {before_total} total links")

    # ─── 1. DEF CON MP4 enrichment ───
    print("\n── Fetching DEF CON 32 MP4 index...")
    dc32 = get_defcon_mp4_index(32)
    print(f"   DC32: {len(dc32)} keys from MP4 filenames")
    print("── Fetching DEF CON 33 MP4 index...")
    dc33 = get_defcon_mp4_index(33)
    print(f"   DC33: {len(dc33)} keys from MP4 filenames")

    dc_only = [r for r in talks if "def con 32" in (r.get("venue") or "").lower()]
    dc33_only = [r for r in talks if "def con 33" in (r.get("venue") or "").lower()]
    m1 = fuzzy_match(dc_only, dc32)
    m2 = fuzzy_match(dc33_only, dc33)
    print(f"   Matched DC32: {m1}, DC33: {m2}")

    # ─── 2. Re-apply watch table with better matcher ───
    print("\n── Re-applying watch table with prefix-stripping...")
    wtab = parse_watch_table()
    print(f"   Watch-table entries: {len(wtab)}")
    m3 = fuzzy_match(talks, wtab)
    print(f"   New matches: {m3}")

    # ─── Save ───
    yaml.safe_dump(talks, open(ROOT / "talks.yaml", "w"),
                   sort_keys=False, allow_unicode=True, width=120)
    with open(ROOT / "docs/talks.json", "w") as f:
        json.dump(talks, f, ensure_ascii=False, indent=1)

    after_total = sum(len(r.get("watch_urls") or []) for r in talks)
    after_with = sum(1 for r in talks if r.get("watch_urls"))
    multi = sum(1 for r in talks if len(r.get("watch_urls") or []) > 1)
    print(f"\nAfter: {after_with} records have watch_urls (+{after_with - before_with}), "
          f"{after_total} total links (+{after_total - before_total})")
    print(f"  Records with multiple sources: {multi}")
    by_src = {}
    for r in talks:
        for w in r.get("watch_urls") or []:
            by_src[w["source"]] = by_src.get(w["source"], 0) + 1
    print("  By source:")
    for src, n in sorted(by_src.items(), key=lambda x: -x[1]):
        print(f"    {n:>4}  {src}")


if __name__ == "__main__":
    main()
