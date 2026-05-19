#!/usr/bin/env python3
"""Robust YouTube enrichment.

Two strategies running together:

  1. **Bulk playlist scrape** — for each conference YouTube playlist we know
     about, fetch the playlist HTML once and harvest every `(videoId, title)`
     pair. Match talks against the playlist by fuzzy title-key. One playlist
     scrape covers ~100 videos in one request.

  2. **Per-talk search** — for talks that still have no YouTube URL after the
     playlist pass, query `youtube.com/results?search_query=...`. The first
     few `videoRenderer` blocks from the initial HTML are the search results;
     oEmbed-validate each before accepting.

Robustness:
  * Every candidate match is validated via the YouTube oEmbed API
    (`youtube.com/oembed?url=...`). Only HTTP 200 responses count.
  * Cross-checks: video title vs talk title must share enough word-set
    overlap (Jaccard >= 0.5 OR title-key substring containment).
  * Skip records that already have a verified YouTube watch_url.
  * Cache results in scripts/.yt-search-cache.json so re-runs do not
    re-query YouTube.
  * Polite delay between search queries.

Usage:
    python3 scripts/youtube-enrich.py [--limit N]
"""

import json
import re
import subprocess
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

ROOT = Path.home() / "repos/windows-security-talks"
CACHE_FILE = ROOT / "scripts/.yt-search-cache.json"

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/120.0.0.0 Safari/537.36")

# Known conference YouTube playlists — one scrape gets us every video on the playlist.
# Add new ones here as they're identified.
PLAYLISTS = {
    "BH-USA-2024":   "PLH15HpR5qRsUkDM0oIZInQ--Wv3K8I6af",   # actually all years; will filter by title
    "BH-USA-2025":   "PLH15HpR5qRsWoBx8EMeECDfVYWrsEdy7E",
    "DC32":          "PL9fPq3eQfaaA8R-zsvFEDgvxJtP0WX1bC",
    "DC33":          "PL9fPq3eQfaaBB9HANwjaTlICFuVhRxkdz2",
}

# Channels to try as additional playlist sources (uploads playlist UU... = channelId with C->U).
CHANNELS = {
    "Black Hat":         "UCJ6q9Ie29ajGqKApbLqfBOg",
    "DEF CON":           "UC6Om9kAkl32dWlDSNlDS9Iw",
    "BlueHat (MSRC)":    "UCBaP6X3IzqgnmlAJ4sQ16TQ",
    "OffensiveCon":      "UC5JhqlA5MIZIcfywAY4_huQ",
    "TROOPERS":          "UCmeBjjsjyfPjGc0rJfMcptg",
}


def fetch(url, timeout=20):
    out = subprocess.run(
        ["curl", "-s", "-A", UA, "-L", "--max-time", str(timeout), url],
        capture_output=True, text=True, timeout=timeout + 5,
    )
    return out.stdout if out.returncode == 0 else ""


def http_status(url, timeout=12):
    out = subprocess.run(
        ["curl", "-sI", "-o", "/dev/null", "-w", "%{http_code}",
         "-A", UA, "-L", "--max-time", str(timeout), url],
        capture_output=True, text=True, timeout=timeout + 5,
    )
    try:
        return int(out.stdout.strip() or 0)
    except ValueError:
        return 0


# ─────────── Title normalization & similarity ───────────

NOISE_TOKENS = {
    "def", "con", "defcon", "dc32", "dc33", "dc", "black", "hat", "blackhat",
    "usa", "talk", "presentation", "the", "a", "an", "of", "in", "and", "or",
    "for", "to", "from", "with", "by", "on", "at", "vs", "your", "windows",
    "is", "are", "was", "were", "be", "this", "that", "into", "out", "we",
    "us", "their", "you", "i", "but", "as", "via",
    "bluehat", "troopers", "offensivecon", "recon",
}


def words(text):
    return [w for w in re.findall(r"[A-Za-z0-9]+", (text or "").lower())]


def content_words(text):
    return set(w for w in words(text) if w not in NOISE_TOKENS and len(w) >= 3)


def jaccard(a, b):
    sa = content_words(a)
    sb = content_words(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def first_n_content_words(text, n=3):
    return [w for w in words(text) if w not in NOISE_TOKENS and len(w) >= 3][:n]


def title_match(talk_title, video_title, min_jaccard=0.5, speakers=None):
    """Return (match: bool, score: float).

    Match strategies (any of these wins):
      1. Direct substring of the first 30+ normalized chars in either
         direction — BUT only when the shorter side is at least 25 chars
         (otherwise a generic short video title trivially matches as a
         prefix of any longer talk title).
      2. The first 3 content words of the talk title all appear in the
         video title (truncation-tolerant — covers "Conference - Speaker
         - Truncated Title" YouTube titles). Requires speaker presence
         to avoid matching unrelated videos that happen to share the same
         leading words.
      3. Jaccard >= min_jaccard.
      4. Speaker name appears AND Jaccard >= 0.3.
    """
    j = jaccard(talk_title, video_title)
    ka = re.sub(r"[^a-z0-9]", "", (talk_title or "").lower())
    kb = re.sub(r"[^a-z0-9]", "", (video_title or "").lower())
    speaker_words = []
    if speakers:
        for sp in (speakers if isinstance(speakers, list) else [speakers]):
            for word in re.findall(r"\w+", (sp or "").lower()):
                if len(word) > 4:
                    speaker_words.append(word)
    vt_lower = (video_title or "").lower()
    has_speaker = any(w in vt_lower for w in speaker_words) if speaker_words else False

    # 1. Substring containment — both sides must be long enough that the
    #    overlap is meaningful (>=25 normalized chars on each side).
    if ka and kb and min(len(ka), len(kb)) >= 25 and (ka[:30] in kb or kb[:30] in ka):
        return (True, max(0.85, j))

    # 2. First few content words all present — but require speaker word
    #    presence to avoid generic-title false positives.
    head = first_n_content_words(talk_title, 3)
    if len(head) >= 2 and all(w in vt_lower for w in head):
        if has_speaker or j >= 0.5:
            return (True, max(0.75, j))

    # 3. Plain Jaccard threshold.
    if j >= min_jaccard:
        return (True, j)

    # 4. Speaker present + lower Jaccard.
    if has_speaker and j >= 0.3:
        return (True, max(0.6, j))

    return (False, j)


# ─────────── Playlist scrape ───────────

VIDEO_TITLE_RE = re.compile(
    r'"videoRenderer":\{"videoId":"([\w-]{11})".*?"title":\{"runs":\[\{"text":"([^"]+)"',
    re.DOTALL,
)
# Playlist items use a different shape.
PLAYLIST_ITEM_RE = re.compile(
    r'"playlistVideoRenderer":\{"videoId":"([\w-]{11})".*?"title":\{"runs":\[\{"text":"([^"]+)"',
    re.DOTALL,
)


def scrape_playlist(list_id):
    """Fetch a YouTube playlist HTML and return list of (videoId, title)."""
    url = f"https://www.youtube.com/playlist?list={list_id}"
    html = fetch(url)
    if not html:
        return []
    results = PLAYLIST_ITEM_RE.findall(html)
    if not results:
        results = VIDEO_TITLE_RE.findall(html)
    # Deduplicate by videoId
    seen = {}
    for vid, title in results:
        seen.setdefault(vid, title)
    return list(seen.items())


def scrape_channel_uploads(channel_id, max_results=200):
    """Fetch the channel /videos page; pulls the most-recent N videos."""
    url = f"https://www.youtube.com/channel/{channel_id}/videos"
    html = fetch(url)
    if not html:
        return []
    results = VIDEO_TITLE_RE.findall(html)
    seen = {}
    for vid, title in results[:max_results]:
        seen.setdefault(vid, title)
    return list(seen.items())


# ─────────── Per-talk search ───────────

def youtube_search(query, max_results=5):
    """Return list of (videoId, title) for the first N search results."""
    q = urllib.parse.quote_plus(query)
    url = f"https://www.youtube.com/results?search_query={q}"
    html = fetch(url)
    if not html:
        return []
    results = VIDEO_TITLE_RE.findall(html)
    seen = []
    seen_ids = set()
    for vid, title in results:
        if vid in seen_ids:
            continue
        seen_ids.add(vid)
        seen.append((vid, title))
        if len(seen) >= max_results:
            break
    return seen


def oembed_verify(video_id):
    """Confirm the video is public via the YouTube oEmbed API. Returns the
    canonical title from oEmbed (which we trust more than the search result
    title) or None if the video is private/removed/region-locked.
    """
    oembed = (f"https://www.youtube.com/oembed?url="
              f"https://www.youtube.com/watch?v={video_id}&format=json")
    out = subprocess.run(
        ["curl", "-s", "-A", UA, "--max-time", "10",
         "-w", "\n%{http_code}", oembed],
        capture_output=True, text=True, timeout=15,
    )
    parts = out.stdout.rsplit("\n", 1)
    if len(parts) != 2:
        return None
    body, code = parts[0], parts[1].strip()
    if code != "200":
        return None
    try:
        data = json.loads(body)
        return data.get("title")
    except Exception:
        return None


# ─────────── Cache ───────────

def load_cache():
    if CACHE_FILE.exists():
        try: return json.load(open(CACHE_FILE))
        except Exception: return {}
    return {}


def save_cache(cache):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    json.dump(cache, open(CACHE_FILE, "w"), indent=1)


# ─────────── Main pipeline ───────────

def already_has_youtube(record):
    for w in (record.get("watch_urls") or []):
        if "youtube.com/watch" in w["url"] or "youtu.be/" in w["url"]:
            return True
    return False


def maybe_add_youtube(record, video_id, score, add_watch_url):
    """Add a verified YouTube URL to the record."""
    url = f"https://www.youtube.com/watch?v={video_id}"
    return add_watch_url(record, url, "VERIFIED")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit to N per-talk searches (0 = all)")
    parser.add_argument("--no-search", action="store_true",
                        help="Skip per-talk search; only do bulk playlist matching")
    args = parser.parse_args()

    talks = yaml.safe_load(open(ROOT / "talks.yaml"))
    print(f"Loaded {len(talks)} records.")

    import importlib.util
    spec = importlib.util.spec_from_file_location("etalks", ROOT / "scripts/extract-talks.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    add_watch_url = mod.add_watch_url

    cache = load_cache()
    print(f"Cache: {len(cache)} entries.")

    # ─── Phase 1: Bulk playlist scrape ───
    print("\n=== Phase 1: bulk playlist scrape ===")
    all_playlist_videos = []  # list of (videoId, video_title, source_label)
    for label, plist_id in PLAYLISTS.items():
        key = f"playlist:{plist_id}"
        if key in cache:
            videos = cache[key]
        else:
            videos = scrape_playlist(plist_id)
            cache[key] = videos
            save_cache(cache)
        print(f"  {label} ({plist_id}): {len(videos)} videos")
        for vid, title in videos:
            all_playlist_videos.append((vid, title, label))

    for label, ch_id in CHANNELS.items():
        key = f"channel:{ch_id}"
        if key in cache:
            videos = cache[key]
        else:
            videos = scrape_channel_uploads(ch_id, max_results=200)
            cache[key] = videos
            save_cache(cache)
        print(f"  {label} channel: {len(videos)} videos")
        for vid, title in videos:
            all_playlist_videos.append((vid, title, f"{label} channel"))

    print(f"  Total candidate playlist/channel videos: {len(all_playlist_videos)}")

    # Match talks against playlist videos.
    pl_matched = 0
    for t in talks:
        if already_has_youtube(t):
            continue
        best = None  # (score, vid, video_title)
        for vid, vtitle, _ in all_playlist_videos:
            ok, score = title_match(t.get("title", ""), vtitle)
            if ok and (best is None or score > best[0]):
                best = (score, vid, vtitle)
        if best:
            # oEmbed-verify before accepting.
            ekey = f"oembed:{best[1]}"
            if ekey not in cache:
                cache[ekey] = oembed_verify(best[1])
                save_cache(cache)
            oembed_title = cache[ekey]
            if oembed_title is None:
                continue
            # Double-check title match using the oEmbed-canonical title.
            ok2, _ = title_match(t.get("title", ""), oembed_title)
            if not ok2:
                continue
            if maybe_add_youtube(t, best[1], best[0], add_watch_url):
                pl_matched += 1
                print(f"  +playlist [{best[0]:.2f}] {t.get('title','')[:55]} -> {best[1]}")
    print(f"\n  Playlist matches added: {pl_matched}")

    # ─── Phase 2: Per-talk search for the remainder ───
    if not args.no_search:
        print("\n=== Phase 2: per-talk YouTube search (multi-query) ===")
        # Skip records that don't have actual talks (Pwn2Own competition results,
        # blog-only foundational items where the "talk" is just a blog post).
        SKIP_VENUES = ("pwn2own",)
        candidates = []
        for t in talks:
            if already_has_youtube(t):
                continue
            if not t.get("title"):
                continue
            venue = (t.get("venue") or "").lower()
            if any(s in venue for s in SKIP_VENUES):
                continue
            candidates.append(t)
        if args.limit:
            candidates = candidates[: args.limit]
        print(f"  Candidates needing search: {len(candidates)}")

        def build_queries(t):
            """Try several query shapes — short/long, with/without speaker, etc."""
            title = t.get("title", "")
            venue = (t.get("venue") or "").split("/")[0].strip()
            speakers = re.split(r"[,;]", t.get("speaker") or "")
            first_speaker = re.sub(r"\([^)]*\)", "", speakers[0]).strip() if speakers else ""
            # Title segments (often only the part before the colon survives on YouTube)
            short_title = re.split(r"[:\u2014\u2013\-]", title)[0].strip()
            queries = []
            if title:
                queries.append(f'"{title}"' + (f" {venue}" if venue else ""))
            if short_title and short_title != title:
                queries.append(f'"{short_title}" {first_speaker}'.strip())
            if first_speaker and venue:
                queries.append(f'{first_speaker} {venue} {short_title or title}'.strip())
            if venue:
                queries.append(f'{venue} {short_title or title}'.strip())
            # Dedupe preserving order, drop empties
            seen = set()
            out = []
            for q in queries:
                q = q.strip()
                if q and q not in seen:
                    seen.add(q)
                    out.append(q)
            return out

        search_matched = 0
        for i, t in enumerate(candidates, 1):
            title = t.get("title", "")
            speakers = re.split(r"[,;]", t.get("speaker") or "")
            # Try each query shape; first acceptable match wins.
            best_overall = None
            for query in build_queries(t):
                cache_key = f"search:{query}"
                if cache_key in cache:
                    results = cache[cache_key]
                else:
                    results = youtube_search(query, max_results=5)
                    cache[cache_key] = results
                    save_cache(cache)
                    time.sleep(0.3)
                for vid, vtitle in results:
                    ok, score = title_match(title, vtitle, speakers=speakers)
                    if ok and (best_overall is None or score > best_overall[0]):
                        best_overall = (score, vid, vtitle)
                if best_overall and best_overall[0] >= 0.7:
                    break  # confident enough — stop searching

            if not best_overall:
                continue
            score, vid, vtitle = best_overall

            ekey = f"oembed:{vid}"
            if ekey not in cache:
                cache[ekey] = oembed_verify(vid)
                save_cache(cache)
            oembed_title = cache[ekey]
            if oembed_title is None:
                continue
            ok2, _ = title_match(title, oembed_title, speakers=speakers)
            if not ok2:
                continue

            # Higher-confidence gate: when score is in the 0.6-0.8 range, also
            # require at least one speaker word to appear in the video title.
            # This kills generic "Windows X Y Z" / explainer false-positives.
            if score < 0.8 and speakers:
                speaker_words = [w.lower() for sp in speakers
                                 for w in re.findall(r"\w+", sp or "")
                                 if len(w) > 4]
                vt_lower = (oembed_title or "").lower()
                if speaker_words and not any(w in vt_lower for w in speaker_words):
                    print(f"  -reject   [{score:.2f}] {title[:55]} -> {vid}  ({oembed_title[:45]}) [no speaker match]")
                    continue

            if maybe_add_youtube(t, vid, score, add_watch_url):
                search_matched += 1
                print(f"  +search   [{score:.2f}] {title[:55]} -> {vid}  ({oembed_title[:55]})")

            if i % 25 == 0:
                print(f"  ... {i}/{len(candidates)}, matched {search_matched} so far")

        print(f"\n  Search matches added: {search_matched}")

    save_cache(cache)

    # ─── Save ───
    yaml.safe_dump(talks, open(ROOT / "talks.yaml", "w"),
                   sort_keys=False, allow_unicode=True, width=120)
    with open(ROOT / "docs/talks.json", "w") as f:
        json.dump(talks, f, ensure_ascii=False, indent=1)

    # Stats
    yt = sum(1 for t in talks if any("youtube.com/watch" in (w["url"] or "")
             for w in (t.get("watch_urls") or [])))
    total_links = sum(len(t.get("watch_urls") or []) for t in talks)
    with_any = sum(1 for t in talks if t.get("watch_urls"))
    print(f"\nFinal state:")
    print(f"  records: {len(talks)}")
    print(f"  with YouTube embed: {yt}")
    print(f"  with any watch URL: {with_any}")
    print(f"  total watch links: {total_links}")


if __name__ == "__main__":
    main()
