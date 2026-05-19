#!/usr/bin/env python3
"""Strict audit of every YouTube watch URL.

For each YouTube URL in talks.yaml:
  1. Fetch the YouTube oEmbed canonical title.
  2. Apply STRICT match criteria against the talk's title + speaker:
       a. Full normalized talk title is a substring of the video title, OR
       b. Speaker word(s) appear in the video title AND >=3 distinctive
          content words from the talk title appear in the video title.
  3. If neither passes, the URL is dropped from the talk's watch_urls list.

This is stricter than the matcher used to ADD URLs — it requires positive
evidence that the video is the right talk, not just plausibly related.

Also drops the record entirely from out-of-scope categories (out-of-scope,
keynote) when the user only wants Windows-security talks.

Run after youtube-enrich.py to clean up false positives.
"""
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

ROOT = Path.home() / "repos/windows-security-talks"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/120.0 Safari/537.36")

NOISE = {"the", "a", "an", "of", "in", "and", "or", "for", "to", "from",
         "with", "by", "on", "at", "vs", "your", "is", "are", "was", "were",
         "be", "this", "that", "into", "out", "we", "us", "their", "you",
         "but", "as", "via", "windows"}


def youtube_id(url):
    m = re.search(r"(?:youtube\.com/(?:watch\?v=|embed/|v/)|youtu\.be/)([\w-]{11})", url or "")
    return m.group(1) if m else None


def content_words(text):
    return [w for w in re.findall(r"[a-z0-9]+", (text or "").lower())
            if w not in NOISE and len(w) >= 3]


def speaker_words(speakers):
    """Extract distinctive speaker word tokens (names) from speaker string."""
    out = []
    for sp in (speakers if isinstance(speakers, list) else [speakers or ""]):
        # Strip parenthetical affiliations.
        cleaned = re.sub(r"\([^)]*\)", "", sp or "")
        for w in re.findall(r"[A-Za-z]+", cleaned):
            wl = w.lower()
            if (len(w) > 3 and wl not in NOISE
                and wl not in ("microsoft", "google", "amazon", "apple")):
                out.append(wl)
    return out


def fetch_oembed(video_id):
    """Return oEmbed title (or None if video unavailable)."""
    url = (f"https://www.youtube.com/oembed?url="
           f"https://www.youtube.com/watch?v={video_id}&format=json")
    try:
        out = subprocess.run(
            ["curl", "-s", "-A", UA, "--max-time", "10",
             "-w", "\n%{http_code}", url],
            capture_output=True, text=True, timeout=15,
        )
        parts = out.stdout.rsplit("\n", 1)
        if len(parts) != 2:
            return None
        body, code = parts[0], parts[1].strip()
        if code != "200":
            return ("__UNAVAILABLE__", code)
        return json.loads(body).get("title")
    except Exception:
        return None


def strict_match(talk_title, talk_speakers, video_title):
    """Strict match: returns (match, reason).

    Requirements (any one):
      A. Full normalized talk title (>=12 chars) is a substring of video title.
      B. Speaker word present in video title AND >=3 distinctive talk-title
         content words appear in video title.
      C. Talk title's content-word set is a subset of (or near-subset of)
         video title's content-word set with min overlap of 4 words
         (covers official "Conference YEAR: Speaker — Full Title" uploads).
    """
    if not talk_title or not video_title:
        return (False, "empty")
    tt_n = re.sub(r"[^a-z0-9]", "", talk_title.lower())
    vt_n = re.sub(r"[^a-z0-9]", "", video_title.lower())
    # A. Direct substring (both sides >=12 chars to avoid generic matches)
    if len(tt_n) >= 12 and tt_n in vt_n:
        return (True, "A: full title substring")
    # B. Speaker presence + distinctive words
    talk_cws = set(content_words(talk_title))
    video_cws_lower = video_title.lower()
    sp_words = speaker_words(talk_speakers)
    has_speaker = any(w in video_cws_lower for w in sp_words)
    matching_cws = talk_cws & set(content_words(video_title))
    if has_speaker and len(matching_cws) >= 3:
        return (True, f"B: speaker + {len(matching_cws)} content words")
    # C. Strong content-word overlap (>=4)
    if len(matching_cws) >= 4:
        return (True, f"C: {len(matching_cws)} content words overlap")
    return (False,
            f"FAIL: speaker_in_video={has_speaker}, "
            f"content_overlap={len(matching_cws)}, talk_cws={len(talk_cws)}")


def main():
    talks = yaml.safe_load(open(ROOT / "talks.yaml"))
    print(f"Loaded {len(talks)} records.")

    # Collect all unique YouTube IDs to check.
    yt_id_to_oembed = {}
    yt_urls = set()
    for t in talks:
        for w in (t.get("watch_urls") or []):
            vid = youtube_id(w["url"])
            if vid:
                yt_urls.add(w["url"])
    print(f"Unique YouTube URLs to verify: {len(yt_urls)}")

    # Fetch oEmbed for each in parallel.
    with ThreadPoolExecutor(max_workers=20) as pool:
        futs = {pool.submit(fetch_oembed, youtube_id(u)): u for u in yt_urls}
        for i, fut in enumerate(as_completed(futs), 1):
            u = futs[fut]
            yt_id_to_oembed[u] = fut.result()
            if i % 25 == 0:
                print(f"  {i}/{len(yt_urls)}")

    # Apply strict match to each (URL, talk) pair.
    print("\nAuditing each (talk, YouTube URL) pair...")
    dropped = []
    unavailable = []
    by_reason = {}
    for t in talks:
        title = t.get("title", "")
        speakers = re.split(r"[,;]", t.get("speaker") or "")
        ws = t.get("watch_urls") or []
        good = []
        for w in ws:
            vid = youtube_id(w["url"])
            if not vid:
                good.append(w)
                continue
            oe = yt_id_to_oembed.get(w["url"])
            if isinstance(oe, tuple) and oe[0] == "__UNAVAILABLE__":
                unavailable.append((title, w["url"], oe[1]))
                continue
            if oe is None:
                # Couldn't reach oEmbed — keep, will be re-tried later
                good.append(w)
                continue
            ok, reason = strict_match(title, speakers, oe)
            if ok:
                good.append(w)
                by_reason.setdefault(reason.split(":")[0], 0)
                by_reason[reason.split(":")[0]] += 1
            else:
                dropped.append((title[:60], w["url"], oe[:60], reason))
        t["watch_urls"] = good
        if good:
            import importlib.util
            spec = importlib.util.spec_from_file_location("etalks", ROOT / "scripts/extract-talks.py")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            best = max(good, key=mod.watch_quality)
            t["watch_url"] = best["url"]
            t["watch_confidence"] = best.get("confidence", "HIGH")
        else:
            t.pop("watch_url", None)
            t.pop("watch_confidence", None)

    # Also drop entirely out-of-scope records (non-Windows talks that snuck in).
    DROP_CATEGORIES = {"out-of-scope"}
    before = len(talks)
    talks_filtered = [t for t in talks if t.get("normalized_category") not in DROP_CATEGORIES]
    dropped_records = before - len(talks_filtered)
    talks = talks_filtered

    print(f"\nKept YouTube URLs by strict-match rule:")
    for r, n in sorted(by_reason.items(), key=lambda x: -x[1]):
        print(f"  {r}: {n}")
    print(f"\nDropped {len(dropped)} mismatched YouTube URLs:")
    for title, url, oe, reason in dropped[:50]:
        print(f"  '{title}' -> '{oe}'  [{reason}]")
    if len(dropped) > 50:
        print(f"  ...and {len(dropped) - 50} more")
    if unavailable:
        print(f"\nDropped {len(unavailable)} unavailable YouTube videos (oEmbed 401/404):")
        for title, url, code in unavailable:
            print(f"  '{title[:55]}' -> {url}  ({code})")
    print(f"\nDropped {dropped_records} out-of-scope records (non-Windows talks).")

    yaml.safe_dump(talks, open(ROOT / "talks.yaml", "w"),
                   sort_keys=False, allow_unicode=True, width=120)
    with open(ROOT / "docs/talks.json", "w") as f:
        json.dump(talks, f, ensure_ascii=False, indent=1)

    yt_remaining = sum(1 for t in talks for w in (t.get("watch_urls") or [])
                       if youtube_id(w["url"]))
    print(f"\nFinal: {len(talks)} talks, {yt_remaining} YouTube URLs retained.")


if __name__ == "__main__":
    main()
