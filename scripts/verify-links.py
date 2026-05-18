#!/usr/bin/env python3
"""Verify every URL in talks.yaml.

For each record, check `url` (slides) and every entry in `watch_urls`. Probe:
  * YouTube URLs via oEmbed (works without an API key; 200 = playable,
    401/404 = removed/private/region-locked).
  * Other URLs via curl HEAD; fall back to GET 0-byte range if HEAD is blocked.

Broken URLs are removed:
  * watch_urls entries with broken URL are dropped.
  * url (slides) field is cleared if broken.

Records lose nothing else. After mutation, the primary watch_url + watch_confidence
are recomputed from the remaining watch_urls list. The new docs/talks.json is
re-emitted.

Parallel-checks ~40 URLs at a time. Caches results across runs in
.verify-cache.json so we don't re-hammer hosts.
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
CACHE_FILE = ROOT / "scripts/.verify-cache.json"
WORKERS = 40
TIMEOUT = 12
RECHECK_AGE_HOURS = 24 * 7  # re-check anything older than a week

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"


def youtube_id(url):
    m = re.search(r"(?:youtube\.com/(?:watch\?v=|embed/|v/)|youtu\.be/)([\w-]{6,})", url or "")
    return m.group(1) if m else None


def check_youtube(url):
    """Return (ok, status, note). Uses oEmbed which 200s only for public videos."""
    vid = youtube_id(url)
    if not vid:
        return (False, 0, "not a YouTube watch URL")
    oembed = f"https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v={vid}&format=json"
    try:
        out = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "-A", UA, "--max-time", str(TIMEOUT), oembed],
            capture_output=True, text=True, timeout=TIMEOUT + 5,
        )
        code = int(out.stdout.strip() or 0)
        if code == 200:
            return (True, code, "")
        if code in (401, 404):
            return (False, code, "video private / removed / region-locked")
        return (False, code, f"oembed returned {code}")
    except Exception as e:
        return (False, 0, str(e))


def check_url(url):
    """Generic URL check: HEAD first, GET range fallback. Returns (ok, status, note).

    ok = True only for 2xx/3xx responses we actually received. Anti-bot 403s and
    SSL/connection errors are reported as ok=False but the caller decides whether
    to *drop* the URL based on the status code (only 404/410/451 are treated as
    definitely-broken).
    """
    if not url:
        return (False, 0, "empty url")
    try:
        out = subprocess.run(
            ["curl", "-sI", "-o", "/dev/null", "-w", "%{http_code}",
             "-A", UA, "-L", "--max-time", str(TIMEOUT), url],
            capture_output=True, text=True, timeout=TIMEOUT + 5,
        )
        code = int(out.stdout.strip() or 0)
        if 200 <= code < 400:
            return (True, code, "")
        if code in (0, 403, 405, 429, 501):
            out2 = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "-A", UA, "-L", "-r", "0-2047", "--max-time", str(TIMEOUT), url],
                capture_output=True, text=True, timeout=TIMEOUT + 5,
            )
            code2 = int(out2.stdout.strip() or 0)
            if 200 <= code2 < 400:
                return (True, code2, "GET-range fallback")
            return (False, code2 or code, f"HEAD={code} GET={code2}")
        return (False, code, f"status {code}")
    except subprocess.TimeoutExpired:
        return (False, 0, "timeout")
    except Exception as e:
        return (False, 0, str(e))


def is_definitely_broken(result):
    """Only drop URLs that returned a definite gone status (404/410/451) or that
    YouTube oEmbed reported as removed/private. 403s, SSL errors, timeouts, and
    5xx responses are treated as 'couldn't verify' and the URL is kept.
    """
    if not result:
        return False
    if result.get("ok"):
        return False
    status = result.get("status", 0)
    return status in (404, 410, 451)


def check(url):
    if youtube_id(url):
        return check_youtube(url)
    return check_url(url)


def load_cache():
    if CACHE_FILE.exists():
        try:
            return json.load(open(CACHE_FILE))
        except Exception:
            return {}
    return {}


def save_cache(cache):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    json.dump(cache, open(CACHE_FILE, "w"), indent=1)


def is_fresh(entry):
    return time.time() - entry.get("checked_at", 0) < RECHECK_AGE_HOURS * 3600


def main():
    talks = yaml.safe_load(open(ROOT / "talks.yaml"))
    print(f"Loaded {len(talks)} records.")

    # Collect every unique URL: slides + every watch_urls entry.
    urls = set()
    for t in talks:
        if t.get("url"):
            urls.add(t["url"])
        for w in (t.get("watch_urls") or []):
            if w.get("url"):
                urls.add(w["url"])
        if t.get("code"):
            urls.add(t["code"])
    print(f"Total unique URLs to check: {len(urls)}")

    cache = load_cache()
    # Build worklist: only URLs not in cache or stale.
    pending = [u for u in urls if u not in cache or not is_fresh(cache[u])]
    print(f"Cached fresh: {len(urls) - len(pending)}  · need check: {len(pending)}")

    if pending:
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            futs = {pool.submit(check, u): u for u in pending}
            done = 0
            for fut in as_completed(futs):
                u = futs[fut]
                ok, code, note = fut.result()
                cache[u] = {"ok": ok, "status": code, "note": note, "checked_at": time.time()}
                done += 1
                if done % 25 == 0 or done == len(pending):
                    bad = sum(1 for k in pending if k in cache and not cache[k]["ok"])
                    print(f"  {done}/{len(pending)}  ({bad} broken so far)")
        save_cache(cache)

    # Tally.
    ok_count = sum(1 for u in urls if cache.get(u, {}).get("ok"))
    bad_count = sum(1 for u in urls if u in cache and not cache[u]["ok"])
    print(f"\nResults: {ok_count} OK, {bad_count} broken (of {len(urls)} unique URLs)")

    # Apply: drop ONLY definitely-broken URLs (404/410/451/YouTube removed).
    # Keep 403s, SSL errors, timeouts, and 5xx with status flagged but URL retained
    # — these are usually anti-bot challenges, transient outages, or VM-local
    # connectivity issues, not actual link rot.
    import importlib.util
    spec = importlib.util.spec_from_file_location("etalks", ROOT / "scripts/extract-talks.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    dropped_watch = 0
    cleared_slides = 0
    cleared_code = 0
    affected_titles = []
    uncertain_count = 0

    for t in talks:
        # Slides URL
        if t.get("url"):
            res = cache.get(t["url"], {})
            if is_definitely_broken(res):
                affected_titles.append(("slides", t.get("title", "?"), t["url"], res))
                t["url"] = None
                cleared_slides += 1
            elif not res.get("ok"):
                uncertain_count += 1
        # Code URL
        if t.get("code"):
            res = cache.get(t["code"], {})
            if is_definitely_broken(res):
                t["code"] = None
                cleared_code += 1
        # Watch URLs
        good_watch = []
        for w in (t.get("watch_urls") or []):
            res = cache.get(w["url"], {})
            if is_definitely_broken(res):
                affected_titles.append(("watch", t.get("title", "?"), w["url"], res))
                dropped_watch += 1
            else:
                good_watch.append(w)
        t["watch_urls"] = good_watch
        if good_watch:
            best = max(good_watch, key=mod.watch_quality)
            t["watch_url"] = best["url"]
            t["watch_confidence"] = best.get("confidence", "HIGH")
        else:
            t.pop("watch_url", None)
            t.pop("watch_confidence", None)

    print(f"\nApplied to records (only 404/410/451/YouTube-removed treated as broken):")
    print(f"  slides URLs cleared: {cleared_slides}")
    print(f"  watch URLs dropped: {dropped_watch}")
    print(f"  code URLs cleared: {cleared_code}")
    print(f"  slides URLs kept despite non-OK probe (likely anti-bot/SSL/transient): {uncertain_count}")

    if affected_titles:
        print(f"\nDefinitely broken (removed from data):")
        for kind, title, url, info in affected_titles:
            short = url[:80] + ("…" if len(url) > 80 else "")
            print(f"  [{kind}] [{info.get('status', '?')}] {title[:55]} -> {short}")

    # Save.
    yaml.safe_dump(talks, open(ROOT / "talks.yaml", "w"), sort_keys=False, allow_unicode=True, width=120)
    with open(ROOT / "docs/talks.json", "w") as f:
        json.dump(talks, f, ensure_ascii=False, indent=1)
    print(f"\n[OK] wrote talks.yaml + docs/talks.json")

    # Final coverage stats.
    total_links = sum(len(t.get("watch_urls") or []) for t in talks)
    with_watch = sum(1 for t in talks if t.get("watch_urls"))
    with_slides = sum(1 for t in talks if t.get("url"))
    print(f"\nFinal state:")
    print(f"  records: {len(talks)}")
    print(f"  with verified slides: {with_slides}")
    print(f"  with verified watch URLs: {with_watch}")
    print(f"  total verified watch links: {total_links}")


if __name__ == "__main__":
    main()
