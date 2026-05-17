#!/usr/bin/env python3
"""Extract structured talk records from the conference-research markdown reports."""
import re, yaml
from pathlib import Path
from collections import defaultdict

SRC = Path.home() / ".copilot/session-state/0ce251fa-7bd2-45c2-813a-b727a180df40/files/conference-research"
DST = Path.home() / "repos/windows-security-talks"

PATTERNS = {
    "title": [r"(?:Title|Exact Title|Talk Title|Post Title)\**\s*[:\u2014\-\|]+\s*\**\s*`?([^\n|*`]+?)`?\s*\**\s*(?:\||$)"],
    "speaker": [r"(?:Speaker|Speaker\(s\)|Author|Researcher)\**\s*[:\u2014\-\|]+\s*\**\s*([^\n|*`]+?)\s*\**\s*(?:\||$)"],
    "year": [r"(?:Year|Date|Conference Year)\**\s*[:\u2014\-\|]+\s*\**\s*(\d{4})"],
    "venue": [r"(?:Conference|Venue|Source|Source Outlet)\**\s*[:\u2014\-\|]+\s*\**\s*([^\n|*`(]+?)(?:\(|\s*\**\s*\||\s*$)"],
    "theme": [r"(?:Theme|One-sentence theme|One-Sentence Theme|Description)\**\s*[:\u2014\-\|]+\s*\**\s*([^\n|*]+?)\s*\**\s*(?:\||$)"],
    "category": [r"(?:Topic\s+)?Category\**\s*[:\u2014\-\|]+\s*\**`?\s*([^\n|*`]+?)`?\s*\**(?:\||\n|$)"],
    "url": [r"(?:URL|Link)\**\s*[:\u2014\-\|]+\s*\**\s*(https?://[^\s|>)*]+)"],
}

NORMALIZE = [("kernel-exploitation","kernel-exploit"),("kernel exploitation","kernel-exploit"),("kernel exploit","kernel-exploit"),
("hive-based","kernel-exploit"),("spectre","kernel-exploit"),("cfg/cet bypass","kernel-exploit"),("kernel mitigation","kernel-exploit"),
("microarchitecture","kernel-exploit"),("side channel","kernel-exploit"),("ad-attack","ad-attack"),("active directory","ad-attack"),
("ad cs","ad-attack"),("ldap","ad-attack"),("kerberos","ad-attack"),("hyper-v","hyper-v"),("virtualization","hyper-v"),
("vbs","vbs-bypass"),("hvci","vbs-bypass"),("credential guard","vbs-bypass"),("confidential computing","vbs-bypass"),
("edr-bypass","edr-bypass"),("edr bypass","edr-bypass"),("byovd","byovd"),("driver","byovd"),("identity-attack","identity"),
("identity","identity"),("authentication","identity"),("oauth","identity"),("windows hello","identity"),("smartcard","identity"),
("entra","cloud-identity"),("azure ad","cloud-identity"),("cloud-identity","cloud-identity"),("post-exploitation","post-exploit"),
("post exploitation","post-exploit"),("lateral movement","post-exploit"),("code-integrity","code-integrity"),
("code integrity","code-integrity"),("code signing","code-integrity"),("authenticode","code-integrity"),("wdac","code-integrity"),
("defense-evasion","defense-evasion"),("downgrade","defense-evasion"),("credentials","credentials"),("credential theft","credentials"),
("dpapi","credentials"),("lsass","credentials"),("password manager","credentials"),("hardware-attack","hardware-attack"),
("uefi","boot-firmware"),("secure boot","boot-firmware"),("firmware","boot-firmware"),("bootkit","boot-firmware"),
("bitlocker","boot-firmware"),("boot chain","boot-firmware"),("recovery","boot-firmware"),("browser-windows","browser-sandbox"),
("browser sandbox","browser-sandbox"),("sandbox-escape","browser-sandbox"),("sandbox escape","browser-sandbox"),
("ipc/rpc","ipc-rpc"),("rpc","ipc-rpc"),("dcom","ipc-rpc"),("ntlm relay","ipc-rpc"),("ntlm reflection","ipc-rpc"),("potato","ipc-rpc"),
("malware-analysis","malware"),("malware analysis","malware"),("ransomware","malware"),("fuzzing-tooling","fuzzing"),
("fuzzing","fuzzing"),("ai-security","ai-security"),("copilot","ai-security"),("prompt injection","ai-security"),
("agentic","ai-security"),("supply-chain","supply-chain"),("microsoft 365","ai-security"),("exchange","exchange"),
("http.sys","kernel-exploit"),("filesystem","filesystem"),("office","office-attack")]

def normalize_category(raw):
    raw_lower = (raw or "").lower()
    for needle, bucket in NORMALIZE:
        if needle in raw_lower: return bucket
    return "uncategorized"

def extract_records(text, source):
    records = []
    lines = text.split("\n")
    window = 30
    i = 0
    while i < len(lines):
        block = "\n".join(lines[i : i + window])
        rec = {}
        for field, patterns in PATTERNS.items():
            for pat in patterns:
                m = re.search(pat, block, re.IGNORECASE | re.MULTILINE)
                if m:
                    val = m.group(1).strip().rstrip(",.")
                    if val and len(val) > 1 and not val.startswith(("|", "-", "—", "*")):
                        rec[field] = val
                        break
        if rec.get("title") and (rec.get("category") or rec.get("theme")):
            rec["source"] = source
            rec["normalized_category"] = normalize_category(rec.get("category", ""))
            records.append(rec)
            i += window
        else:
            i += 5
    return records

def dedupe(records):
    seen = {}
    for r in records:
        key = re.sub(r"[^a-z0-9]", "", r["title"].lower())[:80]
        if key in seen:
            existing = seen[key]
            if sum(1 for v in r.values() if v) > sum(1 for v in existing.values() if v):
                seen[key] = r
        else:
            seen[key] = r
    return list(seen.values())

def main():
    all_records = []
    for report in sorted(SRC.glob("*.md")):
        source = report.stem.replace("-research", "")
        text = report.read_text()
        recs = extract_records(text, source)
        print(f"  {source}: {len(recs)} records extracted")
        all_records.extend(recs)
    print(f"\nTotal before dedupe: {len(all_records)}")
    all_records = dedupe(all_records)
    print(f"After dedupe: {len(all_records)}")

    DST.mkdir(parents=True, exist_ok=True)
    with open(DST / "talks.yaml", "w") as f:
        yaml.safe_dump(all_records, f, sort_keys=False, allow_unicode=True, width=120)
    print(f"\n[OK] wrote {DST / 'talks.yaml'}")

    (DST / "by-theme").mkdir(exist_ok=True)
    by_cat = defaultdict(list)
    for r in all_records:
        by_cat[r["normalized_category"]].append(r)
    for cat, recs in sorted(by_cat.items()):
        with open(DST / "by-theme" / f"{cat}.md", "w") as f:
            f.write(f"# {cat}\n\n_{len(recs)} talks_\n\n")
            f.write("| Year | Title | Speakers | Venue | URL |\n|---|---|---|---|---|\n")
            for r in sorted(recs, key=lambda x: (x.get("year") or "0000"), reverse=True):
                title = r.get("title", "")[:80].replace("|", "\\|")
                speaker = (r.get("speaker") or "")[:50].replace("|", "\\|")
                year = r.get("year") or ""
                venue = (r.get("venue") or r.get("source") or "")[:30].replace("|", "\\|")
                url = r.get("url") or ""
                url_md = f"[link]({url})" if url else ""
                f.write(f"| {year} | {title} | {speaker} | {venue} | {url_md} |\n")
        print(f"  wrote by-theme/{cat}.md ({len(recs)})")

    with open(DST / "all-talks.md", "w") as f:
        f.write(f"# All Talks ({len(all_records)} total)\n\n")
        f.write("| Year | Category | Title | Speakers | Venue | URL |\n|---|---|---|---|---|---|\n")
        for r in sorted(all_records, key=lambda x: (x.get("year") or "0000"), reverse=True):
            title = r.get("title", "")[:80].replace("|", "\\|")
            speaker = (r.get("speaker") or "")[:50].replace("|", "\\|")
            year = r.get("year") or ""
            venue = (r.get("venue") or r.get("source") or "")[:30].replace("|", "\\|")
            url = r.get("url") or ""
            url_md = f"[link]({url})" if url else ""
            cat = r.get("normalized_category", "")
            f.write(f"| {year} | {cat} | {title} | {speaker} | {venue} | {url_md} |\n")
    print(f"\n[OK] wrote all-talks.md")

    print(f"\nTotals by theme:")
    for cat, recs in sorted(by_cat.items(), key=lambda x: -len(x[1])):
        print(f"  {len(recs):>3}  {cat}")

if __name__ == "__main__": main()
