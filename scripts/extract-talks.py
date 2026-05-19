#!/usr/bin/env python3
"""Extract structured talk records from the conference-research markdown reports.

v2 strategy:
  * Split each report into records using `^---$` separators (with optional whitespace).
  * Within each record block, fields are extracted from `**Field** | value` table rows,
    `**Field**: value` bullet lines, OR the record's own H2/H3 heading (for the title).
  * Pass watch URLs through by parsing the watch-link-enrichment.md markdown table and
    fuzzy-matching against record titles.
  * Normalize raw category strings into a controlled vocabulary.
"""
import re
import yaml
from pathlib import Path
from collections import defaultdict

SRC = Path.home() / ".copilot/session-state/0ce251fa-7bd2-45c2-813a-b727a180df40/files/conference-research"
DST = Path.home() / "repos/windows-security-talks"

# Field name aliases for the per-record parser. Each label may appear inside `**…**`,
# as a markdown table row (`| **Field** | value |`), or as a bullet/colon line
# (`- **Field:** value`, `**Field**: value`, `Field: value`).
FIELD_LABELS = {
    "title": ["Title", "Exact Title", "Talk Title", "Post Title", "Paper Title", "Name",
              "Target / Achievement", "Target/Achievement"],
    "speaker": ["Speaker", "Speakers", "Speaker(s)", "Author", "Authors", "Author(s)",
                "Researcher", "Researchers", "Presenter", "Presenter(s)", "Team"],
    "year": ["Year", "Date", "Year/Conference", "Year / Conference", "Year/Venue",
             "Year / Venue", "Year/Competition", "Year / Competition",
             "Conference Year", "Published"],
    "venue": ["Conference", "Venue", "Source", "Source Outlet", "Year/Conference",
              "Year / Conference", "Year/Venue", "Year / Venue", "Year/Competition",
              "Year / Competition", "Track", "Conference/Year", "Conference / Year",
              "Competition"],
    "theme": ["Theme", "One-sentence theme", "One-Sentence Theme", "Description",
              "Abstract", "Summary", "Abstract summary"],
    "category": ["Category", "Topic Category", "Topic category", "Categories", "Topic tags", "Tags"],
    "url": ["URL", "Link", "Slides", "Slides URL", "Paper URL", "Slide URL",
            "Reference", "Primary URL", "Schedule URL", "InfoconDB / source URL",
            "Source URL", "Video / slides", "Video/slides"],
    "watch_url_explicit": ["Watch URL", "Video", "Recording", "Watch Link",
                           "Video URL", "YouTube"],
    "code": ["Code", "Code URL", "Repo", "GitHub", "Source Code"],
}


def _label_alts(labels):
    """Build a `(?:Label1|Label2|...)` regex fragment with each label `\\s*` between
    its words to tolerate variable whitespace."""
    escaped = []
    for lbl in labels:
        parts = [re.escape(p) for p in re.split(r"\s+", lbl)]
        escaped.append(r"\s*".join(parts))
    # Longest first so e.g. "Year/Conference" wins over "Year"
    escaped.sort(key=len, reverse=True)
    return r"(?:" + "|".join(escaped) + r")"


def _build_field_patterns():
    patterns = {}
    for field, labels in FIELD_LABELS.items():
        alts = _label_alts(labels)
        if field == "year":
            value_capture = r"[^|]*?(\d{4})[^|]*?"
            value_capture_line = r"[^\n]*?(\d{4})"
        elif field in ("url", "watch_url_explicit", "code"):
            value_capture = r"[^|\n]*?(https?://[^\s|>)\]*]+)"
            value_capture_line = r"\[?\s*(https?://[^\s|>)\]*]+)"
        else:
            # Capture lazily up to the next pipe; whitespace/markdown is post-stripped.
            value_capture = r"([^|\n]+?)"
            value_capture_line = r"([^\n]+?)"
        patterns[field] = [
            # Markdown table row: | **Field** | value |
            rf"^\|\s*\*{{0,2}}{alts}\*{{0,2}}\s*\|\s*{value_capture}\s*\|",
            # Bullet/inline: optional "- " then **Field:** value  OR  **Field**: value  OR Field: value
            rf"^\s*[-*]?\s*\*{{0,2}}{alts}\*{{0,2}}\s*[:\u2014]\s*{value_capture_line}\s*$",
        ]
    return patterns


FIELD_PATTERNS = _build_field_patterns()

# Headings that introduce records: ## N. Title, ### Talk N, ### Paper N, ### Entry N, ### Item X-NN
HEADING_RE = re.compile(
    r"^(?:#{2,4})\s+"
    r"(?:Talk|Paper|Entry|Item|Post|Session|Briefing|Adventure)?\s*"
    r"(?:[A-Z]?-?\d+(?:\.\d+)?(?:\s*[—-]\s*)?)?"
    r"\s*(.+?)\s*$",
    re.MULTILINE,
)

# Map raw category strings → controlled vocabulary.
# Order matters: more-specific buckets first so they win the substring scan.
NORMALIZE = [
    ("vbs", "vbs-bypass"),
    ("hvci", "vbs-bypass"),
    ("credential guard", "vbs-bypass"),
    ("trustlet", "vbs-bypass"),
    ("confidential computing", "vbs-bypass"),
    ("hyper-v", "hyper-v"),
    ("hyperv", "hyper-v"),
    ("virtualization", "hyper-v"),
    ("byovd", "byovd"),
    ("vulnerable driver", "byovd"),
    ("driver-load", "byovd"),
    ("kernel exploit", "kernel-exploit"),
    ("kernel-exploit", "kernel-exploit"),
    ("kernel exploitation", "kernel-exploit"),
    ("kernel mitigation", "kernel-exploit"),
    ("hive-based", "kernel-exploit"),
    ("spectre", "kernel-exploit"),
    ("cfg/cet", "kernel-exploit"),
    ("microarchitecture", "kernel-exploit"),
    ("side channel", "kernel-exploit"),
    ("rop", "kernel-exploit"),
    ("http.sys", "kernel-exploit"),
    ("ksmbd", "kernel-exploit"),
    ("ad cs", "ad-attack"),
    ("adcs", "ad-attack"),
    ("active directory", "ad-attack"),
    ("ad-attack", "ad-attack"),
    ("kerberos", "ad-attack"),
    ("ldap", "ad-attack"),
    ("dcsync", "ad-attack"),
    ("dcshadow", "ad-attack"),
    ("krbtgt", "ad-attack"),
    ("bloodhound", "ad-attack"),
    ("sccm", "ad-attack"),
    ("entra", "cloud-identity"),
    ("azure ad", "cloud-identity"),
    ("aad", "cloud-identity"),
    ("cloud identity", "cloud-identity"),
    ("cloud-identity", "cloud-identity"),
    ("conditional access", "cloud-identity"),
    ("ntlm relay", "ipc-rpc"),
    ("ntlm reflection", "ipc-rpc"),
    ("potato", "ipc-rpc"),
    ("alpc", "ipc-rpc"),
    ("dcom", "ipc-rpc"),
    ("rpc ", "ipc-rpc"),
    ("rpc-", "ipc-rpc"),
    ("ipc-rpc", "ipc-rpc"),
    ("ipc/rpc", "ipc-rpc"),
    ("named pipe", "ipc-rpc"),
    ("coercion", "ipc-rpc"),
    ("windows hello", "credentials"),
    ("smartcard", "credentials"),
    ("dpapi", "credentials"),
    ("lsass", "credentials"),
    ("mimikatz", "credentials"),
    ("credential theft", "credentials"),
    ("credentials", "credentials"),
    ("password manager", "credentials"),
    ("uefi", "boot-firmware"),
    ("secure boot", "boot-firmware"),
    ("firmware", "boot-firmware"),
    ("bootkit", "boot-firmware"),
    ("bitlocker", "boot-firmware"),
    ("boot chain", "boot-firmware"),
    ("recovery", "boot-firmware"),
    ("tpm", "boot-firmware"),
    ("code integrity", "code-integrity"),
    ("code-integrity", "code-integrity"),
    ("code signing", "code-integrity"),
    ("authenticode", "code-integrity"),
    ("wdac", "code-integrity"),
    ("smart app control", "code-integrity"),
    ("edr bypass", "edr-bypass"),
    ("edr-bypass", "edr-bypass"),
    ("edr evasion", "edr-bypass"),
    ("etw", "edr-bypass"),
    ("amsi", "edr-bypass"),
    ("hooking", "edr-bypass"),
    ("post-exploit", "post-exploit"),
    ("post exploitation", "post-exploit"),
    ("post-exploitation", "post-exploit"),
    ("lateral movement", "post-exploit"),
    ("lolbin", "post-exploit"),
    ("persistence", "post-exploit"),
    ("token impersonation", "post-exploit"),
    ("com hijack", "post-exploit"),
    ("dll hijack", "post-exploit"),
    ("defense evasion", "defense-evasion"),
    ("defense-evasion", "defense-evasion"),
    ("downgrade", "defense-evasion"),
    ("downdate", "defense-evasion"),
    ("obfuscation", "defense-evasion"),
    ("browser sandbox", "browser-sandbox"),
    ("browser-sandbox", "browser-sandbox"),
    ("sandbox escape", "browser-sandbox"),
    ("sandbox-escape", "browser-sandbox"),
    ("chrome", "browser-sandbox"),
    ("edge", "browser-sandbox"),
    ("hardware attack", "hardware-attack"),
    ("hardware-attack", "hardware-attack"),
    ("dma", "hardware-attack"),
    ("identity attack", "identity"),
    ("identity-attack", "identity"),
    ("authentication", "identity"),
    ("oauth", "identity"),
    ("identity", "identity"),
    ("malware analysis", "malware"),
    ("malware-analysis", "malware"),
    ("malware detection", "malware"),
    ("ml-based defense", "malware"),
    ("ransomware", "malware"),
    ("fuzzing", "fuzzing"),
    ("fuzzing-tooling", "fuzzing"),
    ("ai-security", "ai-security"),
    ("ai security", "ai-security"),
    ("ai/ml", "ai-security"),
    ("ml security", "ai-security"),
    ("genai", "ai-security"),
    ("copilot", "ai-security"),
    ("prompt injection", "ai-security"),
    ("agentic", "ai-security"),
    ("llm", "ai-security"),
    ("microsoft 365", "ai-security"),
    ("m365", "ai-security"),
    ("supply chain", "supply-chain"),
    ("supply-chain", "supply-chain"),
    ("exchange", "exchange"),
    ("registry", "registry"),
    ("registry-exploit", "registry"),
    ("filesystem", "filesystem"),
    ("ntfs", "filesystem"),
    ("symlink", "filesystem"),
    ("toctou", "filesystem"),
    ("forensics", "forensics"),
    ("dfir", "forensics"),
    ("memory forensics", "forensics"),
    ("office", "office-attack"),
    ("outlook", "office-attack"),
    ("ole", "office-attack"),
    ("rce", "rce"),
    ("uac bypass", "post-exploit"),
    ("uac", "post-exploit"),
    ("privilege escalation", "post-exploit"),
    ("windows kernel", "kernel-exploit"),
    ("windows internals", "kernel-exploit"),
    ("kernel", "kernel-exploit"),
    ("exploitation", "kernel-exploit"),
    ("threat intelligence", "threat-intel"),
    ("threat hunting", "threat-intel"),
    ("threat detection", "threat-intel"),
    # Specific named attacks/tools that should always classify the talk.
    ("printspoofer", "ipc-rpc"),
    ("printnightmare", "ipc-rpc"),
    ("spoolsample", "ipc-rpc"),
    ("petitpotam", "ipc-rpc"),
    ("nopac", "ad-attack"),
    ("zerologon", "ad-attack"),
    ("certifried", "ad-attack"),
    ("certipy", "ad-attack"),
    ("rubeus", "ad-attack"),
    ("mimikatz", "credentials"),
    ("sudo for windows", "post-exploit"),
    # Out-of-scope buckets (talk at a Windows venue but not Windows-internals).
    ("macos", "out-of-scope"),
    ("ios", "out-of-scope"),
    ("iot", "out-of-scope"),
    ("scam", "out-of-scope"),
    ("mdm", "out-of-scope"),
    ("low-code", "out-of-scope"),
    ("citizen development", "out-of-scope"),
    ("developer security", "out-of-scope"),
    ("developer-friendly", "out-of-scope"),
    ("appsec", "out-of-scope"),
    ("dast", "out-of-scope"),
    ("network security", "out-of-scope"),
    ("keynote", "keynote"),
]


def normalize_category(*candidates) -> str:
    """Pick the first bucket-mapping needle that matches any candidate string.
    Candidates are tried in order; within each candidate, NORMALIZE order wins."""
    blobs = [(c or "").lower() for c in candidates]
    for needle, bucket in NORMALIZE:
        for blob in blobs:
            if needle in blob:
                return bucket
    return "uncategorized"


def title_key(title: str) -> str:
    """Normalize a title for fuzzy matching: lowercase, alnum-only, first 60 chars."""
    return re.sub(r"[^a-z0-9]", "", (title or "").lower())[:60]


def clean_value(val: str) -> str:
    val = val.strip()
    # Strip markdown emphasis everywhere, then trim again.
    val = re.sub(r"\*+", "", val)
    val = re.sub(r"`+", "", val)
    val = val.strip("_")
    val = re.sub(r"\s+", " ", val)
    return val.strip(" ,.;|")


def extract_first(patterns, block):
    for pat in patterns:
        m = re.search(pat, block, re.MULTILINE | re.IGNORECASE)
        if m:
            v = clean_value(m.group(1))
            if v and len(v) > 1:
                return v
    return None


def fill_year(rec):
    """If year is missing, derive it from venue/title (regex or DEF CON N convention)."""
    if rec.get("year"):
        return
    for src_field in ("venue", "title", "speaker"):
        if rec.get(src_field):
            m = re.search(r"\b(20\d{2}|19[89]\d)\b", rec[src_field])
            if m:
                rec["year"] = m.group(1)
                return
    v = (rec.get("venue") or "") + " " + (rec.get("title") or "")
    m = re.search(r"DEF\s*CON\s*(\d{1,2})", v, re.IGNORECASE)
    if m:
        rec["year"] = str(1992 + int(m.group(1)))


def parse_records(text: str, source: str):
    """Split on `---` lines; each chunk between `---` lines is one candidate record."""
    chunks = re.split(r"^\s*---\s*$", text, flags=re.MULTILINE)
    records = []
    venue_keywords = ("BLUEHAT", "BLACK HAT", "DEF CON", "TROOPERS", "OFFENSIVE",
                      "RECON", "USENIX", "S&P", "CCS", "NDSS", "PWN2OWN", "HARDWEAR")
    context_year = None  # rolling section-year carried forward chunk-to-chunk
    for chunk in chunks:
        chunk_stripped = chunk.strip()
        if len(chunk_stripped) < 50:
            # Still scan short chunks for year-bearing headings so context persists.
            for line in chunk_stripped.split("\n"):
                upper = line.upper()
                if line.startswith("#") or any(kw in upper for kw in venue_keywords):
                    m = re.search(r"\b(20\d{2}|19[89]\d)\b", line)
                    if m:
                        context_year = m.group(1)
            continue
        # Update context_year from any year-bearing heading in this chunk.
        for line in chunk_stripped.split("\n")[:30]:
            upper = line.upper()
            if line.startswith("#") or any(kw in upper for kw in venue_keywords):
                m = re.search(r"\b(20\d{2}|19[89]\d)\b", line)
                if m:
                    context_year = m.group(1)
                    break

        # If chunk contains a wide multi-row table where columns map to fields,
        # parse rows separately. Otherwise treat it as a single record.
        wide_records = parse_wide_tables(chunk_stripped, source, context_year=context_year)
        if wide_records:
            records.extend(wide_records)
            continue

        chunk = chunk_stripped

        rec = {}
        for field, pats in FIELD_PATTERNS.items():
            v = extract_first(pats, chunk)
            if v:
                rec[field] = v

        # Title fallback: pick the chunk's first heading if no Title row found.
        if not rec.get("title"):
            for line in chunk.split("\n"):
                m = HEADING_RE.match(line)
                if m:
                    candidate = clean_value(m.group(1))
                    # Strip "Talk N", "Paper N", "Entry N — " leading noise if heading regex missed it
                    candidate = re.sub(r"^(?:Talk|Paper|Entry|Item|Post)\s*[A-Z]?-?\d+\s*[—-]?\s*", "", candidate, flags=re.IGNORECASE)
                    if len(candidate) > 5 and not candidate.lower().startswith(("summary", "key", "theme", "category", "field")):
                        rec["title"] = candidate
                        break

        # Year fallback: scan for a year in the venue/title field.
        fill_year(rec)

        # Only keep records that have a title and at least one other classifying field.
        if rec.get("title") and (rec.get("category") or rec.get("theme") or rec.get("url") or rec.get("venue")):
            # Reject obvious section-header artifacts.
            bad_titles = ("summary of findings", "format key", "key citations", "gaps and",
                          "table of contents", "by category", "notable recurring", "watch url",
                          "recurring theme", "research gaps", "access notes", "section ",
                          "data not found", "session not in repository",
                          "research summary", "key takeaways", "sources and citations",
                          "citation evidence", "what appears here", "five dominant themes",
                          "competition calendar")
            if any(b in rec["title"].lower() for b in bad_titles):
                continue
            if "watch_url_explicit" in rec:
                rec["watch_url"] = rec.pop("watch_url_explicit")
            rec["source"] = source
            rec["normalized_category"] = normalize_category(
                rec.get("category"), rec.get("theme"), rec.get("title")
            )
            records.append(rec)
    return records


# Column-header → field mappings for "wide" multi-row tables (BlueHat style).
COLUMN_FIELD_MAP = {
    "title": "title", "exact title": "title", "talk title": "title", "name": "title",
    "speaker": "speaker", "speakers": "speaker", "speaker(s)": "speaker",
    "speaker(s) & affiliation": "speaker", "speakers & affiliation": "speaker",
    "author": "speaker", "authors": "speaker", "author(s)": "speaker",
    "researcher": "speaker", "presenter": "speaker",
    "year": "year", "date": "year",
    "conference": "venue", "venue": "venue", "track": "venue", "source": "venue",
    "theme": "theme", "one-sentence theme": "theme", "one sentence theme": "theme",
    "description": "theme", "abstract": "theme", "summary": "theme",
    "category": "category", "topic category": "category", "categories": "category",
    "topic tags": "category", "tags": "category",
    "url": "url", "link": "url", "slides": "url", "slides url": "url",
    "watch url": "watch_url_explicit", "video": "watch_url_explicit",
    "recording": "watch_url_explicit", "youtube": "watch_url_explicit",
}


def parse_wide_tables(chunk: str, source: str, context_year: str = None):
    """Find tables in the chunk where each data row is one record.

    A wide table has a header row whose columns include a Title column plus at least
    one of Speaker/Category/Theme/URL. Each subsequent data row becomes a record.
    `context_year` overrides the rolling-section year if known up front.
    """
    records = []
    lines = chunk.split("\n")
    # Track the most-recent year-mentioning heading/text BEFORE each line.
    line_year = [None] * len(lines)
    current = context_year
    venue_keywords = ("BLUEHAT", "BLACK HAT", "DEF CON", "TROOPERS", "OFFENSIVE",
                      "RECON", "USENIX", "S&P", "CCS", "NDSS", "PWN2OWN", "HARDWEAR")
    for idx, line in enumerate(lines):
        upper = line.upper()
        if any(kw in upper for kw in venue_keywords):
            m = re.search(r"\b(20\d{2}|19[89]\d)\b", line)
            if m:
                current = m.group(1)
        elif line.startswith("#"):
            m = re.search(r"\b(20\d{2}|19[89]\d)\b", line)
            if m:
                current = m.group(1)
        line_year[idx] = current

    i = 0
    while i < len(lines) - 2:
        line = lines[i].rstrip()
        # Look for a header row.
        if line.startswith("|") and "|" in line[1:]:
            header_cells = [c.strip().lower().strip("*") for c in line.split("|")[1:-1]]
            # Need a separator row right after.
            sep = lines[i + 1].strip() if i + 1 < len(lines) else ""
            if not re.match(r"^\|[\s\-:]+(\|[\s\-:]+)+\|?$", sep):
                i += 1
                continue
            # Map header columns to fields.
            col_map = {}
            for idx, h in enumerate(header_cells):
                h_clean = re.sub(r"[`*]", "", h).strip()
                if h_clean in COLUMN_FIELD_MAP:
                    col_map[idx] = COLUMN_FIELD_MAP[h_clean]
            if "title" not in col_map.values():
                i += 1
                continue
            # Need at least one other classifying field column.
            other_fields = {v for v in col_map.values() if v != "title"}
            if not other_fields & {"speaker", "category", "theme", "url", "venue", "year"}:
                i += 1
                continue
            # Parse data rows.
            j = i + 2
            while j < len(lines):
                row = lines[j].rstrip()
                if not row.startswith("|"):
                    break
                cells = [c.strip() for c in row.split("|")[1:-1]]
                if len(cells) < len(header_cells) - 1:
                    j += 1
                    continue
                rec = {}
                for idx, field in col_map.items():
                    if idx < len(cells):
                        val = cells[idx]
                        # Strip markdown emphasis and skip empty/placeholder rows.
                        val = re.sub(r"\*+", "", val).strip()
                        val = val.strip("`").strip()
                        if not val or val in ("—", "-", "–", "—", "*", "❌", "✅"):
                            continue
                        if field == "year":
                            m = re.search(r"\b(20\d{2}|19[89]\d)\b", val)
                            if m:
                                rec[field] = m.group(1)
                        elif field in ("url", "watch_url_explicit", "code"):
                            m = re.search(r"(https?://[^\s|>)\]*]+)", val)
                            if m:
                                rec[field] = m.group(1).rstrip(".,;")
                        else:
                            rec[field] = clean_value(val)
                if rec.get("title") and len(rec["title"]) > 3:
                    bad_titles = ("session not in repository", "—", "not in repo",
                                  "data not found", "sources and citations",
                                  "citation evidence")
                    if not any(b in rec["title"].lower() for b in bad_titles):
                        if "watch_url_explicit" in rec:
                            rec["watch_url"] = rec.pop("watch_url_explicit")
                        rec["source"] = source
                        # Use the section-context year as a fallback when the row has none.
                        if not rec.get("year") and j - 1 < len(line_year):
                            ctx = line_year[j - 1]
                            if ctx:
                                rec["year"] = ctx
                        fill_year(rec)
                        rec["normalized_category"] = normalize_category(
                            rec.get("category"), rec.get("theme"), rec.get("title")
                        )
                        records.append(rec)
                j += 1
            i = j
        else:
            i += 1
    return records


def parse_watch_table(path: Path):
    """Parse the markdown table in watch-link-enrichment.md → list of dicts with watch_url + confidence."""
    if not path.exists():
        return []
    text = path.read_text()
    rows = []
    in_table = False
    for line in text.split("\n"):
        if line.startswith("| Title |") or line.startswith("|Title|"):
            in_table = True
            continue
        if in_table:
            if not line.startswith("|"):
                in_table = False
                continue
            if line.startswith("|-") or line.startswith("|---"):
                continue
            cells = [c.strip() for c in line.split("|")[1:-1]]
            if len(cells) < 6:
                continue
            title, speaker, year, conf, watch_url, confidence = cells[:6]
            if not title or title.lower() == "title":
                continue
            rows.append({
                "title": title,
                "speaker": speaker,
                "year": year,
                "conference": conf,
                "watch_url": watch_url,
                "watch_confidence": confidence,
            })
    return rows


def source_for_url(url):
    """Classify a watch URL by its host + specificity."""
    if not url:
        return None
    if "youtube.com" in url or "youtu.be" in url:
        return "YouTube"
    if "media.defcon.org" in url:
        if url.endswith(".mp4") or url.endswith(".webm"):
            return "DEF CON MP4"
        return "DEF CON archive"
    if "media.ccc.de" in url:
        return "media.ccc.de"
    if "recon.cx" in url:
        return "recon.cx"
    if "vimeo.com" in url:
        return "Vimeo"
    if "infocondb.org" in url:
        return "InfoconDB"
    if "i.blackhat.com" in url:
        return "Black Hat slides"
    if "blackhat.com" in url:
        return "Black Hat"
    if "troopers.de" in url:
        return "Troopers"
    if "offensivecon.org" in url:
        return "OffensiveCon"
    import urllib.parse as _u
    try:
        return _u.urlparse(url).hostname or "external"
    except Exception:
        return "external"


def watch_quality(entry):
    """Higher = better. Embeddable YouTube > playable MP4 > host page > directory listing."""
    url = entry.get("url", "")
    conf = (entry.get("confidence") or "").upper()
    score = 0
    if "youtube.com/watch" in url or "youtu.be/" in url:
        score = 100
    elif url.endswith(".mp4") or url.endswith(".webm"):
        score = 80
    elif "media.ccc.de/v/" in url or "/talks/" in url or "/sessions/" in url:
        score = 60
    elif url.endswith("/"):
        score = 5  # bare directory listing — pretty useless when we have a specific link
    else:
        score = 40
    if conf == "VERIFIED": score += 5
    elif conf == "HIGH": score += 3
    elif conf == "MED": score += 1
    return score


def add_watch_url(record, url, confidence="HIGH"):
    """Append a watch URL to record's watch_urls list, deduped by URL.
    Drops bare directory listings if a more-specific link from the same host
    already exists. Maintains watch_url (singular, best) for backward compat.

    Returns True if newly added.
    """
    if not url or "://" not in url:
        return False
    if url == record.get("url"):
        return False
    record.setdefault("watch_urls", [])
    if any(w.get("url") == url for w in record["watch_urls"]):
        return False

    record["watch_urls"].append({
        "url": url,
        "source": source_for_url(url),
        "confidence": confidence,
    })

    # If any non-directory URL exists for a host, drop bare directory URLs
    # from the same host (they're useless once we have a specific link).
    import urllib.parse as _u
    def _host(u):
        try: return _u.urlparse(u).hostname or ""
        except Exception: return ""

    hosts_with_specific = {_host(w["url"]) for w in record["watch_urls"] if not w["url"].endswith("/")}
    record["watch_urls"] = [
        w for w in record["watch_urls"]
        if not (w["url"].endswith("/") and _host(w["url"]) in hosts_with_specific)
    ]

    best = max(record["watch_urls"], key=watch_quality)
    record["watch_url"] = best["url"]
    record["watch_confidence"] = best["confidence"]
    return True


def merge_watch_urls(records, watch_rows):
    """Fuzzy-match titles to add watch URLs to records as a deduped list."""
    idx = {}
    for w in watch_rows:
        if (w.get("watch_confidence") or "").strip().upper() == "NONE":
            continue
        idx.setdefault(title_key(w["title"]), w)

    matched = 0
    for r in records:
        key = title_key(r.get("title", ""))
        hit = idx.get(key)
        if not hit:
            short = key[:30]
            if short and len(short) >= 20:
                for k, w in idx.items():
                    if k.startswith(short) or short.startswith(k[:30]):
                        hit = w
                        break
        if hit:
            if add_watch_url(r, hit["watch_url"], hit.get("watch_confidence", "HIGH")):
                matched += 1
    return matched


def dedupe(records):
    """Merge duplicate records by title-key; keep the one with the most populated fields."""
    seen = {}
    for r in records:
        k = title_key(r.get("title", ""))
        if not k:
            continue
        if k in seen:
            existing = seen[k]
            # Merge: take any field present in r but missing in existing.
            for field, val in r.items():
                if not existing.get(field) and val:
                    existing[field] = val
            # Replace if r has strictly more populated fields.
            if sum(1 for v in r.values() if v) > sum(1 for v in existing.values() if v):
                merged = dict(existing)
                merged.update({k2: v2 for k2, v2 in r.items() if v2})
                seen[k] = merged
        else:
            seen[k] = r
    return list(seen.values())


def render_row(r, columns):
    out = []
    for col in columns:
        v = r.get(col, "") or ""
        v = str(v).replace("|", "\\|").replace("\n", " ")
        if col in ("url", "watch_url") and v:
            v = f"[link]({v})"
        if col == "title":
            v = v[:90]
        elif col == "speaker":
            v = v[:50]
        elif col in ("venue", "source"):
            v = v[:30]
        out.append(v)
    return "| " + " | ".join(out) + " |"


def main():
    all_records = []
    for report in sorted(SRC.glob("*.md")):
        if report.stem == "watch-link-enrichment":
            continue
        source = report.stem.replace("-research", "")
        text = report.read_text()
        recs = parse_records(text, source)
        print(f"  {source}: {len(recs)} records extracted")
        all_records.extend(recs)

    print(f"\nTotal before dedupe: {len(all_records)}")
    all_records = dedupe(all_records)
    print(f"After dedupe: {len(all_records)}")

    watch_rows = parse_watch_table(SRC / "watch-link-enrichment.md")
    print(f"\nWatch-link table rows: {len(watch_rows)}")
    matched = merge_watch_urls(all_records, watch_rows)
    print(f"Watch URLs merged into talks: {matched}")

    DST.mkdir(parents=True, exist_ok=True)
    with open(DST / "talks.yaml", "w") as f:
        yaml.safe_dump(all_records, f, sort_keys=False, allow_unicode=True, width=120)
    print(f"\n[OK] wrote {DST / 'talks.yaml'}")

    # Also emit a JSON copy for the static GitHub Pages site.
    import json
    (DST / "docs").mkdir(exist_ok=True)
    with open(DST / "docs" / "talks.json", "w") as f:
        json.dump(all_records, f, ensure_ascii=False, indent=1)
    print(f"[OK] wrote {DST / 'docs' / 'talks.json'}")

    (DST / "by-theme").mkdir(exist_ok=True)
    # Wipe stale per-theme files first.
    for p in (DST / "by-theme").glob("*.md"):
        p.unlink()

    by_cat = defaultdict(list)
    for r in all_records:
        by_cat[r["normalized_category"]].append(r)

    theme_cols = ["year", "title", "speaker", "venue", "url", "watch_url"]
    for cat, recs in sorted(by_cat.items()):
        with open(DST / "by-theme" / f"{cat}.md", "w") as f:
            f.write(f"# {cat}\n\n_{len(recs)} talks_\n\n")
            f.write("| Year | Title | Speakers | Venue | Slides | Watch |\n")
            f.write("|---|---|---|---|---|---|\n")
            for r in sorted(recs, key=lambda x: (x.get("year") or "0000", x.get("title") or ""), reverse=True):
                f.write(render_row(r, theme_cols) + "\n")

    # Consolidated all-talks.md
    with open(DST / "all-talks.md", "w") as f:
        f.write(f"# All Talks ({len(all_records)} total)\n\n")
        watch_count = sum(1 for r in all_records if r.get("watch_url"))
        f.write(f"_{watch_count} with watch links · {len(by_cat)} theme buckets_\n\n")
        f.write("| Year | Category | Title | Speakers | Venue | Slides | Watch |\n")
        f.write("|---|---|---|---|---|---|---|\n")
        all_cols = ["year", "normalized_category", "title", "speaker", "venue", "url", "watch_url"]
        for r in sorted(all_records, key=lambda x: (x.get("year") or "0000", x.get("normalized_category") or ""), reverse=True):
            f.write(render_row(r, all_cols) + "\n")

    # by-year/
    (DST / "by-year").mkdir(exist_ok=True)
    for p in (DST / "by-year").glob("*.md"):
        p.unlink()
    by_year = defaultdict(list)
    for r in all_records:
        by_year[r.get("year") or "unknown"].append(r)
    year_cols = ["normalized_category", "title", "speaker", "venue", "url", "watch_url"]
    for y, recs in sorted(by_year.items(), reverse=True):
        with open(DST / "by-year" / f"{y}.md", "w") as f:
            f.write(f"# Talks from {y} ({len(recs)})\n\n")
            f.write("| Category | Title | Speakers | Venue | Slides | Watch |\n")
            f.write("|---|---|---|---|---|---|\n")
            for r in sorted(recs, key=lambda x: (x.get("normalized_category") or "", x.get("title") or "")):
                f.write(render_row(r, year_cols) + "\n")

    # by-conference/
    (DST / "by-conference").mkdir(exist_ok=True)
    for p in (DST / "by-conference").glob("*.md"):
        p.unlink()
    by_venue = defaultdict(list)
    for r in all_records:
        v = ((r.get("venue") or r.get("source") or "")).lower()
        if "def con" in v or "defcon" in v:
            key = "defcon"
        elif "black hat" in v or "blackhat" in v:
            key = "blackhat-usa"
        elif "bluehat" in v:
            key = "bluehat"
        elif "offensivecon" in v:
            key = "offensivecon"
        elif "recon" in v:
            key = "recon"
        elif "troopers" in v:
            key = "troopers"
        elif "pwn2own" in v:
            key = "pwn2own"
        elif "hardwear" in v:
            key = "hardwear-io"
        elif "project zero" in v or "project-zero" in v:
            key = "project-zero"
        elif "usenix" in v:
            key = "usenix-security"
        elif " ccs" in v or v.startswith("ccs") or "acm ccs" in v:
            key = "acm-ccs"
        elif "ieee" in v or "s&p" in v:
            key = "ieee-sp"
        elif "ndss" in v:
            key = "ndss"
        elif r.get("source") == "community":
            key = "community-blogs"
        elif r.get("source") == "foundational-pre-2024":
            key = "foundational"
        else:
            key = re.sub(r"[^a-z0-9-]+", "-", v).strip("-") or "other"
        by_venue[key].append(r)
    venue_cols = ["year", "normalized_category", "title", "speaker", "url", "watch_url"]
    for venue, recs in sorted(by_venue.items()):
        if not venue:
            continue
        with open(DST / "by-conference" / f"{venue}.md", "w") as f:
            f.write(f"# {venue} ({len(recs)})\n\n")
            f.write("| Year | Category | Title | Speakers | Slides | Watch |\n")
            f.write("|---|---|---|---|---|---|\n")
            for r in sorted(recs, key=lambda x: (x.get("year") or "0000", x.get("title") or ""), reverse=True):
                f.write(render_row(r, venue_cols) + "\n")

    print(f"\n[OK] wrote all-talks.md ({watch_count}/{len(all_records)} have watch links)")
    print(f"[OK] by-year/ ({len(by_year)} files), by-conference/ ({len(by_venue)} files)")
    print(f"\nTotals by theme:")
    for cat, recs in sorted(by_cat.items(), key=lambda x: -len(x[1])):
        with_watch = sum(1 for r in recs if r.get("watch_url"))
        print(f"  {len(recs):>3}  ({with_watch:>3} w/ watch)  {cat}")


if __name__ == "__main__":
    main()
