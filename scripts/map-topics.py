#!/usr/bin/env python3
"""Map talks to WindowsSecurity (MaliParag/WindowsSecurity) topic taxonomy.

The companion repo organizes Windows-security topics into a controlled vocabulary of
~95 stub posts under posts/md/<slug>.md, grouped into 6 category pages.

This script:
  1. Loads the topic taxonomy (slug → display name → category) from the WindowsSecurity site.
  2. For each topic, defines a list of keyword/phrase aliases.
  3. Walks talks.yaml and matches each talk to 0+ topics by case-insensitive keyword
     hits in (title + theme + venue + speaker).
  4. Emits docs/topic-map.json: {topic_slug: [{slug, title, year, venue, url, watch_url, theme}, ...]}.
  5. Emits docs/by-topic/<slug>.md indexes for each topic with at least one matching talk.
  6. Emits docs/by-topic/index.md as a master index grouped by category.
  7. Sets a `topics` field on each talks.yaml record so the cards UI can render topic chips.

Heuristics intentionally lean conservative: a topic matches only when a strong keyword
hits (e.g., "BitLocker" matches bitlocker topic, but "memory" alone does not match any
single memory topic). False positives are worse than false negatives here.
"""
from __future__ import annotations
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
TALKS = ROOT / "talks.yaml"
DOCS = ROOT / "docs"
BY_TOPIC = DOCS / "by-topic"
WS_BASE = "https://maliparag.github.io/WindowsSecurity"
WS_POST = f"{WS_BASE}/post_template.html?post="

# slug -> (display_name, category, [keywords])
# Categories: application, cloud_services, hardware, identity, operating_system, security_foundation
# Keywords are matched case-insensitively as whole-word or hyphen-tolerant substrings.
TOPICS: dict[str, tuple[str, str, list[str]]] = {
    # ===== identity =====
    "credential_guard":          ("Credential Guard", "identity",
        [r"credential guard", r"\bcred ?guard\b", r"lsass.*protect", r"runasppl", r"wdigest"]),
    "windows_hello":             ("Windows Hello", "identity",
        [r"windows hello\b(?! enhanced)", r"\bhello for business\b", r"\bWHfB\b"]),
    "windows_hello_enhanced_sign_in_security": ("Windows Hello ESS", "identity",
        [r"enhanced sign[- ]in security", r"\bESS\b(?!ent)", r"windows hello.*enhanced"]),
    "fido2":                     ("FIDO2", "identity",
        [r"\bfido ?2\b", r"webauthn", r"passkey"]),
    "smart_card":                ("Smart Card", "identity",
        [r"\bsmart ?card\b"]),
    "microsoft_authenticator":   ("Microsoft Authenticator", "identity",
        [r"microsoft authenticator", r"\bauthenticator app"]),
    "remote_credential_guard":   ("Remote Credential Guard", "identity",
        [r"remote credential guard"]),
    "token_protection":          ("Token Protection", "identity",
        [r"token protection", r"\bPRT\b", r"primary refresh token"]),
    "vbs_key_protection":        ("VBS Key Protection", "identity",
        [r"vbs key", r"vsm.*key"]),
    "account_lockout_policy":   ("Account Lockout Policy", "identity",
        [r"account lockout", r"lockout polic"]),
    "azure_ad_join":             ("Azure AD Join / Entra Join", "identity",
        [r"azure ad join", r"entra join", r"hybrid ad join", r"aad join", r"azureadjoin"]),
    "enhanced_phishing_protection": ("Enhanced Phishing Protection", "identity",
        [r"enhanced phishing protection", r"\bEPP\b"]),

    # ===== cloud_services =====
    "microsoft_entra_id":        ("Microsoft Entra ID (Azure AD)", "cloud_services",
        [r"entra id\b", r"\bazure ad\b", r"\bAAD\b(?![a-z])", r"azure active directory"]),
    "microsoft_intune":          ("Microsoft Intune", "cloud_services",
        [r"\bintune\b"]),
    "microsoft_defender_for_endpoint": ("Defender for Endpoint", "cloud_services",
        [r"defender for endpoint", r"\bMDE\b", r"\bdefender atp\b"]),
    "microsoft_defender_antivirus": ("Defender Antivirus", "cloud_services",
        [r"defender antivirus", r"defender av", r"\bWindows Defender\b", r"\bMpEngine\b", r"\bASR\b"]),
    "microsoft_defender_for_business": ("Defender for Business", "cloud_services",
        [r"defender for business"]),
    "onedrive_for_work_or_school": ("OneDrive for Work/School", "cloud_services",
        [r"onedrive for (work|business|school)"]),
    "onedrive_for_personal_use": ("OneDrive (Personal)", "cloud_services",
        [r"onedrive (personal|consumer)"]),
    "personal_vault":            ("Personal Vault", "cloud_services",
        [r"personal vault"]),
    "microsoft_entra_internet_access": ("Entra Internet Access", "cloud_services",
        [r"entra internet access", r"\bEIA\b"]),
    "microsoft_entra_private_access": ("Entra Private Access", "cloud_services",
        [r"entra private access", r"\bEPA\b"]),
    "microsoft_cloud_pki":       ("Cloud PKI", "cloud_services",
        [r"cloud pki", r"microsoft cloud pki"]),
    "microsoft_account":         ("Microsoft Account (MSA)", "cloud_services",
        [r"microsoft account\b", r"\bMSA\b(?![a-z])"]),
    "windows_autopilot":         ("Windows Autopilot", "cloud_services",
        [r"\bautopilot\b"]),
    "windows_autopatch":         ("Windows Autopatch", "cloud_services",
        [r"\bautopatch\b"]),

    # ===== application =====
    "applocker":                 ("AppLocker", "application",
        [r"\bapplocker\b"]),
    "smart_app_control":         ("Smart App Control", "application",
        [r"smart app control", r"\bSAC\b(?![a-z])"]),
    "microsoft_defender_application_guard": ("Defender Application Guard", "application",
        [r"application guard", r"\bMDAG\b", r"\bWDAG\b"]),
    "microsoft_vulnerable_driver_block": ("Vulnerable Driver Blocklist", "application",
        [r"vulnerable driver block", r"driver block ?list", r"\bWDAC.*block ?list\b", r"\bbyovd\b", r"bring your own vulnerable driver"]),
    "code_signing_and_integrity": ("Code Signing & Integrity", "application",
        [r"code signing", r"code integrity", r"\bWDAC\b", r"app ?id ?\.sys", r"signed catalog"]),
    "controlled_folder_access":  ("Controlled Folder Access", "application",
        [r"controlled folder access", r"\bCFA\b(?![a-z])"]),
    "browser_protection":        ("Browser Protection", "application",
        [r"browser protect", r"smartscreen.*browser"]),
    "trusted_signing":           ("Trusted Signing", "application",
        [r"trusted signing"]),
    "windows_sandbox":           ("Windows Sandbox", "application",
        [r"windows sandbox"]),

    # ===== operating_system =====
    "bitlocker":                 ("BitLocker", "operating_system",
        [r"bitlocker", r"\bBL\b(?![a-z])\s*encrypt", r"bitunlocker", r"bdedrive"]),
    "encrypted_hard_drive":      ("Encrypted Hard Drive", "operating_system",
        [r"encrypted hard drive", r"\beHDD\b"]),
    "personal_data_encryption":  ("Personal Data Encryption", "operating_system",
        [r"personal data encryption", r"\bPDE\b(?![a-z])"]),
    "encrypted_file_system_efs": ("Encrypted File System (EFS)", "operating_system",
        [r"\befs\b", r"encrypted file system"]),
    "secure_boot":               ("Secure Boot", "operating_system",
        [r"secure boot"]),
    "trusted_platform_module_tpm_2_0": ("TPM 2.0", "operating_system",
        [r"\btpm\b", r"trusted platform module"]),
    "virtualization_based_security_vbs": ("Virtualization-Based Security (VBS)", "operating_system",
        [r"\bVBS\b(?!.*key)", r"virtualization[- ]based security", r"\bvirtual secure mode\b", r"\bVSM\b(?![a-z])", r"\bvtl\d?", r"secure kernel"]),
    "virtualization_based_integrity_vbi": ("Virtualization-Based Integrity", "operating_system",
        [r"virtualization[- ]based integrity", r"\bVBI\b"]),
    "hypervisor_protected_code_integrity_hvci": ("HVCI", "operating_system",
        [r"\bHVCI\b", r"hypervisor[- ]protected code integrity"]),
    "hypervisor_enforced_bug_reporting_hebr": ("HEBR (Hypervisor Bug Reporting)", "operating_system",
        [r"\bHEBR\b", r"hypervisor[- ]enforced bug reporting"]),
    "hardware_enforced_stack_protection": ("Hardware-Enforced Stack Protection", "operating_system",
        [r"hardware[- ]enforced stack protection", r"\bCET\b", r"shadow stack", r"intel cet"]),
    "exploit_protection":        ("Exploit Protection", "operating_system",
        [r"exploit protection", r"\bEMET\b", r"\bACG\b", r"arbitrary code guard", r"\bCFG\b", r"control flow guard", r"\bXFG\b", r"extended flow guard", r"\bkCFG\b", r"\bKCET\b"]),
    "kernel_data_memory_entropy_dma_protection": ("Kernel DMA Protection", "operating_system",
        [r"kernel dma protection"]),
    "direct_memory_access_dma_protection": ("DMA Protection", "operating_system",
        [r"\bDMA\b protect", r"thunderbolt.*dma"]),
    "microsoft_secure_process_protections": ("Protected Process / PPL", "operating_system",
        [r"\bPPL\b", r"protected process( light)?", r"protected process light", r"runasppl", r"BYOVDLL", r"ghost in the ppl"]),
    "windows_protected_process": ("Windows Protected Process", "operating_system",
        [r"protected process\b(?! light)"]),
    "windows_firewall":          ("Windows Firewall", "operating_system",
        [r"windows firewall", r"\bMpsSvc\b", r"firewall.dll"]),
    "windows_hotpatch":          ("Windows Hotpatch", "operating_system",
        [r"\bhotpatch", r"hot[- ]patch"]),
    "windows_update_for_business": ("Windows Update for Business", "operating_system",
        [r"windows update for business", r"\bWUfB\b"]),
    "kiosk_mode":                ("Kiosk Mode", "operating_system",
        [r"kiosk mode"]),
    "tamper_protection":         ("Tamper Protection", "operating_system",
        [r"tamper protection"]),
    "windows_security_app":      ("Windows Security App", "operating_system",
        [r"windows security app"]),
    "windows_subsystem_for_linux_wsl": ("WSL", "operating_system",
        [r"\bWSL\b(?![a-z])", r"windows subsystem for linux"]),
    "wsl_app_isolation":         ("WSL App Isolation", "operating_system",
        [r"wsl.*app isolation"]),
    "server_message_block_smb_for_remote_connections": ("SMB", "operating_system",
        [r"\bSMB\b(?![a-z])", r"server message block", r"\bSMBv?[12]\b"]),
    "domain_name_system_dns_security": ("DNS Security", "operating_system",
        [r"\bDNS\b.*(security|spoofing|cache|poison)", r"dns server.*windows"]),
    "windows_diagnostic_data_processor_configuration": ("Diagnostic Data", "operating_system",
        [r"diagnostic data"]),
    "network_access_protection": ("Network Access Protection", "operating_system",
        [r"network access protection"]),
    "internet_protocol_security_ipsec": ("IPsec", "operating_system",
        [r"\bipsec\b"]),
    "transport_layer_security_tls": ("TLS", "operating_system",
        [r"\bTLS\b", r"transport layer security", r"schannel"]),

    # ===== hardware =====
    "device_health_attestation": ("Device Health Attestation", "hardware",
        [r"device health attestation", r"\bDHA\b(?![a-z])"]),
    "windows_enrollment_attestation": ("Windows Enrollment Attestation", "hardware",
        [r"enrollment attestation"]),
    "azure_attestation_service": ("Azure Attestation Service", "hardware",
        [r"azure attestation"]),

    # ===== security_foundation =====
    "cryptography":              ("Cryptography", "security_foundation",
        [r"\bcryptograph", r"\bcipher\b", r"\bAES\b", r"\bRSA\b", r"\bECDSA\b", r"\bECDH\b", r"\bBcrypt\b", r"\bCryptoAPI\b", r"\bCAPI\b", r"\bCNG\b"]),
    "certificates":              ("Certificates", "security_foundation",
        [r"\bX\.?509\b", r"\bcertificate\b", r"\bAD CS\b", r"\bPKI\b", r"esc1|esc2|esc3|esc4|esc5|esc6|esc7|esc8|esc9", r"certified pre-owned"]),
    "security_baselines":        ("Security Baselines", "security_foundation",
        [r"security baselines?"]),
    "security_development_lifecycle_sdl": ("SDL", "security_foundation",
        [r"\bSDL\b(?![a-z])", r"security development lifecycle"]),
    "secure_future_initiative_sfi": ("Secure Future Initiative (SFI)", "security_foundation",
        [r"\bSFI\b(?![a-z])", r"secure future initiative"]),
    "windows_kernel_and_microsoft_bug_bounty_programs": ("Bug Bounty Programs", "security_foundation",
        [r"bug bounty", r"\bMSRC\b.*reward"]),
    "microsoft_offensive_research_and_security_engineering_morse": ("MORSE", "security_foundation",
        [r"\bMORSE\b"]),
    "rust_for_windows":          ("Rust for Windows", "security_foundation",
        [r"\bRust for Windows\b", r"\brust\b.*kernel", r"\brust\b.*windows"]),
}

# Whole-word/hyphen-tolerant pattern compile
COMPILED: dict[str, list[re.Pattern]] = {
    slug: [re.compile(pat, re.IGNORECASE) for pat in keywords]
    for slug, (_, _, keywords) in TOPICS.items()
}


def topics_for(rec: dict) -> list[str]:
    """Return list of topic slugs that match this record. Conservative."""
    haystack_parts = [
        rec.get("title") or "",
        rec.get("theme") or "",
        rec.get("speaker") or "",
        rec.get("venue") or "",
    ]
    haystack = " | ".join(haystack_parts)
    hits = []
    for slug, patterns in COMPILED.items():
        for pat in patterns:
            if pat.search(haystack):
                hits.append(slug)
                break
    return hits


def slug_for_talk(rec: dict) -> str:
    t = (rec.get("title") or "").lower()
    s = re.sub(r"[^a-z0-9]+", "-", t).strip("-")
    return s[:80]


def main() -> int:
    if not TALKS.exists():
        print(f"ERROR: {TALKS} not found", file=sys.stderr)
        return 1
    talks = yaml.safe_load(TALKS.read_text()) or []
    print(f"Loaded {len(talks)} talks")

    topic_to_talks: dict[str, list[dict]] = defaultdict(list)
    total_assignments = 0
    talks_with_topic = 0
    for r in talks:
        ts = topics_for(r)
        if ts:
            r["topics"] = ts
            talks_with_topic += 1
            total_assignments += len(ts)
            best_watch = ""
            wus = r.get("watch_urls") or []
            if wus:
                best_watch = wus[0].get("url", "")
            entry = {
                "title": r.get("title", ""),
                "year": r.get("year", ""),
                "venue": r.get("venue", ""),
                "speaker": r.get("speaker", ""),
                "url": r.get("url", ""),
                "watch_url": best_watch,
                "theme": r.get("normalized_category") or r.get("category", ""),
            }
            for slug in ts:
                topic_to_talks[slug].append(entry)
        elif "topics" in r:
            del r["topics"]

    print(f"Talks with at least one topic: {talks_with_topic} / {len(talks)}")
    print(f"Total topic assignments: {total_assignments}")
    print(f"Topics matched: {len(topic_to_talks)} / {len(TOPICS)}")

    # Persist topics field back into talks.yaml
    TALKS.write_text(yaml.safe_dump(talks, sort_keys=False, allow_unicode=True))
    print(f"[OK] wrote topics into {TALKS}")

    # docs/topic-map.json
    out = {
        "windows_security_base": WS_BASE,
        "post_template": WS_POST + "{slug}",
        "topics": {
            slug: {
                "name": TOPICS[slug][0],
                "category": TOPICS[slug][1],
                "post_url": WS_POST + slug,
                "talks": sorted(topic_to_talks[slug], key=lambda x: (str(x.get("year") or "0"), x.get("title") or ""), reverse=True),
            }
            for slug in sorted(topic_to_talks.keys())
        },
    }
    (DOCS / "topic-map.json").write_text(json.dumps(out, indent=2, ensure_ascii=False))
    print(f"[OK] wrote docs/topic-map.json")

    # docs/by-topic/<slug>.md
    BY_TOPIC.mkdir(parents=True, exist_ok=True)
    # Wipe stale per-topic files
    for old in BY_TOPIC.glob("*.md"):
        old.unlink()

    by_category: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
    for slug, entries in topic_to_talks.items():
        name, cat, _ = TOPICS[slug]
        by_category[cat].append((slug, name, len(entries)))

        lines = [
            f"# {name}",
            "",
            f"**WindowsSecurity reference:** [{WS_POST}{slug}]({WS_POST}{slug})",
            "",
            f"**Category:** {cat.replace('_', ' ').title()}",
            "",
            f"**{len(entries)} matching talks** across the corpus.",
            "",
            "| Year | Title | Speaker | Venue | Material |",
            "|---|---|---|---|---|",
        ]
        for e in sorted(entries, key=lambda x: (str(x.get("year") or "0"), x.get("title") or ""), reverse=True):
            year = str(e.get("year") or "")[:4]
            title = (e.get("title") or "").replace("|", "\\|")[:120]
            speaker = (e.get("speaker") or "").replace("|", "\\|")[:80]
            venue = (e.get("venue") or "").replace("|", "\\|")[:40]
            mat_links = []
            if e.get("url"):
                mat_links.append(f"[slides]({e['url']})")
            if e.get("watch_url"):
                mat_links.append(f"[watch]({e['watch_url']})")
            material = " · ".join(mat_links) or "—"
            lines.append(f"| {year} | {title} | {speaker} | {venue} | {material} |")
        (BY_TOPIC / f"{slug}.md").write_text("\n".join(lines) + "\n")

    # Master index
    idx_lines = [
        "# Talks by Windows-Security Topic",
        "",
        f"Each topic links to its [MaliParag/WindowsSecurity]({WS_BASE}) reference page",
        f"and lists the matching talks from this corpus.",
        "",
        f"**{talks_with_topic}** of {len(talks)} talks are tagged with at least one topic ({total_assignments} total tags across {len(topic_to_talks)} topics).",
        "",
    ]
    cat_order = ["identity", "cloud_services", "application", "operating_system", "hardware", "security_foundation"]
    for cat in cat_order:
        if not by_category[cat]:
            continue
        idx_lines.append(f"## {cat.replace('_', ' ').title()}")
        idx_lines.append("")
        for slug, name, count in sorted(by_category[cat], key=lambda x: -x[2]):
            idx_lines.append(f"- [{name}]({slug}.md) — {count} talk{'s' if count != 1 else ''} · [WindowsSecurity ref]({WS_POST}{slug})")
        idx_lines.append("")
    (BY_TOPIC / "index.md").write_text("\n".join(idx_lines) + "\n")
    print(f"[OK] wrote {len(topic_to_talks)} topic pages + index.md under docs/by-topic/")

    # Update docs/talks.json with the new topics field
    talks_json = DOCS / "talks.json"
    if talks_json.exists():
        cur = json.loads(talks_json.read_text())
        # Rebuild from talks.yaml since we mutated it
        slim = []
        for r in talks:
            slim.append({k: v for k, v in r.items() if v not in ("", None, [], {})})
        talks_json.write_text(json.dumps(slim, indent=2, ensure_ascii=False))
        print(f"[OK] refreshed docs/talks.json with topics field")

    return 0


if __name__ == "__main__":
    sys.exit(main())
