# Windows Security Talks

**🔎 Browse the interactive site: https://maliparag.github.io/windows-security-talks/**

A curated index of conference talks, blog posts, and research about Microsoft Windows security — covering the foundational pre-2024 canon plus the 2024–2026 research wave.

**265 talks** across **27 themes**. **215 have verified slides/paper links** and **147 have verified recordings** (183 total recording links — many talks have multiple mirrors so a single dead host doesn't kill access).

The static site at the URL above supports free-text search, filters (category / year / venue / has-video), sortable columns, and embedded YouTube playback when the talk has a confirmed video.

## What This Is

There are 17,000+ talks in [InfoconDB](https://infocondb.org/), all the LOLDrivers metadata, and several "awesome" lists of Windows security resources. None of them filter, theme-cluster, and annotate **specifically Windows-targeting research talks** for the current research wave. This repo does.

For each talk:

- Title (exact, as published)
- Speaker(s) with primary affiliation
- Year + Conference / Venue
- One-sentence theme
- Topic category (controlled vocabulary, see below)
- URL — to the official talk page, paper, or blog post
- Watch URL — YouTube / media.defcon.org recording where verified

## Topic Categories

Talks are tagged with a single controlled-vocabulary category. (Theme blurbs cover any cross-cutting nuance.)

| Category | Description |
|---|---|
| `kernel-exploit` | Kernel exploitation, mitigation bypass, microarchitectural attacks, ROP/CFG/CET work |
| `ad-attack` | Active Directory: Kerberos, AD CS, LDAP, BloodHound, DCSync, NoPAC, SCCM |
| `ipc-rpc` | ALPC, LRPC, DCOM, named-pipe attacks (Potato family), NTLM relay |
| `post-exploit` | Token impersonation, lateral movement, persistence, UAC bypass, LOLBins |
| `edr-bypass` | EDR evasion, AMSI bypass, ETW patching, hooking |
| `cloud-identity` | Entra ID / Azure AD, hybrid identity, Conditional Access |
| `hyper-v` | Hyper-V exploitation, virtualization escape |
| `credentials` | Credential extraction, DPAPI, LSASS, Windows Hello, Mimikatz, smart cards |
| `boot-firmware` | Secure Boot, Measured Boot, UEFI, BitLocker, TPM |
| `vbs-bypass` | VBS, HVCI, Credential Guard bypass, trustlets |
| `ai-security` | Copilot, M365 AI, prompt injection, agentic, LLM security |
| `office-attack` | Word/Excel/Outlook attack surface, OLE |
| `defense-evasion` | Downgrade attacks, signature bypass, obfuscation |
| `filesystem` | NTFS, ReFS, symlinks, TOCTOU |
| `identity` | Authentication primitives (non-cloud): WebAuthn, smart cards, RDP |
| `browser-sandbox` | Browser sandbox escape, AppContainer escape |
| `code-integrity` | WDAC, code signing, Authenticode, Smart App Control |
| `byovd` | Bring Your Own Vulnerable Driver |
| `registry` | Windows Registry / hive parsing exploitation |
| `rce` | Remote code execution (cross-cutting) |
| `fuzzing` | Fuzzing tooling and methodology |
| `malware` | Malware analysis, ransomware, APT campaigns |
| `supply-chain` | Software supply-chain attacks |
| `exchange` | Exchange Server security |
| `hardware-attack` | TPM, Pluton, DMA, SGX/TDX/SEV-SNP |
| `forensics` | DFIR, memory forensics |
| `threat-intel` | Threat hunting, intelligence reports |
| `out-of-scope` | Talk at a Windows-security venue but covering macOS / iOS / IoT / etc. — kept for completeness |
| `keynote` | Conference keynotes, security-history retrospectives |

## Browse

- [By Theme](./by-theme/) — one markdown per topic category
- [By Conference](./by-conference/) — one markdown per venue (blackhat-usa, defcon, bluehat, offensivecon, recon, troopers, project-zero, ...)
- [By Year](./by-year/) — chronological per-year listings (1997–2026)
- [All Talks](./all-talks.md) — single consolidated table
- [talks.yaml](./talks.yaml) — machine-readable database

## Source Venues Currently Covered

- **Black Hat USA** (2024–2026)
- **DEF CON** (32, 33, 34)
- **BlueHat** Microsoft (Redmond + IL + India editions, 2024)
- **OffensiveCon** Berlin (2024–2026)
- **Recon** Montreal (2024–2026)
- **Troopers** Heidelberg (2024–2025)
- **Pwn2Own** Vancouver + Berlin (2024–2026)
- **Hardwear.io** USA (2024)
- **Project Zero** blog
- **Academic**: USENIX Security, ACM CCS, IEEE S&P, NDSS
- **Community blogs**: SpecterOps, Outflank, dirkjanm, tiraniddo, itm4n, Yarden Shafir, Connor McGarr
- **Foundational pre-2024 canon** (1997–2023): Hot Potato, RottenPotato, JuicyPotato, PrintNightmare, ZeroLogon, Certified Pre-Owned, Mimikatz, BloodHound, etc.

## Generation

Built from a parallel research pipeline that runs nine specialized agents against the venues above plus a watch-link enrichment pass, then aggregates and de-duplicates. See [scripts/extract-talks.py](scripts/extract-talks.py).

The extractor handles three record formats found across the source reports:

1. **Per-record blocks** separated by `---`, with `**Field**: value` lines or 2-column key/value tables
2. **Wide multi-row tables** where each data row is one record (BlueHat style)
3. **Mixed** with section-heading year context propagated forward (BlueHat 2024 → BlueHat 2025 sections)

To regenerate after editing the source research reports:

```bash
python3 scripts/extract-talks.py
```

## Contributing

Issues and PRs welcome for missing talks, new venues, categorization corrections, or YouTube/recording links.

## Companion Blog

The deep technical writeups that use these talks as primary sources are at [paragmali.com](https://paragmali.com).

## License

CC-BY-4.0 for the curated data. All linked talks and posts are property of their respective authors.
