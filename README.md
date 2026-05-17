# Windows Security Talks

A curated index of conference talks, blog posts, and research about Microsoft Windows security from 2024 onward.

## What This Is

There are 17,000+ talks in [InfoconDB](https://infocondb.org/), all the LOLDrivers metadata, and several "awesome" lists of Windows security resources. None of them filter, theme-cluster, and annotate **specifically Windows-targeting research talks** for the current research wave. This repo does.

For each talk:

- Title (exact, as published)
- Speaker(s) with primary affiliation
- Year + Conference / Venue
- One-sentence theme
- Topic category (controlled vocabulary, see below)
- URL — to the official talk page, paper, or blog post

## Topic Categories

| Category | Description |
|---|---|
| `kernel-exploit` | Kernel exploitation, mitigation bypass, fuzzing targeting kernel |
| `ad-attack` | Active Directory: Kerberos, AD CS, BloodHound, DCSync, ESC catalog |
| `identity` | Authentication primitives: WebAuthn, smart cards, Windows Hello, RDP |
| `credentials` | Credential extraction, DPAPI, LSASS, password managers |
| `hyper-v` | Hyper-V exploitation, hypervisor security |
| `vbs-bypass` | VBS, HVCI, Credential Guard bypass |
| `code-integrity` | WDAC, code signing, Authenticode |
| `edr-bypass` | EDR evasion, AMSI bypass, ETW patching |
| `byovd` | Bring Your Own Vulnerable Driver |
| `cloud-identity` | Entra ID, Azure AD, hybrid identity |
| `post-exploit` | Token impersonation, lateral movement, persistence |
| `defense-evasion` | Downgrade attacks, signature bypass, LOLBins |
| `hardware-attack` | TPM, Pluton, SGX/TDX/SEV-SNP |
| `boot-firmware` | Secure Boot, Measured Boot, UEFI, BitLocker |
| `browser-sandbox` | Browser sandbox escape, AppContainer escape |
| `ipc-rpc` | ALPC, LRPC, DCOM, named-pipe attacks (Potato family) |
| `fuzzing` | Fuzzing tooling and methodology |
| `malware` | Malware analysis, ransomware, APT campaigns |
| `ai-security` | Copilot, agent security, AI on Windows |
| `supply-chain` | Software supply-chain attacks |
| `office-attack` | Word/Excel/Outlook attack surface |
| `filesystem` | NTFS, ReFS, filesystem attacks |
| `exchange` | Exchange Server security |

## Browse

- [By Theme](./by-theme/) — one markdown per topic category
- [By Conference](./by-conference/) — one markdown per venue
- [By Year](./by-year/) — chronological per-year listings
- [All Talks](./all-talks.md) — single consolidated table
- [talks.yaml](./talks.yaml) — machine-readable database

## Source Venues Currently Covered

- Black Hat USA (2024-2026)
- DEF CON (32, 33, 34)
- BlueHat (Microsoft) — Redmond, IL, India editions
- OffensiveCon (Berlin) + Recon (Montreal/Brussels)
- Project Zero blog and issue tracker
- Academic: USENIX Security, ACM CCS, IEEE S&P, NDSS
- Troopers + Hardwear.io + POC + HITB + Pwn2Own/ZDI
- Community blogs: SpecterOps, Outflank, dirkjanm, tiraniddo, itm4n, Yarden Shafir, Connor McGarr

## Generation

Built from a parallel research pipeline that runs eight specialized agents against the venues above, then aggregates and de-duplicates. See [scripts/extract-talks.py](scripts/extract-talks.py).

## Contributing

Issues and PRs welcome for missing talks, new venues, categorization corrections, or YouTube/recording links.

## Companion Blog

The deep technical writeups that use these talks as primary sources are at [paragmali.com](https://paragmali.com).

## License

CC-BY-4.0 for the curated data. All linked talks and posts are property of their respective authors.
