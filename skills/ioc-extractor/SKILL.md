---
name: ioc-extractor
description: When the user has a pile of mixed text (incident ticket body, malware report, pasted log lines, blog post, PCAP excerpt) and needs to extract, deduplicate, and normalise indicators of compromise (IPv4, IPv6, domain, URL, MD5/SHA1/SHA256, email, BTC address, CVE, MITRE technique ID, JA3, YARA-style imphash), use this skill. It refangs defanged IOCs (e.g., 1.2.3[.]4 → 1.2.3.4), classifies each, and prepares a SIEM-ready table.
---

# IOC Extractor

> **Privacy:** the underlying `extract_iocs.py` has a `--redact` mode that replaces detected emails/IPs with placeholders and emits a local-only redaction map. Use it before feeding output to remote models.

## When to use this skill

- User pastes a paragraph of mixed text and asks "pull out the IOCs".
- User shares a TI report URL or excerpt.
- User wants to deduplicate IOCs across several sources.
- User wants defanged → refanged conversion.

## Inputs

- Pasted text, file path, or URL excerpt.
- Optional flags: `--redact`, `--types ip,domain,hash`, `--format markdown|json|csv`.

## Workflow

### Step 1 — Run the extractor

If `scripts/extract_iocs.py` is available:

```bash
python3 scripts/extract_iocs.py <input-file>           # or - for stdin
python3 scripts/extract_iocs.py <input> --json
python3 scripts/extract_iocs.py <input> --redact       # PII safety
```

If the script is not available, fall back to the regexes below.

### Step 2 — Classify by type

| Type | Regex hint | Notes |
|------|-----------|-------|
| IPv4 | `\b(?:\d{1,3}\.){3}\d{1,3}\b` | Strip RFC1918, loopback, link-local before reporting as external IOC |
| IPv6 | standard pattern | Often missed — explicitly hunt for `:` clusters |
| Domain | `\b[a-z0-9.-]+\.[a-z]{2,}\b` | Drop obvious vendor noise (microsoft.com, google.com) unless context says otherwise |
| URL | `https?://[^\s]+` | |
| MD5 | `\b[a-f0-9]{32}\b` | Case-insensitive |
| SHA1 | `\b[a-f0-9]{40}\b` | |
| SHA256 | `\b[a-f0-9]{64}\b` | |
| Email | `\b[\w.+-]+@[\w-]+\.[\w.-]+\b` | Often PII — redact by default in shared writeups |
| CVE | `CVE-\d{4}-\d{4,7}` | Verify on NVD; do not invent |
| MITRE | `T\d{4}(\.\d{3})?` | |
| BTC | `\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b` | Beware of false positives in long alphanumeric strings |
| JA3 | `\b[a-f0-9]{32}\b` (same as MD5) | Distinguish via context — JA3 lives in TLS metadata |

### Step 3 — Refang defanged IOCs

| Defanged form | Refanged |
|---------------|----------|
| `1.2.3[.]4` | `1.2.3.4` |
| `1.2.3(.)4` | `1.2.3.4` |
| `example[.]com` | `example.com` |
| `hxxp://`, `hXXp://` | `http://` |
| `hxxps://` | `https://` |
| `mailto[:]` | `mailto:` |

### Step 4 — Deduplicate & rank

- Lowercase hashes and domains before dedup.
- Sort by frequency in the source text (often a proxy for centrality in the campaign).
- Mark each row with a confidence: `high` (appears in IR ticket or sample-pulled), `medium` (single mention with context), `low` (single mention, no context).

### Step 5 — Optional enrichment hints (offline)

This skill does not call external APIs. It produces a "to-enrich" column listing services the analyst can hit manually:

- IP → VirusTotal, AbuseIPDB, Shodan, GreyNoise.
- Domain → VT, urlscan.io, ThreatFox, DomainTools.
- Hash → VT, Hybrid Analysis, MalwareBazaar.

## Output format

Default Markdown table appended to `findings.md`:

```markdown
## IOCs (extracted <timestamp>)

| Type | Value | First-seen | Count | Confidence | Enrich-with |
|------|-------|------------|-------|------------|-------------|
| ipv4 | 185.220.101.42 | line 14 | 3 | medium | abuseipdb, greynoise |
| domain | malicious[.]example.com | line 22 | 1 | low | virustotal, threatfox |
| sha256 | abc123... | line 31 | 1 | high | virustotal, malwarebazaar |
```

JSON (`--format json`) emits the same as a list of objects.

## Hand-off

- IOCs feed `/log-hunter` (pivot queries), `/detection-engineer` (rule input), `/ir-report` (final table).

## Hard rules

- Never invent IOCs not present in input.
- Refang for analysis, but **redact when sharing publicly** to avoid SEO-polluting malicious domains.
- CVEs and MITRE IDs must be verified before being reported with `high` confidence.
