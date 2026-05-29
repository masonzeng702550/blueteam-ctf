---
name: log-hunter
description: When the user has Windows Event Logs (.evtx, Security/System/Sysmon), Linux auth.log/syslog, IIS/Apache access logs, or any SIEM export and needs to hunt for malicious activity, use this skill. It produces structured triage queries (Splunk SPL, Elastic KQL, Sentinel KQL), Chainsaw/Hayabusa command lines for offline EVTX, and maps findings to MITRE ATT&CK. Covers lateral movement, privilege escalation, persistence, and webshell detection.
---

# Log Hunter — Event Log & SIEM analysis

> **Privacy:** logs may contain usernames, internal hostnames, and IPs. Redact with `scripts/extract_iocs.py --redact` before sending to a hosted model if data is sensitive.

## When to use this skill

- File extensions: `.evtx`, `.log`, `.json` (alert payload), `.csv` (SIEM export).
- User mentions: Splunk, Elastic, Sentinel, QRadar, Chainsaw, Hayabusa, Sysmon, Event ID, EventCode, KQL, SPL.
- Investigating: lateral movement, privilege escalation, webshells, persistence, brute force, golden ticket.

## Inputs

- Path to log file(s), or pasted log excerpt.
- SIEM platform if known.
- Time window of interest.

## Workflow

### Step 1 — Identify log source

| Marker | Source | Primary IDs to triage |
|--------|--------|-----------------------|
| `Microsoft-Windows-Security-Auditing` | Windows Security | 4624, 4625, 4648, 4672, 4688, 4768, 4769, 4776 |
| `Microsoft-Windows-Sysmon` | Sysmon | 1, 3, 7, 8, 10, 11, 13, 22 |
| `sshd[`, `sudo:` in text | Linux auth.log | accepted/failed password, sudo invocations |
| Apache/Nginx access | Web server | 200 to admin paths, 500 spikes, UA anomalies |
| EDR JSON (CrowdStrike, Defender) | EDR | platform-specific |

See `references/windows-event-ids.md` for the full triage cheatsheet.

### Step 2 — Offline EVTX preflight (recommended)

If user has the raw `.evtx`:

```bash
# Chainsaw — Sigma + Hunting rules
chainsaw hunt <evtx-dir> -s sigma/ --mapping mappings/sigma-event-logs-all.yml -o csv

# Hayabusa — alternative, JSON output
hayabusa csv-timeline -d <evtx-dir> -o timeline.csv
```

### Step 3 — Generate SIEM queries

For each hypothesis, produce one query per platform the user runs. Templates:

**Splunk SPL — lateral movement via logon-type-3:**
```spl
index=wineventlog EventCode=4624 Logon_Type=3
| stats count by Account_Name, Source_Network_Address, Workstation_Name
| where count > 5
| sort - count
```

**Sentinel KQL — suspicious process tree:**
```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| where ParentProcessName endswith "winword.exe" or ParentProcessName endswith "excel.exe"
| project TimeGenerated, Computer, Account, NewProcessName, ParentProcessName, CommandLine
```

**Elastic KQL — Sysmon network connection from rare process:**
```
event.dataset:"windows.sysmon_operational" and event.code:"3" and
not process.name:("chrome.exe" or "msedge.exe" or "firefox.exe" or "svchost.exe")
```

### Step 4 — Hunting patterns

| Tactic | Pattern | Event IDs |
|--------|---------|-----------|
| Brute force | Many 4625 from same source, then a 4624 | 4625 → 4624 |
| Pass-the-hash | 4624 type 3 with NTLM, no preceding 4768/4769 | 4624 + auth pkg |
| Golden Ticket | 4769 with mismatched encryption / lifetime | 4769 |
| Webshell | Web server spawns cmd.exe/powershell.exe | Sysmon 1 (parent=w3wp/php-fpm) |
| Service install | New service from non-admin path | 7045 |
| Scheduled task | Task created with action calling cmd/powershell | 4698 |

### Step 5 — Correlate & summarise

Build a per-host timeline. For each finding, capture: timestamp (UTC), event ID, actor, target, evidence snippet, confidence.

## Outputs

Append to `findings.md`:

```markdown
## Log hunt — <source>

### Hypothesis
- 

### Queries run
- (SPL/KQL list)

### Findings
| UTC | Host | Event ID | Actor | Detail | Confidence |

### IOCs
| Type | Value | Confidence | Source |

### MITRE ATT&CK
- T1078 — Valid Accounts
- T1021.002 — SMB/Admin Shares
- T1059.001 — PowerShell

### Suggested detection rule
- (hand off to /detection-engineer)
```

## Hand-off

- IOCs → `/ioc-extractor`.
- Detection ideas → `/detection-engineer`.
- Final write-up → `/ir-report`.

## Hard rules

- Always specify the time zone of timestamps (default to UTC).
- Do not invent EventCode numbers; if unsure, write `EventCode=????` and ask the user.
- Confidence is `medium` until at least two corroborating events are found.
