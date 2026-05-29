# IR Report — <Case ID>

> **Classification:** TLP:AMBER
> **Author:** <name>
> **Date (UTC):** YYYY-MM-DD
> **Status:** Draft | Final
> **Investigation window (UTC):** <start> → <end>

---

## 1. Executive summary

<3-5 sentences, no jargon. Cover: what happened, business impact, current status.>

## 2. Incident timeline (UTC)

| Time | Source | Event | Confidence |
|------|--------|-------|------------|
| 2026-05-29T14:32Z | Sysmon ID 1 | powershell.exe -enc … spawned by winword.exe on HOST-01 | high |
| | | | |

## 3. IOCs

| Type | Value | First-seen | Confidence | Source |
|------|-------|------------|------------|--------|
| sha256 | abc123… | 14:32 UTC | high | dropper.exe in Word temp folder |
| ipv4 | 185.220.101.42 | 14:33 UTC | high | Sysmon ID 3 outbound |
| domain | malicious[.]example.com | 14:33 UTC | high | DNS query log |

## 4. MITRE ATT&CK mapping

| Tactic | Technique | Sub-technique | Evidence (timeline row) |
|--------|-----------|---------------|-------------------------|
| Initial Access | T1566 | .001 Spearphishing Attachment | Email msg-id … |
| Execution | T1059 | .001 PowerShell | Sysmon 1 @ 14:32 |
| Defense Evasion | T1027 | — | base64-encoded command |
| C2 | T1071 | .001 Web Protocols | HTTP POST to 185.220.101.42 |

## 5. Technical analysis

### 5.1 Initial access
<2-3 paragraphs. Cite artefacts. Include log snippets in fenced blocks.>

```
Sat 29 May 2026 14:32:01 UTC  HOST-01  Sysmon  ID 1
ParentImage: C:\Program Files\Microsoft Office\winword.exe
Image:       C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -enc JABz...
```

### 5.2 Execution
<…>

### 5.3 Command & control
<…>

### 5.4 Impact
<…>

## 6. Remediation recommendations

### Immediate (0-24 h)
- [ ] Block IOCs listed in §3 at perimeter and EDR.
- [ ] Isolate HOST-01 from the network; preserve memory.
- [ ] Force password reset for affected user(s).

### Short-term (1-7 d)
- [ ] Deploy Sigma rule `Detect-Word-Spawns-Encoded-PowerShell` (see §7).
- [ ] Patch <CVE if applicable>.
- [ ] Review email gateway rules for similar attachments.

### Long-term (1-3 m)
- [ ] Roll out AppLocker policy preventing Office → script-host child processes.
- [ ] Tabletop exercise within 14 days, scope: macro-based initial access.
- [ ] User awareness micro-training: 1 module on macro-laden attachments.

## 7. Detection rules (referenced)

- `rules/sigma/word-spawns-encoded-powershell.yml` — UUID … — level: high
- `rules/suricata/c2-185.220.101.42.rules` — sid …

## 8. Confidence statement

- **Strongest evidence:** <…>
- **Remaining uncertainty:** <…>
- **What would resolve it:** <e.g., the full email with headers; the original maldoc; egress proxy logs covering 14:00-14:35 UTC>

## 9. Appendix

- A. Tool versions used: Volatility 3.x, Wireshark 4.x, Sysmon 15.x …
- B. Chain of custody table.
- C. Raw artefact hashes.
