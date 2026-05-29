---
name: detection-engineer
description: When the user has identified a TTP / IOC / attack pattern (from PCAP, logs, memory, threat-intel feed) and wants to author a detection rule — Sigma (cross-SIEM), YARA (file content), Suricata/Snort (network), or KQL (Sentinel/Defender) — use this skill. It generates the rule, validates Sigma against the 2.0 spec via `scripts/validate_sigma.py`, maps the rule to MITRE ATT&CK, and proposes an Atomic Red Team test ID for re-validation.
---

# Detection Engineer

> **Privacy:** rules themselves are safe to publish, but the example logs you base them on may not be — redact before sharing.

## When to use this skill

- User says "write a Sigma rule for…", "give me a YARA rule…", "Suricata rule for…".
- User has finished an investigation and wants to operationalise the detection.
- User is preparing a Pyramid-of-Pain talk / portfolio piece.

## Inputs

- Plain-text TTP description, sample log line, IOC list, or hash + strings.
- Target SIEM if user wants the converted form.

## Workflow

### Step 1 — Identify the rule type

| Signal | Rule type |
|--------|-----------|
| Log pattern across many systems | Sigma → convert to SPL/KQL via Uncoder |
| File content (strings, imphash, sections) | YARA |
| Network signature (URI, payload bytes, JA3) | Suricata or Snort |
| EDR-specific telemetry not in Sigma backends | KQL or vendor-native |

### Step 2 — Author the rule

Use the corresponding template under `templates/`:

- `templates/sigma-template.yml`
- `templates/yara-template.yar`

#### Sigma skeleton

```yaml
title: <Imperative, action-oriented>
id: <uuid-v4>
status: experimental
description: <one paragraph; what behaviour, why malicious, expected FP sources>
references:
  - <URL to TI report, blog, or MITRE technique>
author: <name or handle>
date: <YYYY/MM/DD>
modified: <YYYY/MM/DD>
tags:
  - attack.<tactic>
  - attack.t<id>
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
  condition: selection
falsepositives:
  - Legitimate admin scripts (rare in -enc form)
level: high
```

#### YARA skeleton

```yara
rule Apt28_Drovorub_Loader
{
    meta:
        author      = "<handle>"
        date        = "2026-05-29"
        description = "Detects Drovorub loader strings"
        reference   = "https://media.defense.gov/2020/Aug/13/2002476465/-1/-1/0/CSA_DROVORUB_AUG_13_2020.PDF"
        tlp         = "WHITE"
        hash        = "<sha256>"

    strings:
        $s1 = "drovorub-kernel" ascii
        $s2 = "uniq_payload" ascii
        $s3 = { 6D 6F 64 75 6C 65 5F 69 6E 69 74 }   // module_init

    condition:
        uint16(0) == 0x457f and 2 of ($s*)
}
```

### Step 3 — Validate

If `scripts/validate_sigma.py` is available, run it on the generated Sigma:

```bash
python3 scripts/validate_sigma.py <rule.yml>
```

Expected exit 0. On failure, the script prints the schema violation; fix and retry.

For YARA: recommend `yarac` or `yara -w -s <rule> <sample>` on the analyst side (no auto-execution).

### Step 4 — MITRE ATT&CK mapping

Map every rule to ≥1 `tactic` and ≥1 `technique`. Use sub-techniques where available. Common pairs:

| Technique | When |
|-----------|------|
| T1059.001 PowerShell | Suspicious PS in command line |
| T1003.001 LSASS Memory | LSASS access by non-system PID |
| T1021.002 SMB/Admin Shares | Lateral mount of ADMIN$/C$ |
| T1055 Process Injection | Sysmon 8 / malfind hit |
| T1547.001 Registry Run Keys | Persistence under Run/RunOnce |

### Step 5 — Atomic Red Team mapping

Suggest the Atomic Red Team test that would re-trigger the rule. Examples:

- T1059.001 → `T1059.001-1` (Mshta) or `T1059.001-3` (PowerShell EncodedCommand).
- T1003.001 → `T1003.001-1` (Powershell Mimikatz) or `T1003.001-3` (procdump).

Output the recipe as a shell snippet for the analyst (do not auto-execute).

### Step 6 — Document false-positive sources

Every rule MUST end with a `falsepositives:` list of at least one realistic FP source.

## Outputs

```markdown
## Detection: <rule title>

### Rule (Sigma)
```yaml
<rule body>
```

### Validation
- sigma-validate: PASS

### MITRE
- Txxxx.yyy — name

### Re-validation
- Atomic Red Team: T1059.001-3
- Command (run only in lab):
```bash
Invoke-AtomicTest T1059.001-3
```

### False-positive sources
- ...

### Converted forms (optional)
- Splunk: `<spl>`
- Sentinel: `<kql>`
```

## Hand-off

- Final rule → `/ir-report` for inclusion under "Suggested detections".

## Hard rules

- Do not invent Sigma fields not in the 2.0 spec.
- Every rule has a UUID — generate with `python3 -c "import uuid; print(uuid.uuid4())"`.
- Sigma `level` must be one of: informational, low, medium, high, critical.
