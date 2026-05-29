---
name: ir-report
description: When the user has finished (or paused) an investigation and needs to produce a publishable IR report / CTF writeup / internal post-incident review, use this skill. It assembles the standard six-section structure — Executive Summary, Incident Timeline, IOC Table, MITRE ATT&CK Mapping, Technical Analysis, Remediation Recommendations — from the accumulated `findings.md` notes, applies the 5W discipline, and outputs Markdown ready for Medium / GitHub / internal wiki.
---

# IR Report builder — BTL1 / SAL1 aligned

> **Privacy:** before publishing externally, redact internal hostnames, real usernames, and customer-identifying IPs. Use `scripts/extract_iocs.py --redact`.

## When to use this skill

- Investigation is wrapped or paused for write-up.
- User explicitly asks for "writeup", "report", "post-incident review", "lessons learned".
- Preparing a portfolio / Medium post / BTL1 practical answer.

## Inputs

- The accumulated `findings.md` from prior skills.
- Optional: target audience (executives, technical peers, both).
- Optional: classification level (TLP:WHITE / GREEN / AMBER / RED).

## Workflow

### Step 1 — Audience-tune the Executive Summary

Three sentences, no jargon:
1. What happened (one verb-driven sentence).
2. Impact in business terms (data, downtime, regulatory exposure).
3. Current status (contained / eradicated / monitoring).

### Step 2 — Build the timeline

UTC throughout. Each row: `Time | Source | Event | Confidence`. Order chronologically across all sources. Mark gaps with `(unknown)`.

### Step 3 — Consolidate IOCs

Merge across all `## IOCs` blocks in `findings.md`. Deduplicate, sort by confidence then type.

### Step 4 — MITRE ATT&CK mapping table

```markdown
| Tactic | Technique | Sub-technique | Evidence |
|--------|-----------|---------------|----------|
| Initial Access | T1566 | .001 Spearphishing Attachment | Email <id>, attachment <hash> |
| Execution | T1059 | .001 PowerShell | Sysmon 1 at 14:32 UTC |
```

### Step 5 — Technical analysis

For each tactic in the timeline, write 1-3 paragraphs with:
- Direct quote / snippet from the artefact (log line, decoded blob, Volatility output).
- Tool used (Wireshark filter, KQL query, vol plugin).
- Interpretation.

### Step 6 — Remediation recommendations

Group by horizon:

- **Immediate (0-24 h):** block IOCs, rotate credentials, isolate hosts.
- **Short-term (1-7 d):** patch, restore from backup, deploy detection rules from `/detection-engineer`.
- **Long-term (1-3 m):** architecture changes, training, tabletop exercises.

Each recommendation: action verb + owner + measurable outcome.

### Step 7 — Confidence statement

Close with one paragraph stating:
- What evidence is strongest.
- What remains uncertain.
- What additional artefacts would resolve the uncertainty.

## Template

Copy from `templates/ir-report-template.md`. Replace placeholders.

## Outputs

A new file in the working directory: `report-<case-id>-<YYYYMMDD>.md` containing all six sections.

## Hand-off

- Detection rules referenced → `/detection-engineer` if not already authored.
- Lessons-learned items requiring follow-up investigations → `@threat-hunter` agent.

## Hard rules

- Six sections — no fewer.
- Every IOC in the report MUST appear in the IOC table.
- Every claim in Technical Analysis MUST cite an artefact (log line, hash, screenshot reference).
- Mark confidence on every analytic claim.
- No attribution without ≥3 independent corroborating sources.
