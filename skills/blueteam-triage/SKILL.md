---
name: blueteam-triage
description: When the user shares any blue-team CTF artefact (PCAP, EVTX, memory dump, disk image, malware sample, raw log line, alert JSON) or simply says "I have an alert / I have a forensic file / where do I start?", use this skill first. It classifies the artefact, sets up a working folder, and routes the user to the right deep-dive skill (pcap-analysis, memory-forensics, log-hunter, ioc-extractor) or agent. This is the SOC tier-1 entry point.
---

# Blue Team Triage — entry-point router

> **Privacy reminder:** if the source data is sensitive, run `scripts/extract_iocs.py --redact` first or use a local LLM (Ollama + Foundation-Sec-8B). Do not paste raw PII into a hosted model.

## When to use this skill

- The user mentions a file extension among: `.pcap`, `.pcapng`, `.evtx`, `.dmp`, `.mem`, `.raw`, `.E01`, `.AD1`, `.zip` (suspected sample), `.json` (alert).
- The user says "I have a SOC alert", "I got a CyberDefenders challenge", "I need to investigate", "where do I start", "triage this".
- The user is preparing for AIS3 / 金盾獎 / HITCON Cyber Range / BTL1 and is mid-investigation.

## Inputs

You will typically receive one or more of:
- A file path (preferred — read with `Read` or hand off to a script).
- A pasted log excerpt or alert payload.
- A free-form description of what was observed.

## Workflow

### Step 1 — Classify

Identify the artefact class. Use this decision table:

| Signal | Class | Hand off to |
|--------|-------|-------------|
| `.pcap`, `.pcapng`, mentions tcpdump/Wireshark | Network capture | `pcap-analysis` |
| `.evtx`, EventCode/EventID, Sysmon, auth.log, IIS | Log / SIEM | `log-hunter` |
| `.dmp`, `.mem`, `.raw`, Volatility, MemProcFS | Memory image | `memory-forensics` |
| `.E01`, `.AD1`, MFT, Prefetch, ShimCache | Disk image | `dfir-investigator` agent |
| Hash, defanged URL, IP, JA3 | IOC blob | `ioc-extractor` |
| Suspicious binary, PE/ELF | Malware sample | `dfir-investigator` agent + sandbox advice |
| Alert JSON / EDR ticket | Live alert | `soc-analyst` agent |

### Step 2 — Establish baseline context

Ask (or infer) the **3 essentials**:

1. **Scope** — single host, subnet, or enterprise?
2. **Time window** — what is the suspected dwell-time start?
3. **Authorisation** — is this a CTF / lab / authorised IR? (Refuse to proceed if no.)

### Step 3 — Set up a working note

Create or update `findings.md` in the user's current directory using the 5W skeleton:

```markdown
# Investigation — <case-id>
- Start: <UTC timestamp>
- Scope: <hosts/subnets>
- Hypothesis: <one sentence>

## Timeline
| UTC | Source | Event | Confidence |

## IOCs
| Type | Value | Confidence | Source |

## Open questions
- 
```

### Step 4 — Route

Tell the user, in one line, which skill or agent to invoke next, and why. Example:

> Artefact looks like a Windows Event Log export. Invoking `/log-hunter` next; it will start with logon-type-3 and 4688 process-creation analysis.

### Step 5 — Hand off

If you have the right context, you may directly invoke the next skill in the same turn (do not wait for the user to re-prompt).

## Outputs

- A populated `findings.md` skeleton in the working directory.
- A one-line routing decision with rationale.
- The next skill or agent invocation, if context permits.

## Hard rules

- Never speculate on attribution at this stage. Save that for the IR report.
- Never invoke offensive tools.
- Mark every preliminary call with `confidence: low` until corroborated.

## Hand-off matrix

| Next step | When |
|-----------|------|
| `pcap-analysis` | Network capture in hand |
| `log-hunter` | Event Log / syslog / SIEM export |
| `memory-forensics` | Memory image |
| `ioc-extractor` | Pile of mixed IOCs, no structured artefact yet |
| `detection-engineer` | User already knows the TTP and wants a rule |
| `ir-report` | Investigation effectively complete, just needs write-up |
| `@soc-analyst` (agent) | Live alert in production-style queue |
| `@dfir-investigator` (agent) | Disk image or deep memory investigation |
